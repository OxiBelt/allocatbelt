#!/usr/bin/env python3
"""Independently validate bounded application feedback traces.

The reader accepts caller-pinned expectations and raw digests, streams both
large trace artifacts, and reconstructs the feedback policy from sensor,
decision, ticket, write, readback, acknowledgement, and reconciliation events.
It does not trust a producer pass label. A valid trace is one component of a
later qualification; it never establishes allocator performance.
"""
from __future__ import annotations

import argparse
from array import array
from bisect import bisect_right
import copy
import hashlib
import json
import os
import platform
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import types
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Callable, Iterator


EXPECTATION_SCHEMA_V1 = "allocatbelt.application-feedback-expectation.v1"
EXPECTATION_SCHEMA_V2 = "allocatbelt.application-feedback-expectation.v2"
EXPECTATION_SCHEMA_V3 = "allocatbelt.application-feedback-expectation.v3"
EXPECTATION_SCHEMA_V4 = "allocatbelt.application-feedback-expectation.v4"
EXPECTATION_SCHEMA_V5 = "allocatbelt.application-feedback-expectation.v5"
EXPECTATION_SCHEMA_V6 = "allocatbelt.application-feedback-expectation.v6"
EXPECTATION_SCHEMA = EXPECTATION_SCHEMA_V2
CONSTRUCTION_PROBE_SCHEMA = "allocatbelt.application-feedback-policy-probe.v1"
TRACE_MANIFEST_SCHEMA = "allocatbelt.application-feedback-trace-manifest.v1"
EVENT_SCHEMA = "allocatbelt.application-feedback-event.v1"
SAMPLE_SCHEMA = "allocatbelt.application-feedback-resource-sample.v1"
READBACK_SCHEMA = "allocatbelt.application-feedback-validation.v1"
READBACK_SCHEMA_V2 = "allocatbelt.application-feedback-validation.v2"
SOURCE_MANIFEST_SCHEMA = "allocatbelt.application-source-manifest.v4"
SOURCE_MANIFEST_SCHEMA_V5 = "allocatbelt.application-source-manifest.v5"
SOURCE_V5_CONTROLLER_PATH = "scripts/application-campaign.py"
SOURCE_V5_CAMPAIGN_INPUTS_PATH = "scripts/application-campaign-inputs.py"
PRESSURE_READBACK_SCHEMA = "allocatbelt.application-pressure-readback.v1"
PRESSURE_READBACK_SCHEMA_V2 = "allocatbelt.application-pressure-readback.v2"
RUNTIME_BINDING_SCHEMA_V1 = "allocatbelt.application-runtime-binding.v1"
RUNTIME_BINDING_SCHEMA_V2 = "allocatbelt.application-runtime-binding.v2"
RUNTIME_SOAK_SCHEMA_V2 = "allocatbelt.runtime-soak.v2"
SOAK_READBACK_SCHEMA_V2 = "allocatbelt.application-soak-readback.v2"
APPLICATION_ALLOCATOR_LABELS = ("allocatbelt", "mimalloc-secure", "mimalloc-standard", "system")
V5_EXECUTOR_LABELS = ("allocatbelt", "tokio-1.53.1")

SOAK_PARENT_IDENTITY_FIELDS = {
    "campaign_id", "host_id", "run_id", "nonce", "allocator", "executor", "workload",
    "profile", "comparison_family", "source_sha256", "build_sha256", "binary_sha256",
    "resource_ceiling_sha256",
}
SOAK_RECEIPT_CLOCK_PHASES = (
    "started", "trace_ended", "drain_ended", "shutdown_ended", "postprocess_ended",
)
SOAK_RECEIPT_CLOCK_FIELDS = {
    f"{phase}_monotonic_{bound}_ns"
    for phase in SOAK_RECEIPT_CLOCK_PHASES
    for bound in ("lower", "upper")
}
SOAK_RECEIPT_FIELDS_V2 = {
    "schema", "campaign_id", "host_id", "run_id", "nonce", "allocator", "executor", "workload",
    "profile", "comparison_family", "mode", "qualification_eligible", "source_sha256", "binary_sha256",
    "resource_ceiling_sha256", "reference_ring_sha256", "reference_ring_rows",
    "reference_average_rate_per_second", "duration_seconds", "sample_interval_ms", "warmup_seconds",
    "logical_window", "attempted", "completed", "errors", "lost", "terminal_records",
    "terminal_stream_sha256", "terminal_stream_relative_path", "resource_samples_count",
    "resource_samples_sha256", "resource_samples_relative_path", "first_post_warmup_hour_rss_median_kib",
    "final_hour_rss_median_kib", "feedback_started", "feedback_worker_joined", "feedback_worker_failure",
    "feedback_trace_worker_joined", "qualified_horizon", "started_monotonic_ns", "trace_ended_monotonic_ns",
    "drain_ended_monotonic_ns", "shutdown_ended_monotonic_ns", "postprocess_ended_monotonic_ns",
    "ended_monotonic_ns", "actual_trace_duration_ns", "drain_duration_ns", "shutdown_duration_ns",
    "postprocess_after_shutdown_ns", "production_cpu_started_ns", "production_cpu_ended_ns",
    "production_cpu_ns", "final_global_live_tenants", "final_global_cpu_used", "final_global_memory_used",
    "final_global_disk_used", "final_global_network_used", "final_global_tasks_used", "final_global_control_used",
    "fixed_global_control_baseline", "final_tenant_cpu_used", "final_tenant_memory_used", "final_tenant_disk_used",
    "final_tenant_network_used", "final_tenant_tasks_used", "final_tenant_control_used", "final_scope_memory_used",
    "final_scope_disk_used", "final_scope_network_used",
} | SOAK_RECEIPT_CLOCK_FIELDS
SOAK_READBACK_FIELDS_V2 = {
    "schema", "validated", "passed", "qualification_eligible", "mode", "identity",
    "source_manifest_sha256", "source_tree_sha256", "build_sha256", "candidate_binary_sha256",
    "resource_ceiling_sha256", "fixed_global_control_baseline", "receipt_sha256", "validator_sha256",
    "monotonic_endpoints",
}

MAX_EXPECTATION_BYTES = 2 * 1024 * 1024
MAX_SOURCE_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_PRESSURE_PROOF_BYTES = 256 * 1024
MAX_RUNTIME_BINDING_BYTES = 4 * 1024 * 1024
MAX_SOAK_BINDING_BYTES = 256 * 1024
MAX_CONSTRUCTION_PROBE_BYTES = 512 * 1024
MAX_PROBE_OUTPUT_BYTES = 512 * 1024
MAX_APP_BINARY_BYTES = 512 * 1024 * 1024
PROBE_CAPTURE_RECEIPT_SCHEMA = "allocatbelt.application-feedback-probe-capture.v2"
FEEDBACK_OFFLINE_CONTEXT_SCHEMA = "allocatbelt.application-feedback-offline-replay-context.v1"
FEEDBACK_CAPTURED_OFFLINE_CONTEXT_SCHEMA = "allocatbelt.application-feedback-captured-offline-replay-context.v1"
PRESSURE_CAPTURED_OFFLINE_CONTEXT_SCHEMA = "allocatbelt.application-source5-pressure-captured-replay.v1"
EVIDENCE_PATH_MAP_SCHEMA = "allocatbelt.application-pressure-evidence-path-map.v1"
PRESSURE_PAIR_REPLAY_REQUEST_SCHEMA = "allocatbelt.application-feedback-pressure-pair-replay-request.v1"
CAPACITY_REQUEST_SCHEMA_V1 = "allocatbelt.application-byte-capacity-request.v1"
CAPACITY_TRACE_FILES = (
    "feedback-trace-manifest.tsv", "feedback-events.jsonl", "resource-samples.tsv",
)
MAX_OFFLINE_PATH_MAP_ENTRIES = 16_384
MAX_OFFLINE_NESTED_JSON_BYTES = 256 * 1024 * 1024
MAX_PROBE_CAPTURE_RECEIPT_BYTES = 16 * 1024 * 1024
MAX_PROBE_OWNER_RESULT_BYTES = 16 * 1024 * 1024
MAX_PROBE_TMPDIR_INVENTORY_BYTES = 16 * 1024 * 1024
MAX_PROBE_CAPTURE_FAILURE_BYTES = 64 * 1024
PROBE_OWNER_RESULT_SCHEMA = "allocatbelt.application-feedback-probe-owner-result.v1"
PROBE_TMPDIR_INVENTORY_SCHEMA = "allocatbelt.application-feedback-probe-tmpdir-inventory.v1"
PROBE_CAPTURE_FAILURE_SCHEMA = "allocatbelt.application-feedback-probe-capture-failure.v1"
PROBE_CAPTURE_RECEIPT_FIELDS = {
    "schema", "source_manifest", "capacity_bundle", "capacity_tsv", "probe_pin", "binary", "observed_host",
    "origin_facts", "probe_argv", "environment", "cwd", "affinity", "netns", "capture_timeout_ns",
    "start_callback_count", "start_callback_proof", "start", "owner_result_pin",
    "tmpdir_inventory_pin", "stdout", "stderr", "exit_status", "output_matches_probe", "stderr_empty",
    "storage_budget", "output_mount", "tmpdir_initial", "tmpdir_final",
    "owner_modules", "qualification_eligible", "execution_ready", "controller_chronology_proven",
    "receipt_sha256",
}
DIRECT_CAPTURE_FIELDS = {
    "status", "child_return_code", "start", "binary_path", "binary_sha256", "binary_device",
    "binary_inode", "binary_size", "requested_argv", "requested_argv_sha256", "environment",
    "environment_sha256", "cwd", "cpu_affinity", "network_namespace_inode", "received_signal",
    "supervision", "timing", "started_monotonic_ns", "ended_monotonic_ns",
}
APP_CAPTURE_OWNER_START_FIELDS = {
    "pid", "start_ticks", "requested_argv", "requested_argv_sha256", "environment_sha256",
}
APP_CAPTURE_START_ROLE_FIELDS = {"schema", "role", "owner_proof", "start_sha256"}
PROBE_TERM_GRACE_SECONDS = 0.2
PROBE_KILL_GRACE_SECONDS = 1.0
PROBE_REAP_GRACE_SECONDS = 0.25
PROBE_POLL_INTERVAL_SECONDS = 0.01
PROBE_CLEANUP_TOTAL_SECONDS = (
    PROBE_TERM_GRACE_SECONDS + PROBE_KILL_GRACE_SECONDS + PROBE_REAP_GRACE_SECONDS
)
MAX_MANIFEST_BYTES = 64 * 1024
MAX_EVENT_FILE_BYTES = 1024 * 1024 * 1024
MAX_SAMPLE_FILE_BYTES = 1024 * 1024 * 1024
MAX_EVENT_LINE_BYTES = 2048
MAX_SAMPLE_LINE_BYTES = 8192
MAX_EVENT_RECORDS = 478_915
MAX_SAMPLE_ROWS = 114_002
MAX_TRACE_HORIZON_NS = 11_400_000_000_000
U64_MAX = (1 << 64) - 1
U128_MAX = (1 << 128) - 1
NSEC = 1_000_000_000

DOMAIN = ("cpu", "memory", "disk", "network", "tasks", "control")
RESOURCES = ("cpu", "disk", "download")
RATE_DIRECTIONS = ("disk", "upload", "download")
CONSTRUCTION_PROBE_SOURCE_REFERENCES = {
    "application_entrypoint": "bench/src/application.rs",
    "application_http": "bench/src/application/http.rs",
    "application_runtime_bindings": "bench/src/application/runtime_bindings.rs",
    "construction_policy_probe": "bench/src/application/feedback_policy_probe.rs",
    "disk_port_config": "crates/allocatbelt-app-ports/src/disk.rs",
    "feedback_trace_collector": "bench/src/application/feedback_trace.rs",
    "filesystem_rate_control": "crates/allocatbelt/src/runtime/fs_rate.rs",
    "http_port_config": "crates/allocatbelt-app-ports/src/http.rs",
    "memory_port_config": "crates/allocatbelt-app-ports/src/memory.rs",
    "rate_limited_io": "crates/allocatbelt/src/runtime/rate_io.rs",
    "resource_domain": "crates/allocatbelt/src/runtime/resource_domain.rs",
    "resource_feedback_policy": "crates/allocatbelt/src/runtime/resource_feedback_policy.rs",
}
CONSTRUCTION_PROBE_METER_SOURCE_MODEL = {
    "disk_registration_owner": "one shared FsRateControl owner; clones retain its single registration",
    "disk_source_path": "crates/allocatbelt/src/runtime/fs_rate.rs",
    "http_client_window_source": "bench/src/application.rs::WINDOW",
    "http_handler_window_source": "bench/src/application/http.rs::{CLIENT_TASKS,HANDLER_TASKS}",
    "http_registration_owner": "each client and accepted handler RateLimitedIo registers one read and one write meter source",
    "http_registration_source": "crates/allocatbelt/src/runtime/rate_io.rs::FeedbackMeters::new",
    "http_source_path": "bench/src/application/http.rs",
    "stream_registration_owner": "one registration for each endpoint direction while the adapter lives",
    "disk_registration_source": "crates/allocatbelt/src/runtime/fs_rate.rs::FsRateControl::new",
}
REQUIRED_PHASES = (
    "production_start", "production_end", "drain_end", "rss_before",
    "rss_after_drain", "shutdown_end", "rss_after_shutdown", "owner_release",
)

SAMPLE_HEADER = (
    "sample_sequence", "window_lower_ns", "window_upper_ns", "rss_kib", "hwm_kib",
    "collector_task_lease_count",
    *(f"global_{part}_{resource}" for resource in DOMAIN for part in ("ceiling", "limit", "used")),
    *(f"tenant_{part}_{resource}" for resource in DOMAIN for part in ("ceiling", "limit", "used")),
    "scope_managed_memory_limit", "scope_disk_operation_limit", "scope_network_operation_limit",
    "scope_managed_memory_used", "scope_disk_operations_used", "scope_network_operations_used",
    *(f"{direction}_rate_{field}" for direction in RATE_DIRECTIONS for field in (
        "bytes_per_second", "burst_bytes", "ceiling_bytes_per_second",
        "ceiling_burst_bytes", "max_reservations", "available_bytes",
        "reserved_bytes", "reservations",
    )),
    *(f"{direction}_meter_{field}" for direction in RATE_DIRECTIONS for field in (
        "measured_lower_ns", "measured_upper_ns", "committed_bytes", "completions",
        "attached_sources", "generation", "counter_overflow", "invalid_io",
        "source_count_overflow", "generation_overflow",
    )),
    "feedback_sample_count", "feedback_stop_requested", "feedback_shutdown_complete",
    "feedback_worker_failure",
    *(f"{resource}_{field}" for resource in RESOURCES for field in (
        "current_limit", "utilization_basis_points", "telemetry", "policy_faulted",
        "pending_generation", "no_change",
    )),
)


class ValidationError(ValueError):
    """A pinned expectation or trace artifact fails validation."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def canonical_bytes(value: object) -> bytes:
    try:
        text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValidationError(f"value is not canonical JSON: {error}") from error
    return (text + "\n").encode("ascii")


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest_object(value: object) -> str:
    return sha256_bytes(canonical_bytes(value))


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValidationError(f"non-finite JSON value is forbidden: {value}")


def parse_json(raw: bytes, label: str, maximum: int) -> dict[str, Any]:
    require(len(raw) <= maximum, f"{label} exceeds its byte bound")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValidationError(f"{label} is not bounded UTF-8 JSON: {error}") from error
    require(type(value) is dict, f"{label} must be one JSON object")
    return value


def exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == keys, f"{label} has an unexpected key set")
    return value


def uint(value: object, label: str, *, positive: bool = False, maximum: int = U64_MAX) -> int:
    require(type(value) is int and 0 <= value <= maximum, f"{label} must be an unsigned integer")
    require(not positive or value > 0, f"{label} must be positive")
    return value


def text(value: object, label: str, maximum: int = 512) -> str:
    require(type(value) is str and 0 < len(value) <= maximum, f"{label} must be a bounded string")
    require(not any(ord(char) < 32 or ord(char) == 127 for char in value), f"{label} contains a control character")
    return value


def digest(value: object, label: str) -> str:
    result = text(value, label, 64)
    require(re.fullmatch(r"[0-9a-f]{64}", result) is not None, f"{label} must be lowercase SHA-256")
    return result


def validate_probe_capture_receipt_envelope(
    raw: object, expected_raw_sha256: object, expected_receipt_sha256: object,
) -> dict[str, Any]:
    """Validate raw and semantic digest roles for one closed ProbeV2 receipt envelope."""
    require(type(raw) is bytes, "ProbeV2 capture envelope must be raw bytes")
    expected_raw = digest(expected_raw_sha256, "ProbeV2 capture envelope raw SHA-256")
    expected_semantic = digest(expected_receipt_sha256, "ProbeV2 capture envelope semantic SHA-256")
    require(len(raw) <= MAX_PROBE_CAPTURE_RECEIPT_BYTES,
            "ProbeV2 capture envelope exceeds its finite byte bound")
    actual_raw = sha256_bytes(raw)
    require(actual_raw == expected_raw,
            "ProbeV2 capture envelope raw SHA-256 differs from its pin")
    receipt = parse_json(raw, "ProbeV2 capture receipt", MAX_PROBE_CAPTURE_RECEIPT_BYTES)
    require(canonical_bytes(receipt) == raw,
            "ProbeV2 capture receipt is not canonical JSON")
    exact(receipt, PROBE_CAPTURE_RECEIPT_FIELDS, "ProbeV2 capture receipt")
    body = {key: item for key, item in receipt.items() if key != "receipt_sha256"}
    require(receipt["schema"] == PROBE_CAPTURE_RECEIPT_SCHEMA and
            digest(receipt["receipt_sha256"], "ProbeV2 capture receipt digest") ==
            expected_semantic == digest_object(body) and
            receipt["qualification_eligible"] is False and
            receipt["execution_ready"] is False and
            receipt["controller_chronology_proven"] is False,
            "ProbeV2 capture receipt schema, semantic digest or eligibility flags differ")
    return receipt


def absolute_path(value: object, label: str) -> Path:
    raw = text(value, label, 4096)
    path = Path(raw)
    require(path.is_absolute() and str(path) == raw and ".." not in PurePosixPath(raw).parts, f"{label} must be a normalized absolute path")
    return path


def _stat_key(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_stable(
    path: Path, label: str, maximum: int, *, artifact_view: Any = None,
) -> tuple[bytes, str]:
    if artifact_view is not None:
        require(artifact_view.has_file(path), f"{label} is absent from the exact captured refs")
        raw, checksum = artifact_view.read(path, label, maximum)
        require(type(raw) is bytes and len(raw) <= maximum and
                digest(checksum, f"{label} captured raw digest") == sha256_bytes(raw),
                f"{label} captured bytes differ from their raw digest or bound")
        return raw, checksum
    try:
        require(path.resolve(strict=True) == path, f"{label} traverses a symlink or alias")
        before_path = path.lstat()
        require(stat.S_ISREG(before_path.st_mode) and before_path.st_uid == os.getuid(),
                f"{label} must be an owned regular nonsymlink file")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as error:
        raise ValidationError(f"cannot safely open {label}: {error}") from error
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and _stat_key(before) == _stat_key(before_path), f"{label} changed while opening")
        require(0 <= before.st_size <= maximum, f"{label} exceeds its hard byte cap")
        raw = bytearray()
        while len(raw) < before.st_size:
            block = os.read(fd, min(1024 * 1024, before.st_size - len(raw)))
            require(block, f"{label} was truncated during readback")
            raw.extend(block)
        after_fd, after_path = os.fstat(fd), path.lstat()
        require(_stat_key(before) == _stat_key(after_fd) == _stat_key(after_path), f"{label} changed during readback")
        return bytes(raw), sha256_bytes(raw)
    finally:
        os.close(fd)


def read_canonical(
    path: Path, label: str, maximum: int, expected_sha: str | None = None,
    *, artifact_view: Any = None,
) -> tuple[dict[str, Any], str]:
    if artifact_view is None:
        raw, raw_sha = read_stable(path, label, maximum)
    else:
        raw, raw_sha = read_stable(path, label, maximum, artifact_view=artifact_view)
    value = parse_json(raw, label, maximum)
    require(raw == canonical_bytes(value), f"{label} is not canonical JSON")
    if expected_sha is not None:
        require(raw_sha == expected_sha, f"{label} raw SHA-256 differs from caller pin")
    return value, raw_sha


def _open_trace_directory(path: Path) -> int:
    try:
        require(path.resolve(strict=True) == path, "trace directory traverses a symlink or alias")
        before = path.lstat()
        require(stat.S_ISDIR(before.st_mode), "trace root must be a real directory")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError as error:
        raise ValidationError(f"cannot safely open trace directory: {error}") from error
    after = os.fstat(fd)
    require(stat.S_ISDIR(after.st_mode) and _stat_key(before)[:3] == _stat_key(after)[:3], "trace directory changed while opening")
    return fd


TRACE_FILES = frozenset({
    "feedback-trace-manifest.tsv", "feedback-events.jsonl", "resource-samples.tsv",
})


def _validate_trace_directory_layout(directory_fd: int) -> None:
    """Bound directory inspection and require exactly three regular files."""
    names: set[str] = set()
    try:
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                require(len(names) < len(TRACE_FILES), "feedback trace directory has more than three entries")
                require(entry.name in TRACE_FILES, "feedback trace directory has an unexpected entry")
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError as error:
                    raise ValidationError(f"cannot inspect feedback trace entry {entry.name}: {error}") from error
                require(stat.S_ISREG(info.st_mode), f"feedback trace entry {entry.name} must be a regular nonsymlink file")
                names.add(entry.name)
    except OSError as error:
        raise ValidationError(f"cannot enumerate feedback trace directory: {error}") from error
    require(names == TRACE_FILES, "feedback trace directory has missing or unexpected files")


class BoundedLines:
    """One anchored regular file read, hashed while bounded lines are consumed."""

    def __init__(self, directory_fd: int, name: str, label: str, maximum_bytes: int, maximum_line: int):
        require(name in {"feedback-trace-manifest.tsv", "feedback-events.jsonl", "resource-samples.tsv"}, f"invalid anchored trace filename for {label}")
        self.name, self.label, self.maximum_line = name, label, maximum_line
        try:
            self.fd = os.open(name, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0), dir_fd=directory_fd)
        except OSError as error:
            raise ValidationError(f"cannot safely open {label}: {error}") from error
        self.before = os.fstat(self.fd)
        require(stat.S_ISREG(self.before.st_mode) and 0 <= self.before.st_size <= maximum_bytes, f"{label} is not a bounded regular file")
        self.byte_count = self.before.st_size
        self.maximum_bytes = maximum_bytes
        self.hash = hashlib.sha256()
        self.bytes_read = 0
        self.lines = 0

    def __enter__(self) -> "BoundedLines":
        return self

    def __exit__(self, *_: object) -> None:
        os.close(self.fd)

    def __iter__(self) -> Iterator[bytes]:
        with os.fdopen(os.dup(self.fd), "rb", buffering=0) as stream:
            while True:
                line = stream.readline(self.maximum_line + 1)
                if not line:
                    break
                require(len(line) <= self.maximum_line, f"{self.label} contains an oversized line")
                require(line.endswith(b"\n"), f"{self.label} has a partial final record")
                require(b"\r" not in line and b"\x00" not in line, f"{self.label} has invalid framing")
                self.bytes_read += len(line)
                require(self.bytes_read <= self.maximum_bytes, f"{self.label} exceeded its byte bound while reading")
                self.lines += 1
                self.hash.update(line)
                yield line[:-1]

    def finish(self, directory_fd: int) -> str:
        after_fd = os.fstat(self.fd)
        after_path = os.stat(self.name, dir_fd=directory_fd, follow_symlinks=False)
        require(_stat_key(self.before) == _stat_key(after_fd) == _stat_key(after_path), f"{self.label} changed during streaming read")
        require(self.bytes_read == self.before.st_size, f"{self.label} size differs from bytes consumed")
        return self.hash.hexdigest()


class CapturedBoundedLines:
    """Consume one exact captured trace stream; metadata describes no origin stat."""

    def __init__(
        self, origin: Path, label: str, maximum_bytes: int, maximum_line: int,
        artifact_view: Any,
    ):
        require(origin.name in TRACE_FILES, f"invalid captured trace filename for {label}")
        require(artifact_view.has_file(origin), f"{label} is absent from the exact captured refs")
        self.label, self.maximum_bytes, self.maximum_line = label, maximum_bytes, maximum_line
        self._snapshot = artifact_view.open_snapshot(origin, label, maximum_bytes)
        self._stream = None
        self._entered = False
        self.byte_count = 0
        self.bytes_read = 0
        self.lines = 0
        self.hash = hashlib.sha256()
        self._expected_sha = None

    def __enter__(self) -> "CapturedBoundedLines":
        try:
            self._stream, checksum, size = self._snapshot.__enter__()
            self._entered = True
            require(type(size) is int and 0 <= size <= self.maximum_bytes,
                    f"{self.label} captured stream exceeds its reader byte bound")
            self._expected_sha = digest(checksum, f"{self.label} captured stream raw SHA-256")
            self.byte_count = size
            return self
        except BaseException:
            if self._entered:
                self._snapshot.__exit__(*sys.exc_info())
            raise

    def __exit__(self, *error: object) -> None:
        self._snapshot.__exit__(*error)

    def __iter__(self) -> Iterator[bytes]:
        require(self._stream is not None, f"{self.label} captured stream is not open")
        while True:
            line = self._stream.readline(self.maximum_line + 1)
            if not line:
                break
            require(type(line) is bytes and len(line) <= self.maximum_line,
                    f"{self.label} contains an oversized line")
            require(line.endswith(b"\n"), f"{self.label} has a partial final record")
            require(b"\r" not in line and b"\x00" not in line,
                    f"{self.label} has invalid framing")
            self.bytes_read += len(line)
            require(self.bytes_read <= self.maximum_bytes,
                    f"{self.label} exceeded its byte bound while reading")
            self.lines += 1
            self.hash.update(line)
            yield line[:-1]

    def finish(self, _directory_fd: int | None = None) -> str:
        require(self._stream is not None and self.bytes_read == self.byte_count,
                f"{self.label} size differs from bytes consumed")
        checksum = self.hash.hexdigest()
        require(checksum == self._expected_sha,
                f"{self.label} captured stream differs from its exact raw digest")
        return checksum


def build_pressure_expectation_recipe(spec: object) -> tuple[bytes, str]:
    """Return canonical expectation bytes and raw SHA-256 for a frozen spec."""
    require(type(spec) is dict and "recipe_sha256" not in spec, "expectation spec must omit recipe_sha256")
    _validate_expectation_body(spec)
    raw_body = canonical_bytes(spec)
    value = dict(spec)
    value["recipe_sha256"] = sha256_bytes(raw_body)
    raw = canonical_bytes(value)
    return raw, sha256_bytes(raw)


def _validate_expectation_body(value: object) -> dict[str, Any]:
    require(type(value) is dict, "feedback expectation must be one JSON object")
    schema = value.get("schema")
    require(
        schema in (EXPECTATION_SCHEMA_V1, EXPECTATION_SCHEMA_V2, EXPECTATION_SCHEMA_V3, EXPECTATION_SCHEMA_V4, EXPECTATION_SCHEMA_V5, EXPECTATION_SCHEMA_V6),
        "unsupported feedback expectation schema",
    )
    expectation_v2 = schema in (EXPECTATION_SCHEMA_V2, EXPECTATION_SCHEMA_V3, EXPECTATION_SCHEMA_V4, EXPECTATION_SCHEMA_V5, EXPECTATION_SCHEMA_V6)
    expectation_v3 = schema == EXPECTATION_SCHEMA_V3
    expectation_v4 = schema == EXPECTATION_SCHEMA_V4
    expectation_v5 = schema in (EXPECTATION_SCHEMA_V5, EXPECTATION_SCHEMA_V6)
    expectation_v6 = schema == EXPECTATION_SCHEMA_V6
    recipe_keys = {
        "schema", "mode", "identity", "policy", "app_capacity_artifact_sha256",
        "host_binding", "external_pressure_proof", "final_runtime_binding",
        "minimum_production_seconds", "minimum_pressure_overlap_seconds",
    }
    if expectation_v2:
        recipe_keys.add("construction_probe")
    if expectation_v3:
        recipe_keys.add("external_soak_identity")
    if expectation_v5:
        recipe_keys.add("app_capacity_artifact")
    recipe = exact(value, recipe_keys, "feedback expectation")
    if expectation_v3:
        require(recipe["mode"] == "pressure_soak_validation", "expectation v3 requires pressure_soak_validation mode")
    elif expectation_v4:
        require(recipe["mode"] == "capacity_calibration", "expectation v4 requires capacity_calibration mode")
    elif expectation_v5:
        require(recipe["mode"] == "pressure_validation", "expectation v5 requires pressure_validation mode")
    else:
        require(recipe["mode"] in ("capacity_calibration", "pressure_validation"), "unsupported expectation mode")
    identity = exact(recipe["identity"], {
        "host_id", "run_id", "report_nonce", "process_id", "allocator", "executor",
        "workload", "profile", "mode", "source_sha256", "binary_sha256",
        "pressure_qualification",
    }, "feedback identity")
    for key in ("host_id", "run_id", "allocator", "executor", "workload", "profile", "mode"):
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", text(identity[key], f"identity.{key}")) is not None, f"identity.{key} is not a canonical token")
    require(re.fullmatch(r"[0-9a-f]{32}", text(identity["report_nonce"], "identity.report_nonce", 32)) is not None, "identity.report_nonce must be 32 lowercase hexadecimal characters")
    uint(identity["process_id"], "identity.process_id", positive=True, maximum=(1 << 31) - 1)
    digest(identity["source_sha256"], "identity.source_sha256")
    digest(identity["binary_sha256"], "identity.binary_sha256")
    require(type(identity["pressure_qualification"]) is bool, "identity.pressure_qualification must be boolean")
    if expectation_v5:
        require(identity["allocator"] in APPLICATION_ALLOCATOR_LABELS, "expectation v5 allocator is outside the original application artifact set")
        require(identity["executor"] in V5_EXECUTOR_LABELS, "expectation v5 executor is outside the original native/Tokio role set")
    if expectation_v2:
        _validate_v2_workload_profile(identity["workload"], identity["profile"])
        construction_probe = exact(recipe["construction_probe"], {
            "path", "raw_sha256", "allocator", "binary_sha256",
        }, "construction policy probe pin")
        absolute_path(construction_probe["path"], "construction policy probe path")
        require(
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", text(construction_probe["allocator"], "construction probe allocator")) is not None,
            "construction probe allocator is not a canonical token",
        )
        digest(construction_probe["raw_sha256"], "construction policy probe raw SHA-256")
        digest(construction_probe["binary_sha256"], "construction probe binary SHA-256")
        require(construction_probe["allocator"] == identity["allocator"], "construction probe allocator differs from feedback identity")
        if expectation_v3:
            require(construction_probe["binary_sha256"] != identity["binary_sha256"], "construction probe application binary must differ from the timed soak binary")
        else:
            require(construction_probe["binary_sha256"] == identity["binary_sha256"], "construction probe binary differs from feedback identity")

    if expectation_v3:
        soak_identity = exact(recipe["external_soak_identity"], set(SOAK_PARENT_IDENTITY_FIELDS), "external soak identity")
        for key in ("campaign_id", "host_id", "run_id", "allocator", "executor", "workload", "profile", "comparison_family"):
            require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", text(soak_identity[key], f"external_soak_identity.{key}")) is not None, f"external_soak_identity.{key} is not a canonical token")
        require(re.fullmatch(r"[0-9a-f]{32}", text(soak_identity["nonce"], "external_soak_identity.nonce", 32)) is not None, "external soak nonce must be 32 lowercase hexadecimal characters")
        for key in ("source_sha256", "build_sha256", "binary_sha256", "resource_ceiling_sha256"):
            digest(soak_identity[key], f"external_soak_identity.{key}")
        require(identity["allocator"] == "allocatbelt" and soak_identity["allocator"] == "allocatbelt", "pressure-soak validation supports only the allocatbelt artifact role")
        require(identity["executor"] == "allocatbelt" and soak_identity["executor"] == "bounded", "pressure-soak validation requires the explicit bounded-to-allocatbelt executor role mapping")
        require(identity["workload"] == "mixed" and soak_identity["workload"] == "mixed", "pressure-soak validation requires the mixed workload role")
        require(identity["mode"] == "soak", "pressure-soak feedback trace must carry the soak run mode")
        require(identity["profile"] == soak_identity["profile"], "external soak profile differs from the feedback trace profile")
        require(soak_identity["comparison_family"] == "external_pressure", "external soak identity is not the external-pressure role")
        require(soak_identity["host_id"] == identity["host_id"] and soak_identity["source_sha256"] == identity["source_sha256"], "external soak host or source differs from feedback identity")
        require(soak_identity["run_id"] == identity["run_id"] and soak_identity["nonce"] == identity["report_nonce"], "external soak run ID or nonce differs from the feedback trace")
        require(soak_identity["binary_sha256"] == identity["binary_sha256"], "external soak binary differs from the timed feedback trace executable")

    policy_keys = {
        "version", "sample_interval_ns", "max_dense_gap_ns", "telemetry_freshness_ns",
        "required_breach_samples", "actuation_cooldown_ns", "minimum_dense_observations",
        "controls", "capacity_sources", "global_ceilings", "tenant_ceilings", "scope_limits",
        "rate_buckets", "collector",
    }
    policy_keys.add("meter_source_bounds" if expectation_v2 else "meter_sources")
    if expectation_v6:
        policy_keys.update({"capacity_floor_policy_id", "capacity_floor_policy"})
    policy = exact(recipe["policy"], policy_keys, "feedback policy expectation")
    selected_floor_policy_id = policy.get("capacity_floor_policy_id")
    if selected_floor_policy_id is not None:
        descriptor = _validate_capacity_floor_policy_descriptor(
            policy.get("capacity_floor_policy"),
        )
        require(selected_floor_policy_id == descriptor["policy_id"] == CAPACITY_FLOOR_POLICY_ID,
                "feedback expectation floor policy ID differs from its source-published descriptor")
        require(recipe["mode"] == "pressure_validation" and
                identity["pressure_qualification"] is True,
                "capacity-relative floors require the explicit external-pressure opt-in")
    require(policy["version"] == "runtime-feedback-policy-v1", "unsupported feedback policy version")
    for key, expected in (("sample_interval_ns", 100_000_000), ("max_dense_gap_ns", 200_000_000),
                          ("telemetry_freshness_ns", 500_000_000), ("required_breach_samples", 3),
                          ("actuation_cooldown_ns", NSEC), ("minimum_dense_observations", 1)):
        require(uint(policy[key], f"policy.{key}", positive=True) == expected, f"policy.{key} differs from the fixed runtime contract")
    controls = exact(policy["controls"], set(RESOURCES), "control set")
    for resource in RESOURCES:
        control = exact(controls[resource], {"floor", "initial", "ceiling", "low_bps", "high_bps"}, f"{resource} control")
        floor = uint(control["floor"], f"{resource}.floor", positive=True)
        initial = uint(control["initial"], f"{resource}.initial", positive=True, maximum=(1 << 32) - 1 if resource == "cpu" else U64_MAX)
        ceiling = uint(control["ceiling"], f"{resource}.ceiling", positive=True, maximum=(1 << 32) - 1 if resource == "cpu" else U64_MAX)
        low = uint(control["low_bps"], f"{resource}.low_bps", maximum=10_000)
        high = uint(control["high_bps"], f"{resource}.high_bps", positive=True, maximum=10_000)
        require(floor <= initial <= ceiling and low < high, f"{resource} control bounds or hysteresis are invalid")
    capacity_sources = exact(policy["capacity_sources"], {"disk", "download"}, "application byte-capacity sources")
    for direction, available in capacity_sources.items():
        require(type(available) is bool, f"{direction} capacity-source availability must be boolean")
    global_ceilings = _uint_map(policy["global_ceilings"], set(DOMAIN), "global ceilings")
    tenant_ceilings = _uint_map(policy["tenant_ceilings"], set(DOMAIN), "tenant ceilings")
    if not expectation_v2:
        for owner, ceilings in (("global", global_ceilings), ("tenant", tenant_ceilings)):
            require(all(value > 0 for value in ceilings.values()), f"{owner} domain ceilings must be positive")
    scope_limits = _uint_map(
        policy["scope_limits"], {"managed_memory", "disk_operations", "network_operations"},
        "scope limits", positive=not expectation_v2,
    )
    buckets = exact(policy["rate_buckets"], set(RATE_DIRECTIONS), "rate bucket set")
    for direction, item in buckets.items():
        bucket_keys = {"ceiling_bytes_per_second", "ceiling_burst_bytes", "max_reservations"}
        if expectation_v5:
            bucket_keys.add("initial_bytes_per_second")
        item = exact(item, bucket_keys, f"{direction} bucket")
        for name in item:
            uint(item[name], f"{direction}.{name}", positive=True)
    if expectation_v2:
        _validate_meter_source_bounds(policy["meter_source_bounds"], identity["workload"])
    else:
        meter_sources = exact(policy["meter_sources"], set(RATE_DIRECTIONS), "legacy meter source counts")
        for direction, value in meter_sources.items():
            uint(value, f"{direction} attached meter sources")
    collector = exact(policy["collector"], {
        "task_lease_count", "control_charge_bytes", "expected_global_control_baseline",
    }, "collector accounting")
    require(uint(collector["task_lease_count"], "collector task lease", positive=True) == 1, "unsupported collector task lease")
    uint(collector["control_charge_bytes"], "collector Control charge", positive=True)
    uint(collector["expected_global_control_baseline"], "global Control baseline")

    app_capacity = recipe["app_capacity_artifact_sha256"]
    if expectation_v5:
        capacity_pin = exact(recipe["app_capacity_artifact"], {"path", "raw_sha256"}, "V5 application capacity artifact pin")
        absolute_path(capacity_pin["path"], "V5 application capacity artifact path")
        digest(capacity_pin["raw_sha256"], "V5 application capacity artifact raw SHA-256")
        require(app_capacity == capacity_pin["raw_sha256"], "V5 capacity artifact digest fields disagree")
    if recipe["mode"] == "capacity_calibration":
        require(app_capacity is None, "capacity calibration must not depend on app-byte denominators")
        require(capacity_sources == {"disk": False, "download": False}, "capacity calibration must freeze missing application-byte denominators")
        require(recipe["external_pressure_proof"] is None and recipe["final_runtime_binding"] is None, "calibration mode cannot carry qualification proofs")
        require(identity["pressure_qualification"] is False, "capacity calibration identity must not claim pressure qualification")
        cpu = controls["cpu"]
        require(cpu["initial"] in (2, 4) and cpu["ceiling"] == cpu["initial"], "capacity calibration CPU control must be pinned at 2 or 4 slots")
        for resource in ("disk", "download"):
            require(controls[resource]["ceiling"] >= controls[resource]["initial"], f"{resource} policy bounds are invalid")
    else:
        digest(app_capacity, "app_capacity_artifact_sha256")
        proof = exact(recipe["external_pressure_proof"], {"path", "raw_sha256", "validator_sha256", "recipe_raw_sha256"}, "external pressure proof pin")
        absolute_path(proof["path"], "pressure proof path")
        digest(proof["raw_sha256"], "pressure proof raw SHA-256")
        digest(proof["validator_sha256"], "pressure validator SHA-256")
        digest(proof["recipe_raw_sha256"], "pressure recipe raw SHA-256")
        if expectation_v3:
            binding = exact(recipe["final_runtime_binding"], {"soak_receipt", "soak_readback"}, "v3 final runtime binding")
            for key, label in (("soak_receipt", "Rust soak receipt"), ("soak_readback", "audited soak readback")):
                pin = exact(binding[key], {"path", "raw_sha256"}, f"{label} pin")
                absolute_path(pin["path"], f"{label} path")
                digest(pin["raw_sha256"], f"{label} raw SHA-256")
            require(identity["pressure_qualification"] is True, "pressure-soak validation identity must request pressure qualification")
        else:
            runtime = exact(recipe["final_runtime_binding"], {"path", "raw_sha256"}, "final runtime binding pin")
            absolute_path(runtime["path"], "runtime binding path")
            digest(runtime["raw_sha256"], "runtime binding raw SHA-256")
            require(identity["pressure_qualification"] is True, "pressure validation identity must request pressure qualification")
    uint(recipe["minimum_production_seconds"], "minimum production duration", positive=True, maximum=10_800)
    uint(recipe["minimum_pressure_overlap_seconds"], "minimum pressure overlap", maximum=10_800)
    if recipe["mode"] == "capacity_calibration":
        require(recipe["minimum_pressure_overlap_seconds"] == 0, "capacity calibration has no pressure overlap threshold")
    else:
        require(recipe["minimum_pressure_overlap_seconds"] > 0, "pressure validation requires a positive overlap threshold")
    host_binding = exact(recipe["host_binding"], {"path", "raw_sha256"}, "source-manifest host binding")
    absolute_path(host_binding["path"], "source manifest path")
    digest(host_binding["raw_sha256"], "source manifest raw SHA-256")
    return recipe


def _uint_map(value: object, keys: set[str], label: str, *, positive: bool = False) -> dict[str, int]:
    result = exact(value, keys, label)
    for key, item in result.items():
        uint(item, f"{label}.{key}", positive=positive)
    return result


def meter_source_bounds_for_workload(workload: str) -> dict[str, dict[str, object]]:
    """Return the source-derived registration ceiling for a frozen workload."""
    require(workload in ("cpu", "memory", "http", "disk", "mixed"), "unsupported construction probe workload")
    disk_enabled = workload in ("disk", "mixed")
    http_enabled = workload in ("http", "mixed")
    return {
        "disk": {
            "minimum_live": 0,
            "maximum_live": 1 if disk_enabled else 0,
            "source_rule": "disk_shared_owner" if disk_enabled else "not_applicable",
            "lifetime": "registered_endpoint_owner",
        },
        "upload": {
            "minimum_live": 0,
            "maximum_live": 16 if http_enabled else 0,
            "source_rule": "http_client_and_server_window" if http_enabled else "not_applicable",
            "lifetime": "registered_endpoint_owner",
        },
        "download": {
            "minimum_live": 0,
            "maximum_live": 16 if http_enabled else 0,
            "source_rule": "http_client_and_server_window" if http_enabled else "not_applicable",
            "lifetime": "registered_endpoint_owner",
        },
    }


def _validate_v2_workload_profile(workload: object, profile: object) -> None:
    require(type(workload) is str and workload in ("cpu", "memory", "http", "disk", "mixed"), "v2 expectation workload is outside the frozen 15-context matrix")
    valid_profiles = ("mixed", "burst", "oversubscribed") if workload == "mixed" else ("steady", "burst", "oversubscribed")
    require(type(profile) is str and profile in valid_profiles, "v2 expectation workload/profile pair is outside the frozen 15-context matrix")


def _validate_meter_source_bounds(
    value: object, workload: str, label: str = "meter source bounds",
) -> dict[str, dict[str, Any]]:
    expected_bounds = meter_source_bounds_for_workload(workload)
    bounds = exact(value, set(RATE_DIRECTIONS), label)
    validated: dict[str, dict[str, Any]] = {}
    for direction, expected in expected_bounds.items():
        bound = exact(bounds[direction], {
            "minimum_live", "maximum_live", "source_rule", "lifetime",
        }, f"{label}.{direction}")
        minimum = uint(bound["minimum_live"], f"{direction} minimum live meter sources")
        maximum = uint(bound["maximum_live"], f"{direction} maximum live meter sources", maximum=(1 << 32) - 1)
        require(minimum == expected["minimum_live"], f"{direction} minimum live meter sources differ from the source-derived bound")
        require(maximum == expected["maximum_live"], f"{direction} maximum live meter sources differ from the source-derived bound")
        require(bound["source_rule"] == expected["source_rule"], f"{direction} meter source rule differs from the workload")
        require(bound["lifetime"] == "registered_endpoint_owner", f"{direction} meter source lifetime is unsupported")
        validated[direction] = bound
    return validated


def _validate_capacity_floor_policy_descriptor(value: object) -> dict[str, Any]:
    descriptor = exact(value, {
        "capacity_divisor", "minimum_floor_bytes_per_second", "policy_id",
        "probe_activation", "rule", "rule_version", "runtime_activation",
        "static_floor_bytes_per_second", "static_rate_roof_bytes_per_second",
    }, "SourceV5 calibrated capacity-floor policy")
    numeric = {
        "capacity_divisor": CAPACITY_FLOOR_DIVISOR,
        "minimum_floor_bytes_per_second": CAPACITY_FLOOR_MINIMUM_BYTES_PER_SECOND,
        "static_floor_bytes_per_second": CAPACITY_RATE_FLOOR,
        "static_rate_roof_bytes_per_second": CAPACITY_RATE_ROOF,
    }
    for field, expected in numeric.items():
        require(uint(descriptor[field], f"capacity floor policy {field}", positive=True) == expected,
                f"capacity floor policy {field} differs from the independent reader contract")
    require(descriptor["policy_id"] == CAPACITY_FLOOR_POLICY_ID and
            descriptor["probe_activation"] == CAPACITY_FLOOR_PROBE_ACTIVATION and
            descriptor["rule"] == CAPACITY_FLOOR_RULE and
            descriptor["rule_version"] == CAPACITY_RESOLUTION_VERSION and
            descriptor["runtime_activation"] == CAPACITY_FLOOR_RUNTIME_ACTIVATION,
            "capacity floor policy ID, arithmetic, or activation differs from the independent reader contract")
    return descriptor


def _source_v5_base_feedback_policy(
    recipe: dict[str, Any], source_manifest_value: dict[str, Any], probe: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], int]:
    """Derive static controls and accounting from the verified SourceV5 inputs."""
    identity = recipe["identity"]
    feedback_artifact = exact(
        source_manifest_value["feedback_policy"],
        {"schema", "policy", "policy_sha256"},
        "SourceV5 feedback policy artifact",
    )
    require(feedback_artifact["schema"] in (
        "allocatbelt.application-feedback-policy-artifact.v1",
        "allocatbelt.application-feedback-policy-artifact.v2",
    ), "unsupported SourceV5 feedback policy artifact schema")
    feedback_body_keys = {
        "schema", "version", "reader_contract", "algorithm", "contexts", "source_pins",
    }
    if feedback_artifact["schema"] == "allocatbelt.application-feedback-policy-artifact.v2":
        feedback_body_keys.add("capacity_floor_policy")
    feedback_body = exact(feedback_artifact["policy"], feedback_body_keys,
                          "SourceV5 feedback policy body")
    require(feedback_body["schema"] == feedback_artifact["schema"] and
            digest(feedback_artifact["policy_sha256"], "SourceV5 feedback policy digest") ==
            digest_object(feedback_body),
            "SourceV5 feedback policy artifact/body schema or digest differs")
    if "capacity_floor_policy" in feedback_body:
        _validate_capacity_floor_policy_descriptor(feedback_body["capacity_floor_policy"])
    context_key = f"{identity['workload']}/{identity['profile']}"
    contexts = feedback_body["contexts"]
    require(type(contexts) is dict and context_key in contexts, "SourceV5 feedback policy omits the V4 workload/profile context")
    context = exact(contexts[context_key], {"workers", "minimum_dense_observations", "controls"}, "SourceV5 V4 feedback context")
    workers = uint(context["workers"], "SourceV5 V4 worker count", positive=True, maximum=4)
    require(workers == (2 if identity["profile"] == "oversubscribed" else 4), "SourceV5 V4 worker count differs from the frozen profile")

    fixed_artifact = exact(
        source_manifest_value["fixed_runtime_policy"],
        {"schema", "policy", "policy_sha256"},
        "SourceV5 fixed runtime policy artifact",
    )
    fixed_body = exact(fixed_artifact["policy"], {
        "schema", "comparison_family", "resource_policy", "logical_window", "task_ceiling",
        "workers_by_profile", "workloads", "byte_buckets", "kernel",
    }, "SourceV5 fixed runtime policy body")
    worker_policy = exact(fixed_body["workers_by_profile"], {"ordinary", "oversubscribed"}, "SourceV5 fixed worker policy")
    require(worker_policy == {"ordinary": 4, "oversubscribed": 2}, "SourceV5 fixed worker policy differs from the V4 context contract")
    workloads = fixed_body["workloads"]
    require(type(workloads) is dict and identity["workload"] in workloads, "SourceV5 fixed policy omits the V4 workload")
    fixed_workload = exact(workloads[identity["workload"]], {"domain_ceiling", "scope_limits"}, "SourceV5 fixed workload policy")
    global_ceilings = dict(_uint_map(fixed_workload["domain_ceiling"], set(DOMAIN), "SourceV5 fixed domain ceilings"))
    require(global_ceilings["cpu"] == worker_policy["ordinary"], "SourceV5 ordinary CPU ceiling differs from its fixed worker policy")
    global_ceilings["cpu"] = workers
    tenant_ceilings = dict(global_ceilings)

    fixed_scope = exact(fixed_workload["scope_limits"], {
        "managed_memory_limit", "disk_operation_limit", "network_operation_limit",
    }, "SourceV5 fixed scope limits")
    for name, value in fixed_scope.items():
        uint(value, f"SourceV5 fixed scope limit {name}")
    scope_limits = {
        "managed_memory": fixed_scope["managed_memory_limit"],
        "disk_operations": fixed_scope["disk_operation_limit"],
        "network_operations": fixed_scope["network_operation_limit"],
    }

    source_buckets = exact(fixed_body["byte_buckets"], set(RATE_DIRECTIONS), "SourceV5 fixed byte buckets")
    rate_buckets: dict[str, dict[str, int]] = {}
    for direction in RATE_DIRECTIONS:
        source_bucket = exact(source_buckets[direction], {
            "bytes_per_second", "ceiling_bytes_per_second", "burst_bytes",
            "ceiling_burst_bytes", "max_reservations",
        }, f"SourceV5 fixed {direction} byte bucket")
        for name, value in source_bucket.items():
            uint(value, f"SourceV5 fixed {direction} bucket {name}", positive=True)
        rate_buckets[direction] = {
            "ceiling_bytes_per_second": source_bucket["ceiling_bytes_per_second"],
            "ceiling_burst_bytes": source_bucket["ceiling_burst_bytes"],
            "max_reservations": source_bucket["max_reservations"],
        }

    calibration = exact(source_manifest_value["resource_domain_calibration"], {
        "binary", "output", "record", "source", "build", "build_sha256",
    }, "SourceV5 resource-domain calibration")
    calibration_record = exact(calibration["record"], {
        "schema", "architecture", "max_tenants", "max_waiters", "control_ceiling",
        "fixed_global_control_baseline", "tenant_owner_control_bytes", "final_live_tenants",
        "final_global_control_bytes",
    }, "SourceV5 resource-domain calibration record")
    baseline = uint(calibration_record["fixed_global_control_baseline"], "SourceV5 calibrated global Control baseline", positive=True)

    collector_probe = exact(probe["collector"], {"control_charge_bytes", "task_lease_count"}, "V4 construction probe collector")
    collector = {
        "task_lease_count": uint(collector_probe["task_lease_count"], "V4 collector task lease", positive=True),
        "control_charge_bytes": uint(collector_probe["control_charge_bytes"], "V4 collector Control charge", positive=True),
        "expected_global_control_baseline": baseline,
    }
    require(collector["task_lease_count"] == 1, "V4 collector Task lease differs from the fixed trace contract")
    meter_bounds = meter_source_bounds_for_workload(identity["workload"])
    expected = {
        "version": feedback_body["version"],
        **exact(feedback_body["reader_contract"], {
            "sample_interval_ns", "max_dense_gap_ns", "telemetry_freshness_ns",
            "required_breach_samples", "actuation_cooldown_ns", "minimum_dense_observations",
        }, "SourceV5 feedback reader contract"),
        "controls": copy.deepcopy(context["controls"]),
        "capacity_sources": {"disk": False, "download": False},
        "global_ceilings": global_ceilings,
        "tenant_ceilings": tenant_ceilings,
        "scope_limits": scope_limits,
        "rate_buckets": rate_buckets,
        "meter_source_bounds": meter_bounds,
        "collector": collector,
    }
    require(context["minimum_dense_observations"] == expected["minimum_dense_observations"], "SourceV5 context density differs from its numeric reader contract")
    require(feedback_body["algorithm"] == probe["rust_control_context"]["algorithm"], "SourceV5 feedback algorithm differs from the construction probe")
    return expected, copy.deepcopy(feedback_body["algorithm"]), workers


def _validate_v4_policy_source_projection(
    recipe: dict[str, Any], source_manifest_value: dict[str, Any], probe: dict[str, Any],
) -> None:
    """Bind V4 expectations to SourceV5 policy artifacts after full source verification."""
    expected, _algorithm, _workers = _source_v5_base_feedback_policy(recipe, source_manifest_value, probe)
    policy = recipe["policy"]
    for key, projected in expected.items():
        require(policy[key] == projected, f"V4 expectation policy {key} differs from verified SourceV5 inputs")


CAPACITY_RESOLUTION_RULE = "clip_relevant_initial_and_ceiling_to_raw_capacity_and_explicit_floor"
CAPACITY_RESOLUTION_VERSION = "application-feedback-capacity-resolution-v2"
CAPACITY_RESOLUTION_STATIC_RULE = "clip_relevant_initial_and_ceiling_to_raw_capacity"
CAPACITY_RESOLUTION_STATIC_VERSION = "application-feedback-capacity-resolution-v1"
CAPACITY_RATE_ROOF = 16 * 1024**3
CAPACITY_RATE_FLOOR = 64 * 1024**2
CAPACITY_FLOOR_POLICY_ID = "application_capacity_relative_tenth_v1"
CAPACITY_FLOOR_RULE = "max_one_min_static_floor_capacity_div_ten"
CAPACITY_FLOOR_DIVISOR = 10
CAPACITY_FLOOR_MINIMUM_BYTES_PER_SECOND = 1
CAPACITY_FLOOR_PROBE_ACTIVATION = "explicit_policy_id_and_capacity_artifact"
CAPACITY_FLOOR_RUNTIME_ACTIVATION = "explicit_pressure_qualification_and_policy_id_and_capacity_artifact"
CALIBRATED_PROBE_SCHEMA_V2 = "allocatbelt.application-feedback-policy-probe.v2"
CAPACITY_ARTIFACT_FIELDS = {
    "schema", "calibration_id", "host_id", "profile", "workload", "source_sha256",
    "disk.bytes_per_second", "disk.units", "disk.provenance",
    "download.bytes_per_second", "download.units", "download.provenance",
}


def _read_capacity_artifact_v5(pin: object) -> tuple[dict[str, str], str]:
    artifact_pin = exact(pin, {"path", "raw_sha256"}, "V5 application capacity artifact pin")
    path = absolute_path(artifact_pin["path"], "V5 application capacity artifact path")
    expected_sha = digest(artifact_pin["raw_sha256"], "V5 application capacity artifact raw SHA-256")
    raw, actual_sha = read_stable(path, "V5 application capacity artifact", 4096)
    require(actual_sha == expected_sha, "V5 application capacity artifact raw SHA-256 differs from its pin")
    require(raw.endswith(b"\n") and b"\r" not in raw and b"\x00" not in raw, "V5 capacity artifact has invalid LF framing")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeError as error:
        raise ValidationError("V5 application capacity artifact is not ASCII") from error
    fields: dict[str, str] = {}
    names: list[str] = []
    for line in lines:
        parts = line.split("\t")
        require(len(parts) == 2 and all(parts), "V5 capacity artifact row is malformed")
        name, value = parts
        require(name not in fields and not any(ord(char) < 32 or ord(char) == 127 for char in name + value), "V5 capacity artifact has duplicate or invalid fields")
        fields[name] = value
        names.append(name)
    require(set(fields) == CAPACITY_ARTIFACT_FIELDS, "V5 capacity artifact has an unexpected field set")
    require(names == sorted(names, key=lambda name: name.encode("ascii")), "V5 capacity artifact rows are not canonically sorted")
    require(fields["schema"] == "allocatbelt.app-byte-capacity.v1", "unsupported V5 application capacity artifact schema")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", fields["calibration_id"]) is not None, "V5 calibration ID is malformed")
    digest(fields["source_sha256"], "V5 capacity source SHA-256")
    for direction in ("disk", "download"):
        rate = fields[f"{direction}.bytes_per_second"]
        units = fields[f"{direction}.units"]
        provenance = fields[f"{direction}.provenance"]
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}", provenance) is not None, f"V5 {direction} provenance is malformed")
        if rate == "missing":
            require(units == "missing", f"missing V5 {direction} capacity must use missing units")
        else:
            require(re.fullmatch(r"[1-9][0-9]{0,19}", rate) is not None, f"V5 {direction} capacity is not a canonical positive integer")
            require(int(rate) <= U64_MAX and units == "application_bytes_per_second", f"V5 {direction} capacity units/value are invalid")
    return fields, actual_sha


def _validate_v2_collector(value: object, label: str = "V2 construction probe collector") -> dict[str, int]:
    """Validate all four V2 collector fields without conflating owner charges."""
    actual_collector = exact(value, {
        "control_charge_bytes", "task_lease_count", "tenant_control_used_with_admission",
        "tenant_tasks_used_with_admission",
    }, label)
    control_charge = uint(actual_collector["control_charge_bytes"], "V2 collector Control charge", positive=True)
    task_lease = uint(actual_collector["task_lease_count"], "V2 collector Task lease", positive=True)
    tenant_control = uint(actual_collector["tenant_control_used_with_admission"], "V2 tenant Control with collector", positive=True)
    tenant_tasks = uint(actual_collector["tenant_tasks_used_with_admission"], "V2 tenant Tasks with collector", positive=True)
    require(task_lease == 1 and tenant_tasks == 1, "V2 collector must own exactly one Task lease")
    require(tenant_control >= control_charge, "V2 tenant Control observation omits the actual collector charge")
    return {
        "control_charge_bytes": control_charge,
        "task_lease_count": task_lease,
        "tenant_control_used_with_admission": tenant_control,
        "tenant_tasks_used_with_admission": tenant_tasks,
    }


def _static_policy_from_source_v5(
    source_manifest: dict[str, Any], identity: dict[str, Any], collector: object, algorithm: object,
) -> tuple[dict[str, Any], dict[str, Any], int]:
    """Project calibrated-probe V2 observations into the shared static policy."""
    actual_collector = _validate_v2_collector(collector)
    # The V4 projection deliberately remains a two-field exact contract. V2's
    # extra constructor observations are checked above and in the V2 evidence
    # validator, then only the shared collector facts are projected here.
    probe = {
        "collector": {
            "control_charge_bytes": actual_collector["control_charge_bytes"],
            "task_lease_count": actual_collector["task_lease_count"],
        },
        "rust_control_context": {"algorithm": algorithm},
    }
    recipe = {"identity": identity, "policy": {}}
    policy, actual_algorithm, workers = _source_v5_base_feedback_policy(recipe, source_manifest, probe)
    return policy, actual_algorithm, workers


def resolve_calibrated_feedback_policy_v5(
    source_manifest: dict[str, Any], probe: dict[str, Any], capacity_artifact_pin: object,
    identity: dict[str, Any], *, capacity_floor_policy_id: str | None = None,
) -> dict[str, Any]:
    """Resolve only the relevant application-byte rates against SourceV5 limits."""
    require(type(source_manifest) is dict and source_manifest.get("schema") == SOURCE_MANIFEST_SCHEMA_V5, "calibrated feedback resolution requires SourceV5")
    require(type(identity) is dict, "calibrated feedback identity must be an object")
    for name in ("host_id", "workload", "profile", "allocator"):
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", text(identity.get(name), f"calibrated identity.{name}")) is not None, f"calibrated identity.{name} is not a canonical token")
    require(identity["allocator"] in APPLICATION_ALLOCATOR_LABELS, "calibrated feedback resolver allocator is outside the original application artifact set")
    digest(identity.get("source_sha256"), "calibrated identity source SHA-256")
    digest(identity.get("binary_sha256"), "calibrated identity binary SHA-256")
    _verify_source_manifest_v5(source_manifest, {
        "schema": EXPECTATION_SCHEMA_V5, "mode": "pressure_validation", "identity": identity,
    })
    require(source_manifest["build"]["host_id"] == identity["host_id"], "calibrated identity host differs from SourceV5 build")
    require(source_manifest["source"]["source_tree_sha256"] == identity["source_sha256"], "calibrated identity source differs from SourceV5 tree")
    app_artifact = exact(source_manifest["artifacts"].get(identity["allocator"]), {"path", "sha256"}, "SourceV5 calibrated APP artifact")
    require(digest(app_artifact["sha256"], "SourceV5 calibrated APP artifact SHA-256") == identity["binary_sha256"], "calibrated identity binary differs from SourceV5 APP artifact")
    _validate_v2_workload_profile(identity.get("workload"), identity.get("profile"))
    probe_keys = {
        "schema", "context", "reader_context", "rust_control_context", "collector", "baseline",
        "capacity_calibration", "construction", "after_release", "meter_source_bounds",
        "meter_source_model", "source_references",
    }
    if capacity_floor_policy_id is not None:
        probe_keys.add("capacity_floor_policy_id")
    exact(probe, probe_keys, "calibrated construction probe v2")
    require(probe["schema"] == CALIBRATED_PROBE_SCHEMA_V2, "unsupported calibrated construction probe schema")
    require(capacity_floor_policy_id is None or
            capacity_floor_policy_id == CAPACITY_FLOOR_POLICY_ID,
            "requested capacity floor policy ID is unknown")
    context = exact(probe["context"], {"workload", "profile", "workers"}, "calibrated probe context")
    require(context["workload"] == identity["workload"] and context["profile"] == identity["profile"], "calibrated probe context differs from feedback identity")
    workers = uint(context["workers"], "calibrated probe workers", positive=True, maximum=4)
    require(workers == (2 if identity["profile"] == "oversubscribed" else 4), "calibrated probe workers differ from the profile")
    reader_context = exact(probe["reader_context"], {
        "version", "sample_interval_ns", "max_dense_gap_ns", "telemetry_freshness_ns",
        "required_breach_samples", "actuation_cooldown_ns", "minimum_dense_observations",
    }, "calibrated probe reader context")
    require(reader_context["version"] == "runtime-feedback-policy-v1", "unsupported calibrated reader policy version")
    reader_numeric = {
        "sample_interval_ns": 100_000_000, "max_dense_gap_ns": 200_000_000,
        "telemetry_freshness_ns": 500_000_000, "required_breach_samples": 3,
        "actuation_cooldown_ns": NSEC, "minimum_dense_observations": 1,
    }
    for name, expected in reader_numeric.items():
        require(uint(reader_context[name], f"calibrated reader {name}", positive=True) == expected, f"calibrated reader {name} differs from the SourceV5 contract")

    rust_context = exact(probe["rust_control_context"], {
        "algorithm", "controls", "global_ceilings", "tenant_ceilings", "scope_limits",
        "rate_buckets", "required_byte_sources",
    }, "calibrated Rust control context")
    algorithm = exact(rust_context["algorithm"], {
        "cpu_reduction_rule", "cpu_recovery_increment", "network_sensor_source", "upload_controlled",
    }, "calibrated feedback algorithm")
    require(type(algorithm["upload_controlled"]) is bool, "calibrated upload-control flag must be boolean")
    require(uint(algorithm["cpu_recovery_increment"], "calibrated CPU recovery increment", positive=True) == 1, "calibrated CPU recovery increment differs from contract")
    require(algorithm == {
        "cpu_reduction_rule": "floor_current_limit_over_10_zero_is_quantized",
        "cpu_recovery_increment": 1,
        "network_sensor_source": "download_application_bytes_only",
        "upload_controlled": False,
    }, "calibrated feedback algorithm differs from SourceV5")

    capacity, capacity_sha = _read_capacity_artifact_v5(capacity_artifact_pin)
    calibration_keys = {
        "artifact_sha256", "calibration_id", "disk", "download", "hash_scope", "host_id",
        "identity", "profile", "resolution", "schema", "source_sha256", "verification_scope", "workload",
    }
    if capacity_floor_policy_id is not None:
        calibration_keys.add("capacity_floor_policy_id")
    calibration = exact(probe["capacity_calibration"], calibration_keys,
                        "calibrated capacity context")
    if capacity_floor_policy_id is not None:
        require(probe.get("capacity_floor_policy_id") == capacity_floor_policy_id,
                "ProbeV2 top-level capacity-floor ID differs from the frozen caller selection")
        require(calibration.get("capacity_floor_policy_id") == capacity_floor_policy_id,
                "ProbeV2 capacity calibration floor ID differs from the frozen caller selection")
    else:
        require("capacity_floor_policy_id" not in probe and
                "capacity_floor_policy_id" not in calibration,
                "default ProbeV2 must preserve its original no-selector shape")
    source_feedback_body = source_manifest["feedback_policy"]["policy"]
    floor_policy_descriptor = source_feedback_body.get("capacity_floor_policy")
    if capacity_floor_policy_id is not None:
        floor_policy_descriptor = _validate_capacity_floor_policy_descriptor(
            floor_policy_descriptor,
        )
        require(floor_policy_descriptor["policy_id"] == capacity_floor_policy_id,
                "selected floor policy ID is not published by the pinned SourceV5 policy")
    else:
        require("capacity_floor_policy" not in source_feedback_body,
                "default ProbeV2 cannot resolve a SourceV5 selected-floor artifact")
    require(calibration["schema"] == "allocatbelt.app-byte-capacity.v1", "calibrated capacity schema differs")
    require(digest(calibration["artifact_sha256"], "probe capacity artifact SHA") == capacity_sha, "probe capacity artifact SHA differs from the pinned raw bytes")
    require(calibration["calibration_id"] == capacity["calibration_id"], "probe calibration ID differs from the capacity artifact")
    require(calibration["host_id"] == capacity["host_id"] == identity["host_id"], "capacity host differs from the SourceV5 feedback identity")
    require(calibration["profile"] == capacity["profile"] == identity["profile"], "capacity profile differs from the SourceV5 feedback identity")
    require(calibration["workload"] == capacity["workload"] == identity["workload"], "capacity workload differs from the SourceV5 feedback identity")
    require(calibration["source_sha256"] == capacity["source_sha256"] == identity["source_sha256"], "capacity source differs from the SourceV5 feedback identity")
    capacity_identity = exact(calibration["identity"], {"host_id", "profile", "source_sha256", "workload"}, "probe capacity identity")
    require(capacity_identity == {name: calibration[name] for name in capacity_identity}, "probe capacity identity projection differs")
    require(calibration["hash_scope"] == "exact_bounded_artifact_bytes", "probe capacity hash scope differs")
    require(calibration["verification_scope"] == "exact_artifact_hash_and_run_identity_only;producer_and_measurement_chronology_unverified", "probe capacity scope must retain its chronology limitation")
    relevant = {
        "disk": identity["workload"] in ("disk", "mixed"),
        "download": identity["workload"] in ("http", "mixed"),
    }
    for direction in ("disk", "download"):
        direction_value = exact(calibration[direction], {"bytes_per_second", "direction", "provenance", "units"}, f"probe {direction} calibration")
        require(direction_value["direction"] == direction, f"probe {direction} direction label differs")
        require(direction_value["provenance"] == capacity[f"{direction}.provenance"], f"probe {direction} provenance differs from raw artifact")
        rate = capacity[f"{direction}.bytes_per_second"]
        if rate == "missing":
            require(direction_value["bytes_per_second"] is None and direction_value["units"] == "missing", f"probe missing {direction} calibration differs from artifact")
        else:
            require(uint(direction_value["bytes_per_second"], f"probe {direction} bytes per second", positive=True) == int(rate), f"probe {direction} calibration differs from raw artifact")
            require(direction_value["units"] == "application_bytes_per_second", f"probe {direction} units differ from raw artifact")
        if relevant[direction]:
            require(rate != "missing", f"required application-byte capacity source is missing: {direction}")
            if capacity_floor_policy_id is None:
                require(int(rate) >= CAPACITY_RATE_FLOOR,
                        f"{direction} application-byte capacity is below the static feedback floor")
        else:
            require(rate == "missing", f"irrelevant {direction} capacity source must remain missing")

    expected, expected_algorithm, expected_workers = _static_policy_from_source_v5(
        source_manifest, identity, probe["collector"], algorithm,
    )
    require(expected_algorithm == algorithm and expected_workers == workers, "calibrated algorithm or worker count differs from SourceV5")
    expected["capacity_sources"] = {"disk": relevant["disk"], "download": relevant["download"]}
    expected["rate_buckets"] = {
        direction: {
            "initial_bytes_per_second": expected["rate_buckets"][direction]["ceiling_bytes_per_second"],
            **expected["rate_buckets"][direction],
        }
        for direction in RATE_DIRECTIONS
    }
    expected_controls = expected["controls"]
    for direction, resource in (("disk", "disk"), ("download", "download")):
        if relevant[direction]:
            raw_capacity = int(capacity[f"{direction}.bytes_per_second"])
            resolved = min(raw_capacity, CAPACITY_RATE_ROOF)
            expected_controls[resource]["initial"] = resolved
            expected_controls[resource]["ceiling"] = resolved
            expected["rate_buckets"][direction]["initial_bytes_per_second"] = resolved
            expected["rate_buckets"][direction]["ceiling_bytes_per_second"] = resolved
            if capacity_floor_policy_id is not None:
                floor = max(
                    floor_policy_descriptor["minimum_floor_bytes_per_second"],
                    min(
                        floor_policy_descriptor["static_floor_bytes_per_second"],
                        raw_capacity // floor_policy_descriptor["capacity_divisor"],
                    ),
                )
                require(floor <= resolved,
                        f"{direction} capacity-relative floor exceeds its resolved initial rate")
                expected_controls[resource]["floor"] = floor

    resolution_keys = {
        "controls", "rate_buckets", "rule", "rule_version",
        "static_rate_roof_bytes_per_second", "upload_controlled",
    }
    if capacity_floor_policy_id is not None:
        resolution_keys.update({"capacity_floor_policy", "capacity_floor_policy_id"})
    resolution = exact(calibration["resolution"], resolution_keys,
                       "calibrated capacity resolution")
    expected_resolution_rule = (
        CAPACITY_RESOLUTION_RULE if capacity_floor_policy_id is not None
        else CAPACITY_RESOLUTION_STATIC_RULE
    )
    expected_resolution_version = (
        CAPACITY_RESOLUTION_VERSION if capacity_floor_policy_id is not None
        else CAPACITY_RESOLUTION_STATIC_VERSION
    )
    require(resolution["rule"] == expected_resolution_rule and
            resolution["rule_version"] == expected_resolution_version,
            "calibrated capacity resolution version/rule differs")
    if capacity_floor_policy_id is None:
        require("capacity_floor_policy" not in resolution and
                "capacity_floor_policy_id" not in resolution,
                "default calibrated policy must preserve its original resolution shape")
    else:
        require(resolution["capacity_floor_policy_id"] == capacity_floor_policy_id,
                "ProbeV2 resolution floor policy ID differs from its capacity context")
        require(resolution["capacity_floor_policy"] == floor_policy_descriptor,
                "ProbeV2 capacity-floor parameters differ from the pinned SourceV5 policy")
    require(uint(resolution["static_rate_roof_bytes_per_second"], "calibrated static rate roof", positive=True) == CAPACITY_RATE_ROOF, "calibrated static rate roof differs")
    require(type(resolution["upload_controlled"]) is bool and resolution["upload_controlled"] is False, "calibrated resolution changes upload control")
    resolution_controls = exact(resolution["controls"], set(RESOURCES), "calibrated resolution controls")
    for resource in RESOURCES:
        item = exact(resolution_controls[resource], {"floor", "initial", "ceiling", "low_bps", "high_bps"}, f"calibrated resolution {resource} control")
        for field, number in item.items():
            uint(number, f"calibrated resolution {resource}.{field}")
    resolution_buckets = exact(resolution["rate_buckets"], set(RATE_DIRECTIONS), "calibrated resolution rate buckets")
    for direction in RATE_DIRECTIONS:
        item = exact(resolution_buckets[direction], {
            "initial_bytes_per_second", "ceiling_bytes_per_second", "ceiling_burst_bytes", "max_reservations",
        }, f"calibrated resolution {direction} rate bucket")
        for field, number in item.items():
            uint(number, f"calibrated resolution {direction}.{field}", positive=True)
    require(resolution["controls"] == rust_context["controls"], "capacity resolution controls differ from the Rust control context")
    require(resolution["rate_buckets"] == rust_context["rate_buckets"], "capacity resolution buckets differ from the Rust control context")
    controls = exact(rust_context["controls"], set(RESOURCES), "calibrated Rust controls")
    for resource in RESOURCES:
        observed = exact(controls[resource], {"floor", "initial", "ceiling", "low_bps", "high_bps"}, f"calibrated {resource} control")
        for key, item in observed.items():
            uint(item, f"calibrated {resource}.{key}")
        require(observed == expected_controls[resource], f"calibrated {resource} control differs from independent resolution")
    required_sources = exact(rust_context["required_byte_sources"], {"disk", "download"}, "calibrated required byte sources")
    require(required_sources == relevant, "calibrated required byte sources differ from workload")
    for owner in ("global_ceilings", "tenant_ceilings"):
        require(_uint_map(rust_context[owner], set(DOMAIN), f"calibrated {owner}") == expected[owner], f"calibrated {owner} differs from SourceV5")
    require(_uint_map(rust_context["scope_limits"], {"managed_memory", "disk_operations", "network_operations"}, "calibrated scope limits") == expected["scope_limits"], "calibrated scope limits differ from SourceV5")
    require(rust_context["rate_buckets"] == expected["rate_buckets"], "calibrated Rust rate buckets differ from independent capacity resolution")
    if capacity_floor_policy_id is not None:
        expected["capacity_floor_policy"] = floor_policy_descriptor
        expected["capacity_floor_policy_id"] = capacity_floor_policy_id
    return expected


def _stable_file_sha256(path: Path, label: str, maximum: int) -> tuple[str, int, int]:
    try:
        require(path.resolve(strict=True) == path, f"{label} traverses a symlink or alias")
        before_path = path.lstat()
        require(stat.S_ISREG(before_path.st_mode), f"{label} must be a regular nonsymlink file")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as error:
        raise ValidationError(f"cannot safely open {label}: {error}") from error
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and _stat_key(before) == _stat_key(before_path), f"{label} changed while opening")
        require(0 <= before.st_size <= maximum, f"{label} exceeds its hard size bound")
        hasher = hashlib.sha256()
        count = 0
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            count += len(block)
            require(count <= maximum, f"{label} exceeded its hard size bound")
            hasher.update(block)
        after_fd, after_path = os.fstat(fd), path.lstat()
        require(count == before.st_size and _stat_key(before) == _stat_key(after_fd) == _stat_key(after_path), f"{label} changed during hashing")
        return hasher.hexdigest(), count, before.st_mode
    finally:
        os.close(fd)


def _leader_exit_status_unreaped(process: subprocess.Popen[bytes]) -> Any | None:
    """Observe child exit without releasing the PID that anchors its new session."""
    require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, "probe cleanup requires the default SIGCHLD disposition to preserve child ownership")
    require(callable(getattr(os, "waitid", None)) and hasattr(os, "WNOWAIT"), "probe cleanup requires waitid(WNOWAIT) to preserve child ownership")
    require(process.returncode is None, "probe leader was reaped before process-group cleanup completed")
    try:
        result = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError as error:
        raise ValidationError("probe leader ownership was lost before its process group was verified") from error
    if result is not None:
        require(result.si_pid == process.pid, "waitid observed a different probe leader")
        return result
    return None


def _owned_session_members(session_id: int) -> tuple[list[int], list[int]]:
    """Return live PIDs in the owned PGID and live PIDs that escaped to another PGID."""
    group_members: list[int] = []
    escaped_members: list[int] = []
    try:
        entries = list(os.scandir("/proc"))
    except OSError as error:
        raise ValidationError(f"cannot inspect process ownership for probe cleanup: {error}") from error
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
            raise ValidationError(f"cannot inspect process {pid} during probe cleanup: {error}") from error
        closing = stat_line.rfind(")")
        require(closing >= 0, f"cannot parse process {pid} during probe cleanup")
        fields = stat_line[closing + 1 :].split()
        require(len(fields) >= 4, f"cannot parse process identity for {pid} during probe cleanup")
        state = fields[0]
        try:
            process_group_id = int(fields[2])
            observed_session_id = int(fields[3])
        except ValueError as error:
            raise ValidationError(f"cannot parse process group for {pid} during probe cleanup") from error
        if pid == session_id:
            require(process_group_id == session_id and observed_session_id == session_id, "probe leader no longer anchors its original session")
            saw_leader = True
        if observed_session_id != session_id or state in {"Z", "X"}:
            continue
        if process_group_id == session_id:
            group_members.append(pid)
        else:
            escaped_members.append(pid)
    require(saw_leader, "probe session leader disappeared before it was safely reaped")
    return group_members, escaped_members


def _signal_unreaped_owned_group(process: subprocess.Popen[bytes], signum: int) -> None:
    """Signal only the fresh PGID while its unreaped session leader pins that ID."""
    _leader_exit_status_unreaped(process)
    group_members, _escaped_members = _owned_session_members(process.pid)
    if not group_members:
        return
    # Recheck immediately before the numeric PGID operation. In particular, a
    # procfs scan does not preserve child wait ownership if SIGCHLD changed.
    _leader_exit_status_unreaped(process)
    try:
        os.killpg(process.pid, signum)
    except ProcessLookupError:
        return
    except OSError as error:
        raise ValidationError(f"cannot signal the unreaped probe process group: {error}") from error


def _signal_unreaped_group_without_scan(process: subprocess.Popen[bytes], signum: int) -> None:
    """Emergency signal under verified wait semantics when procfs is unavailable."""
    # Popen used start_new_session=True, so its still-owned, unreaped child
    # reserves the fresh session's numeric PGID even if procfs cannot be read.
    _leader_exit_status_unreaped(process)
    try:
        os.killpg(process.pid, signum)
    except ProcessLookupError:
        return
    except OSError as error:
        raise ValidationError(f"cannot emergency-signal the unreaped probe process group: {error}") from error


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
        time.sleep(min(PROBE_POLL_INTERVAL_SECONDS, remaining))


def _observed_owned_exit_code(process: subprocess.Popen[bytes], observation: Any) -> int:
    """Translate the exit already observed while WNOWAIT retained its status."""
    require(observation is not None and observation.si_pid == process.pid, "waitid did not observe the owned probe leader")
    if observation.si_code == getattr(os, "CLD_EXITED", None):
        return observation.si_status
    if observation.si_code in {
        getattr(os, "CLD_KILLED", None), getattr(os, "CLD_DUMPED", None),
    }:
        return -observation.si_status
    raise ValidationError("waitid returned an unsupported probe-leader exit condition")


def _wait_owned_leader(process: subprocess.Popen[bytes], timeout_seconds: float, label: str) -> int:
    """Reap only after WNOWAIT proves the exit under this capture's sole-waiter ownership.

    The Popen is private to this capture path. Callers must not poll or wait on
    it concurrently; all earlier exit observations retain status with WNOWAIT.
    """
    deadline = time.monotonic() + timeout_seconds
    observation = _leader_exit_status_unreaped(process)
    while observation is None:
        remaining = deadline - time.monotonic()
        require(remaining > 0, f"{label} leader did not exit within its bounded wait")
        time.sleep(min(PROBE_POLL_INTERVAL_SECONDS, remaining))
        observation = _leader_exit_status_unreaped(process)
    expected_exit_code = _observed_owned_exit_code(process, observation)

    # Recheck default SIGCHLD, WNOWAIT, and ownership immediately before the
    # one actual wait. A scanner may have lost that ownership since an earlier
    # observation; Popen.wait can otherwise turn ECHILD into a synthetic zero.
    final_observation = _leader_exit_status_unreaped(process)
    require(final_observation is not None, "probe leader exit status disappeared before its bounded reap")
    require(
        _observed_owned_exit_code(process, final_observation) == expected_exit_code,
        "probe leader exit status changed before its bounded reap",
    )
    remaining = max(0.0, deadline - time.monotonic())
    try:
        exit_code = process.wait(timeout=remaining)
    except subprocess.TimeoutExpired as error:
        raise ValidationError(f"{label} leader could not be reaped within its bounded wait") from error
    require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, f"{label} SIGCHLD disposition changed during leader reaping")
    require(exit_code == expected_exit_code, f"{label} Popen status differs from its WNOWAIT exit observation")
    require(process.returncode == expected_exit_code, f"{label} Popen return code differs from its WNOWAIT exit observation")
    return exit_code


def _cleanup_owned_process_group(process: subprocess.Popen[bytes]) -> None:
    """Boundedly clean and reap an isolated group without losing its PGID anchor."""
    require(process.returncode is None, "probe leader was already reaped before process-group cleanup")
    cleanup_deadline = time.monotonic() + PROBE_CLEANUP_TOTAL_SECONDS
    reap_reserve = min(PROBE_REAP_GRACE_SECONDS, PROBE_CLEANUP_TOTAL_SECONDS)
    signal_deadline = cleanup_deadline - reap_reserve
    cleanup_trigger: BaseException | None = None
    emergency_errors: list[BaseException] = []
    verified_cleanup_error: BaseException | None = None
    group_quiescent = False
    escaped_members: list[int] = []
    group_members: list[int] = []
    try:
        _leader_exit_status_unreaped(process)
        _signal_unreaped_owned_group(process, signal.SIGTERM)
        term_budget = min(PROBE_TERM_GRACE_SECONDS, max(0.0, signal_deadline - time.monotonic()))
        group_quiescent = _wait_owned_group_quiescent(process, term_budget)
        if not group_quiescent:
            require(time.monotonic() < signal_deadline, "probe cleanup exhausted its signal deadline before SIGKILL")
            _signal_unreaped_owned_group(process, signal.SIGKILL)
            kill_budget = min(PROBE_KILL_GRACE_SECONDS, max(0.0, signal_deadline - time.monotonic()))
            group_quiescent = _wait_owned_group_quiescent(process, kill_budget)
        _leader_exit_status_unreaped(process)
        group_members, escaped_members = _owned_session_members(process.pid)
        _leader_exit_status_unreaped(process)
        if group_members:
            verified_cleanup_error = ValidationError("probe process group remained after bounded TERM/KILL cleanup")
            try:
                _signal_unreaped_group_without_scan(process, signal.SIGKILL)
            except BaseException as emergency_error:
                emergency_errors.append(emergency_error)
        elif escaped_members:
            verified_cleanup_error = ValidationError("probe left live descendants outside its owned process group")
    except BaseException as error:
        # A failed inspection, ownership check or signal cannot establish that
        # the group is empty. Retain the unreaped leader and make bounded
        # emergency attempts without procfs; cleanup remains an error even if
        # these signals stop the children.
        cleanup_trigger = error
        for signum in (signal.SIGTERM, signal.SIGKILL):
            try:
                _signal_unreaped_group_without_scan(process, signum)
            except BaseException as emergency_error:
                emergency_errors.append(emergency_error)

    reap_error: BaseException | None = None
    try:
        remaining = max(0.0, cleanup_deadline - time.monotonic())
        _wait_owned_leader(process, min(PROBE_REAP_GRACE_SECONDS, remaining), "probe cleanup")
    except BaseException as error:
        reap_error = error

    # wait() may release the PID/PGID. No scan, signal, poll or wait is allowed
    # after this point. Even a successful emergency attempt is unverified.
    if reap_error is not None:
        if cleanup_trigger is not None:
            message = f"probe process-group cleanup is unverified after cleanup failure: {cleanup_trigger}; bounded leader wait failed: {reap_error}"
        else:
            message = f"probe leader could not be reaped within its cleanup bound: {reap_error}"
        if emergency_errors:
            message += "; emergency signaling failed: " + "; ".join(str(item) for item in emergency_errors)
        raise ValidationError(message) from reap_error
    if cleanup_trigger is not None:
        message = f"probe process-group cleanup is unverified after cleanup failure: {cleanup_trigger}"
        if emergency_errors:
            message += "; emergency signaling failed: " + "; ".join(str(item) for item in emergency_errors)
        raise ValidationError(message) from cleanup_trigger
    if verified_cleanup_error is not None:
        message = str(verified_cleanup_error)
        if emergency_errors:
            message += "; emergency signaling failed: " + "; ".join(str(item) for item in emergency_errors)
        raise ValidationError(message) from verified_cleanup_error


def _capture_bounded_process(
    argv: list[str], cwd: Path, label: str, *, timeout_seconds: float = 30.0,
    maximum_output_bytes: int = MAX_PROBE_OUTPUT_BYTES,
) -> tuple[int, bytes, bytes]:
    require(timeout_seconds > 0 and maximum_output_bytes > 0, f"{label} bounds must be positive")
    require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, f"{label} requires the default SIGCHLD disposition to preserve child ownership")
    require(callable(getattr(os, "waitid", None)) and hasattr(os, "WNOWAIT"), f"{label} requires waitid(WNOWAIT) for owned process-group cleanup")
    try:
        process = subprocess.Popen(
            argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, close_fds=True, start_new_session=True, bufsize=0,
        )
    except OSError as error:
        raise ValidationError(f"cannot execute {label}: {error}") from error
    selector: Any | None = None
    output: dict[int, bytearray] = {}
    streams: dict[int, Any] = {}
    cleanup_attempted = False
    try:
        require(process.stdout is not None and process.stderr is not None, f"{label} did not receive captured output pipes")
        stdout_fd = process.stdout.fileno()
        stderr_fd = process.stderr.fileno()
        streams = {stdout_fd: process.stdout, stderr_fd: process.stderr}
        output = {stdout_fd: bytearray(), stderr_fd: bytearray()}
        selector = selectors.DefaultSelector()
        for fd, stream in streams.items():
            os.set_blocking(fd, False)
            selector.register(stream, selectors.EVENT_READ, fd)
        deadline = time.monotonic() + timeout_seconds
        while selector.get_map():
            remaining = deadline - time.monotonic()
            require(remaining > 0, f"{label} exceeded its {timeout_seconds:g}-second deadline")
            for key, _mask in selector.select(min(0.1, remaining)):
                fd = key.data
                block = os.read(fd, 64 * 1024)
                if not block:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                output[fd].extend(block)
                require(sum(len(data) for data in output.values()) <= maximum_output_bytes, f"{label} output exceeds its {maximum_output_bytes}-byte bound")
        remaining = deadline - time.monotonic()
        require(remaining > 0, f"{label} exceeded its {timeout_seconds:g}-second deadline")
        while _leader_exit_status_unreaped(process) is None:
            remaining = deadline - time.monotonic()
            require(remaining > 0, f"{label} exceeded its {timeout_seconds:g}-second deadline")
            time.sleep(min(PROBE_POLL_INTERVAL_SECONDS, remaining))
        group_members, escaped_members = _owned_session_members(process.pid)
        if group_members or escaped_members:
            cleanup_attempted = True
            _cleanup_owned_process_group(process)
            raise ValidationError(f"{label} exited while owned descendant processes remained")
        remaining = deadline - time.monotonic()
        require(remaining > 0, f"{label} exceeded its {timeout_seconds:g}-second deadline")
        exit_code = _wait_owned_leader(
            process, min(PROBE_REAP_GRACE_SECONDS, remaining), label,
        )
        return exit_code, bytes(output[stdout_fd]), bytes(output[stderr_fd])
    except BaseException as error:
        if not cleanup_attempted and process.returncode is None:
            cleanup_attempted = True
            try:
                _cleanup_owned_process_group(process)
            except BaseException as cleanup_error:
                raise cleanup_error from error
        if isinstance(error, subprocess.TimeoutExpired):
            raise ValidationError(f"{label} exceeded its {timeout_seconds:g}-second deadline") from error
        raise
    finally:
        try:
            if selector is not None:
                selector.close()
        except OSError:
            pass
        finally:
            for stream in (process.stdout, process.stderr):
                if stream is None:
                    continue
                try:
                    stream.close()
                except OSError:
                    pass


def _run_feedback_probe(
    binary: Path, source_root: Path, identity: dict[str, Any], capacity_path: Path,
    capacity_sha: str, capacity_floor_policy_id: str | None = None,
) -> bytes:
    argv = [
        str(binary), "--emit-feedback-policy-only", "--workload", identity["workload"],
        "--profile", identity["profile"], "--capacity-calibration-file", str(capacity_path),
        "--capacity-calibration-sha256", capacity_sha, "--host-id", identity["host_id"],
        "--source-sha256", identity["source_sha256"],
    ]
    if capacity_floor_policy_id is not None:
        require(capacity_floor_policy_id == CAPACITY_FLOOR_POLICY_ID,
                "captured probe capacity floor policy ID is unknown")
        argv.extend(["--capacity-floor-policy-id", capacity_floor_policy_id])
    exit_code, stdout, stderr = _capture_bounded_process(
        argv, source_root, "pinned SourceV5 APP probe",
    )
    require(exit_code == 0, f"pinned SourceV5 APP probe exited with status {exit_code}: {stderr[:1024]!r}")
    require(not stderr, "pinned SourceV5 APP probe wrote unexpected stderr")
    return stdout


def validate_calibrated_construction_probe_v2(
    probe_pin: object, source_manifest: dict[str, Any], capacity_artifact_pin: object,
    identity: dict[str, Any], expected_policy: dict[str, Any] | None = None,
    capacity_floor_policy_id: str | None = None,
) -> str:
    """Fully verify SourceV5 and rerun its exact APP binary's calibrated probe."""
    probe_sha, probe, binary, source_root, capacity_sha, capacity_path = _check_calibrated_construction_probe_v2_inputs(
        probe_pin, source_manifest, capacity_artifact_pin, identity, expected_policy,
        capacity_floor_policy_id,
    )
    rerun = _run_feedback_probe(
        binary, source_root, identity, capacity_path, capacity_sha,
        capacity_floor_policy_id,
    )
    require(rerun == canonical_bytes(probe), "pinned construction probe bytes differ from stdout from the exact SourceV5 APP artifact")
    return probe_sha


def _check_calibrated_construction_probe_v2_inputs(
    probe_pin: object, source_manifest: dict[str, Any], capacity_artifact_pin: object,
    identity: dict[str, Any], expected_policy: dict[str, Any] | None = None,
    capacity_floor_policy_id: str | None = None, *, artifact_view: Any = None,
    closed_recorded: bool = False,
) -> tuple[str, dict[str, Any], Path, Path, str, Path]:
    """Check every static V2 source/policy input without launching an APP."""
    require(source_manifest.get("schema") == SOURCE_MANIFEST_SCHEMA_V5, "calibrated construction probe requires SourceV5")
    pin = exact(probe_pin, {"path", "raw_sha256", "allocator", "binary_sha256"}, "calibrated construction probe pin")
    absolute_path(pin["path"], "calibrated construction probe path")
    digest(pin["raw_sha256"], "calibrated construction probe raw SHA-256")
    require(pin["allocator"] in APPLICATION_ALLOCATOR_LABELS and pin["allocator"] == identity["allocator"], "calibrated probe allocator differs from the selected application artifact")
    digest(pin["binary_sha256"], "calibrated probe binary SHA-256")
    require(pin["binary_sha256"] == identity["binary_sha256"], "calibrated probe binary differs from feedback identity")
    probe, probe_sha = read_canonical(
        Path(pin["path"]), "calibrated construction probe v2",
        MAX_CONSTRUCTION_PROBE_BYTES, pin["raw_sha256"],
        artifact_view=artifact_view,
    )
    resolved_policy = resolve_calibrated_feedback_policy_v5(
        source_manifest, probe, capacity_artifact_pin, identity,
        capacity_floor_policy_id=capacity_floor_policy_id,
    )
    if expected_policy is not None:
        require(expected_policy == resolved_policy, "V5 feedback expectation differs from independently resolved SourceV5/capacity policy")
    source = source_manifest.get("source")
    require(source_manifest["build"]["host_id"] == identity["host_id"], "calibrated probe SourceV5 host differs from feedback identity")
    require(source["source_tree_sha256"] == identity["source_sha256"], "calibrated probe SourceV5 tree differs from feedback identity")
    artifact = exact(source_manifest["artifacts"].get(identity["allocator"]), {"path", "sha256"}, "calibrated SourceV5 APP artifact")
    require(digest(artifact["sha256"], "calibrated SourceV5 APP artifact SHA-256") == pin["binary_sha256"], "calibrated probe binary differs from SourceV5 APP artifact")
    source_root = Path(__file__).resolve().parent.parent
    relative = PurePosixPath(text(artifact["path"], "SourceV5 APP artifact relative path", 4096))
    require(not relative.is_absolute() and ".." not in relative.parts and
            relative.as_posix() == artifact["path"] and "\\" not in artifact["path"],
            "SourceV5 APP artifact path is not portable")
    binary = source_root.joinpath(*relative.parts)
    if closed_recorded:
        require(digest(artifact["sha256"], "SourceV5 APP artifact SHA-256") ==
                pin["binary_sha256"],
                "closed-recorded probe binary differs from the exact SourceV5 artifact identity")
    else:
        binary_sha, _size, binary_mode = _stable_file_sha256(
            binary, "SourceV5 APP artifact", MAX_APP_BINARY_BYTES,
        )
        require(stat.S_IMODE(binary_mode) & 0o111 and
                binary_sha == artifact["sha256"],
                "SourceV5 APP artifact bytes or executable mode differ from the manifest")
    _fields, capacity_sha = _read_capacity_artifact_v5(capacity_artifact_pin)
    _validate_calibrated_construction_evidence(source_manifest, probe, identity)
    capacity_path = absolute_path(exact(capacity_artifact_pin, {"path", "raw_sha256"}, "V5 capacity artifact pin")["path"], "V5 capacity artifact path")
    return probe_sha, probe, binary, source_root, capacity_sha, capacity_path


def _validate_feedback_offline_context(value: object) -> dict[str, Any]:
    if type(value) is dict and value.get("schema") in {
            FEEDBACK_CAPTURED_OFFLINE_CONTEXT_SCHEMA,
            PRESSURE_CAPTURED_OFFLINE_CONTEXT_SCHEMA,
    }:
        if value["schema"] == FEEDBACK_CAPTURED_OFFLINE_CONTEXT_SCHEMA:
            context = exact(value, {
                "schema", "artifact_view", "captured_origin_paths",
                "evidence_file_paths", "evidence_directory_paths",
                "source_symlink_paths", "tree_inventories",
                "probe_capture_pin", "capacity_bundle",
            }, "captured feedback offline replay context")
        else:
            context = exact(value, {
                "schema", "artifact_view", "captured_origin_paths",
                "evidence_file_paths", "evidence_directory_paths",
                "source_symlink_paths", "tree_inventories",
                "probe_capture_pin", "capacity_bundle",
            }, "captured pressure feedback replay context")
        view = context["artifact_view"]
        require(callable(getattr(view, "has_file", None)) and
                callable(getattr(view, "read", None)) and
                callable(getattr(view, "open_snapshot", None)),
                "captured feedback replay has no exact artifact-view reader")

        def path_set(value: object, label: str) -> frozenset[str]:
            require(type(value) is list and len(value) <=
                    MAX_OFFLINE_PATH_MAP_ENTRIES,
                    f"{label} is malformed or oversized")
            rendered = [str(absolute_path(item, f"{label}[{index}]"))
                        for index, item in enumerate(value)]
            require(rendered == sorted(set(rendered)),
                    f"{label} is not sorted and unique")
            return frozenset(rendered)

        captured = path_set(context["captured_origin_paths"],
                            "captured feedback object origins")
        files = path_set(context["evidence_file_paths"],
                         "captured feedback owner inventory files")
        directories = path_set(context["evidence_directory_paths"],
                               "captured feedback owner inventory directories")
        source_symlinks = path_set(context["source_symlink_paths"],
                                   "resident SourceV5 symlink paths")
        require(captured and captured <= files and
                not captured.intersection(directories) and
                source_symlinks <= files and
                all(view.has_file(path) for path in captured),
                "captured feedback object closure differs from the strict owner inventory")
        require(type(context["tree_inventories"]) is list,
                "captured feedback typed tree inventory is not a list")
        capture = exact(context["probe_capture_pin"], {
            "path", "raw_sha256", "receipt_sha256",
        }, "captured calibrated probe receipt pin")
        absolute_path(capture["path"], "captured calibrated probe receipt path")
        digest(capture["raw_sha256"], "captured calibrated probe receipt raw SHA-256")
        digest(capture["receipt_sha256"], "captured calibrated probe receipt digest")
        bundle = exact(context["capacity_bundle"], {
            "request", "artifact", "receipt",
        }, "captured offline capacity producer bundle")
        for name, pin_value in bundle.items():
            pin = exact(pin_value, {"path", "raw_sha256"},
                        f"captured offline capacity {name} pin")
            absolute_path(pin["path"], f"captured offline capacity {name} path")
            digest(pin["raw_sha256"],
                   f"captured offline capacity {name} raw SHA-256")
        require(len({bundle[name]["path"] for name in bundle}) == 3,
                "captured capacity producer paths must be distinct")
        frozen_capture = types.MappingProxyType(dict(capture))
        frozen_bundle = types.MappingProxyType({
            name: types.MappingProxyType(dict(bundle[name])) for name in bundle
        })
        return types.MappingProxyType({
            "schema": context["schema"], "artifact_view": view,
            "captured": True, "captured_files": captured,
            "mapped_paths": captured | files | directories,
            "mapped_directories": directories,
            "mapped_files": files,
            "mapped_symlinks": source_symlinks,
            "tree_inventories": tuple(context["tree_inventories"]),
            "probe_capture_pin": frozen_capture,
            "capacity_bundle": frozen_bundle,
        })
    try:
        snapshot = json.loads(canonical_bytes(value).decode("ascii"))
    except (TypeError, ValueError, UnicodeError) as error:
        raise ValidationError(f"feedback offline replay context is not closed JSON: {error}") from error
    context = exact(snapshot, {
        "schema", "evidence_path_map", "probe_capture_pin", "capacity_bundle",
    }, "feedback offline replay context")
    require(context["schema"] == FEEDBACK_OFFLINE_CONTEXT_SCHEMA,
            "unsupported feedback offline replay context schema")
    mapping = exact(context["evidence_path_map"], {"schema", "entries"}, "feedback evidence path map")
    require(mapping["schema"] == EVIDENCE_PATH_MAP_SCHEMA and
            type(mapping["entries"]) is list and
            1 <= len(mapping["entries"]) <= MAX_OFFLINE_PATH_MAP_ENTRIES,
            "feedback evidence path map schema or entry count is invalid")
    previous = ""
    local_paths: set[str] = set()
    directories: set[str] = set()
    files: set[str] = set()
    symlinks: set[str] = set()
    for index, entry_value in enumerate(mapping["entries"]):
        entry = exact(entry_value, {"origin", "local"}, f"feedback path map entry[{index}]")
        origin = absolute_path(entry["origin"], f"feedback evidence origin[{index}]")
        local = absolute_path(entry["local"], f"feedback evidence local[{index}]")
        origin_text, local_text = str(origin), str(local)
        require(origin_text > previous, "feedback path map origins must be sorted and unique")
        previous = origin_text
        require(origin == local and local_text not in local_paths,
                "feedback path map must contain unique identity paths only")
        try:
            require(local.parent.resolve(strict=True) == local.parent,
                    "feedback evidence path parent traverses a symlink or alias")
            info = local.lstat()
            if not stat.S_ISLNK(info.st_mode):
                require(local.resolve(strict=True) == local,
                        "feedback evidence path traverses a symlink or alias")
        except OSError as error:
            raise ValidationError(f"feedback evidence map path is unavailable: {error}") from error
        require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) or
                stat.S_ISLNK(info.st_mode),
                f"feedback evidence map entry[{index}] is not a regular file, directory, or typed symlink")
        local_paths.add(local_text)
        if stat.S_ISDIR(info.st_mode):
            directories.add(origin_text)
        elif stat.S_ISREG(info.st_mode):
            files.add(origin_text)
        else:
            symlinks.add(origin_text)
    capture_pin = exact(context["probe_capture_pin"], {
        "path", "raw_sha256", "receipt_sha256",
    }, "calibrated probe capture receipt pin")
    absolute_path(capture_pin["path"], "calibrated probe capture receipt path")
    digest(capture_pin["raw_sha256"], "calibrated probe capture receipt raw SHA-256")
    digest(capture_pin["receipt_sha256"], "calibrated probe capture receipt digest")
    bundle = exact(context["capacity_bundle"], {"request", "artifact", "receipt"},
                   "offline capacity producer bundle")
    for name, pin_value in bundle.items():
        pin = exact(pin_value, {"path", "raw_sha256"}, f"offline capacity {name} pin")
        absolute_path(pin["path"], f"offline capacity {name} path")
        digest(pin["raw_sha256"], f"offline capacity {name} raw SHA-256")
    require(len({bundle[name]["path"] for name in bundle}) == 3,
            "offline capacity producer paths must be distinct")
    frozen_mapping = types.MappingProxyType({
        "schema": mapping["schema"],
        "entries": tuple(types.MappingProxyType(dict(entry)) for entry in mapping["entries"]),
    })
    frozen_capture = types.MappingProxyType(dict(capture_pin))
    frozen_bundle = types.MappingProxyType({
        name: types.MappingProxyType(dict(bundle[name])) for name in bundle
    })
    return types.MappingProxyType({
        "schema": context["schema"], "evidence_path_map": frozen_mapping,
        "captured": False, "captured_files": frozenset(),
        "mapped_directories": frozenset(directories), "mapped_paths": frozenset(local_paths),
        "mapped_files": frozenset(files), "mapped_symlinks": frozenset(symlinks),
        "probe_capture_pin": frozen_capture, "capacity_bundle": frozen_bundle,
    })


def _require_offline_paths(context: dict[str, Any], paths: set[str], label: str) -> None:
    mapped = context["mapped_paths"]
    for raw_path in paths:
        path = absolute_path(raw_path, f"{label} path")
        path_text = str(path)
        require(path_text in mapped,
                f"feedback evidence path map omits exact {label}: {path_text}")


def _require_offline_files(context: dict[str, Any], paths: set[str], label: str) -> None:
    _require_offline_paths(context, paths, label)
    for raw_path in paths:
        require(raw_path in context["mapped_files"],
                f"feedback evidence path map does not mark {label} as a file: {raw_path}")


def _require_offline_directories(context: dict[str, Any], paths: set[str], label: str) -> None:
    _require_offline_paths(context, paths, label)
    for raw_path in paths:
        require(raw_path in context["mapped_directories"],
                f"feedback evidence path map does not mark {label} as a directory: {raw_path}")


def _captured_view_for_path(context: dict[str, Any], path: str | Path) -> Any:
    if context.get("captured") is True and str(path) in context["captured_files"]:
        return context["artifact_view"]
    return None


def _required_captured_file_view(
    context: dict[str, Any], path_value: object, label: str,
) -> Any:
    path = str(absolute_path(path_value, f"{label} path"))
    _require_offline_files(context, {path}, label)
    require(path in context["captured_files"],
            f"{label} is not an exact captured owner output")
    return context["artifact_view"]


def _hash_captured_file(
    artifact_view: Any, path: Path, label: str, maximum: int,
) -> tuple[int, str]:
    require(artifact_view.has_file(path),
            f"{label} is absent from the exact captured refs")
    total = 0
    hasher = hashlib.sha256()
    with artifact_view.open_snapshot(path, label, maximum) as (
            stream, expected_sha, byte_count):
        require(type(byte_count) is int and 0 <= byte_count <= maximum,
                f"{label} captured size exceeds its finite parser bound")
        while total < byte_count:
            block = stream.read(min(1024 * 1024, byte_count - total))
            require(bool(block), f"{label} captured object was truncated")
            total += len(block)
            hasher.update(block)
        require(stream.read(1) == b"" and total == byte_count and
                hasher.hexdigest() == expected_sha,
                f"{label} captured object differs from its exact raw pin")
    return total, hasher.hexdigest()


def _sha256_stable_file(path: Path, label: str, maximum: int) -> tuple[int, str]:
    try:
        require(path.resolve(strict=True) == path, f"{label} traverses a symlink or alias")
        before_path = path.lstat()
        require(stat.S_ISREG(before_path.st_mode), f"{label} must be a regular nonsymlink file")
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
            getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
    except OSError as error:
        raise ValidationError(f"cannot safely open {label}: {error}") from error
    try:
        before = os.fstat(descriptor)
        key = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size,
                            item.st_mtime_ns, item.st_ctime_ns)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
                key(before) == key(before_path) and
                0 <= before.st_size <= maximum,
                f"{label} changed while opening or exceeds its finite byte bound")
        digest_state = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            require(block, f"{label} was truncated during hashing")
            digest_state.update(block)
            remaining -= len(block)
        after_fd, after_path = os.fstat(descriptor), path.lstat()
        require(key(before) == key(after_fd) == key(after_path), f"{label} changed during hashing")
        return before.st_size, digest_state.hexdigest()
    finally:
        os.close(descriptor)


def _preflight_probe_capture_tree(
    capture: dict[str, Any], context: dict[str, Any], capture_path: Path,
) -> list[dict[str, Any]]:
    """Close the mapped output/TMPDIR trees before reading descendants or loading dependencies."""
    stdout_pin = exact(capture["stdout"], {"path", "raw_sha256"}, "offline ProbeV2 stdout pin")
    stderr_pin = exact(capture["stderr"], {"path", "raw_sha256"}, "offline ProbeV2 stderr pin")
    owner_pin = exact(capture["owner_result_pin"], {
        "path", "raw_sha256", "owner_result_sha256",
    }, "offline ProbeV2 owner-result pin")
    inventory_pin = exact(capture["tmpdir_inventory_pin"], {
        "path", "raw_sha256", "inventory_sha256",
    }, "offline ProbeV2 TMPDIR inventory pin")
    for label, pin in (("stdout", stdout_pin), ("stderr", stderr_pin),
                       ("owner result", owner_pin), ("TMPDIR inventory", inventory_pin)):
        absolute_path(pin["path"], f"offline ProbeV2 {label} path")
        digest(pin["raw_sha256"], f"offline ProbeV2 {label} raw SHA-256")
    digest(owner_pin["owner_result_sha256"], "offline ProbeV2 owner-result semantic SHA-256")
    digest(inventory_pin["inventory_sha256"], "offline ProbeV2 TMPDIR inventory semantic SHA-256")
    initial = exact(capture["tmpdir_initial"], {
        "path", "device", "inode", "mode", "mount", "available_bytes", "available_inodes",
        "bytes_limit", "inode_limit",
    }, "offline ProbeV2 initial TMPDIR proof")
    final = exact(capture["tmpdir_final"], {
        "path", "device", "inode", "mode", "mount", "bytes_used", "file_count", "directory_count",
        "bytes_limit", "inode_limit", "available_bytes", "available_inodes",
    }, "offline ProbeV2 final TMPDIR proof")
    tmp_path = absolute_path(initial["path"], "offline ProbeV2 TMPDIR path")
    output_path = absolute_path(str(stdout_pin["path"]), "offline ProbeV2 output root")
    output_directory = output_path.parent
    expected_output_files = {
        str(capture_path), str(Path(stderr_pin["path"])), str(Path(owner_pin["path"])),
        str(Path(inventory_pin["path"])), str(output_path),
    }
    require(Path(stderr_pin["path"]).parent == output_directory and
            Path(owner_pin["path"]).parent == output_directory and capture_path.parent == output_directory and
            Path(inventory_pin["path"]).parent == output_directory and
            tmp_path.parent == output_directory,
            "offline ProbeV2 output/TMPDIR paths do not share their captured private root")
    _require_offline_directories(context, {str(output_directory), str(tmp_path)},
                                 "ProbeV2 output/TMPDIR root")
    _require_offline_files(context, expected_output_files, "ProbeV2 output/receipt member")
    if context.get("captured") is True:
        require(str(output_directory) in context["mapped_directories"] and
                str(tmp_path) in context["mapped_directories"],
                "captured ProbeV2 output/TMPDIR roots lack owner-receipt directory facts")
        direct_files = {
            path for path in context["mapped_files"]
            if Path(path).parent == output_directory
        }
        direct_directories = {
            path for path in context["mapped_directories"]
            if Path(path).parent == output_directory
        }
        require(direct_files == expected_output_files and
                direct_directories == {str(tmp_path)},
                "captured ProbeV2 output root differs from its exact owner inventory")
    else:
        try:
            require(output_directory.resolve(strict=True) == output_directory and
                    tmp_path.resolve(strict=True) == tmp_path,
                    "offline ProbeV2 output/TMPDIR traverses an alias")
            output_info = output_directory.lstat()
            tmp_info = tmp_path.lstat()
            with os.scandir(output_directory) as entries:
                output_names = {entry.name for entry in entries}
        except OSError as error:
            raise ValidationError(f"cannot inspect copied ProbeV2 output/TMPDIR root: {error}") from error
        require(stat.S_ISDIR(output_info.st_mode) and not stat.S_ISLNK(output_info.st_mode) and
                output_info.st_uid == os.getuid() and stat.S_IMODE(output_info.st_mode) == 0o700 and
                stat.S_ISDIR(tmp_info.st_mode) and not stat.S_ISLNK(tmp_info.st_mode) and
                tmp_info.st_uid == os.getuid() and stat.S_IMODE(tmp_info.st_mode) == 0o700,
                "copied ProbeV2 output/TMPDIR roots are not owned private directories")
        require(output_names == {
            "tmp", "stdout.bin", "stderr.bin", "owner-result.json", "tmpdir-inventory.json",
            "capture-receipt.json",
        }, "copied ProbeV2 output root has an unpinned or missing member")
    inventory_value, inventory_raw_sha = read_canonical(
        Path(inventory_pin["path"]), "offline ProbeV2 TMPDIR inventory sidecar",
        MAX_PROBE_TMPDIR_INVENTORY_BYTES, inventory_pin["raw_sha256"],
        artifact_view=_captured_view_for_path(context, inventory_pin["path"]),
    )
    exact(inventory_value, {"schema", "entries", "inventory_sha256"},
          "offline ProbeV2 TMPDIR inventory sidecar")
    inventory_body = {key: item for key, item in inventory_value.items()
                      if key != "inventory_sha256"}
    require(inventory_value["schema"] == PROBE_TMPDIR_INVENTORY_SCHEMA and
            inventory_raw_sha == inventory_pin["raw_sha256"] and
            inventory_value["inventory_sha256"] == inventory_pin["inventory_sha256"] ==
            digest_object(inventory_body),
            "offline ProbeV2 TMPDIR inventory sidecar digest differs from its receipt pin")
    budget = exact(capture["storage_budget"], {
        "tmpdir_bytes", "tmpdir_inodes", "stdout_bytes", "stderr_bytes",
        "owner_result_bytes", "inventory_bytes", "failure_bytes", "receipt_bytes", "output_inodes",
    }, "offline ProbeV2 storage budget")
    inode_limit = uint(budget["tmpdir_inodes"], "offline ProbeV2 TMPDIR inode limit", positive=True)
    byte_limit = uint(budget["tmpdir_bytes"], "offline ProbeV2 TMPDIR byte limit", positive=True)
    require(inode_limit <= 4096 and byte_limit <= 1024 * 1024 * 1024,
            "offline ProbeV2 TMPDIR bounds exceed the fixed finite limits")
    require(budget["owner_result_bytes"] == MAX_PROBE_OWNER_RESULT_BYTES and
            budget["inventory_bytes"] == MAX_PROBE_TMPDIR_INVENTORY_BYTES and
            budget["failure_bytes"] == MAX_PROBE_CAPTURE_FAILURE_BYTES and
            0 < budget["receipt_bytes"] <= MAX_PROBE_CAPTURE_RECEIPT_BYTES and
            7 <= budget["output_inodes"] <= 4096,
            "offline ProbeV2 output budget differs from its finite sidecar bounds")
    inventory = inventory_value["entries"]
    require(type(inventory) is list and len(inventory) <= inode_limit,
            "offline ProbeV2 TMPDIR inventory exceeds its finite inode bound")
    expected: dict[str, dict[str, Any]] = {}
    total_bytes = 0
    paths_in_order: list[str] = []
    for index, item_value in enumerate(inventory):
        item = exact(item_value, {"path", "kind", "uid", "mode", "size", "raw_sha256"},
                     f"offline ProbeV2 TMPDIR inventory[{index}]")
        item_path = absolute_path(item["path"], f"offline ProbeV2 TMPDIR inventory path[{index}]")
        item_text = str(item_path)
        try:
            relative = item_path.relative_to(tmp_path)
        except ValueError as error:
            raise ValidationError("offline ProbeV2 TMPDIR inventory escapes its root") from error
        require(relative.parts and item_text not in expected and item["kind"] in ("file", "directory") and
                type(item["uid"]) is int and item["uid"] >= 0 and
                item["uid"] == os.getuid() and
                type(item["mode"]) is int and 0 <= item["mode"] <= 0o7777,
                "offline ProbeV2 TMPDIR inventory identity/type is malformed")
        if item["kind"] == "file":
            size = uint(item["size"], f"offline ProbeV2 TMPDIR file size[{index}]")
            raw_sha = digest(item["raw_sha256"], f"offline ProbeV2 TMPDIR file SHA[{index}]")
            total_bytes += size
            _require_offline_files(context, {item_text}, "ProbeV2 TMPDIR file descendant")
        else:
            require(item["size"] is None and item["raw_sha256"] is None,
                    "offline ProbeV2 TMPDIR directory inventory carries file content fields")
            _require_offline_directories(context, {item_text}, "ProbeV2 TMPDIR directory descendant")
        expected[item_text] = item
        paths_in_order.append(item_text)
    require(paths_in_order == sorted(paths_in_order) and total_bytes <= byte_limit and
            len(canonical_bytes(inventory)) <= MAX_PROBE_TMPDIR_INVENTORY_BYTES,
            "offline ProbeV2 TMPDIR inventory is unordered or exceeds its finite bound")
    if context.get("captured") is True:
        tree_rows = [exact(row, {
            "owner_job_sha256", "root_path", "role", "owner_receipt_pin",
            "inventory_pin", "inventory_sha256", "entry_count", "byte_count",
            "entries",
        }, f"captured ProbeV2 typed tree[{index}]")
            for index, row in enumerate(context["tree_inventories"])
            if type(row) is dict and row.get("root_path") == str(tmp_path)]
        require(len(tree_rows) == 1,
                "captured ProbeV2 request has no unique typed TMPDIR tree row")
        tree = tree_rows[0]
        receipt_pin = context["probe_capture_pin"]
        expected_owner_pin = {
            "path": receipt_pin["path"],
            "raw_sha256": receipt_pin["raw_sha256"],
            "semantic_sha256": receipt_pin["receipt_sha256"],
        }
        expected_inventory_pin = {
            "path": inventory_pin["path"],
            "raw_sha256": inventory_pin["raw_sha256"],
            "semantic_sha256": inventory_pin["inventory_sha256"],
        }
        require(tree["role"] == "opaque_trace" and
                tree["owner_receipt_pin"] == expected_owner_pin and
                tree["inventory_pin"] == expected_inventory_pin and
                tree["inventory_sha256"] == inventory_pin["inventory_sha256"] and
                tree["entries"] == inventory and
                tree["entry_count"] == len(inventory) and
                tree["byte_count"] == total_bytes,
                "captured ProbeV2 typed tree differs from its exact owner receipt/inventory")
        required_directories = {str(tmp_path)} | {
            path for path, item in expected.items()
            if item["kind"] == "directory"
        }
        require(required_directories <= context["mapped_directories"],
                "captured ProbeV2 typed tree omits an authenticated directory fact")
        for item_path, item in expected.items():
            if item["kind"] == "file":
                size, raw_sha = _hash_captured_file(
                    context["artifact_view"], Path(item_path),
                    "captured ProbeV2 TMPDIR file", byte_limit,
                )
                require(size == item["size"] and raw_sha == item["raw_sha256"],
                        "captured ProbeV2 TMPDIR file differs from its typed inventory")
    require(initial["path"] == final["path"] == str(tmp_path) and
            initial["mode"] == final["mode"] == 0o700 and
            initial["device"] == final["device"] and initial["inode"] == final["inode"] and
            initial["bytes_limit"] == final["bytes_limit"] == byte_limit and
            initial["inode_limit"] == final["inode_limit"] == inode_limit and
            final["bytes_used"] == total_bytes and
            final["file_count"] == sum(1 for item in inventory if item["kind"] == "file") and
            final["directory_count"] == sum(1 for item in inventory if item["kind"] == "directory"),
            "offline ProbeV2 TMPDIR inventory totals differ from its original strict proof")
    owner_result, owner_result_raw_sha = read_canonical(
        Path(owner_pin["path"]), "offline FixedR8 owner-result sidecar",
        MAX_PROBE_OWNER_RESULT_BYTES, owner_pin["raw_sha256"],
        artifact_view=_captured_view_for_path(context, owner_pin["path"]),
    )
    exact(owner_result, {
        "schema", "direct", "start_callback_count", "start_callback_proofs",
        "owner_result_sha256",
    }, "offline FixedR8 owner-result sidecar")
    owner_result_body = {key: item for key, item in owner_result.items()
                         if key != "owner_result_sha256"}
    require(owner_result["schema"] == PROBE_OWNER_RESULT_SCHEMA and
            owner_result_raw_sha == owner_pin["raw_sha256"] and
            owner_result["owner_result_sha256"] == owner_pin["owner_result_sha256"] ==
            digest_object(owner_result_body),
            "offline FixedR8 owner-result sidecar digest differs from its receipt pin")

    if context.get("captured") is True:
        return inventory

    pending = [tmp_path]
    observed: dict[str, os.stat_result] = {}
    while pending:
        current = pending.pop()
        try:
            with os.scandir(current) as entries:
                names: list[str] = []
                for entry in entries:
                    require(len(observed) + len(names) < inode_limit,
                            "copied ProbeV2 TMPDIR directory exceeds its finite inode bound")
                    names.append(entry.name)
        except OSError as error:
            raise ValidationError(f"cannot enumerate copied ProbeV2 TMPDIR {current}: {error}") from error
        for name in names:
            child = current / name
            child_text = str(child)
            item = expected.get(child_text)
            require(item is not None,
                    f"evidence path map omits exact ProbeV2 TMPDIR descendant: {child_text}")
            try:
                info = child.lstat()
            except OSError as error:
                raise ValidationError(f"cannot inspect mapped ProbeV2 TMPDIR descendant: {error}") from error
            actual_kind = "directory" if stat.S_ISDIR(info.st_mode) else "file" if stat.S_ISREG(info.st_mode) else "special"
            require(not stat.S_ISLNK(info.st_mode) and actual_kind == item["kind"] and
                    info.st_uid == item["uid"] == os.getuid() and
                    stat.S_IMODE(info.st_mode) == item["mode"] and
                    (item["kind"] == "directory" or info.st_size == item["size"]),
                    "copied ProbeV2 TMPDIR descendant differs from its closed inventory")
            observed[child_text] = info
            if item["kind"] == "directory":
                pending.append(child)
            require(len(observed) <= inode_limit,
                    "copied ProbeV2 TMPDIR traversal exceeds its finite inode bound")
    require(set(observed) == set(expected),
            "copied ProbeV2 TMPDIR is missing a declared inventory descendant")
    for item_path, item in expected.items():
        if item["kind"] == "file":
            size, raw_sha = _sha256_stable_file(
                Path(item_path), "copied ProbeV2 TMPDIR file", byte_limit,
            )
            require(size == item["size"] and raw_sha == item["raw_sha256"],
                    "copied ProbeV2 TMPDIR file bytes differ from its strict inventory")


def _probe_capture_receipt_budget_bound(receipt: dict[str, Any]) -> int:
    """Recompute the strict capture's maximum-width canonical receipt envelope."""
    template = copy.deepcopy(receipt)
    max_u64 = U64_MAX
    argv = template["probe_argv"]
    environment = template["environment"]
    start_proof = {
        "pid": (1 << 31) - 1,
        "start_ticks": max_u64,
        "requested_argv": argv,
        "requested_argv_sha256": "f" * 64,
        "environment_sha256": "f" * 64,
    }
    role_body = {
        "schema": "allocatbelt.application-feedback-probe-start-role.v1",
        "role": "calibrated_construction_probe",
        "owner_proof": start_proof,
    }
    template["start_callback_count"] = 1
    template["start_callback_proof"] = start_proof
    template["start"] = {**role_body, "start_sha256": "f" * 64}
    template["owner_result_pin"]["raw_sha256"] = "f" * 64
    template["owner_result_pin"]["owner_result_sha256"] = "f" * 64
    template["tmpdir_inventory_pin"]["raw_sha256"] = "f" * 64
    template["tmpdir_inventory_pin"]["inventory_sha256"] = "f" * 64
    template["stdout"]["raw_sha256"] = "f" * 64
    template["stderr"]["raw_sha256"] = "f" * 64
    template["exit_status"] = -((1 << 63) - 1)
    budget = template["storage_budget"]
    final_tmp = template["tmpdir_final"]
    final_tmp["device"] = max_u64
    final_tmp["inode"] = max_u64
    final_tmp["bytes_used"] = budget["tmpdir_bytes"]
    final_tmp["file_count"] = budget["tmpdir_inodes"]
    final_tmp["directory_count"] = budget["tmpdir_inodes"]
    final_tmp["available_bytes"] = max_u64
    final_tmp["available_inodes"] = max_u64
    template["receipt_sha256"] = "f" * 64
    return len(canonical_bytes(template))


def _absolute_json_paths(value: object) -> set[str]:
    paths: set[str] = set()
    path_keys = {
        "path", "source_root", "output_root", "binary_path", "executable_path", "cwd",
        "tmpdir", "trace_directory", "directory", "root", "tmpdir_path",
        "application_tmpdir_path", "pressure_scratch_path", "mount_point",
    }

    def visit(current: object, argv_context: bool = False) -> None:
        if type(current) is dict:
            for key, item in current.items():
                if key in path_keys and type(item) is str and item.startswith("/"):
                    paths.add(item)
                elif key == "environment" and type(item) is dict:
                    temp = item.get("TMPDIR")
                    if type(temp) is str and temp.startswith("/"):
                        paths.add(temp)
                    visit(item)
                else:
                    visit(item, key in {"argv", "requested_argv", "executed_argv", "probe_argv"})
        elif type(current) is list:
            for item in current:
                visit(item, argv_context)
        elif argv_context and type(current) is str and current.startswith("/"):
            paths.add(current)

    visit(value)
    return paths


def _preflight_capacity_request_trace(
    request: object, context: dict[str, Any],
) -> dict[str, Any]:
    request_value = exact(request, {
        "schema", "calibration_id", "identity", "source_manifest", "validation",
        "expectation", "expectation_sha256", "validator_sha256", "trace_directory",
        "context", "minimum_interval_seconds",
    }, "offline capacity producer request")
    require(request_value["schema"] == CAPACITY_REQUEST_SCHEMA_V1,
            "unsupported offline capacity producer request schema")
    for name in ("source_manifest", "validation", "expectation", "context"):
        pin = exact(request_value[name], {"path", "sha256"},
                    f"offline capacity {name} pin")
        absolute_path(pin["path"], f"offline capacity {name} path")
        digest(pin["sha256"], f"offline capacity {name} raw SHA-256")
        _require_offline_files(context, {pin["path"]}, f"offline capacity {name} input")
    digest(request_value["expectation_sha256"], "offline capacity expectation SHA-256")
    digest(request_value["validator_sha256"], "offline capacity validator SHA-256")
    exact(request_value["identity"], {
        "host_id", "run_id", "report_nonce", "process_id", "allocator", "executor",
        "workload", "profile", "mode", "source_sha256", "binary_sha256",
        "pressure_qualification",
    }, "offline capacity identity")
    trace_directory = absolute_path(request_value["trace_directory"],
                                    "offline capacity trace directory")
    _require_offline_directories(context, {str(trace_directory)},
                                 "capacity V4 trace directory")
    trace_files = {str(trace_directory / name) for name in CAPACITY_TRACE_FILES}
    _require_offline_files(context, trace_files, "capacity V4 trace member")
    validation_pin = exact(request_value["validation"], {"path", "sha256"},
                           "offline capacity validation receipt pin")
    validation_path = absolute_path(validation_pin["path"],
                                    "offline capacity validation receipt path")
    _require_offline_files(context, {str(validation_path)},
                           "capacity validation receipt")
    validation, _validation_sha = read_canonical(
        validation_path, "offline capacity validation receipt", MAX_EXPECTATION_BYTES,
        digest(validation_pin["sha256"], "offline capacity validation receipt raw SHA-256"),
    )
    exact(validation, {
        "schema", "mode", "validated", "qualification_eligible", "expectation_raw_sha256",
        "validator_sha256", "identity", "raw_artifact_sha256", "production_window",
        "final_runtime_binding",
    }, "offline capacity validation receipt")
    require(validation["schema"] == READBACK_SCHEMA and
            validation["mode"] == "capacity_calibration" and
            validation["validated"] is True and
            validation["qualification_eligible"] is False,
            "offline capacity validation receipt is not a validated ineligible calibration result")
    raw_trace_pins = exact(validation["raw_artifact_sha256"],
                           {"manifest", "events", "samples"},
                           "offline capacity trace raw pins")
    for name, raw_sha in raw_trace_pins.items():
        digest(raw_sha, f"offline capacity {name} trace raw SHA-256")
    return {
        "trace_directory": str(trace_directory),
        "validation": validation,
        "trace_files": frozenset(trace_files),
    }


def _captured_source5_module(
    source_manifest: dict[str, Any], relative_path: str, label: str, maximum: int,
) -> tuple[types.ModuleType, str]:
    source = source_manifest.get("source")
    record = _source_v5_regular_record(source, relative_path, label)
    raw = _capture_source_v5_sibling(relative_path, record, label)
    path = Path(__file__).resolve().parent.parent.joinpath(*PurePosixPath(relative_path).parts)
    name = f"feedback_source5_{relative_path.rsplit('/', 1)[-1].replace('-', '_')}_{record['sha256']}"
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ""
    try:
        exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    except (SyntaxError, ValueError, TypeError) as error:
        raise ValidationError(f"pinned {label} cannot be compiled from captured bytes: {error}") from error
    require(len(raw) <= maximum, f"pinned {label} exceeds its finite module bound")
    return module, record["sha256"]


def _verify_source5_symlink_literal(
    source_root: Path, relative: PurePosixPath, record: object, label: str,
) -> None:
    """Compare one mapped symlink's bounded literal bytes without following it."""
    value = exact(record, {"path", "kind", "mode", "target", "sha256", "size"},
                  f"{label} symlink inventory record")
    require(value["path"] == relative.as_posix() and value["kind"] == "symlink" and
            value["mode"] == "120000",
            f"{label} symlink record path/kind/mode is invalid")
    target = value["target"]
    require(type(target) is str, f"{label} symlink target is malformed")
    try:
        expected_target = target.encode("utf-8", "strict")
    except UnicodeEncodeError as error:
        raise ValidationError(f"{label} symlink target is not UTF-8") from error
    expected_size = uint(value["size"], f"{label} symlink target size")
    expected_sha = digest(value["sha256"], f"{label} symlink target SHA-256")
    require(0 < len(expected_target) <= 4096 and expected_size == len(expected_target) and
            sha256_bytes(expected_target) == expected_sha,
            f"{label} symlink target hash/size differs from its typed record")
    try:
        components = [part.encode("utf-8", "strict") for part in relative.parts]
    except UnicodeEncodeError as error:
        raise ValidationError(f"{label} symlink path is not UTF-8") from error
    require(bool(components), f"{label} symlink path has no leaf")

    directory_flags = (
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
        getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    root_fd = -1
    parent_fd = -1
    verify_parent_fd = -1

    def stat_key(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
        return (
            info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns,
        )

    def open_parent() -> tuple[int, tuple[tuple[int, int, int, int, int, int], ...]]:
        current = os.dup(root_fd)
        identities: list[tuple[int, int, int, int, int, int]] = []
        try:
            for component in components[:-1]:
                try:
                    child = os.open(component, directory_flags, dir_fd=current)
                except OSError as error:
                    raise ValidationError(
                        f"{label} symlink parent is missing or not a real directory: {error}"
                    ) from error
                try:
                    info = os.fstat(child)
                    require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
                            f"{label} symlink parent is not a real directory")
                    identities.append(stat_key(info))
                except BaseException:
                    os.close(child)
                    raise
                os.close(current)
                current = child
            return current, tuple(identities)
        except BaseException:
            os.close(current)
            raise

    try:
        require(source_root.resolve(strict=True) == source_root,
                f"{label} source root traverses a symlink or alias")
        root_path_before = source_root.lstat()
        require(stat.S_ISDIR(root_path_before.st_mode) and not stat.S_ISLNK(root_path_before.st_mode),
                f"{label} source root is not a real directory")
        root_fd = os.open(os.fsencode(str(source_root)), directory_flags)
        root_before = os.fstat(root_fd)
        require(stat_key(root_before) == stat_key(root_path_before),
                f"{label} source root changed while opening")

        parent_fd, parent_ids = open_parent()
        parent_before = os.fstat(parent_fd)
        leaf = components[-1]
        link_before = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        require(stat.S_ISLNK(link_before.st_mode),
                f"{label} typed symlink path is not a symlink")
        actual_target = os.readlink(leaf, dir_fd=parent_fd)
        require(type(actual_target) is bytes and len(actual_target) <= 4096 and
                link_before.st_size == len(actual_target) == expected_size,
                f"{label} literal symlink target exceeds its finite byte bound or size pin")
        link_after = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        parent_after = os.fstat(parent_fd)

        verify_parent_fd, verify_parent_ids = open_parent()
        verify_parent_before = os.fstat(verify_parent_fd)
        verify_link_before = os.stat(leaf, dir_fd=verify_parent_fd, follow_symlinks=False)
        verify_target = os.readlink(leaf, dir_fd=verify_parent_fd)
        verify_link_after = os.stat(leaf, dir_fd=verify_parent_fd, follow_symlinks=False)
        require(verify_link_before.st_size == len(verify_target) == expected_size,
                f"{label} rechecked symlink target size differs from its typed record")
        verify_parent_after = os.fstat(verify_parent_fd)
        root_after = os.fstat(root_fd)
        root_path_after = source_root.lstat()
        require(source_root.resolve(strict=True) == source_root,
                f"{label} source root moved through an alias")
        require(parent_ids == verify_parent_ids and
                stat_key(parent_before) == stat_key(parent_after) ==
                stat_key(verify_parent_before) == stat_key(verify_parent_after),
                f"{label} symlink parent changed during literal capture")
        require(stat_key(link_before) == stat_key(link_after) ==
                stat_key(verify_link_before) == stat_key(verify_link_after) and
                actual_target == verify_target,
                f"{label} symlink changed during literal capture")
        require(stat_key(root_before) == stat_key(root_after) == stat_key(root_path_after),
                f"{label} source root changed during literal capture")
    except OSError as error:
        raise ValidationError(f"cannot safely capture {label} symlink literal: {error}") from error
    finally:
        for descriptor in (verify_parent_fd, parent_fd, root_fd):
            if descriptor >= 0:
                os.close(descriptor)

    require(actual_target == expected_target and len(actual_target) == expected_size and
            sha256_bytes(actual_target) == expected_sha,
            f"{label} literal target/hash/size differs from its SourceV5 typed record")


def _source5_offline_inventory_closure(
    source_root: Path, inventory: object, artifact_paths: set[str],
    context: dict[str, Any], label: str, *, recorded_artifacts: bool = False,
) -> None:
    """Close typed SourceV5 regular/link paths before the captured verifier runs."""
    require(type(inventory) is list and
            len(inventory) <= MAX_OFFLINE_PATH_MAP_ENTRIES,
            f"{label} typed inventory is malformed or exceeds the path-map bound")
    records: dict[str, str] = {}
    source_files: set[str] = set()
    source_symlinks: set[str] = set()
    symlink_records: list[tuple[PurePosixPath, dict[str, Any]]] = []
    for index, value in enumerate(inventory):
        require(type(value) is dict and type(value.get("kind")) is str,
                f"{label} inventory entry[{index}] is malformed")
        relative_text = text(value.get("path"), f"{label} inventory path[{index}]", 4096)
        relative = PurePosixPath(relative_text)
        require(not relative.is_absolute() and relative.parts and
                ".." not in relative.parts and relative.as_posix() == relative_text and
                "\\" not in relative_text,
                f"{label} inventory path[{index}] is not portable")
        kind = value["kind"]
        require(kind in ("file", "symlink"),
                f"{label} inventory kind[{index}] is unsupported")
        require(relative_text not in records,
                f"{label} inventory repeats {relative_text}")
        records[relative_text] = kind
        absolute = str(source_root.joinpath(*relative.parts))
        if kind == "file":
            source_files.add(absolute)
            continue
        source_symlinks.add(absolute)
        symlink_records.append((relative, value))

    checked_artifacts = {str(absolute_path(path, f"{label} artifact path"))
                         for path in artifact_paths}
    require(not checked_artifacts.intersection(source_files | source_symlinks),
            f"{label} artifact aliases a typed source path")
    require(set(context["mapped_symlinks"]) == source_symlinks,
            f"{label} path map symlinks differ from the typed inventory")
    _require_offline_paths(context, source_symlinks, f"{label} symlink member")
    required_files = source_files if recorded_artifacts else source_files | checked_artifacts
    _require_offline_files(context, required_files,
                           f"{label} regular inventory/artifact member")
    for relative, record in symlink_records:
        _verify_source5_symlink_literal(source_root, relative, record, label)


def _preflight_offline_probe_evidence(
    source_manifest: dict[str, Any], source_pin: dict[str, Any], probe_pin: dict[str, Any],
    capacity_pin: dict[str, Any], context: dict[str, Any], *,
    recorded_artifacts: bool = False,
) -> None:
    source_root = Path(__file__).resolve().parent.parent
    paths = {
        source_pin["path"], probe_pin["path"], capacity_pin["path"],
        context["probe_capture_pin"]["path"],
        *(context["capacity_bundle"][name]["path"] for name in context["capacity_bundle"]),
        str(source_root),
    }
    _require_offline_paths(context, paths, "pinned calibrated probe input")
    _require_offline_directories(context, {str(source_root)}, "SourceV5 source root")
    _require_offline_files(context, {
        source_pin["path"], probe_pin["path"], capacity_pin["path"],
        context["probe_capture_pin"]["path"],
        *(context["capacity_bundle"][name]["path"] for name in context["capacity_bundle"]),
    }, "pinned calibrated probe input")
    source = exact(source_manifest.get("source"), {
        "git_commit", "source_tree_sha256", "cargo_lock_sha256", "files",
    }, "offline SourceV5 typed inventory")
    require(type(source["files"]) is list, "offline SourceV5 inventory is not a list")
    artifact_paths: set[str] = set()
    artifacts = source_manifest.get("artifacts")
    require(type(artifacts) is dict, "offline SourceV5 artifacts are malformed")
    for artifact_value in artifacts.values():
        artifact = exact(artifact_value, {"path", "sha256"}, "offline SourceV5 artifact")
        relative = PurePosixPath(text(artifact["path"], "offline SourceV5 artifact path", 4096))
        require(not relative.is_absolute() and ".." not in relative.parts and
                relative.as_posix() == artifact["path"] and "\\" not in artifact["path"],
                "offline SourceV5 artifact path is not portable")
        digest(artifact["sha256"], "offline SourceV5 artifact SHA-256")
        artifact_paths.add(str(source_root.joinpath(*relative.parts)))
    _source5_offline_inventory_closure(
        source_root, source["files"], artifact_paths, context, "offline SourceV5",
        recorded_artifacts=recorded_artifacts,
    )
    owner_paths = {
        str(source_root / "scripts/application-fixed-pair.py"),
        str(source_root / "scripts/application-soak-readback.py"),
    }
    _require_offline_files(context, owner_paths, "owned probe-capture module")
    _require_offline_paths(context, _absolute_json_paths(source_manifest),
                           "nested SourceV5 evidence")
    capture_pin = context["probe_capture_pin"]
    _require_offline_files(context, {capture_pin["path"]}, "ProbeV2 capture receipt")
    capture_path = absolute_path(capture_pin["path"], "offline ProbeV2 capture receipt path")
    capture_output_root = capture_path.parent
    _require_offline_directories(context, {str(capture_output_root)},
                                 "ProbeV2 captured output root")
    try:
        require(capture_output_root.resolve(strict=True) == capture_output_root,
                "offline ProbeV2 output root traverses an alias")
        capture_output_info = capture_output_root.lstat()
    except OSError as error:
        raise ValidationError(f"cannot inspect copied ProbeV2 output root: {error}") from error
    require(stat.S_ISDIR(capture_output_info.st_mode) and
            not stat.S_ISLNK(capture_output_info.st_mode) and
            capture_output_info.st_uid == os.getuid() and
            stat.S_IMODE(capture_output_info.st_mode) == 0o700,
            "copied ProbeV2 output root is not an owned private directory")
    capture_raw, _capture_sha = read_stable(
        capture_path, "offline ProbeV2 capture receipt",
        MAX_PROBE_CAPTURE_RECEIPT_BYTES,
        artifact_view=_captured_view_for_path(context, capture_path),
    )
    capture = validate_probe_capture_receipt_envelope(
        capture_raw, capture_pin["raw_sha256"], capture_pin["receipt_sha256"],
    )
    capture_paths = _absolute_json_paths(capture)
    if recorded_artifacts:
        capture_paths.difference_update(artifact_paths)
    _require_offline_paths(context, capture_paths,
                           "nested ProbeV2 capture evidence")
    _preflight_probe_capture_tree(capture, context, capture_path)
    probe, _probe_raw_sha = read_canonical(
        Path(probe_pin["path"]), "offline calibrated ProbeV2", MAX_CONSTRUCTION_PROBE_BYTES,
        probe_pin["raw_sha256"],
    )
    _require_offline_paths(context, _absolute_json_paths(probe), "nested ProbeV2 evidence")
    request_pin = context["capacity_bundle"]["request"]
    _require_offline_files(context, {request_pin["path"]}, "capacity producer request")
    request, _request_raw_sha = read_canonical(
        Path(request_pin["path"]), "offline byte-capacity request", MAX_EXPECTATION_BYTES,
        request_pin["raw_sha256"],
    )
    _require_offline_paths(context, _absolute_json_paths(request),
                           "nested byte-capacity request evidence")
    _preflight_capacity_request_trace(request, context)
    expectation_pin = exact(request.get("expectation"), {"path", "sha256"},
                            "offline capacity expectation pin")
    _require_offline_files(context, {expectation_pin["path"]}, "nested capacity expectation")
    capacity_expectation, _capacity_expectation_sha = read_canonical(
        Path(expectation_pin["path"]), "offline capacity expectation",
        MAX_EXPECTATION_BYTES, expectation_pin["sha256"],
    )
    _require_offline_paths(context, _absolute_json_paths(capacity_expectation),
                           "nested capacity expectation evidence")
    capacity_receipt_pin = context["capacity_bundle"]["receipt"]
    _require_offline_files(context, {capacity_receipt_pin["path"]}, "capacity producer receipt")
    capacity_receipt, _capacity_receipt_sha = read_canonical(
        Path(capacity_receipt_pin["path"]), "offline capacity producer receipt",
        MAX_EXPECTATION_BYTES, capacity_receipt_pin["raw_sha256"],
    )
    _require_offline_paths(context, _absolute_json_paths(capacity_receipt),
                           "nested capacity receipt evidence")
    stdout_pin = exact(capture["stdout"], {"path", "raw_sha256"},
                       "offline ProbeV2 stdout pin")
    stderr_pin = exact(capture["stderr"], {"path", "raw_sha256"},
                       "offline ProbeV2 stderr pin")
    _require_offline_files(context, {stdout_pin["path"], stderr_pin["path"]},
                           "offline ProbeV2 raw output")
    stdout, stdout_sha = read_stable(
        Path(stdout_pin["path"]), "offline ProbeV2 stdout",
        MAX_PROBE_OUTPUT_BYTES,
        artifact_view=_captured_view_for_path(context, stdout_pin["path"]),
    )
    stderr, stderr_sha = read_stable(
        Path(stderr_pin["path"]), "offline ProbeV2 stderr",
        MAX_PROBE_OUTPUT_BYTES,
        artifact_view=_captured_view_for_path(context, stderr_pin["path"]),
    )
    require(stdout_sha == stdout_pin["raw_sha256"] == probe_pin["raw_sha256"] and
            stdout == canonical_bytes(probe) and stderr_sha == stderr_pin["raw_sha256"] and not stderr,
            "offline ProbeV2 receipt does not retain the original exact stdout and empty stderr")


def _verify_capacity_bundle_v5_offline(
    source_manifest: dict[str, Any], source_pin: dict[str, Any], identity: dict[str, Any],
    capacity_pin: dict[str, Any], context: dict[str, Any],
) -> None:
    bundle = context["capacity_bundle"]
    require(bundle["artifact"] == capacity_pin,
            "offline capacity artifact pin differs from the feedback expectation")
    artifact_fields, _artifact_sha = _read_capacity_artifact_v5(capacity_pin)
    target_context = {
        "host_id": identity["host_id"], "workload": identity["workload"],
        "profile": identity["profile"], "calibration_id": artifact_fields["calibration_id"],
    }
    pinned_reader, _reader_sha = _captured_source5_module(
        source_manifest, "scripts/application-feedback-readback.py", "feedback validator",
        MAX_SOURCE_MANIFEST_BYTES,
    )
    composer, _composer_sha = _captured_source5_module(
        source_manifest, "scripts/application-feedback-composition.py", "feedback composition validator",
        MAX_SOURCE_MANIFEST_BYTES,
    )
    producer, _producer_sha = _captured_source5_module(
        source_manifest, "scripts/application-byte-capacity.py", "byte-capacity producer",
        MAX_SOURCE_MANIFEST_BYTES,
    )
    bundle_pins = {name: dict(bundle[name]) for name in ("request", "artifact", "receipt")}
    try:
        composer._verify_capacity_request_binding(
            pinned_reader, producer, source_manifest, target_context, identity,
            dict(source_pin), bundle_pins,
        )
    except Exception as error:
        raise ValidationError(f"SourceV5-pinned capacity producer scope replay failed: {error}") from error


def validate_calibrated_construction_probe_v2_offline(
    probe_pin: object, source_manifest_pin: object, capacity_artifact_pin: object,
    identity: dict[str, Any], *, replay_context: object,
    expected_policy: dict[str, Any] | None = None,
    capacity_floor_policy_id: str | None = None,
) -> str:
    """Replay the original SourceV5 ProbeV2 using captured origin-host bytes only."""
    return _validate_calibrated_construction_probe_v2_offline_impl(
        probe_pin, source_manifest_pin, capacity_artifact_pin, identity,
        replay_context=replay_context, expected_policy=expected_policy,
        capacity_floor_policy_id=capacity_floor_policy_id,
        closed_recorded=False,
    )


def validate_calibrated_construction_probe_v2_closed_recorded_v1(
    probe_pin: object, source_manifest_pin: object, capacity_artifact_pin: object,
    identity: dict[str, Any], *, replay_context: object,
    expected_policy: dict[str, Any] | None = None,
    capacity_floor_policy_id: str | None = None,
) -> str:
    """Replay strict capture.v2 owner facts without reopening a historical ELF."""
    return _validate_calibrated_construction_probe_v2_offline_impl(
        probe_pin, source_manifest_pin, capacity_artifact_pin, identity,
        replay_context=replay_context, expected_policy=expected_policy,
        capacity_floor_policy_id=capacity_floor_policy_id,
        closed_recorded=True,
    )


def _closed_recorded_source_executable_paths_v1(
    source_root: Path, source_manifest: dict[str, Any],
) -> set[str]:
    """Derive SourceV5 executable artifacts from an exact canonical manifest."""
    require(source_manifest.get("schema") == SOURCE_MANIFEST_SCHEMA_V5,
            "closed-recorded probe requires SourceV5 metadata")
    semantic = digest(source_manifest.get("manifest_sha256"),
                      "closed-recorded SourceV5 semantic manifest SHA-256")
    body = {key: value for key, value in source_manifest.items()
            if key != "manifest_sha256"}
    require(semantic == digest_object(body),
            "closed-recorded SourceV5 semantic manifest digest is invalid")
    artifacts = source_manifest.get("artifacts")
    require(type(artifacts) is dict and
            set(artifacts) == set(APPLICATION_ALLOCATOR_LABELS),
            "closed-recorded SourceV5 application artifact table is incomplete")
    result: set[str] = set()

    def add(value: object, label: str) -> None:
        artifact = exact(value, {"path", "sha256"},
                         f"closed-recorded SourceV5 executable artifact {label}")
        relative_text = text(artifact["path"], f"{label} artifact path", 4096)
        relative = PurePosixPath(relative_text)
        require(not relative.is_absolute() and relative.parts and
                ".." not in relative.parts and relative.as_posix() == relative_text and
                "\\" not in relative_text,
                f"closed-recorded SourceV5 artifact {label} path is not portable")
        digest(artifact["sha256"], f"closed-recorded SourceV5 artifact {label} SHA-256")
        result.add(str(source_root.joinpath(*relative.parts)))

    for label in APPLICATION_ALLOCATOR_LABELS:
        add(artifacts[label], label)
    soak_artifacts = source_manifest.get("soak_artifacts")
    require(type(soak_artifacts) is dict and set(soak_artifacts) == {"allocatbelt"},
            "closed-recorded SourceV5 soak artifact table is malformed")
    add(soak_artifacts["allocatbelt"], "soak-allocatbelt")
    add(source_manifest.get("analysis_artifact"), "analysis")
    calibration = exact(source_manifest.get("resource_domain_calibration"), {
        "binary", "output", "record", "source", "build", "build_sha256",
    }, "closed-recorded SourceV5 resource-domain calibration")
    add(calibration["binary"], "resource-domain calibration")
    require(len(result) == len(APPLICATION_ALLOCATOR_LABELS) + 3,
            "closed-recorded SourceV5 executable artifacts alias one another")
    return result


def _reject_closed_recorded_artifact_map_v1(
    replay_context: object, role_pins: list[dict[str, Any]],
    source_root: Path, source_manifest: dict[str, Any],
) -> None:
    forbidden = _closed_recorded_source_executable_paths_v1(
        source_root, source_manifest,
    )
    for index, pin in enumerate(role_pins):
        path = str(absolute_path(pin["path"],
                                 f"closed-recorded feedback role path[{index}]"))
        require(path not in forbidden,
                "closed-recorded feedback input pin aliases a SourceV5 executable artifact")
    require(type(replay_context) is dict,
            "closed-recorded feedback context must be a closed identity-map object")
    context = exact(replay_context, {
        "schema", "evidence_path_map", "probe_capture_pin", "capacity_bundle",
    }, "closed-recorded feedback replay context")
    require(context["schema"] == FEEDBACK_OFFLINE_CONTEXT_SCHEMA,
            "closed-recorded feedback replay context schema differs")
    capture = exact(context["probe_capture_pin"], {
        "path", "raw_sha256", "receipt_sha256",
    }, "closed-recorded ProbeV2 capture pin")
    require(str(absolute_path(capture["path"],
                              "closed-recorded ProbeV2 capture path")) not in forbidden,
            "closed-recorded capture pin aliases a SourceV5 executable artifact")
    capacity = exact(context["capacity_bundle"], {"request", "artifact", "receipt"},
                     "closed-recorded feedback capacity bundle")
    for name in capacity:
        pin = exact(capacity[name], {"path", "raw_sha256"},
                    f"closed-recorded feedback capacity {name} pin")
        require(str(absolute_path(pin["path"],
                                  f"closed-recorded capacity {name} path")) not in forbidden,
                "closed-recorded capacity pin aliases a SourceV5 executable artifact")

    mapping = exact(context["evidence_path_map"], {"schema", "entries"},
                    "closed-recorded feedback evidence path map")
    require(mapping["schema"] == EVIDENCE_PATH_MAP_SCHEMA and
            type(mapping["entries"]) is list and
            1 <= len(mapping["entries"]) <= MAX_OFFLINE_PATH_MAP_ENTRIES,
            "closed-recorded feedback evidence map schema or entry count differs")
    previous = ""
    local_paths: set[str] = set()
    for index, entry_value in enumerate(mapping["entries"]):
        entry = exact(entry_value, {"origin", "local"},
                      f"closed-recorded feedback evidence map[{index}]")
        origin = str(absolute_path(entry["origin"],
                                   f"closed-recorded evidence origin[{index}]"))
        local = str(absolute_path(entry["local"],
                                  f"closed-recorded evidence local[{index}]"))
        require(origin == local and origin > previous and local not in local_paths,
                "closed-recorded feedback map must be sorted unique identity paths")
        previous = origin
        local_paths.add(local)
        require(origin not in forbidden and local not in forbidden,
                "closed-recorded feedback map names a SourceV5 executable artifact")


def _validate_calibrated_construction_probe_v2_offline_impl(
    probe_pin: object, source_manifest_pin: object, capacity_artifact_pin: object,
    identity: dict[str, Any], *, replay_context: object,
    expected_policy: dict[str, Any] | None = None,
    capacity_floor_policy_id: str | None = None,
    closed_recorded: bool,
) -> str:
    def snapshot_inputs() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any] | None]:
        try:
            pin_value = json.loads(canonical_bytes(probe_pin).decode("ascii"))
            source_value = json.loads(canonical_bytes(source_manifest_pin).decode("ascii"))
            capacity_value = json.loads(canonical_bytes(capacity_artifact_pin).decode("ascii"))
            identity_value = json.loads(canonical_bytes(identity).decode("ascii"))
            policy_value = (None if expected_policy is None else
                            json.loads(canonical_bytes(expected_policy).decode("ascii")))
        except (TypeError, ValueError, UnicodeError) as error:
            raise ValidationError(
                f"offline calibrated probe inputs are not closed JSON: {error}",
            ) from error
        return pin_value, source_value, capacity_value, identity_value, policy_value

    context = None
    source_manifest_preloaded = None
    source_root = Path(__file__).resolve().parent.parent
    if closed_recorded:
        pin_snapshot, source_pin_snapshot, capacity_snapshot, identity_snapshot, policy_snapshot = snapshot_inputs()
    else:
        context = _validate_feedback_offline_context(replay_context)
        pin_snapshot, source_pin_snapshot, capacity_snapshot, identity_snapshot, policy_snapshot = snapshot_inputs()
    identity = identity_snapshot
    expected_policy = policy_snapshot
    pin = exact(pin_snapshot, {"path", "raw_sha256", "allocator", "binary_sha256"},
                "offline calibrated construction probe pin")
    capacity_pin = exact(capacity_snapshot, {"path", "raw_sha256"},
                         "offline V5 capacity artifact pin")
    source_pin = exact(source_pin_snapshot, {"path", "raw_sha256"},
                       "offline SourceV5 manifest pin")
    if closed_recorded:
        require(source_pin["path"] != str(source_root) and
                not source_pin["path"].startswith(str(source_root).rstrip("/") + "/"),
                "closed-recorded SourceV5 manifest must be outside SourceRoot")
        source_manifest_preloaded, source_raw_sha = read_canonical(
            Path(source_pin["path"]), "closed-recorded SourceV5 manifest",
            MAX_SOURCE_MANIFEST_BYTES,
            digest(source_pin["raw_sha256"], "closed-recorded SourceV5 raw SHA-256"),
        )
        require(source_raw_sha == source_pin["raw_sha256"],
                "closed-recorded SourceV5 manifest raw digest differs")
        source_recipe = {
            "schema": EXPECTATION_SCHEMA_V5, "mode": "pressure_validation",
            "identity": identity,
        }
        _verify_source_manifest_v5(source_manifest_preloaded, source_recipe)
        _reject_closed_recorded_artifact_map_v1(
            replay_context, [source_pin, pin, capacity_pin], source_root,
            source_manifest_preloaded,
        )
        context = _validate_feedback_offline_context(replay_context)
    require(context is not None,
            "feedback offline replay context was not validated")
    _require_offline_directories(context, {str(source_root)}, "SourceV5 source root")
    _require_offline_files(context, {source_pin["path"]}, "SourceV5 manifest")
    if source_manifest_preloaded is None:
        source_manifest, _source_raw_sha = read_canonical(
            Path(source_pin["path"]), "offline SourceV5 manifest", MAX_SOURCE_MANIFEST_BYTES,
            digest(source_pin["raw_sha256"], "offline SourceV5 raw SHA-256"),
        )
    else:
        source_manifest = source_manifest_preloaded
    _preflight_offline_probe_evidence(
        source_manifest, source_pin, pin, capacity_pin, context,
        recorded_artifacts=closed_recorded,
    )
    # The captured SourceV5 campaign verifier checks SourceInventory records only after map closure.
    source_recipe = {
        "schema": EXPECTATION_SCHEMA_V5, "mode": "pressure_validation", "identity": identity,
    }
    if not closed_recorded:
        _verify_source_manifest_v5(source_manifest, source_recipe)
    probe_sha, probe, binary, source_root, _capacity_sha, capacity_path = _check_calibrated_construction_probe_v2_inputs(
        pin, source_manifest, capacity_pin, identity, expected_policy,
        capacity_floor_policy_id,
        artifact_view=_captured_view_for_path(context, pin["path"]),
        closed_recorded=closed_recorded,
    )
    _verify_capacity_bundle_v5_offline(source_manifest, source_pin, identity, capacity_pin, context)
    receipt_pin = context["probe_capture_pin"]
    receipt_raw, receipt_raw_sha = read_stable(
        Path(receipt_pin["path"]), "strict origin-host calibrated probe receipt",
        MAX_PROBE_CAPTURE_RECEIPT_BYTES,
        artifact_view=_captured_view_for_path(context, receipt_pin["path"]),
    )
    receipt = validate_probe_capture_receipt_envelope(
        receipt_raw, receipt_pin["raw_sha256"], receipt_pin["receipt_sha256"],
    )
    if context.get("captured") is True:
        receipt_size = context["artifact_view"].objects[
            receipt_pin["path"]
        ]["byte_count"]
    else:
        receipt_info = Path(receipt_pin["path"]).lstat()
        require(stat.S_ISREG(receipt_info.st_mode) and receipt_info.st_uid == os.getuid() and
                stat.S_IMODE(receipt_info.st_mode) == 0o600,
                "origin-host calibrated probe receipt is not a fresh owned mode-0600 file")
        receipt_size = receipt_info.st_size
    expected_source = {
        "path": source_pin["path"], "raw_sha256": digest(source_pin["raw_sha256"], "SourceV5 raw SHA-256"),
        "semantic_sha256": digest(source_manifest.get("manifest_sha256"), "SourceV5 semantic SHA-256"),
        "source_tree_sha256": digest(source_manifest.get("source", {}).get("source_tree_sha256"), "SourceV5 source-tree SHA-256"),
        "build_sha256": digest_object(source_manifest.get("build")),
    }
    require(receipt["source_manifest"] == expected_source,
            "origin-host probe receipt changed the SourceV5 raw/semantic/tree roles")
    context_bundle = {name: dict(context["capacity_bundle"][name])
                      for name in context["capacity_bundle"]}
    require(receipt["capacity_bundle"] == context_bundle and
            receipt["capacity_tsv"] == context_bundle["artifact"] and
            receipt["probe_pin"] == pin,
            "origin-host probe receipt names a different capacity bundle or ProbeV2")
    artifact = exact(source_manifest["artifacts"].get(identity["allocator"]), {"path", "sha256"},
                     "offline SourceV5 APP artifact")
    binary_pin = {
        "path": str(source_root.joinpath(*PurePosixPath(artifact["path"]).parts)),
        "raw_sha256": digest(artifact["sha256"], "SourceV5 APP artifact SHA-256"),
    }
    require(receipt["binary"] == binary_pin and binary == Path(binary_pin["path"]),
            "origin-host probe receipt names a different SourceV5 ELF")
    expected_probe_argv = [
        str(binary), "--emit-feedback-policy-only", "--workload", identity["workload"],
        "--profile", identity["profile"], "--capacity-calibration-file", str(capacity_path),
        "--capacity-calibration-sha256", _read_capacity_artifact_v5(capacity_pin)[1],
        "--host-id", identity["host_id"], "--source-sha256", identity["source_sha256"],
    ]
    if capacity_floor_policy_id is not None:
        require(capacity_floor_policy_id == CAPACITY_FLOOR_POLICY_ID,
                "offline ProbeV2 capacity floor policy ID is unknown")
        expected_probe_argv.extend(["--capacity-floor-policy-id", capacity_floor_policy_id])
    require(receipt["cwd"] == str(source_root) and
            receipt["probe_argv"] == expected_probe_argv,
            "origin-host probe argv/cwd differs from the original ProbeV2 invocation")
    require(receipt["qualification_eligible"] is False and receipt["execution_ready"] is False and
            receipt["controller_chronology_proven"] is False,
            "origin-host probe receipt claims qualification or launch authority")
    observed_pin = exact(receipt["observed_host"], {"path", "raw_sha256"},
                         "origin-host observed-host pin")
    _require_offline_paths(context, {observed_pin["path"]}, "origin-host observed-host evidence")
    observed, observed_raw_sha = read_canonical(
        Path(observed_pin["path"]), "origin-host observed-host context",
        MAX_SOURCE_MANIFEST_BYTES, observed_pin["raw_sha256"],
        artifact_view=_captured_view_for_path(context, observed_pin["path"]),
    )
    observed = exact(observed, {
        "schema", "host_id", "boot_id_sha256", "controls_sha256", "controls",
        "kernel_release", "cpu_model", "cpu_affinity", "network_namespace_inode",
    }, "origin-host observed-host context")
    require(observed_raw_sha == observed_pin["raw_sha256"] and
            observed["schema"] == "allocatbelt.application-capacity-host-context.v1" and
            observed["host_id"] == identity["host_id"],
            "origin-host observed-host context differs from the exact SourceV5 host")
    origin_facts = exact(receipt["origin_facts"], {
        "schema", "host_id", "boot_id_sha256", "kernel_release", "cpu_affinity",
        "network_namespace_inode", "observed_host_raw_sha256", "origin_facts_sha256",
    }, "captured ProbeV2 origin-host facts")
    origin_body = {key: item for key, item in origin_facts.items() if key != "origin_facts_sha256"}
    require(origin_facts["schema"] == "allocatbelt.application-feedback-probe-origin-facts.v1" and
            origin_facts["host_id"] == observed["host_id"] and
            origin_facts["boot_id_sha256"] == observed["boot_id_sha256"] and
            origin_facts["kernel_release"] == observed["kernel_release"] and
            origin_facts["cpu_affinity"] == observed["cpu_affinity"] and
            origin_facts["network_namespace_inode"] == observed["network_namespace_inode"] and
            origin_facts["observed_host_raw_sha256"] == observed_raw_sha and
            origin_facts["origin_facts_sha256"] == digest_object(origin_body),
            "captured ProbeV2 host facts differ from the original observed-host bytes")
    initial_tmp_for_launch = exact(receipt["tmpdir_initial"], {
        "path", "device", "inode", "mode", "mount", "available_bytes", "available_inodes",
        "bytes_limit", "inode_limit",
    }, "origin-host probe initial TMPDIR storage")
    tmpdir_path_for_launch = absolute_path(
        initial_tmp_for_launch["path"], "origin-host probe launch TMPDIR",
    )
    environment = exact(receipt["environment"], {"PATH", "LANG", "LC_ALL", "TMPDIR"},
                         "captured ProbeV2 strict environment")
    expected_environment = {
        "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
        "TMPDIR": str(tmpdir_path_for_launch),
    }
    receipt_affinity = receipt["affinity"]
    observed_affinity = observed["cpu_affinity"]
    observed_netns = observed["network_namespace_inode"]
    require(type(receipt_affinity) is list and receipt_affinity and
            all(type(cpu) is int and 0 <= cpu <= 65_535 for cpu in receipt_affinity) and
            receipt_affinity == sorted(set(receipt_affinity)) and
            type(receipt["netns"]) is int and receipt["netns"] > 0 and
            type(observed_affinity) is list and observed_affinity and
            all(type(cpu) is int and 0 <= cpu <= 65_535 for cpu in observed_affinity) and
            observed_affinity == sorted(set(observed_affinity)) and
            type(observed_netns) is int and observed_netns > 0 and
            environment == expected_environment and
            receipt_affinity == observed_affinity == origin_facts["cpu_affinity"] and
            receipt["netns"] == observed_netns ==
            origin_facts["network_namespace_inode"],
            "captured ProbeV2 environment/affinity/netns differs from strict origin-host facts")
    start_role = exact(receipt["start"], APP_CAPTURE_START_ROLE_FIELDS,
                       "captured calibrated-probe start role")
    start_role_body = {key: item for key, item in start_role.items() if key != "start_sha256"}
    owner_start = exact(start_role["owner_proof"], APP_CAPTURE_OWNER_START_FIELDS,
                        "FixedR8 minimal probe start proof")
    callback_start = exact(receipt["start_callback_proof"], APP_CAPTURE_OWNER_START_FIELDS,
                           "FixedR8 on-start callback proof")
    require(start_role["schema"] == "allocatbelt.application-feedback-probe-start-role.v1" and
            start_role["role"] == "calibrated_construction_probe" and
            start_role["start_sha256"] == digest_object(start_role_body) and
            uint(receipt["start_callback_count"], "FixedR8 start callback count", positive=True) == 1 and
            callback_start == owner_start and
            uint(owner_start["pid"], "origin probe PID", positive=True, maximum=(1 << 31) - 1) > 0 and
            uint(owner_start["start_ticks"], "origin probe start ticks", positive=True) > 0 and
            owner_start["requested_argv"] == receipt["probe_argv"] and
            owner_start["requested_argv_sha256"] == digest_object(receipt["probe_argv"]) and
            owner_start["environment_sha256"] == digest_object(receipt["environment"]),
            "FixedR8 minimal probe proof differs from its exact versioned role projection")
    owner_result_pin = exact(receipt["owner_result_pin"], {
        "path", "raw_sha256", "owner_result_sha256",
    }, "captured FixedR8 owner-result pin")
    _require_offline_files(context, {owner_result_pin["path"]},
                           "captured FixedR8 owner result")
    owner_result_path = absolute_path(owner_result_pin["path"],
                                      "captured FixedR8 owner-result path")
    owner_result, owner_result_raw_sha = read_canonical(
        owner_result_path, "captured FixedR8 direct owner result",
        MAX_PROBE_OWNER_RESULT_BYTES, digest(owner_result_pin["raw_sha256"],
                                             "captured FixedR8 owner-result raw SHA-256"),
        artifact_view=_captured_view_for_path(context, owner_result_path),
    )
    exact(owner_result, {
        "schema", "direct", "start_callback_count", "start_callback_proofs",
        "owner_result_sha256",
    }, "captured FixedR8 owner-result record")
    owner_result_body = {key: item for key, item in owner_result.items()
                         if key != "owner_result_sha256"}
    require(owner_result["schema"] == PROBE_OWNER_RESULT_SCHEMA and
            digest(owner_result["owner_result_sha256"], "FixedR8 owner-result digest") ==
            owner_result_pin["owner_result_sha256"] == digest_object(owner_result_body) and
            owner_result_raw_sha == owner_result_pin["raw_sha256"] and
            owner_result["start_callback_count"] == receipt["start_callback_count"] and
            owner_result["start_callback_proofs"] ==
            ([] if receipt["start_callback_proof"] is None else [receipt["start_callback_proof"]]),
            "captured FixedR8 owner result differs from the receipt's original direct status/callback")
    if context.get("captured") is not True:
        owner_result_info = owner_result_path.lstat()
        require(stat.S_ISREG(owner_result_info.st_mode) and owner_result_info.st_uid == os.getuid() and
                stat.S_IMODE(owner_result_info.st_mode) == 0o600,
                "captured FixedR8 owner-result file is not an owned mode-0600 file")
    inventory_pin = exact(receipt["tmpdir_inventory_pin"], {
        "path", "raw_sha256", "inventory_sha256",
    }, "captured ProbeV2 TMPDIR inventory pin")
    _require_offline_files(context, {inventory_pin["path"]},
                           "captured ProbeV2 TMPDIR inventory sidecar")
    inventory_path = absolute_path(inventory_pin["path"],
                                   "captured ProbeV2 TMPDIR inventory path")
    inventory_value, inventory_raw_sha = read_canonical(
        inventory_path, "captured ProbeV2 TMPDIR inventory sidecar",
        MAX_PROBE_TMPDIR_INVENTORY_BYTES, digest(inventory_pin["raw_sha256"],
                                                 "ProbeV2 TMPDIR inventory raw SHA-256"),
        artifact_view=_captured_view_for_path(context, inventory_path),
    )
    exact(inventory_value, {"schema", "entries", "inventory_sha256"},
          "captured ProbeV2 TMPDIR inventory sidecar")
    inventory_body = {key: item for key, item in inventory_value.items()
                      if key != "inventory_sha256"}
    require(inventory_value["schema"] == PROBE_TMPDIR_INVENTORY_SCHEMA and
            inventory_raw_sha == inventory_pin["raw_sha256"] and
            digest(inventory_value["inventory_sha256"], "ProbeV2 TMPDIR inventory digest") ==
            inventory_pin["inventory_sha256"] == digest_object(inventory_body),
            "captured ProbeV2 TMPDIR inventory differs from its exact raw/semantic pins")
    if context.get("captured") is not True:
        inventory_info = inventory_path.lstat()
        require(stat.S_ISREG(inventory_info.st_mode) and inventory_info.st_uid == os.getuid() and
                stat.S_IMODE(inventory_info.st_mode) == 0o600,
                "captured ProbeV2 TMPDIR inventory is not an owned mode-0600 file")
    inventory = inventory_value["entries"]
    direct = exact(owner_result["direct"], DIRECT_CAPTURE_FIELDS,
                   "owned calibrated probe process capture")
    require(direct["start"] == owner_start,
            "captured owner-result start proof differs from the exact versioned role projection")
    supervision = exact(direct["supervision"], {
        "leader_info", "child_return_code", "timed_out", "artifact_budget_exceeded", "received_signal",
        "term_grace_seconds", "kill_reap_seconds", "signals", "leader_unreaped_during_group_signals",
        "group_signal_after_leader_reap_count", "leader_reaped", "remaining_session_members",
        "cleanup_errors", "cleanup_status",
    }, "owned calibrated probe cleanup")
    leader_info = exact(supervision["leader_info"], {"si_code", "si_status", "si_pid"},
                        "owned calibrated probe unreaped leader status")
    timing = exact(direct["timing"], {
        "schema", "time_source", "pid", "started_monotonic_ns", "ended_monotonic_ns",
        "elapsed_ns", "exit_code", "child_return_code", "timed_out",
        "artifact_budget_exceeded", "cleanup_status",
    }, "owned calibrated probe timing")
    if closed_recorded:
        binary_size = uint(direct["binary_size"],
                           "captured ProbeV2 executable byte size", positive=True,
                           maximum=MAX_APP_BINARY_BYTES)
        binary_info_size = binary_size
    else:
        binary_info = binary.stat(follow_symlinks=False)
        binary_info_size = binary_info.st_size
    capture_timeout_ns = uint(receipt["capture_timeout_ns"],
                              "captured ProbeV2 timeout nanoseconds", positive=True,
                              maximum=30_000_000_000)
    require(direct["status"] == receipt["exit_status"] == 0 and
            direct["child_return_code"] == supervision["child_return_code"] == 0 and
            direct["start"] == owner_start and direct["requested_argv"] == receipt["probe_argv"] and
            direct["requested_argv_sha256"] == digest_object(receipt["probe_argv"]) and
            direct["environment"] == receipt["environment"] and direct["cwd"] == receipt["cwd"] and
            direct["environment_sha256"] == digest_object(receipt["environment"]) and
            direct["binary_path"] == binary_pin["path"] and
            direct["binary_sha256"] == binary_pin["raw_sha256"] and
            direct["binary_size"] == binary_info_size and
            (not closed_recorded or (
                uint(direct["binary_device"],
                     "captured ProbeV2 executable device", positive=True) > 0 and
                uint(direct["binary_inode"],
                     "captured ProbeV2 executable inode", positive=True) > 0
            )) and
            direct["cpu_affinity"] == receipt["affinity"] and
            direct["network_namespace_inode"] == receipt["netns"] and
            timing["schema"] == "allocatbelt.application-fixed-pair-direct-launch-time.v1" and
            timing["time_source"] == "monotonic_direct_supervisor" and
            timing["pid"] == owner_start["pid"] and timing["exit_code"] == direct["status"] and
            timing["child_return_code"] == direct["child_return_code"] and
            timing["timed_out"] is False and timing["artifact_budget_exceeded"] is False and
            timing["cleanup_status"] == supervision["cleanup_status"] and
            timing["ended_monotonic_ns"] > timing["started_monotonic_ns"] and
            timing["elapsed_ns"] == timing["ended_monotonic_ns"] - timing["started_monotonic_ns"] and
            timing["elapsed_ns"] <= capture_timeout_ns and
            direct["started_monotonic_ns"] == timing["started_monotonic_ns"] and
            direct["ended_monotonic_ns"] == timing["ended_monotonic_ns"] and
            direct["received_signal"] is None and supervision["timed_out"] is False and
            supervision["artifact_budget_exceeded"] is False and
            supervision["received_signal"] is None and supervision["signals"] == [] and
            leader_info["si_pid"] == owner_start["pid"] and leader_info["si_status"] == 0 and
            type(leader_info["si_code"]) is int and leader_info["si_code"] > 0 and
            supervision["leader_reaped"] is True and supervision["remaining_session_members"] == [] and
            supervision["cleanup_errors"] == [] and supervision["cleanup_status"] == "verified" and
            supervision["group_signal_after_leader_reap_count"] == 0 and
            supervision["leader_unreaped_during_group_signals"] is True,
            "origin-host direct process/cleanup evidence is not a successful owned capture")
    stdout_pin = exact(receipt["stdout"], {"path", "raw_sha256"}, "captured probe stdout pin")
    stderr_pin = exact(receipt["stderr"], {"path", "raw_sha256"}, "captured probe stderr pin")
    _require_offline_paths(context, {stdout_pin["path"], stderr_pin["path"]},
                           "owned calibrated probe output")
    if context.get("captured") is not True:
        for label, output_pin in (("stdout", stdout_pin), ("stderr", stderr_pin)):
            output_info = Path(output_pin["path"]).lstat()
            require(stat.S_ISREG(output_info.st_mode) and output_info.st_uid == os.getuid() and
                    stat.S_IMODE(output_info.st_mode) == 0o600,
                    f"captured ProbeV2 {label} is not an owned mode-0600 file")
    storage_budget = exact(receipt["storage_budget"], {
        "tmpdir_bytes", "tmpdir_inodes", "stdout_bytes", "stderr_bytes",
        "owner_result_bytes", "inventory_bytes", "failure_bytes", "receipt_bytes", "output_inodes",
    }, "origin-host probe storage budget")
    for key in storage_budget:
        uint(storage_budget[key], f"origin-host probe {key} budget", positive=True)
    require(storage_budget["tmpdir_bytes"] <= 1024 * 1024 * 1024 and
            storage_budget["tmpdir_inodes"] <= 4096 and
            storage_budget["stdout_bytes"] <= MAX_PROBE_OUTPUT_BYTES and
            storage_budget["stderr_bytes"] <= 64 * 1024 and
            storage_budget["owner_result_bytes"] == MAX_PROBE_OWNER_RESULT_BYTES and
            storage_budget["inventory_bytes"] == MAX_PROBE_TMPDIR_INVENTORY_BYTES and
            storage_budget["failure_bytes"] == MAX_PROBE_CAPTURE_FAILURE_BYTES and
            0 < storage_budget["receipt_bytes"] <= MAX_PROBE_CAPTURE_RECEIPT_BYTES and
            7 <= storage_budget["output_inodes"] <= 4096 and
            receipt_size <= storage_budget["receipt_bytes"],
            "origin-host probe storage budget exceeds the finite owner limits")
    receipt_budget_bound = _probe_capture_receipt_budget_bound(receipt)
    require(storage_budget["receipt_bytes"] >= receipt_budget_bound,
            "origin-host probe receipt budget is below its recomputed prospective canonical bound")
    stdout, stdout_sha = read_stable(
        Path(stdout_pin["path"]), "captured ProbeV2 stdout",
        MAX_PROBE_OUTPUT_BYTES,
        artifact_view=_captured_view_for_path(context, stdout_pin["path"]),
    )
    stderr, stderr_sha = read_stable(
        Path(stderr_pin["path"]), "captured ProbeV2 stderr",
        MAX_PROBE_OUTPUT_BYTES,
        artifact_view=_captured_view_for_path(context, stderr_pin["path"]),
    )
    require(stdout_sha == stdout_pin["raw_sha256"] and stderr_sha == stderr_pin["raw_sha256"] and
            receipt["output_matches_probe"] is True and receipt["stderr_empty"] is True and
            len(stdout) <= storage_budget["stdout_bytes"] and
            len(stderr) <= storage_budget["stderr_bytes"] and
            stdout == canonical_bytes(probe) and stdout_sha == probe_sha and not stderr,
            "captured origin-host ProbeV2 stdout/stderr differs from the unchanged original bytes")
    output_mount = exact(receipt["output_mount"], {
        "mount_id", "major_minor", "mount_root", "mount_point", "filesystem_type",
        "mount_source", "device", "available_bytes", "available_inodes",
    }, "origin-host probe output mount")
    require(type(output_mount["mount_id"]) is int and output_mount["mount_id"] > 0 and
            type(output_mount["device"]) is int and output_mount["device"] >= 0 and
            type(output_mount["available_bytes"]) is int and output_mount["available_bytes"] >= 0 and
            type(output_mount["available_inodes"]) is int and output_mount["available_inodes"] >= 0 and
            output_mount["available_bytes"] >= storage_budget["tmpdir_bytes"] +
            storage_budget["stdout_bytes"] +
            storage_budget["stderr_bytes"] + storage_budget["owner_result_bytes"] +
            storage_budget["inventory_bytes"] + storage_budget["failure_bytes"] +
            storage_budget["receipt_bytes"] and
            output_mount["available_inodes"] >= storage_budget["tmpdir_inodes"] +
            storage_budget["output_inodes"] and
            type(output_mount["filesystem_type"]) is str and
            output_mount["filesystem_type"] not in ("tmpfs", "ramfs", "devtmpfs"),
            "origin-host probe output mount facts are malformed or memory-backed")
    output_mount_static = {key: output_mount[key] for key in (
        "mount_id", "major_minor", "mount_root", "mount_point", "filesystem_type",
        "mount_source", "device",
    )}
    output_directory = Path(stdout_pin["path"]).parent
    require(Path(stderr_pin["path"]).parent == output_directory and
            owner_result_path.parent == output_directory and inventory_path.parent == output_directory and
            Path(receipt_pin["path"]).parent == output_directory and
            Path(receipt["tmpdir_initial"]["path"]).parent == output_directory and
            Path(output_mount["mount_point"]).is_absolute(),
            "origin-host probe storage paths are outside their captured private output root")
    if context.get("captured") is not True:
        try:
            output_members = {item.name for item in output_directory.iterdir()}
        except OSError as error:
            raise ValidationError(f"cannot enumerate origin-host probe output root: {error}") from error
        require(output_members == {
            "tmp", "stdout.bin", "stderr.bin", "owner-result.json", "tmpdir-inventory.json",
            "capture-receipt.json",
        },
                "origin-host probe output root has missing or unpinned members")
    initial_tmp = exact(receipt["tmpdir_initial"], {
        "path", "device", "inode", "mode", "mount", "available_bytes", "available_inodes",
        "bytes_limit", "inode_limit",
    }, "origin-host probe initial TMPDIR storage")
    final_tmp = exact(receipt["tmpdir_final"], {
        "path", "device", "inode", "mode", "mount", "bytes_used", "file_count",
        "directory_count", "bytes_limit", "inode_limit", "available_bytes", "available_inodes",
    }, "origin-host probe final TMPDIR storage")
    tmp_path = absolute_path(initial_tmp["path"], "origin-host probe TMPDIR")
    require(initial_tmp["path"] == final_tmp["path"] == str(tmp_path) and
            initial_tmp["mode"] == final_tmp["mode"] == 0o700 and
            initial_tmp["device"] == final_tmp["device"] and
            initial_tmp["inode"] == final_tmp["inode"] and
            initial_tmp["mount"] == final_tmp["mount"] and
            type(initial_tmp["bytes_limit"]) is int and initial_tmp["bytes_limit"] > 0 and
            initial_tmp["bytes_limit"] == final_tmp["bytes_limit"] == storage_budget["tmpdir_bytes"] and
            type(initial_tmp["inode_limit"]) is int and initial_tmp["inode_limit"] > 0 and
            initial_tmp["inode_limit"] == final_tmp["inode_limit"] == storage_budget["tmpdir_inodes"] and
            type(initial_tmp["available_bytes"]) is int and
            initial_tmp["available_bytes"] >= initial_tmp["bytes_limit"] and
            type(initial_tmp["available_inodes"]) is int and
            initial_tmp["available_inodes"] >= initial_tmp["inode_limit"] and
            initial_tmp["mount"] == final_tmp["mount"] == output_mount_static,
            "origin-host probe TMPDIR storage does not match its original bounded output mount")
    modules = exact(receipt["owner_modules"], {"fixed_pair", "launch_identity_helper"},
                    "origin-host process owner module pins")
    for name, relative in (
        ("fixed_pair", "scripts/application-fixed-pair.py"),
        ("launch_identity_helper", "scripts/application-soak-readback.py"),
    ):
        module_pin = exact(modules[name], {"path", "raw_sha256"}, f"origin {name} pin")
        require(module_pin["path"] == relative, f"origin {name} path differs from the captured SourceV5 owner")
        record = _source_v5_regular_record(source_manifest["source"], relative, name)
        require(module_pin["raw_sha256"] == record["sha256"], f"origin {name} bytes differ from SourceV5 inventory")
    fixed_module, _fixed_sha = _captured_source5_module(
        source_manifest, "scripts/application-fixed-pair.py", "FixedR8 direct process owner",
        MAX_SOURCE_MANIFEST_BYTES,
    )
    _helper_module, _helper_sha = _captured_source5_module(
        source_manifest, "scripts/application-soak-readback.py", "FixedR8 launch identity helper",
        MAX_SOURCE_MANIFEST_BYTES,
    )
    verify_tmpdir = getattr(fixed_module, "_verify_tmpdir_storage_offline", None)
    require(callable(verify_tmpdir),
            "SourceV5-pinned FixedR8 offline TMPDIR storage verifier is unavailable")
    verify_tmpdir(
        initial_tmp, final_tmp, str(tmp_path), initial_tmp["bytes_limit"],
        initial_tmp["inode_limit"], output_mount_static, "origin-host probe",
    )
    inventory = inventory_value["entries"]
    require(final_tmp["bytes_used"] == sum(
                item["size"] for item in inventory if item["kind"] == "file"
            ) and
            final_tmp["file_count"] == sum(1 for item in inventory if item["kind"] == "file") and
            final_tmp["directory_count"] == sum(1 for item in inventory if item["kind"] == "directory"),
            "origin-host ProbeV2 TMPDIR inventory totals differ from strict storage receipt")
    require(final_tmp["bytes_used"] <= final_tmp["bytes_limit"] and
            final_tmp["file_count"] + final_tmp["directory_count"] <= final_tmp["inode_limit"],
            "origin-host probe TMPDIR exceeded its captured finite storage limits")
    return probe_sha


def _validate_calibrated_construction_evidence(
    source_manifest: dict[str, Any], probe: dict[str, Any], identity: dict[str, Any],
) -> None:
    expected_bounds = _validate_meter_source_bounds(probe["meter_source_bounds"], identity["workload"], "calibrated probe meter source bounds")
    require(probe["meter_source_bounds"] == meter_source_bounds_for_workload(identity["workload"]), "calibrated meter bounds differ from the workload source model")
    model = exact(probe["meter_source_model"], set(CONSTRUCTION_PROBE_METER_SOURCE_MODEL) | {"http_client_window", "http_handler_window"}, "calibrated meter source model")
    for key, value in CONSTRUCTION_PROBE_METER_SOURCE_MODEL.items():
        require(model[key] == value, f"calibrated meter source model differs at {key}")
    require(uint(model["http_client_window"], "calibrated HTTP client window", positive=True) == 8, "calibrated HTTP client window differs")
    require(uint(model["http_handler_window"], "calibrated HTTP handler window", positive=True) == 8, "calibrated HTTP handler window differs")
    if identity["workload"] in ("http", "mixed"):
        require(expected_bounds["upload"]["maximum_live"] == 16 and expected_bounds["download"]["maximum_live"] == 16, "calibrated endpoint windows do not explain meter bounds")

    source = exact(source_manifest["source"], {"git_commit", "source_tree_sha256", "cargo_lock_sha256", "files"}, "calibrated SourceV5 source inventory")
    records = source["files"]
    require(type(records) is list, "calibrated SourceV5 source inventory is not a list")
    by_path = {item.get("path"): item for item in records if type(item) is dict}
    require(len(by_path) == len(records), "calibrated SourceV5 source inventory has malformed or duplicate paths")
    references = exact(probe["source_references"], set(CONSTRUCTION_PROBE_SOURCE_REFERENCES), "calibrated probe source references")
    for name, relative in CONSTRUCTION_PROBE_SOURCE_REFERENCES.items():
        require(references[name] == relative, f"calibrated probe source reference differs at {name}")
        record = exact(by_path.get(relative), {"path", "kind", "mode", "sha256", "size"}, f"calibrated source reference {name}")
        require(record["path"] == relative and record["kind"] == "file" and record["mode"] in ("100644", "100755"), f"calibrated source reference is not an exact regular inventory entry: {name}")
        digest(record["sha256"], f"calibrated source reference SHA {name}")
        uint(record["size"], f"calibrated source reference size {name}")

    policy, _algorithm, _workers = _static_policy_from_source_v5(source_manifest, identity, probe["collector"], probe["rust_control_context"]["algorithm"])
    baseline = policy["collector"]["expected_global_control_baseline"]
    calibration = exact(source_manifest["resource_domain_calibration"], {
        "binary", "output", "record", "source", "build", "build_sha256",
    }, "calibrated SourceV5 resource-domain calibration")
    calibration_record = exact(calibration["record"], {
        "schema", "architecture", "max_tenants", "max_waiters", "control_ceiling",
        "fixed_global_control_baseline", "tenant_owner_control_bytes", "final_live_tenants",
        "final_global_control_bytes",
    }, "calibrated SourceV5 resource-domain calibration record")
    baseline_probe = exact(probe["baseline"], {"expected_global_control_baseline"}, "calibrated probe baseline")
    require(uint(baseline_probe["expected_global_control_baseline"], "calibrated expected global Control baseline", positive=True) == baseline, "calibrated probe baseline differs from SourceV5")

    collector = _validate_v2_collector(probe["collector"], "calibrated V2 probe collector")
    control_charge = uint(collector["control_charge_bytes"], "calibrated collector Control charge", positive=True)
    require(uint(collector["task_lease_count"], "calibrated collector task lease", positive=True) == 1, "calibrated probe collector must own one Task lease")
    construction = exact(probe["construction"], {"collector", "global_control_used_with_owners", "meters", "rate_buckets", "tenant_live_with_owners"}, "calibrated construction evidence")
    actual_collector = _validate_v2_collector(construction["collector"], "calibrated constructed collector evidence")
    require(uint(actual_collector["control_charge_bytes"], "actual collector Control charge", positive=True) == control_charge, "construction Control charge differs from the top-level collector")
    require(uint(actual_collector["task_lease_count"], "actual collector Task lease", positive=True) == 1, "construction Task lease differs from the contract")
    tenant_control_with_admission = uint(actual_collector["tenant_control_used_with_admission"], "actual tenant collector Control use", positive=True)
    require(actual_collector == collector, "constructed collector observations differ from the top-level V2 collector")
    require(tenant_control_with_admission >= control_charge, "constructed tenant Control use omits the observed collector charge")
    require(uint(actual_collector["tenant_tasks_used_with_admission"], "actual tenant collector Task use", positive=True) == 1, "constructed collector Task use differs")
    require(uint(construction["global_control_used_with_owners"], "actual global Control use", positive=True) == baseline + tenant_control_with_admission, "construction global Control does not include calibrated tenant and collector charges")
    require(uint(construction["tenant_live_with_owners"], "constructed live tenant count", positive=True) == 1, "construction probe did not observe exactly one live tenant")

    actual_buckets = exact(construction["rate_buckets"], set(RATE_DIRECTIONS), "constructed rate bucket set")
    expected_buckets = probe["rust_control_context"]["rate_buckets"]
    for direction in RATE_DIRECTIONS:
        actual = exact(actual_buckets[direction], {
            "bytes_per_second", "ceiling_bytes_per_second", "burst_bytes", "ceiling_burst_bytes", "max_reservations", "reservations",
        }, f"constructed {direction} rate bucket")
        expected = exact(expected_buckets[direction], {
            "initial_bytes_per_second", "ceiling_bytes_per_second", "ceiling_burst_bytes", "max_reservations",
        }, f"resolved {direction} rate bucket")
        require(uint(actual["bytes_per_second"], f"constructed {direction} initial rate", positive=True) == expected["initial_bytes_per_second"], f"constructed {direction} initial rate differs from resolution")
        require(uint(actual["ceiling_bytes_per_second"], f"constructed {direction} rate ceiling", positive=True) == expected["ceiling_bytes_per_second"], f"constructed {direction} rate ceiling differs from resolution")
        require(uint(actual["burst_bytes"], f"constructed {direction} burst", positive=True) == expected["ceiling_burst_bytes"], f"constructed {direction} burst differs from source policy")
        require(uint(actual["ceiling_burst_bytes"], f"constructed {direction} burst ceiling", positive=True) == expected["ceiling_burst_bytes"], f"constructed {direction} burst ceiling differs from source policy")
        require(uint(actual["max_reservations"], f"constructed {direction} reservation cap", positive=True) == expected["max_reservations"], f"constructed {direction} reservation cap differs from source policy")
        require(uint(actual["reservations"], f"constructed {direction} reservations") == 0, f"constructed {direction} bucket has a live reservation")

    meters = exact(construction["meters"], set(RATE_DIRECTIONS), "constructed meter set")
    for direction in RATE_DIRECTIONS:
        meter = exact(meters[direction], {"attached_sources", "committed_bytes", "completions", "diagnostics_clear", "generation"}, f"constructed {direction} meter")
        for key in ("attached_sources", "committed_bytes", "completions", "generation"):
            require(uint(meter[key], f"constructed {direction} meter {key}") == 0, f"constructed {direction} meter {key} is nonzero")
        require(type(meter["diagnostics_clear"]) is bool and meter["diagnostics_clear"] is True, f"constructed {direction} meter diagnostics are not clear")

    after = exact(probe["after_release"], {
        "control_used", "control_matches_fixed_baseline", "expected_global_control_baseline", "live_tenants", "zero_dimensions",
    }, "calibrated owner-release evidence")
    require(uint(after["control_used"], "after-release Control use") == baseline, "after-release Control use differs from SourceV5 baseline")
    require(after["control_matches_fixed_baseline"] is True, "after-release Control baseline check did not pass")
    require(uint(after["expected_global_control_baseline"], "after-release expected baseline", positive=True) == baseline, "after-release expected baseline differs from SourceV5")
    require(uint(after["live_tenants"], "after-release live tenants") == 0, "after-release probe retains a live tenant")
    zeros = _uint_map(after["zero_dimensions"], {"cpu", "memory", "disk", "network", "tasks"}, "after-release zero dimensions")
    require(all(value == 0 for value in zeros.values()), "after-release probe retains resource usage")


def validate_construction_probe(
    recipe: dict[str, Any], source_manifest_value: dict[str, Any],
    *, artifact_reader: Callable[[Path, str, int], tuple[bytes, str]] | None = None,
) -> str:
    """Validate a v2 probe against a checked expectation and source manifest."""
    require(recipe.get("schema") in (EXPECTATION_SCHEMA_V2, EXPECTATION_SCHEMA_V3, EXPECTATION_SCHEMA_V4), "construction probe validation requires expectation v2, v3, or v4")
    identity = recipe["identity"]
    _validate_v2_workload_profile(identity["workload"], identity["profile"])
    pin = exact(recipe["construction_probe"], {
        "path", "raw_sha256", "allocator", "binary_sha256",
    }, "construction policy probe pin")
    absolute_path(pin["path"], "construction policy probe path")
    digest(pin["raw_sha256"], "construction policy probe raw SHA-256")
    digest(pin["binary_sha256"], "construction probe binary SHA-256")
    require(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", text(pin["allocator"], "construction probe allocator")) is not None,
        "construction probe allocator is not a canonical token",
    )
    require(pin["allocator"] == identity["allocator"], "construction probe allocator differs from feedback identity")
    if recipe.get("schema") == EXPECTATION_SCHEMA_V3:
        require(pin["binary_sha256"] != identity["binary_sha256"], "construction probe application binary must differ from the timed soak binary")
    else:
        require(pin["binary_sha256"] == identity["binary_sha256"], "construction probe binary differs from feedback identity")
    source_schema = source_manifest_value.get("schema")
    require(
        (recipe.get("schema") == EXPECTATION_SCHEMA_V2 and source_schema == SOURCE_MANIFEST_SCHEMA)
        or (recipe.get("schema") in (EXPECTATION_SCHEMA_V3, EXPECTATION_SCHEMA_V4) and source_schema == SOURCE_MANIFEST_SCHEMA_V5),
        "construction probe source manifest schema is unsupported",
    )
    artifacts = source_manifest_value["artifacts"]
    require(type(artifacts) is dict and recipe["identity"]["allocator"] in artifacts, "construction probe allocator is absent from the source manifest")
    if source_schema == SOURCE_MANIFEST_SCHEMA:
        require(set(artifacts) == {"allocatbelt", "mimalloc-secure", "mimalloc-standard", "system"}, "source manifest artifact set is incomplete")
    require(pin["allocator"] in artifacts, "construction probe allocator is absent from the source manifest")
    artifact = exact(artifacts[pin["allocator"]], {"path", "sha256"}, "construction probe source artifact")
    require(
        digest(artifact["sha256"], "construction probe source artifact SHA-256") == pin["binary_sha256"],
        "construction probe binary differs from its source-manifest artifact",
    )
    if artifact_reader is None:
        probe, probe_sha = read_canonical(
            Path(pin["path"]), "construction policy probe", MAX_CONSTRUCTION_PROBE_BYTES, pin["raw_sha256"],
        )
    else:
        raw, probe_sha = artifact_reader(Path(pin["path"]), "construction policy probe", MAX_CONSTRUCTION_PROBE_BYTES)
        require(type(raw) is bytes and len(raw) <= MAX_CONSTRUCTION_PROBE_BYTES and
                probe_sha == pin["raw_sha256"] == sha256_bytes(raw),
                "captured construction policy probe raw bytes differ from their pin or ceiling")
        probe = parse_json(raw, "captured construction policy probe", MAX_CONSTRUCTION_PROBE_BYTES)
        require(raw == canonical_bytes(probe),
                "captured construction policy probe is not canonical JSON")
    exact(probe, {
        "schema", "context", "reader_context", "rust_control_context", "collector",
        "baseline", "meter_source_bounds", "meter_source_model", "source_references",
    }, "construction policy probe")
    require(probe["schema"] == CONSTRUCTION_PROBE_SCHEMA, "unsupported construction policy probe schema")

    context = exact(probe["context"], {"workload", "profile", "workers"}, "construction probe context")
    require(context["workload"] == identity["workload"] and context["profile"] == identity["profile"], "construction probe workload or profile differs from expectation")
    workers = uint(context["workers"], "construction probe workers", positive=True, maximum=4)
    require(workers == (2 if identity["profile"] == "oversubscribed" else 4), "construction probe worker count differs from the frozen profile")

    policy = recipe["policy"]
    reader_context = exact(probe["reader_context"], {
        "version", "minimum_dense_observations", "sample_interval_ns", "max_dense_gap_ns",
        "required_breach_samples", "telemetry_freshness_ns", "actuation_cooldown_ns",
    }, "construction probe reader context")
    require(reader_context["version"] == policy["version"], "construction probe feedback version differs from expectation")
    for field in (
        "minimum_dense_observations", "sample_interval_ns", "max_dense_gap_ns",
        "required_breach_samples", "telemetry_freshness_ns", "actuation_cooldown_ns",
    ):
        value = uint(reader_context[field], f"construction probe reader_context.{field}", positive=True)
        require(value == policy[field], f"construction probe timing or density differs from expectation at {field}")

    rust_context = exact(probe["rust_control_context"], {
        "algorithm", "controls", "global_ceilings", "tenant_ceilings", "scope_limits",
        "rate_buckets", "required_byte_sources",
    }, "construction probe Rust control context")
    algorithm = exact(rust_context["algorithm"], {
        "cpu_reduction_rule", "cpu_recovery_increment", "network_sensor_source", "upload_controlled",
    }, "construction probe feedback algorithm")
    require(type(algorithm["upload_controlled"]) is bool, "construction probe upload-control flag must be boolean")
    require(uint(algorithm["cpu_recovery_increment"], "construction probe CPU recovery increment", positive=True) == 1, "construction probe CPU recovery increment differs from the fixed runtime contract")
    require(
        algorithm["cpu_reduction_rule"] == "floor_current_limit_over_10_zero_is_quantized"
        and algorithm["network_sensor_source"] == "download_application_bytes_only"
        and algorithm["upload_controlled"] is False,
        "construction probe feedback algorithm differs from the fixed runtime contract",
    )
    probe_controls = exact(rust_context["controls"], set(RESOURCES), "construction probe controls")
    for resource in RESOURCES:
        fields = exact(probe_controls[resource], {"floor", "initial", "ceiling", "low_bps", "high_bps"}, f"construction probe {resource} control")
        for field, actual in fields.items():
            uint(actual, f"construction probe {resource}.{field}")
            require(actual == policy["controls"][resource][field], f"construction probe control differs from expectation at {resource}.{field}")
    for owner in ("global_ceilings", "tenant_ceilings"):
        ceilings = _uint_map(rust_context[owner], set(DOMAIN), f"construction probe {owner}")
        require(ceilings == policy[owner], f"construction probe {owner} differ from expectation")
    scope_limits = _uint_map(
        rust_context["scope_limits"], {"managed_memory", "disk_operations", "network_operations"},
        "construction probe scope limits",
    )
    require(scope_limits == policy["scope_limits"], "construction probe scope limits differ from expectation")
    probe_buckets = exact(rust_context["rate_buckets"], set(RATE_DIRECTIONS), "construction probe rate buckets")
    for direction in RATE_DIRECTIONS:
        bucket = exact(probe_buckets[direction], {
            "ceiling_bytes_per_second", "ceiling_burst_bytes", "max_reservations",
        }, f"construction probe {direction} rate bucket")
        for field, actual in bucket.items():
            uint(actual, f"construction probe {direction}.{field}", positive=True)
        require(bucket == policy["rate_buckets"][direction], f"construction probe {direction} rate bucket differs from expectation")

    required_sources = exact(rust_context["required_byte_sources"], {"disk", "download"}, "construction probe required byte sources")
    require(all(type(value) is bool for value in required_sources.values()), "construction probe byte-source flags must be boolean")
    expected_sources = {
        "disk": identity["workload"] in {"disk", "mixed"},
        "download": identity["workload"] in {"http", "mixed"},
    }
    require(required_sources == expected_sources, "construction probe required byte sources differ from workload")

    collector = exact(probe["collector"], {"control_charge_bytes", "task_lease_count"}, "construction probe collector")
    control_charge = uint(collector["control_charge_bytes"], "construction probe collector Control charge", positive=True)
    task_lease_count = uint(collector["task_lease_count"], "construction probe collector Task lease", positive=True)
    require(control_charge == policy["collector"]["control_charge_bytes"], "construction probe collector Control charge differs from expectation")
    require(task_lease_count == policy["collector"]["task_lease_count"], "construction probe collector Task lease differs from expectation")
    baseline = exact(probe["baseline"], {"expected_global_control_baseline"}, "construction probe baseline")
    baseline_value = uint(baseline["expected_global_control_baseline"], "construction probe global Control baseline")
    require(baseline_value == policy["collector"]["expected_global_control_baseline"], "construction probe global Control baseline differs from expectation")

    probe_bounds = _validate_meter_source_bounds(probe["meter_source_bounds"], identity["workload"], "construction probe meter source bounds")
    expected_bounds = _validate_meter_source_bounds(policy["meter_source_bounds"], identity["workload"])
    require(probe_bounds == expected_bounds, "construction probe meter source bounds differ from expectation")
    model = exact(probe["meter_source_model"], {
        "disk_registration_owner", "disk_source_path", "http_client_window", "http_handler_window",
        "http_client_window_source", "http_handler_window_source", "http_registration_owner",
        "http_registration_source", "http_source_path", "stream_registration_owner",
        "disk_registration_source",
    }, "construction probe meter source model")
    for key, expected in CONSTRUCTION_PROBE_METER_SOURCE_MODEL.items():
        require(model[key] == expected, f"construction probe meter source model differs at {key}")
    client_window = uint(model["http_client_window"], "construction probe HTTP client window", positive=True)
    handler_window = uint(model["http_handler_window"], "construction probe HTTP handler window", positive=True)
    require(client_window == 8 and handler_window == 8, "construction probe HTTP source windows differ from the fixed runtime contract")
    if identity["workload"] in {"http", "mixed"}:
        require(client_window + handler_window == expected_bounds["upload"]["maximum_live"], "construction probe HTTP window does not explain its upload source ceiling")
        require(client_window + handler_window == expected_bounds["download"]["maximum_live"], "construction probe HTTP window does not explain its download source ceiling")

    source_references = exact(probe["source_references"], set(CONSTRUCTION_PROBE_SOURCE_REFERENCES), "construction probe source references")
    for name, expected in CONSTRUCTION_PROBE_SOURCE_REFERENCES.items():
        require(source_references[name] == expected, f"construction probe source reference differs at {name}")
    if source_schema == SOURCE_MANIFEST_SCHEMA_V5:
        source = exact(source_manifest_value["source"], {"git_commit", "source_tree_sha256", "cargo_lock_sha256", "files"}, "SourceV5 manifest source")
        records = source["files"]
        require(type(records) is list, "SourceV5 typed source inventory must be a list")
        by_path: dict[str, dict[str, Any]] = {}
        for index, record_value in enumerate(records):
            require(type(record_value) is dict, f"SourceV5 inventory record {index} is malformed")
            record = record_value
            path = text(record.get("path"), f"SourceV5 inventory record {index} path", 4096)
            require(path not in by_path, f"SourceV5 inventory repeats {path}")
            by_path[path] = record
        for name, relative in CONSTRUCTION_PROBE_SOURCE_REFERENCES.items():
            record = by_path.get(relative)
            require(type(record) is dict and record.get("kind") == "file", f"construction probe source reference is not a regular SourceV5 inventory entry: {name}")
            exact(record, {"path", "kind", "mode", "sha256", "size"}, f"SourceV5 regular source entry {name}")
            require(record["path"] == relative and record["mode"] in ("100644", "100755"), f"SourceV5 source entry is malformed at {name}")
            digest(record["sha256"], f"SourceV5 source entry SHA-256 {name}")
            uint(record["size"], f"SourceV5 source entry size {name}")
        policy_artifact = exact(source_manifest_value["feedback_policy"], {"schema", "policy", "policy_sha256"}, "SourceV5 feedback policy artifact")
        require(policy_artifact["schema"] in (
            "allocatbelt.application-feedback-policy-artifact.v1",
            "allocatbelt.application-feedback-policy-artifact.v2",
        ), "SourceV5 feedback policy artifact schema is unsupported")
        policy_body_keys = {
            "schema", "version", "reader_contract", "algorithm", "contexts", "source_pins",
        }
        if policy_artifact["schema"] == "allocatbelt.application-feedback-policy-artifact.v2":
            policy_body_keys.add("capacity_floor_policy")
        policy_body = exact(policy_artifact["policy"], policy_body_keys,
                            "SourceV5 feedback policy body")
        require(digest(policy_artifact["policy_sha256"], "SourceV5 feedback policy digest") == digest_object(policy_body), "SourceV5 feedback policy digest is invalid")
        require(policy_body["schema"] == policy_artifact["schema"], "SourceV5 feedback policy body schema differs")
        if "capacity_floor_policy" in policy_body:
            _validate_capacity_floor_policy_descriptor(policy_body["capacity_floor_policy"])
        require(policy_body["version"] == policy["version"], "SourceV5 feedback policy version differs from expectation")
        reader_contract = exact(policy_body["reader_contract"], {
            "sample_interval_ns", "max_dense_gap_ns", "telemetry_freshness_ns",
            "required_breach_samples", "actuation_cooldown_ns", "minimum_dense_observations",
        }, "SourceV5 feedback policy reader contract")
        expected_reader_contract = {field: policy[field] for field in (
            "sample_interval_ns", "max_dense_gap_ns", "telemetry_freshness_ns",
            "required_breach_samples", "actuation_cooldown_ns", "minimum_dense_observations",
        )}
        require(reader_contract == expected_reader_contract, "SourceV5 reader contract differs from the frozen feedback expectation")
        require(policy_body["algorithm"] == algorithm, "SourceV5 feedback algorithm differs from the construction probe")
        context_key = f"{identity['workload']}/{identity['profile']}"
        contexts = policy_body["contexts"]
        require(type(contexts) is dict and context_key in contexts, "SourceV5 feedback policy omits the frozen workload/profile context")
        context = exact(contexts[context_key], {"workers", "minimum_dense_observations", "controls"}, "SourceV5 feedback policy context")
        require(context["workers"] == workers and context["minimum_dense_observations"] == policy["minimum_dense_observations"], "SourceV5 feedback policy context worker/density differs from the construction probe")
        require(context["controls"] == policy["controls"], "SourceV5 feedback policy context controls differ from the construction probe")
        if recipe.get("schema") == EXPECTATION_SCHEMA_V4:
            _validate_v4_policy_source_projection(recipe, source_manifest_value, probe)
    return probe_sha


def _source_v5_regular_record(source: object, relative_path: str, label: str) -> dict[str, Any]:
    require(type(source) is dict, "SourceV5 source identity must be an object")
    files = source.get("files")
    require(type(files) is list, "SourceV5 typed source inventory must be a list")
    matches = [item for item in files if type(item) is dict and item.get("path") == relative_path]
    require(len(matches) == 1, f"SourceV5 inventory must contain exactly one {label} entry")
    record = exact(matches[0], {"path", "kind", "mode", "sha256", "size"}, f"SourceV5 {label} inventory entry")
    require(record["path"] == relative_path and record["kind"] == "file", f"SourceV5 {label} must be a regular file entry")
    require(record["mode"] in ("100644", "100755"), f"SourceV5 {label} mode is unsupported")
    digest(record["sha256"], f"SourceV5 {label} SHA-256")
    uint(record["size"], f"SourceV5 {label} size")
    return record


def _capture_source_v5_sibling(relative_path: str, record: dict[str, Any], label: str) -> bytes:
    """Capture only the known pinned controller/helper sibling before executing it."""
    path = Path(__file__).resolve().with_name(PurePosixPath(relative_path).name)
    try:
        require(path.resolve(strict=True) == path, f"SourceV5 {label} traverses a symlink or alias")
        before_path = path.lstat()
        require(stat.S_ISREG(before_path.st_mode), f"SourceV5 {label} is not a regular nonsymlink file")
        mode_text = f"{stat.S_IFMT(before_path.st_mode) | stat.S_IMODE(before_path.st_mode):06o}"
        require(mode_text == record["mode"] and before_path.st_size == record["size"], f"SourceV5 {label} mode or size differs from its typed inventory pin")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as error:
        raise ValidationError(f"cannot safely capture SourceV5 {label}: {error}") from error
    try:
        before_fd = os.fstat(descriptor)
        require(stat.S_ISREG(before_fd.st_mode) and _stat_key(before_fd) == _stat_key(before_path), f"SourceV5 {label} changed while opening")
        require(before_fd.st_size <= MAX_SOURCE_MANIFEST_BYTES, f"SourceV5 {label} exceeds its finite size bound")
        raw = bytearray()
        while len(raw) < before_fd.st_size:
            block = os.read(descriptor, min(1024 * 1024, before_fd.st_size - len(raw)))
            require(block, f"SourceV5 {label} was truncated during capture")
            raw.extend(block)
        after_fd = os.fstat(descriptor)
        after_path = path.lstat()
        require(_stat_key(before_fd) == _stat_key(after_fd) == _stat_key(after_path), f"SourceV5 {label} changed during capture")
    finally:
        os.close(descriptor)
    captured = bytes(raw)
    require(len(captured) == record["size"] and sha256_bytes(captured) == record["sha256"], f"SourceV5 {label} bytes differ from the typed inventory pin")
    return captured


def _verify_source_manifest_v5(value: dict[str, Any], recipe: dict[str, Any]) -> None:
    if recipe.get("schema") == EXPECTATION_SCHEMA_V3:
        require(recipe.get("mode") == "pressure_soak_validation", "SourceV5 expectation v3 requires pressure-soak validation mode")
    elif recipe.get("schema") == EXPECTATION_SCHEMA_V4:
        require(recipe.get("mode") == "capacity_calibration", "SourceV5 expectation v4 requires capacity calibration mode")
    elif recipe.get("schema") in (EXPECTATION_SCHEMA_V5, EXPECTATION_SCHEMA_V6):
        require(recipe.get("mode") == "pressure_validation", "SourceV5 expectation v5/v6 requires pressure validation mode")
    else:
        require(False, "SourceV5 verification requires feedback expectation v3, v4, v5, or v6")
    source = value.get("source")
    controller_record = _source_v5_regular_record(source, SOURCE_V5_CONTROLLER_PATH, "campaign controller")
    # The captured controller's V5 verifier validates this regular entry and
    # passes its expected digest into campaign_inputs_module before executing
    # the source-bound qualification policy validators.
    inputs_record = _source_v5_regular_record(source, SOURCE_V5_CAMPAIGN_INPUTS_PATH, "campaign inputs module")
    _capture_source_v5_sibling(SOURCE_V5_CAMPAIGN_INPUTS_PATH, inputs_record, "campaign inputs module")
    harness = value.get("qualification_harness")
    require(type(harness) is dict and "campaign_controller" in harness, "SourceV5 qualification harness omits its campaign controller pin")
    controller_pin = exact(harness["campaign_controller"], {"path", "sha256"}, "SourceV5 campaign controller pin")
    require(controller_pin["path"] == SOURCE_V5_CONTROLLER_PATH, "SourceV5 campaign controller path is unsupported")
    require(controller_pin["sha256"] == controller_record["sha256"], "SourceV5 campaign controller pin differs from its typed inventory entry")

    # Validate the caller-executed validator itself before evaluating the
    # independently captured controller.  The controller's full verifier then
    # checks all versioned SourceV5 records, policy artifacts and pins.
    feedback_record = _source_v5_regular_record(source, "scripts/application-feedback-readback.py", "feedback validator")
    feedback_pin = exact(harness.get("feedback_validator"), {"path", "sha256"}, "SourceV5 feedback validator pin")
    require(feedback_pin["path"] == "scripts/application-feedback-readback.py" and feedback_pin["sha256"] == feedback_record["sha256"], "SourceV5 feedback validator pin differs from its typed inventory entry")
    _capture_source_v5_sibling("scripts/application-feedback-readback.py", feedback_record, "feedback validator")

    raw = _capture_source_v5_sibling(SOURCE_V5_CONTROLLER_PATH, controller_record, "campaign controller")
    controller_sha = sha256_bytes(raw)
    module_name = f"application_campaign_controller_{controller_sha}"
    import types

    controller = types.ModuleType(module_name)
    controller.__file__ = str(Path(__file__).resolve().with_name("application-campaign.py"))
    controller.__package__ = ""
    try:
        exec(compile(raw, controller.__file__, "exec", dont_inherit=True), controller.__dict__)
    except (SyntaxError, ValueError, TypeError) as error:
        raise ValidationError(f"pinned SourceV5 campaign controller cannot be compiled: {error}") from error
    require(
        getattr(controller, "SOURCE_SCHEMA_V5", None) == SOURCE_MANIFEST_SCHEMA_V5
        and callable(getattr(controller, "verify_source_manifest", None)),
        "pinned SourceV5 campaign controller has no supported full verifier",
    )
    try:
        controller.verify_source_manifest(value, verify_artifacts=False)
    except getattr(controller, "CampaignError", Exception) as error:
        raise ValidationError(f"SourceV5 full campaign verifier rejected the manifest: {error}") from error


def _verify_source_manifest(recipe: dict[str, Any]) -> dict[str, Any]:
    pin = recipe["host_binding"]
    value, raw_sha = read_canonical(
        Path(pin["path"]), "source manifest", MAX_SOURCE_MANIFEST_BYTES, pin["raw_sha256"],
    )
    if value.get("schema") == SOURCE_MANIFEST_SCHEMA_V5:
        _verify_source_manifest_v5(value, recipe)
        source = value["source"]
        build = value["build"]
        artifacts = value["artifacts"]
        require(text(build["host_id"], "SourceV5 manifest host ID") == recipe["identity"]["host_id"], "SourceV5 manifest host differs from feedback expectation")
        require(digest(source["source_tree_sha256"], "SourceV5 source tree SHA-256") == recipe["identity"]["source_sha256"], "SourceV5 source tree hash differs from feedback identity")
        require(recipe["identity"]["allocator"] in artifacts, "SourceV5 manifest omits the expected application allocator artifact")
        app_artifact = exact(artifacts[recipe["identity"]["allocator"]], {"path", "sha256"}, "SourceV5 application emitter artifact")
        app_binary_sha = digest(app_artifact["sha256"], "SourceV5 application emitter binary SHA-256")
        if recipe["schema"] == EXPECTATION_SCHEMA_V3:
            probe_binary_sha = recipe["construction_probe"]["binary_sha256"]
            require(app_binary_sha == probe_binary_sha, "SourceV5 application emitter binary differs from the construction probe")
            require(app_binary_sha != recipe["identity"]["binary_sha256"], "SourceV5 application emitter and timed soak binaries must be distinct")
            soak_artifacts = value["soak_artifacts"]
            require(type(soak_artifacts) is dict and "allocatbelt" in soak_artifacts, "SourceV5 manifest omits the allocatbelt timed soak artifact")
            soak_artifact = exact(soak_artifacts["allocatbelt"], {"path", "sha256"}, "SourceV5 timed soak artifact")
            soak_binary_sha = digest(soak_artifact["sha256"], "SourceV5 timed soak binary SHA-256")
            require(soak_binary_sha == recipe["identity"]["binary_sha256"], "SourceV5 timed soak binary differs from the feedback trace identity")
            external = recipe["external_soak_identity"]
            require(external["build_sha256"] == digest_object(build), "external soak build digest differs from SourceV5")
            require(external["binary_sha256"] == soak_binary_sha, "external soak identity differs from SourceV5 timed soak artifact")
        else:
            require(app_binary_sha == recipe["identity"]["binary_sha256"], "SourceV5 application binary hash differs from feedback identity")
        return {"raw_sha256": raw_sha, "value": value}

    if recipe["schema"] == EXPECTATION_SCHEMA_V3:
        require(False, "feedback expectation v3 requires a SourceV5 manifest")
    require(recipe["schema"] in (EXPECTATION_SCHEMA_V1, EXPECTATION_SCHEMA_V2), "feedback expectation v4 requires a SourceV5 manifest")
    exact(value, {
        "schema", "source", "build", "artifacts", "soak_artifacts", "analysis_artifact",
        "fixed_runtime_policy", "runtime_readback_validator", "resource_domain_calibration",
        "manifest_sha256",
    }, "source manifest")
    require(value["schema"] == SOURCE_MANIFEST_SCHEMA, "unsupported source manifest schema")
    body = {key: item for key, item in value.items() if key != "manifest_sha256"}
    require(digest(value["manifest_sha256"], "source manifest self digest") == digest_object(body), "source manifest self digest is invalid")
    source = exact(value["source"], {"git_commit", "source_tree_sha256", "cargo_lock_sha256", "files"}, "source manifest source")
    build = exact(value["build"], {
        "host_id", "rustc_release", "rustc_verbose", "cargo_version", "target_triple", "target_cpu",
        "profile", "features_sha256", "build_inputs_sha256",
    }, "source manifest build")
    require(text(build["host_id"], "source manifest host ID") == recipe["identity"]["host_id"], "source manifest host differs from feedback expectation")
    require(digest(source["source_tree_sha256"], "source tree SHA-256") == recipe["identity"]["source_sha256"], "source tree hash differs from feedback identity")
    artifacts = value["artifacts"]
    require(type(artifacts) is dict and set(artifacts) == {"allocatbelt", "mimalloc-secure", "mimalloc-standard", "system"}, "source manifest artifact set is incomplete")
    for allocator, record in artifacts.items():
        exact(record, {"path", "sha256"}, f"source manifest binary artifact {allocator}")
        digest(record["sha256"], f"source manifest {allocator} binary hash")
    require(recipe["identity"]["allocator"] in artifacts, "source manifest omits the expected allocator artifact")
    artifact = artifacts[recipe["identity"]["allocator"]]
    require(digest(artifact["sha256"], "source manifest binary SHA-256") == recipe["identity"]["binary_sha256"], "source manifest binary hash differs from feedback identity")
    return {"raw_sha256": raw_sha, "value": value}


def _verify_pressure_proof(
    recipe: dict[str, Any], production: tuple[int, int], drain: tuple[int, int], *,
    offline_replayed_proof: dict[str, Any] | None = None,
    allow_pressure_v2: bool = False,
    artifact_view: Any = None,
) -> tuple[bool, str]:
    pin = recipe["external_pressure_proof"]
    proof, raw_sha = read_canonical(
        Path(pin["path"]), "external pressure readback",
        MAX_PRESSURE_PROOF_BYTES, pin["raw_sha256"],
        artifact_view=artifact_view,
    )
    pressure_fields = {
        "schema", "status", "recipe_sha256", "recipe_raw_sha256", "validator_sha256", "condition_sha256", "identity",
        "run_sha256", "events_sha256",
        "launch_record_sha256", "process_binding_sha256", "readiness_marker_sha256", "sample_count",
        "application_overlap_nanoseconds", "application_process", "application_window", "continuous_ready_window",
        "readiness_windows_passed", "cleanup_rechecked", "physical_nic_claimed", "readback_sha256",
    }
    if allow_pressure_v2 and type(proof) is dict and proof.get("schema") == PRESSURE_READBACK_SCHEMA_V2:
        pressure_fields.add("calibration_scope_v2")
    exact(proof, pressure_fields, "external pressure validation receipt")
    allowed_schema = (PRESSURE_READBACK_SCHEMA, PRESSURE_READBACK_SCHEMA_V2) if allow_pressure_v2 else (PRESSURE_READBACK_SCHEMA,)
    require(proof["schema"] in allowed_schema and proof["status"] == "valid", "external pressure readback is not valid")
    body = {key: item for key, item in proof.items() if key != "readback_sha256"}
    require(digest(proof["readback_sha256"], "pressure readback self digest") == digest_object(body), "external pressure readback self digest is invalid")
    for key in ("recipe_sha256", "recipe_raw_sha256", "validator_sha256", "condition_sha256", "run_sha256", "events_sha256", "launch_record_sha256", "process_binding_sha256", "readiness_marker_sha256"):
        digest(proof[key], f"pressure receipt {key}")
    require(proof["recipe_raw_sha256"] == pin["recipe_raw_sha256"] and proof["validator_sha256"] == pin["validator_sha256"], "external pressure proof does not match caller-pinned recipe or validator bytes")
    _, actual_validator_sha = read_stable(Path(__file__).resolve().with_name("application-pressure-readback.py"), "pressure readback validator", 4 * 1024 * 1024)
    require(actual_validator_sha == pin["validator_sha256"], "installed pressure validator bytes differ from caller pin")
    pressure_identity = exact(proof["identity"], {
        "host_id", "run_id", "pair_id", "condition_id", "member", "nonce", "allocator", "executor", "phase",
    }, "pressure recipe identity")
    identity = recipe["identity"]
    for source_key, feedback_key in (("host_id", "host_id"), ("run_id", "run_id"), ("allocator", "allocator"), ("executor", "executor"), ("nonce", "report_nonce")):
        require(pressure_identity[source_key] == identity[feedback_key], f"pressure proof identity differs from feedback {feedback_key}")
    pressure_process = exact(proof["application_process"], {"pid", "start_ticks", "nonce", "executable_sha256"}, "pressure-bound application process")
    require(uint(pressure_process["pid"], "pressure-bound application PID", positive=True, maximum=(1 << 31) - 1) == identity["process_id"], "pressure proof is bound to a different application PID")
    uint(pressure_process["start_ticks"], "pressure-bound application start ticks", positive=True)
    require(pressure_process["nonce"] == identity["report_nonce"] and digest(pressure_process["executable_sha256"], "pressure-bound application binary SHA-256") == identity["binary_sha256"], "pressure proof application nonce or binary differs from feedback identity")
    if offline_replayed_proof is not None:
        require(proof == offline_replayed_proof,
                "external pressure proof bytes differ from the independent offline raw-artifact replay")
    require(proof["readiness_windows_passed"] is True and proof["cleanup_rechecked"] is True and proof["physical_nic_claimed"] is False, "external pressure readiness or cleanup proof is incomplete")
    uint(proof["sample_count"], "pressure proof sample count", positive=True, maximum=120_000)
    overlap = uint(proof["application_overlap_nanoseconds"], "pressure proof application overlap", positive=True)
    app_window = exact(proof["application_window"], {"observed_start_monotonic_ns", "observed_exit_monotonic_ns"}, "pressure application observation window")
    app_start = uint(app_window["observed_start_monotonic_ns"], "observed application start", positive=True)
    app_exit = uint(app_window["observed_exit_monotonic_ns"], "observed application exit", positive=True)
    require(app_exit > app_start and app_exit - app_start == overlap, "pressure application observation window disagrees with measured overlap")
    ready = exact(proof["continuous_ready_window"], {"start_monotonic_ns", "end_monotonic_ns"}, "continuous ready pressure window")
    ready_start = uint(ready["start_monotonic_ns"], "continuous ready start", positive=True)
    ready_end = uint(ready["end_monotonic_ns"], "continuous ready end", positive=True)
    require(app_exit > app_start, "pressure application observation window is empty")
    require(ready_end > ready_start, "continuous ready pressure window is empty")
    require(ready_start <= production[0] and ready_end >= drain[1], "continuous ready pressure window does not cover production through drain")
    required = recipe["minimum_pressure_overlap_seconds"] * NSEC
    require(overlap >= required, "measured application pressure overlap is below the preregistered minimum")
    return True, raw_sha


def _runtime_key_allowed(key: str) -> bool:
    if re.fullmatch(r"after_release\.global\.used\.(cpu|memory|disk|network|tasks)", key):
        return True
    for stage in ("setup", "after_drain", "after_shutdown"):
        prefix = stage + "."
        if key.startswith(prefix):
            suffix = key[len(prefix):]
            if re.fullmatch(r"(?:global|tenant)\.(?:ceiling|limit|used)\.(?:cpu|memory|disk|network|tasks|control)", suffix):
                return True
            if re.fullmatch(r"(?:global|tenant)\.(?:live_tenants|application_work_tasks)", suffix):
                return True
            if suffix in {
                "scope.managed_memory_limit", "scope.disk_operation_limit", "scope.network_operation_limit",
                "scope.managed_memory_used", "scope.disk_operations_used", "scope.network_operations_used",
                "collector_task_lease_count",
            }:
                return True
            io_match = re.fullmatch(r"io\.(disk|upload|download)_(bytes_per_second|burst_bytes|ceiling_bytes_per_second|ceiling_burst_bytes|max_reservations|available_bytes|reserved_bytes|reservations)", suffix)
            if io_match:
                return True
            feedback_fields = {
                "sample_count", "worker_failure", "last_diagnostic", "last_sample_offset_ns",
                "last_sample_age_ns", "last_plan_offset_ns", "last_plan_age_ns", "stop_requested",
                "shutdown_complete", "reconciliation_pending", "reconciliation_in_flight",
                "decision_evidence",
            }
            if suffix.startswith("feedback."):
                rest = suffix.removeprefix("feedback.")
                if rest in feedback_fields:
                    return True
                control_match = re.fullmatch(r"(cpu|disk_rate|download_rate)\.(current_limit|utilization_basis_points|telemetry|policy_faulted|no_change|pending_generation|last_diagnostic|decision_evidence)", rest)
                if control_match:
                    return True
                meter_match = re.fullmatch(r"meter\.(disk|upload|download)\.(committed_bytes|completions|attached_sources|generation|diagnostics_clear|diagnostics\.(?:counter_overflow|invalid_io|source_count_overflow|generation_overflow))", rest)
                if meter_match:
                    return True
            return False
    if key.startswith("configuration.domain_ceiling."):
        return key.rsplit(".", 1)[-1] in DOMAIN
    if key.startswith("identity."):
        return key in {
            "identity.report_nonce", "identity.run_id", "identity.allocator", "identity.executor",
            "identity.source_sha256", "identity.binary_sha256", "identity.comparison_family",
            "identity.resource_ceiling_sha256", "identity.policy_sha256", "identity.profile",
            "identity.workload", "identity.hashes_are_echoed_bindings_not_self_proof",
        }
    if key in {
        "feedback.schema", "feedback.policy.version", "feedback.sample_interval_ms",
        "feedback.max_dense_sample_gap_ms", "feedback.telemetry_freshness_ms",
        "feedback.required_breach_samples", "feedback.actuation_cooldown_ms",
        "feedback.minimum_dense_observations", "feedback.cpu_reduction_rule",
        "feedback.cpu_recovery_increment", "feedback.cpu_capacity_equivalents",
        "feedback.disk_source", "feedback.network_source", "feedback.network_direction",
        "feedback.upload_controlled", "feedback.pressure_qualification_requested",
        "feedback.pressure_claim", "feedback.calibration.schema", "feedback.calibration.id",
        "feedback.calibration.artifact_sha256", "feedback.calibration.hash_scope",
        "feedback.calibration.host_id", "feedback.calibration.profile", "feedback.calibration.workload",
        "feedback.calibration.source_sha256", "feedback.calibration.source_sha256_meaning",
        "feedback.policy.canonicalization",
    }:
        return True
    if re.fullmatch(r"feedback\.policy\.(cpu|disk|download)\.(floor|initial|ceiling|low_utilization_basis_points|high_utilization_basis_points)", key):
        return True
    if re.fullmatch(r"feedback\.calibration\.(disk|download)\.(status|bytes_per_second|units|provenance)", key):
        return True
    static = {
        "configuration.mode", "configuration.rate_per_second", "configuration.arrivals",
        "configuration.async_workers", "configuration.logical_window", "configuration.trace_duration_ns",
        "configuration.pulse_rate_per_second", "configuration.task_ceiling", "configuration.domain_ceiling.cpu",
        "configuration.domain_ceiling.memory", "configuration.domain_ceiling.disk", "configuration.domain_ceiling.network",
        "configuration.domain_ceiling.tasks", "configuration.domain_ceiling.control", "configuration.managed_memory_limit_bytes",
        "configuration.disk_operation_limit", "configuration.network_operation_limit",
        "configuration.fixed_global_control_baseline", "configuration.setup_global_control",
        "configuration.blocking_disk_adapter_constructed", "accounting.cpu", "accounting.tasks",
        "accounting.managed_payload", "accounting.disk_operations", "accounting.disk_bytes",
        "accounting.network_operations", "accounting.network_bytes", "accounting.opaque_runtime_allocations",
        "accounting.receipt_writer_storage", "kernel.cpu_rounds", "kernel.memory_initial_bytes",
        "kernel.memory_grown_bytes", "kernel.memory_seed", "kernel.disk_bytes", "kernel.disk_offset",
        "kernel.disk_seed", "kernel.http_body_bytes", "kernel.mixed_interleave",
        "after_release.global.live_tenants", "after_release.global.used.control",
        "after_release.expected_global_control_baseline", "after_release.control_matches_fixed_baseline",
    }
    return key in static


def _verify_runtime_binding(
    recipe: dict[str, Any], final_policy: dict[str, dict[str, Any]], accepted_sample_count: int,
    *, artifact_view: Any = None,
) -> tuple[bool, str, bool]:
    pin = recipe["final_runtime_binding"]
    raw, raw_sha = read_stable(
        Path(pin["path"]), "final runtime binding",
        MAX_RUNTIME_BINDING_BYTES, artifact_view=artifact_view,
    )
    require(raw_sha == pin["raw_sha256"], "final runtime binding raw SHA-256 differs from caller pin")
    require(raw.endswith(b"\n") and b"\r" not in raw and b"\x00" not in raw, "runtime binding has invalid LF framing")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise ValidationError("runtime binding is not UTF-8") from error
    require(lines, "runtime binding omits its schema header")
    schema_header = lines[0]
    require(schema_header in {
        f"schema\t{RUNTIME_BINDING_SCHEMA_V1}", f"schema\t{RUNTIME_BINDING_SCHEMA_V2}",
    }, "unsupported runtime binding schema")
    schema_v2 = schema_header == f"schema\t{RUNTIME_BINDING_SCHEMA_V2}"
    rows: dict[str, str] = {}
    for line in lines[1:]:
        fields = line.split("\t")
        require(len(fields) == 2 and fields[0] and fields[1] and not any(ord(c) < 32 or ord(c) == 127 for c in fields[0] + fields[1]), "runtime binding row is malformed")
        key, value = fields
        require(key not in rows and _runtime_key_allowed(key), f"runtime binding contains duplicate or unknown field: {key}")
        rows[key] = value
    identity = recipe["identity"]
    expected_identity = {
        "identity.report_nonce": identity["report_nonce"], "identity.run_id": identity["run_id"],
        "identity.allocator": identity["allocator"], "identity.executor": identity["executor"],
        "identity.source_sha256": identity["source_sha256"], "identity.binary_sha256": identity["binary_sha256"],
        "identity.comparison_family": "external_pressure",
        "identity.profile": identity["profile"], "identity.workload": identity["workload"],
    }
    for key, value in expected_identity.items():
        require(rows.get(key) == value, f"runtime binding identity differs at {key}")
    baseline = str(recipe["policy"]["collector"]["expected_global_control_baseline"])
    require(rows.get("configuration.fixed_global_control_baseline") == baseline, "runtime configuration Control baseline differs from expectation")
    for resource in DOMAIN:
        require(rows.get(f"configuration.domain_ceiling.{resource}") == str(recipe["policy"]["global_ceilings"][resource]), f"runtime configuration {resource} ceiling differs from expectation")
        require(rows.get(f"after_shutdown.global.ceiling.{resource}") == str(recipe["policy"]["global_ceilings"][resource]), f"runtime after-shutdown global {resource} ceiling differs from expectation")
        require(rows.get(f"after_shutdown.tenant.ceiling.{resource}") == str(recipe["policy"]["tenant_ceilings"][resource]), f"runtime after-shutdown tenant {resource} ceiling differs from expectation")
        for owner, ceiling in (("global", recipe["policy"]["global_ceilings"][resource]), ("tenant", recipe["policy"]["tenant_ceilings"][resource])):
            positive_limit = recipe["schema"] == EXPECTATION_SCHEMA_V1 or ceiling > 0
            limit = uint(
                _decimal(rows.get(f"after_shutdown.{owner}.limit.{resource}", ""), f"runtime {owner} {resource} limit"),
                f"runtime {owner} {resource} limit", positive=positive_limit,
            )
            require(limit <= ceiling, f"runtime after-shutdown {owner} {resource} limit exceeds its hard ceiling")
    for sample_key, policy_key in (("configuration.managed_memory_limit_bytes", "managed_memory"),
                                   ("configuration.disk_operation_limit", "disk_operations"),
                                   ("configuration.network_operation_limit", "network_operations")):
        require(rows.get(sample_key) == str(recipe["policy"]["scope_limits"][policy_key]), f"runtime configuration scope limit differs at {sample_key}")
    for row_key, policy_key in (("after_shutdown.scope.managed_memory_limit", "managed_memory"),
                                ("after_shutdown.scope.disk_operation_limit", "disk_operations"),
                                ("after_shutdown.scope.network_operation_limit", "network_operations")):
        require(rows.get(row_key) == str(recipe["policy"]["scope_limits"][policy_key]), f"runtime after-shutdown scope limit differs at {row_key}")
    for resource in RESOURCES:
        control = recipe["policy"]["controls"][resource]
        name = {"cpu": "cpu", "disk": "disk", "download": "download"}[resource]
        for field, policy_field in (("floor", "floor"), ("initial", "initial"), ("ceiling", "ceiling"),
                                    ("low_utilization_basis_points", "low_bps"), ("high_utilization_basis_points", "high_bps")):
            key = f"feedback.policy.{name}.{field}"
            require(rows.get(key) == str(control[policy_field]), f"runtime policy differs from expectation at {key}")
        feedback_name = {"cpu": "cpu", "disk": "disk_rate", "download": "download_rate"}[resource]
        prefix = f"after_shutdown.feedback.{feedback_name}"
        require(rows.get(prefix + ".current_limit") == str(final_policy[resource]["current_limit"]), f"runtime shutdown {resource} limit differs from event reconstruction")
        expected_utilization = "missing" if final_policy[resource]["utilization_basis_points"] is None else str(final_policy[resource]["utilization_basis_points"])
        require(rows.get(prefix + ".utilization_basis_points") == expected_utilization, f"runtime shutdown {resource} telemetry differs from event reconstruction")
        require(rows.get(prefix + ".telemetry") == final_policy[resource]["telemetry"].lower(), f"runtime shutdown {resource} telemetry state differs from event reconstruction")
        require(rows.get(prefix + ".policy_faulted") == "false" and rows.get(prefix + ".pending_generation") == "none", f"runtime shutdown {resource} control remains faulted or pending")
    require(rows.get("feedback.policy.version") == "runtime-feedback-policy-v1", "runtime binding feedback policy version differs")
    require(rows.get("feedback.sample_interval_ms") == "100" and rows.get("feedback.max_dense_sample_gap_ms") == "200" and rows.get("feedback.telemetry_freshness_ms") == "500" and rows.get("feedback.required_breach_samples") == "3" and rows.get("feedback.actuation_cooldown_ms") == "1000", "runtime feedback timing policy differs from the fixed contract")
    require(rows.get("feedback.minimum_dense_observations") == "1", "runtime feedback density threshold differs from expectation")
    require(rows.get("feedback.pressure_qualification_requested") == "true", "runtime binding did not request pressure qualification")
    require(rows.get("feedback.calibration.artifact_sha256") == recipe["app_capacity_artifact_sha256"], "runtime app-byte calibration hash differs from expectation")
    require(rows.get("feedback.calibration.host_id") == recipe["identity"]["host_id"] and rows.get("feedback.calibration.profile") == recipe["identity"]["profile"] and rows.get("feedback.calibration.workload") == recipe["identity"]["workload"] and rows.get("feedback.calibration.source_sha256") == recipe["identity"]["source_sha256"], "runtime capacity calibration identity differs from expectation")
    for direction in ("disk", "download"):
        expected_status = "calibrated" if recipe["policy"]["capacity_sources"][direction] else "missing"
        require(rows.get(f"feedback.calibration.{direction}.status") == expected_status, f"runtime {direction} byte source availability differs from expectation")
        if expected_status == "missing":
            require(rows.get(f"feedback.calibration.{direction}.bytes_per_second") == "missing" and rows.get(f"feedback.calibration.{direction}.units") == "missing", f"runtime missing {direction} capacity was not preserved")
        else:
            uint(_decimal(rows.get(f"feedback.calibration.{direction}.bytes_per_second", ""), f"runtime {direction} capacity"), f"runtime {direction} capacity", positive=True)
    for direction in RATE_DIRECTIONS:
        bucket = recipe["policy"]["rate_buckets"][direction]
        io_prefix = f"after_shutdown.io.{direction}_"
        require(rows.get(io_prefix + "ceiling_bytes_per_second") == str(bucket["ceiling_bytes_per_second"]), f"runtime {direction} byte-rate ceiling differs from expectation")
        require(rows.get(io_prefix + "ceiling_burst_bytes") == str(bucket["ceiling_burst_bytes"]), f"runtime {direction} burst ceiling differs from expectation")
        require(rows.get(io_prefix + "max_reservations") == str(bucket["max_reservations"]), f"runtime {direction} reservation cap differs from expectation")
        current_rate = uint(_decimal(rows.get(io_prefix + "bytes_per_second", ""), f"runtime {direction} current rate"), f"runtime {direction} current rate")
        burst = uint(_decimal(rows.get(io_prefix + "burst_bytes", ""), f"runtime {direction} current burst"), f"runtime {direction} current burst")
        available = uint(_decimal(rows.get(io_prefix + "available_bytes", ""), f"runtime {direction} available credits"), f"runtime {direction} available credits")
        reserved = uint(_decimal(rows.get(io_prefix + "reserved_bytes", ""), f"runtime {direction} reserved credits"), f"runtime {direction} reserved credits")
        require(current_rate <= bucket["ceiling_bytes_per_second"] and burst <= bucket["ceiling_burst_bytes"] and available + reserved <= burst, f"runtime {direction} bucket exceeds its rate or credit ceiling")
    required = [
        "after_shutdown.global.used.cpu", "after_shutdown.global.used.memory", "after_shutdown.global.used.disk",
        "after_shutdown.global.used.network", "after_shutdown.global.used.tasks",
        "after_shutdown.tenant.used.cpu", "after_shutdown.tenant.used.memory", "after_shutdown.tenant.used.disk",
        "after_shutdown.tenant.used.network", "after_shutdown.tenant.used.tasks",
        "after_shutdown.scope.managed_memory_used", "after_shutdown.scope.disk_operations_used",
        "after_shutdown.scope.network_operations_used", "after_shutdown.io.disk_reservations",
        "after_shutdown.io.upload_reservations", "after_shutdown.io.download_reservations",
        "after_shutdown.feedback.shutdown_complete",
        "after_shutdown.feedback.worker_failure", "after_shutdown.feedback.sample_count",
        "after_shutdown.feedback.stop_requested", "after_shutdown.feedback.reconciliation_pending",
        "after_shutdown.feedback.reconciliation_in_flight",
        "after_release.global.live_tenants", "after_release.global.used.control",
        "after_release.expected_global_control_baseline", "after_release.control_matches_fixed_baseline",
    ]
    require(all(key in rows for key in required), "runtime binding omits final shutdown/release evidence")
    for key in required[:16]:
        require(rows[key] == "0", f"runtime binding reports nonzero application or owner usage at {key}")
    require(rows["after_shutdown.feedback.shutdown_complete"] == "true" and rows["after_shutdown.feedback.worker_failure"] == "none", "feedback worker did not cleanly join")
    require(rows["after_shutdown.feedback.stop_requested"] == "true" and rows["after_shutdown.feedback.sample_count"] == str(accepted_sample_count), "feedback runtime receipt does not bind complete stop and sample count")
    require(rows["after_shutdown.feedback.reconciliation_pending"] == "none" and rows["after_shutdown.feedback.reconciliation_in_flight"] == "none", "feedback runtime receipt has unfinished reconciliation")
    require(rows["after_release.global.live_tenants"] == "0" and rows["after_release.global.used.control"] == baseline and rows["after_release.expected_global_control_baseline"] == baseline and rows["after_release.control_matches_fixed_baseline"] == "true", "runtime binding did not return global Control to its fixed baseline")
    after_release_global = {f"after_release.global.used.{name}" for name in ("cpu", "memory", "disk", "network", "tasks")}
    present_release = after_release_global.intersection(rows)
    if schema_v2:
        require(present_release == after_release_global, "runtime binding v2 omits a final after-release global resource field")
    else:
        require(not present_release, "runtime binding v1 contains v2-only after-release global resource fields")
    release_complete = schema_v2
    if release_complete:
        require(all(rows[key] == "0" for key in after_release_global), "runtime binding reports live global application usage after owner release")
    return True, raw_sha, release_complete


def _verify_soak_final_binding_v3(
    recipe: dict[str, Any], source_manifest_binding: dict[str, Any], manifest: dict[str, Any],
    *, artifact_view: Any = None,
) -> dict[str, Any]:
    """Bind the feedback trace to its independently audited SourceV5 soak run."""
    source_manifest = source_manifest_binding["value"]
    source_manifest_raw_sha = digest(source_manifest_binding["raw_sha256"], "SourceV5 manifest raw SHA-256")
    binding = exact(recipe["final_runtime_binding"], {"soak_receipt", "soak_readback"}, "v3 final runtime binding")
    receipt_pin = exact(binding["soak_receipt"], {"path", "raw_sha256"}, "Rust soak receipt pin")
    readback_pin = exact(binding["soak_readback"], {"path", "raw_sha256"}, "audited soak readback pin")
    receipt, receipt_sha = read_canonical(
        Path(receipt_pin["path"]), "Rust runtime-soak v2 receipt", MAX_SOAK_BINDING_BYTES,
        digest(receipt_pin["raw_sha256"], "Rust soak receipt raw SHA-256"),
        artifact_view=artifact_view,
    )
    readback, readback_sha = read_canonical(
        Path(readback_pin["path"]), "application-soak-readback v2 composite", MAX_SOAK_BINDING_BYTES,
        digest(readback_pin["raw_sha256"], "soak readback raw SHA-256"),
        artifact_view=artifact_view,
    )
    exact(receipt, SOAK_RECEIPT_FIELDS_V2, "Rust runtime-soak v2 receipt")
    exact(readback, SOAK_READBACK_FIELDS_V2, "audited application soak readback v2")
    require(receipt["schema"] == RUNTIME_SOAK_SCHEMA_V2, "unsupported Rust runtime-soak receipt schema")
    require(readback["schema"] == SOAK_READBACK_SCHEMA_V2, "unsupported application soak readback schema")
    require(readback["validated"] is True and readback["passed"] is True, "application soak readback did not pass its independent audit")
    require(readback["mode"] in ("qualified", "functional"), "application soak readback mode is unsupported")
    require(type(readback["qualification_eligible"]) is bool, "application soak qualification eligibility is not boolean")
    composite_receipt_sha = digest(readback["receipt_sha256"], "soak composite receipt SHA-256")
    require(composite_receipt_sha == receipt_sha, "soak composite receipt digest differs from the captured Rust receipt bytes")
    if readback["mode"] == "functional":
        require(readback["qualification_eligible"] is False, "short functional soak cannot be qualification-eligible")

    external = recipe["external_soak_identity"]
    receipt_fields = (
        "campaign_id", "host_id", "run_id", "nonce", "allocator", "executor", "workload", "profile",
        "comparison_family", "source_sha256", "binary_sha256", "resource_ceiling_sha256",
    )
    for field in receipt_fields:
        require(receipt[field] == external[field], f"Rust soak receipt identity differs at {field}")
    require(receipt["mode"] == "soak", "Rust soak receipt mode is not soak")
    require(receipt["qualification_eligible"] is False, "Rust soak receipt must not self-assert qualification eligibility")
    require(receipt["feedback_started"] is True and receipt["feedback_worker_joined"] is True, "Rust soak receipt omits feedback start/join evidence")
    require(receipt["feedback_trace_worker_joined"] is True and receipt["feedback_worker_failure"] is None, "Rust soak feedback trace worker did not join cleanly")
    require(type(receipt["qualified_horizon"]) is bool, "Rust soak qualified-horizon field is not boolean")
    soak_duration = uint(receipt["duration_seconds"], "Rust soak duration", positive=True, maximum=10_800)
    if readback["mode"] == "qualified":
        require(soak_duration == 10_800 and receipt["qualified_horizon"] is True, "qualified soak mode differs from the exact Rust horizon")
    else:
        require(soak_duration < 10_800 and receipt["qualified_horizon"] is False, "functional soak mode must remain short and ineligible")

    source = exact(source_manifest["source"], {"git_commit", "source_tree_sha256", "cargo_lock_sha256", "files"}, "SourceV5 source identity")
    build_sha = digest_object(source_manifest["build"])
    require(external["source_sha256"] == source["source_tree_sha256"], "external soak source differs from SourceV5")
    require(external["build_sha256"] == build_sha, "external soak build differs from SourceV5")
    require(readback["source_manifest_sha256"] == source_manifest_raw_sha, "soak composite source manifest digest differs from SourceV5")
    require(readback["source_tree_sha256"] == external["source_sha256"], "soak composite source tree differs from external soak identity")
    require(readback["build_sha256"] == external["build_sha256"], "soak composite build digest differs from external soak identity")
    require(readback["candidate_binary_sha256"] == external["binary_sha256"], "soak composite candidate binary differs from external soak identity")
    require(readback["resource_ceiling_sha256"] == external["resource_ceiling_sha256"], "soak composite resource ceiling differs from external soak identity")

    source_soak_artifacts = source_manifest["soak_artifacts"]
    require(type(source_soak_artifacts) is dict and "allocatbelt" in source_soak_artifacts, "SourceV5 manifest omits the allocatbelt soak artifact")
    soak_artifact = exact(source_soak_artifacts["allocatbelt"], {"path", "sha256"}, "SourceV5 allocatbelt soak artifact")
    soak_binary_sha = digest(soak_artifact["sha256"], "SourceV5 allocatbelt soak binary SHA-256")
    require(soak_binary_sha == external["binary_sha256"] == recipe["identity"]["binary_sha256"], "SourceV5 soak artifact differs from the timed feedback executable")
    app_artifact = exact(source_manifest["artifacts"]["allocatbelt"], {"path", "sha256"}, "SourceV5 application emitter artifact")
    app_binary_sha = digest(app_artifact["sha256"], "SourceV5 application emitter binary SHA-256")
    require(app_binary_sha == recipe["construction_probe"]["binary_sha256"] and app_binary_sha != soak_binary_sha, "SourceV5 application emitter and timed soak artifact roles are not distinct")

    readback_identity = exact(readback["identity"], set(SOAK_PARENT_IDENTITY_FIELDS), "soak composite parent identity")
    require(readback_identity == external, "soak composite identity differs from caller-frozen external soak identity")
    harness = source_manifest["qualification_harness"]
    soak_validator = exact(harness["soak_validator"], {"path", "sha256"}, "SourceV5 soak validator pin")
    pressure_validator = exact(harness["pressure_validator"], {"path", "sha256"}, "SourceV5 pressure validator pin")
    require(readback["validator_sha256"] == soak_validator["sha256"], "soak composite validator differs from SourceV5 harness pin")
    require(recipe["external_pressure_proof"]["validator_sha256"] == pressure_validator["sha256"], "pressure readback validator differs from SourceV5 harness pin")

    calibration = exact(source_manifest["resource_domain_calibration"], {
        "binary", "output", "record", "source", "build", "build_sha256",
    }, "SourceV5 resource-domain calibration")
    baseline = uint(calibration["record"]["fixed_global_control_baseline"], "SourceV5 fixed global Control baseline", positive=True)
    require(baseline == recipe["policy"]["collector"]["expected_global_control_baseline"], "SourceV5 calibration baseline differs from the feedback construction probe")
    require(uint(readback["fixed_global_control_baseline"], "soak composite fixed Control baseline", positive=True) == baseline, "soak composite fixed Control baseline differs from SourceV5 calibration")
    require(uint(receipt["fixed_global_control_baseline"], "Rust soak fixed Control baseline", positive=True) == baseline, "Rust soak receipt fixed Control baseline differs from SourceV5 calibration")
    require(uint(receipt["final_global_live_tenants"], "Rust soak final global live tenants") == 0, "Rust soak receipt retains live global tenants")
    require(uint(receipt["final_global_control_used"], "Rust soak final global Control use") == baseline, "Rust soak receipt global Control does not return to the calibrated baseline")
    for field in (
        "final_global_cpu_used", "final_global_memory_used", "final_global_disk_used", "final_global_network_used",
        "final_global_tasks_used", "final_tenant_cpu_used", "final_tenant_memory_used", "final_tenant_disk_used",
        "final_tenant_network_used", "final_tenant_tasks_used", "final_tenant_control_used",
        "final_scope_memory_used", "final_scope_disk_used", "final_scope_network_used",
    ):
        require(uint(receipt[field], f"Rust soak final field {field}") == 0, f"Rust soak receipt retains final application usage at {field}")

    scalar_fields = {
        "started": "started_monotonic_ns",
        "trace_ended": "trace_ended_monotonic_ns",
        "drain_ended": "drain_ended_monotonic_ns",
        "shutdown_ended": "shutdown_ended_monotonic_ns",
        "postprocess_ended": "postprocess_ended_monotonic_ns",
    }
    receipt_endpoints: dict[str, list[int]] = {}
    clock_width = manifest["clock_anchor"][1] - manifest["clock_anchor"][0]
    for phase in SOAK_RECEIPT_CLOCK_PHASES:
        lower = uint(receipt[f"{phase}_monotonic_lower_ns"], f"Rust soak {phase} lower endpoint", positive=True, maximum=U128_MAX)
        upper = uint(receipt[f"{phase}_monotonic_upper_ns"], f"Rust soak {phase} upper endpoint", positive=True, maximum=U128_MAX)
        scalar = uint(receipt[scalar_fields[phase]], f"Rust soak {phase} scalar endpoint", positive=True, maximum=U128_MAX)
        require(lower <= scalar <= upper, f"Rust soak {phase} scalar endpoint is outside its captured TraceClock bracket")
        require(upper - lower == clock_width, f"Rust soak {phase} bracket width differs from the feedback trace clock anchor")
        receipt_endpoints[phase] = [lower, upper]
    composite_endpoints = exact(readback["monotonic_endpoints"], set(SOAK_RECEIPT_CLOCK_PHASES), "soak composite monotonic endpoints")
    for phase, pair in receipt_endpoints.items():
        value = composite_endpoints[phase]
        require(type(value) is list and len(value) == 2, f"soak composite {phase} endpoint must be a two-value bracket")
        actual = [
            uint(value[0], f"soak composite {phase} lower endpoint", positive=True, maximum=U128_MAX),
            uint(value[1], f"soak composite {phase} upper endpoint", positive=True, maximum=U128_MAX),
        ]
        require(actual == pair, f"soak composite {phase} bracket differs from the Rust receipt")

    phases = manifest["phases"]
    for soak_phase, trace_phase in (
        ("started", "production_start"),
        ("trace_ended", "production_end"),
        ("drain_ended", "drain_end"),
        ("shutdown_ended", "shutdown_end"),
    ):
        trace = phases[trace_phase]
        require(receipt_endpoints[soak_phase] == [trace["lower"], trace["upper"]], f"Rust soak {soak_phase} clock bracket differs from feedback trace {trace_phase}")
    owner_release = phases["owner_release"]
    require(
        receipt_endpoints["shutdown_ended"][1] <= owner_release["lower"]
        and owner_release["upper"] <= receipt_endpoints["postprocess_ended"][0],
        "feedback owner-release marker does not lie between soak shutdown and postprocess endpoints",
    )
    scalars = {phase: uint(receipt[field], f"Rust soak {field}", positive=True, maximum=U128_MAX) for phase, field in scalar_fields.items()}
    require(scalars["started"] <= scalars["trace_ended"] <= scalars["drain_ended"] <= scalars["shutdown_ended"] <= scalars["postprocess_ended"], "Rust soak scalar phase endpoints are unordered")
    require(uint(receipt["ended_monotonic_ns"], "Rust soak ended endpoint", positive=True, maximum=U128_MAX) == scalars["postprocess_ended"], "Rust soak ended endpoint differs from postprocess")
    require(uint(receipt["actual_trace_duration_ns"], "Rust soak trace duration", maximum=U128_MAX) == scalars["trace_ended"] - scalars["started"], "Rust soak trace duration differs from its captured endpoints")
    require(uint(receipt["drain_duration_ns"], "Rust soak drain duration", maximum=U128_MAX) == scalars["drain_ended"] - scalars["trace_ended"], "Rust soak drain duration differs from its captured endpoints")
    require(uint(receipt["shutdown_duration_ns"], "Rust soak shutdown duration", maximum=U128_MAX) == scalars["shutdown_ended"] - scalars["drain_ended"], "Rust soak shutdown duration differs from its captured endpoints")
    require(uint(receipt["postprocess_after_shutdown_ns"], "Rust soak postprocess duration", maximum=U128_MAX) == scalars["postprocess_ended"] - scalars["shutdown_ended"], "Rust soak postprocess duration differs from its captured endpoints")
    return {
        "raw_sha256": receipt_sha,
        "readback_raw_sha256": readback_sha,
        "validated": True,
        "qualification_eligible": readback["qualification_eligible"],
        "mode": readback["mode"],
    }


def _parse_manifest(lines: list[bytes], recipe: dict[str, Any]) -> dict[str, Any]:
    require(lines and len(lines) <= 256, "feedback manifest has an invalid row count")
    try:
        rows = [line.decode("ascii") for line in lines]
    except UnicodeError as error:
        raise ValidationError("feedback manifest is not ASCII") from error
    index = 0

    def take(prefix: str, field_count: int | None = None) -> list[str]:
        nonlocal index
        require(index < len(rows), f"feedback manifest omits {prefix}")
        parts = rows[index].split("\t")
        index += 1
        require(parts[0] == prefix and (field_count is None or len(parts) == field_count), f"feedback manifest row is malformed: {prefix}")
        return parts

    require(take("schema", 2) == ["schema", TRACE_MANIFEST_SCHEMA], "unsupported feedback manifest schema")
    identity = recipe["identity"]
    process_row = take("identity", 3)
    require(process_row[1:] == ["process_id", str(identity["process_id"])], "trace manifest process ID differs from expectation")
    manifest_identity: dict[str, str] = {"process_id": process_row[2]}
    expected_identity = {
        "report_nonce": identity["report_nonce"], "run_id": identity["run_id"],
        "executor": identity["executor"], "allocator": identity["allocator"],
        "workload": identity["workload"], "profile": identity["profile"],
        "mode": identity["mode"], "source_sha256": identity["source_sha256"],
        "binary_sha256": identity["binary_sha256"],
    }
    for key, expected in expected_identity.items():
        row = take("identity", 3)
        require(row[1] == key and row[2] == expected, f"trace manifest identity differs at {key}")
        manifest_identity[key] = row[2]
    pressure_row = take("identity", 3)
    require(pressure_row[1] == "pressure_qualification" and pressure_row[2] in ("true", "false"), "trace pressure-qualification identity row is malformed")
    require((pressure_row[2] == "true") is identity["pressure_qualification"], "trace pressure-qualification flag differs from expectation")
    manifest_identity[pressure_row[1]] = pressure_row[2]
    directory = take("trace_directory", 5)
    require(directory[1] == "device" and directory[3] == "mode", "trace directory manifest row is malformed")
    _decimal(directory[2], "trace directory device")
    require(re.fullmatch(r"[0-7]{3,4}", directory[4]) is not None, "trace directory mode is malformed")

    artifacts: dict[str, dict[str, Any]] = {}
    for _ in range(2):
        row = take("artifact", 4)
        name = row[1]
        require(name in ("feedback-events.jsonl", "resource-samples.tsv") and name not in artifacts, "feedback manifest has an unexpected artifact")
        artifacts[name] = {"bytes": uint(_decimal(row[2], f"{name} bytes"), f"{name} bytes"), "sha256": digest(row[3], f"{name} SHA-256")}
    require(set(artifacts) == {"feedback-events.jsonl", "resource-samples.tsv"}, "feedback manifest omits a trace artifact")

    event_row = take("events", 9)
    require(event_row[1] == EVENT_SCHEMA, "feedback event summary schema is malformed")
    event_count = uint(_decimal(event_row[2], "event count"), "event count", positive=True, maximum=MAX_EVENT_RECORDS)
    event_first = uint(_decimal(event_row[3], "first event sequence"), "first event sequence", positive=True)
    event_last = uint(_decimal(event_row[4], "last event sequence"), "last event sequence", positive=True)
    require(event_first == 1 and event_last == event_count, "feedback event sequence summary has a gap")
    require(event_row[5] == "ring_wrapped" and event_row[6] in ("true", "false") and event_row[7:] == ["read_gaps", "0"], "feedback event stream reports missing history")

    sample_row = take("samples", 5)
    require(sample_row[1] == SAMPLE_SCHEMA, "unsupported feedback sample schema")
    sample_count = uint(_decimal(sample_row[2], "sample row count"), "sample row count", positive=True, maximum=MAX_SAMPLE_ROWS)
    require(uint(_decimal(sample_row[3], "first sample sequence"), "first sample sequence", positive=True) == 1 and uint(_decimal(sample_row[4], "last sample sequence"), "last sample sequence", positive=True) == sample_count, "feedback sample sequence summary has a gap")
    anchor = take("clock_anchor", 3)
    clock_lower = uint(_decimal(anchor[1], "trace clock lower anchor"), "trace clock lower anchor", positive=True)
    clock_upper = uint(_decimal(anchor[2], "trace clock upper anchor"), "trace clock upper anchor", positive=True)
    require(clock_lower <= clock_upper and clock_upper - clock_lower <= 50_000_000, "trace monotonic anchor uncertainty exceeds 50 ms")
    require(take("history_capacity", 2) == ["history_capacity", "16384"], "feedback history capacity differs from trace contract")

    expected_budgets = {
        "max_horizon_seconds": "11400", "sample_interval_ms": "100", "max_sample_rows": "114002",
        "max_sample_cycles": "114001", "terminal_sample_headroom": "1", "max_sample_record_bytes": "8192",
        "max_sample_file_bytes": str(MAX_SAMPLE_FILE_BYTES), "max_event_records": str(MAX_EVENT_RECORDS),
        "max_event_record_bytes": str(MAX_EVENT_LINE_BYTES), "max_event_file_bytes": str(MAX_EVENT_FILE_BYTES),
        "max_manifest_file_bytes": str(MAX_MANIFEST_BYTES), "base_events_per_sample_cycle": "3",
        "control_count": "3", "actuation_cooldown_ms": "1000", "max_tickets_per_control": "11401",
        "events_per_ticket": "4", "application_reconciliation_requests": "0", "terminal_event_headroom": "100",
    }
    budgets: dict[str, str] = {}
    for _ in range(len(expected_budgets)):
        row = take("budget", 3)
        require(row[1] in expected_budgets and row[1] not in budgets, "feedback manifest contains an unknown or duplicate budget")
        require(row[2] == expected_budgets[row[1]], f"feedback trace budget differs at {row[1]}")
        budgets[row[1]] = row[2]
    require(budgets == expected_budgets, "feedback manifest has incomplete artifact bounds")

    phases: dict[str, dict[str, Any]] = {}
    for _ in REQUIRED_PHASES:
        row = take("phase", 6)
        name = row[1]
        require(name in REQUIRED_PHASES and name not in phases, "feedback manifest has unknown or duplicate phase marker")
        lower, upper = uint(_decimal(row[2], f"phase {name} lower"), f"phase {name} lower", positive=True), uint(_decimal(row[3], f"phase {name} upper"), f"phase {name} upper", positive=True)
        require(lower <= upper and upper - lower == clock_upper - clock_lower, f"phase {name} clock bracket differs from its fixed anchor")
        if row[4] == "none" or row[5] == "none":
            require(row[4:] == ["none", "none"], f"phase {name} RSS pair is incomplete")
            rss = None
        else:
            rss = uint(_decimal(row[4], f"phase {name} RSS"), f"phase {name} RSS", positive=True)
            hwm = uint(_decimal(row[5], f"phase {name} HWM"), f"phase {name} HWM", positive=True)
            require(hwm >= rss, f"phase {name} HWM is below RSS")
            rss = {"rss_kib": rss, "hwm_kib": hwm}
        phases[name] = {"lower": lower, "upper": upper, "rss": rss}
    require(set(phases) == set(REQUIRED_PHASES), "feedback manifest omits a phase marker")

    control_row = take("control", 5)
    require(control_row[1] == "collector_charge_bytes" and control_row[3] == "expected_global_control_baseline", "trace collector accounting row is malformed")
    require(uint(_decimal(control_row[2], "trace collector Control charge"), "trace collector Control charge", positive=True) == recipe["policy"]["collector"]["control_charge_bytes"], "trace collector Control charge differs from expectation")
    require(uint(_decimal(control_row[4], "trace Control baseline"), "trace Control baseline") == recipe["policy"]["collector"]["expected_global_control_baseline"], "trace Control baseline differs from expectation")
    task_row = take("task", 3)
    require(task_row == ["task", "collector_task_lease_count", "1"], "trace collector Task lease differs from expectation")
    require(take("completion", 3) == ["completion", "complete", "true"], "feedback trace is not complete")
    require(index == len(rows), "feedback manifest has trailing or unknown rows")

    ordered = [phases[name] for name in (
        "rss_before", "production_start", "production_end", "drain_end",
        "rss_after_drain", "shutdown_end", "rss_after_shutdown", "owner_release",
    )]
    for previous, following in zip(ordered, ordered[1:]):
        require(previous["upper"] <= following["lower"], "feedback phase markers overlap or are out of order")
    require(phases["rss_before"]["rss"] is not None and phases["rss_after_drain"]["rss"] is not None and phases["rss_after_shutdown"]["rss"] is not None, "feedback trace omits required RSS checkpoints")
    prod_start, prod_end = phases["production_start"], phases["production_end"]
    drain_end = phases["drain_end"]
    duration_lower = prod_end["lower"] - prod_start["upper"]
    duration_upper = prod_end["upper"] - prod_start["lower"]
    require(duration_lower > 0 and duration_lower >= recipe["minimum_production_seconds"] * NSEC, "feedback production interval is shorter than preregistered")
    require(duration_upper <= MAX_TRACE_HORIZON_NS, "feedback production interval exceeds finite trace horizon")
    require(prod_end["upper"] <= drain_end["lower"], "feedback production end does not precede drain completion")
    return {
        "identity": manifest_identity, "artifacts": artifacts, "event_count": event_count,
        "sample_count": sample_count, "clock_anchor": (clock_lower, clock_upper),
        "phases": phases, "production_window": {
            "start_monotonic_ns": [prod_start["lower"], prod_start["upper"]],
            "end_monotonic_ns": [prod_end["lower"], prod_end["upper"]],
            "duration_lower_bound_ns": duration_lower,
            "duration_upper_bound_ns": duration_upper,
        }, "drain_window": (drain_end["lower"], drain_end["upper"]),
    }


def _timestamp(value: object, label: str, anchor_width: int) -> tuple[int, int]:
    require(type(value) is list and len(value) == 2, f"{label} must be a two-bound monotonic bracket")
    lower = uint(value[0], f"{label} lower", positive=True)
    upper = uint(value[1], f"{label} upper", positive=True)
    require(lower <= upper and upper - lower == anchor_width, f"{label} bracket differs from the fixed trace-clock uncertainty")
    return lower, upper


def _json_line(raw: bytes, label: str) -> dict[str, Any]:
    value = parse_json(raw, label, MAX_EVENT_LINE_BYTES)
    quoted = False
    escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                quoted = False
        elif byte == 0x22:
            quoted = True
        elif byte in b" \t\r\n":
            raise ValidationError(f"{label} is not compact JSONL")
    require(not quoted and not escaped, f"{label} has incomplete JSON string framing")
    return value


def _optional_uint(value: object, label: str, maximum: int = U64_MAX) -> int | None:
    if value is None:
        return None
    return uint(value, label, maximum=maximum)


def _sample_object(value: object, label: str, anchor_width: int, *, raw_sensor: bool = False) -> tuple[tuple[int, int], dict[str, int | None]]:
    sample = exact(value, {"at", "cpu_basis_points", "disk_basis_points", "download_basis_points"}, label)
    at = _timestamp(sample["at"], f"{label}.at", anchor_width)
    readings: dict[str, int | None] = {}
    for resource, key in (("cpu", "cpu_basis_points"), ("disk", "disk_basis_points"), ("download", "download_basis_points")):
        reading = _optional_uint(sample[key], f"{label}.{key}", 65_535 if raw_sensor else 10_000)
        readings[resource] = reading
    return at, readings


def _ticket(value: object, label: str, anchor_width: int) -> dict[str, Any]:
    ticket = exact(value, {"resource", "generation", "from_limit", "to_limit", "planned_at"}, label)
    require(ticket["resource"] in RESOURCES, f"{label} names an unknown resource")
    result = dict(ticket)
    result["generation"] = uint(ticket["generation"], f"{label}.generation", positive=True)
    result["from_limit"] = uint(ticket["from_limit"], f"{label}.from_limit", positive=True)
    result["to_limit"] = uint(ticket["to_limit"], f"{label}.to_limit", positive=True)
    result["planned_at_bounds"] = _timestamp(ticket["planned_at"], f"{label}.planned_at", anchor_width)
    return result


class PolicyModel:
    """Small independent transcription of runtime-feedback-policy-v1."""

    def __init__(self, expectation: dict[str, Any], clock_width: int):
        self.expectation = expectation
        self.policy = expectation["policy"]
        self.mode = expectation["mode"]
        self.clock_width = clock_width
        self.last_sample_at: int | None = None
        self.sample_count = 0
        self.accepted_sample_times = array("Q")
        self.sample_decision_record_times = array("Q")
        self.first_sample_at: int | None = None
        self.last_sample_at: int | None = None
        self.present_during_overlap = {resource: 0 for resource in RESOURCES}
        self.dense_during_overlap = {resource: 0 for resource in RESOURCES}
        self.production_bounds: tuple[int, int] | None = None
        self.drain_bounds: tuple[int, int] | None = None
        self.next_generation = 1
        self.seen_generations: set[int] = set()
        self.seen_limits: dict[str, set[int]] = {}
        self.pending_intervals: dict[str, list[list[int | None]]] = {}
        self.states: dict[str, dict[str, Any]] = {}
        for resource in RESOURCES:
            config = self.policy["controls"][resource]
            self.states[resource] = {
                "config": config, "current": config["initial"], "pending": None, "faulted": False,
                "latest": None, "latest_at": None, "last_observation": None, "last_present": None,
                "sparse": False, "breaches": 0, "last_success": None, "last_reconcile_bounds": None,
                "invalidated_at": None, "visible": {
                    "current_limit": config["initial"], "utilization_basis_points": None,
                    "telemetry": "Missing", "policy_faulted": False,
                    "pending_generation": None, "no_change": "None",
                },
            }
            self.seen_limits[resource] = {config["initial"]}
            self.pending_intervals[resource] = []
        self.ticket_count = 0
        self.pending_sensor: tuple[tuple[int, int], dict[str, int | None]] | None = None
        self.expected_plan_at: tuple[int, int] | None = None
        self.ticket_queue: list[dict[str, Any]] = []
        self.ticket_stage: str | None = None
        self.current_ticket: dict[str, Any] | None = None
        self.apply_result: str | None = None
        self.post_readback: tuple[str, int | None] | None = None
        self.reconciliation: dict[str, Any] | None = None
        self.started = False
        self.stop_requested = False
        self.joined = False
        self.event_count = 0
        self.last_event_lower: int | None = None

    def observe(self, at: int, readings: dict[str, int | None]) -> None:
        if self.last_sample_at is not None:
            elapsed = at - self.last_sample_at
            require(elapsed >= self.policy["sample_interval_ns"], "accepted feedback sample cadence is below 100 ms")
        for resource in RESOURCES:
            state = self.states[resource]
            if state["invalidated_at"] is not None and at <= state["invalidated_at"]:
                state["latest"] = None
                state["latest_at"] = None
                state["sparse"] = False
                state["breaches"] = 0
                continue
            value = readings[resource]
            observation_gap = state["last_observation"] is not None and at - state["last_observation"] > self.policy["max_dense_gap_ns"]
            if value is None:
                state["latest"], state["latest_at"] = None, None
                state["sparse"] = observation_gap
                state["breaches"] = 0
            else:
                present_gap = state["last_present"] is not None and at - state["last_present"] > self.policy["max_dense_gap_ns"]
                state["sparse"] = observation_gap or present_gap
                state["latest"], state["latest_at"], state["last_present"] = value, at, at
                if state["sparse"]:
                    state["breaches"] = 0
                elif value >= state["config"]["high_bps"]:
                    state["breaches"] = min(self.policy["required_breach_samples"], state["breaches"] + 1)
                else:
                    state["breaches"] = 0
            state["last_observation"] = at
        self.last_sample_at = at
        self.sample_count += 1
        if self.first_sample_at is None:
            self.first_sample_at = at
        self.last_sample_at = at
        if self.production_bounds is not None and self.drain_bounds is not None and self.production_bounds[0] <= at <= self.drain_bounds[1]:
            for resource, value in readings.items():
                if value is not None:
                    self.present_during_overlap[resource] += 1
                    if not self.states[resource]["sparse"]:
                        self.dense_during_overlap[resource] += 1

    def _telemetry(self, state: dict[str, Any], now: int) -> str:
        if state["latest"] is None or state["latest_at"] is None:
            return "Missing"
        age = now - state["latest_at"]
        require(age >= 0, "feedback plan precedes its latest sample")
        if age > self.policy["telemetry_freshness_ns"]:
            return "Stale"
        if state["sparse"] or age > self.policy["max_dense_gap_ns"]:
            return "Sparse"
        return "Fresh"

    def _remaining_cooldown(self, state: dict[str, Any], now: int) -> tuple[int, int] | None:
        ranges: list[tuple[int, int]] = []
        at = state["last_success"]
        if at is not None:
            elapsed = now - at
            require(elapsed >= 0, "feedback cooldown anchor follows current plan")
            if elapsed < self.policy["actuation_cooldown_ns"]:
                remaining = self.policy["actuation_cooldown_ns"] - elapsed
                ranges.append((remaining, remaining))
        bounds = state["last_reconcile_bounds"]
        if bounds is not None:
            early, late = bounds
            require(now >= late >= early, "feedback reconciliation cooldown bounds are out of order")
            minimum = max(0, self.policy["actuation_cooldown_ns"] - (now - early))
            maximum = max(0, self.policy["actuation_cooldown_ns"] - (now - late))
            if maximum > 0:
                require(minimum > 0, "feedback plan falls inside an unresolvable reconciliation-cooldown boundary")
                ranges.append((minimum, maximum))
        return (max(item[0] for item in ranges), max(item[1] for item in ranges)) if ranges else None

    def _decision(self, resource: str, now: int) -> dict[str, Any]:
        state = self.states[resource]
        config = state["config"]
        telemetry = self._telemetry(state, now)
        current = state["current"]
        utilization = state["latest"]
        no_change: dict[str, Any] | None = {"reason": "telemetry_unavailable"}
        target: int | None = None
        if state["faulted"]:
            no_change = {"reason": "actuation_fault_latched"}
        elif state["pending"] is not None:
            no_change = {"reason": "plan_pending"}
        elif telemetry != "Fresh":
            no_change = {"reason": "telemetry_unavailable"}
        elif utilization is not None and utilization >= config["high_bps"]:
            if state["breaches"] < self.policy["required_breach_samples"]:
                no_change = {"reason": "breach_samples_remaining", "observed": state["breaches"], "required": self.policy["required_breach_samples"]}
            else:
                remaining = self._remaining_cooldown(state, now)
                if remaining is not None:
                    no_change = {"reason": "cooling_down", "remaining_min_ns": remaining[0], "remaining_max_ns": remaining[1]}
                else:
                    reduction = current // 10
                    if reduction == 0:
                        no_change = {"reason": "reduction_quantized"}
                    elif current == config["floor"]:
                        no_change = {"reason": "at_floor"}
                    else:
                        target = max(config["floor"], current - reduction)
                        no_change = None
        elif utilization is not None and utilization <= config["low_bps"]:
            if current == config["ceiling"]:
                no_change = {"reason": "at_ceiling"}
            else:
                remaining = self._remaining_cooldown(state, now)
                if remaining is not None:
                    no_change = {"reason": "cooling_down", "remaining_min_ns": remaining[0], "remaining_max_ns": remaining[1]}
                else:
                    increment = 1 if resource == "cpu" else config["ceiling"] // 100
                    if increment == 0:
                        no_change = {"reason": "recovery_quantized"}
                    else:
                        target = min(config["ceiling"], current + increment)
                        no_change = None
        elif utilization is not None:
            no_change = {"reason": "hysteresis_band"}
        ticket = None
        if target is not None:
            require(target != current, "feedback policy constructed a no-op ticket")
            ticket = {
                "resource": resource, "generation": self.next_generation,
                "from_limit": current, "to_limit": target,
            }
            self.seen_generations.add(self.next_generation)
            self.ticket_count += 1
            self.next_generation += 1
            no_change = None
        return {
            "resource": resource, "current_limit": current,
            "utilization_basis_points": utilization, "telemetry": telemetry,
            "ticket": ticket, "no_change": no_change,
        }

    def validate_plan(self, event: dict[str, Any], now: int, planned_at: tuple[int, int]) -> None:
        require(self.expected_plan_at is not None and planned_at == self.expected_plan_at, "plan time differs from accepted sample decision")
        require(now >= planned_at[0], "plan history event precedes its planning instant")
        require(type(event["controls"]) is list and len(event["controls"]) == len(RESOURCES), "plan must contain all three controls")
        queue: list[dict[str, Any]] = []
        for resource, actual in zip(RESOURCES, event["controls"]):
            expected = self._decision(resource, planned_at[0])
            actual_base = exact(actual, {"resource", "current_limit", "utilization_basis_points", "telemetry", "ticket", "no_change"}, f"{resource} plan decision")
            for key in ("resource", "current_limit", "utilization_basis_points", "telemetry"):
                require(actual_base[key] == expected[key], f"feedback plan {resource} differs at {key}")
            if expected["ticket"] is None:
                require(actual_base["ticket"] is None, f"feedback {resource} plan has an unexpected ticket")
                if expected["no_change"]["reason"] == "cooling_down":
                    actual_change = exact(actual_base["no_change"], {"reason", "remaining_ns"}, f"{resource} cooldown diagnostic")
                    remaining = uint(actual_change["remaining_ns"], f"{resource} cooldown remaining")
                    require(actual_change["reason"] == "cooling_down" and expected["no_change"]["remaining_min_ns"] <= remaining <= expected["no_change"]["remaining_max_ns"], f"feedback {resource} cooldown differs from reconstructed policy time")
                else:
                    require(actual_base["no_change"] == expected["no_change"], f"feedback {resource} no-change reason differs from reconstructed policy")
                state = self.states[resource]
                state["visible"] = {
                    "current_limit": state["current"], "utilization_basis_points": state["latest"],
                    "telemetry": expected["telemetry"], "policy_faulted": state["faulted"],
                    "pending_generation": None if state["pending"] is None else state["pending"]["generation"],
                    "no_change": _debug_no_change(actual_base["no_change"]),
                }
            else:
                require(actual_base["no_change"] is None, f"planned {resource} change contains a no-change reason")
                ticket = _ticket(actual_base["ticket"], f"{resource} planned ticket", self.clock_width)
                expected_ticket = expected["ticket"]
                require(
                    ticket["resource"] == resource and ticket["generation"] == expected_ticket["generation"]
                    and ticket["from_limit"] == expected_ticket["from_limit"] and ticket["to_limit"] == expected_ticket["to_limit"]
                    and ticket["planned_at_bounds"] == planned_at,
                    f"{resource} ticket differs from independently calculated limit transition",
                )
                state = self.states[resource]
                state["pending"] = ticket
                self.pending_intervals[resource].append([ticket["generation"], planned_at[0], None])
                state["visible"] = {
                    "current_limit": state["current"], "utilization_basis_points": state["latest"],
                    "telemetry": expected["telemetry"], "policy_faulted": state["faulted"],
                    "pending_generation": ticket["generation"], "no_change": "None",
                }
                queue.append(ticket)
        self.expected_plan_at = None
        self.ticket_queue = queue
        self.ticket_stage = "pre" if queue else None
        self.current_ticket = queue[0] if queue else None

    def validate_ticket_event(self, event: dict[str, Any], now: int) -> None:
        require(self.current_ticket is not None and self.ticket_stage is not None, "ticket operation appears without a planned write")
        ticket = self.current_ticket
        kind = event["kind"]
        if kind == "pre_apply_readback":
            require(self.ticket_stage == "pre", "pre-write readback is out of order")
            found = _ticket(event["ticket"], "pre-write ticket", self.clock_width)
            _same_ticket(found, ticket)
            _callback_bounds(event, now, self.clock_width, allow_readback=True)
            outcome, actual = _readback_value(event, "pre-write readback")
            require(type(event["matches_ticket"]) is bool, "pre-write matches_ticket field is not boolean")
            matches = event["matches_ticket"]
            good = outcome == "value" and actual == ticket["from_limit"] and matches
            require(matches == (outcome == "value" and actual == ticket["from_limit"]), "pre-write matches_ticket flag contradicts actual readback")
            self.ticket_stage = "apply" if good else "ack_pre_failure"
            return
        if kind == "apply":
            require(self.ticket_stage == "apply", "write callback lacks a matching pre-write readback")
            found = _ticket(event["ticket"], "apply ticket", self.clock_width)
            _same_ticket(found, ticket)
            _callback_bounds(event, now, self.clock_width)
            self.apply_result = text(event["outcome"], "apply result", 128)
            require(self.apply_result == "Applied" or self.apply_result.startswith(("Failed(", "Panicked")), "apply result is not a known runtime diagnostic")
            apply_start, apply_end = _timestamp(event["started_at"], "apply.started_at", self.clock_width), _timestamp(event["completed_at"], "apply.completed_at", self.clock_width)
            self.set_apply_completed(apply_end)
            self.ticket_stage = "post"
            return
        if kind == "post_apply_readback":
            require(self.ticket_stage == "post", "post-write readback lacks a matching write callback")
            found = _ticket(event["ticket"], "post-write ticket", self.clock_width)
            _same_ticket(found, ticket)
            _callback_bounds(event, now, self.clock_width, allow_readback=True)
            self.post_readback = _readback_value(event, "post-write readback")
            self.ticket_stage = "ack_post"
            return
        require(kind == "acknowledgement" and self.ticket_stage in ("ack_pre_failure", "ack_post"), "ticket acknowledgement is missing required readbacks or write")
        found = _ticket(event["ticket"], "acknowledgement ticket", self.clock_width)
        _same_ticket(found, ticket)
        result = text(event["result"], "actuation acknowledgement result", 32)
        require(type(event["accepted"]) is bool and type(event["faulted"]) is bool, "ticket acknowledgement flags are not boolean")
        accepted = event["accepted"]
        require(accepted and event["pending_generation"] is None, "ticket acknowledgement was rejected or remained pending")
        acknowledged_limit = uint(event["current_limit"], "acknowledged current limit", positive=True)
        state = self.states[ticket["resource"]]
        if self.ticket_stage == "ack_pre_failure":
            require(result == "Failed" and acknowledged_limit == ticket["from_limit"] and event["faulted"] is True, "failed pre-write readback did not latch the policy fault")
            state["faulted"] = True
        else:
            require(type(self.apply_result) is str and self.post_readback is not None, "write attempt omits post-write evidence")
            success = self.apply_result == "Applied" and self.post_readback == ("value", ticket["to_limit"])
            require(result == ("Applied" if success else "Failed"), "acknowledgement disagrees with apply and post-readback evidence")
            if success:
                state["current"] = ticket["to_limit"]
                self.seen_limits[ticket["resource"]].add(ticket["to_limit"])
                state["last_success"] = self._apply_completed_at
                state["faulted"] = False
            else:
                state["faulted"] = True
            require(acknowledged_limit == state["current"] and event["faulted"] is state["faulted"], "acknowledgement state differs from reconstructed ticket result")
        state["pending"] = None
        interval = self.pending_intervals[ticket["resource"]][-1]
        require(interval[0] == ticket["generation"] and interval[2] is None, "ticket pending-interval history is inconsistent")
        interval[2] = now
        state["visible"]["current_limit"] = state["current"]
        state["visible"]["policy_faulted"] = state["faulted"]
        state["visible"]["pending_generation"] = None
        self.ticket_queue.pop(0)
        self.current_ticket = self.ticket_queue[0] if self.ticket_queue else None
        self.ticket_stage = "pre" if self.ticket_queue else None
        self.apply_result = None
        self.post_readback = None

    def set_apply_completed(self, value: tuple[int, int]) -> None:
        self._apply_completed_at = value[0]

    def finish_reconciliation(self, event: dict[str, Any], now: int) -> None:
        state = self.reconciliation
        require(state is not None and state["stage"] == "finish" and event["resource"] == state["resource"], "reconciliation finish has no matching readback")
        resource = state["resource"]
        control = self.states[resource]
        actual = _optional_uint(event["actual_limit"], "reconciliation finished actual limit")
        require(actual == state["actual"], "reconciliation finish changed its actual readback")
        accepted = event["accepted"]
        require(type(accepted) is bool, "reconciliation accepted flag is not boolean")
        require(type(event["faulted"]) is bool, "reconciliation fault flag is not boolean")
        current_limit = uint(event["current_limit"], "reconciliation current limit", positive=True)
        if accepted:
            require(state["outcome"] == "value" and actual is not None and control["config"]["floor"] <= actual <= control["config"]["ceiling"] and event["rejection"] is None, "accepted reconciliation is outside policy bounds or lacks a value readback")
            require(current_limit == actual and event["faulted"] is False and event["pending_generation"] is None, "reconciliation did not clear the fault and pending state")
            control["current"], control["faulted"], control["pending"] = actual, False, None
            self.seen_limits[resource].add(actual)
            control["latest"], control["latest_at"], control["sparse"], control["breaches"] = None, None, False, 0
            control["invalidated_at"] = now
            control["last_reconcile_bounds"] = (state["readback_completed"], now)
            control["visible"] = {
                "current_limit": actual, "utilization_basis_points": None, "telemetry": "Missing",
                "policy_faulted": False, "pending_generation": None,
                "no_change": "Some(TelemetryUnavailable)",
            }
        else:
            require(event["faulted"] is True and current_limit == control["current"], "rejected reconciliation cleared a fault or changed the current limit")
            if state["outcome"] == "value":
                require(event["rejection"] is not None, "out-of-range reconciliation omitted its policy rejection")
                text(event["rejection"], "reconciliation rejection", 1024)
            else:
                require(event["rejection"] is None, "failed readback fabricated a policy reconciliation rejection")
            require(control["faulted"], "rejected reconciliation has no latched fault")
        self.reconciliation = None

    def finish(self) -> dict[str, dict[str, Any]]:
        require(self.started and self.stop_requested and self.joined, "feedback service omitted startup, stop, or joined evidence")
        require(self.pending_sensor is None and self.expected_plan_at is None and not self.ticket_queue and self.reconciliation is None, "feedback trace ends with an incomplete operation")
        for resource, state in self.states.items():
            require(state["pending"] is None and not state["faulted"], f"feedback control {resource} remains pending or faulted")
            require(all(interval[2] is not None for interval in self.pending_intervals[resource]), f"feedback control {resource} has an unclosed ticket interval")
        require(self.first_sample_at is not None and self.last_sample_at is not None, "feedback trace has no accepted samples")
        require(self.production_bounds is not None and self.drain_bounds is not None, "feedback reader lacks pinned production and drain windows")
        require(self.first_sample_at <= self.production_bounds[0] and self.last_sample_at >= self.drain_bounds[1], "accepted feedback samples do not cover production through drain")
        if self.mode == "capacity_calibration":
            require(self.states["disk"]["current"] == self.states["disk"]["config"]["initial"] and self.states["download"]["current"] == self.states["download"]["config"]["initial"], "capacity calibration changed a byte-rate limit")
            require(self.dense_during_overlap["cpu"] >= self.policy["minimum_dense_observations"], "capacity calibration has insufficient dense CPU observations during production/drain")
        else:
            require(self.dense_during_overlap["cpu"] >= self.policy["minimum_dense_observations"], "pressure validation has insufficient dense CPU observations during production/drain")
            for resource in ("disk", "download"):
                if self.policy["capacity_sources"][resource]:
                    require(self.dense_during_overlap[resource] >= self.policy["minimum_dense_observations"], f"{resource} capacity has insufficient dense telemetry during production/drain")
                else:
                    require(self.states[resource]["latest"] is None and self.states[resource]["current"] == self.states[resource]["config"]["initial"], f"missing {resource} application-byte source was not held frozen")
        return {resource: state["visible"] for resource, state in self.states.items()}


def _debug_no_change(value: dict[str, Any]) -> str:
    reason = value["reason"]
    if reason == "breach_samples_remaining":
        return f"Some(BreachSamplesRemaining {{ observed: {value['observed']}, required: {value['required']} }})"
    if reason == "cooling_down":
        duration = value["remaining_ns"]
        if duration >= NSEC:
            unit, suffix = NSEC, "s"
        elif duration >= 1_000_000:
            unit, suffix = 1_000_000, "ms"
        elif duration >= 1_000:
            unit, suffix = 1_000, "µs"
        else:
            unit, suffix = 1, "ns"
        whole, fraction = divmod(duration, unit)
        if unit == 1:
            formatted = f"{whole}ns"
        elif fraction == 0:
            formatted = f"{whole}{suffix}"
        else:
            digits = {NSEC: 9, 1_000_000: 6, 1_000: 3}[unit]
            fractional = f"{fraction:0{digits}d}".rstrip("0")
            formatted = f"{whole}.{fractional}{suffix}"
        return f"Some(CoolingDown {{ remaining: {formatted} }})"
    names = {
        "telemetry_unavailable": "TelemetryUnavailable", "plan_pending": "PlanPending",
        "actuation_fault_latched": "ActuationFaultLatched", "hysteresis_band": "HysteresisBand",
        "at_floor": "AtFloor", "at_ceiling": "AtCeiling", "reduction_quantized": "ReductionQuantized",
        "recovery_quantized": "RecoveryQuantized",
    }
    require(reason in names, "unknown reconstructed no-change reason")
    return f"Some({names[reason]})"


def _same_ticket(found: dict[str, Any], expected: dict[str, Any]) -> None:
    for key in ("resource", "generation", "from_limit", "to_limit", "planned_at_bounds"):
        require(found[key] == expected[key], f"ticket event differs at {key}")


def _callback_bounds(event: dict[str, Any], event_at: int, anchor_width: int, *, allow_readback: bool = False) -> tuple[tuple[int, int], tuple[int, int]]:
    start = _timestamp(event["started_at"], f"{event['kind']}.started_at", anchor_width)
    end = _timestamp(event["completed_at"], f"{event['kind']}.completed_at", anchor_width)
    require(start[0] < end[0] <= event_at, f"{event['kind']} callback timestamps are out of order")
    if allow_readback:
        _readback_value(event, f"{event['kind']} readback")
    return start, end


def _readback_value(event: dict[str, Any], label: str) -> tuple[str, int | None]:
    outcome = text(event["outcome"], f"{label} outcome", 32)
    if outcome == "value":
        require("error" not in event, f"{label} value outcome contains an error")
        return outcome, uint(event["actual_limit"], f"{label} actual limit", positive=True)
    if outcome == "failed":
        require(event["actual_limit"] is None and "error" in event, f"{label} failure record is incomplete")
        text(event["error"], f"{label} error", 1024)
        return outcome, None
    require(outcome == "panicked" and event["actual_limit"] is None and "error" not in event, f"{label} has an unknown readback outcome")
    return outcome, None


def _event_keys(event: dict[str, Any]) -> None:
    base = {"schema", "sequence", "at", "kind"}
    kind = event.get("kind")
    keys: dict[str, set[str]] = {
        "startup_readback": base | {"resource", "expected_limit", "started_at", "completed_at", "outcome", "actual_limit"},
        "service_started": base,
        "sensor_callback": base | {"started_at", "completed_at", "outcome", "raw_sample"},
        "sample_decision": base | {"sample_at", "sample", "accepted", "rejection", "planned_at"},
        "plan": base | {"planned_at", "controls"},
        "plan_rejected": base | {"error"},
        "pre_apply_readback": base | {"ticket", "started_at", "completed_at", "outcome", "actual_limit", "matches_ticket"},
        "apply": base | {"ticket", "started_at", "completed_at", "outcome"},
        "post_apply_readback": base | {"ticket", "started_at", "completed_at", "outcome", "actual_limit"},
        "acknowledgement": base | {"ticket", "result", "accepted", "current_limit", "faulted", "pending_generation"},
        "reconciliation_requested": base | {"resource"},
        "reconciliation_started": base | {"resource"},
        "reconciliation_readback": base | {"resource", "started_at", "completed_at", "outcome", "actual_limit"},
        "reconciliation_finished": base | {"resource", "actual_limit", "accepted", "current_limit", "faulted", "pending_generation", "rejection"},
        "stop_requested": base,
        "worker_failure": base | {"failure"},
        "worker_joined": base | {"panicked"},
    }
    require(kind in keys, f"unknown feedback event kind: {kind}")
    expected = keys[kind]
    if kind in ("startup_readback", "pre_apply_readback", "post_apply_readback", "reconciliation_readback") and event.get("outcome") == "failed":
        expected = expected | {"error"}
    require(set(event) == expected, f"feedback event {kind} has unknown or missing fields")


def _begin_reconciliation(model: PolicyModel, event: dict[str, Any]) -> None:
    resource = event["resource"]
    require(resource in RESOURCES and model.reconciliation is None, "reconciliation request is unknown or duplicated")
    state = model.states[resource]
    require(state["faulted"] and state["pending"] is None, "reconciliation request lacks a latched fault or has a pending ticket")
    model.reconciliation = {"resource": resource, "stage": "started", "outcome": None, "actual": None}


def _validate_event_stream(
    stream: BoundedLines | CapturedBoundedLines,
    directory_fd: int | None,
    expectation: dict[str, Any],
    manifest: dict[str, Any],
    expected_sha: str,
) -> tuple[str, PolicyModel, dict[str, Any]]:
    model = PolicyModel(expectation, manifest["clock_anchor"][1] - manifest["clock_anchor"][0])
    model.production_bounds = (manifest["phases"]["production_start"]["lower"], manifest["phases"]["production_start"]["upper"])
    model.drain_bounds = (manifest["phases"]["drain_end"]["lower"], manifest["phases"]["drain_end"]["upper"])
    startup_count = 0
    event_count = 0
    joined_at: tuple[int, int] | None = None
    last_sensor: tuple[tuple[int, int], dict[str, int | None]] | None = None
    for raw_line in stream:
        event = _json_line(raw_line, "feedback event")
        _event_keys(event)
        require(event["schema"] == EVENT_SCHEMA, "unsupported feedback event schema")
        sequence = uint(event["sequence"], "feedback event sequence", positive=True, maximum=MAX_EVENT_RECORDS)
        require(sequence == event_count + 1, "feedback event sequence has a gap or duplicate")
        at = _timestamp(event["at"], "feedback event time", model.clock_width)
        require(model.last_event_lower is None or at[0] >= model.last_event_lower, "feedback event timestamps moved backwards")
        model.last_event_lower = at[0]
        model.event_count = sequence
        event_count += 1
        kind = event["kind"]
        if model.joined:
            raise ValidationError("feedback event appears after WorkerJoined")
        if kind == "startup_readback":
            require(not model.started and startup_count < len(RESOURCES), "startup readback is duplicated or follows service start")
            resource = RESOURCES[startup_count]
            require(event["resource"] == resource, "startup readback controls are out of fixed CPU/disk/download order")
            initial = expectation["policy"]["controls"][resource]["initial"]
            require(uint(event["expected_limit"], f"{resource} startup expected limit", positive=True) == initial, f"{resource} startup limit differs from expectation")
            _callback_bounds(event, at[0], model.clock_width, allow_readback=True)
            outcome, actual = _readback_value(event, f"{resource} startup readback")
            require(outcome == "value" and actual == initial, f"{resource} startup actuator readback failed")
            startup_count += 1
        elif kind == "service_started":
            require(startup_count == len(RESOURCES) and not model.started, "feedback service started without all three startup readbacks")
            model.started = True
        elif kind == "sensor_callback":
            require(model.started and not model.joined and model.pending_sensor is None and model.expected_plan_at is None and not model.ticket_queue and model.reconciliation is None, "sensor callback overlaps an unfinished feedback operation")
            start, end = _callback_bounds(event, at[0], model.clock_width)
            outcome = text(event["outcome"], "sensor callback outcome", 1024)
            require(outcome == "Sampled" and event["raw_sample"] is not None, "feedback sensor callback failed or returned no measured sample")
            sample_at, readings = _sample_object(event["raw_sample"], "raw feedback sample", model.clock_width, raw_sensor=True)
            require(start[0] <= sample_at[0] <= end[0] and end[0] <= at[0], "raw feedback sample lies outside its callback interval")
            model.pending_sensor = (sample_at, readings)
            last_sensor = model.pending_sensor
        elif kind == "sample_decision":
            require(model.started and model.pending_sensor is not None, "sample decision has no matching sensor callback")
            sample_at, readings = _sample_object(event["sample"], "policy feedback sample", model.clock_width)
            named_at = _timestamp(event["sample_at"], "sample decision time", model.clock_width)
            require(sample_at == named_at and at[0] >= sample_at[0], "sample decision timestamp differs from its sample")
            raw_at, raw_readings = model.pending_sensor
            require(sample_at == raw_at, "sample decision changed the sensor's monotonic timestamp")
            for resource, raw_value in raw_readings.items():
                sanitized = None if raw_value is not None and raw_value > 10_000 else raw_value
                require(readings[resource] == sanitized, f"sample decision changed or failed to sanitize {resource} telemetry")
            require(type(event["accepted"]) is bool and event["rejection"] is None, "sample decision is rejected or has an unknown rejection diagnostic")
            planned = None if event["planned_at"] is None else _timestamp(event["planned_at"], "sample planned time", model.clock_width)
            if model.stop_requested:
                require(event["accepted"] is False and planned is None, "feedback policy accepted a sample after stop was requested")
                model.pending_sensor = None
                last_sensor = None
                continue
            require(event["accepted"] is True and planned is not None, "feedback sample was rejected or lacks its policy plan")
            if expectation["mode"] == "capacity_calibration":
                require(readings["disk"] is None and readings["download"] is None, "capacity calibration emitted app-byte telemetry before denominators existed")
                if readings["cpu"] is None:
                    require(
                        expectation["schema"] in (EXPECTATION_SCHEMA_V2, EXPECTATION_SCHEMA_V4),
                        "legacy capacity calibration CPU telemetry is missing",
                    )
            model.observe(sample_at[0], readings)
            model.accepted_sample_times.append(sample_at[0])
            model.sample_decision_record_times.append(at[0])
            model.expected_plan_at = planned
            model.pending_sensor = None
            last_sensor = None
        elif kind == "plan":
            require(model.expected_plan_at is not None, "feedback plan has no accepted sample")
            planned = _timestamp(event["planned_at"], "policy plan time", model.clock_width)
            model.validate_plan(event, at[0], planned)
        elif kind == "plan_rejected":
            raise ValidationError("feedback runtime rejected policy planning")
        elif kind in ("pre_apply_readback", "apply", "post_apply_readback", "acknowledgement"):
            model.validate_ticket_event(event, at[0])
        elif kind == "reconciliation_requested":
            require(model.started and not model.ticket_queue and model.expected_plan_at is None, "reconciliation overlaps a pending plan or write")
            _begin_reconciliation(model, event)
        elif kind == "reconciliation_started":
            require(model.reconciliation is not None and model.reconciliation["stage"] == "started" and event["resource"] == model.reconciliation["resource"], "reconciliation start does not match a request")
            model.reconciliation["stage"] = "readback"
        elif kind == "reconciliation_readback":
            state = model.reconciliation
            require(state is not None and state["stage"] == "readback" and event["resource"] == state["resource"], "reconciliation readback has no matching start")
            _, completed = _callback_bounds(event, at[0], model.clock_width, allow_readback=True)
            outcome, actual = _readback_value(event, "reconciliation readback")
            state["outcome"], state["actual"], state["readback_completed"] = outcome, actual, completed[0]
            state["stage"] = "finish"
        elif kind == "reconciliation_finished":
            model.finish_reconciliation(event, at[0])
        elif kind == "stop_requested":
            require(model.started and not model.stop_requested, "feedback stop request is missing startup or duplicated")
            model.stop_requested = True
        elif kind == "worker_failure":
            raise ValidationError("feedback trace records a worker failure")
        elif kind == "worker_joined":
            require(model.stop_requested and event["panicked"] is False, "feedback worker did not join cleanly after stop")
            require(last_sensor is None, "feedback worker joined with an unfinished sensor callback")
            model.joined = True
            joined_at = at
        else:
            raise ValidationError(f"feedback event kind is unsupported: {kind}")

    actual_sha = stream.finish(directory_fd)
    require(actual_sha == expected_sha, "feedback event raw SHA-256 differs from caller pin")
    require(event_count == manifest["event_count"] and event_count > 0, "feedback event count differs from manifest")
    final_state = model.finish()
    require(joined_at is not None, "feedback event stream omits WorkerJoined")
    return actual_sha, model, {"final_state": final_state, "worker_joined_at": joined_at}


def _parse_sample_row(line: bytes, sequence: int) -> dict[str, Any]:
    try:
        fields = line.decode("ascii").split("\t")
    except UnicodeError as error:
        raise ValidationError("resource sample row is not ASCII") from error
    require(len(fields) == len(SAMPLE_HEADER), "resource sample row field count differs from its strict schema")
    require(fields[0] == str(sequence), "resource sample sequence has a gap or duplicate")
    result: dict[str, Any] = dict(zip(SAMPLE_HEADER, fields))
    bool_fields = {
        "feedback_stop_requested", "feedback_shutdown_complete",
        *(f"{direction}_meter_{field}" for direction in RATE_DIRECTIONS for field in (
            "counter_overflow", "invalid_io", "source_count_overflow", "generation_overflow",
        )),
        *(f"{resource}_policy_faulted" for resource in RESOURCES),
    }
    optional_fields = {
        *(f"{resource}_utilization_basis_points" for resource in RESOURCES),
        *(f"{resource}_pending_generation" for resource in RESOURCES),
    }
    enum_fields = {*(f"{resource}_telemetry" for resource in RESOURCES)}
    textual_fields = {"feedback_worker_failure", *(f"{resource}_no_change" for resource in RESOURCES)}
    for key, value in tuple(result.items()):
        if key in bool_fields:
            require(value in ("true", "false"), f"resource sample {key} is not boolean")
            result[key] = value == "true"
        elif key in optional_fields:
            result[key] = None if value == "none" else uint(_decimal(value, key), key)
        elif key in enum_fields:
            require(value in ("Missing", "Sparse", "Stale", "Fresh"), f"resource sample {key} is an unknown telemetry state")
        elif key in textual_fields:
            text(value, key, 1024)
        else:
            result[key] = uint(_decimal(value, key), key)
    for resource in RESOURCES:
        value = result[f"{resource}_utilization_basis_points"]
        require(value is None or value <= 10_000, f"resource sample {resource} utilization exceeds 100 percent")
        telemetry = result[f"{resource}_telemetry"]
        require((telemetry == "Missing") == (value is None), f"resource sample {resource} telemetry/value state contradicts")
    require(result["feedback_worker_failure"] == "none", "resource sample records a feedback worker failure")
    return result


def _decimal(value: str, label: str) -> int:
    require(re.fullmatch(r"0|[1-9][0-9]*", value) is not None, f"{label} is not a canonical unsigned decimal")
    return int(value)


def _validate_resource_sample_rows(
    stream: BoundedLines | CapturedBoundedLines,
    directory_fd: int | None,
    expectation: dict[str, Any],
    manifest: dict[str, Any],
    expected_sha: str,
    model: PolicyModel,
    event_info: dict[str, Any],
) -> str:
    iterator = iter(stream)
    schema = next(iterator, None)
    header = next(iterator, None)
    require(schema == f"schema\t{SAMPLE_SCHEMA}".encode("ascii"), "resource sample file has an unsupported schema header")
    require(header == "\t".join(SAMPLE_HEADER).encode("ascii"), "resource sample file has unknown, missing, or reordered columns")
    previous_lower: int | None = None
    previous_feedback_count = 0
    previous_meters: dict[str, tuple[int, int, int, int, int, int]] = {}
    final: dict[str, Any] | None = None
    count = 0
    phases = manifest["phases"]
    anchor_width = manifest["clock_anchor"][1] - manifest["clock_anchor"][0]
    policy = expectation["policy"]
    for raw_line in iterator:
        count += 1
        require(count <= MAX_SAMPLE_ROWS, "resource sample file exceeds its fixed row cap")
        row = _parse_sample_row(raw_line, count)
        lower, upper = row["window_lower_ns"], row["window_upper_ns"]
        require(lower <= upper and upper - lower <= 200_000_000, "resource sample window is reversed or excessively wide")
        if previous_lower is not None:
            elapsed = lower - previous_lower
            require(0 < elapsed <= policy["max_dense_gap_ns"], "resource snapshots are duplicated, out of order, or sparse")
        previous_lower = lower
        require(row["rss_kib"] > 0 and row["hwm_kib"] >= row["rss_kib"], "resource sample RSS/HWM is invalid")
        require(row["collector_task_lease_count"] == policy["collector"]["task_lease_count"], "resource sample collector Task lease differs from expectation")

        for owner, ceilings in (("global", policy["global_ceilings"]), ("tenant", policy["tenant_ceilings"])):
            for resource in DOMAIN:
                ceiling = row[f"{owner}_ceiling_{resource}"]
                limit = row[f"{owner}_limit_{resource}"]
                used = row[f"{owner}_used_{resource}"]
                require(ceiling == ceilings[resource], f"resource sample {owner} {resource} ceiling differs from caller-pinned value")
                zero_limit_allowed = expectation["schema"] in (EXPECTATION_SCHEMA_V2, EXPECTATION_SCHEMA_V3, EXPECTATION_SCHEMA_V4) and ceiling == 0
                require((limit > 0 or zero_limit_allowed) and limit <= ceiling and used <= ceiling, f"resource sample {owner} {resource} exceeds its hard ceiling")
        expected_scope = {
            "managed_memory_limit": "managed_memory", "disk_operation_limit": "disk_operations",
            "network_operation_limit": "network_operations",
        }
        for sample_key, policy_key in expected_scope.items():
            require(row[f"scope_{sample_key}"] == policy["scope_limits"][policy_key], f"scope {sample_key} differs from caller-pinned limit")
        for used_key, limit_key in (("scope_managed_memory_used", "scope_managed_memory_limit"),
                                    ("scope_disk_operations_used", "scope_disk_operation_limit"),
                                    ("scope_network_operations_used", "scope_network_operation_limit")):
            require(row[used_key] <= row[limit_key], f"resource sample {used_key} exceeds its scope limit")

        for direction in RATE_DIRECTIONS:
            bucket = policy["rate_buckets"][direction]
            prefix = f"{direction}_rate_"
            require(row[prefix + "ceiling_bytes_per_second"] == bucket["ceiling_bytes_per_second"], f"{direction} bucket rate ceiling differs from expectation")
            require(row[prefix + "ceiling_burst_bytes"] == bucket["ceiling_burst_bytes"], f"{direction} bucket burst ceiling differs from expectation")
            require(row[prefix + "max_reservations"] == bucket["max_reservations"], f"{direction} bucket reservation cap differs from expectation")
            require(row[prefix + "bytes_per_second"] <= bucket["ceiling_bytes_per_second"] and row[prefix + "burst_bytes"] <= bucket["ceiling_burst_bytes"], f"{direction} bucket exceeds its hard rate/burst cap")
            # Admission tokens refill while earlier I/O owners retain their bytes.
            # Reconfiguration can lower the current burst below an old admission.
            available = row[prefix + "available_bytes"]
            reserved = row[prefix + "reserved_bytes"]
            owners = row[prefix + "reservations"]
            require(available <= row[prefix + "burst_bytes"],
                    f"{direction} available bucket credits exceed its burst")
            require(owners <= reserved <= owners * bucket["ceiling_burst_bytes"],
                    f"{direction} retained bucket credits exceed their owner bounds")
            require(row[prefix + "reservations"] <= bucket["max_reservations"], f"{direction} bucket exceeds its reservation cap")
        require(row["upload_rate_bytes_per_second"] == policy["rate_buckets"]["upload"]["ceiling_bytes_per_second"], "upload control changed despite being fixed")

        for direction in RATE_DIRECTIONS:
            prefix = f"{direction}_meter_"
            measured_lower, measured_upper = row[prefix + "measured_lower_ns"], row[prefix + "measured_upper_ns"]
            require(measured_lower <= measured_upper and measured_upper - measured_lower == anchor_width, f"{direction} meter timestamp bracket differs from trace anchor")
            require(lower <= measured_lower and measured_upper <= upper, f"{direction} meter timestamp is outside its independently bracketed resource snapshot")
            if expectation["schema"] == EXPECTATION_SCHEMA_V1:
                require(row[prefix + "attached_sources"] == policy["meter_sources"][direction], f"legacy {direction} meter source count differs from expectation")
            else:
                bounds = policy["meter_source_bounds"][direction]
                require(
                    bounds["minimum_live"] <= row[prefix + "attached_sources"] <= bounds["maximum_live"],
                    f"{direction} meter attached source count is outside caller-frozen bounds",
                )
            require(not any(row[prefix + field] for field in ("counter_overflow", "invalid_io", "source_count_overflow", "generation_overflow")), f"{direction} meter reports a counter or I/O fault")
            current = (
                measured_lower, row[prefix + "committed_bytes"], row[prefix + "completions"],
                row[prefix + "generation"], row[prefix + "attached_sources"], measured_upper,
            )
            previous = previous_meters.get(direction)
            if previous is not None:
                meter_elapsed = measured_lower - previous[0]
                require(0 < meter_elapsed <= policy["max_dense_gap_ns"] and row[prefix + "generation"] >= previous[3], f"{direction} meter timestamps failed strict advancement or 200 ms freshness")
                if row[prefix + "generation"] == previous[3]:
                    require(current[1] >= previous[1] and current[2] >= previous[2], f"{direction} meter counters decreased without a generation change")
            previous_meters[direction] = current

        feedback_count = row["feedback_sample_count"]
        require(previous_feedback_count <= feedback_count <= model.sample_count, "resource sample feedback count moved backwards or exceeds event history")
        definitely_updated = bisect_right(model.sample_decision_record_times, lower)
        possibly_updated = bisect_right(model.accepted_sample_times, upper)
        require(definitely_updated <= feedback_count <= possibly_updated, "resource sample feedback count does not fit its same-clock event window")
        previous_feedback_count = feedback_count
        for resource in RESOURCES:
            config = policy["controls"][resource]
            current = row[f"{resource}_current_limit"]
            require(config["floor"] <= current <= config["ceiling"] and current in model.seen_limits[resource], f"resource sample {resource} current limit is not a reconstructed policy value")
            if resource in ("disk", "download") and not policy["capacity_sources"][resource]:
                require(row[f"{resource}_utilization_basis_points"] is None and row[f"{resource}_current_limit"] == config["initial"], f"missing {resource} byte source was not frozen")
            pending = row[f"{resource}_pending_generation"]
            if pending is not None:
                require(pending in model.seen_generations, f"resource sample {resource} reports a generation absent from the event history")
                active = any(
                    gen == pending and start <= upper and (end is None or end >= lower)
                    for gen, start, end in model.pending_intervals[resource]
                )
                require(active, f"resource sample {resource} reports a stale or fabricated pending generation")
        final = row
    actual_sha = stream.finish(directory_fd)
    require(actual_sha == expected_sha and actual_sha == manifest["artifacts"]["resource-samples.tsv"]["sha256"], "resource sample raw SHA-256 differs from caller or manifest pin")
    require(stream.bytes_read == manifest["artifacts"]["resource-samples.tsv"]["bytes"], "resource sample byte count differs from manifest")
    require(count == manifest["sample_count"] and final is not None, "resource sample count differs from manifest")
    require(final["window_lower_ns"] >= event_info["worker_joined_at"][0], "terminal resource sample precedes WorkerJoined history")
    require(final["feedback_sample_count"] == model.sample_count and final["feedback_stop_requested"] is True and final["feedback_shutdown_complete"] is True, "terminal resource sample does not prove complete feedback shutdown")
    for resource in RESOURCES:
        expected = event_info["final_state"][resource]
        require(final[f"{resource}_current_limit"] == expected["current_limit"], f"terminal {resource} limit differs from reconstructed policy")
        require(final[f"{resource}_utilization_basis_points"] == expected["utilization_basis_points"], f"terminal {resource} telemetry differs from reconstructed policy")
        require(final[f"{resource}_telemetry"] == expected["telemetry"], f"terminal {resource} telemetry state differs from reconstructed policy")
        require(final[f"{resource}_policy_faulted"] is expected["policy_faulted"] and final[f"{resource}_pending_generation"] == expected["pending_generation"], f"terminal {resource} fault/pending state differs from reconstructed policy")
        require(final[f"{resource}_no_change"] == expected["no_change"], f"terminal {resource} no-change reason differs from reconstructed policy")
    if expectation["mode"] == "capacity_calibration":
        require(model.ticket_count == 0, "capacity calibration contains a feedback write")
        for resource in ("disk", "download"):
            require(final[f"{resource}_telemetry"] == "Missing" and final[f"{resource}_utilization_basis_points"] is None, f"capacity calibration {resource} telemetry is not Missing")
    require(final["feedback_worker_failure"] == "none", "terminal resource sample reports a worker failure")
    return actual_sha


def verify_feedback(
    expectation_path: Path,
    expected_expectation_sha256: str,
    trace_directory: Path,
    expected_artifact_sha256: dict[str, str],
) -> dict[str, Any]:
    return _verify_feedback_replay(
        expectation_path, expected_expectation_sha256, trace_directory,
        expected_artifact_sha256,
    )


def _verify_feedback_replay(
    expectation_path: Path,
    expected_expectation_sha256: str,
    trace_directory: Path,
    expected_artifact_sha256: dict[str, str],
    *, offline_replay_context: object | None = None,
    offline_replayed_proof: dict[str, Any] | None = None,
) -> dict[str, Any]:
    replay_context = (None if offline_replay_context is None else
                      _validate_feedback_offline_context(offline_replay_context))
    captured = (replay_context is not None and
                replay_context.get("captured") is True)
    captured_view = (replay_context["artifact_view"] if captured else None)
    if captured:
        expectation_origin = str(absolute_path(
            str(expectation_path), "captured feedback expectation path",
        ))
        require(expectation_origin in replay_context["captured_files"],
                "captured feedback expectation is absent from the exact archived output refs")
    expectation, expectation_raw_sha = read_canonical(
        expectation_path, "feedback expectation", MAX_EXPECTATION_BYTES,
        digest(expected_expectation_sha256, "expected expectation raw SHA-256"),
        artifact_view=_captured_view_for_path(replay_context, expectation_path)
        if captured else None,
    )
    recipe = _validate_expectation_body({key: value for key, value in expectation.items() if key != "recipe_sha256"})
    require(digest(expectation.get("recipe_sha256"), "expectation self digest") == digest_object(recipe), "feedback expectation self digest is invalid")
    if captured:
        source_manifest_pin = exact(
            recipe.get("host_binding"), {"path", "raw_sha256"},
            "captured feedback resident SourceV5 manifest pin",
        )
        source_manifest_origin = str(absolute_path(
            source_manifest_pin["path"],
            "captured feedback resident SourceV5 manifest path",
        ))
        _require_offline_files(
            replay_context, {source_manifest_origin},
            "resident source manifest",
        )
        require(source_manifest_origin not in replay_context["captured_files"],
                "source manifest must remain a resident pinned input")
        trace_origin = str(absolute_path(
            str(trace_directory), "captured feedback trace directory",
        ))
        _require_offline_directories(
            replay_context, {trace_origin}, "captured feedback trace root",
        )
        expected_trace_origins = {
            str(Path(trace_origin) / name) for name in TRACE_FILES
        }
        _require_offline_files(
            replay_context, expected_trace_origins,
            "captured feedback trace member",
        )
        actual_trace_origins = {
            path for path in replay_context["mapped_files"]
            if Path(path) != Path(trace_origin) and
            Path(trace_origin) in Path(path).parents
        }
        nested_trace_directories = {
            path for path in replay_context["mapped_directories"]
            if Path(path) != Path(trace_origin) and
            Path(trace_origin) in Path(path).parents
        }
        require(actual_trace_origins == expected_trace_origins,
                "captured feedback trace has an unpinned or missing output member")
        require(not nested_trace_directories,
                "captured feedback trace directory contains an unpinned nested directory")
    source_manifest = _verify_source_manifest(recipe)
    if recipe["schema"] in (EXPECTATION_SCHEMA_V5, EXPECTATION_SCHEMA_V6):
        capacity_floor_policy_id = recipe["policy"].get("capacity_floor_policy_id")
        if offline_replay_context is None:
            validate_calibrated_construction_probe_v2(
                recipe["construction_probe"], source_manifest["value"],
                recipe["app_capacity_artifact"], recipe["identity"], recipe["policy"],
                capacity_floor_policy_id,
            )
        else:
            source_pin = exact(recipe["host_binding"], {"path", "raw_sha256"},
                               "offline feedback SourceV5 manifest pin")
            validate_calibrated_construction_probe_v2_offline(
                recipe["construction_probe"], source_pin, recipe["app_capacity_artifact"],
                recipe["identity"], replay_context=offline_replay_context,
                expected_policy=recipe["policy"],
                capacity_floor_policy_id=capacity_floor_policy_id,
            )
    elif recipe["schema"] in (EXPECTATION_SCHEMA_V2, EXPECTATION_SCHEMA_V3, EXPECTATION_SCHEMA_V4):
        validate_construction_probe(recipe, source_manifest["value"])
    artifact_pins = {
        "feedback-trace-manifest.tsv": digest(expected_artifact_sha256.get("manifest"), "expected manifest raw SHA-256"),
        "feedback-events.jsonl": digest(expected_artifact_sha256.get("events"), "expected events raw SHA-256"),
        "resource-samples.tsv": digest(expected_artifact_sha256.get("samples"), "expected samples raw SHA-256"),
    }
    trace_root = absolute_path(str(trace_directory), "trace directory")
    root_fd: int | None = None
    if not captured:
        root_fd = _open_trace_directory(trace_root)
    try:
        require(TRACE_FILES == set(artifact_pins), "feedback trace artifact pins do not match the fixed file set")
        if not captured:
            require(root_fd is not None, "feedback trace directory descriptor is absent")
            _validate_trace_directory_layout(root_fd)
        manifest_origin = trace_root / "feedback-trace-manifest.tsv"
        manifest_stream = (
            CapturedBoundedLines(
                manifest_origin, "feedback trace manifest", MAX_MANIFEST_BYTES,
                MAX_MANIFEST_BYTES, captured_view,
            ) if captured else
            BoundedLines(root_fd, manifest_origin.name,
                         "feedback trace manifest", MAX_MANIFEST_BYTES,
                         MAX_MANIFEST_BYTES)
        )
        with manifest_stream as manifest_file:
            manifest_rows = list(manifest_file)
            manifest_sha = manifest_file.finish(root_fd)
            require(manifest_sha == artifact_pins["feedback-trace-manifest.tsv"], "feedback manifest raw SHA-256 differs from caller pin")
            manifest = _parse_manifest(manifest_rows, recipe)
        require(manifest["artifacts"]["feedback-events.jsonl"]["sha256"] == artifact_pins["feedback-events.jsonl"], "manifest event digest differs from separately pinned raw SHA-256")
        require(manifest["artifacts"]["resource-samples.tsv"]["sha256"] == artifact_pins["resource-samples.tsv"], "manifest sample digest differs from separately pinned raw SHA-256")
        events_origin = trace_root / "feedback-events.jsonl"
        events_stream = (
            CapturedBoundedLines(
                events_origin, "feedback events", MAX_EVENT_FILE_BYTES,
                MAX_EVENT_LINE_BYTES, captured_view,
            ) if captured else
            BoundedLines(root_fd, events_origin.name, "feedback events",
                         MAX_EVENT_FILE_BYTES, MAX_EVENT_LINE_BYTES)
        )
        with events_stream as events_file:
            require(events_file.byte_count == manifest["artifacts"]["feedback-events.jsonl"]["bytes"], "event file size differs from manifest")
            events_sha, model, event_info = _validate_event_stream(
                events_file, root_fd, recipe, manifest, artifact_pins["feedback-events.jsonl"],
            )
        samples_origin = trace_root / "resource-samples.tsv"
        samples_stream = (
            CapturedBoundedLines(
                samples_origin, "resource samples", MAX_SAMPLE_FILE_BYTES,
                MAX_SAMPLE_LINE_BYTES, captured_view,
            ) if captured else
            BoundedLines(root_fd, samples_origin.name, "resource samples",
                         MAX_SAMPLE_FILE_BYTES, MAX_SAMPLE_LINE_BYTES)
        )
        with samples_stream as samples_file:
            require(samples_file.byte_count == manifest["artifacts"]["resource-samples.tsv"]["bytes"], "resource sample file size differs from manifest")
            samples_sha = _validate_resource_sample_rows(
                samples_file, root_fd, recipe, manifest, artifact_pins["resource-samples.tsv"], model, event_info,
            )
    finally:
        if root_fd is not None:
            os.close(root_fd)

    production = manifest["production_window"]
    drain = manifest["drain_window"]
    pressure_ok = False
    runtime_ok = False
    runtime_sha: str | None = None
    soak_readback_sha: str | None = None
    soak_qualification_eligible = False
    soak_mode: str | None = None
    release_complete = False
    if recipe["mode"] in ("pressure_validation", "pressure_soak_validation"):
        pressure_view = None
        runtime_view = None
        soak_view = None
        if captured:
            pressure_pin = recipe.get("external_pressure_proof")
            require(type(pressure_pin) is dict and
                    type(pressure_pin.get("path")) is str,
                    "captured pressure expectation omits its external proof pin")
            pressure_view = _required_captured_file_view(
                replay_context, pressure_pin["path"],
                "captured external pressure proof",
            )
            if recipe["schema"] == EXPECTATION_SCHEMA_V3:
                binding = exact(
                    recipe.get("final_runtime_binding"),
                    {"soak_receipt", "soak_readback"},
                    "captured final soak bindings",
                )
                for name in ("soak_receipt", "soak_readback"):
                    pin = exact(
                        binding[name], {"path", "raw_sha256"},
                        f"captured {name.replace('_', ' ')} pin",
                    )
                    _required_captured_file_view(
                        replay_context, pin["path"],
                        f"captured {name.replace('_', ' ')}",
                    )
                soak_view = replay_context["artifact_view"]
            else:
                runtime_pin = recipe.get("final_runtime_binding")
                require(type(runtime_pin) is dict and
                        set(runtime_pin) == {"path", "raw_sha256"},
                        "captured pressure expectation omits its final runtime-binding pin")
                runtime_view = _required_captured_file_view(
                    replay_context, runtime_pin["path"],
                    "captured final runtime binding",
                )
        if recipe["schema"] == EXPECTATION_SCHEMA_V3:
            harness = source_manifest["value"]["qualification_harness"]
            pressure_validator = exact(harness["pressure_validator"], {"path", "sha256"}, "SourceV5 pressure validator pin")
            require(recipe["external_pressure_proof"]["validator_sha256"] == pressure_validator["sha256"], "pressure proof validator differs from SourceV5 harness pin")
        pressure_ok, _ = _verify_pressure_proof(
            recipe, tuple(production["start_monotonic_ns"]), drain,
            offline_replayed_proof=offline_replayed_proof,
            allow_pressure_v2=offline_replay_context is not None,
            artifact_view=pressure_view,
        )
        if recipe["schema"] == EXPECTATION_SCHEMA_V3:
            soak_binding = _verify_soak_final_binding_v3(
                recipe, source_manifest, manifest, artifact_view=soak_view,
            )
            runtime_ok = soak_binding["validated"]
            runtime_sha = soak_binding["raw_sha256"]
            soak_readback_sha = soak_binding["readback_raw_sha256"]
            soak_qualification_eligible = soak_binding["qualification_eligible"]
            soak_mode = soak_binding["mode"]
            release_complete = runtime_ok
        else:
            runtime_ok, runtime_sha, release_complete = _verify_runtime_binding(
                recipe, event_info["final_state"], model.sample_count,
                artifact_view=runtime_view,
            )
    source_value = source_manifest["value"]
    if recipe["schema"] in (EXPECTATION_SCHEMA_V3, EXPECTATION_SCHEMA_V4, EXPECTATION_SCHEMA_V5, EXPECTATION_SCHEMA_V6):
        feedback_record = _source_v5_regular_record(
            source_value.get("source"),
            "scripts/application-feedback-readback.py",
            "feedback validator",
        )
        final_reader_raw = _capture_source_v5_sibling(
            "scripts/application-feedback-readback.py", feedback_record, "feedback validator",
        )
        reader_sha = sha256_bytes(final_reader_raw)
    else:
        _, reader_sha = read_stable(Path(__file__).resolve(), "feedback readback validator", 4 * 1024 * 1024)
    result = {
        "schema": READBACK_SCHEMA_V2 if recipe["schema"] == EXPECTATION_SCHEMA_V3 else READBACK_SCHEMA,
        "mode": recipe["mode"],
        "validated": True,
        "qualification_eligible": bool(
            (
                recipe["schema"] == EXPECTATION_SCHEMA_V2
                and recipe["mode"] == "pressure_validation"
                and pressure_ok and runtime_ok and release_complete
            )
            or (
                recipe["schema"] == EXPECTATION_SCHEMA_V3
                and recipe["mode"] == "pressure_soak_validation"
                and pressure_ok and runtime_ok and release_complete and soak_qualification_eligible
            )
        ),
        "expectation_raw_sha256": expectation_raw_sha,
        "validator_sha256": reader_sha,
        "identity": dict(recipe["identity"]),
        "raw_artifact_sha256": {"manifest": manifest_sha, "events": events_sha, "samples": samples_sha},
        "production_window": production,
        "final_runtime_binding": (
            {
                "raw_sha256": runtime_sha,
                "readback_raw_sha256": soak_readback_sha,
                "validated": runtime_ok,
                "qualification_eligible": soak_qualification_eligible,
                "mode": soak_mode,
            }
            if recipe["schema"] == EXPECTATION_SCHEMA_V3 else
            {"raw_sha256": runtime_sha, "validated": runtime_ok}
        ),
    }
    require(set(result) == {
        "schema", "mode", "validated", "qualification_eligible", "expectation_raw_sha256",
        "validator_sha256", "identity", "raw_artifact_sha256", "production_window",
        "final_runtime_binding",
    }, "feedback validation receipt has an unstable key set")
    return result




def _preflight_feedback_nested_json_paths(
    documents: list[dict[str, Any]], context: dict[str, Any],
) -> None:
    """Close nested original JSON path references before captured code runs."""
    pending = list(documents)
    seen: set[str] = set()
    while pending:
        document = pending.pop()
        paths = _absolute_json_paths(document)
        _require_offline_paths(context, paths, "nested feedback/pressure evidence")
        for raw_path in paths:
            if not raw_path.endswith(".json") or raw_path in seen:
                continue
            seen.add(raw_path)
            _require_offline_files(context, {raw_path}, "nested JSON evidence")
            nested, _raw_sha = read_canonical(
                Path(raw_path), "preflighted nested feedback/pressure JSON",
                MAX_OFFLINE_NESTED_JSON_BYTES,
            )
            pending.append(nested)
            require(len(seen) <= MAX_OFFLINE_PATH_MAP_ENTRIES,
                    "nested feedback/pressure JSON path closure exceeds its finite bound")


def _verify_pressure_pair_replay_request(
    value: object, expectation_source_pin: dict[str, Any], source_manifest: dict[str, Any],
    context: dict[str, Any],
) -> dict[str, Any]:
    request = exact(value, {
        "schema", "source_manifest", "source_root", "pair", "module_pins",
    }, "offline feedback pressure-pair replay request")
    require(request["schema"] == PRESSURE_PAIR_REPLAY_REQUEST_SCHEMA,
            "unsupported offline feedback pressure-pair request schema")
    source_pin = exact(request["source_manifest"], {
        "path", "raw_sha256", "semantic_sha256", "source_tree_sha256",
    }, "offline feedback pressure request SourceV5 pin")
    require(source_pin["path"] == expectation_source_pin["path"] and
            source_pin["raw_sha256"] == expectation_source_pin["raw_sha256"] and
            source_pin["semantic_sha256"] == source_manifest["manifest_sha256"] and
            source_pin["source_tree_sha256"] == source_manifest["source"]["source_tree_sha256"],
            "offline feedback pressure request changed the original SourceV5 raw/semantic/tree roles")
    for key in ("raw_sha256", "semantic_sha256", "source_tree_sha256"):
        digest(source_pin[key], f"offline feedback pressure SourceV5 {key}")
    source_root = absolute_path(request["source_root"], "offline feedback pressure SourceV5 root")
    require(str(source_root) == str(Path(__file__).resolve().parent.parent),
            "offline feedback pressure replay requires the original identity-mapped SourceV5 root")
    _require_offline_directories(context, {str(source_root)}, "SourceV5 pressure replay root")
    pair = exact(request["pair"], {
        "recipe", "output_root", "readback", "host_verification",
    }, "offline feedback pressure-pair artifact set")
    recipe_pin = exact(pair["recipe"], {"path", "raw_sha256"},
                       "offline feedback pressure-pair recipe pin")
    readback_pin = exact(pair["readback"], {"path", "raw_sha256"},
                         "offline feedback pressure-pair readback pin")
    host_pin = exact(pair["host_verification"], {
        "path", "raw_sha256", "receipt_sha256",
    }, "offline feedback pressure-pair host receipt pin")
    for label, pin in (("recipe", recipe_pin), ("readback", readback_pin),
                       ("host receipt", host_pin)):
        absolute_path(pin["path"], f"offline feedback pressure-pair {label} path")
        digest(pin["raw_sha256"], f"offline feedback pressure-pair {label} raw SHA-256")
    digest(host_pin["receipt_sha256"], "offline feedback pressure-pair host receipt semantic SHA-256")
    output_root = absolute_path(pair["output_root"], "offline feedback pressure-pair output root")
    module_pins = exact(request["module_pins"], {
        "pressure_pair", "pressure_readback", "campaign_chronology",
    }, "offline feedback pressure replay module pins")
    module_paths = {
        "pressure_pair": "scripts/application-pressure-pair.py",
        "pressure_readback": "scripts/application-pressure-readback.py",
        "campaign_chronology": "scripts/application-campaign-chronology.py",
    }
    for name, relative in module_paths.items():
        pin = exact(module_pins[name], {"path", "raw_sha256"},
                    f"offline feedback {name} SourceV5 pin")
        require(pin["path"] == relative,
                f"offline feedback {name} path differs from the captured SourceV5 contract")
        digest(pin["raw_sha256"], f"offline feedback {name} raw SHA-256")
        record = _source_v5_regular_record(source_manifest["source"], relative, name)
        require(pin["raw_sha256"] == record["sha256"],
                f"offline feedback {name} bytes differ from the SourceV5 typed inventory")
        module_path = str(source_root.joinpath(*PurePosixPath(relative).parts))
        _require_offline_files(context, {module_path}, f"captured {name} module")
    _require_offline_files(context, {
        recipe_pin["path"], readback_pin["path"], host_pin["path"],
    }, "pressure-pair top-level artifact")
    _require_offline_directories(context, {str(output_root)}, "pressure-pair output root")
    require(readback_pin["path"] == str(output_root / "pressure-pair-readback.json"),
            "offline feedback pressure-pair readback differs from its original output layout")
    recipe, _recipe_raw_sha = read_canonical(
        Path(recipe_pin["path"]), "offline feedback pressure-pair recipe", 16 * 1024 * 1024,
        recipe_pin["raw_sha256"],
    )
    sidecar, _sidecar_raw_sha = read_canonical(
        Path(readback_pin["path"]), "offline feedback pressure-pair readback", 16 * 1024 * 1024,
        readback_pin["raw_sha256"],
    )
    host_receipt, _host_raw_sha = read_canonical(
        Path(host_pin["path"]), "offline feedback pressure-pair host receipt", 16 * 1024 * 1024,
        host_pin["raw_sha256"],
    )
    _preflight_feedback_nested_json_paths(
        [recipe, sidecar, host_receipt], context,
    )
    source_records = source_manifest["source"]["files"]
    for index, record_value in enumerate(source_records):
        record = exact(record_value, {"path", "kind", "mode", "sha256", "size"},
                       f"offline pressure SourceV5 inventory[{index}]")
        relative = PurePosixPath(text(record["path"], "offline pressure source member path", 4096))
        require(not relative.is_absolute() and ".." not in relative.parts and
                relative.as_posix() == record["path"] and record["kind"] == "file" and
                record["mode"] in ("100644", "100755"),
                "offline pressure SourceV5 typed inventory entry is malformed")
        exact_path = str(source_root.joinpath(*relative.parts))
        _require_offline_files(context, {exact_path}, "SourceV5 typed source member")
    for artifact in source_manifest["artifacts"].values():
        artifact_value = exact(artifact, {"path", "sha256"}, "offline pressure SourceV5 artifact")
        relative = PurePosixPath(text(artifact_value["path"], "offline pressure APP artifact path", 4096))
        require(not relative.is_absolute() and ".." not in relative.parts and
                relative.as_posix() == artifact_value["path"],
                "offline pressure SourceV5 APP artifact path is malformed")
        _require_offline_files(context, {
            str(source_root.joinpath(*relative.parts)),
        }, "SourceV5 APP artifact")
    return {
        "source_manifest": source_pin,
        "source_root": str(source_root),
        "pair": {
            "recipe": recipe_pin, "output_root": str(output_root),
            "readback": readback_pin, "host_verification": host_pin,
        },
        "module_pins": module_pins,
        "recipe_value": recipe,
        "sidecar_value": sidecar,
        "host_receipt_value": host_receipt,
    }


def verify_feedback_offline(
    expectation_path: Path,
    expected_expectation_sha256: str,
    trace_directory: Path,
    expected_artifact_sha256: dict[str, str],
    *, replay_context: object,
    pressure_replay_request: object | None = None,
) -> dict[str, Any]:
    """Replay peer feedback and its Source5 pressure pair without launching workloads.

    A full result is returned only after the exact SourceV5-captured pressure
    pair reader has independently replayed the original pair and its chronology
    dependency. Missing that adapter remains a hard error, never a partial pass.
    """
    context = _validate_feedback_offline_context(replay_context)
    expected_path = absolute_path(str(expectation_path), "offline feedback expectation path")
    trace_root = absolute_path(str(trace_directory), "offline feedback trace directory")
    trace_paths = {str(trace_root / name) for name in TRACE_FILES}
    _require_offline_paths(context, {
        str(expected_path), str(trace_root), *trace_paths,
        context["probe_capture_pin"]["path"],
        *(context["capacity_bundle"][name]["path"] for name in context["capacity_bundle"]),
    }, "offline feedback top-level evidence")
    _require_offline_files(context, {str(expected_path)}, "offline feedback expectation")
    _require_offline_directories(context, {str(trace_root)}, "offline feedback trace directory")
    _require_offline_files(context, trace_paths, "offline feedback trace artifact")
    expectation, expectation_sha = read_canonical(
        expected_path, "offline feedback expectation", MAX_EXPECTATION_BYTES,
        digest(expected_expectation_sha256, "offline expected expectation raw SHA-256"),
    )
    recipe = _validate_expectation_body({key: value for key, value in expectation.items() if key != "recipe_sha256"})
    require(expectation.get("recipe_sha256") == digest_object(recipe),
            "offline feedback expectation self digest is invalid")
    require(recipe["schema"] in (EXPECTATION_SCHEMA_V5, EXPECTATION_SCHEMA_V6),
            "offline feedback reader is scoped to SourceV5 calibrated ProbeV2 evidence")
    source_pin = exact(recipe["host_binding"], {"path", "raw_sha256"},
                       "offline feedback SourceV5 manifest pin")
    validate_calibrated_construction_probe_v2_offline(
        recipe["construction_probe"], source_pin, recipe["app_capacity_artifact"],
        recipe["identity"], replay_context=replay_context,
        expected_policy=recipe["policy"],
        capacity_floor_policy_id=recipe["policy"].get("capacity_floor_policy_id"),
    )
    require(type(expected_artifact_sha256) is dict and
            set(expected_artifact_sha256) == {"manifest", "events", "samples"},
            "offline feedback raw artifact pins have an unexpected key set")
    for key, value in expected_artifact_sha256.items():
        digest(value, f"offline feedback {key} raw SHA-256")
    proof_pin = exact(recipe["external_pressure_proof"], {
        "path", "raw_sha256", "validator_sha256", "recipe_raw_sha256",
    }, "offline external pressure receipt pin")
    _require_offline_paths(context, {proof_pin["path"]}, "offline external pressure receipt")
    _require_offline_files(context, {proof_pin["path"]}, "offline external pressure receipt")
    if pressure_replay_request is None:
        raise ValidationError(
            "offline feedback replay is blocked: a closed independent pressure-pair request is required; "
            "the captured ProbeV2 and trace pins cannot stand in for pressure replay"
        )
    source_manifest, _source_raw_sha = read_canonical(
        Path(source_pin["path"]), "offline feedback SourceV5 manifest", MAX_SOURCE_MANIFEST_BYTES,
        source_pin["raw_sha256"],
    )
    pressure_request = _verify_pressure_pair_replay_request(
        pressure_replay_request, source_pin, source_manifest, context,
    )
    pressure_pair_pin = pressure_request["module_pins"]["pressure_pair"]
    pressure_pair, pressure_pair_sha = _captured_source5_module(
        source_manifest, pressure_pair_pin["path"], "offline pressure-pair reader",
        MAX_SOURCE_MANIFEST_BYTES,
    )
    require(pressure_pair_sha == pressure_pair_pin["raw_sha256"],
            "captured pressure-pair reader differs from its closed module pin")
    pair = pressure_request["pair"]
    pressure_path_map = {
        "schema": context["evidence_path_map"]["schema"],
        "entries": [dict(entry) for entry in context["evidence_path_map"]["entries"]],
    }
    pair_result = pressure_pair.validate_pressure_pair_artifacts_offline(
        pair["recipe"], pair["output_root"], pair["readback"],
        pair["host_verification"], pressure_path_map,
    )
    require(type(pair_result) is dict and pair_result.get("validated") is True and
            pair_result.get("qualification_eligible") is False and
            pair_result.get("execution_ready") is False,
            "offline pressure-pair replay returned an incomplete or readiness-bearing result")
    member_results = pair_result.get("member_results")
    require(type(member_results) is list and len(member_results) == 2,
            "offline pressure-pair result does not retain both original member readbacks")
    matches = []
    for index, member in enumerate(member_results):
        exact(member, {"ordinal", "identity", "pressure_recipe", "proof_pin", "readback"},
              f"offline pressure-pair member result[{index}]")
        require(member["ordinal"] == index, "offline pressure-pair member result order changed")
        if member["proof_pin"]["path"] == proof_pin["path"]:
            matches.append(member)
    require(len(matches) == 1 and matches[0]["proof_pin"]["raw_sha256"] == proof_pin["raw_sha256"],
            "offline SourceV5 pressure pair does not contain the exact feedback pressure-proof bytes")
    pressure_identity = matches[0]["readback"].get("identity")
    require(type(pressure_identity) is dict and
            pressure_identity["host_id"] == recipe["identity"]["host_id"] and
            pressure_identity["run_id"] == recipe["identity"]["run_id"] and
            pressure_identity["allocator"] == recipe["identity"]["allocator"] and
            pressure_identity["executor"] == recipe["identity"]["executor"] and
            pressure_identity["nonce"] == recipe["identity"]["report_nonce"] and
            matches[0]["readback"]["application_process"]["pid"] == recipe["identity"]["process_id"],
            "offline pressure replay is bound to another SourceV5 feedback process")
    return _verify_feedback_replay(
        expected_path, expectation_sha, trace_root, expected_artifact_sha256,
        offline_replay_context=replay_context,
        offline_replayed_proof=matches[0]["readback"],
    )


def _write_exclusive(path: Path, raw: bytes) -> None:
    require(path.is_absolute() and str(path) == str(Path(str(path))), "output path must be absolute and normalized")
    try:
        require(path.parent.resolve(strict=True) == path.parent, "output parent traverses a symlink or alias")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
    except OSError as error:
        raise ValidationError(f"cannot create fresh output file: {error}") from error
    try:
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            require(written > 0, "output write made no progress")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    freeze = commands.add_parser("freeze", help="canonicalize a caller-supplied feedback expectation")
    freeze.add_argument("--spec", type=Path, required=True)
    freeze.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify", help="independently stream and validate one feedback trace")
    verify.add_argument("--expectation", type=Path, required=True)
    verify.add_argument("--expected-expectation-sha256", required=True)
    verify.add_argument("--trace-directory", type=Path, required=True)
    verify.add_argument("--expected-manifest-sha256", required=True)
    verify.add_argument("--expected-events-sha256", required=True)
    verify.add_argument("--expected-samples-sha256", required=True)
    verify.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "freeze":
            raw, raw_sha = read_stable(args.spec, "feedback expectation spec", MAX_EXPECTATION_BYTES)
            spec = parse_json(raw, "feedback expectation spec", MAX_EXPECTATION_BYTES)
            require(raw == canonical_bytes(spec), "feedback expectation spec is not canonical JSON")
            frozen, frozen_sha = build_pressure_expectation_recipe(spec)
            _write_exclusive(args.output, frozen)
            sys.stdout.buffer.write(canonical_bytes({"expectation_raw_sha256": frozen_sha, "recipe_sha256": json.loads(frozen)["recipe_sha256"]}))
            return 0
        result = verify_feedback(
            args.expectation, args.expected_expectation_sha256, args.trace_directory,
            {
                "manifest": args.expected_manifest_sha256,
                "events": args.expected_events_sha256,
                "samples": args.expected_samples_sha256,
            },
        )
        _write_exclusive(args.output, canonical_bytes(result))
        sys.stdout.buffer.write(canonical_bytes({"validated": result["validated"], "qualification_eligible": result["qualification_eligible"], "expectation_raw_sha256": result["expectation_raw_sha256"], "validator_sha256": result["validator_sha256"]}))
        return 0
    except (ValidationError, OSError, ValueError) as error:
        print(f"application-feedback-readback: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
