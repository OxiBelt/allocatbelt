#!/usr/bin/env python3
"""Source5 adapter for one original, externally supervised three-hour soak."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import stat
import threading
import time
import types
from pathlib import Path, PurePosixPath
from typing import Any


MATERIALS_SCHEMA = "allocatbelt.application-source5-soak-materials.v1"
MATERIALS_INDEX_SCHEMA = "allocatbelt.application-source5-soak-materials-index.v1"
MATERIALS_INDEX_SCHEMA_V2 = "allocatbelt.application-source5-soak-materials-index.v2"
COMPONENT_SCHEMA = "allocatbelt.application-source5-soak-component.v1"
COMPONENT_SCHEMA_V2 = "allocatbelt.application-source5-soak-component.v2"
LAUNCH_AUTHORIZATION_SCHEMA = "allocatbelt.application-source5-soak-launch-authorization.v1"
LAUNCH_AUTHORIZATION_SCHEMA_V2 = "allocatbelt.application-source5-soak-launch-authorization.v2"
LAUNCH_AUTHORIZATION_SCHEMA_V3 = "allocatbelt.application-source5-soak-launch-authorization.v3"
LAUNCH_SCHEMA_V3 = "allocatbelt.application-soak-launch.v3"
POSTFLIGHT_SCHEMA = "allocatbelt.application-source5-soak-postflight.v1"
POSTFLIGHT_SCHEMA_V2 = "allocatbelt.application-source5-soak-postflight.v2"
AUDIT_PROJECTION_SCHEMA = "allocatbelt.application-source5-soak-audit-projection.v1"
MODULE_CLOSURE_SCHEMA = "allocatbelt.application-source5-captured-module-closure.v1"
READBACK_SCHEMA = "allocatbelt.application-soak-readback.v2"
RECIPE_SCHEMA = "allocatbelt.application-soak-parent-recipe.v2"
BUILD_RECEIPT_SCHEMA = "allocatbelt.application-soak-recipe-build-receipt.v2"
HOST_VERIFICATION_SCHEMA = "allocatbelt.application-source5-soak-host-verification.v2"
HOST_VERIFICATION_SCHEMA_V3 = "allocatbelt.application-source5-soak-host-verification.v3"
PROBE_CAPTURE_SCHEMA = "allocatbelt.application-source5-soak-probe-capture.v1"
PROBE_CAPTURE_SCHEMA_V2 = "allocatbelt.application-feedback-probe-capture.v2"
SOAK_OFFLINE_CONTEXT_SCHEMA = "allocatbelt.application-source5-soak-offline-replay-context.v1"
SOAK_OFFLINE_CONTEXT_SCHEMA_V2 = "allocatbelt.application-source5-soak-offline-replay-context.v2"
SOAK_RESOURCE_BUDGET_SCHEMA = "allocatbelt.application-source5-soak-resource-budget.v2"
SOAK_RESOURCE_MONITOR_SCHEMA = "allocatbelt.application-source5-soak-resource-monitor-stream.v1"
SOAK_RESOURCE_MONITOR_ROW_SCHEMA = "allocatbelt.application-source5-soak-resource-monitor-row.v1"
SOAK_RESOURCE_MONITOR_FOOTER_SCHEMA = "allocatbelt.application-source5-soak-resource-monitor-footer.v1"
SOAK_RESOURCE_OWNER_RETURN_SCHEMA = "allocatbelt.application-source5-soak-owner-return.v1"
SOAK_BOUNDED_OFFLINE_RESULT_SCHEMA = "allocatbelt.application-source5-soak-bounded-offline-result.v1"
EVIDENCE_PATH_MAP_SCHEMA = "allocatbelt.application-pressure-evidence-path-map.v1"
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_SCRIPT_BYTES = 8 * 1024 * 1024
MAX_RECIPE_BYTES = 16 * 1024 * 1024
MAX_RECEIPT_BYTES = 32 * 1024 * 1024
MAX_EVIDENCE_ENTRIES = 250_000
MAX_RESOURCE_BUDGET_BYTES = 64 * 1024
MAX_RESOURCE_MONITOR_STREAM_BYTES = 1024 * 1024 * 1024
MAX_RESOURCE_MONITOR_ROW_BYTES = 2 * 1024 * 1024
MAX_RESOURCE_MONITOR_ROWS = 1_000_000
MAX_RESOURCE_OWNER_POLL_NS = 100_000_000
# Reserve forced samples at every preflight, ProbeV2, owner, cleanup, and
# postflight handoff in addition to the interval-derived full authorization bound.
RESOURCE_MONITOR_ENDPOINT_RESERVE_ROWS = 64
RESOURCE_MONITOR_PHASES = (
    "preflight", "probe_capture", "preflight_audit", "pressure_startup",
    "application", "pressure_cleanup", "postflight",
)
RESOURCE_BUDGET_FIELDS = {
    "schema", "binding", "layout", "schedule", "ceilings",
    "artifact_limits", "resource_budget_sha256",
}
RESOURCE_BUDGET_BINDING_FIELDS = {
    "campaign_id", "host_id", "job_sha256", "source_manifest",
    "source_tree_sha256", "parent_recipe", "build_receipt",
    "prepared_host_binding_sha256", "observed_host", "monitor_owner",
    "soak_adapter", "soak_reader",
}
RESOURCE_BUDGET_LAYOUT_FIELDS = {
    "output_root", "application_tmpdir", "pressure_scratch",
    "probe_capture_root", "probe_tmpdir", "host_receipt_path",
}
RESOURCE_BUDGET_SCHEDULE_FIELDS = {
    "production_seconds", "application_sample_interval_ms",
    "application_sample_tolerance_ns", "application_sample_count",
    "application_wall_timeout_seconds", "pressure_total_deadline_seconds",
    "authorization_effective_timeout_seconds", "probe_timeout_seconds",
    "resource_monitor_interval_ms", "resource_monitor_tolerance_ns",
}
RESOURCE_BUDGET_CEILING_FIELDS = {
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
RESOURCE_BUDGET_ARTIFACT_LIMIT_FIELDS = {
    "terminal_stream_bytes", "resource_samples_bytes",
    "application_stdout_bytes", "application_stderr_bytes",
    "application_timing_bytes", "soak_receipt_bytes",
    "launch_receipt_bytes", "launch_authorization_bytes",
    "preflight_receipt_bytes",
    "postflight_receipt_bytes", "readback_receipt_bytes",
    "source5_supervisor_bytes", "pressure_events_bytes",
    "pressure_readback_bytes", "pressure_run_receipt_bytes", "pressure_launch_bytes",
    "pressure_binding_bytes", "pressure_ready_bytes",
    "pressure_driver_stdout_bytes", "pressure_driver_stderr_bytes",
    "pressure_worker_stderr_bytes", "probe_stdout_bytes",
    "probe_stderr_bytes", "probe_owner_receipt_bytes",
    "probe_inventory_bytes", "probe_failure_bytes",
    "probe_capture_receipt_bytes", "resource_monitor_stream_bytes",
    "owner_return_receipt_bytes", "host_receipt_bytes",
    "failure_receipt_bytes", "component_receipt_bytes",
}
SOAK_PRESSURE_OUTPUT_FILES = (
    "run.json", "events.jsonl", "launch-record.json",
    "process-binding.json", "pressure-ready.json",
)
SOAK_BOUNDED_OUTPUT_FILES = (
    "soak-preflight.json", "soak-postflight.json", "soak-launch.json",
    "soak-readback.json", "source5-soak-launch-authorization.json",
    "source5-soak-postflight.json", "source5-soak-supervisor.json",
    "soak-receipt.json", "pressure-readback.json", "stdout.log",
    "stderr.log", "time.txt", "terminal-records.tsv",
    "resource-samples.tsv", "pressure-driver.stdout.log",
    "pressure-driver.stderr.log", "source5-soak-resource-monitor.jsonl",
    "source5-soak-application-owner-return.json",
    "source5-soak-pressure-owner-return.json",
    "source5-soak-component.json",
)
SOAK_BOUNDED_FAILURE_OUTPUT_FILES = ("source5-soak-failure.json",)
SOAK_BOUNDED_OUTPUT_MIN_INODES = (
    len(SOAK_BOUNDED_OUTPUT_FILES) +
    len(SOAK_BOUNDED_FAILURE_OUTPUT_FILES) +
    len(SOAK_PRESSURE_OUTPUT_FILES) + 1
)


class Source5SoakError(ValueError):
    """A pinned Source5 Soak material, launch, or offline replay is invalid."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Source5SoakError(message)


def canonical_bytes(value: object) -> bytes:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise Source5SoakError(f"value is not canonical JSON: {error}") from error
    return (encoded + "\n").encode("ascii")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def digest(value: object, label: str) -> str:
    require(type(value) is str and len(value) == 64 and
            all(character in "0123456789abcdef" for character in value),
            f"{label} is not a lowercase SHA-256 digest")
    return value


def exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == keys,
            f"{label} has an unexpected field set")
    return value


def read_stable(path: Path, label: str, maximum: int) -> tuple[bytes, str, os.stat_result]:
    require(path.is_absolute() and path.resolve(strict=True) == path,
            f"{label} path is not canonical")
    before_path = path.lstat()
    require(stat.S_ISREG(before_path.st_mode), f"{label} is not a regular nonsymlink file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
                 getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(fd)
        fingerprint = lambda item: (item.st_dev, item.st_ino, item.st_mode,
                                    item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        require(stat.S_ISREG(before.st_mode) and
                fingerprint(before) == fingerprint(before_path) and
                0 <= before.st_size <= maximum,
                f"{label} changed or exceeds its finite bound")
        chunks: list[bytes] = []
        count = 0
        while count < before.st_size:
            block = os.read(fd, min(1024 * 1024, before.st_size - count))
            require(bool(block), f"{label} was truncated while being read")
            chunks.append(block)
            count += len(block)
        after = os.fstat(fd)
        after_path = path.lstat()
        require(fingerprint(before) == fingerprint(after) == fingerprint(after_path) and
                count == before.st_size,
                f"{label} changed during its stable read")
        raw = b"".join(chunks)
        return raw, sha256(raw), before
    finally:
        os.close(fd)


def read_json(path: Path, expected_sha256: str, label: str,
              maximum: int = MAX_ARTIFACT_BYTES) -> tuple[dict[str, Any], bytes, str]:
    raw, raw_sha, _info = read_stable(path, label, maximum)
    require(raw_sha == digest(expected_sha256, f"{label} raw SHA-256"),
            f"{label} differs from its raw pin")
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise Source5SoakError(f"{label} is not bounded JSON: {error}") from error
    require(type(value) is dict and raw == canonical_bytes(value),
            f"{label} is not a canonical JSON object")
    return value, raw, raw_sha


def raw_pin(value: object, label: str) -> dict[str, str]:
    pin = exact(value, {"path", "raw_sha256"}, f"{label} raw pin")
    require(type(pin["path"]) is str and Path(pin["path"]).is_absolute(),
            f"{label} path is not absolute")
    digest(pin["raw_sha256"], f"{label} raw SHA-256")
    return {"path": pin["path"], "raw_sha256": pin["raw_sha256"]}


def resource_budget_pin(value: object, label: str = "Source5 Soak resource budget") -> dict[str, str]:
    pin = exact(value, {"path", "raw_sha256", "semantic_sha256"}, label)
    require(type(pin["path"]) is str and Path(pin["path"]).is_absolute() and
            str(Path(pin["path"])) == pin["path"] and ".." not in Path(pin["path"]).parts,
            f"{label} path is not a normalized original absolute path")
    digest(pin["raw_sha256"], f"{label} raw SHA-256")
    digest(pin["semantic_sha256"], f"{label} semantic SHA-256")
    return dict(pin)


def _resource_budget_shape(value: object) -> dict[str, Any]:
    budget = exact(value, RESOURCE_BUDGET_FIELDS, "Source5 Soak resource budget")
    require(budget["schema"] == SOAK_RESOURCE_BUDGET_SCHEMA,
            "unsupported Source5 Soak resource budget schema")
    body = {key: item for key, item in budget.items()
            if key != "resource_budget_sha256"}
    require(budget["resource_budget_sha256"] == sha256(canonical_bytes(body)),
            "Source5 Soak resource budget semantic digest differs")
    binding = exact(budget["binding"], RESOURCE_BUDGET_BINDING_FIELDS,
                    "Source5 Soak resource budget binding")
    for label in ("campaign_id", "host_id"):
        require(type(binding[label]) is str and binding[label],
                f"Source5 Soak resource budget {label} is malformed")
    for label in ("job_sha256", "source_tree_sha256",
                  "prepared_host_binding_sha256"):
        digest(binding[label], f"Source5 Soak budget {label}")
    source_pin = exact(binding["source_manifest"],
                       {"path", "raw_sha256", "semantic_sha256"},
                       "Source5 Soak budget SourceV5 manifest pin")
    parent_pin = raw_pin(binding["parent_recipe"],
                         "Source5 Soak budget parent recipe")
    build_pin = raw_pin(binding["build_receipt"],
                        "Source5 Soak budget build receipt")
    observed_pin = raw_pin(binding["observed_host"],
                           "Source5 Soak budget observed host")
    for name, pin in (("source manifest", source_pin),
                      ("parent recipe", parent_pin),
                      ("build receipt", build_pin),
                      ("observed host", observed_pin)):
        require(type(pin["path"]) is str and Path(pin["path"]).is_absolute() and
                str(Path(pin["path"])) == pin["path"] and
                ".." not in Path(pin["path"]).parts,
                f"Source5 Soak budget {name} path is malformed")
        digest(pin["raw_sha256"], f"Source5 Soak budget {name} raw SHA-256")
        if "semantic_sha256" in pin:
            digest(pin["semantic_sha256"],
                   f"Source5 Soak budget {name} semantic SHA-256")
    for name in ("monitor_owner", "soak_adapter", "soak_reader"):
        module = exact(binding[name], {"path", "raw_sha256", "mode", "size"},
                       f"Source5 Soak budget {name} SourceV5 module pin")
        require(type(module["path"]) is str and module["path"].startswith("scripts/") and
                ".." not in Path(module["path"]).parts and
                module["mode"] in {"100644", "100755"} and
                type(module["size"]) is int and 0 < module["size"] <= MAX_SCRIPT_BYTES,
                f"Source5 Soak budget {name} module path/mode/size is malformed")
        digest(module["raw_sha256"], f"Source5 Soak budget {name} module SHA-256")
    layout = exact(budget["layout"], RESOURCE_BUDGET_LAYOUT_FIELDS,
                   "Source5 Soak resource budget layout")
    for name, raw_path in layout.items():
        require(type(raw_path) is str and Path(raw_path).is_absolute() and
                str(Path(raw_path)) == raw_path and ".." not in Path(raw_path).parts,
                f"Source5 Soak resource budget {name} is not a normalized original path")
    require(layout["probe_tmpdir"] == str(Path(layout["probe_capture_root"]) / "tmp"),
            "Source5 Soak ProbeV2 TMPDIR differs from its frozen capture root")
    schedule = exact(budget["schedule"], RESOURCE_BUDGET_SCHEDULE_FIELDS,
                     "Source5 Soak resource budget schedule")
    for name, amount in schedule.items():
        require(type(amount) is int and 0 < amount <= (1 << 64) - 1,
                f"Source5 Soak resource budget {name} must be a positive u64")
    require(schedule["production_seconds"] == 10_800 and
            schedule["application_sample_interval_ms"] == 100 and
            schedule["application_sample_tolerance_ns"] == 10_000_000 and
            schedule["application_sample_count"] == 108_001 and
            1 <= schedule["resource_monitor_interval_ms"] <= 100 and
            schedule["resource_monitor_tolerance_ns"] <= 100_000_000,
            "Source5 Soak resource budget changed the APP horizon or exceeds owner polling bounds")
    require((schedule["resource_monitor_interval_ms"] * 1_000_000 +
             schedule["resource_monitor_tolerance_ns"]) <= 200_000_000,
            "Source5 Soak resource monitor gap exceeds finite cleanup/readiness polling bounds")
    ceilings = exact(budget["ceilings"], RESOURCE_BUDGET_CEILING_FIELDS,
                     "Source5 Soak resource budget ceilings")
    for name, amount in ceilings.items():
        require(type(amount) is int and 0 < amount <= (1 << 64) - 1,
                f"Source5 Soak resource budget ceiling {name} must be a positive u64")
    require(ceilings["maximum_monitor_stream_bytes"] <= MAX_RESOURCE_MONITOR_STREAM_BYTES and
            ceilings["maximum_monitor_rows"] <= MAX_RESOURCE_MONITOR_ROWS and
            ceilings["maximum_monitor_row_bytes"] <= MAX_RESOURCE_MONITOR_ROW_BYTES and
            ceilings["maximum_monitor_stream_bytes"] >= 4096 and
            ceilings["maximum_monitor_rows"] >= len(RESOURCE_MONITOR_PHASES) + 4 and
            ceilings["maximum_monitor_row_bytes"] >= 1024,
            "Source5 Soak resource monitor limits exceed the finite stream bound")
    artifact_limits = exact(budget["artifact_limits"],
                            RESOURCE_BUDGET_ARTIFACT_LIMIT_FIELDS,
                            "Source5 Soak artifact limits")
    for name, amount in artifact_limits.items():
        require(type(amount) is int and 0 < amount <= (1 << 64) - 1,
                f"Source5 Soak artifact limit {name} must be a positive u64")
    require(artifact_limits["terminal_stream_bytes"] <= 32 * 1024 * 1024 * 1024 and
            artifact_limits["resource_samples_bytes"] <= 96 * 1024 * 1024 and
            artifact_limits["pressure_events_bytes"] <= 512 * 1024 * 1024 and
            artifact_limits["probe_stdout_bytes"] <= 512 * 1024 and
            artifact_limits["probe_stderr_bytes"] <= 64 * 1024 and
            artifact_limits["probe_owner_receipt_bytes"] == 16 * 1024 * 1024 and
            artifact_limits["probe_inventory_bytes"] == 16 * 1024 * 1024 and
            artifact_limits["probe_failure_bytes"] == 64 * 1024 and
            artifact_limits["resource_monitor_stream_bytes"] <=
                ceilings["maximum_monitor_stream_bytes"] and
            artifact_limits["owner_return_receipt_bytes"] <=
                ceilings["durable_receipt_reserve_bytes"],
            "Source5 Soak artifact limits exceed their original finite owner bounds")
    return budget


def make_resource_budget_document(body_value: object) -> dict[str, Any]:
    """Seal caller-frozen prospective bounds without choosing defaults."""
    body = exact(body_value, RESOURCE_BUDGET_FIELDS - {"resource_budget_sha256"},
                 "Source5 Soak resource budget body")
    require(body["schema"] == SOAK_RESOURCE_BUDGET_SCHEMA,
            "unsupported Source5 Soak resource budget body schema")
    result = {**body, "resource_budget_sha256": sha256(canonical_bytes(body))}
    return _resource_budget_shape(result)


def _read_resource_budget_pin(value: object) -> tuple[dict[str, Any], dict[str, str]]:
    pin = resource_budget_pin(value)
    path = Path(pin["path"])
    try:
        require(path.resolve(strict=True) == path,
                "Source5 Soak resource-budget path traverses an alias")
        info = path.lstat()
    except OSError as error:
        raise Source5SoakError(
            f"Source5 Soak resource budget is unavailable: {error}",
        ) from error
    require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and
            info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600,
            "Source5 Soak resource budget must be an owned mode-0600 regular file")
    budget, _raw, actual = read_json(
        path, pin["raw_sha256"],
        "Source5 prospective Soak resource budget", MAX_RESOURCE_BUDGET_BYTES,
    )
    _resource_budget_shape(budget)
    require(actual == pin["raw_sha256"] and
            budget["resource_budget_sha256"] == pin["semantic_sha256"],
            "Source5 Soak resource-budget raw/semantic pin differs")
    return budget, pin


def _resource_budget_module_pin(
    prepared: dict[str, Any], relative: str, label: str,
) -> dict[str, Any]:
    files = prepared["source"].get("source", {}).get("files")
    require(type(files) is list,
            "Source5 resource budget has no typed source-file inventory")
    rows = [row for row in files if type(row) is dict and
            row.get("path") == relative]
    require(len(rows) == 1,
            f"Source5 resource budget source inventory omits {label}")
    row = exact(rows[0], {"path", "kind", "mode", "sha256", "size"},
                f"Source5 resource budget {label} inventory row")
    require(row["kind"] == "file" and row["mode"] in {"100644", "100755"} and
            type(row["size"]) is int and 0 < row["size"] <= MAX_SCRIPT_BYTES,
            f"Source5 resource budget {label} inventory row is malformed")
    path = Path(prepared["source_root"]) / relative
    raw, actual, info = read_stable(path, f"Source5 resource budget {label}",
                                    MAX_SCRIPT_BYTES)
    mode = f"{stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode):06o}"
    require(actual == row["sha256"] and len(raw) == row["size"] and
            mode == row["mode"],
            f"Source5 resource budget {label} differs from captured SourceV5 bytes")
    return {"path": relative, "raw_sha256": actual,
            "mode": mode, "size": len(raw)}


def _resource_monitor_worst_line_bounds(
    budget: dict[str, Any], budget_pin: dict[str, str],
) -> tuple[int, int, int]:
    layout = budget["layout"]
    maximum = (1 << 64) - 1
    names = (
        "output", "application_tmpdir", "pressure_scratch",
        "probe_capture", "probe_tmpdir",
    )
    domains = {
        name: {
            "path": layout[path_field], "device": maximum, "inode": maximum,
            "bytes_used": maximum, "inode_count": maximum,
            "available_bytes": maximum, "available_inodes": maximum,
            "bytes_limit": maximum, "inode_limit": maximum,
        }
        for name, path_field in (
            ("output", "output_root"),
            ("application_tmpdir", "application_tmpdir"),
            ("pressure_scratch", "pressure_scratch"),
            ("probe_capture", "probe_capture_root"),
            ("probe_tmpdir", "probe_tmpdir"),
        )
    }
    devices = {
        str(maximum - index): {
            "available_bytes": maximum, "available_inodes": maximum,
            "remaining_bytes": maximum, "remaining_inodes": maximum,
            "required_bytes": maximum, "required_inodes": maximum,
        }
        for index, _name in enumerate(names)
    }
    row_body = {
        "schema": SOAK_RESOURCE_MONITOR_ROW_SCHEMA,
        "sequence": maximum, "phase": "pressure_cleanup",
        "monotonic_ns": maximum, "previous_sha256": "f" * 64,
        "domains": domains, "devices": devices,
        "failure": "x" * 4096,
    }
    row_size = len(canonical_bytes({
        **row_body, "row_sha256": "f" * 64,
    }))
    header_body = {
        "schema": SOAK_RESOURCE_MONITOR_SCHEMA,
        "budget": budget_pin,
        "monitor_owner": budget["binding"]["monitor_owner"],
        "layout": layout, "schedule": budget["schedule"],
        "ceilings": budget["ceilings"],
        "started_monotonic_ns": maximum,
    }
    header_size = len(canonical_bytes({
        **header_body, "header_sha256": "f" * 64,
    }))
    footer_body = {
        "schema": SOAK_RESOURCE_MONITOR_FOOTER_SCHEMA,
        "budget": budget_pin,
        "row_count": maximum, "previous_sha256": "f" * 64,
        "prefix_sha256": "f" * 64,
        "high_water": {name: {"bytes": maximum, "inodes": maximum}
                       for name in names},
        "final_usage": {
            "domains": domains, "devices": devices,
        },
        "failure": "x" * 4096, "ended_monotonic_ns": maximum,
    }
    footer_size = len(canonical_bytes({
        **footer_body, "footer_sha256": "f" * 64,
    }))
    return max(row_size, header_size, footer_size), header_size, footer_size


def _resource_budget_metadata_bounds(
    budget: dict[str, Any], prepared: dict[str, Any], job: dict[str, Any],
    binding: dict[str, Any], recipe: dict[str, Any],
    material_index: dict[str, Any], details: dict[str, Any],
    pressure_recipe: dict[str, Any], readback: types.ModuleType,
) -> dict[str, int]:
    """Derive receipt bounds from pinned inputs, maximum paths, and inode ceilings."""
    require(type(details) is dict,
            "Source5 resource budget metadata sizing requires the original authorization")
    ceilings = budget["ceilings"]
    limits = budget["artifact_limits"]
    source_files = prepared["source"].get("source", {}).get("files")
    require(type(source_files) is list,
            "Source5 resource budget metadata sizing lacks the typed source-file inventory")
    pinned_inputs = _raw_pins_in((
        prepared["source"], prepared["source5_execution_manifest"],
        prepared["source5_prepared_input_completion"], job, binding,
        recipe, material_index, details,
    ))
    workers = readback._expected_pressure_worker_keys(
        pressure_recipe["schedule"],
    )
    worker_count = len(workers)
    max_path = "\x01" * 4096
    max_path_bytes = len(canonical_bytes(max_path))
    max_inventory_file = len(canonical_bytes({
        "path": max_path, "kind": "file", "mode": "0777",
        "size": (1 << 64) - 1, "raw_sha256": "f" * 64,
    }))
    max_inventory_directory = len(canonical_bytes({
        "path": max_path, "kind": "directory", "mode": "0777",
    }))
    max_inventory_entry = max(max_inventory_file, max_inventory_directory)
    dynamic_inode_bound = sum(ceilings[name] for name in (
        "maximum_output_inodes", "maximum_application_tmpdir_inodes",
        "maximum_pressure_scratch_inodes", "maximum_probe_output_inodes",
        "maximum_probe_tmpdir_inodes",
    ))
    inventory_entries = (
        dynamic_inode_bound + len(source_files) +
        2 * len(pinned_inputs) + 32
    )
    evidence_bases = len(source_files) + len(pinned_inputs) + 32
    require(inventory_entries <= MAX_EVIDENCE_ENTRIES and
            evidence_bases <= MAX_EVIDENCE_ENTRIES,
            "Source5 resource ceilings cannot be represented by the finite recursive inventory")

    source_bytes = len(canonical_bytes(prepared["source"]))
    manifest_bytes = len(canonical_bytes(
        prepared["source5_execution_manifest"],
    ))
    completion_bytes = len(canonical_bytes(
        prepared["source5_prepared_input_completion"],
    ))
    job_bytes = len(canonical_bytes(job))
    binding_bytes = len(canonical_bytes(binding))
    recipe_bytes = len(canonical_bytes(recipe))
    material_bytes = len(canonical_bytes(material_index))
    authorization_bytes = len(canonical_bytes(details))
    path_field_reserve = 20 * max_path_bytes
    owner_bytes = (recipe_bytes + job_bytes + authorization_bytes +
                   path_field_reserve + 16 * 1024)
    supervisor_bytes = (owner_bytes + (worker_count + 2) *
                        (max_path_bytes + 2048) + 64 * 1024)
    preflight_bytes = (source_bytes + recipe_bytes + material_bytes +
                       authorization_bytes + 64 * 1024)
    launch_authorization_bytes = (preflight_bytes + manifest_bytes +
                                  completion_bytes + 64 * 1024)
    readback_bytes = (source_bytes + recipe_bytes + job_bytes + 64 * 1024)
    component_bytes = (readback_bytes + binding_bytes +
                       path_field_reserve + 64 * 1024)
    pressure_receipt_bytes = (recipe_bytes + (worker_count + 2) *
                              (max_path_bytes + 2048) + 64 * 1024)
    postflight_bytes = (4 * max_path_bytes + 32 * 1024)
    failure_bytes = (authorization_bytes + 8 * max_path_bytes +
                     (worker_count + 2) * 1024 + 32 * 1024)
    fixed_host_bytes = (
        source_bytes + manifest_bytes + completion_bytes + job_bytes +
        binding_bytes + recipe_bytes + material_bytes + authorization_bytes +
        len(canonical_bytes(budget)) + path_field_reserve +
        limits["readback_receipt_bytes"] +
        limits["probe_capture_receipt_bytes"] +
        (worker_count + 2) * (max_path_bytes + 4096) + 128 * 1024
    )
    host_bytes = (
        fixed_host_bytes + inventory_entries * (max_inventory_entry + 1) +
        evidence_bases * (max_path_bytes + 1)
    )
    return {
        "owner_return_receipt_bytes": owner_bytes,
        "source5_supervisor_bytes": supervisor_bytes,
        "preflight_receipt_bytes": preflight_bytes,
        "launch_authorization_bytes": launch_authorization_bytes,
        "launch_receipt_bytes": owner_bytes + 32 * 1024,
        "soak_receipt_bytes": recipe_bytes + job_bytes + 64 * 1024,
        "readback_receipt_bytes": readback_bytes,
        "component_receipt_bytes": component_bytes,
        "pressure_readback_bytes": pressure_receipt_bytes,
        "pressure_run_receipt_bytes": pressure_receipt_bytes,
        "pressure_launch_bytes": pressure_receipt_bytes,
        "pressure_binding_bytes": pressure_receipt_bytes,
        "pressure_ready_bytes": pressure_receipt_bytes,
        "postflight_receipt_bytes": postflight_bytes,
        "failure_receipt_bytes": failure_bytes,
        "host_receipt_bytes": host_bytes,
    }


def _validate_resource_budget_bindings(
    budget: dict[str, Any], prepared: dict[str, Any], job: dict[str, Any],
    binding: dict[str, Any], recipe: dict[str, Any],
    material_index: dict[str, Any], *, output_root: Path | None = None,
    details: dict[str, Any] | None = None, audit: dict[str, Any] | None = None,
    readback: types.ModuleType | None = None,
) -> dict[str, Any]:
    """Rebind caller-frozen limits to the original selected SourceV5 job."""
    checked = _resource_budget_shape(budget)
    budget_file = Path(material_index["resource_budget"]["path"])
    source_root_for_budget = Path(prepared["source_root"]).resolve(strict=True)
    require(budget_file != source_root_for_budget and
            source_root_for_budget not in budget_file.parents and
            budget_file != output_root and
            (output_root is None or output_root not in budget_file.parents),
            "Source5 Soak resource budget must remain outside immutable SourceRoot and job output")
    scope = checked["binding"]
    source_ref = exact(prepared["source_manifest_raw_refs"][prepared["host_id"]], {
        "host_id", "path", "raw_sha256", "semantic_sha256",
        "source_tree_sha256",
    }, "Source5 selected SourceV5 manifest pin")
    expected_source = {key: source_ref[key] for key in
                       ("path", "raw_sha256", "semantic_sha256")}
    expected_parent = raw_pin(material_index["parent_recipe"],
                              "Source5 resource budget parent recipe")
    expected_build = raw_pin(material_index["build_receipt"],
                             "Source5 resource budget build receipt")
    expected_observed = raw_pin(binding["prepared_host_context_pin"],
                                "Source5 resource budget observed-host context")
    expected_modules = {
        "monitor_owner": _resource_budget_module_pin(
            prepared, "scripts/application-fixed-pair.py", "FixedR8 monitor owner",
        ),
        "soak_adapter": _resource_budget_module_pin(
            prepared, "scripts/application-source5-soak.py", "Source5 Soak adapter",
        ),
        "soak_reader": _resource_budget_module_pin(
            prepared, "scripts/application-soak-readback.py", "Source5 Soak reader",
        ),
    }
    require(scope["campaign_id"] == prepared["campaign_id"] ==
                job.get("campaign_id", prepared["campaign_id"]) and
            scope["host_id"] == prepared["host_id"] == job.get("host_id", prepared["host_id"]) and
            scope["job_sha256"] == sha256(canonical_bytes(job)) and
            scope["source_manifest"] == expected_source and
            scope["source_tree_sha256"] == source_ref["source_tree_sha256"] and
            scope["parent_recipe"] == expected_parent and
            scope["build_receipt"] == expected_build and
            scope["prepared_host_binding_sha256"] == binding["binding_sha256"] and
            scope["observed_host"] == expected_observed and
            all(scope[name] == pin for name, pin in expected_modules.items()),
            "Source5 Soak resource budget is not bound to the original job, source, host, recipe, or owner modules")

    layout = checked["layout"]
    pressure_pin = recipe["pressure"].get("recipe")
    require(type(pressure_pin) is dict,
            "bounded Source5 Soak requires its original pressure recipe")
    pressure_value, _pressure_raw, _pressure_sha = read_json(
        Path(pressure_pin["path"]), pressure_pin["raw_sha256"],
        "Source5 resource budget pressure recipe", MAX_RECIPE_BYTES,
    )
    original_tmpdir = pressure_value["process"]["application_tmpdir_path"]
    original_scratch = pressure_value["storage"]["pressure_scratch_path"]
    capture_parent = Path(layout["probe_capture_root"]).parent
    try:
        capture_parent_info = capture_parent.lstat()
    except OSError as error:
        raise Source5SoakError(
            f"Source5 Soak ProbeV2 capture parent is unavailable: {error}",
        ) from error
    require(layout["application_tmpdir"] == original_tmpdir and
            layout["pressure_scratch"] == original_scratch and
            stat.S_ISDIR(capture_parent_info.st_mode) and
            not stat.S_ISLNK(capture_parent_info.st_mode) and
            capture_parent_info.st_uid == os.getuid() and
            stat.S_IMODE(capture_parent_info.st_mode) == 0o700,
            "Source5 Soak budget changes original TMPDIR/scratch or probe-root parent")
    if output_root is not None:
        require(layout["output_root"] == str(output_root),
                "Source5 Soak budget output root differs from its authorized job")

    ceilings = checked["ceilings"]
    limits = checked["artifact_limits"]
    schedule = checked["schedule"]
    if readback is None:
        readback = _load_readback_module(prepared)
    pressure_request_pin = raw_pin(
        recipe["pressure"]["request_template"],
        "Source5 resource budget pressure request template",
    )
    pressure_request, _request_raw, _request_sha = read_json(
        Path(pressure_request_pin["path"]), pressure_request_pin["raw_sha256"],
        "Source5 resource budget pressure request template", MAX_ARTIFACT_BYTES,
    )
    derived = readback._derive_v5_pressure_schedule(
        recipe["runtime"]["duration_seconds"], pressure_request,
        recipe["qualification"]["pressure_condition"]["schedule"],
    )
    require(recipe["runtime"]["mode"] in {"qualified", "functional"} and
            recipe["runtime"]["duration_seconds"] ==
                schedule["production_seconds"] and
            job.get("duration_seconds") == schedule["production_seconds"] and
            recipe["runtime"]["sample_interval_ms"] ==
                schedule["application_sample_interval_ms"] and
            schedule["pressure_total_deadline_seconds"] ==
                derived["pressure_schedule"]["total_deadline_seconds"] ==
                    pressure_value["schedule"]["total_deadline_seconds"] and
            schedule["application_wall_timeout_seconds"] ==
                derived["application_wall_timeout_seconds"] and
            schedule["probe_timeout_seconds"] <= 30,
            "Source5 Soak resource budget schedule differs from the derived original owner deadlines")
    row_bound, header_bound, footer_bound = \
        _resource_monitor_worst_line_bounds(
            checked, resource_budget_pin(material_index["resource_budget"]),
        )
    interval_ns = schedule["resource_monitor_interval_ms"] * 1_000_000
    monitored_seconds = (
        schedule["authorization_effective_timeout_seconds"] +
        schedule["probe_timeout_seconds"]
    )
    derived_rows = (monitored_seconds * 1_000_000_000 + interval_ns - 1) // interval_ns
    derived_rows += RESOURCE_MONITOR_ENDPOINT_RESERVE_ROWS
    require(ceilings["maximum_monitor_row_bytes"] >= row_bound and
            ceilings["maximum_monitor_rows"] >= derived_rows and
            ceilings["maximum_monitor_stream_bytes"] >=
                header_bound + footer_bound +
                derived_rows * row_bound and
            checked["artifact_limits"]["resource_monitor_stream_bytes"] >=
                header_bound + footer_bound +
                derived_rows * row_bound,
            "Source5 Soak resource monitor stream cannot encode its full prospective horizon")
    if audit is not None:
        supervision = audit["source"]["application_supervision"]
        pressure_audit = audit["source"]["pressure_recipe"]
        require(schedule["application_wall_timeout_seconds"] ==
                    supervision["application_wall_timeout_seconds"] and
                schedule["pressure_total_deadline_seconds"] ==
                    pressure_audit["pressure_schedule"]["total_deadline_seconds"],
                "Source5 Soak budget differs from the captured reader's complete derived schedule")
    if details is not None:
        require(schedule["authorization_effective_timeout_seconds"] ==
                    details["effective_timeout_seconds"],
                "Source5 Soak resource budget differs from the authorized outer deadline")

    mandatory_output = sum(limits[name] for name in (
        "terminal_stream_bytes", "resource_samples_bytes",
        "application_stdout_bytes", "application_stderr_bytes",
        "application_timing_bytes", "soak_receipt_bytes", "launch_receipt_bytes",
        "launch_authorization_bytes",
        "preflight_receipt_bytes", "postflight_receipt_bytes",
        "readback_receipt_bytes", "source5_supervisor_bytes",
        "pressure_readback_bytes", "pressure_events_bytes",
        "pressure_run_receipt_bytes",
        "pressure_launch_bytes", "pressure_binding_bytes", "pressure_ready_bytes",
        "pressure_driver_stdout_bytes", "pressure_driver_stderr_bytes",
        "resource_monitor_stream_bytes", "failure_receipt_bytes",
        "component_receipt_bytes",
    )) + limits["postflight_receipt_bytes"] + \
        2 * limits["owner_return_receipt_bytes"]
    mandatory_probe = sum(limits[name] for name in (
        "probe_stdout_bytes", "probe_stderr_bytes", "probe_owner_receipt_bytes",
        "probe_inventory_bytes", "probe_capture_receipt_bytes",
        "probe_failure_bytes",
    ))
    metadata_bounds = _resource_budget_metadata_bounds(
        checked, prepared, job, binding, recipe, material_index,
        details, pressure_value, readback,
    )
    reader_receipt_cap = getattr(readback, "MAX_RECEIPT_BYTES", None)
    require(type(reader_receipt_cap) is int and reader_receipt_cap > 0 and
            limits["terminal_stream_bytes"] ==
                recipe["runtime"]["terminal_budget_bytes"] and
            limits["resource_samples_bytes"] ==
                recipe["runtime"]["sample_budget_bytes"] and
            all(limits[name] <= reader_receipt_cap for name in (
                "soak_receipt_bytes", "launch_receipt_bytes",
                "preflight_receipt_bytes", "readback_receipt_bytes",
                "pressure_run_receipt_bytes", "pressure_launch_bytes",
                "pressure_binding_bytes", "pressure_ready_bytes",
            )) and
            limits["source5_supervisor_bytes"] <= MAX_RECEIPT_BYTES and
            limits["postflight_receipt_bytes"] <= MAX_RECEIPT_BYTES and
            limits["launch_authorization_bytes"] <= MAX_RECEIPT_BYTES and
            limits["owner_return_receipt_bytes"] <= MAX_RECEIPT_BYTES and
            limits["host_receipt_bytes"] <= MAX_RECEIPT_BYTES and
            limits["failure_receipt_bytes"] <= MAX_RECEIPT_BYTES and
            limits["component_receipt_bytes"] <= MAX_RECEIPT_BYTES and
            ceilings["maximum_output_bytes"] >= mandatory_output and
            ceilings["maximum_probe_output_bytes"] >= mandatory_probe and
            ceilings["maximum_application_tmpdir_bytes"] <= 1024 * 1024 * 1024 and
            ceilings["maximum_application_tmpdir_inodes"] <= 4096 and
            ceilings["maximum_probe_tmpdir_bytes"] <= 1024 * 1024 * 1024 and
            ceilings["maximum_probe_tmpdir_inodes"] <= 4096 and
            ceilings["maximum_output_inodes"] >=
                SOAK_BOUNDED_OUTPUT_MIN_INODES and
            ceilings["maximum_probe_output_inodes"] >= 7 and
            ceilings["durable_receipt_reserve_bytes"] >=
                limits["host_receipt_bytes"] and
            ceilings["durable_receipt_reserve_inodes"] >= 1,
            "Source5 Soak budget does not reserve complete bounded outputs and durable metadata")
    require(all(limits[name] >= minimum
                for name, minimum in metadata_bounds.items()) and
            limits["failure_receipt_bytes"] >=
                metadata_bounds["failure_receipt_bytes"],
            "Source5 Soak receipt limits cannot encode their maximum-width pinned metadata")
    return checked


def soak_descriptor(job: dict[str, Any]) -> dict[str, str]:
    """Return the single original Soak APP role, without pair semantics."""
    require(job.get("phase") == "soak" and
            type(job.get("run_id")) is str and
            type(job.get("allocator")) is str and
            type(job.get("executor")) is str,
            "Source5 original Soak job lacks its closed single-APP identity")
    return {
        "role": "original_soak_app",
        "allocator": job["allocator"],
        "executor": job["executor"],
    }


def _load_readback_module(prepared: dict[str, Any]) -> types.ModuleType:
    relative = "scripts/application-soak-readback.py"
    source = prepared["source"]
    files = source.get("source", {}).get("files")
    require(type(files) is list,
            "Source5 Soak source has no typed regular-file inventory")
    matches = [item for item in files if type(item) is dict and
               item.get("path") == relative]
    require(len(matches) == 1,
            "Source5 Soak source inventory omits its captured V2 readback")
    entry = exact(matches[0], {"path", "kind", "mode", "sha256", "size"},
                  "captured V2 readback inventory entry")
    require(entry["kind"] == "file" and entry["mode"] in {"100644", "100755"} and
            type(entry["size"]) is int and 0 <= entry["size"] <= MAX_SCRIPT_BYTES and
            type(entry["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is not None,
            "captured V2 readback inventory entry is malformed")
    path = Path(prepared["source_root"]) / relative
    raw, actual, info = read_stable(path, "captured Soak V2 readback source",
                                    MAX_SCRIPT_BYTES)
    mode = f"{stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode):06o}"
    require(actual == entry["sha256"] and len(raw) == entry["size"] and
            mode == entry["mode"],
            "captured Soak V2 readback changed from its selected source inventory")
    module = types.ModuleType(f"source5_soak_readback_{actual}")
    module.__file__ = str(path)
    module.__package__ = ""
    try:
        exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    except (SyntaxError, TypeError, ValueError) as error:
        raise Source5SoakError(f"captured Soak V2 readback cannot be loaded: {error}") from error
    return module


def make_material_index(
    campaign_id: str, host_id: str, job: dict[str, Any],
    parent_recipe_pin: object, build_receipt_pin: object,
    prepared_host_binding_sha256: str,
    *, resource_budget_pin: object | None = None,
) -> dict[str, Any]:
    """Make the v1 index unchanged or add a prospectively pinned bounded v2."""
    recipe_pin = raw_pin(parent_recipe_pin, "Source5 parent Soak recipe")
    receipt_pin = raw_pin(build_receipt_pin, "Source5 Soak recipe-build receipt")
    digest(prepared_host_binding_sha256, "prepared fixed-pair host-binding SHA-256")
    body = {
        "schema": (MATERIALS_INDEX_SCHEMA if resource_budget_pin is None
                   else MATERIALS_INDEX_SCHEMA_V2),
        "campaign_id": campaign_id,
        "host_id": host_id,
        "job": job,
        "job_sha256": sha256(canonical_bytes(job)),
        "parent_recipe": recipe_pin,
        "build_receipt": receipt_pin,
        "prepared_host_binding_sha256": prepared_host_binding_sha256,
    }
    if resource_budget_pin is not None:
        _budget, budget_pin = _read_resource_budget_pin(resource_budget_pin)
        body["resource_budget"] = budget_pin
    return {**body, "materials_sha256": sha256(canonical_bytes(body))}


def validate_material_index(
    value: object, campaign_id: str, host_id: str, job: dict[str, Any],
    prepared_host_binding_sha256: str,
) -> dict[str, Any]:
    """Validate the complete closed ordinal/material binding before preflight."""
    require(type(value) is dict,
            "Source5 Soak materials index must be an object")
    schema = value.get("schema")
    expected_fields = {
        "schema", "campaign_id", "host_id", "job", "job_sha256",
        "parent_recipe", "build_receipt", "prepared_host_binding_sha256",
        "materials_sha256",
    }
    if schema == MATERIALS_INDEX_SCHEMA_V2:
        expected_fields.add("resource_budget")
    index = exact(value, expected_fields, "Source5 Soak materials index")
    body = {key: item for key, item in index.items()
            if key != "materials_sha256"}
    digest(prepared_host_binding_sha256,
           "prepared fixed-pair host-binding SHA-256")
    require(index["schema"] in {MATERIALS_INDEX_SCHEMA,
                                MATERIALS_INDEX_SCHEMA_V2} and
            index["campaign_id"] == campaign_id and
            index["host_id"] == host_id and index["job"] == job and
            index["job_sha256"] == sha256(canonical_bytes(job)) and
            index["prepared_host_binding_sha256"] == prepared_host_binding_sha256 and
            index["materials_sha256"] == sha256(canonical_bytes(body)),
            "Source5 Soak materials index does not bind its exact original host/job/preparation")
    raw_pin(index["parent_recipe"], "Source5 parent Soak recipe")
    raw_pin(index["build_receipt"], "Source5 Soak recipe-build receipt")
    if schema == MATERIALS_INDEX_SCHEMA_V2:
        _read_resource_budget_pin(index["resource_budget"])
    return index


def normalize_cleanup_status(cleanup: object) -> tuple[int, int | None]:
    """Keep a raw negative subprocess code while deriving chronology's 0..255 status."""
    value = exact(cleanup, {
        "schema", "status", "pid", "return_code", "received_signal", "cleanup_error",
    }, "captured APP cleanup callback")
    require(value["schema"] == "allocatbelt.application-soak-process-cleanup.v1" and
            value["status"] in {"verified", "failed"} and
            type(value["pid"]) is int and value["pid"] > 0,
            "captured APP cleanup callback identity/status is malformed")
    raw_return = value["return_code"]
    signal_number = value["received_signal"]
    require(raw_return is None or (type(raw_return) is int and -255 <= raw_return <= 255),
            "captured APP cleanup callback raw return code is malformed")
    require(signal_number is None or
            (type(signal_number) is int and 1 <= signal_number <= 127),
            "captured APP cleanup callback signal is malformed")
    if type(raw_return) is int and raw_return < 0:
        require(signal_number is None or signal_number == -raw_return,
                "captured APP cleanup signal contradicts its raw negative return code")
        signal_number = -raw_return
        return 128 + signal_number, signal_number
    if raw_return is None:
        require(signal_number is None,
                "captured APP cleanup has a signal without a raw child status")
        return 125, None
    require(signal_number is None,
            "captured APP cleanup has a positive child status and contradictory signal")
    return raw_return, None


def _selected_prepared_host_binding(
    completion: dict[str, Any], host_id: str,
) -> dict[str, Any]:
    require(completion.get("schema") in {
        "allocatbelt.application-source5-preparation-completion.v1",
        "allocatbelt.application-source5-preparation-completion.v2",
    }, "prepared-input completion is not a closed V1/V2 generation")
    pilots = completion.get("pilots")
    require(type(pilots) is list and len(pilots) == 3,
            "prepared-input completion does not preserve all three host bindings")
    matches = [item for item in pilots if type(item) is dict and item.get("host_id") == host_id]
    require(len(matches) == 1,
            "prepared-input completion has no unique selected-host fixed binding")
    binding = exact(matches[0].get("prepared_host_binding"), {
        "schema", "host_id", "fixed_spec_host_pin", "prepared_host_context_pin",
        "spec_host_semantic_sha256", "boot_id_sha256", "kernel_release",
        "controls_sha256", "process_affinity", "network_namespace_inode",
        "binding_sha256",
    }, "prepared dual-host binding")
    body = {key: value for key, value in binding.items() if key != "binding_sha256"}
    require(binding["schema"] ==
            "allocatbelt.application-source5-fixed-pair-host-binding.v1" and
            binding["host_id"] == host_id and
            binding["binding_sha256"] == sha256(canonical_bytes(body)),
            "prepared dual-host binding digest or host identity differs")
    if completion["schema"] == \
            "allocatbelt.application-source5-preparation-completion.v2":
        _selected_prepared_host_resource_proof(completion, host_id)
    return binding


def _selected_prepared_host_resource_proof(
    completion: dict[str, Any], host_id: str,
) -> dict[str, Any]:
    """Validate the bounded completion's additive selected-host resource proof."""
    require(completion.get("schema") ==
            "allocatbelt.application-source5-preparation-completion.v2",
            "bounded resource proof requires preparation-completion.v2")
    pilots = completion.get("pilots")
    require(type(pilots) is list and len(pilots) == 3,
            "bounded completion does not preserve the exact three-host pilot set")
    host_ids = sorted(item.get("host_id") for item in pilots
                      if type(item) is dict and type(item.get("host_id")) is str)
    require(len(host_ids) == 3 and len(set(host_ids)) == 3,
            "bounded completion does not preserve the exact three-host pilot set")
    budgets = exact(completion.get("resource_budgets"), set(host_ids),
                    "bounded completion per-host resource budget map")
    capacity_rows = completion.get("capacity_preparations")
    require(type(capacity_rows) is list and len(capacity_rows) == 3,
            "bounded completion omits a host capacity resource record")
    matches = [row for row in capacity_rows
               if type(row) is dict and row.get("host_id") == host_id]
    require(len(matches) == 1,
            "bounded completion has no unique selected-host capacity resource record")
    row = matches[0]
    exact(row, {
        "host_id", "completion", "host_verification", "evidence_path_map",
        "completion_sha256", "ledger", "capacity_preparation_templates_sha256",
        "entries", "resource_budget", "resource_monitor",
    }, "bounded completion selected-host capacity resource record")
    budget_pin = exact(row["resource_budget"], {
        "path", "raw_sha256", "semantic_sha256",
    }, "bounded completion selected-host resource budget pin")
    require(type(budget_pin["path"]) is str and Path(budget_pin["path"]).is_absolute(),
            "bounded completion selected-host resource budget path is not absolute")
    digest(budget_pin["raw_sha256"],
           "bounded completion selected-host resource budget raw SHA-256")
    digest(budget_pin["semantic_sha256"],
           "bounded completion selected-host resource budget semantic SHA-256")
    require(budgets[host_id] == budget_pin,
            "bounded completion resource budget map differs from its capacity row")
    require(type(row["entries"]) is list and len(row["entries"]) == 15,
            "bounded completion selected-host capacity row lost its original 15 entries")
    monitor = exact(row["resource_monitor"], {
        "schema", "fixed_pair_sha256", "report_count", "high_water",
        "final_usage",
    }, "bounded completion selected-host resource monitor")
    require(monitor["schema"] ==
            "allocatbelt.application-capacity-preparation-resource-monitor.v1" and
            type(monitor["report_count"]) is int and monitor["report_count"] == 30,
            "bounded completion selected-host monitor schema/report count differs")
    digest(monitor["fixed_pair_sha256"],
           "bounded completion selected-host fixed-pair digest")
    high_water = exact(monitor["high_water"], {
        "generation_bytes", "generation_inodes", "job_output_bytes",
        "job_output_inodes", "tmpdir_bytes", "tmpdir_inodes",
    }, "bounded completion selected-host monitor high-water values")
    require(all(type(value) is int and value >= 0 for value in high_water.values()),
            "bounded completion selected-host high-water values are malformed")
    final = exact(monitor["final_usage"], {
        "generation", "jobs", "tmpdir_bytes", "tmpdir_inodes",
        "tmpdir_by_device", "tmpdir_roots", "monitor_high_water",
        "monitor_report_count",
    }, "bounded completion selected-host final resource usage")
    generation_usage = exact(final["generation"],
                             {"bytes_used", "inode_count"},
                             "bounded completion generation final usage")
    require(all(type(value) is int and value >= 0
                for value in generation_usage.values()),
            "bounded completion generation final usage is malformed")
    require(type(final["jobs"]) is dict and len(final["jobs"]) == 15 and
            type(final["tmpdir_by_device"]) is dict and
            type(final["tmpdir_roots"]) is list and
            final["monitor_high_water"] == high_water and
            final["monitor_report_count"] == monitor["report_count"] == 30 and
            type(final["tmpdir_bytes"]) is int and final["tmpdir_bytes"] >= 0 and
            type(final["tmpdir_inodes"]) is int and final["tmpdir_inodes"] >= 0,
            "bounded completion final usage differs from its exact 15-entry/30-report schedule")
    for run_id, usage in final["jobs"].items():
        require(type(run_id) is str and run_id and type(usage) is dict,
                "bounded completion final job usage map is malformed")
        exact(usage, {"bytes_used", "inode_count"},
              "bounded completion final job usage")
        require(all(type(value) is int and value >= 0 for value in usage.values()),
                "bounded completion final job usage is malformed")
    for device, usage in final["tmpdir_by_device"].items():
        require(type(device) is str and device and type(usage) is dict,
                "bounded completion TMPDIR device usage map is malformed")
        exact(usage, {"bytes", "inodes"},
              "bounded completion TMPDIR device usage")
        require(all(type(value) is int and value >= 0 for value in usage.values()),
                "bounded completion TMPDIR device usage is malformed")
    require(all(type(root) is dict and set(root) == {"path", "device", "inode"} and
                type(root["path"]) is str and Path(root["path"]).is_absolute() and
                type(root["device"]) is int and root["device"] >= 0 and
                type(root["inode"]) is int and root["inode"] > 0
                for root in final["tmpdir_roots"]),
            "bounded completion TMPDIR root inventory is malformed")
    return {"resource_budget": budget_pin, "resource_monitor": monitor}


def _load_source5_recipe_builder(prepared: dict[str, Any]) -> types.ModuleType:
    """Load the exact SourceV5-pinned nonce generator from typed source bytes."""
    source = prepared["source"]
    harness = exact(source.get("qualification_harness"), {
        "campaign_controller", "feedback_validator", "byte_capacity_producer",
        "pressure_driver", "pressure_validator", "soak_recipe_builder",
        "soak_validator", "soak_runner",
    }, "SourceV5 recipe-builder harness")
    pin = exact(harness["soak_recipe_builder"], {"path", "sha256"},
                "SourceV5 recipe-builder source pin")
    digest(pin["sha256"], "SourceV5 recipe-builder source SHA-256")
    require(pin["path"] == "scripts/application-soak-recipe.py",
            "SourceV5 recipe-builder path differs from the closed harness role")
    matches = [item for item in source.get("source", {}).get("files", [])
               if type(item) is dict and item.get("path") == pin["path"]]
    require(len(matches) == 1,
            "SourceV5 inventory has no unique pinned recipe-builder source")
    record = exact(matches[0], {"path", "kind", "mode", "sha256", "size"},
                   "SourceV5 recipe-builder typed source record")
    source_root = Path(prepared["source_root"]).resolve(strict=True)
    path = source_root / pin["path"]
    raw, actual_sha, info = read_stable(
        path, "SourceV5 captured recipe builder", MAX_SCRIPT_BYTES,
    )
    mode = f"{stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode):06o}"
    require(record["kind"] == "file" and record["mode"] in {"100644", "100755"} and
            record["sha256"] == pin["sha256"] == actual_sha and
            record["size"] == len(raw) and record["mode"] == mode,
            "SourceV5 recipe builder differs from its pinned regular-file inventory")
    module = types.ModuleType(f"source5_soak_recipe_builder_{actual_sha}")
    module.__file__ = str(path)
    module.__package__ = ""
    try:
        exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    except (SyntaxError, TypeError, ValueError) as error:
        raise Source5SoakError(
            f"pinned SourceV5 recipe builder cannot be loaded: {error}",
        ) from error
    require(callable(getattr(module, "process_nonce", None)),
            "SourceV5 recipe builder omits the shared process nonce API")
    return module


def _verify_build_receipt(
    material_index: dict[str, Any], prepared: dict[str, Any], job: dict[str, Any],
    binding: dict[str, Any], readback: types.ModuleType,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, str]]:
    material_index = validate_material_index(
        material_index, prepared["campaign_id"], prepared["host_id"], job,
        binding["binding_sha256"],
    )
    recipe_pin = raw_pin(material_index["parent_recipe"], "Source5 parent Soak recipe")
    receipt_pin = raw_pin(material_index["build_receipt"], "Source5 recipe-build receipt")
    recipe, _recipe_raw, recipe_sha = read_json(
        Path(recipe_pin["path"]), recipe_pin["raw_sha256"],
        "Source5 parent Soak recipe", MAX_RECIPE_BYTES,
    )
    receipt, _receipt_raw, receipt_sha = read_json(
        Path(receipt_pin["path"]), receipt_pin["raw_sha256"],
        "Source5 Soak recipe-build receipt", MAX_RECEIPT_BYTES,
    )
    completion = prepared.get("source5_prepared_input_completion")
    if type(completion) is dict and completion.get("schema") == \
            "allocatbelt.application-source5-preparation-completion.v2":
        execution_manifest = prepared.get("source5_execution_manifest")
        require(type(execution_manifest) is dict and
                prepared.get("source5_execution_schema") ==
                    "allocatbelt.application-source5-campaign-execution.v2",
                "bounded Source5 Soak completion requires execution-manifest v2")
        generation = exact(execution_manifest.get("prepared_input_generation"), {
            "completion", "provenance",
        }, "bounded Source5 prepared-input generation")
        completion_pin = exact(generation["completion"], {
            "path", "raw_sha256", "semantic_sha256",
        }, "bounded Source5 completion raw/semantic pin")
        provenance = exact(generation["provenance"], {
            "schema", "preparation_pin", "final_spec_pin", "final_plan_pin",
        }, "bounded Source5 completion provenance")
        require(completion_pin["semantic_sha256"] ==
                completion.get("completion_sha256"),
                "bounded Soak completion changed its execution-manifest semantic pin")
        preparation_module, _preparation_sha, _preparation_path = \
            _load_source5_preparation_verifier(prepared)
        try:
            replayed_completion = preparation_module.verify_prepared_inputs_completion(
                completion_pin, provenance, Path(prepared["source_root"]),
                _generation_input_root(prepared),
            )
        except Exception as error:
            raise Source5SoakError(
                f"bounded Source5 Soak capacity completion replay failed: {error}",
            ) from error
        require(type(replayed_completion) is dict and
                canonical_bytes(replayed_completion) == canonical_bytes(completion),
                "bounded Source5 Soak preparation replay changed the completion bytes")
    require(recipe.get("schema") == RECIPE_SCHEMA,
            "Source5 Soak recipe is not the original V2 parent recipe")
    exact(receipt, {
        "schema", "recipe_path", "recipe_sha256", "soak_run_id",
        "context_job_run_id", "planned_pressure_soak_run_id",
        "source_manifest_semantic_sha256", "source_manifest_file_sha256",
        "source_tree_sha256", "spec_sha256", "plan_sha256", "mode",
        "duration_seconds", "execution_started", "qualification_enabled",
        "launch_enabled", "construction_probe_raw_sha256",
        "construction_probe_binary_sha256", "pressure_recipe_raw_sha256",
        "pressure_recipe_semantic_sha256", "pressure_condition_sha256",
        "capacity_evidence_ready", "feedback_runtime_composition_ready",
    }, "Source5 Soak recipe-build receipt")
    identity = exact(recipe.get("identity"), {
        "campaign_id", "host_id", "run_id", "nonce", "allocator", "executor",
        "workload", "profile", "comparison_family", "source_sha256",
        "build_sha256", "binary_sha256", "resource_ceiling_sha256",
    }, "Source5 parent recipe identity")
    nonce_material = exact(recipe.get("qualification", {}).get("nonce_instantiation"), {
        "schema", "template_nonce", "campaign_id", "job_run_id", "pair_member",
        "ordinal", "nonce",
    }, "Source5 original Soak nonce instantiation")
    require(nonce_material["schema"] ==
            "allocatbelt.application-process-nonce-instantiation.v1" and
            type(nonce_material["template_nonce"]) is str and
            re.fullmatch(r"[0-9a-f]{32}", nonce_material["template_nonce"]) is not None and
            nonce_material["campaign_id"] == prepared["campaign_id"] and
            nonce_material["job_run_id"] == job["run_id"] and
            nonce_material["pair_member"] == "soak" and
            nonce_material["ordinal"] == job["ordinal"],
            "Source5 Soak nonce scope differs from the pinned original-job template")
    recipe_builder = _load_source5_recipe_builder(prepared)
    expected_nonce = recipe_builder.process_nonce(
        nonce_material["template_nonce"], nonce_material["campaign_id"],
        nonce_material["job_run_id"], nonce_material["pair_member"],
        nonce_material["ordinal"],
    )
    require(nonce_material["nonce"] == expected_nonce == identity["nonce"],
            "Source5 Soak nonce differs from the pinned builder's original-job derivation")
    require(receipt["schema"] == BUILD_RECEIPT_SCHEMA and
            receipt["recipe_path"] == recipe_pin["path"] and
            receipt["recipe_sha256"] == recipe_sha and
            receipt["soak_run_id"] == job["run_id"] and
            receipt["context_job_run_id"] == job["run_id"] and
            receipt["planned_pressure_soak_run_id"] == job["run_id"] and
            receipt["execution_started"] is False and
            receipt["qualification_enabled"] is False and
            receipt["mode"] == recipe["runtime"]["mode"] and
            receipt["duration_seconds"] == recipe["runtime"]["duration_seconds"] and
            receipt["capacity_evidence_ready"] is
                recipe["qualification"]["capacity_evidence_ready"] and
            receipt["feedback_runtime_composition_ready"] is
                recipe["qualification"]["feedback_runtime_composition_ready"] and
            receipt["launch_enabled"] is recipe["qualification"]["launch_enabled"] and
            identity == {
                **identity,
                "campaign_id": prepared["campaign_id"],
                "host_id": prepared["host_id"],
                "run_id": job["run_id"],
                "allocator": job["allocator"],
                "executor": job["executor"],
                "workload": job["workload"],
                "profile": job["profile"],
                "comparison_family": job["comparison_family"],
            } and
            identity["nonce"] == recipe["qualification"]["nonce_instantiation"]["nonce"] and
            nonce_material["campaign_id"] == prepared["campaign_id"] and
            nonce_material["job_run_id"] == job["run_id"] and
            nonce_material["pair_member"] == "soak" and
            nonce_material["ordinal"] == job["ordinal"] and
            job["comparison_family"] == "external_pressure",
            "Source5 parent recipe-build receipt differs from the original Soak job")
    # The readback's captured recipe validator checks the nonce derivation and
    # exact V5 recipe contract before any output or Popen occurs.
    normalized_recipe, normalized_identity = readback._validate_recipe(recipe, recipe_sha)
    require(canonical_bytes(normalized_recipe) == canonical_bytes(recipe) and
            normalized_identity == identity,
            "captured V5 Soak validator normalized another recipe or identity")
    expected = prepared["prepared"]
    qualification = recipe["qualification"]
    for role in ("spec", "plan"):
        pin = exact(qualification[role], {
            "path", "raw_sha256", "semantic_sha256",
        }, f"Source5 parent recipe {role} provenance")
        require(pin["path"] == str(expected[f"{role}_path"]) and
                pin["raw_sha256"] == expected[f"{role}_raw_sha256"] and
                pin["semantic_sha256"] == expected[f"{role}_semantic_sha256"],
                f"Source5 parent recipe {role} differs from the immutable original")
    source_refs = prepared["source_manifest_raw_refs"]
    selected_source_ref = source_refs[prepared["host_id"]]
    selected_source_ref = exact(selected_source_ref, {
        "host_id", "path", "raw_sha256", "semantic_sha256",
        "source_tree_sha256",
    }, "Source5 selected source-manifest raw/semantic pin")
    require(selected_source_ref["host_id"] == prepared["host_id"] and
            recipe["source"]["manifest_path"] == selected_source_ref["path"] and
            recipe["source"]["manifest_sha256"] == selected_source_ref["raw_sha256"] and
            receipt["source_manifest_file_sha256"] == selected_source_ref["raw_sha256"] and
            receipt["source_manifest_semantic_sha256"] ==
                selected_source_ref["semantic_sha256"] ==
                    prepared["source"]["manifest_sha256"] and
            receipt["source_tree_sha256"] ==
                selected_source_ref["source_tree_sha256"] ==
                    prepared["source"]["source"]["source_tree_sha256"],
            "Source5 parent recipe/build receipt changed the selected SourceV5 generation")
    require(receipt["spec_sha256"] == expected["spec_semantic_sha256"] and
            receipt["plan_sha256"] == expected["plan_semantic_sha256"],
            "Source5 recipe-build receipt changed the original SpecV3/PlanV3 generation")
    probe = exact(recipe["construction_probe"], {
        "path", "raw_sha256", "allocator", "binary_sha256",
    }, "Source5 original construction-probe pin")
    pressure = exact(recipe["pressure"], {
        "request_template", "recipe", "condition_sha256", "driver", "validator",
    }, "Source5 parent pressure binding")
    require(receipt["construction_probe_raw_sha256"] == probe["raw_sha256"] and
            receipt["construction_probe_binary_sha256"] == probe["binary_sha256"] and
            receipt["pressure_recipe_raw_sha256"] ==
                (None if pressure["recipe"] is None else pressure["recipe"]["raw_sha256"]) and
            receipt["pressure_recipe_semantic_sha256"] ==
                (None if pressure["recipe"] is None else pressure["recipe"]["semantic_sha256"]) and
            receipt["pressure_condition_sha256"] == pressure["condition_sha256"],
            "Source5 recipe-build receipt changed its original probe/pressure pins")
    return material_index, recipe, {
        "recipe_sha256": recipe_sha,
        "build_receipt_sha256": receipt_sha,
        "prepared_host_binding_sha256": binding["binding_sha256"],
    }


def _validate_pressure_binding_recipe_roles(
    binding_recipe_sha256: object,
    parent_recipe_pin: object,
    parent_recipe_raw_sha256: object,
    pressure_recipe_pin: object,
    pressure_recipe_info: object,
) -> dict[str, str]:
    """Keep parent raw, pressure raw, and pressure semantic recipe hashes distinct."""
    parent_pin = raw_pin(parent_recipe_pin, "Source5 parent Soak recipe")
    parent_identity_sha = digest(
        parent_recipe_raw_sha256, "Source5 parent Soak recipe raw SHA-256",
    )
    pressure_pin = exact(pressure_recipe_pin, {
        "path", "raw_sha256", "semantic_sha256",
    }, "Source5 parent pressure recipe pin")
    require(type(pressure_pin["path"]) is str and
            Path(pressure_pin["path"]).is_absolute(),
            "Source5 pressure recipe path is not absolute")
    pressure_raw_pin = digest(
        pressure_pin["raw_sha256"], "Source5 pressure recipe raw SHA-256",
    )
    pressure_semantic_pin = digest(
        pressure_pin["semantic_sha256"],
        "Source5 pressure recipe semantic SHA-256",
    )
    parent_raw, parent_actual_sha, _parent_info = read_stable(
        Path(parent_pin["path"]), "Source5 parent Soak recipe",
        MAX_RECIPE_BYTES,
    )
    pressure_raw, pressure_actual_sha, _pressure_info = read_stable(
        Path(pressure_pin["path"]), "Source5 pressure recipe",
        MAX_RECIPE_BYTES,
    )
    require(parent_raw and
            parent_actual_sha == parent_pin["raw_sha256"] == parent_identity_sha and
            pressure_raw and pressure_actual_sha == pressure_raw_pin,
            "Source5 parent or pressure recipe raw bytes differ from their independent pins")
    require(type(pressure_recipe_info) is dict and
            pressure_recipe_info.get("raw_sha256") == pressure_actual_sha and
            pressure_recipe_info.get("recipe_sha256") == pressure_semantic_pin,
            "captured pressure validator raw/semantic identities differ from the parent pressure pin")
    binding_semantic_sha = digest(
        binding_recipe_sha256, "APP pressure binding recipe SHA-256",
    )
    require(binding_semantic_sha == pressure_semantic_pin,
            "APP pressure binding recipe SHA is not the pressure recipe semantic digest")
    return {
        "parent_recipe_raw_sha256": parent_actual_sha,
        "pressure_recipe_raw_sha256": pressure_actual_sha,
        "pressure_recipe_semantic_sha256": pressure_semantic_pin,
    }


def _cpu_set_for_recipe(recipe: dict[str, Any]) -> str:
    pressure_pin = recipe["pressure"]["recipe"]
    require(type(pressure_pin) is dict,
            "Source5 qualified Soak recipe has no original pressure recipe")
    pressure_path = Path(pressure_pin["path"])
    pressure, _raw, _sha = read_json(
        pressure_path, pressure_pin["raw_sha256"],
        "Source5 Soak pressure recipe", MAX_RECIPE_BYTES,
    )
    schedule = pressure.get("schedule")
    require(type(schedule) is dict and
            type(schedule.get("application_cpu_affinity")) is list and
            schedule["application_cpu_affinity"],
            "Source5 pressure schedule omitted its frozen APP affinity")
    affinity = schedule["application_cpu_affinity"]
    require(all(type(item) is int and item >= 0 for item in affinity) and
            affinity == sorted(set(affinity)),
            "Source5 pressure APP affinity is not a canonical frozen CPU list")
    return ",".join(str(item) for item in affinity)


def _readback_args(
    recipe: dict[str, Any], recipe_pin: dict[str, str], output_dir: Path,
) -> types.SimpleNamespace:
    identity = recipe["identity"]
    source_root = Path(recipe["source"]["root"]).resolve(strict=True)
    source_manifest_path = Path(recipe["source"]["manifest_path"])
    source_manifest_raw, source_manifest_sha, _info = read_stable(
        source_manifest_path, "Source5 Soak SourceV5 manifest", MAX_ARTIFACT_BYTES,
    )
    require(source_manifest_sha == recipe["source"]["manifest_sha256"],
            "Source5 Soak SourceV5 manifest changed after recipe build")
    source_manifest = json.loads(source_manifest_raw)
    soak_pin = exact(source_manifest["soak_artifacts"]["allocatbelt"],
                     {"path", "sha256"}, "Source5 timed Soak binary pin")
    binary = source_root / soak_pin["path"]
    runner = source_root / recipe["runner"]["path"]
    return types.SimpleNamespace(
        recipe=Path(recipe_pin["path"]), recipe_sha256=recipe_pin["raw_sha256"],
        campaign_id=identity["campaign_id"], host_id=identity["host_id"],
        run_id=identity["run_id"], allocator=identity["allocator"],
        executor=identity["executor"], profile=identity["profile"],
        source_sha256=identity["source_sha256"],
        binary_sha256=identity["binary_sha256"],
        resource_ceiling_sha256=identity["resource_ceiling_sha256"],
        binary=binary, mode=recipe["runtime"]["mode"],
        duration_seconds=recipe["runtime"]["duration_seconds"],
        runner_path=runner, output_dir=output_dir,
        cpu_set=_cpu_set_for_recipe(recipe),
    )


def _captured_module_projection(
    module: object, source_root: Path, inventory_entries: object,
    pin_value: object, expected_module_name: str, role: str,
) -> dict[str, Any]:
    """Bind one live captured module handle to its typed source-file bytes."""
    role_prefixes = {
        "SourceV5 campaign controller": "soak_source_v5_controller_",
        "SourceV5 pressure validator": "soak_pressure_reader_",
    }
    require(type(role) is str and role in role_prefixes and
            expected_module_name == role_prefixes[role] +
                (pin_value.get("sha256") if type(pin_value) is dict else ""),
            f"{role} module role is outside the closed capture inventory")
    pin = exact(pin_value, {"path", "sha256"}, f"{role} source pin")
    digest(pin["sha256"], f"{role} source SHA-256")
    require(type(pin["path"]) is str and "\\" not in pin["path"] and
            "\x00" not in pin["path"], f"{role} source path is malformed")
    relative = PurePosixPath(pin["path"])
    require(not relative.is_absolute() and relative.as_posix() == pin["path"] and
            all(part not in ("", ".", "..") for part in relative.parts),
            f"{role} source path is not normalized and relative")
    require(type(inventory_entries) is list,
            f"{role} source lacks its typed regular-file inventory")
    records = [item for item in inventory_entries
               if type(item) is dict and item.get("path") == pin["path"]]
    require(len(records) == 1, f"{role} has no unique typed source record")
    record = exact(records[0], {"path", "kind", "mode", "sha256", "size"},
                   f"{role} typed source record")
    require(record["kind"] == "file" and record["mode"] in {"100644", "100755"} and
            record["sha256"] == pin["sha256"] and
            type(record["size"]) is int and 0 <= record["size"] <= MAX_SCRIPT_BYTES,
            f"{role} source record differs from its closed typed pin")
    root = source_root.resolve(strict=True)
    require(root == source_root and root.is_dir(),
            f"{role} source root is not canonical")
    path = root.joinpath(*relative.parts)
    require(path.resolve(strict=True) == path,
            f"{role} source path contains a symlink or path alias")
    raw, actual_sha, info = read_stable(path, f"captured {role} module",
                                        MAX_SCRIPT_BYTES)
    mode = f"{stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode):06o}"
    require(actual_sha == pin["sha256"] == record["sha256"] and
            len(raw) == record["size"] and mode == record["mode"] and
            type(module) is types.ModuleType and
            module.__name__ == expected_module_name and
            module.__package__ == "" and
            type(module.__file__) is str and
            Path(module.__file__).resolve(strict=True) == path,
            f"{role} module handle differs from its captured typed source bytes")
    return {
        "schema": MODULE_CLOSURE_SCHEMA,
        "role": role,
        "path": pin["path"],
        "raw_sha256": actual_sha,
        "size": len(raw),
        "mode": mode,
    }


def _base_readback_audit_projection(audit: dict[str, Any]) -> dict[str, Any]:
    """Return the closed JSON view of the captured V2 audit and module roles."""
    audit = exact(audit, {
        "recipe", "recipe_sha256", "identity", "source", "ring", "mode",
        "duration_seconds", "sample_interval_ms", "execution", "source_root",
        "comparison_family", "launch_enabled", "launch_descriptor", "preflight",
    }, "captured SourceV5 base audit")
    source = exact(audit["source"], {
        "source_manifest_sha256", "source_manifest_semantic_sha256",
        "source_tree_sha256", "build_sha256", "candidate_binary_path",
        "candidate_binary_sha256", "application_binary_path",
        "application_binary_sha256", "oracle_producer_path",
        "oracle_producer_binary_sha256", "normal_application_artifacts",
        "declared_soak_artifacts", "resource_limits", "domain_ceilings",
        "scope_limits", "byte_buckets", "fixed_policy_sha256",
        "feedback_policy_sha256", "feedback_context",
        "fixed_global_control_baseline", "source_root", "source_manifest_path",
        "manifest", "controller", "controller_sha256", "source_records",
        "ring_context_binary_sha256", "pressure_recipe",
        "qualification_validation", "application_supervision",
    }, "captured SourceV5 base source audit")
    manifest = exact(source["manifest"], {
        "schema", "source", "build", "artifacts", "soak_artifacts",
        "analysis_artifact", "fixed_runtime_policy",
        "runtime_readback_validator", "resource_domain_calibration",
        "qualification_harness", "feedback_policy", "manifest_sha256",
    }, "captured SourceV5 source manifest")
    harness = exact(manifest["qualification_harness"], {
        "campaign_controller", "feedback_validator", "byte_capacity_producer",
        "pressure_driver", "pressure_validator", "soak_recipe_builder",
        "soak_validator", "soak_runner",
    }, "captured SourceV5 qualification harness")
    controller_pin = exact(
        harness["campaign_controller"],
        {"path", "sha256"}, "captured SourceV5 campaign-controller pin",
    )
    require(source["controller_sha256"] == controller_pin["sha256"],
            "captured SourceV5 controller digest differs from its harness pin")
    controller_projection = _captured_module_projection(
        source["controller"], Path(source["source_root"]),
        manifest["source"]["files"], controller_pin,
        f"soak_source_v5_controller_{controller_pin['sha256']}",
        "SourceV5 campaign controller",
    )
    qualification_validation = exact(source["qualification_validation"], {
        "capacity_evidence_ready", "feedback_runtime_composition_ready",
        "execution_ready", "full_gate_ready", "full_gate_gaps",
        "application_wall_timeout_seconds", "pressure_duration_seconds",
        "pressure_schedule", "spec_sha256", "plan_sha256",
    }, "captured SourceV5 qualification validation")
    supervision = exact(source["application_supervision"], {
        "application_wall_timeout_seconds", "pressure_duration_seconds",
        "pressure_schedule",
    }, "captured SourceV5 application supervision")
    pressure_source = source["pressure_recipe"]
    pressure_pin = audit["recipe"]["pressure"]["recipe"]
    pressure_validator_pin = exact(
        audit["recipe"]["pressure"]["validator"], {"path", "sha256"},
        "captured SourceV5 pressure-validator pin",
    )
    harness_pressure_pin = exact(
        harness["pressure_validator"],
        {"path", "sha256"}, "SourceV5 pressure-validator harness pin",
    )
    require(pressure_validator_pin == harness_pressure_pin,
            "parent pressure-validator pin differs from the typed SourceV5 harness")
    if pressure_pin is None:
        require(pressure_source is None and audit["launch_enabled"] is False,
                "SourceV5 audit has a pressure reader without a parent pressure recipe")
        pressure_projection = None
    else:
        pressure_pin = exact(pressure_pin, {
            "path", "raw_sha256", "semantic_sha256",
        }, "captured SourceV5 parent pressure recipe pin")
        pressure_source = exact(pressure_source, {
            "value", "reader", "recipe_sha256", "raw_sha256",
            "condition_sha256", "reader_sha256",
            "application_wall_timeout_seconds", "pressure_duration_seconds",
            "pressure_schedule",
        }, "captured SourceV5 pressure audit")
        require(pressure_source["raw_sha256"] == pressure_pin["raw_sha256"] and
                pressure_source["recipe_sha256"] == pressure_pin["semantic_sha256"] and
                pressure_source["reader_sha256"] == pressure_validator_pin["sha256"],
                "captured pressure reader raw/semantic/module pins differ from the parent")
        pressure_file, pressure_raw_sha, _pressure_info = read_json(
            Path(pressure_pin["path"]), pressure_pin["raw_sha256"],
            "captured SourceV5 parent pressure recipe", MAX_RECIPE_BYTES,
        )
        require(pressure_raw_sha == pressure_source["raw_sha256"] and
                pressure_file == pressure_source["value"],
                "captured pressure recipe bytes differ from its actual reader result")
        pressure_module_projection = _captured_module_projection(
            pressure_source["reader"], Path(source["source_root"]),
            manifest["source"]["files"], pressure_validator_pin,
            f"soak_pressure_reader_{pressure_validator_pin['sha256']}",
            "SourceV5 pressure validator",
        )
        pressure_projection = {
            "value": pressure_source["value"],
            "reader": pressure_module_projection,
            "recipe_sha256": pressure_source["recipe_sha256"],
            "raw_sha256": pressure_source["raw_sha256"],
            "condition_sha256": pressure_source["condition_sha256"],
            "reader_sha256": pressure_source["reader_sha256"],
            "application_wall_timeout_seconds":
                pressure_source["application_wall_timeout_seconds"],
            "pressure_duration_seconds":
                pressure_source["pressure_duration_seconds"],
            "pressure_schedule": pressure_source["pressure_schedule"],
        }
    source_projection = {
        "source_manifest_sha256": source["source_manifest_sha256"],
        "source_manifest_semantic_sha256":
            source["source_manifest_semantic_sha256"],
        "source_tree_sha256": source["source_tree_sha256"],
        "build_sha256": source["build_sha256"],
        "candidate_binary_path": source["candidate_binary_path"],
        "candidate_binary_sha256": source["candidate_binary_sha256"],
        "application_binary_path": source["application_binary_path"],
        "application_binary_sha256": source["application_binary_sha256"],
        "oracle_producer_path": source["oracle_producer_path"],
        "oracle_producer_binary_sha256":
            source["oracle_producer_binary_sha256"],
        "normal_application_artifacts": source["normal_application_artifacts"],
        "declared_soak_artifacts": source["declared_soak_artifacts"],
        "resource_limits": source["resource_limits"],
        "domain_ceilings": source["domain_ceilings"],
        "scope_limits": source["scope_limits"],
        "byte_buckets": source["byte_buckets"],
        "fixed_policy_sha256": source["fixed_policy_sha256"],
        "feedback_policy_sha256": source["feedback_policy_sha256"],
        "feedback_context": source["feedback_context"],
        "fixed_global_control_baseline":
            source["fixed_global_control_baseline"],
        "source_root": source["source_root"],
        "source_manifest_path": source["source_manifest_path"],
        "manifest": source["manifest"],
        "controller": controller_projection,
        "controller_sha256": source["controller_sha256"],
        "source_records": source["source_records"],
        "ring_context_binary_sha256": source["ring_context_binary_sha256"],
        "pressure_recipe": pressure_projection,
        "qualification_validation": qualification_validation,
        "application_supervision": supervision,
    }
    projection = {
        "schema": AUDIT_PROJECTION_SCHEMA,
        "audit": {
            "recipe": audit["recipe"],
            "recipe_sha256": audit["recipe_sha256"],
            "identity": audit["identity"],
            "source": source_projection,
            "ring": audit["ring"],
            "mode": audit["mode"],
            "duration_seconds": audit["duration_seconds"],
            "sample_interval_ms": audit["sample_interval_ms"],
            "execution": audit["execution"],
            "source_root": audit["source_root"],
            "comparison_family": audit["comparison_family"],
            "launch_enabled": audit["launch_enabled"],
            "launch_descriptor": audit["launch_descriptor"],
            "preflight": audit["preflight"],
        },
    }
    canonical_bytes(projection)
    return projection


def _base_readback_audit_sha256(audit: dict[str, Any]) -> str:
    """Digest a closed JSON view, pinning the captured live module roles."""
    return sha256(canonical_bytes(_base_readback_audit_projection(audit)))


def _copy_readback_audit_for_overlay(
    audit: dict[str, Any], preflight: dict[str, Any],
) -> dict[str, Any]:
    """Copy validated audit maps while retaining the two trusted module handles."""
    _base_readback_audit_projection(audit)
    source = dict(audit["source"])
    pressure_source = source["pressure_recipe"]
    if type(pressure_source) is dict:
        source["pressure_recipe"] = {
            "value": pressure_source["value"],
            "reader": pressure_source["reader"],
            "recipe_sha256": pressure_source["recipe_sha256"],
            "raw_sha256": pressure_source["raw_sha256"],
            "condition_sha256": pressure_source["condition_sha256"],
            "reader_sha256": pressure_source["reader_sha256"],
            "application_wall_timeout_seconds":
                pressure_source["application_wall_timeout_seconds"],
            "pressure_duration_seconds": pressure_source["pressure_duration_seconds"],
            "pressure_schedule": pressure_source["pressure_schedule"],
        }
    return {
        "recipe": audit["recipe"],
        "recipe_sha256": audit["recipe_sha256"],
        "identity": audit["identity"],
        "source": source,
        "ring": audit["ring"],
        "mode": audit["mode"],
        "duration_seconds": audit["duration_seconds"],
        "sample_interval_ms": audit["sample_interval_ms"],
        "execution": audit["execution"],
        "source_root": audit["source_root"],
        "comparison_family": audit["comparison_family"],
        "launch_enabled": audit["launch_enabled"],
        "launch_descriptor": audit["launch_descriptor"],
        "preflight": dict(preflight),
    }


def build_source5_launch_overlay(
    helper_input: dict[str, Any], prepared: dict[str, Any],
    details: dict[str, Any], material_index: dict[str, Any],
    binding: dict[str, Any], recipe: dict[str, Any], identities: dict[str, str],
    args: Any, audit: dict[str, Any], preflight: dict[str, Any],
    readback: types.ModuleType, *, path_value: str | None = None,
    source5_probe_capture: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Derive a narrow Soak-only launch descriptor from locked Source5 proofs.

    This keeps the captured SpecV3/PlanV3, recipe and original readback audit
    unchanged. The returned audit copy changes only the top-level launch
    descriptor after validating the final prepared cohort, live chronology
    prerequisite, selected job/material pins and the exact two known legacy
    capability gaps.
    """
    job = details["job"]
    helper_payload = helper_input.get("payload")
    require(type(helper_payload) is dict and
            helper_input.get("schema") ==
                "allocatbelt.application-source5-helper-input.v1" and
            helper_input.get("phase") == "soak" and
            helper_input.get("scope") == "final_frozen" and
            helper_input.get("campaign_id") == details.get("campaign_id") ==
                prepared["campaign_id"] and
            helper_input.get("host_id") == details.get("host_id") ==
                prepared["host_id"] and
            helper_input.get("job") == job and
            helper_input.get("job_sha256") == details.get("job_sha256") ==
                sha256(canonical_bytes(job)) and
            helper_input.get("job_index") == details.get("job_index") and
            helper_input.get("members") == details.get("members") and
            helper_input.get("prerequisites") == details.get("prerequisites") and
            helper_input.get("input_snapshot_sha256") ==
                details.get("input_snapshot_sha256") and
            helper_input.get("outer_deadline_seconds") ==
                details.get("outer_deadline_seconds") and
            helper_input.get("effective_timeout_seconds") ==
                details.get("effective_timeout_seconds") and
            helper_input.get("qualification_eligible") is False and
            details.get("phase") == "soak" and
            details.get("job") == job and
            details.get("members") == [soak_descriptor(job)] and
            helper_payload.get("output_root") == details.get("output_root") and
            helper_payload.get("prepared_host_binding_sha256") ==
                binding["binding_sha256"],
            "Source5 Soak overlay is outside its closed final-prepared helper authorization")
    materials_pin = raw_pin(helper_payload.get("materials_index"),
                            "Source5 overlay material index")
    require(sha256(canonical_bytes(material_index)) == materials_pin["raw_sha256"] and
            validate_material_index(
                material_index, prepared["campaign_id"], prepared["host_id"],
                job, binding["binding_sha256"],
            ) == material_index,
            "Source5 Soak overlay material index differs from the authorized raw pin")
    resource_budget = None
    resource_budget_pin_value = None
    if material_index["schema"] == MATERIALS_INDEX_SCHEMA_V2:
        resource_budget, resource_budget_pin_value = _read_resource_budget_pin(
            material_index["resource_budget"],
        )
        _validate_resource_budget_bindings(
            resource_budget, prepared, job, binding, recipe, material_index,
            output_root=Path(details["output_root"]), details=details, audit=audit,
            readback=readback,
        )
    # Validate and pin the actual captured ModuleType handles before any
    # readiness decision. A real V2 audit contains these live objects, so the
    # closed projection must be exercised before the missing-gate refusal.
    base_audit_sha = _base_readback_audit_sha256(audit)
    qualification = recipe["qualification"]
    validation = audit["source"].get("qualification_validation")
    require(type(validation) is dict and
            audit["launch_enabled"] is False and
            qualification["execution_ready"] is False and
            qualification["full_gate_ready"] is False and
            qualification["launch_enabled"] is False and
            validation.get("execution_ready") is False and
            validation.get("full_gate_ready") is False and
            audit["launch_descriptor"].get("launch_enabled") is False and
            preflight.get("launch_enabled") is False,
            "Source5 overlay requires the unchanged legacy launch readiness to remain false")
    require(validation.get("capacity_evidence_ready") is True and
            validation.get("feedback_runtime_composition_ready") is True and
            qualification["capacity_evidence_ready"] is True and
            qualification["feedback_runtime_composition_ready"] is True and
            recipe["pressure"]["recipe"] is not None and
            type(audit["source"].get("pressure_recipe")) is dict,
            "Source5 overlay lacks genuine capacity, composition, or pressure prerequisites")
    run_mode = recipe["runtime"]["mode"]
    run_duration = recipe["runtime"]["duration_seconds"]
    require(recipe["schema"] == RECIPE_SCHEMA and
            run_mode in {"qualified", "functional"} and
            ((run_mode == "qualified" and run_duration == 10_800) or
             (run_mode == "functional" and 0 < run_duration < 10_800)) and
            job["duration_seconds"] == run_duration and
            job["phase"] == "soak" and job["host_id"] == prepared["host_id"] and
            job["run_id"] == recipe["identity"]["run_id"] and
            details["phase"] == "soak" and
            details["members"] == [soak_descriptor(job)],
            "Source5 launch overlay is outside the exact original qualified or functional Soak job")
    allowed_legacy_gaps = {
        "production binary runtime-domain/policy/ceiling readback is not implemented and independently validated",
        "external-pressure pair driver/readbacks are not implemented; fixed-policy predecessor receipts cannot qualify pressure",
    }
    gaps = validation.get("full_gate_gaps")
    require(type(gaps) is list and set(gaps) == allowed_legacy_gaps and
            qualification["full_gate_gaps"] == gaps,
            "Source5 overlay encountered an unreviewed legacy readiness gap")

    completion = prepared.get("source5_prepared_input_completion")
    manifest = prepared.get("source5_execution_manifest")
    require(type(completion) is dict and type(manifest) is dict and
            completion.get("schema") in {
                "allocatbelt.application-source5-preparation-completion.v1",
                "allocatbelt.application-source5-preparation-completion.v2",
            } and
            completion.get("complete") is True and
            completion.get("qualification_eligible") is False and
            completion.get("campaign_id") == prepared["campaign_id"] and
            manifest.get("schema") ==
                "allocatbelt.application-source5-campaign-execution.v2" and
            manifest.get("scope") == "final_prepared",
            "Source5 overlay lacks the full replayed final-prepared cohort")
    capacity_resource_proof = None
    if completion["schema"] == \
            "allocatbelt.application-source5-preparation-completion.v2":
        capacity_resource_proof = _selected_prepared_host_resource_proof(
            completion, prepared["host_id"],
        )
        generation = exact(manifest.get("prepared_input_generation"), {
            "completion", "provenance",
        }, "Source5 bounded prepared-input generation")
        require(generation["completion"]["semantic_sha256"] ==
                completion["completion_sha256"],
                "Source5 bounded launch overlay changed its resource-completion generation")
    original = manifest["original_inputs"]
    spec_pin = raw_pin(original["spec"]["artifact"], "Source5 overlay SpecV3")
    plan_pin = raw_pin(original["plan"]["artifact"], "Source5 overlay PlanV3")
    require(completion["final_spec"]["path"] == spec_pin["path"] and
            completion["final_spec"]["raw_sha256"] == spec_pin["raw_sha256"] and
            completion["final_spec"]["semantic_sha256"] ==
                original["spec"]["semantic_sha256"] and
            completion["final_plan"]["path"] == plan_pin["path"] and
            completion["final_plan"]["raw_sha256"] == plan_pin["raw_sha256"] and
            completion["final_plan"]["semantic_sha256"] ==
                original["plan"]["semantic_sha256"],
            "Source5 overlay changed the exact original SpecV3/PlanV3 generation")
    selected_sources = completion["source_manifests"]
    selected_source = exact(selected_sources[prepared["host_id"]], {
        "path", "raw_sha256", "semantic_sha256", "source_tree_sha256",
    }, "Source5 overlay selected source manifest")
    live_source = exact(prepared["source_manifest_raw_refs"][prepared["host_id"]], {
        "host_id", "path", "raw_sha256", "semantic_sha256",
        "source_tree_sha256",
    }, "Source5 overlay selected source generation")
    require(selected_source == {
                "path": live_source["path"],
                "raw_sha256": live_source["raw_sha256"],
                "semantic_sha256": live_source["semantic_sha256"],
                "source_tree_sha256": live_source["source_tree_sha256"],
            } and
            set(selected_sources) == set(manifest["hosts"]),
            "Source5 overlay source generation differs from its fully replayed cohort")
    capacity_rows = [row for row in completion["capacity_preparations"]
                     if row.get("host_id") == prepared["host_id"]]
    pressure_rows = [row for row in completion["pressure_calibrations"]
                     if row.get("host_id") == prepared["host_id"] and
                     row.get("capacity_key", {}).get("workload") == "mixed" and
                     row.get("capacity_key", {}).get("profile") == job["profile"]]
    require(len(capacity_rows) == 1 and
            len(capacity_rows[0].get("entries", [])) == 15 and
            len(pressure_rows) == 1,
            "Source5 overlay lacks the selected host's complete 15-entry/pressure preparation")
    prerequisites = details["prerequisites"]
    require(type(prerequisites) is list and len(prerequisites) == 1 and
            prerequisites[0].get("phase") == "pressure_analysis" and
            type(prerequisites[0].get("event_head")) is str and
            len(prerequisites[0]["event_head"]) == 64,
            "Source5 overlay lacks its exact passing pressure-analysis chronology predecessor")
    capacity_registration = manifest["prepared_capacity_registration"]
    details_capacity = raw_pin(details["capacity_completion"],
                               "Source5 authorized prepared capacity completion")
    registered_capacity = raw_pin(
        capacity_registration["host_completion"],
        "Source5 manifest prepared host completion",
    )
    require(details["capacity_registration_head"] ==
            capacity_registration["registration_head"] and
            details_capacity == registered_capacity and
            details["capacity_ledger_raw_sha256"] ==
            capacity_registration["ledger"]["raw_sha256"] and
            details["capacity_terminal_head"] ==
            capacity_registration["ledger"]["terminal_head"] and
            details["capacity_schedule_sha256"] ==
            capacity_registration["capacity_schedule_sha256"],
            "Source5 overlay does not descend from the selected host's registered capacity head")
    require(details["execution_manifest"] ==
                prepared["source5_execution_manifest_pin"] and
            helper_input["helper"]["path"] ==
                "scripts/application-source5-soak.py" and
            helper_input["helper"]["sha256"] == details["helper_module"]["sha256"] and
            helper_input["helper"]["entrypoint"] == "run_source5_soak" and
            identities["recipe_sha256"] ==
                raw_pin(material_index["parent_recipe"], "Source5 overlay recipe")["raw_sha256"],
            "Source5 overlay helper/manifest/recipe closure differs from the one-use authorization")

    # The raw audit/preflight remains false and pinned. Only this newly derived
    # copy receives a descriptor, after all Source5 proof checks above pass.
    overlay_audit = _copy_readback_audit_for_overlay(audit, preflight)
    overlay_audit["launch_enabled"] = True
    launch_descriptor = readback._make_launch_descriptor_v2(
        overlay_audit, Path(args.output_dir), args.cpu_set, None, None,
        path_value=path_value,
    )
    if resource_budget_pin_value is not None:
        launch_descriptor["resource_budget_pin"] = resource_budget_pin_value
        launch_descriptor["resource_monitor_path"] = str(
            Path(args.output_dir) / "source5-soak-resource-monitor.jsonl",
        )
    require(launch_descriptor.get("launch_enabled") is True and
            launch_descriptor.get("execution_scope") ==
                ("qualification" if run_mode == "qualified" else
                 "functional_only") and
            bool(launch_descriptor.get("argv")) and
            launch_descriptor.get("pressure_recipe_path") ==
                recipe["pressure"]["recipe"]["path"],
            "Source5 overlay could not derive the original qualified readback launch descriptor")
    overlay_audit["launch_descriptor"] = launch_descriptor
    overlay_preflight = dict(preflight)
    overlay_audit["preflight"] = overlay_preflight
    preflight_path = Path(args.output_dir) / "soak-preflight.json"
    preflight_raw, preflight_sha, _preflight_info = read_stable(
        preflight_path, "Source5 captured-reader baseline preflight",
        MAX_RECEIPT_BYTES,
    )
    require(preflight_raw == canonical_bytes(preflight),
            "Source5 captured-reader baseline preflight differs from its frozen report")
    body = {
        "schema": (LAUNCH_AUTHORIZATION_SCHEMA_V3
                   if resource_budget is not None else
                   LAUNCH_AUTHORIZATION_SCHEMA_V2
                   if capacity_resource_proof is not None
                   else LAUNCH_AUTHORIZATION_SCHEMA),
        "campaign_id": prepared["campaign_id"],
        "host_id": prepared["host_id"],
        "run_id": job["run_id"],
        "job_sha256": sha256(canonical_bytes(job)),
        "authorization_id": details["authorization_id"],
        "execution_manifest": details["execution_manifest"],
        "helper_input": details["helper_input"],
        "helper_module": details["helper_module"],
        "materials_index": materials_pin,
        **({"resource_budget": resource_budget_pin_value}
           if resource_budget_pin_value is not None else {}),
        "parent_recipe": raw_pin(material_index["parent_recipe"],
                                  "Source5 overlay parent recipe"),
        "build_receipt": raw_pin(material_index["build_receipt"],
                                 "Source5 overlay recipe receipt"),
        "prepared_input_completion": manifest["prepared_input_generation"]["completion"],
        "prepared_input_completion_sha256": completion["completion_sha256"],
        "prepared_host_binding_sha256": binding["binding_sha256"],
        "capacity_registration_head": capacity_registration["registration_head"],
        "pressure_prerequisite": prerequisites[0],
        "spec": {"path": spec_pin["path"],
                 "raw_sha256": spec_pin["raw_sha256"],
                 "semantic_sha256": original["spec"]["semantic_sha256"]},
        "plan": {"path": plan_pin["path"],
                 "raw_sha256": plan_pin["raw_sha256"],
                 "semantic_sha256": original["plan"]["semantic_sha256"]},
        "source_manifest": selected_source,
        "base_legacy_audit_sha256": base_audit_sha,
        "base_preflight": {"path": str(preflight_path),
                           "raw_sha256": preflight_sha},
        "legacy_readiness": {
            "recipe_execution_ready": qualification["execution_ready"],
            "recipe_full_gate_ready": qualification["full_gate_ready"],
            "recipe_launch_enabled": qualification["launch_enabled"],
            "captured_audit_launch_enabled": audit["launch_enabled"],
            "captured_validation_execution_ready": validation["execution_ready"],
            "captured_validation_full_gate_ready": validation["full_gate_ready"],
            "full_gate_gaps": gaps,
        },
        "source5_gate_evidence": {
            "capacity_evidence_ready": validation["capacity_evidence_ready"],
            "feedback_runtime_composition_ready":
                validation["feedback_runtime_composition_ready"],
            "prepared_completion_complete": completion["complete"],
            "capacity_entry_count": len(capacity_rows[0]["entries"]),
            "pressure_calibration_count": len(pressure_rows),
            "source5_pressure_predecessor_event_head":
                prerequisites[0]["event_head"],
        },
        "base_audit_sha256": base_audit_sha,
        "launch_descriptor": launch_descriptor,
        "launch_descriptor_sha256": sha256(canonical_bytes(launch_descriptor)),
        "qualification_eligible": False,
    }
    if capacity_resource_proof is not None:
        body["capacity_resource_proof"] = capacity_resource_proof
        body["source5_gate_evidence"]["resource_monitor_report_count"] = \
            capacity_resource_proof["resource_monitor"]["report_count"]
        body["source5_gate_evidence"]["resource_budget_semantic_sha256"] = \
            capacity_resource_proof["resource_budget"]["semantic_sha256"]
    if resource_budget_pin_value is not None:
        body["source5_gate_evidence"]["soak_resource_budget_semantic_sha256"] = \
            resource_budget_pin_value["semantic_sha256"]
    overlay = {**body, "authorization_sha256": sha256(canonical_bytes(body))}
    return overlay, overlay_audit, overlay_preflight


def prepare_source5_soak(
    helper_input: dict[str, Any], prepared: dict[str, Any], details: dict[str, Any],
    readback: types.ModuleType | None = None,
) -> dict[str, Any]:
    """Recheck every raw input and write the captured reader's preflight before Popen."""
    payload = exact(helper_input.get("payload"), {
        "materials_index", "output_root", "prepared_host_binding_sha256",
    }, "Source5 Soak helper payload")
    index_pin = raw_pin(payload["materials_index"], "Source5 Soak materials index")
    index, _index_raw, _index_sha = read_json(
        Path(index_pin["path"]), index_pin["raw_sha256"],
        "Source5 Soak materials index", MAX_ARTIFACT_BYTES,
    )
    completion = prepared.get("source5_prepared_input_completion")
    require(type(completion) is dict,
            "Source5 Soak requires the fully replayed prepared-input completion")
    binding = _selected_prepared_host_binding(completion, prepared["host_id"])
    require(binding["binding_sha256"] == payload["prepared_host_binding_sha256"],
            "Source5 Soak helper host binding differs from its preparation completion")
    job = details["job"]
    require(job["phase"] == "soak" and len(details["members"]) == 1 and
            details["members"] == [soak_descriptor(job)],
            "Source5 Soak authorization is not the original single-APP job")
    if readback is None:
        readback = _load_readback_module(prepared)
    material_index, recipe, identities = _verify_build_receipt(
        index, prepared, job, binding, readback,
    )
    require(identities["prepared_host_binding_sha256"] ==
            payload["prepared_host_binding_sha256"],
            "Source5 Soak material index lost the verified dual-host binding")
    output_dir = Path(payload["output_root"])
    require(output_dir == Path(details["output_root"]) and
            output_dir.resolve(strict=True) == output_dir and
            stat.S_ISDIR(output_dir.stat().st_mode) and
            output_dir.stat().st_uid == os.getuid() and
            stat.S_IMODE(output_dir.stat().st_mode) == 0o700,
            "Source5 Soak output directory differs from its private authorization")
    recipe_pin = raw_pin(material_index["parent_recipe"], "Source5 parent Soak recipe")
    args = _readback_args(recipe, recipe_pin, output_dir)
    require(args.recipe_sha256 == identities["recipe_sha256"],
            "Source5 parent recipe raw pin changed before preflight")
    budget_document = None
    budget_pin = None
    probe_capture = None
    probe_capture_pin = None
    probe_capture_context = None
    initial_resource_usage = None
    resource_monitor = None
    resource_monitor_summary = None
    if material_index["schema"] == MATERIALS_INDEX_SCHEMA_V2:
        budget_document, budget_pin = _read_resource_budget_pin(
            material_index["resource_budget"],
        )
        fixed_owner, _owner_sha, _owner_path = \
            _load_fixed_pair_process_owner(prepared)
        initial_resource_usage = _preflight_source5_resource_budget(
            budget_document, output_dir, fixed_owner,
        )
        require(callable(getattr(readback, "_SoakResourceMonitor", None)),
                "captured Soak reader lacks its bounded resource monitor")
        resource_monitor = readback._SoakResourceMonitor(
            budget_document, budget_pin, fixed_owner, output_dir,
        )
        if resource_monitor.sample("preflight", force=True):
            resource_monitor.finish(resource_monitor.last_usage)
            raise Source5SoakError(
                "Source5 Soak monitor preflight refused before ProbeV2 owner",
            )
        _run_source5_preflight_monitored(
            lambda: _validate_resource_budget_bindings(
                budget_document, prepared, job, binding, recipe,
                material_index, output_root=output_dir, details=details,
                readback=readback,
            ),
            budget_document, resource_monitor, phase="preflight",
        )
        try:
            probe_capture, probe_capture_pin, probe_capture_context = \
                _capture_source5_soak_probe_monitored(
                    prepared, job, binding, recipe, readback,
                    budget_document, resource_monitor,
                )
        except BaseException as error:
            resource_monitor.failure = resource_monitor.failure or (
                f"probe_capture_owner:{type(error).__name__}:{error}"
            )[:4096]
            resource_monitor.finish(resource_monitor.last_usage)
            raise
        if resource_monitor.sample("preflight_audit", force=True):
            resource_monitor.finish(resource_monitor.last_usage)
            raise Source5SoakError(
                "Source5 Soak resource monitor refused after bounded probe capture",
            )
    # The captured reader independently rebuilds Spec/Plan/source/ring/probe/
    # pressure context and persists its preflight. This path does not launch.
    def run_captured_reader_preflight() -> tuple[dict[str, Any], dict[str, Any]]:
        with contextlib.redirect_stdout(io.StringIO()):
            status = (readback.command_preflight(args)
                      if probe_capture_context is None else
                      readback.command_preflight(
                          args, source5_probe_capture=probe_capture_context,
                      ))
        require(status == 0,
                "captured Soak V2 preflight refused the original inputs")
        return (readback._current_audit(args)
                if probe_capture_context is None else
                readback._current_audit(
                    args, source5_probe_capture=probe_capture_context,
                ))

    audit, preflight = (
        _run_source5_preflight_monitored(
            run_captured_reader_preflight, budget_document, resource_monitor,
        ) if resource_monitor is not None else
        run_captured_reader_preflight()
    )
    require(audit["recipe"]["schema"] == RECIPE_SCHEMA and
            audit["identity"]["run_id"] == job["run_id"] and
            audit["launch_enabled"] is False and
            audit["mode"] == recipe["runtime"]["mode"] and
            audit["duration_seconds"] == recipe["runtime"]["duration_seconds"] and
            (audit["mode"] != "qualified" or
             audit["duration_seconds"] == 10_800),
            "captured Soak V2 audit differs from the exact original qualified or functional job")
    preflight_path = output_dir / "soak-preflight.json"
    preflight_pin_raw, preflight_sha, _preflight_info = read_stable(
        preflight_path, "Source5 Soak preflight receipt", MAX_RECEIPT_BYTES,
    )
    require(json.loads(preflight_pin_raw) == readback._preflight_report(audit) and
            preflight_pin_raw == canonical_bytes(json.loads(preflight_pin_raw)),
            "captured Soak V2 preflight file differs from its recomputed report")
    if material_index["schema"] == MATERIALS_INDEX_SCHEMA_V2:
        _check_budget_file(
            preflight_path,
            budget_document["artifact_limits"]["preflight_receipt_bytes"],
            "Source5 Soak preflight receipt",
        )
        _run_source5_preflight_monitored(
            lambda: _validate_resource_budget_bindings(
                budget_document, prepared, job, binding, recipe, material_index,
                output_root=output_dir, details=details, audit=audit,
                readback=readback,
            ),
            budget_document, resource_monitor,
        )
    def build_overlay_value() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        return build_source5_launch_overlay(
            helper_input, prepared, details, material_index, binding, recipe,
            identities, args, audit, preflight, readback,
            source5_probe_capture=probe_capture_context,
        )
    launch_overlay, overlay_audit, overlay_preflight = (
        _run_source5_preflight_monitored(
            build_overlay_value, budget_document, resource_monitor,
        ) if resource_monitor is not None else build_overlay_value()
    )
    overlay_path = output_dir / "source5-soak-launch-authorization.json"
    if budget_document is not None:
        require(len(canonical_bytes(launch_overlay)) <=
                budget_document["artifact_limits"]["launch_authorization_bytes"],
                "Source5 Soak launch authorization exceeds its frozen metadata bound")
    launch_overlay_pin = _write_exclusive_json(
        overlay_path, launch_overlay,
        "Source5 Soak-only launch authorization overlay",
    )
    if resource_monitor is not None:
        if resource_monitor.sample("preflight_audit", force=True):
            resource_monitor.finish(resource_monitor.last_usage)
            raise Source5SoakError(
                "Source5 Soak monitor refused after source/authorization preflight",
            )
    launch_args = types.SimpleNamespace(**vars(args))
    launch_args.command = ["--", *overlay_audit["launch_descriptor"]["argv"]]
    launch_args.timeout_seconds = overlay_audit["source"]["application_supervision"][
        "application_wall_timeout_seconds"]
    launch_args.term_grace_seconds = 1.5
    preflight_result = {
        "schema": ("allocatbelt.application-source5-soak-preflight.v1"
                   if budget_document is None else
                   "allocatbelt.application-source5-soak-preflight.v2"),
        "materials_index": material_index,
        "materials_index_pin": index_pin,
        "helper_input": helper_input,
        "parent_recipe": recipe,
        "parent_recipe_pin": recipe_pin,
        "build_receipt_pin": raw_pin(material_index["build_receipt"],
                                      "Source5 Soak build receipt"),
        "identities": identities,
        "base_audit": audit,
        "base_audit_sha256": _base_readback_audit_sha256(audit),
        "audit": overlay_audit,
        "preflight": overlay_preflight,
        "preflight_pin": {"path": str(preflight_path),
                          "raw_sha256": preflight_sha},
        "launch_overlay": launch_overlay,
        "launch_overlay_pin": launch_overlay_pin,
        "args": launch_args,
        "output_dir": output_dir,
        "readback_module": readback,
        "prepared": prepared,
        "details": details,
    }
    if budget_document is not None:
        preflight_result.update({
            "resource_budget": budget_document,
            "resource_budget_pin": budget_pin,
            "probe_capture": probe_capture,
            "probe_capture_pin": probe_capture_pin,
            "probe_capture_context": probe_capture_context,
            "initial_resource_usage": initial_resource_usage,
            "resource_monitor": resource_monitor,
        })
    return preflight_result


def _write_exclusive_json(path: Path, value: dict[str, Any], label: str) -> dict[str, str]:
    raw = canonical_bytes(value)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(fd)
    finally:
        os.close(fd)
    parent_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                        getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    return {"path": str(path), "raw_sha256": sha256(raw)}


def _check_budget_file(path: Path, maximum: int, label: str) -> None:
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
            info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600 and
            0 <= info.st_size <= maximum,
            f"{label} exceeds its frozen prospective artifact limit")


def _stable_file_inventory(path: Path, label: str, maximum: int) -> dict[str, Any]:
    """Hash one regular file without retaining a Soak stream in memory."""
    require(path.is_absolute() and path.resolve(strict=True) == path,
            f"{label} path is not canonical")
    before_path = path.lstat()
    require(stat.S_ISREG(before_path.st_mode), f"{label} is not a regular file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
                 getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(fd)
        signature = lambda item: (item.st_dev, item.st_ino, item.st_mode,
                                  item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        require(stat.S_ISREG(before.st_mode) and
                signature(before) == signature(before_path) and
                0 <= before.st_size <= maximum,
                f"{label} changed or exceeds its finite byte bound")
        hasher = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            block = os.read(fd, min(1024 * 1024, remaining))
            require(bool(block), f"{label} was truncated during hashing")
            hasher.update(block)
            remaining -= len(block)
        after = os.fstat(fd)
        after_path = path.lstat()
        require(signature(before) == signature(after) == signature(after_path),
                f"{label} changed during hashing")
        return {
            "path": str(path), "kind": "file",
            "mode": f"{stat.S_IMODE(before.st_mode):04o}",
            "size": before.st_size, "raw_sha256": hasher.hexdigest(),
        }
    finally:
        os.close(fd)


def _tree_inventory(root: Path, label: str, maximum_files: int = MAX_EVIDENCE_ENTRIES) -> list[dict[str, Any]]:
    """Capture an exact no-link directory inventory for later identity replay."""
    require(root.is_absolute() and root.resolve(strict=True) == root,
            f"{label} root is not canonical")
    root_info = root.lstat()
    require(stat.S_ISDIR(root_info.st_mode), f"{label} root is not a real directory")
    entries: list[dict[str, Any]] = []
    pending = [root]
    while pending:
        current = pending.pop()
        info = current.lstat()
        require(stat.S_ISDIR(info.st_mode), f"{label} contains a non-directory traversal root")
        entries.append({
            "path": str(current), "kind": "directory",
            "mode": f"{stat.S_IMODE(info.st_mode):04o}",
        })
        try:
            children = sorted(os.scandir(current), key=lambda item: item.name)
        except OSError as error:
            raise Source5SoakError(f"cannot enumerate {label}: {error}") from error
        for child in children:
            child_path = current / child.name
            child_info = child.stat(follow_symlinks=False)
            require(not stat.S_ISLNK(child_info.st_mode),
                    f"{label} contains a symlink: {child_path}")
            if stat.S_ISDIR(child_info.st_mode):
                pending.append(child_path)
            elif stat.S_ISREG(child_info.st_mode):
                entries.append(_stable_file_inventory(
                    child_path, f"{label} file {child.name}",
                    32 * 1024 * 1024 * 1024,
                ))
            else:
                raise Source5SoakError(f"{label} contains a special file: {child_path}")
            require(len(entries) <= maximum_files,
                    f"{label} exceeds its finite typed-entry bound")
    entries.sort(key=lambda item: item["path"])
    return entries


def _raw_pins_in(value: object) -> dict[str, str]:
    found: dict[str, str] = {}
    pending = [value]
    seen: set[int] = set()
    while pending:
        item = pending.pop()
        if type(item) is dict:
            identity = id(item)
            if identity in seen:
                continue
            seen.add(identity)
            if "path" in item and "raw_sha256" in item and \
                    type(item.get("path")) is str and Path(item["path"]).is_absolute():
                pin = raw_pin({"path": item["path"],
                               "raw_sha256": item["raw_sha256"]},
                              "Source5 Soak dependency")
                prior = found.get(pin["path"])
                require(prior is None or prior == pin["raw_sha256"],
                        f"Source5 Soak dependency path has conflicting raw pins: {pin['path']}")
                found[pin["path"]] = pin["raw_sha256"]
            pending.extend(item.values())
        elif type(item) in (list, tuple):
            pending.extend(item)
    return found


def _absolute_file_sha_pins_in(value: object) -> dict[str, str]:
    """Collect closed absolute `{path, sha256}` file references (for rings)."""
    found: dict[str, str] = {}
    pending = [value]
    seen: set[int] = set()
    while pending:
        item = pending.pop()
        if type(item) is dict:
            identity = id(item)
            if identity in seen:
                continue
            seen.add(identity)
            path, checksum = item.get("path"), item.get("sha256")
            if type(path) is str and Path(path).is_absolute() and checksum is not None:
                checksum = digest(checksum, "Source5 absolute file SHA-256")
                previous = found.get(path)
                require(previous is None or previous == checksum,
                        f"Source5 absolute file reference has conflicting SHA pins: {path}")
                found[path] = checksum
            pending.extend(item.values())
        elif type(item) in (list, tuple):
            pending.extend(item)
    return found


def _nested_evidence_paths_in(value: object) -> set[str]:
    """Collect paths from already typed nested evidence maps, not directory scans."""
    found: set[str] = set()
    pending = [value]
    seen: set[int] = set()
    while pending:
        item = pending.pop()
        if type(item) is dict:
            identity = id(item)
            if identity in seen:
                continue
            seen.add(identity)
            if item.get("schema") == EVIDENCE_PATH_MAP_SCHEMA:
                mapped = _validate_evidence_path_map(item)
                found.update(mapped)
            pending.extend(item.values())
        elif type(item) in (list, tuple):
            pending.extend(item)
    return found


def _validate_evidence_path_map(value: object) -> dict[str, str]:
    mapping = exact(value, {"schema", "entries"}, "Source5 Soak evidence path map")
    require(mapping["schema"] == EVIDENCE_PATH_MAP_SCHEMA and
            type(mapping["entries"]) is list and
            0 < len(mapping["entries"]) <= MAX_EVIDENCE_ENTRIES,
            "Source5 Soak evidence path map schema or size differs")
    paths: dict[str, str] = {}
    locals_seen: set[str] = set()
    previous = ""
    for index, entry_value in enumerate(mapping["entries"]):
        entry = exact(entry_value, {"origin", "local"},
                      f"Source5 Soak evidence path map entry[{index}]")
        origin, local = entry["origin"], entry["local"]
        require(type(origin) is str and type(local) is str and
                Path(origin).is_absolute() and Path(local).is_absolute() and
                str(Path(origin)) == origin and str(Path(local)) == local and
                ".." not in Path(origin).parts and ".." not in Path(local).parts,
                f"Source5 Soak path-map entry[{index}] is not normalized absolute")
        require(origin == local,
                "Source5 Soak offline replay supports identity paths only")
        require(origin > previous and origin not in paths and local not in locals_seen,
                "Source5 Soak path map is unsorted or aliases a path")
        previous = origin
        paths[origin] = local
        locals_seen.add(local)
    return paths


def _require_evidence_paths(mapped: dict[str, str], paths: set[str], label: str) -> None:
    missing = sorted(path for path in paths if path not in mapped)
    require(not missing,
            f"Source5 Soak evidence map omits {label} path: {missing[0] if missing else ''}")


def _load_fixed_pair_process_owner(prepared: dict[str, Any]) -> tuple[types.ModuleType, str, Path]:
    """Compile the exact SourceV5-inventory-pinned direct process owner."""
    source = prepared["source"]
    files = source.get("source", {}).get("files")
    require(type(files) is list,
            "Source5 Soak source has no typed inventory for its process owner")
    rows = [item for item in files if type(item) is dict and
            item.get("path") == "scripts/application-fixed-pair.py"]
    require(len(rows) == 1,
            "Source5 source inventory omits its accepted fixed direct-process owner")
    entry = exact(rows[0], {"path", "kind", "mode", "sha256", "size"},
                  "Source5 fixed process owner inventory entry")
    require(entry["kind"] == "file" and entry["mode"] in {"100644", "100755"} and
            type(entry["size"]) is int and 0 <= entry["size"] <= MAX_SCRIPT_BYTES,
            "Source5 fixed process owner inventory entry is malformed")
    path = Path(prepared["source_root"]) / entry["path"]
    raw, actual, info = read_stable(path, "Source5 captured fixed process owner",
                                    MAX_SCRIPT_BYTES)
    mode = f"{stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode):06o}"
    require(actual == entry["sha256"] and len(raw) == entry["size"] and
            mode == entry["mode"],
            "Source5 fixed process owner differs from its selected SourceV5 inventory")
    module = types.ModuleType(f"source5_soak_fixed_process_owner_{actual}")
    module.__file__ = str(path)
    module.__package__ = ""
    try:
        exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    except (SyntaxError, TypeError, ValueError) as error:
        raise Source5SoakError(f"SourceV5 fixed process owner cannot be compiled: {error}") from error
    for name in ("_run_direct_process", "_prepare_member_tmpdir", "_tmpdir_usage",
                 "_verify_tmpdir_storage", "_artifact_budgets",
                 "_bounded_tmpdir_monitor", "_mount_identity", "_mount_static",
                 "_tmpdir_usage_snapshot", "_open_tmpdir_absolute_directory"):
        require(callable(getattr(module, name, None)),
                f"SourceV5 fixed process owner omits {name}")
    return module, actual, path


def _preflight_source5_resource_budget(
    budget: dict[str, Any], output_root: Path,
    fixed_owner: types.ModuleType,
) -> dict[str, Any]:
    """Check every original writable root and filesystem reserve before owner launch."""
    layout = budget["layout"]
    ceilings = budget["ceilings"]
    domains = [
        ("output", Path(layout["output_root"]),
         ceilings["maximum_output_bytes"], ceilings["maximum_output_inodes"]),
        ("application_tmpdir", Path(layout["application_tmpdir"]),
         ceilings["maximum_application_tmpdir_bytes"],
         ceilings["maximum_application_tmpdir_inodes"]),
        ("pressure_scratch", Path(layout["pressure_scratch"]),
         ceilings["maximum_pressure_scratch_bytes"],
         ceilings["maximum_pressure_scratch_inodes"]),
        ("probe_capture", Path(layout["probe_capture_root"]),
         ceilings["maximum_probe_output_bytes"],
         ceilings["maximum_probe_output_inodes"]),
    ]
    require(output_root == Path(layout["output_root"]),
            "Source5 resource budget output root differs from the authorized job")
    usage_by_domain: dict[str, dict[str, Any]] = {}
    device_rows: dict[int, dict[str, Any]] = {}
    for role, path, byte_limit, inode_limit in domains:
        absent_probe = role == "probe_capture" and not path.exists() and not path.is_symlink()
        stat_path = path.parent if absent_probe else path
        fd = fixed_owner._open_tmpdir_absolute_directory(stat_path)
        try:
            root_info = os.fstat(fd)
            mount = fixed_owner._mount_identity(stat_path)
            filesystem = os.fstatvfs(fd)
            mount["available_bytes"] = filesystem.f_bavail * filesystem.f_frsize
            mount["available_inodes"] = filesystem.f_favail
            require(stat.S_ISDIR(root_info.st_mode) and root_info.st_uid == os.getuid() and
                    stat.S_IMODE(root_info.st_mode) == 0o700 and
                    mount.get("device") == root_info.st_dev,
                    f"Source5 resource budget {role} root is not a private held directory")
            if absent_probe:
                usage = {"bytes_used": 0, "inode_count": 0}
                root_identity = {"device": root_info.st_dev, "inode": None}
            else:
                usage = fixed_owner._tmpdir_usage_snapshot(
                    path, byte_limit, inode_limit,
                    (root_info.st_dev, root_info.st_ino),
                    allow_descendant_enoent=True,
                )
                root_identity = {"device": root_info.st_dev,
                                 "inode": root_info.st_ino}
            require(usage["bytes_used"] <= byte_limit and
                    usage["inode_count"] <= inode_limit,
                    f"Source5 resource budget {role} initial usage exceeds its prospective ceiling")
            item = {
                "path": str(path), "device": root_info.st_dev,
                "inode": root_identity["inode"],
                "bytes_used": usage["bytes_used"],
                "inode_count": usage["inode_count"],
                "available_bytes": mount["available_bytes"],
                "available_inodes": mount["available_inodes"],
                "bytes_limit": byte_limit, "inode_limit": inode_limit,
            }
            usage_by_domain[role] = item
            device = device_rows.setdefault(root_info.st_dev, {
                "available_bytes": mount["available_bytes"],
                "available_inodes": mount["available_inodes"],
                "domains": [],
            })
            device["available_bytes"] = min(
                device["available_bytes"], mount["available_bytes"],
            )
            device["available_inodes"] = min(
                device["available_inodes"], mount["available_inodes"],
            )
            device["domains"].append(role)
        finally:
            os.close(fd)

    host_receipt_parent = Path(layout["host_receipt_path"]).parent
    host_parent_fd = fixed_owner._open_tmpdir_absolute_directory(
        host_receipt_parent,
    )
    try:
        host_parent_info = os.fstat(host_parent_fd)
        require(host_parent_info.st_uid == os.getuid() and
                stat.S_IMODE(host_parent_info.st_mode) == 0o700 and
                host_parent_info.st_dev in device_rows,
                "Source5 host-receipt reserve is outside the monitored origin devices")
    finally:
        os.close(host_parent_fd)

    for device, row in device_rows.items():
        roots = [item for item in domains
                 if usage_by_domain[item[0]]["device"] == device]
        roots.sort(key=lambda item: (len(item[1].parts), str(item[1])))
        top_level: list[Path] = []
        allowances_bytes = 0
        allowances_inodes = 0
        for role, path, byte_limit, inode_limit in roots:
            if any(path == parent or parent in path.parents
                   for parent in top_level):
                continue
            top_level.append(path)
            current = usage_by_domain[role]
            allowances_bytes += max(0, byte_limit - current["bytes_used"])
            allowances_inodes += max(0, inode_limit - current["inode_count"])
        required_bytes = (ceilings["minimum_free_bytes"] +
                          allowances_bytes +
                          ceilings["durable_receipt_reserve_bytes"])
        required_inodes = (ceilings["minimum_free_inodes"] +
                           allowances_inodes +
                           ceilings["durable_receipt_reserve_inodes"])
        require(row["available_bytes"] >= required_bytes and
                row["available_inodes"] >= required_inodes,
                f"Source5 resource budget device {device} cannot satisfy its full output/TMPDIR/free-space reserve")
    return {"domains": usage_by_domain,
            "devices": {str(device): row for device, row in device_rows.items()}}


def _load_source5_preparation_verifier(
    prepared: dict[str, Any],
) -> tuple[types.ModuleType, str, Path]:
    """Compile the exact selected-source preparation replay helper."""
    relative = "scripts/application-source5-input-preparation.py"
    source = prepared["source"]
    files = source.get("source", {}).get("files")
    require(type(files) is list,
            "Source5 Soak source has no typed preparation-verifier inventory")
    rows = [item for item in files if type(item) is dict and
            item.get("path") == relative]
    require(len(rows) == 1,
            "Source5 Soak source inventory omits its preparation completion verifier")
    entry = exact(rows[0], {"path", "kind", "mode", "sha256", "size"},
                  "Source5 preparation verifier inventory entry")
    require(entry["kind"] == "file" and entry["mode"] in {"100644", "100755"} and
            type(entry["size"]) is int and 0 <= entry["size"] <= MAX_SCRIPT_BYTES,
            "Source5 preparation verifier inventory entry is malformed")
    path = Path(prepared["source_root"]) / relative
    raw, actual, info = read_stable(path, "Source5 captured preparation verifier",
                                    MAX_SCRIPT_BYTES)
    mode = f"{stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode):06o}"
    require(actual == entry["sha256"] and len(raw) == entry["size"] and
            mode == entry["mode"],
            "Source5 preparation verifier differs from its selected source inventory")
    module = types.ModuleType(f"source5_soak_preparation_verifier_{actual}")
    module.__file__ = str(path)
    module.__package__ = ""
    try:
        exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    except (SyntaxError, TypeError, ValueError) as error:
        raise Source5SoakError(
            f"Source5 preparation verifier cannot be compiled: {error}",
        ) from error
    require(callable(getattr(module, "verify_prepared_inputs_completion", None)),
            "Source5 preparation verifier lacks its pure completion replay API")
    return module, actual, path


def _load_pressure_driver_storage_reader(
    prepared: dict[str, Any],
) -> tuple[types.ModuleType, str, Path]:
    """Compile the original inventory-pinned pressure storage inspector."""
    source = prepared["source"]
    harness = source.get("qualification_harness")
    require(type(harness) is dict,
            "Source5 source manifest omits its closed pressure-driver harness")
    pin = exact(harness.get("pressure_driver"), {"path", "sha256"},
                "Source5 pressure-driver source pin")
    require(pin["path"] == "scripts/application-pressure-driver.py",
            "Source5 pressure-driver storage inspector path differs")
    digest(pin["sha256"], "Source5 pressure-driver source SHA-256")
    rows = [item for item in source["source"]["files"]
            if type(item) is dict and item.get("path") == pin["path"]]
    require(len(rows) == 1,
            "Source5 source inventory has no unique pressure-driver source")
    entry = exact(rows[0], {"path", "kind", "mode", "sha256", "size"},
                  "Source5 pressure-driver inventory entry")
    path = Path(prepared["source_root"]) / pin["path"]
    raw, actual, info = read_stable(
        path, "Source5 captured pressure-driver source", MAX_SCRIPT_BYTES,
    )
    mode = f"{stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode):06o}"
    require(entry["kind"] == "file" and entry["mode"] in {"100644", "100755"} and
            entry["sha256"] == pin["sha256"] == actual and
            entry["size"] == len(raw) and entry["mode"] == mode,
            "Source5 pressure-driver module differs from its source inventory")
    module = types.ModuleType(f"source5_soak_pressure_storage_{actual}")
    module.__file__ = str(path)
    module.__package__ = ""
    try:
        exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    except (SyntaxError, TypeError, ValueError) as error:
        raise Source5SoakError(
            f"Source5 captured pressure storage inspector cannot be compiled: {error}",
        ) from error
    require(callable(getattr(module, "_storage_record", None)),
            "Source5 pressure driver lacks its typed storage observation helper")
    return module, actual, path


def _load_pressure_readback_module(
    prepared: dict[str, Any],
) -> tuple[types.ModuleType, str, Path]:
    """Compile the exact SourceV5-inventory-pinned pressure reader bytes."""
    source = prepared["source"]
    harness = source.get("qualification_harness")
    require(type(harness) is dict,
            "Source5 source manifest omits its pressure readback validator")
    pin = exact(harness.get("pressure_validator"), {"path", "sha256"},
                "Source5 pressure-readback source pin")
    require(pin["path"] == "scripts/application-pressure-readback.py",
            "Source5 pressure-readback path differs from the captured validator")
    digest(pin["sha256"], "Source5 pressure-readback source SHA-256")
    rows = [item for item in source["source"]["files"]
            if type(item) is dict and item.get("path") == pin["path"]]
    require(len(rows) == 1,
            "Source5 source inventory has no unique pressure-readback source")
    entry = exact(rows[0], {"path", "kind", "mode", "sha256", "size"},
                  "Source5 pressure-readback inventory entry")
    path = Path(prepared["source_root"]) / pin["path"]
    raw, actual, info = read_stable(
        path, "Source5 captured pressure-readback source", MAX_SCRIPT_BYTES,
    )
    mode = f"{stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode):06o}"
    require(entry["kind"] == "file" and entry["mode"] in {"100644", "100755"} and
            entry["sha256"] == pin["sha256"] == actual and
            entry["size"] == len(raw) and entry["mode"] == mode,
            "Source5 pressure-readback module differs from its typed inventory")
    module = types.ModuleType(f"source5_soak_pressure_readback_{actual}")
    module.__file__ = str(path)
    module.__package__ = ""
    try:
        exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    except (SyntaxError, TypeError, ValueError) as error:
        raise Source5SoakError(
            f"Source5 captured pressure readback cannot be compiled: {error}",
        ) from error
    require(callable(getattr(module, "verify_source5_soak_pressure_offline", None)) and
            callable(getattr(module, "verify_source5_soak_pressure_offline_v3", None)) and
            callable(getattr(module, "_pressure_absolute_json_paths", None)) and
            type(getattr(module, "MAX_EVENTS_BYTES", None)) is int,
            "Source5 pressure reader lacks its typed Soak replay APIs")
    return module, actual, path


def _load_feedback_composition_module(
    prepared: dict[str, Any],
) -> tuple[types.ModuleType, dict[str, Any]]:
    """Compile the Composer only from the selected SourceV5 typed inventory."""
    pin = _resource_budget_module_pin(
        prepared, "scripts/application-feedback-composition.py",
        "ProbeV2 composition owner",
    )
    path = Path(prepared["source_root"]) / pin["path"]
    raw, actual, info = read_stable(
        path, "captured ProbeV2 composition owner", MAX_SCRIPT_BYTES,
    )
    mode = f"{stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode):06o}"
    require(actual == pin["raw_sha256"] and len(raw) == pin["size"] and
            mode == pin["mode"],
            "ProbeV2 Composer differs from its SourceV5 typed inventory before execution")
    module = types.ModuleType(f"source5_soak_probe_composer_{actual}")
    module.__file__ = str(path)
    module.__package__ = ""
    try:
        exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    except (SyntaxError, TypeError, ValueError) as error:
        raise Source5SoakError(
            f"captured ProbeV2 composition owner cannot be compiled: {error}",
        ) from error
    require(callable(getattr(module, "capture_calibrated_probe_v2", None)) and
            callable(getattr(module, "_validate_resolve_request", None)),
            "captured SourceV5 Composer lacks its strict ProbeV2 owner API")
    return module, pin


def _source5_soak_capacity_bundle(
    prepared: dict[str, Any], recipe: dict[str, Any],
) -> dict[str, dict[str, str]]:
    completion = prepared["source5_prepared_input_completion"]
    rows = [row for row in completion.get("capacity_preparations", [])
            if type(row) is dict and row.get("host_id") == prepared["host_id"]]
    require(len(rows) == 1,
            "Source5 ProbeV2 has no unique selected-host capacity completion")
    capacity_template = exact(
        recipe["qualification"]["capacity_template"],
        {"template_sha256", "calibration_id", "request_template",
         "context_template", "evidence"},
        "Source5 original capacity template",
    )
    matches = [entry for entry in rows[0].get("entries", [])
               if type(entry) is dict and
               entry.get("capacity_key") == {
                   "host_id": prepared["host_id"], "workload": "mixed",
                   "profile": recipe["identity"]["profile"],
                   "calibration_id": capacity_template["calibration_id"],
               }]
    require(len(matches) == 1,
            "Source5 ProbeV2 capacity bundle differs from the exact mixed Soak context")
    entry = matches[0]
    result: dict[str, dict[str, str]] = {}
    for role in ("request", "artifact", "receipt"):
        pin = exact(entry.get(role), {"path", "sha256"},
                    f"Source5 ProbeV2 capacity {role} pin")
        require(type(pin["path"]) is str and Path(pin["path"]).is_absolute(),
                f"Source5 ProbeV2 capacity {role} path is not absolute")
        result[role] = {"path": pin["path"],
                        "raw_sha256": digest(pin["sha256"],
                                             f"Source5 ProbeV2 capacity {role} SHA-256")}
    require(len({pin["path"] for pin in result.values()}) == 3,
            "Source5 ProbeV2 capacity request/artifact/receipt paths alias")
    evidence = capacity_template["evidence"]
    require(type(evidence) is dict and
            evidence.get("artifact", {}).get("raw_sha256") ==
                result["artifact"]["raw_sha256"] and
            evidence.get("receipt", {}).get("raw_sha256") ==
                result["receipt"]["raw_sha256"],
            "Source5 ProbeV2 capacity bundle differs from the original recipe evidence")
    return result


def _capture_source5_soak_probe_v2(
    prepared: dict[str, Any], binding: dict[str, Any], recipe: dict[str, Any],
    resource_budget: dict[str, Any], capture_root_value: object,
    *, resource_monitor: Any = None,
) -> tuple[dict[str, Any], dict[str, str], dict[str, Any]]:
    """Capture the selected-floor ProbeV2 with the accepted FixedR8 owner."""
    capture_root = Path(str(capture_root_value))
    require(capture_root.is_absolute() and ".." not in capture_root.parts and
            re.fullmatch(r"[a-f0-9]{32}", capture_root.name) is not None and
            not capture_root.exists() and not capture_root.is_symlink(),
            "Source5 ProbeV2 capture root must be its fresh budget-pinned capture ID")
    parent = capture_root.parent
    parent_info = parent.lstat()
    require(stat.S_ISDIR(parent_info.st_mode) and
            not stat.S_ISLNK(parent_info.st_mode) and
            parent_info.st_uid == os.getuid() and
            stat.S_IMODE(parent_info.st_mode) == 0o700,
            "Source5 ProbeV2 capture parent must be an owned private directory")
    probe_pin = exact(recipe["construction_probe"], {
        "path", "raw_sha256", "allocator", "binary_sha256",
    }, "Source5 selected ProbeV2 pin")
    expected_probe, probe_raw, probe_sha = read_json(
        Path(probe_pin["path"]), probe_pin["raw_sha256"],
        "Source5 selected ProbeV2", 512 * 1024,
    )
    normal_sha = digest(
        prepared["source"]["artifacts"]["allocatbelt"]["sha256"],
        "Source5 normal APP artifact SHA-256",
    )
    require(probe_pin["allocator"] == "allocatbelt" and
            probe_pin["binary_sha256"] == normal_sha,
            "Source5 selected ProbeV2 allocator differs from the original normal APP")
    floor_policy = recipe["feedback_expectation"]["policy"].get(
        "capacity_floor_policy_id",
    )
    require(type(floor_policy) is str and
            expected_probe.get("schema") ==
                "allocatbelt.application-feedback-policy-probe.v2" and
            expected_probe.get("context", {}).get("workload") == "mixed" and
            expected_probe.get("context", {}).get("profile") == recipe["identity"]["profile"],
            "Source5 bounded ProbeV2 does not match its selected capacity-floor context")
    source_ref = exact(prepared["source_manifest_raw_refs"][prepared["host_id"]], {
        "host_id", "path", "raw_sha256", "semantic_sha256",
        "source_tree_sha256",
    }, "Source5 ProbeV2 selected SourceV5 manifest pin")
    source_manifest_pin = {"path": source_ref["path"],
                           "raw_sha256": source_ref["raw_sha256"]}
    capacity_bundle = _source5_soak_capacity_bundle(prepared, recipe)
    composition, _composition_pin = _load_feedback_composition_module(prepared)
    request_schema = getattr(composition, "REQUEST_SCHEMA_V2", None)
    require(type(request_schema) is str and request_schema,
            "captured SourceV5 Composer lacks the selected-floor request schema")
    request = {
        "schema": request_schema,
        "source_root": str(Path(prepared["source_root"]).resolve(strict=True)),
        "source_manifest": source_manifest_pin,
        "context": {
            "host_id": prepared["host_id"], "workload": "mixed",
            "profile": recipe["identity"]["profile"],
            "calibration_id": recipe["qualification"]["capacity_template"][
                "calibration_id"],
        },
        "construction_probe": probe_pin,
        "capacity_bundle": capacity_bundle,
        "capacity_floor_policy_id": floor_policy,
    }
    validate_request = composition._validate_resolve_request(request)
    require(validate_request == request,
            "Source5 selected ProbeV2 request changed during Composer normalization")
    ceilings = resource_budget["ceilings"]
    limits = resource_budget["artifact_limits"]
    storage_budget = {
        "tmpdir_bytes": ceilings["maximum_probe_tmpdir_bytes"],
        "tmpdir_inodes": ceilings["maximum_probe_tmpdir_inodes"],
        "stdout_bytes": limits["probe_stdout_bytes"],
        "stderr_bytes": limits["probe_stderr_bytes"],
        "owner_result_bytes": limits["probe_owner_receipt_bytes"],
        "inventory_bytes": limits["probe_inventory_bytes"],
        "failure_bytes": limits["probe_failure_bytes"],
        "receipt_bytes": limits["probe_capture_receipt_bytes"],
        "output_inodes": ceilings["maximum_probe_output_inodes"],
    }
    observed_host_pin = raw_pin(binding["prepared_host_context_pin"],
                                "Source5 ProbeV2 observed-host context")
    timeout_ns = resource_budget["schedule"]["probe_timeout_seconds"] * 1_000_000_000
    receipt_pin = composition.capture_calibrated_probe_v2(
        request, sha256(canonical_bytes(request)), observed_host_pin,
        output_root=parent, capture_id=capture_root.name,
        capture_timeout_ns=timeout_ns, storage_budget=storage_budget,
        resource_monitor=resource_monitor,
    )
    receipt_pin = exact(receipt_pin, {"path", "raw_sha256", "receipt_sha256"},
                        "Source5 ProbeV2 strict capture receipt pin")
    capture, _raw, capture_sha = read_json(
        Path(receipt_pin["path"]), receipt_pin["raw_sha256"],
        "Source5 ProbeV2 strict capture receipt",
        limits["probe_capture_receipt_bytes"],
    )
    require(capture_sha == receipt_pin["raw_sha256"] and
            capture.get("schema") ==
                "allocatbelt.application-feedback-probe-capture.v2" and
            capture.get("receipt_sha256") == receipt_pin["receipt_sha256"] and
            capture.get("probe_pin") == probe_pin and
            capture.get("probe_raw_sha256") == probe_sha and
            capture.get("source_manifest", {}).get("raw_sha256") ==
                source_ref["raw_sha256"] and
            capture.get("source_manifest", {}).get("semantic_sha256") ==
                source_ref["semantic_sha256"] and
            capture.get("capacity_bundle") == capacity_bundle and
            capture.get("capture_timeout_ns") == timeout_ns,
            "Source5 ProbeV2 capture does not bind the pinned source, capacity bundle, and owner deadline")
    probe_context = {
        "schema": "allocatbelt.application-source5-soak-probe-audit-context.v2",
        "capture_pin": receipt_pin,
        "capture": capture,
        "probe": expected_probe,
        "probe_raw": probe_raw,
        "probe_raw_sha256": probe_sha,
        "capacity_bundle": capacity_bundle,
        "capacity_floor_policy_id": floor_policy,
        "normal_binary_sha256": probe_pin["binary_sha256"],
        "request": request,
    }
    return capture, receipt_pin, probe_context


def _source5_probe_v2_audit_context(
    prepared: dict[str, Any], recipe: dict[str, Any],
    capture_pin_value: object,
    *, evidence_path_map: object | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Reconstruct the bounded ProbeV2 audit context from its pinned receipt."""
    capture_pin = exact(capture_pin_value, {
        "path", "raw_sha256", "receipt_sha256",
    }, "Source5 ProbeV2 captured receipt pin")
    capture, _capture_raw, capture_sha = read_json(
        Path(capture_pin["path"]), capture_pin["raw_sha256"],
        "Source5 ProbeV2 captured receipt", MAX_RECEIPT_BYTES,
    )
    require(capture_sha == capture_pin["raw_sha256"] and
            capture.get("schema") ==
                "allocatbelt.application-feedback-probe-capture.v2" and
            capture.get("receipt_sha256") == capture_pin["receipt_sha256"],
            "Source5 ProbeV2 capture receipt differs from its strict host pin")
    probe_pin = exact(recipe["construction_probe"], {
        "path", "raw_sha256", "allocator", "binary_sha256",
    }, "Source5 selected ProbeV2 source pin")
    probe, probe_raw, probe_sha = read_json(
        Path(probe_pin["path"]), probe_pin["raw_sha256"],
        "Source5 selected ProbeV2 source", 512 * 1024,
    )
    capacity_bundle = _source5_soak_capacity_bundle(prepared, recipe)
    composition, _composition_pin = _load_feedback_composition_module(prepared)
    floor_policy = recipe["feedback_expectation"]["policy"].get(
        "capacity_floor_policy_id",
    )
    require(type(floor_policy) is str and
            callable(getattr(composition, "_validate_resolve_request", None)),
            "captured SourceV5 Composer lacks the strict ProbeV2 request API")
    source_ref = prepared["source_manifest_raw_refs"][prepared["host_id"]]
    request = {
        "schema": composition.REQUEST_SCHEMA_V2,
        "source_root": str(Path(prepared["source_root"]).resolve(strict=True)),
        "source_manifest": {"path": source_ref["path"],
                             "raw_sha256": source_ref["raw_sha256"]},
        "context": {
            "host_id": prepared["host_id"], "workload": "mixed",
            "profile": recipe["identity"]["profile"],
            "calibration_id": recipe["qualification"]["capacity_template"][
                "calibration_id"],
        },
        "construction_probe": probe_pin,
        "capacity_bundle": capacity_bundle,
        "capacity_floor_policy_id": floor_policy,
    }
    normalized = composition._validate_resolve_request(request)
    require(normalized == request,
            "captured SourceV5 Composer normalized a different ProbeV2 request")
    context = {
        "schema": "allocatbelt.application-source5-soak-probe-audit-context.v2",
        "capture_pin": capture_pin,
        "capture": capture,
        "probe": probe,
        "probe_raw": probe_raw,
        "probe_raw_sha256": probe_sha,
        "capacity_bundle": capacity_bundle,
        "capacity_floor_policy_id": floor_policy,
        "normal_binary_sha256": probe_pin["binary_sha256"],
        "request": request,
    }
    if evidence_path_map is not None:
        require(callable(getattr(composition,
                                 "compose_calibrated_policy_v5_offline", None)),
                "captured SourceV5 Composer lacks offline ProbeV2 policy replay")
        try:
            policy_document, composition_receipt = \
                composition.compose_calibrated_policy_v5_offline(
                    request, sha256(canonical_bytes(request)),
                    replay_context={
                        "schema": "allocatbelt.application-feedback-offline-replay-context.v1",
                        "evidence_path_map": evidence_path_map,
                        "probe_capture_pin": capture_pin,
                        "capacity_bundle": capacity_bundle,
                    },
                )
        except Exception as error:
            raise Source5SoakError(
                f"Source5 offline Composer rejected the captured ProbeV2 evidence: {error}",
            ) from error
        require(type(policy_document) is dict and
                type(composition_receipt) is dict and
                policy_document.get("policy") ==
                    recipe["feedback_expectation"]["policy"] and
                policy_document.get("capacity_floor_policy_id") == floor_policy and
                policy_document.get("source_manifest_raw_sha256") ==
                    source_ref["raw_sha256"] and
                composition_receipt.get("schema") == composition.RECEIPT_SCHEMA_V2 and
                composition_receipt.get("validated") is True and
                composition_receipt.get("execution_ready") is False and
                composition_receipt.get("qualification_eligible") is False and
                composition_receipt.get("controller_chronology_proven") is False,
                "Source5 offline Composer policy/receipt differs from the original selected ProbeV2 recipe")
    return context, capture_pin


def _verify_source5_probe_resource_budget(
    budget: dict[str, Any], prepared: dict[str, Any],
    probe_context: dict[str, Any],
) -> None:
    """Re-derive the exact ProbeV1/V2 owner limits from the prospective budget."""
    capture = probe_context.get("capture")
    capture_pin = probe_context.get("capture_pin")
    require(type(capture) is dict and type(capture_pin) is dict,
            "Source5 bounded probe capture context is incomplete")
    layout = budget["layout"]
    ceilings = budget["ceilings"]
    limits = budget["artifact_limits"]
    schedule = budget["schedule"]
    root = Path(layout["probe_capture_root"])
    if capture.get("schema") == PROBE_CAPTURE_SCHEMA_V2:
        storage = exact(capture.get("storage_budget"), {
            "tmpdir_bytes", "tmpdir_inodes", "stdout_bytes", "stderr_bytes",
            "owner_result_bytes", "inventory_bytes", "failure_bytes",
            "receipt_bytes", "output_inodes",
        }, "Source5 bounded ProbeV2 owner storage budget")
        expected_storage = {
            "tmpdir_bytes": ceilings["maximum_probe_tmpdir_bytes"],
            "tmpdir_inodes": ceilings["maximum_probe_tmpdir_inodes"],
            "stdout_bytes": limits["probe_stdout_bytes"],
            "stderr_bytes": limits["probe_stderr_bytes"],
            "owner_result_bytes": limits["probe_owner_receipt_bytes"],
            "inventory_bytes": limits["probe_inventory_bytes"],
            "failure_bytes": limits["probe_failure_bytes"],
            "receipt_bytes": limits["probe_capture_receipt_bytes"],
            "output_inodes": ceilings["maximum_probe_output_inodes"],
        }
        require(storage == expected_storage and
                capture.get("capture_timeout_ns") ==
                    schedule["probe_timeout_seconds"] * 1_000_000_000 and
                Path(capture_pin["path"]) == root / "capture-receipt.json" and
                capture.get("tmpdir_initial", {}).get("path") ==
                    layout["probe_tmpdir"],
                "Source5 ProbeV2 owner receipt differs from its exact prospective limits/layout")
        return
    require(capture.get("schema") == PROBE_CAPTURE_SCHEMA,
            "Source5 bounded probe has an unknown original capture schema")
    owner, _owner_sha, _owner_path = _load_fixed_pair_process_owner(prepared)
    owner_limits = owner._artifact_budgets()
    stdout_limit = min(owner.MAX_PROBE_STDOUT_BYTES,
                       limits["probe_stdout_bytes"])
    stderr_limit = min(owner.MAX_PROBE_STDERR_BYTES,
                       limits["probe_stderr_bytes"])
    tmpdir_bytes = min(owner_limits["tmpdir_bytes"],
                       ceilings["maximum_probe_tmpdir_bytes"])
    tmpdir_inodes = min(owner_limits["tmpdir_inodes"],
                        ceilings["maximum_probe_tmpdir_inodes"])
    owner_bytes = min(owner_limits["runtime_receipt_bytes"],
                      limits["probe_owner_receipt_bytes"])
    capture_bytes = min(owner_limits["runtime_receipt_bytes"],
                        limits["probe_capture_receipt_bytes"])
    expected = {
        "stdout_bytes": stdout_limit,
        "stderr_bytes": stderr_limit,
        "tmpdir_bytes": tmpdir_bytes,
        "tmpdir_inodes": tmpdir_inodes,
        "output_bytes": stdout_limit + stderr_limit + 2 * owner_bytes,
        "output_inodes": 4,
        "deadline_seconds": min(
            int(owner.PROBE_TIMEOUT_SECONDS),
            schedule["probe_timeout_seconds"],
        ),
        "owner_receipt_bytes": owner_bytes,
        "capture_receipt_bytes": capture_bytes,
    }
    require(capture.get("capture_budgets") == expected and
            Path(capture_pin["path"]) == root / "probe-capture.json" and
            capture.get("tmpdir_path") == layout["probe_tmpdir"] and
            capture.get("tmpdir_receipt", {}).get("byte_limit") == tmpdir_bytes and
            capture.get("tmpdir_receipt", {}).get("inode_limit") == tmpdir_inodes,
            "Source5 ProbeV1 owner receipt differs from its exact prospective limits/layout")


def _source5_probe_owner_interval(
    prepared: dict[str, Any], probe_context: dict[str, Any],
    budget: dict[str, Any],
) -> tuple[int, int]:
    capture = probe_context["capture"]
    owner_pin_value = capture.get("owner_result_pin")
    if capture.get("schema") == PROBE_CAPTURE_SCHEMA_V2:
        owner_pin = exact(owner_pin_value, {
            "path", "raw_sha256", "owner_result_sha256",
        }, "Source5 ProbeV2 owner-result pin")
        owner, _raw, _sha = read_json(
            Path(owner_pin["path"]), owner_pin["raw_sha256"],
            "Source5 ProbeV2 FixedR8 owner result",
            budget["artifact_limits"]["probe_owner_receipt_bytes"],
        )
        exact(owner, {
            "schema", "direct", "start_callback_count", "start_callback_proofs",
            "owner_result_sha256",
        }, "Source5 ProbeV2 owner-result receipt")
        owner_body = {key: value for key, value in owner.items()
                      if key != "owner_result_sha256"}
        require(owner["schema"] ==
                    "allocatbelt.application-feedback-probe-owner-result.v1" and
                owner["owner_result_sha256"] ==
                    owner_pin["owner_result_sha256"] ==
                    sha256(canonical_bytes(owner_body)) and
                owner["start_callback_count"] == 1 and
                type(owner["start_callback_proofs"]) is list and
                len(owner["start_callback_proofs"]) == 1,
                "Source5 ProbeV2 owner receipt differs from its original callback proof")
        direct = owner["direct"]
    else:
        owner_pin = raw_pin(owner_pin_value,
                            "Source5 ProbeV1 owner-result pin")
        direct, _raw, _sha = read_json(
            Path(owner_pin["path"]), owner_pin["raw_sha256"],
            "Source5 ProbeV1 direct owner result",
            budget["artifact_limits"]["probe_owner_receipt_bytes"],
        )
    require(type(direct) is dict and direct.get("status") == 0 and
            direct.get("child_return_code") == 0 and
            type(direct.get("started_monotonic_ns")) is int and
            type(direct.get("ended_monotonic_ns")) is int and
            0 < direct["started_monotonic_ns"] <=
                direct["ended_monotonic_ns"] and
            type(direct.get("supervision")) is dict and
            direct["supervision"].get("cleanup_status") == "verified" and
            direct["supervision"].get("leader_reaped") is True and
            direct["supervision"].get("group_signal_after_leader_reap_count") == 0,
            "Source5 Probe owner return/cleanup interval is not a successful owned capture")
    return direct["started_monotonic_ns"], direct["ended_monotonic_ns"]


def _verify_source5_owner_phase_intervals(
    monitor_replay: dict[str, Any], budget: dict[str, Any],
    probe_interval: tuple[int, int], app_details: dict[str, Any],
    pressure_owner: dict[str, Any], supervisor: dict[str, Any],
) -> None:
    phases = monitor_replay["phase_bounds"]
    phase_counts = monitor_replay["phase_counts"]
    schedule = budget["schedule"]
    gap_ns = (schedule["resource_monitor_interval_ms"] * 1_000_000 +
              schedule["resource_monitor_tolerance_ns"])

    def bounds(name: str) -> tuple[int, int]:
        value = phases.get(name)
        require(type(value) is list and len(value) == 2 and
                all(type(item) is int and item > 0 for item in value) and
                value[0] <= value[1],
                f"Source5 resource monitor omits the {name} owner interval")
        return value[0], value[1]

    def require_near(actual: int, expected: int, label: str) -> None:
        require(abs(actual - expected) <= gap_ns,
                f"Source5 resource monitor {label} is outside its held-owner interval")

    require(phase_counts.get("preflight", 0) >= 1 and
            phase_counts.get("preflight_audit", 0) >= 2 and
            phase_counts.get("postflight", 0) >= 3,
            "Source5 resource monitor omits preparation or finalization samples")

    probe_started, probe_ended = probe_interval
    app_started = app_details["started_monotonic_ns"]
    app_ended = app_details["ended_monotonic_ns"]
    pressure_started = pressure_owner["started_monotonic_ns"]
    pressure_returned = pressure_owner["returned_monotonic_ns"]
    require(type(app_started) is int and type(app_ended) is int and
            0 < app_started <= app_ended and
            type(pressure_started) is int and type(pressure_returned) is int and
            0 < pressure_started <= pressure_returned and
            probe_ended <= pressure_started < app_started <= app_ended <=
                pressure_returned and
            app_ended - app_started >=
                schedule["production_seconds"] * 1_000_000_000 -
                schedule["application_sample_tolerance_ns"],
            "Source5 Probe/pressure/APP owner intervals do not cover the original run horizon")

    probe_first, probe_last = bounds("probe_capture")
    require(phase_counts.get("probe_capture", 0) >= 2,
            "Source5 probe owner is not covered by monitor start/end samples")
    require_near(probe_first, probe_started, "ProbeV2 owner start")
    require_near(probe_last, probe_ended, "ProbeV2 owner return")
    require(probe_first >= probe_started - gap_ns and
            probe_last <= probe_ended + gap_ns,
            "Source5 probe monitor rows do not bracket the captured FixedR8 owner")
    startup_first, startup_last = bounds("pressure_startup")
    require(phase_counts.get("pressure_startup", 0) >= 2,
            "Source5 pressure startup lacks prelaunch and readiness samples")
    require_near(startup_first, pressure_started, "pressure Popen")
    require_near(startup_last, app_started, "pressure readiness")
    require(startup_first <= pressure_started + gap_ns and
            startup_last <= app_started + gap_ns,
            "Source5 pressure-startup monitor rows do not bracket the owner handoff")
    app_first, app_last = bounds("application")
    require(phase_counts.get("application", 0) >= 2,
            "Source5 APP/pressure lifetime lacks owner start/end samples")
    require_near(app_first, app_started, "APP owner start")
    require_near(app_last, pressure_returned, "post-APP pressure return")
    require(app_first >= app_started - gap_ns and
            app_last >= app_ended - gap_ns and
            app_last <= pressure_returned + gap_ns,
            "Source5 APP monitor rows omit its lifetime or post-APP pressure wait")
    cleanup_first, cleanup_last = bounds("pressure_cleanup")
    require(phase_counts.get("pressure_cleanup", 0) >= 2,
            "Source5 pressure cleanup lacks owner-return and cleanup samples")
    require_near(cleanup_first, pressure_returned, "pressure cleanup start")
    require(cleanup_first >= pressure_returned - gap_ns and
            cleanup_last >= cleanup_first and
            supervisor["pressure_cleanup"] == "verified",
            "Source5 pressure-cleanup monitor rows do not bind the returned owned session")
    postflight_first, postflight_last = bounds("postflight")
    require(postflight_first >= cleanup_last and
            postflight_first - cleanup_last <= gap_ns,
            "Source5 postflight monitor does not follow verified pressure cleanup")
    footer_ended = monitor_replay["footer_ended_monotonic_ns"]
    require(phase_counts.get("postflight", 0) >= 3 and
            footer_ended >= postflight_last and
            footer_ended - postflight_last <= gap_ns,
            "Source5 postflight monitor rows do not cover final source/readback checks")


def _capture_source5_soak_probe(
    prepared: dict[str, Any], job: dict[str, Any], binding: dict[str, Any],
    recipe: dict[str, Any], readback: types.ModuleType, capture_root_value: object,
    *, resource_budget: dict[str, Any] | None = None,
    resource_monitor: Any = None,
) -> tuple[dict[str, Any], dict[str, str], dict[str, Any] | None]:
    """Capture the SourceV5 ProbeV1 on-origin with the accepted process owner."""
    floor_policy = recipe["feedback_expectation"]["policy"].get(
        "capacity_floor_policy_id",
    )
    if resource_budget is not None and floor_policy is not None:
        return _capture_source5_soak_probe_v2(
            prepared, binding, recipe, resource_budget, capture_root_value,
            resource_monitor=resource_monitor,
        )
    capture_root = Path(str(capture_root_value))
    require(capture_root.is_absolute() and ".." not in capture_root.parts and
            not capture_root.exists() and not capture_root.is_symlink(),
            "Source5 Soak probe capture root must be fresh and normalized")
    parent = capture_root.parent
    parent_info = parent.lstat() if resource_budget is not None else parent.stat()
    require(stat.S_ISDIR(parent_info.st_mode) and
            (resource_budget is None or not stat.S_ISLNK(parent_info.st_mode)) and
            parent_info.st_uid == os.getuid() and
            stat.S_IMODE(parent_info.st_mode) == 0o700,
            "Source5 Soak probe capture parent must be an owned private directory")
    capture_root.mkdir(mode=0o700)
    root_info = capture_root.stat(follow_symlinks=False)
    require(stat.S_ISDIR(root_info.st_mode) and root_info.st_uid == os.getuid() and
            stat.S_IMODE(root_info.st_mode) == 0o700,
            "Source5 Soak probe capture root is not a private owned directory")
    owner, owner_sha, owner_path = _load_fixed_pair_process_owner(prepared)
    source_root = Path(prepared["source_root"]).resolve(strict=True)
    normal_path = source_root / prepared["source"]["artifacts"]["allocatbelt"]["path"]
    normal_sha = digest(prepared["source"]["artifacts"]["allocatbelt"]["sha256"],
                        "Source5 normal APP SHA-256")
    probe_pin = exact(recipe["construction_probe"], {
        "path", "raw_sha256", "allocator", "binary_sha256",
    }, "Source5 Soak original ProbeV1 pin")
    expected_probe, _probe_raw, probe_raw_sha = read_json(
        Path(probe_pin["path"]), probe_pin["raw_sha256"],
        "Source5 Soak original ProbeV1", 512 * 1024,
    )
    require(probe_raw_sha == probe_pin["raw_sha256"] and
            probe_pin["allocator"] == "allocatbelt" and
            probe_pin["binary_sha256"] == normal_sha,
            "Source5 Soak construction probe is not bound to the original normal APP")
    tmpdir = capture_root / "tmp"
    stdout_path = capture_root / "probe.stdout"
    stderr_path = capture_root / "probe.stderr"
    owner_path_out = capture_root / "process-owner.json"
    budgets = owner._artifact_budgets()
    byte_limit = budgets["tmpdir_bytes"]
    inode_limit = budgets["tmpdir_inodes"]
    stdout_limit = owner.MAX_PROBE_STDOUT_BYTES
    stderr_limit = owner.MAX_PROBE_STDERR_BYTES
    probe_timeout = owner.PROBE_TIMEOUT_SECONDS
    if resource_budget is not None:
        ceilings = resource_budget["ceilings"]
        limits = resource_budget["artifact_limits"]
        byte_limit = min(byte_limit, ceilings["maximum_probe_tmpdir_bytes"])
        inode_limit = min(inode_limit, ceilings["maximum_probe_tmpdir_inodes"])
        stdout_limit = min(stdout_limit, limits["probe_stdout_bytes"])
        stderr_limit = min(stderr_limit, limits["probe_stderr_bytes"])
        probe_timeout = min(
            probe_timeout, resource_budget["schedule"]["probe_timeout_seconds"],
        )
    tmpdir_budgets = dict(budgets)
    tmpdir_budgets["tmpdir_bytes"] = byte_limit
    tmpdir_budgets["tmpdir_inodes"] = inode_limit
    tmpdir_initial = owner._prepare_member_tmpdir(
        tmpdir, capture_root, tmpdir_budgets,
    )
    output_byte_bound = (
        stdout_limit + stderr_limit +
        2 * min(budgets["runtime_receipt_bytes"],
                (resource_budget["artifact_limits"]["probe_owner_receipt_bytes"]
                 if resource_budget is not None else
                 budgets["runtime_receipt_bytes"]))
    )
    output_inode_bound = 4
    require(tmpdir_initial["available_bytes"] >= byte_limit + output_byte_bound and
            tmpdir_initial["available_inodes"] >= inode_limit + output_inode_bound,
            "Source5 ProbeV1 capture storage cannot reserve its inherited TMPDIR and output budgets")
    tmpdir_mount = owner._mount_static(owner._mount_identity(capture_root))
    environment = {
        "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
        "TMPDIR": str(tmpdir),
    }
    argv = [str(normal_path), "--emit-feedback-policy-only", "--workload",
            "mixed", "--profile", recipe["identity"]["profile"]]
    affinity = list(binding["process_affinity"])
    network_inode = binding["network_namespace_inode"]
    tmpdir_monitor = owner._bounded_tmpdir_monitor(
        tmpdir, byte_limit, inode_limit, tmpdir_initial,
    )

    def combined_resource_monitor() -> bool:
        tmpdir_exceeded = bool(tmpdir_monitor())
        outer_exceeded = bool(resource_monitor()) if resource_monitor is not None else False
        return tmpdir_exceeded or outer_exceeded

    direct = owner._run_direct_process(
        argv, normal_path, normal_sha, source_root, environment, affinity,
        stdout_path, stderr_path, stdout_limit,
        stderr_limit, probe_timeout, readback,
        expected_tmpdir=tmpdir, expected_network_inode=network_inode,
        capture_identity=False,
        resource_monitor=(combined_resource_monitor if resource_monitor is not None
                          else tmpdir_monitor),
    )
    process_pin = None
    process_receipt_limit = budgets["runtime_receipt_bytes"]
    if resource_budget is not None:
        process_receipt_limit = min(
            process_receipt_limit,
            resource_budget["artifact_limits"]["probe_owner_receipt_bytes"],
        )
        # Preserve the actual owner result before reading streams, rescanning
        # TMPDIR, or checking post-return host state.
        process_pin = _write_exclusive_json(
            owner_path_out, direct,
            "Source5 bounded ProbeV1 original process-owner result",
        )
        require(len(canonical_bytes(direct)) <= process_receipt_limit,
                "Source5 bounded ProbeV1 original owner result exceeds its frozen receipt bound")
    stdout_raw, stdout_sha, _stdout_info = read_stable(
        stdout_path, "Source5 Soak captured ProbeV1 stdout",
        stdout_limit,
    )
    stderr_raw, stderr_sha, _stderr_info = read_stable(
        stderr_path, "Source5 Soak captured ProbeV1 stderr",
        stderr_limit,
    )
    require(direct["status"] == direct["child_return_code"] == 0 and
            direct["supervision"]["cleanup_status"] == "verified" and
            direct["supervision"].get("leader_reaped") is True and
            direct["supervision"].get("group_signal_after_leader_reap_count") == 0 and
            direct["start"]["pid"] > 0 and direct["start"]["start_ticks"] > 0 and
            stdout_sha == probe_raw_sha and stdout_raw == _probe_raw and
            stderr_raw == b"" and direct["requested_argv"] == argv and
            direct["environment"] == environment and direct["cwd"] == str(source_root) and
            direct["cpu_affinity"] == affinity and
            direct["network_namespace_inode"] == network_inode,
            "Source5 origin ProbeV1 owner capture differs from its exact input")
    budget_record = {"bytes_limit": byte_limit, "inode_limit": inode_limit}
    tmpdir_final = owner._tmpdir_usage(tmpdir, budget_record)
    owner._verify_tmpdir_storage(
        tmpdir_initial, tmpdir_final, str(tmpdir), byte_limit, inode_limit,
        "Source5 Soak construction probe",
    )
    probe_after = readback._proc_process_identity(direct["start"]["pid"])
    probe_after_start = None if probe_after is None else probe_after["start_ticks"]
    require(probe_after_start != direct["start"]["start_ticks"],
            "Source5 ProbeV1 owner returned while its original PID/start remained live")
    require(len(canonical_bytes(direct)) <= budgets["runtime_receipt_bytes"],
            "Source5 ProbeV1 process-owner result exceeded its frozen receipt budget")
    if process_pin is None:
        process_pin = _write_exclusive_json(owner_path_out, direct,
                                            "Source5 ProbeV1 process-owner result")
    tmpdir_record = {
        "initial": tmpdir_initial, "final": tmpdir_final,
        "output_mount": owner._mount_identity(capture_root),
        "byte_limit": byte_limit, "inode_limit": inode_limit,
    }
    capture = {
        "schema": PROBE_CAPTURE_SCHEMA,
        "source_manifest_raw_sha256": prepared["source_manifest_raw_refs"][prepared["host_id"]]["raw_sha256"],
        "source_tree_sha256": prepared["source"]["source"]["source_tree_sha256"],
        "normal_binary_sha256": normal_sha,
        "probe_raw_sha256": probe_raw_sha,
        "owner_source_sha256": owner_sha,
        "owner_source_path": str(owner_path),
        "owner_result_pin": process_pin,
        "stdout": {"path": str(stdout_path), "raw_sha256": stdout_sha},
        "stderr": {"path": str(stderr_path), "raw_sha256": stderr_sha},
        "argv": argv, "environment": environment, "cwd": str(source_root),
        "cpu_affinity": affinity, "network_namespace_inode": network_inode,
        "tmpdir_path": str(tmpdir), "tmpdir_receipt": tmpdir_record,
        "capture_budgets": {
            "stdout_bytes": budgets["construction_probe_stdout_bytes"],
            "stderr_bytes": budgets["construction_probe_stderr_bytes"],
            "tmpdir_bytes": byte_limit,
            "tmpdir_inodes": inode_limit,
            "output_bytes": output_byte_bound,
            "output_inodes": output_inode_bound,
            "deadline_seconds": int(owner.PROBE_TIMEOUT_SECONDS),
            "owner_receipt_bytes": process_receipt_limit,
            "capture_receipt_bytes": min(
                budgets["runtime_receipt_bytes"],
                (resource_budget["artifact_limits"]["probe_capture_receipt_bytes"]
                 if resource_budget is not None else
                 budgets["runtime_receipt_bytes"]),
            ),
        },
        "process_absence": {
            "pid": direct["start"]["pid"],
            "start_ticks": direct["start"]["start_ticks"],
            "original_identity_absent": True,
            "observed_start_ticks": probe_after_start,
        },
    }
    capture["capture_sha256"] = sha256(canonical_bytes(capture))
    capture_receipt_limit = min(
        budgets["runtime_receipt_bytes"],
        (resource_budget["artifact_limits"]["probe_capture_receipt_bytes"]
         if resource_budget is not None else budgets["runtime_receipt_bytes"]),
    )
    require(len(canonical_bytes(capture)) <= capture_receipt_limit,
            "Source5 ProbeV1 capture receipt exceeded its frozen receipt budget")
    capture_pin = _write_exclusive_json(
        capture_root / "probe-capture.json", capture,
        "Source5 Soak ProbeV1 capture receipt",
    )
    capture_pin["capture_sha256"] = capture["capture_sha256"]
    return capture, capture_pin, None


def _capture_source5_soak_probe_monitored(
    prepared: dict[str, Any], job: dict[str, Any], binding: dict[str, Any],
    recipe: dict[str, Any], readback: types.ModuleType,
    resource_budget: dict[str, Any],
    resource_monitor: Any,
) -> tuple[dict[str, Any], dict[str, str], dict[str, Any] | None]:
    """Monitor SourceV5 probe setup, then the accepted owner's live interval."""
    require(resource_monitor.sample("preflight", force=True) is False,
            "Source5 resource monitor refused before the construction-probe owner")
    capture: dict[str, Any] | None = None
    capture_pin: dict[str, str] | None = None
    probe_context: dict[str, Any] | None = None
    owner_gate = [True]
    owner_started = [False]
    phase_lock = threading.Lock()
    stop_sampler = threading.Event()
    sampler_errors: list[BaseException] = []
    interval_seconds = (
        resource_budget["schedule"]["resource_monitor_interval_ms"] / 1000
    )

    def sample_probe_setup() -> None:
        while not stop_sampler.wait(interval_seconds):
            try:
                with phase_lock:
                    if owner_started[0]:
                        return
                    if resource_monitor.sample("preflight"):
                        return
            except BaseException as error:
                sampler_errors.append(error)
                return

    sampler = threading.Thread(
        target=sample_probe_setup,
        name="source5-soak-probe-setup-monitor",
        daemon=True,
    )
    sampler.start()

    def monitor_probe_owner() -> bool:
        with phase_lock:
            if owner_gate[0]:
                owner_gate[0] = False
                owner_started[0] = True
                return resource_monitor.sample("probe_capture", force=True)
            return resource_monitor.sample("probe_capture")

    operation_error: BaseException | None = None
    try:
        capture, capture_pin, probe_context = _capture_source5_soak_probe(
            prepared, job, binding, recipe, readback,
            resource_budget["layout"]["probe_capture_root"],
            resource_budget=resource_budget,
            resource_monitor=monitor_probe_owner,
        )
    except BaseException as error:
        operation_error = error
    finally:
        stop_sampler.set()
        sampler.join()
        if sampler_errors:
            resource_monitor.failure = resource_monitor.failure or (
                f"probe_setup_monitor:{type(sampler_errors[0]).__name__}:"
                f"{sampler_errors[0]}"
            )[:4096]
        final_phase = "probe_capture" if owner_started[0] else "preflight"
        try:
            resource_monitor.sample(final_phase, force=True)
        except BaseException as error:
            resource_monitor.failure = resource_monitor.failure or (
                f"probe_capture_final_sample:{type(error).__name__}:{error}"
            )[:4096]
    if operation_error is not None:
        raise operation_error
    require(owner_started[0],
            "Source5 probe capture returned without entering its monitored owner interval")
    if resource_monitor.failure is not None:
        raise Source5SoakError(
            f"Source5 resource monitor stopped the owned ProbeV2 capture: "
            f"{resource_monitor.failure}",
        )
    require(capture is not None and capture_pin is not None,
            "Source5 ProbeV2 owner returned no capture receipt")
    return capture, capture_pin, probe_context


def _run_source5_preflight_monitored(
    operation: Any, budget: dict[str, Any], resource_monitor: Any, *,
    phase: str = "preflight_audit",
) -> Any:
    """Keep the held-root monitor sampling through one bounded owner phase."""
    stop = threading.Event()
    sampler_error: list[BaseException] = []
    interval_seconds = budget["schedule"]["resource_monitor_interval_ms"] / 1000

    def sample_until_operation_returns() -> None:
        try:
            while not stop.wait(interval_seconds):
                if resource_monitor.sample(phase):
                    return
        except BaseException as error:
            sampler_error.append(error)

    thread = threading.Thread(
        target=sample_until_operation_returns,
        name=f"source5-soak-resource-monitor-{phase}",
        daemon=True,
    )
    thread.start()
    result: Any = None
    operation_error: BaseException | None = None
    try:
        result = operation()
    except BaseException as error:
        operation_error = error
    finally:
        stop.set()
        thread.join()
        if sampler_error:
            resource_monitor.failure = resource_monitor.failure or (
                f"preflight_monitor_thread:{type(sampler_error[0]).__name__}:"
                f"{sampler_error[0]}"
            )[:4096]
        try:
            resource_monitor.sample(phase, force=True)
        except BaseException as error:
            resource_monitor.failure = resource_monitor.failure or (
                f"{phase}_monitor_final_sample:{type(error).__name__}:{error}"
            )[:4096]
    if operation_error is not None:
        resource_monitor.failure = resource_monitor.failure or (
            f"{phase}:{type(operation_error).__name__}:{operation_error}"
        )[:4096]
    if resource_monitor.failure is not None:
        if resource_monitor.fd is not None:
            try:
                resource_monitor.finish(resource_monitor.last_usage)
            except BaseException:
                pass
        message = f"Source5 bounded {phase} monitor failed: {resource_monitor.failure}"
        if operation_error is not None:
            raise Source5SoakError(f"{message}; preflight also failed: {operation_error}") from operation_error
        raise Source5SoakError(message)
    if operation_error is not None:
        raise operation_error
    return result


def finish_source5_soak_monitor_failure(
    preflight_value: object, error: BaseException,
) -> dict[str, Any] | None:
    """Close and retain the live monitor when the locked caller catches failure."""
    require(type(preflight_value) is dict and
            preflight_value.get("schema") ==
                "allocatbelt.application-source5-soak-preflight.v2",
            "Source5 failure monitor finalization requires bounded preflight context")
    monitor = preflight_value.get("resource_monitor")
    require(monitor is not None and
            callable(getattr(monitor, "sample", None)) and
            callable(getattr(monitor, "finish", None)),
            "Source5 failure monitor owner is unavailable")
    if monitor.fd is None:
        return monitor.final_summary
    monitor.failure = monitor.failure or (
        f"authorized_soak_failure:{type(error).__name__}:{error}"
    )[:4096]
    try:
        monitor.sample("postflight", force=True)
    except BaseException as sample_error:
        monitor.failure = monitor.failure or (
            f"failure_monitor_final_sample:{type(sample_error).__name__}:"
            f"{sample_error}"
        )[:4096]
    try:
        return monitor.finish(monitor.last_usage)
    except BaseException:
        return None


def run_source5_soak(
    preflight_value: dict[str, Any], on_started, on_cleanup,
) -> dict[str, Any]:
    """Launch the one original APP through the captured V2 callback API."""
    require(type(preflight_value) is dict,
            "Source5 Soak preflight context must be an object")
    preflight_keys = {
        "schema", "materials_index", "materials_index_pin", "helper_input",
        "parent_recipe",
        "parent_recipe_pin", "build_receipt_pin", "identities", "audit",
        "preflight", "preflight_pin", "launch_overlay", "launch_overlay_pin",
        "base_audit", "base_audit_sha256", "args", "output_dir",
        "readback_module", "prepared", "details",
    }
    if preflight_value.get("schema") == \
            "allocatbelt.application-source5-soak-preflight.v2":
        preflight_keys |= {
            "resource_budget", "resource_budget_pin", "probe_capture",
            "probe_capture_pin", "probe_capture_context",
            "initial_resource_usage", "resource_monitor",
        }
    preflight = exact(preflight_value, preflight_keys,
                      "Source5 Soak preflight context")
    require(preflight["schema"] in {
                "allocatbelt.application-source5-soak-preflight.v1",
                "allocatbelt.application-source5-soak-preflight.v2",
            } and
            callable(on_started) and callable(on_cleanup),
            "Source5 Soak launch lacks its preflight or lifecycle callbacks")
    readback = preflight["readback_module"]
    resource_monitor = (
        preflight["resource_monitor"]
        if preflight["schema"] ==
        "allocatbelt.application-source5-soak-preflight.v2" else None
    )
    resource_monitor_summary = None
    output_dir = Path(preflight["output_dir"])
    args = preflight["args"]
    started: list[dict[str, Any]] = []
    cleanups: list[dict[str, Any]] = []
    terminal_events: list[dict[str, Any]] = []
    identity = preflight["parent_recipe"]["identity"]
    descriptor = soak_descriptor(preflight["materials_index"]["job"])

    def started_callback(attestation: dict[str, Any]) -> None:
        require(type(attestation) is dict and
                attestation.get("schema") ==
                "allocatbelt.application-pressure-app-launch-attestation.v1",
                "captured supervisor APP-start callback is malformed")
        process = exact(attestation.get("process"), {
            "pid", "start_ticks", "executable_path", "executable_sha256",
            "executable_device", "executable_inode", "executable_size",
            "executable_fd_reference", "cwd", "argv", "argv_sha256",
            "cmdline_raw_sha256", "environment_sha256", "environment_raw_sha256",
        }, "captured supervisor APP process attestation")
        body = {key: value for key, value in attestation.items()
                if key != "attestation_sha256"}
        require(attestation.get("attestation_sha256") == sha256(canonical_bytes(body)) and
                type(process["pid"]) is int and process["pid"] > 0 and
                type(process["start_ticks"]) is int and process["start_ticks"] > 0 and
                process["executable_sha256"] ==
                    preflight["parent_recipe"]["identity"]["binary_sha256"] and
                process["argv"] == preflight["audit"]["launch_descriptor"]["argv"] and
                process["environment_sha256"] ==
                    preflight["audit"]["launch_descriptor"]["environment_sha256"],
                "captured supervisor APP-start attestation differs from the frozen recipe")
        event = {
            "campaign_id": identity["campaign_id"],
            "host_id": identity["host_id"],
            "run_id": identity["run_id"],
            "descriptor": descriptor,
            "member_ordinal": 0,
            "proof": {
                "pid": process["pid"],
                "start_ticks": process["start_ticks"],
                "launch_attestation": attestation,
            },
        }
        started.append(attestation)
        on_started(event)

    def cleanup_callback(cleanup: dict[str, Any]) -> None:
        exact(cleanup, {
            "schema", "status", "pid", "return_code", "received_signal",
            "cleanup_error",
        }, "captured supervisor APP cleanup callback")
        require(cleanup["schema"] == "allocatbelt.application-soak-process-cleanup.v1" and
                cleanup["status"] in {"verified", "failed"} and
                type(cleanup["pid"]) is int and cleanup["pid"] > 0,
                "captured supervisor APP cleanup callback identity differs")
        cleanups.append(cleanup)
        raw_return = cleanup["return_code"]
        status, observed_signal = normalize_cleanup_status(cleanup)
        event = {
            "campaign_id": identity["campaign_id"],
            "host_id": identity["host_id"],
            "run_id": identity["run_id"],
            "descriptor": descriptor,
            "member_ordinal": 0,
            "pid": cleanup["pid"],
            "status": status,
            "child_return_code": raw_return,
            "signal": observed_signal if type(observed_signal) is int else None,
            "cleanup": {
                "status": cleanup["status"],
                "application_cleanup": cleanup,
                "pressure_cleanup": "pending",
            },
            "terminal_monotonic_ns": time.monotonic_ns(),
        }
        terminal_events.append(event)
        on_cleanup(event)

    if preflight["schema"] == \
            "allocatbelt.application-source5-soak-preflight.v2":
        receipt = readback.launch_soak_v2_application(
            args, preflight["audit"], preflight["preflight"], output_dir,
            started_callback, cleanup_callback,
            resource_budget_pin=preflight["resource_budget_pin"],
            resource_monitor_context=preflight["resource_monitor"],
        )
    else:
        receipt = readback.launch_soak_v2_application(
            args, preflight["audit"], preflight["preflight"], output_dir,
            started_callback, cleanup_callback,
        )
    receipt_keys = {
        "schema", "execution_kind", "status", "interrupted", "received_signal",
        "application_cleanup", "application_binding", "application_binding_sha256",
        "application_attestation", "pressure_ready_sha256", "pressure_proof",
        "pressure_cleanup", "pressure_driver", "pressure_worker_sessions", "details",
    }
    exact(receipt, receipt_keys, "captured Source5 Soak supervisor receipt")
    require(receipt["schema"] == "allocatbelt.application-pressure-supervision.v1" and
            receipt["execution_kind"] == "timed_soak" and
            len(started) == len(cleanups) == len(terminal_events) == 1 and
            receipt["application_attestation"] == started[0] and
            receipt["application_cleanup"] == cleanups[0] and
            terminal_events[0]["pid"] == cleanups[0]["pid"] and
            terminal_events[0]["child_return_code"] ==
                cleanups[0]["return_code"],
            "captured Soak supervisor receipt differs from its direct APP callbacks")
    if preflight["schema"] == \
            "allocatbelt.application-source5-soak-preflight.v2":
        require(len(canonical_bytes(receipt)) <=
                preflight["resource_budget"]["artifact_limits"][
                    "source5_supervisor_bytes"],
                "Source5 Soak supervisor receipt exceeds its frozen artifact limit")
    supervisor_pin = _write_exclusive_json(
        output_dir / "source5-soak-supervisor.json", receipt,
        "Source5 Soak supervisor receipt",
    )
    details = receipt["details"]
    require(type(details) is dict,
            "Source5 Soak supervisor omitted the direct child terminal record")
    terminal_event = terminal_events[0]
    terminal_event["cleanup"] = {
        "status": "verified" if cleanups[0]["status"] == "verified" and
                  receipt["pressure_cleanup"] == "verified" else
                  "failed" if cleanups[0]["status"] == "failed" or
                  receipt["pressure_cleanup"] == "failed" else "unverified",
        "application_cleanup": cleanups[0],
        "pressure_cleanup": receipt["pressure_cleanup"],
        "timed_out": details["timed_out"],
        "artifact_budget_exceeded": details["artifact_budget_exceeded"],
    }
    pins = {
        "materials_index": preflight["materials_index_pin"],
        "parent_recipe": preflight["parent_recipe_pin"],
        "build_receipt": preflight["build_receipt_pin"],
        "preflight": preflight["preflight_pin"],
        "launch_authorization": preflight["launch_overlay_pin"],
        "supervisor": supervisor_pin,
        "launch": None, "postflight": None, "readback": None,
    }
    if preflight["schema"] == \
            "allocatbelt.application-source5-soak-preflight.v2":
        pins["resource_budget"] = preflight["resource_budget_pin"]
        pins["probe_capture"] = preflight["probe_capture_pin"]
        for role, filename in (
            ("application_owner", "source5-soak-application-owner-return.json"),
            ("pressure_owner", "source5-soak-pressure-owner-return.json"),
        ):
            owner_path = output_dir / filename
            if owner_path.exists() and not owner_path.is_symlink():
                _owner_raw, owner_sha, _owner_info = read_stable(
                    owner_path, f"Source5 {role} return receipt", MAX_RECEIPT_BYTES,
                )
                pins[role] = {"path": str(owner_path),
                              "raw_sha256": owner_sha}
            else:
                pins[role] = None
    launch_path = output_dir / "soak-launch.json"
    if launch_path.exists() and not launch_path.is_symlink():
        _raw, launch_sha, _info = read_stable(
            launch_path, "Source5 Soak launch receipt", MAX_RECEIPT_BYTES,
        )
        pins["launch"] = {"path": str(launch_path), "raw_sha256": launch_sha}
        if preflight["schema"] == \
                "allocatbelt.application-source5-soak-preflight.v2":
            launch_value, _launch_raw, _launch_sha = read_json(
                launch_path, launch_sha, "Source5 bounded Soak launch receipt",
                MAX_RECEIPT_BYTES,
            )
            require(launch_value.get("schema") ==
                        "allocatbelt.application-soak-launch.v3" and
                    launch_value.get("resource_budget") ==
                        preflight["resource_budget_pin"] and
                    launch_value.get("resource_monitor_prefix", {}).get("budget") ==
                        preflight["resource_budget_pin"],
                    "Source5 bounded launch receipt does not bind its live monitor prefix")

    validated = False
    passed = False
    readback_value: dict[str, Any] | None = None

    def finish_postflight_monitor() -> dict[str, Any] | None:
        if resource_monitor is None:
            return None
        if resource_monitor.fd is not None:
            resource_monitor.sample("postflight", force=True)
            summary = resource_monitor.finish(resource_monitor.last_usage)
        else:
            summary = resource_monitor.final_summary
        require(type(summary) is dict and summary.get("failure") is None,
                "Source5 Soak resource monitor failed during owner or postflight checks")
        return summary

    if receipt["status"] == 0 and receipt["interrupted"] is False and \
            receipt["application_cleanup"]["status"] == "verified" and \
            receipt["pressure_cleanup"] == "verified" and pins["launch"] is not None:
        probe_context = preflight.get("probe_capture_context")
        audit_after, preflight_after = (
            _run_source5_preflight_monitored(
                lambda: (readback._current_audit(args)
                         if probe_context is None else
                         readback._current_audit(
                             args, source5_probe_capture=probe_context,
                         )),
                preflight["resource_budget"], resource_monitor,
                phase="postflight",
            ) if resource_monitor is not None else
            (readback._current_audit(args) if probe_context is None else
             readback._current_audit(
                 args, source5_probe_capture=probe_context,
             ))
        )
        require(_base_readback_audit_sha256(audit_after) ==
                preflight["base_audit_sha256"],
                "captured legacy SourceV5 audit changed after the one-use Soak launch")
        overlay_operation = lambda: build_source5_launch_overlay(
            preflight["helper_input"], preflight["prepared"],
            preflight["details"], preflight["materials_index"],
            _selected_prepared_host_binding(
                preflight["prepared"]["source5_prepared_input_completion"],
                preflight["prepared"]["host_id"],
            ),
            preflight["parent_recipe"], preflight["identities"], args,
            audit_after, preflight_after, readback,
            source5_probe_capture=probe_context,
        )
        overlay_after, overlay_audit_after, overlay_preflight_after = (
            _run_source5_preflight_monitored(
                overlay_operation, preflight["resource_budget"],
                resource_monitor, phase="postflight",
            ) if resource_monitor is not None else overlay_operation()
        )
        require(overlay_after == preflight["launch_overlay"] and
                _base_readback_audit_sha256(preflight["base_audit"]) ==
                    preflight["base_audit_sha256"],
                "Source5 Soak launch authorization overlay changed after APP cleanup")
        launch_receipt, launch_sha = (
            _run_source5_preflight_monitored(
                lambda: readback._verify_launch_receipt(
                    readback._check_private_output_directory(output_dir),
                    overlay_audit_after, overlay_preflight_after,
                    require_success=True,
                ),
                preflight["resource_budget"], resource_monitor,
                phase="postflight",
            ) if resource_monitor is not None else
            readback._verify_launch_receipt(
                readback._check_private_output_directory(output_dir),
                overlay_audit_after, overlay_preflight_after,
                require_success=True,
            )
        )
        overlay_audit_after["launch_receipt"] = launch_receipt
        legacy_postflight_writer = lambda: readback._write_verify_inputs_postflight(
            overlay_audit_after, overlay_preflight_after,
            readback._check_private_output_directory(output_dir), launch_sha,
        )
        _legacy_postflight_sha, _legacy_postflight_value = (
            _run_source5_preflight_monitored(
                legacy_postflight_writer, preflight["resource_budget"],
                resource_monitor, phase="postflight",
            ) if resource_monitor is not None else legacy_postflight_writer()
        )
        if resource_monitor is not None:
            _check_budget_file(
                output_dir / "soak-postflight.json",
                preflight["resource_budget"]["artifact_limits"][
                    "postflight_receipt_bytes"],
                "Source5 legacy Soak input-stability receipt",
            )
        readback._verify_verify_inputs_postflight(
            overlay_audit_after, overlay_preflight_after, output_dir,
            launch_sha,
        )
        readback_value = (
            _run_source5_preflight_monitored(
                lambda: readback._validate_artifacts(
                    readback._check_private_output_directory(output_dir),
                    overlay_audit_after,
                ),
                preflight["resource_budget"], resource_monitor,
                phase="postflight",
            ) if resource_monitor is not None else
            readback._validate_artifacts(
                readback._check_private_output_directory(output_dir),
                overlay_audit_after,
            )
        )
        require(readback_value.get("schema") == READBACK_SCHEMA and
                readback_value.get("validated") is True and
                readback_value.get("passed") is True and
                readback_value.get("qualification_eligible") is
                    (preflight["parent_recipe"]["runtime"]["mode"] == "qualified"),
                "captured Soak V2 failed its original full-horizon numeric/RSS gates")
        if preflight["schema"] == \
                "allocatbelt.application-source5-soak-preflight.v2":
            require(len(canonical_bytes(readback_value)) <=
                    preflight["resource_budget"]["artifact_limits"][
                        "readback_receipt_bytes"],
                    "Source5 Soak readback result exceeds its frozen artifact limit")
        readback_path = output_dir / "soak-readback.json"
        readback_pin = _write_exclusive_json(
            readback_path, readback_value, "Source5 Soak V2 readback result",
        )
        pins["readback"] = readback_pin
        resource_monitor_summary = finish_postflight_monitor()
        postflight_body = {
            "schema": (POSTFLIGHT_SCHEMA if resource_monitor is None else
                       POSTFLIGHT_SCHEMA_V2),
            "campaign_id": preflight["parent_recipe"]["identity"]["campaign_id"],
            "host_id": preflight["parent_recipe"]["identity"]["host_id"],
            "run_id": preflight["parent_recipe"]["identity"]["run_id"],
            "base_legacy_audit_sha256_before": preflight["base_audit_sha256"],
            "base_legacy_audit_sha256_after":
                _base_readback_audit_sha256(audit_after),
            "launch_authorization": preflight["launch_overlay_pin"],
            "baseline_preflight": preflight["preflight_pin"],
            "launch_receipt_sha256": launch_sha,
            "readback": readback_pin,
            "inputs_unchanged": True,
            "campaign_qualification_eligible": False,
        }
        if resource_monitor is not None:
            postflight_body["resource_budget"] = preflight["resource_budget_pin"]
            postflight_body["resource_monitor"] = resource_monitor_summary
        postflight_body["postflight_sha256"] = sha256(canonical_bytes(postflight_body))
        if resource_monitor is not None:
            require(len(canonical_bytes(postflight_body)) <=
                    preflight["resource_budget"]["artifact_limits"][
                        "postflight_receipt_bytes"],
                    "Source5 Soak postflight exceeds its frozen artifact limit")
        pins["postflight"] = _write_exclusive_json(
            output_dir / "source5-soak-postflight.json", postflight_body,
            "Source5 Soak-only postflight receipt",
        )
        validated = True
        passed = readback_value["passed"]

    if resource_monitor is not None and resource_monitor_summary is None:
        resource_monitor_summary = finish_postflight_monitor()

    component = {
        "schema": (COMPONENT_SCHEMA if resource_monitor is None else
                   COMPONENT_SCHEMA_V2),
        "campaign_id": preflight["parent_recipe"]["identity"]["campaign_id"],
        "host_id": preflight["parent_recipe"]["identity"]["host_id"],
        "run_id": preflight["parent_recipe"]["identity"]["run_id"],
        "validated": validated,
        "passed": passed,
        "qualification_eligible": False,
        "launch_enabled": True,
        "prepared_host_binding_sha256":
            preflight["identities"]["prepared_host_binding_sha256"],
        "pins": pins,
        "application_attestation": started[0],
        "application_cleanup": cleanups[0],
        "pressure_cleanup": receipt["pressure_cleanup"],
        "terminal_event": terminal_event,
        "readback": readback_value,
        "supervisor_sha256": supervisor_pin["raw_sha256"],
    }
    if resource_monitor is not None:
        component["resource_budget"] = preflight["resource_budget_pin"]
        component["probe_capture"] = preflight["probe_capture_pin"]
        component["resource_monitor"] = resource_monitor_summary
        pins["resource_monitor"] = resource_monitor_summary["stream"]
    return component


def _verify_source5_soak_component_replay(
    component: dict[str, Any], prepared: dict[str, Any],
    job: dict[str, Any], authorization_context: dict[str, Any],
    readback: types.ModuleType, *,
    offline_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Replay the raw false legacy audit, Soak-only authorization and full V2 gate."""
    require(type(component) is dict,
            "Source5 Soak component must be an object")
    bounded = component.get("schema") == COMPONENT_SCHEMA_V2
    component_fields = {
        "schema", "campaign_id", "host_id", "run_id", "validated", "passed",
        "qualification_eligible", "launch_enabled", "prepared_host_binding_sha256",
        "pins", "application_attestation", "application_cleanup", "pressure_cleanup",
        "terminal_event", "readback", "supervisor_sha256",
    }
    if bounded:
        component_fields |= {"resource_budget", "probe_capture", "resource_monitor"}
    exact(component, component_fields, "Source5 Soak component")
    require(component["schema"] in {COMPONENT_SCHEMA, COMPONENT_SCHEMA_V2} and
            component["campaign_id"] == prepared["campaign_id"] and
            component["host_id"] == prepared["host_id"] and
            component["run_id"] == job["run_id"] and
            component["validated"] is True and component["passed"] is True and
            component["qualification_eligible"] is False and
            component["launch_enabled"] is True,
            "Source5 Soak component identity/status/outer eligibility differs")
    pin_fields = {
        "materials_index", "parent_recipe", "build_receipt", "preflight",
        "launch_authorization", "supervisor", "launch", "postflight", "readback",
    }
    if bounded:
        pin_fields |= {
            "resource_budget", "probe_capture", "resource_monitor",
            "application_owner", "pressure_owner",
        }
    pins = exact(component["pins"], pin_fields, "Source5 Soak component pins")
    materials_pin = raw_pin(pins["materials_index"], "Source5 Soak materials index")
    material_index, _index_raw, _index_sha = read_json(
        Path(materials_pin["path"]), materials_pin["raw_sha256"],
        "Source5 Soak materials index", MAX_ARTIFACT_BYTES,
    )
    binding = _selected_prepared_host_binding(
        prepared["source5_prepared_input_completion"], prepared["host_id"],
    )
    probe_capture_context = None
    budget_document = None
    monitor_replay = None
    probe_owner_interval = None
    if bounded:
        budget_document, budget_pin = _read_resource_budget_pin(
            component["resource_budget"],
        )
        require(material_index["schema"] == MATERIALS_INDEX_SCHEMA_V2 and
                budget_pin == component["resource_budget"] ==
                    pins["resource_budget"] and
                component["probe_capture"] == pins["probe_capture"] and
                resource_budget_pin(component["resource_monitor"]["budget"]) ==
                    budget_pin and
                pins["resource_monitor"] ==
                    component["resource_monitor"]["stream"] and
                type(pins["application_owner"]) is dict and
                type(pins["pressure_owner"]) is dict,
                "Source5 bounded component budget/probe/monitor pins differ")
        launch_pin_preview = raw_pin(
            pins["launch"], "Source5 bounded launch receipt prefix source",
        )
        launch_preview, _launch_preview_raw, _launch_preview_sha = read_json(
            Path(launch_pin_preview["path"]), launch_pin_preview["raw_sha256"],
            "Source5 bounded launch receipt prefix source",
            budget_document["artifact_limits"]["launch_receipt_bytes"],
        )
        require(launch_preview.get("schema") == LAUNCH_SCHEMA_V3,
                "Source5 bounded component launch receipt lacks the v3 live-prefix binding")
        monitor_replay = _verify_source5_resource_monitor_stream(
            budget_document, budget_pin, component["resource_monitor"],
            launch_preview.get("resource_monitor_prefix"),
        )
        recipe_for_probe, _receipt_for_probe, _identities_for_probe = \
            _verify_build_receipt(
                material_index, prepared, job, binding, readback,
            )
        if recipe_for_probe["feedback_expectation"]["policy"].get(
                "capacity_floor_policy_id") is not None:
            if offline_context is None:
                probe_capture_context, _probe_pin = _source5_probe_v2_audit_context(
                    prepared, recipe_for_probe, component["probe_capture"],
                )
            else:
                probe_capture_context = exact(
                    offline_context.get("construction_probe_capture"), {
                        "schema", "capture_pin", "capture", "probe", "probe_raw",
                        "probe_raw_sha256", "capacity_bundle",
                        "capacity_floor_policy_id", "normal_binary_sha256", "request",
                    }, "Source5 offline selected ProbeV2 replay context",
                )
        else:
            probe_pin = component["probe_capture"]
            probe_capture, _probe_raw, _probe_sha = read_json(
                Path(probe_pin["path"]), probe_pin["raw_sha256"],
                "Source5 bounded original ProbeV1 receipt",
                budget_document["artifact_limits"]["probe_capture_receipt_bytes"],
            )
            probe_capture_context = {
                "capture": probe_capture, "capture_pin": probe_pin,
            }
        _verify_source5_probe_resource_budget(
            budget_document, prepared, probe_capture_context,
        )
        probe_owner_interval = _source5_probe_owner_interval(
            prepared, probe_capture_context, budget_document,
        )
    _, recipe, identities = _verify_build_receipt(
        material_index, prepared, job, binding, readback,
    )
    require(identities["prepared_host_binding_sha256"] ==
            component["prepared_host_binding_sha256"] and
            pins["parent_recipe"] == material_index["parent_recipe"] and
            pins["build_receipt"] == material_index["build_receipt"],
            "Source5 Soak recipe/preparation pins differ from the full completion replay")
    output_dir = Path(pins["supervisor"]["path"]).parent.resolve(strict=True)
    args = _readback_args(recipe, pins["parent_recipe"], output_dir)
    if offline_context is None:
        base_audit, base_preflight = (
            readback._current_audit(args)
            if probe_capture_context is None else
            readback._current_audit(
                args, source5_probe_capture=probe_capture_context,
            )
        )
    else:
        base_audit, base_preflight = readback._current_audit_offline(
            args, offline_context,
        )
    require(base_audit["launch_enabled"] is False and
            base_preflight["launch_enabled"] is False,
            "fresh captured reader audit changed its preserved false legacy readiness")
    helper_input_pin = raw_pin(authorization_context["helper_input"],
                               "Source5 Soak helper input")
    helper_input, _helper_raw, _helper_sha = read_json(
        Path(helper_input_pin["path"]), helper_input_pin["raw_sha256"],
        "Source5 Soak helper input", MAX_ARTIFACT_BYTES,
    )
    require(authorization_context.get("phase") == "soak" and
            authorization_context.get("job") == job and
            authorization_context.get("helper_input") == helper_input_pin and
            type(helper_input.get("payload")) is dict and
            raw_pin(helper_input.get("payload", {}).get("materials_index"),
                    "Source5 authorized material index") == materials_pin,
            "Source5 Soak component differs from its original one-use helper/material authorization")
    overlay, overlay_audit, overlay_preflight = build_source5_launch_overlay(
        helper_input, prepared, authorization_context, material_index, binding,
        recipe, identities, args, base_audit, base_preflight, readback,
        path_value=(None if offline_context is None else
                    offline_context["application_environment"]["PATH"]),
        source5_probe_capture=probe_capture_context,
    )
    if offline_context is not None:
        actual_environment = offline_context["application_environment"]
        require(type(actual_environment) is dict and
                type(actual_environment.get("PATH")) is str and
                bool(actual_environment["PATH"]) and
                overlay_audit["launch_descriptor"]["environment"] ==
                    actual_environment,
                "Source5 offline actual APP environment differs from its reconstructed enabled overlay")
    overlay_pin = raw_pin(pins["launch_authorization"],
                          "Source5 Soak launch authorization")
    overlay_path = Path(overlay_pin["path"])
    stored_overlay, overlay_raw, overlay_sha = read_json(
        overlay_path, overlay_pin["raw_sha256"],
        "Source5 Soak launch authorization", MAX_RECEIPT_BYTES,
    )
    require(overlay_path == output_dir / "source5-soak-launch-authorization.json" and
            overlay_sha == overlay_pin["raw_sha256"] and
            overlay_raw == canonical_bytes(stored_overlay) == canonical_bytes(overlay),
            "Source5 Soak launch overlay differs from the fresh authorization/source replay")
    preflight_pin = raw_pin(pins["preflight"], "Source5 baseline preflight")
    require(preflight_pin == overlay["base_preflight"] and
            preflight_pin["path"] == str(output_dir / "soak-preflight.json") and
            overlay["base_audit_sha256"] == _base_readback_audit_sha256(base_audit),
            "Source5 Soak baseline audit/preflight pin differs from its launch overlay")
    launch_receipt, launch_sha = readback._verify_launch_receipt(
        readback._check_private_output_directory(output_dir),
        overlay_audit, overlay_preflight, require_success=True,
    )
    if bounded:
        require(launch_receipt["resource_budget"] == budget_pin and
                launch_receipt.get("schema") == LAUNCH_SCHEMA_V3 and
                launch_receipt["resource_monitor_prefix"]["budget"] ==
                    budget_pin and
                details["resource_budget_exceeded"] is
                    launch_receipt["resource_budget_exceeded"] and
                (details["resource_monitor_error"] is None or
                 type(details["resource_monitor_error"]) is str) and
                launch_receipt["resource_monitor_prefix"]["path"] ==
                    pins["resource_monitor"]["path"],
                "Source5 bounded launch receipt differs from the component monitor prefix")
    readback._verify_verify_inputs_postflight(
        overlay_audit, overlay_preflight, output_dir, launch_sha,
    )
    require(pins["launch"] == {
        "path": str(output_dir / "soak-launch.json"), "raw_sha256": launch_sha,
    }, "Source5 Soak launch receipt differs from its raw pin")
    postflight_pin = raw_pin(pins["postflight"], "Source5 Soak-only postflight")
    postflight, postflight_raw, _postflight_sha = read_json(
        Path(postflight_pin["path"]), postflight_pin["raw_sha256"],
        "Source5 Soak-only postflight", MAX_RECEIPT_BYTES,
    )
    postflight_fields = {
        "schema", "campaign_id", "host_id", "run_id",
        "base_legacy_audit_sha256_before", "base_legacy_audit_sha256_after",
        "launch_authorization", "baseline_preflight", "launch_receipt_sha256",
        "readback", "inputs_unchanged", "campaign_qualification_eligible",
        "postflight_sha256",
    }
    if bounded:
        postflight_fields |= {"resource_budget", "resource_monitor"}
    exact(postflight, postflight_fields, "Source5 Soak postflight receipt")
    postflight_body = {key: value for key, value in postflight.items()
                       if key != "postflight_sha256"}
    require(postflight_pin["path"] ==
                str(output_dir / "source5-soak-postflight.json") and
            postflight["schema"] == (POSTFLIGHT_SCHEMA_V2 if bounded else
                                     POSTFLIGHT_SCHEMA) and
            postflight_raw == canonical_bytes(postflight) and
            postflight["postflight_sha256"] == sha256(canonical_bytes(postflight_body)) and
            postflight["base_legacy_audit_sha256_before"] ==
                postflight["base_legacy_audit_sha256_after"] ==
                overlay["base_audit_sha256"] and
            postflight["launch_authorization"] == overlay_pin and
            postflight["baseline_preflight"] == preflight_pin and
            postflight["launch_receipt_sha256"] == launch_sha and
            postflight["readback"] == pins["readback"] and
            postflight["inputs_unchanged"] is True and
            postflight["campaign_qualification_eligible"] is False,
            "Source5 Soak postflight does not bind unchanged inputs and the overlay launch")
    if bounded:
        require(postflight["resource_budget"] == budget_pin and
                postflight["resource_monitor"] == component["resource_monitor"],
                "Source5 bounded postflight changed its budget/monitor evidence")
    overlay_audit["launch_receipt"] = launch_receipt
    if offline_context is None:
        fresh = readback._validate_artifacts(
            readback._check_private_output_directory(output_dir), overlay_audit,
        )
    else:
        fresh = readback._validate_artifacts_offline(
            readback._check_private_output_directory(output_dir), overlay_audit,
            offline_context,
        )
    readback_pin = raw_pin(pins["readback"], "Source5 V2 readback result")
    readback_value, _readback_raw, readback_sha = read_json(
        Path(readback_pin["path"]), readback_pin["raw_sha256"],
        "Source5 V2 readback result", MAX_RECEIPT_BYTES,
    )
    require(readback_pin == {
                "path": str(output_dir / "soak-readback.json"),
                "raw_sha256": readback_sha,
            } and fresh == readback_value == component["readback"] and
            readback_value.get("validated") is True and
            readback_value.get("passed") is True and
            readback_value.get("qualification_eligible") is
                (recipe["runtime"]["mode"] == "qualified"),
            "Source5 Soak raw component eligibility/readback differs from fresh V2 validation")

    supervisor, _supervisor_raw, supervisor_sha = read_json(
        Path(pins["supervisor"]["path"]), pins["supervisor"]["raw_sha256"],
        "Source5 Soak supervisor receipt", MAX_RECEIPT_BYTES,
    )
    cleanup = exact(component["application_cleanup"], {
        "schema", "status", "pid", "return_code", "received_signal", "cleanup_error",
    }, "Source5 APP cleanup proof")
    exact(supervisor, {
        "schema", "execution_kind", "status", "interrupted", "received_signal",
        "application_cleanup", "application_binding", "application_binding_sha256",
        "application_attestation", "pressure_ready_sha256", "pressure_proof",
        "pressure_cleanup", "pressure_driver", "pressure_worker_sessions", "details",
    }, "Source5 Soak supervisor receipt")
    details_fields = {
        "status", "child_return_code", "timed_out", "artifact_budget_exceeded",
        "received_signal", "started_monotonic_ns", "ended_monotonic_ns",
        "binary_path", "binary_sha256", "binary_device", "binary_inode",
        "binary_size", "requested_argv", "requested_argv_sha256",
        "executed_argv", "executed_file_descriptor", "environment",
        "environment_sha256", "cwd", "cpu_set",
    }
    if bounded:
        details_fields |= {"resource_budget_exceeded", "resource_monitor_error"}
    details = exact(supervisor["details"], details_fields,
                    "Source5 Soak supervisor terminal details")
    if bounded:
        app_owner_pin = raw_pin(pins["application_owner"],
                                "Source5 bounded APP owner result")
        pressure_owner_pin = raw_pin(pins["pressure_owner"],
                                     "Source5 bounded pressure owner result")
        require(app_owner_pin["path"] ==
                    str(output_dir / "source5-soak-application-owner-return.json") and
                pressure_owner_pin["path"] ==
                    str(output_dir / "source5-soak-pressure-owner-return.json"),
                "Source5 bounded owner-result paths differ from their declared output roles")
        app_owner, _app_owner_raw, _app_owner_sha = read_json(
            Path(app_owner_pin["path"]), app_owner_pin["raw_sha256"],
            "Source5 bounded original APP owner result",
            budget_document["artifact_limits"]["owner_return_receipt_bytes"],
        )
        pressure_owner, _pressure_owner_raw, _pressure_owner_sha = read_json(
            Path(pressure_owner_pin["path"]), pressure_owner_pin["raw_sha256"],
            "Source5 bounded original pressure owner result",
            budget_document["artifact_limits"]["owner_return_receipt_bytes"],
        )
        expected_pressure_owner = exact(pressure_owner, {
            "schema", "pid", "start_ticks", "return_code",
            "started_monotonic_ns", "returned_monotonic_ns",
        }, "Source5 bounded original pressure owner result")
        expected_pressure_driver = exact(supervisor["pressure_driver"], {
            "pid", "start_ticks", "return_code",
        }, "Source5 bounded pressure supervisor result")
        require(app_owner == details and
                details["resource_budget_exceeded"] is False and
                details["resource_monitor_error"] is None and
                expected_pressure_owner["schema"] ==
                    "allocatbelt.application-source5-soak-pressure-owner-return.v2" and
                expected_pressure_owner["pid"] == expected_pressure_driver["pid"] and
                expected_pressure_owner["start_ticks"] ==
                    expected_pressure_driver["start_ticks"] and
                expected_pressure_owner["return_code"] ==
                    expected_pressure_driver["return_code"] and
                supervisor["pressure_cleanup"] == "verified" and
                type(expected_pressure_owner["started_monotonic_ns"]) is int and
                type(expected_pressure_owner["returned_monotonic_ns"]) is int and
                0 < expected_pressure_owner["started_monotonic_ns"] <=
                    expected_pressure_owner["returned_monotonic_ns"],
                "Source5 bounded owner sidecars differ from the actual APP/pressure supervisor results")
        require(probe_owner_interval is not None and monitor_replay is not None,
                "Source5 bounded resource replay lacks owner-interval evidence")
        _verify_source5_owner_phase_intervals(
            monitor_replay, budget_document, probe_owner_interval, details,
            expected_pressure_owner, supervisor,
        )
    binding_receipt = exact(supervisor["application_binding"], {
        "schema", "recipe_sha256", "nonce", "process", "launch_binding_sha256",
    }, "Source5 direct APP pressure binding")
    binding_process = exact(binding_receipt["process"], {
        "pid", "start_ticks", "executable_path", "executable_sha256", "cwd",
        "tmpdir_path", "cpu_affinity", "network_namespace_inode",
    }, "Source5 direct APP pressure process")
    binding_body = {key: value for key, value in binding_receipt.items()
                    if key != "launch_binding_sha256"}
    attestation = exact(supervisor["application_attestation"], {
        "schema", "execution_kind", "process", "attestation_sha256",
    }, "Source5 direct APP launch attestation")
    attestation_process = exact(attestation["process"], {
        "pid", "start_ticks", "executable_path", "executable_sha256",
        "executable_device", "executable_inode", "executable_size",
        "executable_fd_reference", "cwd", "argv", "argv_sha256",
        "cmdline_raw_sha256", "environment_sha256", "environment_raw_sha256",
    }, "Source5 direct APP attested process")
    attestation_body = {key: value for key, value in attestation.items()
                        if key != "attestation_sha256"}
    _validate_pressure_binding_recipe_roles(
        binding_receipt["recipe_sha256"],
        material_index["parent_recipe"], identities["recipe_sha256"],
        recipe["pressure"]["recipe"],
        overlay_audit["source"].get("pressure_recipe"),
    )
    require(type(binding_receipt["nonce"]) is str and
            re.fullmatch(r"[0-9a-f]{32}", binding_receipt["nonce"]) is not None and
            binding_receipt["nonce"] == recipe["identity"]["nonce"] and
            overlay_audit["launch_descriptor"]["environment"][
                "ALLOCATBELT_APP_PRESSURE_NONCE"] == recipe["identity"]["nonce"] and
            overlay_audit["launch_descriptor"]["environment"][
                "ALLOCATBELT_APP_REPORT_NONCE"] == recipe["identity"]["nonce"] and
            supervisor["application_binding_sha256"] ==
                binding_receipt["launch_binding_sha256"] ==
                sha256(canonical_bytes(binding_body)) and
            attestation["attestation_sha256"] ==
                sha256(canonical_bytes(attestation_body)) and
            binding_process["pid"] == attestation_process["pid"] ==
                component["application_attestation"]["process"]["pid"] and
            binding_process["start_ticks"] == attestation_process["start_ticks"] and
            binding_process["executable_sha256"] ==
                attestation_process["executable_sha256"] == recipe["identity"]["binary_sha256"] and
            attestation_process["argv"] == overlay_audit["launch_descriptor"]["argv"] and
            attestation_process["environment_sha256"] ==
                overlay_audit["launch_descriptor"]["environment_sha256"],
            "Source5 direct APP binding/attestation differs from the qualified Source5 overlay")
    require(supervisor_sha == component["supervisor_sha256"] and
            supervisor["schema"] == "allocatbelt.application-pressure-supervision.v1" and
            supervisor["execution_kind"] == "timed_soak" and
            supervisor["status"] == launch_receipt["exit_code"] == 0 and
            supervisor["interrupted"] is False and
            supervisor["received_signal"] is None and
            supervisor["application_attestation"] == component["application_attestation"] and
            supervisor["application_cleanup"] == cleanup and
            cleanup["status"] == "verified" and
            supervisor["pressure_cleanup"] == component["pressure_cleanup"] == "verified" and
            details["child_return_code"] == launch_receipt["child_return_code"] and
            details["received_signal"] == launch_receipt["received_signal"] and
            details["started_monotonic_ns"] == launch_receipt["started_monotonic_ns"] and
            details["ended_monotonic_ns"] == launch_receipt["ended_monotonic_ns"] and
            details["timed_out"] == launch_receipt["timed_out"] is False and
            details["artifact_budget_exceeded"] ==
                launch_receipt["artifact_budget_exceeded"] is False,
            "Source5 Soak supervisor summary differs from its actual callback/launch receipts")
    terminal = exact(component["terminal_event"], {
        "campaign_id", "host_id", "run_id", "descriptor", "member_ordinal",
        "pid", "status", "child_return_code", "signal", "cleanup",
        "terminal_monotonic_ns",
    }, "Source5 Soak terminal callback")
    require(cleanup["pid"] == terminal["pid"] and
            cleanup["return_code"] == details["child_return_code"] ==
                terminal["child_return_code"] == 0 and
            terminal["campaign_id"] == component["campaign_id"] and
            terminal["host_id"] == component["host_id"] and
            terminal["run_id"] == component["run_id"] and
            terminal["descriptor"] == soak_descriptor(job) and
            terminal["member_ordinal"] == 0 and terminal["status"] == 0 and
            terminal["signal"] is None and
            terminal["cleanup"] == {
                "status": "verified", "application_cleanup": cleanup,
                "pressure_cleanup": "verified", "timed_out": False,
                "artifact_budget_exceeded": False,
            } and
            cleanup["received_signal"] is None and cleanup["cleanup_error"] is None and
            terminal["terminal_monotonic_ns"] <= details["ended_monotonic_ns"],
            "Source5 Soak direct terminal callback differs from its actual supervisor result")
    return readback_value


def verify_source5_soak_component(
    component: dict[str, Any], prepared: dict[str, Any],
    job: dict[str, Any], authorization_context: dict[str, Any],
    readback: types.ModuleType,
) -> dict[str, Any]:
    """Replay the existing strict/live Soak verifier without changing V1."""
    return _verify_source5_soak_component_replay(
        component, prepared, job, authorization_context, readback,
    )


def _generation_projection(
    prepared: dict[str, Any], job: dict[str, Any], binding: dict[str, Any],
) -> dict[str, Any]:
    original = prepared["source5_execution_manifest"]["original_inputs"]
    expected = prepared["prepared"]
    source_ref = exact(prepared["source_manifest_raw_refs"][prepared["host_id"]], {
        "host_id", "path", "raw_sha256", "semantic_sha256",
        "source_tree_sha256",
    }, "Source5 Soak selected raw/semantic source generation")
    spec_artifact = raw_pin(original["spec"]["artifact"],
                            "Source5 Soak original SpecV3")
    plan_artifact = raw_pin(original["plan"]["artifact"],
                            "Source5 Soak original PlanV3")
    require(spec_artifact == {
                "path": str(expected["spec_path"]),
                "raw_sha256": expected["spec_raw_sha256"],
            } and original["spec"]["semantic_sha256"] ==
                expected["spec_semantic_sha256"] and
            plan_artifact == {
                "path": str(expected["plan_path"]),
                "raw_sha256": expected["plan_raw_sha256"],
            } and original["plan"]["semantic_sha256"] ==
                expected["plan_semantic_sha256"],
            "Source5 Soak generation does not match its original SpecV3/PlanV3")
    completion = prepared["source5_prepared_input_completion"]
    require(type(completion) is dict and
            completion.get("complete") is True and
            completion.get("qualification_eligible") is False,
            "Source5 Soak has no full non-qualifying preparation completion")
    completion_sha = digest(completion.get("completion_sha256"),
                            "Source5 preparation completion semantic SHA-256")
    completion_body = {key: value for key, value in completion.items()
                       if key != "completion_sha256"}
    require(completion_sha == sha256(canonical_bytes(completion_body)),
            "Source5 preparation completion semantic digest differs")
    selected_resource_proof = None
    if completion.get("schema") == \
            "allocatbelt.application-source5-preparation-completion.v2":
        selected_resource_proof = _selected_prepared_host_resource_proof(
            completion, prepared["host_id"],
        )
    execution_manifest = prepared["source5_execution_manifest"]
    manifest_pin = raw_pin(prepared["source5_execution_manifest_pin"],
                           "Source5 Soak execution manifest")
    pinned_manifest, _manifest_raw, manifest_raw_sha = read_json(
        Path(manifest_pin["path"]), manifest_pin["raw_sha256"],
        "Source5 Soak execution manifest", MAX_ARTIFACT_BYTES,
    )
    require(pinned_manifest == execution_manifest and
            manifest_raw_sha == manifest_pin["raw_sha256"],
            "Source5 Soak execution manifest differs from its raw artifact pin")
    prepared_generation = exact(execution_manifest["prepared_input_generation"], {
        "completion", "provenance",
    }, "Source5 Soak prepared-input generation")
    completion_pin = exact(prepared_generation["completion"], {
        "path", "raw_sha256", "semantic_sha256",
    }, "Source5 Soak prepared-input completion pin")
    provenance = exact(prepared_generation["provenance"], {
        "schema", "preparation_pin", "final_spec_pin", "final_plan_pin",
    }, "Source5 Soak prepared-input provenance")
    manifest_body = {key: value for key, value in execution_manifest.items()
                     if key != "manifest_sha256"}
    manifest_semantic_sha = digest(
        execution_manifest.get("manifest_sha256"),
        "Source5 Soak execution-manifest semantic SHA-256",
    )
    require(manifest_semantic_sha == sha256(canonical_bytes(manifest_body)),
            "Source5 Soak execution-manifest semantic digest differs")
    return {
        "campaign_id": prepared["campaign_id"],
        "host_id": prepared["host_id"],
        "job": {"run_id": job["run_id"], "ordinal": job["ordinal"],
                "phase": job["phase"]},
        "source_manifest": {
            "path": source_ref["path"],
            "raw_sha256": source_ref["raw_sha256"],
            "semantic_sha256": source_ref["semantic_sha256"],
            "source_tree_sha256": source_ref["source_tree_sha256"],
        },
        "spec": {
            **spec_artifact,
            "semantic_sha256": expected["spec_semantic_sha256"],
        },
        "plan": {
            **plan_artifact,
            "semantic_sha256": expected["plan_semantic_sha256"],
        },
        "prepared_input_completion_sha256": completion_sha,
        "prepared_input_completion_pin": completion_pin,
        "prepared_input_provenance": provenance,
        "selected_capacity_resource_proof": selected_resource_proof,
        "execution_manifest_pin": manifest_pin,
        "execution_manifest_semantic_sha256": manifest_semantic_sha,
        "prepared_host_binding_sha256": binding["binding_sha256"],
    }


def _capture_origin_host_identity(
    binding: dict[str, Any], host_id: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    host_pin = raw_pin(binding["prepared_host_context_pin"],
                       "Source5 prepared observed-host context")
    observed, _raw, observed_sha = read_json(
        Path(host_pin["path"]), host_pin["raw_sha256"],
        "Source5 origin observed-host context", MAX_ARTIFACT_BYTES,
    )
    exact(observed, {
        "schema", "host_id", "boot_id_sha256", "controls_sha256", "controls",
        "kernel_release", "cpu_model", "cpu_affinity",
        "network_namespace_inode",
    }, "Source5 origin observed-host context")
    require(observed["schema"] ==
            "allocatbelt.application-capacity-host-context.v1" and
            observed["host_id"] == host_id and
            observed["boot_id_sha256"] == binding["boot_id_sha256"] and
            observed["kernel_release"] == binding["kernel_release"] and
            observed["controls_sha256"] == binding["controls_sha256"] and
            observed["cpu_affinity"] == binding["process_affinity"] and
            observed["network_namespace_inode"] ==
                binding["network_namespace_inode"],
            "Source5 prepared observed-host context differs from its dual-host binding")
    try:
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(
            encoding="ascii",
        ).strip()
        kernel_release = os.uname().release
        affinity = sorted(os.sched_getaffinity(0))
        network_namespace_inode = os.stat("/proc/self/ns/net").st_ino
    except (OSError, UnicodeError, AttributeError) as error:
        raise Source5SoakError(f"cannot capture Source5 Soak origin host identity: {error}") from error
    boot_sha = sha256(boot_id.encode("ascii"))
    require(boot_sha == observed["boot_id_sha256"] and
            kernel_release == observed["kernel_release"] and
            affinity == observed["cpu_affinity"] and
            network_namespace_inode == observed["network_namespace_inode"],
            "Source5 Soak verifier is not running on the originally observed host context")
    body = {
        "schema": "allocatbelt.application-source5-soak-origin-host.v1",
        "host_id": host_id,
        "observed_host_raw_sha256": observed_sha,
        "boot_id_sha256": boot_sha,
        "kernel_release": kernel_release,
        "allowed_cpu_affinity": affinity,
        "network_namespace_inode": network_namespace_inode,
        "controls_sha256": observed["controls_sha256"],
    }
    body["host_identity_sha256"] = sha256(canonical_bytes(body))
    return body, host_pin


def _process_absence_snapshot(
    supervisor: dict[str, Any], readback: types.ModuleType,
) -> list[dict[str, Any]]:
    app = supervisor["application_attestation"]["process"]
    driver = supervisor["pressure_driver"]
    require(type(driver) is dict and type(driver.get("pid")) is int and
            type(driver.get("start_ticks")) is int and driver["return_code"] == 0,
            "Source5 Soak pressure driver lacks its completed original PID/start")
    processes = [{
        "role": "application", "pid": app["pid"],
        "start_ticks": app["start_ticks"],
    }, {
        "role": "pressure_driver", "pid": driver["pid"],
        "start_ticks": driver["start_ticks"],
    }]
    sessions = supervisor["pressure_worker_sessions"]
    require(type(sessions) is list and sessions,
            "Source5 Soak supervisor omits captured pressure worker sessions")
    for index, session in enumerate(sessions):
        require(type(session) is dict and
                type(session.get("pid")) is int and session["pid"] > 0 and
                type(session.get("start_ticks")) is int and
                session["start_ticks"] > 0 and
                type(session.get("reaped")) is bool,
                f"Source5 Soak pressure worker session[{index}] lacks its bounded PID/start record")
        role = session.get("role")
        cpu = session.get("cpu")
        require(type(role) is str and role and
                (cpu is None or type(cpu) is int),
                f"Source5 Soak pressure worker session[{index}] role is malformed")
        processes.append({
            "role": f"pressure_worker:{role}:{'-' if cpu is None else cpu}",
            "pid": session["pid"], "start_ticks": session["start_ticks"],
        })
    keys = [(item["pid"], item["start_ticks"]) for item in processes]
    require(len(keys) == len(set(keys)),
            "Source5 Soak supervisor aliases original process identities")
    absence: list[dict[str, Any]] = []
    for item in sorted(processes, key=lambda row: row["role"]):
        observed = readback._proc_process_identity(item["pid"])
        observed_start = None if observed is None else observed["start_ticks"]
        absent = observed_start != item["start_ticks"]
        require(absent,
                f"Source5 Soak original {item['role']} PID/start remains live")
        absence.append({
            **item, "original_identity_absent": True,
            "observed_start_ticks": observed_start,
            "observed_monotonic_ns": time.monotonic_ns(),
        })
    return absence


def _pressure_origin_projection(
    recipe: dict[str, Any], supervisor: dict[str, Any], output_root: Path,
    readback: types.ModuleType, prepared: dict[str, Any],
) -> dict[str, Any]:
    pin = exact(recipe["pressure"]["recipe"], {
        "path", "raw_sha256", "semantic_sha256",
    }, "Source5 Soak pressure recipe raw/semantic pin")
    condition_sha = digest(recipe["pressure"]["condition_sha256"],
                           "Source5 Soak pressure condition SHA-256")
    pressure_recipe_pin = {
        **pin, "condition_sha256": condition_sha,
    }
    pressure_value, _raw, pressure_raw_sha = read_json(
        Path(pin["path"]), pin["raw_sha256"],
        "Source5 Soak original pressure recipe", MAX_RECIPE_BYTES,
    )
    pressure_body = {key: value for key, value in pressure_value.items()
                     if key != "recipe_sha256"}
    require(pressure_raw_sha == pin["raw_sha256"] and
            pressure_value.get("recipe_sha256") == pin["semantic_sha256"] and
            sha256(canonical_bytes(pressure_body)) == pin["semantic_sha256"] and
            pressure_value.get("condition_sha256") == condition_sha,
            "Source5 Soak pressure recipe raw/semantic identities differ")
    pressure_reader, _pressure_reader_sha, _pressure_reader_path = \
        _load_pressure_readback_module(prepared)
    recipe_dependency_paths = set(
        pressure_reader._pressure_absolute_json_paths(pressure_value),
    )
    recipe_dependency_paths.add(pin["path"])
    recipe_dependency_paths.update(_raw_pins_in(pressure_value))
    pressure_dir = output_root / "pressure"
    artifact_hashes = readback._pressure_output_hashes(pressure_dir)
    require(set(artifact_hashes) == {
        "run", "events", "launch", "process_binding", "ready",
    }, "Source5 strict pressure reader returned an open artifact set")
    proof_path = output_root / "pressure-readback.json"
    proof_raw, proof_sha, _proof_info = read_stable(
        proof_path, "Source5 Soak strict pressure readback proof",
        MAX_RECEIPT_BYTES,
    )
    proof = readback._read_json_raw(proof_raw,
                                    "Source5 Soak strict pressure readback proof")
    app_storage = pressure_value["host"]["application_storage"]
    pressure_scratch = pressure_value["host"]["pressure_scratch"]
    tmpdir = pressure_value["process"]["application_tmpdir_path"]
    require(type(app_storage) is list and app_storage and
            any(type(item) is dict and item.get("path") == tmpdir
                for item in app_storage) and
            type(pressure_scratch) is dict and
            supervisor["pressure_cleanup"] == "verified" and
            supervisor["pressure_proof"] == {
                "proof": proof, "raw_sha256": proof_sha,
            },
            "Source5 Soak strict pressure replay does not bind original TMPDIR/storage and proof")
    driver, driver_sha, _driver_path = \
        _load_pressure_driver_storage_reader(prepared)
    storage_policy = pressure_value.get("storage")
    require(type(storage_policy) is dict and
            type(storage_policy.get("application_io_paths")) is list and
            type(storage_policy.get("pressure_scratch_path")) is str and
            type(storage_policy.get("output_minimum_free_bytes")) is int and
            storage_policy["output_minimum_free_bytes"] > 0,
            "Source5 Soak pressure recipe omits its frozen TMPDIR/ext4 storage contract")
    pressure_artifacts = {
        "directory": str(pressure_dir),
        "pins": artifact_hashes,
        "proof": {"path": str(proof_path), "raw_sha256": proof_sha},
        "ready_sha256": artifact_hashes["ready"],
        "driver": supervisor["pressure_driver"],
        "worker_sessions": supervisor["pressure_worker_sessions"],
        "driver_logs": {
            "stdout": {
                "path": str(output_root / "pressure-driver.stdout.log"),
                "raw_sha256": read_stable(
                    output_root / "pressure-driver.stdout.log",
                    "Source5 pressure driver stdout log",
                    pressure_reader.MAX_EVENTS_BYTES,
                )[1],
            },
            "stderr": {
                "path": str(output_root / "pressure-driver.stderr.log"),
                "raw_sha256": read_stable(
                    output_root / "pressure-driver.stderr.log",
                    "Source5 pressure driver stderr log",
                    pressure_reader.MAX_EVENTS_BYTES,
                )[1],
            },
        },
    }
    after_storage: list[dict[str, Any]] = []
    expected_storage = {
        item["path"]: item for item in app_storage
        if type(item) is dict and type(item.get("path")) is str
    }
    require(set(expected_storage) == set(storage_policy["application_io_paths"]),
            "Source5 Soak pressure storage paths differ from their original recipe")
    for index, path_text in enumerate(storage_policy["application_io_paths"]):
        path = Path(path_text)
        actual = driver._storage_record(path, f"Source5 Soak post-run application storage[{index}]")
        stats = os.statvfs(path)
        require(actual == expected_storage[path_text],
                f"Source5 Soak post-run storage changed from its frozen host fact: {path_text}")
        available_bytes = stats.f_bavail * stats.f_frsize
        available_inodes = stats.f_favail
        require(available_bytes >= storage_policy["output_minimum_free_bytes"] and
                available_inodes >= 0,
                f"Source5 Soak post-run ext4 reserve is below its frozen free-space floor: {path_text}")
        after_storage.append({
            "path": path_text, "record": actual,
            "available_bytes": available_bytes,
            "available_inodes": available_inodes,
        })
    scratch_path_text = storage_policy["pressure_scratch_path"]
    actual_scratch = driver._storage_record(
        Path(scratch_path_text), "Source5 Soak post-run pressure scratch storage",
    )
    stats = os.statvfs(scratch_path_text)
    require(actual_scratch == pressure_scratch and
            stats.f_bavail * stats.f_frsize >= storage_policy["output_minimum_free_bytes"],
            "Source5 Soak post-run pressure scratch storage differs from its frozen ext4 contract")
    scratch_after = {
        "path": scratch_path_text, "record": actual_scratch,
        "available_bytes": stats.f_bavail * stats.f_frsize,
        "available_inodes": stats.f_favail,
    }
    app_binding = supervisor["application_binding"]["process"]
    return {
        "schema": "allocatbelt.application-source5-soak-pressure-origin.v2",
        "recipe_pin": pressure_recipe_pin,
        "recipe_dependency_paths": sorted(recipe_dependency_paths),
        "application_tmpdir_path": tmpdir,
        "storage_before": {
            "application_storage": app_storage,
            "pressure_scratch": pressure_scratch,
            "recipe_storage": storage_policy,
        },
        "storage_after": {
            "application_process": {
                "pid": app_binding["pid"],
                "start_ticks": supervisor["application_attestation"]["process"]["start_ticks"],
                "tmpdir_path": app_binding["tmpdir_path"],
                "cpu_affinity": app_binding["cpu_affinity"],
                "network_namespace_inode": app_binding["network_namespace_inode"],
            },
            "pressure_artifacts": pressure_artifacts,
            "pressure_readback_sha256": proof.get("readback_sha256"),
            "pressure_cleanup": supervisor["pressure_cleanup"],
            "pressure_driver_source_sha256": driver_sha,
            "application_storage": after_storage,
            "pressure_scratch": scratch_after,
        },
    }


def _generation_input_root(prepared: dict[str, Any]) -> Path:
    root = Path(prepared["prepared"]["spec_path"]).parent
    require(root.is_absolute() and root.resolve(strict=True) == root,
            "Source5 Soak input root is not canonical")
    return root


def _typed_source_inventory(
    source_root: Path, source_manifest: dict[str, Any],
) -> list[dict[str, Any]]:
    """Capture only the SourceV5-declared source and artifact paths."""
    source_info = source_manifest.get("source")
    files = source_info.get("files") if type(source_info) is dict else None
    require(type(files) is list,
            "Source5 Soak source manifest has no typed regular-source inventory")
    records: dict[str, dict[str, Any]] = {
        str(source_root): {
            "path": str(source_root), "kind": "directory",
            "mode": f"{stat.S_IMODE(source_root.lstat().st_mode):04o}",
        },
    }
    for index, record_value in enumerate(files):
        require(type(record_value) is dict,
                f"Source5 typed source record[{index}] is not an object")
        relative = record_value.get("path")
        require(type(relative) is str and relative and
                not Path(relative).is_absolute() and ".." not in Path(relative).parts,
                f"Source5 typed source record[{index}] has a nonportable path")
        path = source_root.joinpath(*PurePosixPath(relative).parts)
        if record_value.get("kind") == "file":
            record = _stable_file_inventory(
                path, f"Source5 typed source {relative}",
                32 * 1024 * 1024 * 1024,
            )
            inventory_mode = "100755" if int(record["mode"], 8) & 0o111 else "100644"
            require(record["raw_sha256"] == record_value.get("sha256") and
                    inventory_mode == record_value.get("mode") and
                    record["size"] == record_value.get("size"),
                    f"Source5 typed source differs from its manifest: {relative}")
        elif record_value.get("kind") == "symlink":
            require(type(record_value.get("target")) is str,
                    f"Source5 typed source symlink target is malformed: {relative}")
            parent = source_root
            for part in PurePosixPath(relative).parts[:-1]:
                parent = parent / part
                parent_info = parent.lstat()
                require(stat.S_ISDIR(parent_info.st_mode) and
                        not stat.S_ISLNK(parent_info.st_mode),
                        f"Source5 typed symlink traverses a non-directory: {relative}")
            info = path.lstat()
            target = os.readlink(path)
            target_raw = target.encode("utf-8")
            record = {
                "path": str(path), "kind": "symlink", "mode": "120000",
                "size": len(target_raw), "raw_sha256": sha256(target_raw),
                "target": target,
            }
            require(stat.S_ISLNK(info.st_mode) and
                    target == record_value["target"] and
                    record["raw_sha256"] == record_value.get("sha256") and
                    record["size"] == record_value.get("size") and
                    record_value.get("mode") == "120000",
                    f"Source5 typed symlink differs from its manifest: {relative}")
        else:
            raise Source5SoakError(
                f"Source5 typed source record has an unknown kind: {relative}",
            )
        require(str(path) not in records,
                f"Source5 typed source path repeats: {relative}")
        records[str(path)] = record

    pending = [source_manifest]
    seen: set[int] = set()
    artifact_pins: dict[str, str] = {}
    while pending:
        item = pending.pop()
        if type(item) is dict:
            identity = id(item)
            if identity in seen:
                continue
            seen.add(identity)
            raw_path, raw_sha = item.get("path"), item.get("sha256")
            if type(raw_path) is str and type(raw_sha) is str and \
                    not Path(raw_path).is_absolute():
                relative = Path(raw_path)
                require(".." not in relative.parts and str(relative) == raw_path,
                        "Source5 source/artifact pin is not a normalized relative path")
                digest(raw_sha, "Source5 source/artifact raw SHA-256")
                full_path = str(source_root / relative)
                prior = artifact_pins.get(full_path)
                require(prior is None or prior == raw_sha,
                        f"Source5 source/artifact paths conflict: {raw_path}")
                artifact_pins[full_path] = raw_sha
            pending.extend(item.values())
        elif type(item) is list:
            pending.extend(item)
    for path_text, expected_sha in artifact_pins.items():
        if path_text in records:
            require(records[path_text].get("raw_sha256") == expected_sha,
                    f"Source5 module/artifact pin differs from its typed entry: {path_text}")
            continue
        record = _stable_file_inventory(
            Path(path_text), "Source5 declared artifact/module",
            32 * 1024 * 1024 * 1024,
        )
        require(record["raw_sha256"] == expected_sha,
                f"Source5 declared artifact/module differs from its source pin: {path_text}")
        records[path_text] = record

    # The offline path map must cover every directory traversed while reading a
    # declared source file. Keep this closure bounded to parents of the typed
    # manifest entries; do not walk unrelated checkout contents such as .git
    # or build caches.
    declared_paths = list(records)
    for path_text in declared_paths:
        current_path = Path(path_text)
        if current_path == source_root:
            continue
        parent = current_path.parent
        while parent != source_root:
            require(source_root in parent.parents,
                    f"Source5 typed path escapes its source root: {path_text}")
            info = parent.lstat()
            require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
                    f"Source5 typed path traverses an untyped directory: {parent}")
            directory = {
                "path": str(parent), "kind": "directory",
                "mode": f"{stat.S_IMODE(info.st_mode):04o}",
            }
            previous = records.get(str(parent))
            require(previous is None or previous == directory,
                    f"Source5 typed directory collides with a file entry: {parent}")
            records[str(parent)] = directory
            parent = parent.parent
    return sorted(records.values(), key=lambda item: item["path"])


def _declared_soak_output_inventory(
    component: dict[str, Any], output_root: Path, readback: types.ModuleType,
) -> list[dict[str, Any]]:
    """Pin only the closed Soak/pressure artifact layout, never a directory glob."""
    directory = output_root.lstat()
    require(stat.S_ISDIR(directory.st_mode) and not stat.S_ISLNK(directory.st_mode),
            "Source5 Soak output root is not a real directory")
    entries: dict[str, dict[str, Any]] = {
        str(output_root): {
            "path": str(output_root), "kind": "directory",
            "mode": f"{stat.S_IMODE(directory.st_mode):04o}",
        },
    }
    pressure_dir = output_root / "pressure"
    pressure_info = pressure_dir.lstat()
    require(stat.S_ISDIR(pressure_info.st_mode) and not stat.S_ISLNK(pressure_info.st_mode),
            "Source5 pressure artifact root is not a real directory")
    entries[str(pressure_dir)] = {
        "path": str(pressure_dir), "kind": "directory",
        "mode": f"{stat.S_IMODE(pressure_info.st_mode):04o}",
    }
    expected_direct = set(SOAK_BOUNDED_OUTPUT_FILES) | {"pressure"}
    if component.get("schema") != COMPONENT_SCHEMA_V2:
        expected_direct.difference_update({
            "source5-soak-resource-monitor.jsonl",
            "source5-soak-application-owner-return.json",
            "source5-soak-pressure-owner-return.json",
        })
    try:
        direct_children = sorted(os.scandir(output_root), key=lambda item: item.name)
    except OSError as error:
        raise Source5SoakError(f"cannot enumerate declared Soak outputs: {error}") from error
    require({item.name for item in direct_children} == expected_direct,
            "Source5 Soak output root has missing or undeclared top-level artifacts")

    receipt_sha = digest(component["readback"]["receipt_sha256"],
                         "Source5 runtime-soak.v2 raw receipt SHA-256")
    runtime_receipt, _runtime_raw, _runtime_raw_sha = read_json(
        output_root / "soak-receipt.json", receipt_sha,
        "Source5 runtime-soak.v2 artifact receipt", MAX_RECEIPT_BYTES,
    )
    stream_pins = {
        runtime_receipt["terminal_stream_relative_path"]:
            runtime_receipt["terminal_stream_sha256"],
        runtime_receipt["resource_samples_relative_path"]:
            runtime_receipt["resource_samples_sha256"],
    }
    require(set(stream_pins) == {"terminal-records.tsv", "resource-samples.tsv"},
            "Source5 Soak runtime stream pins differ from the exact declared stream files")
    pressure_filenames = {
        "run.json": "run", "events.jsonl": "events",
        "launch-record.json": "launch",
        "process-binding.json": "process_binding",
        "pressure-ready.json": "ready",
    }
    expected_pressure = set(SOAK_PRESSURE_OUTPUT_FILES)
    try:
        pressure_children = sorted(os.scandir(pressure_dir), key=lambda item: item.name)
    except OSError as error:
        raise Source5SoakError(f"cannot enumerate declared pressure outputs: {error}") from error
    require({item.name for item in pressure_children} == expected_pressure,
            "Source5 pressure output directory has missing or undeclared artifacts")

    paths: dict[str, str | None] = {}
    for name in expected_direct - {"pressure"}:
        paths[str(output_root / name)] = None
    component_bytes = canonical_bytes(component)
    paths[str(output_root / "source5-soak-component.json")] = \
        sha256(component_bytes)
    if component.get("schema") == COMPONENT_SCHEMA_V2:
        for role in ("application_owner", "pressure_owner", "resource_monitor"):
            pin = component["pins"].get(role)
            require(type(pin) is dict and pin.get("path") ==
                    str(output_root / {
                        "application_owner": "source5-soak-application-owner-return.json",
                        "pressure_owner": "source5-soak-pressure-owner-return.json",
                        "resource_monitor": "source5-soak-resource-monitor.jsonl",
                    }[role]),
                    f"Source5 bounded {role} output lacks its exact raw pin")
            raw_pin_value = raw_pin(pin, f"Source5 bounded {role} output")
            paths[raw_pin_value["path"]] = raw_pin_value["raw_sha256"]
    for relative, expected_sha in stream_pins.items():
        relative_path = Path(relative)
        require(not relative_path.is_absolute() and ".." not in relative_path.parts and
                relative_path.parent == Path("."),
                "Source5 Soak runtime stream path differs from its closed output layout")
        paths[str(output_root / relative_path)] = digest(
            expected_sha, "Source5 Soak runtime stream raw SHA-256",
        )
    pressure_hashes = readback._pressure_output_hashes(pressure_dir)
    require(set(pressure_hashes) == set(pressure_filenames.values()),
            "strict Soak pressure reader returned an open artifact set")
    for child in direct_children:
        if child.name == "pressure":
            continue
        path = output_root / child.name
        info = child.stat(follow_symlinks=False)
        require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and
                info.st_nlink == 1 and info.st_uid == os.getuid(),
                f"Source5 Soak output is not a regular file: {path}")
        expected_sha = paths.get(str(path))
        record = _stable_file_inventory(
            path, f"Source5 Soak output {child.name}",
            32 * 1024 * 1024 * 1024,
        )
        require(expected_sha is None or record["raw_sha256"] == expected_sha,
                f"Source5 Soak output differs from its runtime receipt: {child.name}")
        entries[str(path)] = record
    # The strict pressure reader has already independently checked these five
    # records; pin their literal files here so the offline path map is exact.
    pressure_hashes = readback._pressure_output_hashes(pressure_dir)
    for name, key in sorted(pressure_filenames.items()):
        path = pressure_dir / name
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                info.st_uid == os.getuid(),
                f"Source5 pressure artifact is linked or unowned: {name}")
        entries[str(path)] = _stable_file_inventory(
            path, f"Source5 pressure artifact {name}",
            32 * 1024 * 1024 * 1024,
        )
        require(entries[str(path)]["raw_sha256"] == pressure_hashes[key],
                f"Source5 pressure artifact changed after strict readback: {name}")
    return sorted(entries.values(), key=lambda item: item["path"])


def _declared_probe_capture_inventory(
    probe_root: Path, probe_capture: dict[str, Any],
    probe_capture_pin: dict[str, str],
) -> list[dict[str, Any]]:
    """Pin the fixed process-owner output set and bounded TMPDIR descendants."""
    info = probe_root.lstat()
    require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
            "Source5 ProbeV1 output root is not a real directory")
    if probe_capture.get("schema") == PROBE_CAPTURE_SCHEMA_V2:
        expected_names = {
            "stdout.bin", "stderr.bin", "owner-result.json",
            "tmpdir-inventory.json", "capture-receipt.json", "tmp",
        }
    else:
        expected_names = {
            "probe.stdout", "probe.stderr", "process-owner.json",
            "probe-capture.json", "tmp",
        }
    children = sorted(os.scandir(probe_root), key=lambda item: item.name)
    require({item.name for item in children} == expected_names,
            "Source5 ProbeV1 output root has missing or undeclared artifacts")
    entries: dict[str, dict[str, Any]] = {
        str(probe_root): {
            "path": str(probe_root), "kind": "directory",
            "mode": f"{stat.S_IMODE(info.st_mode):04o}",
        },
    }
    tmpdir = probe_root / "tmp"
    for item in _tree_inventory(tmpdir, "Source5 ProbeV1 bounded TMPDIR"):
        entries[item["path"]] = item
    if probe_capture.get("schema") == PROBE_CAPTURE_SCHEMA_V2:
        expected_files = {
            "stdout.bin": probe_capture["stdout"]["raw_sha256"],
            "stderr.bin": probe_capture["stderr"]["raw_sha256"],
            "owner-result.json": probe_capture["owner_result_pin"]["raw_sha256"],
            "tmpdir-inventory.json": probe_capture["tmpdir_inventory_pin"]["raw_sha256"],
            "capture-receipt.json": probe_capture_pin["raw_sha256"],
        }
    else:
        expected_files = {
            "probe.stdout": probe_capture["stdout"]["raw_sha256"],
            "probe.stderr": probe_capture["stderr"]["raw_sha256"],
            "process-owner.json": probe_capture["owner_result_pin"]["raw_sha256"],
            "probe-capture.json": probe_capture_pin["raw_sha256"],
        }
    for name, expected_sha in expected_files.items():
        path = probe_root / name
        file_info = path.lstat()
        require(stat.S_ISREG(file_info.st_mode) and file_info.st_nlink == 1 and
                file_info.st_uid == os.getuid(),
                f"Source5 probe output is linked or unowned: {name}")
        record = _stable_file_inventory(
            path, f"Source5 ProbeV2 output {name}", MAX_RECEIPT_BYTES,
        )
        require(record["raw_sha256"] == expected_sha,
                f"Source5 ProbeV2 output raw pin differs: {name}")
        entries[str(path)] = record
    return sorted(entries.values(), key=lambda item: item["path"])


def _resource_monitor_expected_device_rows(
    budget: dict[str, Any], domains: object,
) -> dict[str, dict[str, int]]:
    require(type(domains) is dict and set(domains) == {
        "output", "application_tmpdir", "pressure_scratch",
        "probe_capture", "probe_tmpdir",
    }, "Source5 resource-monitor domain set differs")
    ceilings = budget["ceilings"]
    roots = (
        ("output", "output_root", "maximum_output_bytes", "maximum_output_inodes"),
        ("application_tmpdir", "application_tmpdir", "maximum_application_tmpdir_bytes", "maximum_application_tmpdir_inodes"),
        ("pressure_scratch", "pressure_scratch", "maximum_pressure_scratch_bytes", "maximum_pressure_scratch_inodes"),
        ("probe_capture", "probe_capture_root", "maximum_probe_output_bytes", "maximum_probe_output_inodes"),
        ("probe_tmpdir", "probe_tmpdir", "maximum_probe_tmpdir_bytes", "maximum_probe_tmpdir_inodes"),
    )
    by_device: dict[int, dict[str, Any]] = {}
    for role, path_field, byte_field, inode_field in roots:
        item = exact(domains[role], {
            "path", "device", "inode", "bytes_used", "inode_count",
            "available_bytes", "available_inodes", "bytes_limit", "inode_limit",
        }, f"Source5 resource-monitor {role} row")
        require(item["path"] == budget["layout"][path_field] and
                type(item["device"]) is int and item["device"] >= 0 and
                (item["inode"] is None or
                 type(item["inode"]) is int and item["inode"] > 0) and
                type(item["bytes_used"]) is int and item["bytes_used"] >= 0 and
                type(item["inode_count"]) is int and item["inode_count"] >= 0 and
                type(item["available_bytes"]) is int and item["available_bytes"] >= 0 and
                type(item["available_inodes"]) is int and item["available_inodes"] >= 0 and
                item["bytes_limit"] == ceilings[byte_field] and
                item["inode_limit"] == ceilings[inode_field] and
                item["bytes_used"] <= item["bytes_limit"] and
                item["inode_count"] <= item["inode_limit"],
                f"Source5 resource-monitor {role} origin usage differs from its frozen root/budget")
        device = by_device.setdefault(item["device"], {
            "available_bytes": item["available_bytes"],
            "available_inodes": item["available_inodes"],
            "roles": [],
        })
        device["available_bytes"] = min(device["available_bytes"],
                                        item["available_bytes"])
        device["available_inodes"] = min(device["available_inodes"],
                                         item["available_inodes"])
        device["roles"].append(role)
    expected: dict[str, dict[str, int]] = {}
    for device, record in by_device.items():
        selected = [next(root for root in roots if root[0] == role)
                    for role in record["roles"]]
        selected.sort(key=lambda root: (len(Path(budget["layout"][root[1]]).parts),
                                        budget["layout"][root[1]]))
        top: list[Path] = []
        remaining_bytes = 0
        remaining_inodes = 0
        for role, path_field, byte_field, inode_field in selected:
            path = Path(budget["layout"][path_field])
            if any(path == parent or parent in path.parents for parent in top):
                continue
            top.append(path)
            usage = domains[role]
            remaining_bytes += max(0, ceilings[byte_field] - usage["bytes_used"])
            remaining_inodes += max(0, ceilings[inode_field] - usage["inode_count"])
        required_bytes = (ceilings["minimum_free_bytes"] + remaining_bytes +
                          ceilings["durable_receipt_reserve_bytes"])
        required_inodes = (ceilings["minimum_free_inodes"] + remaining_inodes +
                           ceilings["durable_receipt_reserve_inodes"])
        require(record["available_bytes"] >= required_bytes and
                record["available_inodes"] >= required_inodes,
                f"Source5 resource-monitor device {device} violated its recorded free-space/reserve inequality")
        expected[str(device)] = {
            "available_bytes": record["available_bytes"],
            "available_inodes": record["available_inodes"],
            "remaining_bytes": remaining_bytes,
            "remaining_inodes": remaining_inodes,
            "required_bytes": required_bytes,
            "required_inodes": required_inodes,
        }
    return expected


def _verify_source5_resource_monitor_stream(
    budget: dict[str, Any], budget_pin: dict[str, str],
    summary_value: object,
    launch_prefix_value: object | None = None,
) -> dict[str, Any]:
    summary = exact(summary_value, {
        "schema", "budget", "stream", "row_count", "high_water",
        "final_usage", "failure", "prefix_sha256",
    }, "Source5 Soak resource-monitor summary")
    stream_pin = exact(summary["stream"], {"path", "raw_sha256"},
                       "Source5 Soak resource-monitor stream pin")
    path = Path(stream_pin["path"])
    require(summary["schema"] ==
                "allocatbelt.application-source5-soak-resource-monitor-summary.v1" and
            summary["budget"] == budget_pin and
            path == Path(budget["layout"]["output_root"]) /
                "source5-soak-resource-monitor.jsonl" and
            type(summary["row_count"]) is int and
            1 <= summary["row_count"] <= budget["ceilings"]["maximum_monitor_rows"] and
            summary["failure"] is None,
            "Source5 Soak resource-monitor summary is incomplete or blocked")
    digest(stream_pin["raw_sha256"],
           "Source5 Soak resource-monitor stream raw SHA-256")
    maximum = budget["ceilings"]["maximum_monitor_stream_bytes"]
    try:
        require(path.resolve(strict=True) == path,
                "Source5 resource-monitor path traverses an alias")
        before_path = path.lstat()
        require(stat.S_ISREG(before_path.st_mode) and before_path.st_uid == os.getuid() and
                stat.S_IMODE(before_path.st_mode) == 0o600 and
                before_path.st_nlink == 1 and 0 <= before_path.st_size <= maximum,
                "Source5 resource-monitor stream is not a bounded private regular file")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
                     getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as error:
        raise Source5SoakError(
            f"Source5 resource-monitor stream is unavailable: {error}",
        ) from error
    digest_state = hashlib.sha256()
    line = bytearray()
    header: dict[str, Any] | None = None
    footer: dict[str, Any] | None = None
    previous_sha = "0" * 64
    previous_ns: int | None = None
    previous_phase = "preflight"
    rows = 0
    seen_phases: set[str] = set()
    phase_bounds: dict[str, list[int]] = {}
    phase_counts: dict[str, int] = {}
    origin_root_identities: dict[str, tuple[int, int]] = {}
    placeholder_devices: dict[str, int] = {}
    high_water = {
        role: {"bytes": 0, "inodes": 0}
        for role in ("output", "application_tmpdir", "pressure_scratch",
                     "probe_capture", "probe_tmpdir")
    }
    prefix_digest = hashlib.sha256()
    row_limit = budget["ceilings"]["maximum_monitor_row_bytes"]
    interval_ns = budget["schedule"]["resource_monitor_interval_ms"] * 1_000_000
    gap_ns = interval_ns + budget["schedule"]["resource_monitor_tolerance_ns"]
    launch_prefix = None
    if launch_prefix_value is not None:
        launch_prefix = exact(launch_prefix_value, {
            "schema", "path", "budget", "row_count", "prefix_sha256",
            "last_row_sha256", "high_water", "failure",
        }, "Source5 launch monitor prefix")
        require(launch_prefix["schema"] ==
                    "allocatbelt.application-source5-soak-resource-monitor-prefix.v1" and
                launch_prefix["path"] == str(path) and
                launch_prefix["budget"] == budget_pin and
                type(launch_prefix["row_count"]) is int and
                launch_prefix["row_count"] > 0 and
                type(launch_prefix["prefix_sha256"]) is str and
                re.fullmatch(r"[0-9a-f]{64}", launch_prefix["prefix_sha256"]) is not None and
                type(launch_prefix["last_row_sha256"]) is str and
                re.fullmatch(r"[0-9a-f]{64}", launch_prefix["last_row_sha256"]) is not None and
                launch_prefix["failure"] is None,
                "Source5 launch monitor prefix is malformed or detached from its budget")
    prefix_checked = False
    prefix_high_water: dict[str, dict[str, int]] | None = None

    def parse_line(raw_line: bytes) -> None:
        nonlocal header, footer, previous_sha, previous_ns, previous_phase, rows
        nonlocal prefix_checked, prefix_high_water
        require(footer is None,
                "Source5 resource-monitor stream contains data after its footer")
        require(len(raw_line) <= row_limit,
                "Source5 resource-monitor line exceeds its prospective bound")
        try:
            value = json.loads(raw_line)
        except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
            raise Source5SoakError(
                f"Source5 resource-monitor line is invalid: {error}",
            ) from error
        require(type(value) is dict and
                raw_line == canonical_bytes(value),
                "Source5 resource-monitor line is not canonical")
        if header is None:
            header = value
            body = {key: item for key, item in header.items()
                    if key != "header_sha256"}
            require(set(header) == {
                        "schema", "budget", "monitor_owner", "layout",
                        "schedule", "ceilings", "started_monotonic_ns",
                        "header_sha256",
                    } and header["schema"] == SOAK_RESOURCE_MONITOR_SCHEMA and
                    header["budget"] == budget_pin and
                    header["monitor_owner"] == budget["binding"]["monitor_owner"] and
                    header["layout"] == budget["layout"] and
                    header["schedule"] == budget["schedule"] and
                    header["ceilings"] == budget["ceilings"] and
                    header["header_sha256"] == sha256(canonical_bytes(body)) and
                    type(header["started_monotonic_ns"]) is int and
                    header["started_monotonic_ns"] > 0,
                    "Source5 resource-monitor header differs from its original budget")
            prefix_digest.update(raw_line)
            return
        if value.get("schema") == SOAK_RESOURCE_MONITOR_FOOTER_SCHEMA:
            footer = value
            return
        body = {key: item for key, item in value.items()
                if key != "row_sha256"}
        require(set(value) == {
                    "schema", "sequence", "phase", "monotonic_ns",
                    "previous_sha256", "domains", "devices", "failure",
                    "row_sha256",
                } and value["schema"] == SOAK_RESOURCE_MONITOR_ROW_SCHEMA and
                value["sequence"] == rows and
                value["previous_sha256"] == previous_sha and
                value["row_sha256"] == sha256(canonical_bytes(body)) and
                value["phase"] in RESOURCE_MONITOR_PHASES and
                RESOURCE_MONITOR_PHASES.index(value["phase"]) >=
                    RESOURCE_MONITOR_PHASES.index(previous_phase) and
                value["failure"] is None,
                f"Source5 resource-monitor row[{rows}] chain/order/failure differs")
        monotonic_ns = value["monotonic_ns"]
        require(type(monotonic_ns) is int and monotonic_ns > 0 and
                (previous_ns is None or
                 0 < monotonic_ns - previous_ns <= gap_ns),
                f"Source5 resource-monitor row[{rows}] violates its prospective timing bound")
        if rows == 0:
            require(header is not None and
                    header["started_monotonic_ns"] <= monotonic_ns and
                    monotonic_ns - header["started_monotonic_ns"] <= gap_ns,
                    "Source5 resource-monitor header is outside the first origin sample interval")
        expected_devices = _resource_monitor_expected_device_rows(
            budget, value["domains"],
        )
        require(all(item["inode"] is not None or
                    (value["phase"] in {"preflight", "preflight_audit"} and
                     role in {"probe_capture", "probe_tmpdir"})
                    for role, item in value["domains"].items()),
                "Source5 resource-monitor missing root appears outside initial preflight")
        for role, item in value["domains"].items():
            if item["inode"] is None:
                require(role not in origin_root_identities,
                        f"Source5 resource-monitor {role} root disappeared after origin binding")
                previous_device = placeholder_devices.setdefault(role, item["device"])
                require(item["device"] == previous_device,
                        f"Source5 resource-monitor {role} absent-root device changed")
            else:
                identity = (item["device"], item["inode"])
                previous_identity = origin_root_identities.get(role)
                require(previous_identity is None or previous_identity == identity,
                        f"Source5 resource-monitor {role} root device/inode changed across rows")
                expected_device = placeholder_devices.get(role)
                require(expected_device is None or expected_device == item["device"],
                        f"Source5 resource-monitor {role} created root changed its held-parent device")
                placeholder_devices.pop(role, None)
                origin_root_identities[role] = identity
        require(value["devices"] == expected_devices,
                f"Source5 resource-monitor row[{rows}] device reserve arithmetic differs")
        for role, usage in value["domains"].items():
            high_water[role]["bytes"] = max(
                high_water[role]["bytes"], usage["bytes_used"],
            )
            high_water[role]["inodes"] = max(
                high_water[role]["inodes"], usage["inode_count"],
            )
        previous_sha = value["row_sha256"]
        previous_ns = monotonic_ns
        previous_phase = value["phase"]
        seen_phases.add(value["phase"])
        bounds = phase_bounds.setdefault(value["phase"], [monotonic_ns, monotonic_ns])
        bounds[1] = monotonic_ns
        phase_counts[value["phase"]] = phase_counts.get(value["phase"], 0) + 1
        rows += 1
        prefix_digest.update(raw_line)
        if launch_prefix is not None and rows == launch_prefix["row_count"]:
            require(prefix_digest.hexdigest() == launch_prefix["prefix_sha256"] and
                    previous_sha == launch_prefix["last_row_sha256"],
                    "Source5 launch monitor prefix is not the exact first stream prefix")
            prefix_high_water = {
                role: dict(value) for role, value in high_water.items()
            }
            require(launch_prefix["high_water"] == prefix_high_water,
                    "Source5 launch monitor prefix high-water differs from its rows")
            prefix_checked = True

    try:
        before = os.fstat(fd)
        signature = lambda item: (
            item.st_dev, item.st_ino, item.st_mode, item.st_size,
            item.st_mtime_ns, item.st_ctime_ns,
        )
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                signature(before) == signature(before_path) and
                0 <= before.st_size <= maximum,
                "Source5 resource-monitor stream changed while opening")
        consumed = 0
        while consumed < before.st_size:
            block = os.read(fd, min(64 * 1024, before.st_size - consumed))
            require(bool(block), "Source5 resource-monitor stream was truncated")
            consumed += len(block)
            digest_state.update(block)
            for byte in block:
                line.append(byte)
                if byte == 10:
                    parse_line(bytes(line))
                    line.clear()
                else:
                    require(len(line) <= row_limit,
                            "Source5 resource-monitor line exceeds its prospective bound")
        after = os.fstat(fd)
        after_path = path.lstat()
        require(not line and signature(before) == signature(after) ==
                signature(after_path) and
                digest_state.hexdigest() == stream_pin["raw_sha256"],
                "Source5 resource-monitor stream changed during its replay")
    finally:
        os.close(fd)
    require(header is not None and footer is not None and
            rows == summary["row_count"] and
            previous_phase == "postflight" and
            set(RESOURCE_MONITOR_PHASES) <= seen_phases,
            "Source5 resource-monitor stream omits its full bounded phase coverage")
    require(launch_prefix is None or (prefix_checked and
            launch_prefix["high_water"] == prefix_high_water),
            "Source5 launch monitor prefix extends beyond the finalized stream")
    require(set(origin_root_identities) == set(high_water) and
            not placeholder_devices,
            "Source5 resource-monitor stream never bound every writable root identity")
    footer_body = {key: item for key, item in footer.items()
                   if key != "footer_sha256"}
    require(set(footer) == {
                "schema", "budget", "row_count", "previous_sha256",
                "prefix_sha256", "high_water", "final_usage", "failure",
                "ended_monotonic_ns", "footer_sha256",
            } and footer["schema"] == SOAK_RESOURCE_MONITOR_FOOTER_SCHEMA and
            footer["budget"] == budget_pin and footer["row_count"] == rows and
            footer["previous_sha256"] == previous_sha and
            footer["prefix_sha256"] == prefix_digest.hexdigest() and
            footer["high_water"] == high_water == summary["high_water"] and
            footer["final_usage"] == summary["final_usage"] and
            footer["failure"] is None and summary["failure"] is None and
            footer["footer_sha256"] == sha256(canonical_bytes(footer_body)) and
            type(footer["ended_monotonic_ns"]) is int and
            previous_ns <= footer["ended_monotonic_ns"] and
            footer["ended_monotonic_ns"] - previous_ns <= gap_ns,
            "Source5 resource-monitor footer/high-water summary differs")
    require(summary["prefix_sha256"] == footer["prefix_sha256"],
            "Source5 resource-monitor launch/footer prefix digest differs")
    return {
        "summary": summary,
        "phase_bounds": phase_bounds,
        "phase_counts": phase_counts,
        "origin_root_identities": origin_root_identities,
        "footer_ended_monotonic_ns": footer["ended_monotonic_ns"],
    }


def _collect_evidence_inventory(
    component: dict[str, Any], prepared: dict[str, Any], job: dict[str, Any],
    authorization_context: dict[str, Any], material_index: dict[str, Any],
    recipe: dict[str, Any], probe_capture: dict[str, Any],
    probe_capture_pin: dict[str, str],
    pressure_origin: dict[str, Any], output_root: Path,
    probe_root: Path, readback: types.ModuleType,
) -> tuple[list[dict[str, Any]], list[str]]:
    source_root = Path(prepared["source_root"]).resolve(strict=True)
    input_root = _generation_input_root(prepared)
    inventory: dict[str, dict[str, Any]] = {}

    def add(record: dict[str, Any], label: str) -> None:
        path = record["path"]
        previous = inventory.get(path)
        require(previous is None or previous == record,
                f"Source5 Soak evidence inventory conflicts at {label}: {path}")
        inventory[path] = record

    for entry in _typed_source_inventory(source_root, prepared["source"]):
        add(entry, "typed SourceV5 source/artifact")
    for entry in _declared_soak_output_inventory(component, output_root, readback):
        add(entry, "closed Soak output")
    for entry in _declared_probe_capture_inventory(
        probe_root, probe_capture, probe_capture_pin,
    ):
        add(entry, "closed ProbeV1 output")

    dependency_values = (
        component, prepared, job, authorization_context, material_index,
        recipe, probe_capture, pressure_origin,
    )
    raw_pins = _raw_pins_in(dependency_values)
    for path, checksum in _absolute_file_sha_pins_in(dependency_values).items():
        prior = raw_pins.get(path)
        require(prior is None or prior == checksum,
                f"Source5 Soak raw/SHA pin roles conflict for {path}")
        raw_pins[path] = checksum
    # Relative raw pins are interpreted only inside the original frozen input
    # generation. These values have already passed their typed caller schemas;
    # no file is classified or parsed merely because its name ends in .json.
    for path, checksum in _relative_raw_pins_in(dependency_values, input_root):
        prior = raw_pins.get(path)
        require(prior is None or prior == checksum,
                f"Source5 Soak relative/raw pin roles conflict for {path}")
        raw_pins[path] = checksum
    for host_ref in prepared["source_manifest_raw_refs"].values():
        pin = raw_pin({"path": host_ref["path"],
                       "raw_sha256": host_ref["raw_sha256"]},
                      "Source5 source manifest dependency")
        raw_pins[pin["path"]] = pin["raw_sha256"]
    for pair in (prepared["prepared"]["spec_path"],
                 prepared["prepared"]["plan_path"]):
        require(Path(pair).is_absolute(),
                "Source5 Soak original SpecV3/PlanV3 path is not absolute")

    raw_pins[str(prepared["prepared"]["spec_path"])] = prepared["prepared"]["spec_raw_sha256"]
    raw_pins[str(prepared["prepared"]["plan_path"])] = prepared["prepared"]["plan_raw_sha256"]
    # All document references are collected from these role-validated values
    # and the explicit SourceV5/source/Spec/Plan pins above. Hash each declared
    # dependency once, but do not recursively deserialize arbitrary pinned
    # files based on a filename suffix: each original owner independently
    # parses its own closed schemas during offline replay after the whole path
    # map has been checked.
    for path_text, expected_sha in sorted(raw_pins.items()):
        expected_sha = digest(expected_sha,
                              "Source5 Soak dependency raw SHA-256")
        entry = _stable_file_inventory(
            Path(path_text), "Source5 Soak dependency", 32 * 1024 * 1024 * 1024,
        )
        require(entry["raw_sha256"] == expected_sha,
                f"Source5 Soak dependency changed from its raw pin: {path_text}")
        add(entry, "raw dependency")
    for path_text in pressure_origin["recipe_dependency_paths"]:
        path = Path(path_text)
        require(path.is_absolute() and path.resolve(strict=True) == path,
                f"Source5 pressure recipe dependency path is aliased: {path}")
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode),
                f"Source5 pressure recipe dependency is a symlink: {path}")
        if stat.S_ISDIR(info.st_mode):
            add({"path": path_text, "kind": "directory",
                 "mode": f"{stat.S_IMODE(info.st_mode):04o}"},
                "pressure recipe directory dependency")
        elif stat.S_ISREG(info.st_mode):
            record = _stable_file_inventory(
                path, "Source5 pressure recipe path dependency",
                32 * 1024 * 1024 * 1024,
            )
            expected_sha = raw_pins.get(path_text)
            inventoried = inventory.get(path_text)
            require((expected_sha is not None and
                     record["raw_sha256"] == expected_sha) or
                    (expected_sha is None and inventoried is not None and
                     inventoried["kind"] == "file" and
                     inventoried["raw_sha256"] == record["raw_sha256"]),
                    f"Source5 pressure recipe file dependency lacks its exact raw pin: {path}")
            add(record, "pressure recipe file dependency")
        else:
            raise Source5SoakError(
                f"Source5 pressure recipe dependency is a special file: {path}",
            )
    # Source5 completion carries closed per-producer maps. Include those exact
    # declared paths before the completion verifier reopens any of them; these
    # entries are sourced from typed manifests, not a directory walk.
    nested_paths = _nested_evidence_paths_in((
        prepared, job, authorization_context, material_index, recipe,
    ))
    for path_text in sorted(nested_paths):
        if path_text in inventory:
            continue
        path = Path(path_text)
        require(path.resolve(strict=True) == path,
                f"nested Source5 evidence map path is aliased: {path}")
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode),
                f"nested Source5 evidence map names an untyped symlink: {path}")
        if stat.S_ISDIR(info.st_mode):
            add({"path": path_text, "kind": "directory",
                 "mode": f"{stat.S_IMODE(info.st_mode):04o}"},
                "nested typed evidence-map directory")
        elif stat.S_ISREG(info.st_mode):
            add(_stable_file_inventory(
                path, "nested Source5 typed evidence-map file",
                32 * 1024 * 1024 * 1024,
            ), "nested typed evidence-map file")
        else:
            raise Source5SoakError(
                f"nested Source5 evidence map names a special file: {path}",
            )
    storage_paths = {
        item["path"]
        for item in pressure_origin["storage_before"]["application_storage"]
    } | {pressure_origin["storage_before"]["pressure_scratch"]["path"]}
    storage_paths.update(
        item["path"]
        for item in pressure_origin["storage_after"]["application_storage"]
    )
    storage_paths.add(pressure_origin["storage_after"]["pressure_scratch"]["path"])
    for path_text in sorted(storage_paths):
        path = Path(path_text)
        require(path.is_absolute() and path.resolve(strict=True) == path,
                f"Source5 Soak TMPDIR/storage path is aliased: {path}")
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
                f"Source5 Soak TMPDIR/storage path is not a real directory: {path}")
        add({"path": path_text, "kind": "directory",
             "mode": f"{stat.S_IMODE(info.st_mode):04o}"},
            "frozen pressure storage directory")
    if component.get("schema") == COMPONENT_SCHEMA_V2:
        budget_document, _budget_pin = _read_resource_budget_pin(
            component["resource_budget"],
        )
        fixed_owner, _owner_sha, _owner_path = \
            _load_fixed_pair_process_owner(prepared)
        for role, path_field, byte_field, inode_field in (
            ("application TMPDIR", "application_tmpdir",
             "maximum_application_tmpdir_bytes",
             "maximum_application_tmpdir_inodes"),
            ("pressure scratch", "pressure_scratch",
             "maximum_pressure_scratch_bytes",
             "maximum_pressure_scratch_inodes"),
        ):
            root = Path(budget_document["layout"][path_field])
            root_fd = fixed_owner._open_tmpdir_absolute_directory(root)
            try:
                root_info = os.fstat(root_fd)
                fixed_owner._tmpdir_usage_snapshot(
                    root, budget_document["ceilings"][byte_field],
                    budget_document["ceilings"][inode_field],
                    (root_info.st_dev, root_info.st_ino),
                    allow_descendant_enoent=False,
                )
            finally:
                os.close(root_fd)
            for record in _tree_inventory(
                    root, f"Source5 bounded {role}"):
                if record["kind"] == "file":
                    file_info = Path(record["path"]).lstat()
                    require(file_info.st_nlink == 1 and
                            file_info.st_uid == os.getuid(),
                            f"Source5 bounded {role} contains a hardlink/unowned file")
                add(record, f"bounded {role} recursive inventory")
    require(len(inventory) <= MAX_EVIDENCE_ENTRIES,
            "Source5 Soak evidence inventory exceeds its finite entry bound")
    required_directories = {
        str(source_root), str(input_root), str(output_root), str(probe_root),
    }
    required_directories.update(storage_paths)
    required_directories.add(str(output_root.parent))
    for path_text in raw_pins:
        required_directories.add(str(Path(path_text).parent))
    for directory in required_directories:
        require(Path(directory).is_dir() and not Path(directory).is_symlink(),
                f"Source5 Soak evidence base is not a real directory: {directory}")
        if directory not in inventory:
            info = Path(directory).lstat()
            add({"path": directory, "kind": "directory",
                 "mode": f"{stat.S_IMODE(info.st_mode):04o}"},
                "evidence base")
    return sorted(inventory.values(), key=lambda item: item["path"]), sorted(required_directories)


def _relative_raw_pins_in(value: object, input_root: Path) -> list[tuple[str, str]]:
    pins: list[tuple[str, str]] = []
    pending = [value]
    seen: set[int] = set()
    while pending:
        item = pending.pop()
        if type(item) is dict:
            identity = id(item)
            if identity in seen:
                continue
            seen.add(identity)
            relative = item.get("relative_path")
            raw_sha = item.get("raw_sha256")
            if type(relative) is str and raw_sha is not None:
                candidate = Path(relative)
                require(not candidate.is_absolute() and ".." not in candidate.parts,
                        "Source5 Soak nested input path is not portable")
                pins.append((str(input_root / candidate),
                             digest(raw_sha, "Source5 nested input raw SHA-256")))
            pending.extend(item.values())
        elif type(item) in (list, tuple):
            pending.extend(item)
    return pins


def _source5_resource_final_usage(
    budget: dict[str, Any], inventory: list[dict[str, Any]],
    monitor: dict[str, Any],
) -> dict[str, Any]:
    """Recompute quiescent usage from the complete captured writable inventory."""
    ceilings = budget["ceilings"]
    roots = {
        "output": (Path(budget["layout"]["output_root"]),
                   "maximum_output_bytes", "maximum_output_inodes"),
        "application_tmpdir": (Path(budget["layout"]["application_tmpdir"]),
                               "maximum_application_tmpdir_bytes",
                               "maximum_application_tmpdir_inodes"),
        "pressure_scratch": (Path(budget["layout"]["pressure_scratch"]),
                             "maximum_pressure_scratch_bytes",
                             "maximum_pressure_scratch_inodes"),
        "probe_capture": (Path(budget["layout"]["probe_capture_root"]),
                          "maximum_probe_output_bytes",
                          "maximum_probe_output_inodes"),
        "probe_tmpdir": (Path(budget["layout"]["probe_tmpdir"]),
                         "maximum_probe_tmpdir_bytes",
                         "maximum_probe_tmpdir_inodes"),
    }
    final: dict[str, dict[str, int]] = {}
    sampled = exact(monitor.get("high_water"), set(roots),
                    "Source5 Soak monitor sampled high-water map")
    high_water: dict[str, dict[str, int]] = {}
    by_path = {entry["path"]: entry for entry in inventory}
    for role, (root, byte_cap, inode_cap) in roots.items():
        require(type(by_path.get(str(root))) is dict and
                by_path[str(root)]["kind"] == "directory",
                f"Source5 bounded final inventory omits the {role} root")
        descendants = [entry for entry in inventory
                       if type(entry) is dict and type(entry.get("path")) is str and
                       root in Path(entry["path"]).parents]
        bytes_used = sum(entry["size"] for entry in descendants
                         if entry.get("kind") == "file")
        inode_count = len(descendants)
        require(type(bytes_used) is int and type(inode_count) is int and
                bytes_used <= ceilings[byte_cap] and
                inode_count <= ceilings[inode_cap],
                f"Source5 bounded final {role} inventory exceeds its frozen ceiling")
        final[role] = {"bytes_used": bytes_used,
                       "inode_count": inode_count}
        high = exact(sampled[role], {"bytes", "inodes"},
                     f"Source5 Soak sampled {role} high-water")
        require(type(high["bytes"]) is int and high["bytes"] >= 0 and
                type(high["inodes"]) is int and high["inodes"] >= 0,
                f"Source5 Soak sampled {role} high-water is malformed")
        high_water[role] = {
            "bytes": max(high["bytes"], bytes_used),
            "inodes": max(high["inodes"], inode_count),
        }
    return {"domains": final, "high_water": high_water}


def _host_receipt_value(
    component: dict[str, Any], prepared: dict[str, Any], job: dict[str, Any],
    authorization_context: dict[str, Any], binding: dict[str, Any],
    generation: dict[str, Any], host_identity: dict[str, Any],
    observed_host_pin: dict[str, str], absence: list[dict[str, Any]],
    probe_capture: dict[str, Any], probe_capture_pin: dict[str, str],
    pressure_origin: dict[str, Any],
    evidence_inventory: list[dict[str, Any]], evidence_bases: list[str],
    source_root: Path, input_root: Path, output_root: Path,
    probe_root: Path, result: dict[str, Any], *,
    resource_budget_pin_value: dict[str, str] | None = None,
    resource_monitor_value: dict[str, Any] | None = None,
    probe_capture_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    helper_pin = raw_pin(authorization_context["helper_input"],
                         "Source5 Soak original helper input")
    bounded = resource_budget_pin_value is not None
    require((resource_monitor_value is None) == (not bounded),
            "Source5 bounded host receipt must bind its monitor summary")
    if bounded:
        require(probe_capture_context is not None,
                "Source5 bounded host receipt requires its captured construction probe")
        if probe_capture_context["capture"].get("schema") == PROBE_CAPTURE_SCHEMA_V2:
            probe_projection = {
                "schema": PROBE_CAPTURE_SCHEMA_V2,
                "receipt_pin": dict(probe_capture_context["capture_pin"]),
                "capture_sha256": probe_capture_context["capture"]["receipt_sha256"],
                "probe_raw_sha256": probe_capture_context["probe_raw_sha256"],
                "normal_binary_sha256": probe_capture_context["normal_binary_sha256"],
                "owner_source_sha256": probe_capture_context["capture"][
                    "owner_modules"]["fixed_pair"]["raw_sha256"],
                "capacity_bundle": probe_capture_context["capacity_bundle"],
                "request": probe_capture_context["request"],
            }
        else:
            probe_projection = {
                "schema": PROBE_CAPTURE_SCHEMA,
                "receipt_pin": {
                    "path": probe_capture_context["capture_pin"]["path"],
                    "raw_sha256": probe_capture_context["capture_pin"]["raw_sha256"],
                },
                "capture_sha256": probe_capture_context["capture"]["capture_sha256"],
                "probe_raw_sha256": probe_capture_context["capture"]["probe_raw_sha256"],
                "normal_binary_sha256": probe_capture_context["capture"]["normal_binary_sha256"],
                "owner_source_sha256": probe_capture_context["capture"]["owner_source_sha256"],
            }
        budget_document, checked_budget_pin = _read_resource_budget_pin(
            resource_budget_pin_value,
        )
        require(checked_budget_pin == resource_budget_pin_value,
                "Source5 bounded host receipt budget pin changed")
        require(component.get("schema") == COMPONENT_SCHEMA_V2 and
                component.get("validated") is True and
                component.get("passed") is True and
                result.get("validated") is True and
                result.get("passed") is True and
                result.get("qualification_eligible") is
                    (component["readback"].get("mode") == "qualified") and
                resource_monitor_value.get("failure") is None,
                "Source5 bounded host receipt cannot seal an incomplete strict component replay")
        _verify_source5_resource_monitor_stream(
            budget_document, checked_budget_pin, resource_monitor_value,
        )
        final_usage = _source5_resource_final_usage(
            budget_document, evidence_inventory, resource_monitor_value,
        )
        monitor_projection = dict(resource_monitor_value)
        monitor_projection["high_water"] = final_usage["high_water"]
        monitor_projection["final_usage"] = final_usage["domains"]
    else:
        probe_projection = {
            "receipt_pin": {
                "path": probe_capture_pin["path"],
                "raw_sha256": probe_capture_pin["raw_sha256"],
            },
            "capture_sha256": probe_capture["capture_sha256"],
            "probe_raw_sha256": probe_capture["probe_raw_sha256"],
            "normal_binary_sha256": probe_capture["normal_binary_sha256"],
            "owner_source_sha256": probe_capture["owner_source_sha256"],
        }
    body = {
        "schema": (HOST_VERIFICATION_SCHEMA_V3 if bounded else
                   HOST_VERIFICATION_SCHEMA),
        "campaign_id": component["campaign_id"],
        "host_id": component["host_id"],
        "run_id": component["run_id"],
        "component_sha256": sha256(canonical_bytes(component)),
        "component_pins": component["pins"],
        "generation": generation,
        "prepared_host_context_pin": raw_pin(
            binding["prepared_host_context_pin"],
            "Source5 Soak prepared host context",
        ),
        "fixed_spec_host_pin": raw_pin(
            binding["fixed_spec_host_pin"], "Source5 Soak frozen SpecV3 host",
        ),
        "observed_host_pin": observed_host_pin,
        "prepared_host_binding_sha256": binding["binding_sha256"],
        "helper_input_pin": helper_pin,
        "construction_probe": probe_projection,
        "pressure_origin": pressure_origin,
        "origin_host": host_identity,
        "process_absence": absence,
        "tree_roots": {
            "source": str(source_root), "input": str(input_root),
            "output": str(output_root), "probe_capture": str(probe_root),
        },
        "evidence_inventory": evidence_inventory,
        "evidence_bases": evidence_bases,
        "readback_sha256": sha256(canonical_bytes(result)),
        "bounded_execution_ready": bounded,
        "bounded_blockers": ([] if bounded else
                              ["prospective_bounded_soak_resource_budget_not_pinned"]),
        "qualification_eligible": False,
        "execution_ready": False,
    }
    if bounded:
        body["resource_budget"] = resource_budget_pin_value
        body["resource_monitor"] = monitor_projection
        body["final_usage"] = final_usage
    body["receipt_sha256"] = sha256(canonical_bytes(body))
    return body


def verify_source5_soak_component_with_host_receipt(
    component: dict[str, Any], prepared: dict[str, Any],
    job: dict[str, Any], authorization_context: dict[str, Any],
    readback: types.ModuleType, host_receipt_path: str | Path, *,
    probe_capture_root: str | Path, resource_monitor: Any = None,
) -> dict[str, str]:
    """Strictly replay on the origin host and seal its exact Soak evidence."""
    receipt_path = Path(host_receipt_path)
    capture_root = Path(probe_capture_root)
    require(receipt_path.is_absolute() and ".." not in receipt_path.parts and
            not receipt_path.exists() and not receipt_path.is_symlink(),
            "Source5 Soak host-verification receipt must be a new normalized path")
    receipt_parent = receipt_path.parent
    receipt_parent_info = receipt_parent.stat()
    require(stat.S_ISDIR(receipt_parent_info.st_mode) and
            receipt_parent_info.st_uid == os.getuid() and
            stat.S_IMODE(receipt_parent_info.st_mode) == 0o700,
            "Source5 Soak host-verification parent must be owned mode 0700")
    binding = _selected_prepared_host_binding(
        prepared["source5_prepared_input_completion"], prepared["host_id"],
    )
    materials_pin = raw_pin(component["pins"]["materials_index"],
                            "Source5 Soak materials index")
    material_index, _index_raw, _index_sha = read_json(
        Path(materials_pin["path"]), materials_pin["raw_sha256"],
        "Source5 Soak materials index", MAX_ARTIFACT_BYTES,
    )
    _, recipe, _identities = _verify_build_receipt(
        material_index, prepared, job, binding, readback,
    )
    bounded = component.get("schema") == COMPONENT_SCHEMA_V2
    budget_document = None
    budget_pin = None
    probe_capture_context = None
    if bounded:
        budget_document, budget_pin = _read_resource_budget_pin(
            component["resource_budget"],
        )
        _validate_resource_budget_bindings(
            budget_document, prepared, job, binding, recipe, material_index,
            output_root=Path(component["pins"]["supervisor"]["path"]).parent,
            details=authorization_context.get("details"), readback=readback,
        )
        require(budget_pin == component["resource_budget"],
                "Source5 Soak host receipt budget pin differs from component")
        require(str(capture_root) == budget_document["layout"]["probe_capture_root"] and
                str(receipt_path) == budget_document["layout"]["host_receipt_path"],
                "Source5 Soak host receipt/capture paths differ from their prospective budget")
        require(len(canonical_bytes(component)) <=
                budget_document["artifact_limits"]["component_receipt_bytes"],
                "Source5 bounded component exceeds its frozen output role limit")
        require(resource_monitor is not None and
                getattr(resource_monitor, "fd", None) is None and
                getattr(resource_monitor, "budget_pin", None) == budget_pin and
                getattr(resource_monitor, "final_summary", None) ==
                    component.get("resource_monitor"),
                "Source5 host verifier requires the finalized budget-pinned monitor owner")
        probe_capture_pin = component["pins"]["probe_capture"]
        if recipe["feedback_expectation"]["policy"].get(
                "capacity_floor_policy_id") is not None:
            probe_capture_context, probe_capture_pin = \
                _source5_probe_v2_audit_context(
                    prepared, recipe, probe_capture_pin,
                )
            probe_capture = probe_capture_context["capture"]
        else:
            probe_capture, _capture_raw, _capture_sha = read_json(
                Path(probe_capture_pin["path"]),
                probe_capture_pin["raw_sha256"],
                "Source5 bounded ProbeV1 capture receipt", MAX_RECEIPT_BYTES,
            )
            probe_capture_context = {
                "capture": probe_capture,
                "capture_pin": probe_capture_pin,
            }
        require(Path(probe_capture_pin["path"]).parent == capture_root,
                "Source5 Soak component probe receipt is outside the budgeted capture root")
    else:
        probe_capture, probe_capture_pin, _probe_context = \
            _capture_source5_soak_probe(
                prepared, job, binding, recipe, readback, capture_root,
            )
    # Preserve the public strict/live path unchanged. It independently replays
    # its original APP probe, authorization overlay, cleanup and full readback.
    result = verify_source5_soak_component(
        component, prepared, job, authorization_context, readback,
    )
    host_identity, observed_host_pin = _capture_origin_host_identity(
        binding, prepared["host_id"],
    )
    supervisor_pin = raw_pin(component["pins"]["supervisor"],
                             "Source5 Soak supervisor receipt")
    supervisor, _supervisor_raw, _supervisor_sha = read_json(
        Path(supervisor_pin["path"]), supervisor_pin["raw_sha256"],
        "Source5 Soak supervisor receipt", MAX_RECEIPT_BYTES,
    )
    absence = _process_absence_snapshot(supervisor, readback)
    pressure_origin = _pressure_origin_projection(
        recipe, supervisor, Path(supervisor_pin["path"]).parent,
        readback, prepared,
    )
    supervisor_path = Path(supervisor_pin["path"])
    output_root = supervisor_path.parent.resolve(strict=True)
    source_root = Path(prepared["source_root"]).resolve(strict=True)
    input_root = _generation_input_root(prepared)
    capture_root = capture_root.resolve(strict=True)
    for protected in (source_root, input_root, output_root):
        require(capture_root != protected and protected not in capture_root.parents and
                capture_root not in protected.parents,
                "Source5 Soak ProbeV1 capture must remain outside immutable inputs and run artifacts")
    require(receipt_path != capture_root and
            capture_root not in receipt_path.parents and
            receipt_path.parent.resolve(strict=True) not in
                (source_root, input_root, output_root, capture_root),
            "Source5 Soak host receipt must remain outside immutable inputs and run artifacts")
    generation = _generation_projection(prepared, job, binding)
    inventory, evidence_bases = _collect_evidence_inventory(
        component, prepared, job, authorization_context, material_index,
        recipe, probe_capture, probe_capture_pin, pressure_origin,
        output_root, capture_root, readback,
    )
    if str(receipt_parent) not in evidence_bases:
        info = receipt_parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
                "Source5 Soak host-receipt parent is not a real directory")
        inventory.append({
            "path": str(receipt_parent), "kind": "directory",
            "mode": f"{stat.S_IMODE(info.st_mode):04o}",
        })
        inventory.sort(key=lambda item: item["path"])
        evidence_bases = sorted([*evidence_bases, str(receipt_parent)])
    receipt = _host_receipt_value(
        component, prepared, job, authorization_context, binding, generation,
        host_identity, observed_host_pin, absence, probe_capture,
        probe_capture_pin, pressure_origin, inventory, evidence_bases, source_root, input_root,
        output_root, capture_root, result,
        resource_budget_pin_value=budget_pin,
        resource_monitor_value=(None if not bounded else
                                component["resource_monitor"]),
        probe_capture_context=probe_capture_context,
    )
    require(len(canonical_bytes(receipt)) <= MAX_RECEIPT_BYTES,
            "Source5 Soak host-verification receipt exceeds its finite byte bound")
    if bounded:
        require(len(canonical_bytes(receipt)) <=
                budget_document["artifact_limits"]["host_receipt_bytes"],
                "Source5 Soak host-verification receipt exceeds its frozen artifact limit")
    written = _write_exclusive_json(
        receipt_path, receipt, "Source5 Soak strict host-verification receipt",
    )
    info = receipt_path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
            stat.S_IMODE(info.st_mode) == 0o600,
            "Source5 Soak host-verification receipt is not an owned mode-0600 file")
    return {**written, "receipt_sha256": receipt["receipt_sha256"]}


def _current_tree_entries_without_hash(
    root: Path, allowed_paths: set[str],
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    pending = [root]
    while pending:
        current = pending.pop()
        info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
                f"offline Source5 Soak evidence directory is linked or missing: {current}")
        entries.append({"path": str(current), "kind": "directory",
                        "mode": f"{stat.S_IMODE(info.st_mode):04o}"})
        children = sorted(os.scandir(current), key=lambda item: item.name)
        for child in children:
            path = current / child.name
            require(str(path) in allowed_paths,
                    f"offline Source5 Soak tree contains an undeclared path: {path}")
            child_info = child.stat(follow_symlinks=False)
            require(not stat.S_ISLNK(child_info.st_mode),
                    f"offline Source5 Soak evidence contains a symlink: {path}")
            if stat.S_ISDIR(child_info.st_mode):
                pending.append(path)
            elif stat.S_ISREG(child_info.st_mode):
                entries.append({
                    "path": str(path), "kind": "file",
                    "mode": f"{stat.S_IMODE(child_info.st_mode):04o}",
                    "size": child_info.st_size,
                })
            else:
                raise Source5SoakError(
                    f"offline Source5 Soak evidence contains a special file: {path}",
                )
    entries.sort(key=lambda item: item["path"])
    return entries


def _verify_evidence_inventory(
    receipt: dict[str, Any], mapped: dict[str, str],
) -> None:
    entries = receipt["evidence_inventory"]
    require(type(entries) is list and 0 < len(entries) <= MAX_EVIDENCE_ENTRIES,
            "Source5 Soak host receipt evidence inventory size differs")
    expected: dict[str, dict[str, Any]] = {}
    previous = ""
    for index, entry_value in enumerate(entries):
        require(type(entry_value) is dict and type(entry_value.get("kind")) is str,
                f"Source5 Soak evidence inventory entry[{index}] is malformed")
        if entry_value["kind"] == "file":
            entry = exact(entry_value,
                          {"path", "kind", "mode", "size", "raw_sha256"},
                          f"Source5 Soak evidence file[{index}]")
            digest(entry["raw_sha256"],
                   f"Source5 Soak evidence file[{index}] raw SHA-256")
            require(type(entry["size"]) is int and entry["size"] >= 0,
                    f"Source5 Soak evidence file[{index}] size is invalid")
        elif entry_value["kind"] == "symlink":
            entry = exact(entry_value, {
                "path", "kind", "mode", "size", "raw_sha256", "target",
            }, f"Source5 Soak evidence symlink[{index}]")
            digest(entry["raw_sha256"],
                   f"Source5 Soak evidence symlink[{index}] target SHA-256")
            require(type(entry["size"]) is int and entry["size"] >= 0 and
                    type(entry["target"]) is str,
                    f"Source5 Soak evidence symlink[{index}] is malformed")
        else:
            entry = exact(entry_value, {"path", "kind", "mode"},
                          f"Source5 Soak evidence directory[{index}]")
            require(entry["kind"] == "directory",
                    f"Source5 Soak evidence inventory entry[{index}] kind differs")
        require(type(entry["path"]) is str and Path(entry["path"]).is_absolute() and
                str(Path(entry["path"])) == entry["path"] and
                entry["path"] > previous and entry["path"] not in expected and
                type(entry["mode"]) is str and
                ((entry["kind"] == "symlink" and entry["mode"] == "120000") or
                 (entry["kind"] != "symlink" and
                  re.fullmatch(r"[0-7]{4}", entry["mode"]) is not None)),
                f"Source5 Soak evidence inventory entry[{index}] is unsorted or malformed")
        previous = entry["path"]
        expected[entry["path"]] = entry
    tree_roots = exact(receipt["tree_roots"], {
        "source", "input", "output", "probe_capture",
    }, "Source5 Soak evidence tree roots")
    for role in ("source", "input", "output", "probe_capture"):
        path = tree_roots[role]
        require(type(path) is str and Path(path).is_absolute() and
                str(Path(path)) == path,
                f"Source5 Soak {role} root is not normalized absolute")
    recursive_roots = {
        tree_roots["output"], tree_roots["probe_capture"],
    }
    if receipt.get("schema") == HOST_VERIFICATION_SCHEMA_V3:
        budget, _budget_pin = _read_resource_budget_pin(
            receipt["resource_budget"],
        )
        recursive_roots.update({
            budget["layout"]["application_tmpdir"],
            budget["layout"]["pressure_scratch"],
            budget["layout"]["probe_tmpdir"],
        })
    for root_text in sorted(recursive_roots):
        root = Path(root_text)
        require(root_text in expected and expected[root_text]["kind"] == "directory",
                f"offline Source5 Soak receipt omits recursive evidence root: {root_text}")
        actual = _current_tree_entries_without_hash(root, set(expected))
        declared = [entry for entry in entries
                    if entry["path"] == str(root) or
                    root in Path(entry["path"]).parents]
        declared_projection = []
        for entry in declared:
            if entry["kind"] == "file":
                declared_projection.append({
                    "path": entry["path"], "kind": "file",
                    "mode": entry["mode"], "size": entry["size"],
                })
            else:
                declared_projection.append({
                    "path": entry["path"], "kind": "directory",
                    "mode": entry["mode"],
                })
        require(actual == sorted(declared_projection, key=lambda item: item["path"]),
                f"offline Source5 Soak recursive tree membership/modes differ: {root}")
    _require_evidence_paths(mapped, set(expected), "typed inventory")
    _require_evidence_paths(mapped, set(receipt["evidence_bases"]),
                            "evidence-base directory")
    for directory in receipt["evidence_bases"]:
        path = Path(directory)
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
                f"offline Source5 Soak evidence base is not a real directory: {directory}")
    for entry in entries:
        path = Path(entry["path"])
        info = path.lstat()
        actual_mode = "120000" if stat.S_ISLNK(info.st_mode) else f"{stat.S_IMODE(info.st_mode):04o}"
        require(actual_mode == entry["mode"],
                f"offline Source5 Soak evidence mode changed: {entry['path']}")
        if entry["kind"] == "file":
            actual = _stable_file_inventory(
                path, "offline Source5 Soak evidence file",
                32 * 1024 * 1024 * 1024,
            )
            require(actual == entry,
                    f"offline Source5 Soak evidence bytes changed: {entry['path']}")
        elif entry["kind"] == "symlink":
            path_parent = path.parent
            parent_info = path_parent.lstat()
            require(stat.S_ISDIR(parent_info.st_mode) and
                    not stat.S_ISLNK(parent_info.st_mode),
                    f"offline Source5 Soak symlink parent is linked: {entry['path']}")
            target = os.readlink(path)
            target_raw = target.encode("utf-8")
            require(stat.S_ISLNK(info.st_mode) and target == entry["target"] and
                    len(target_raw) == entry["size"] and
                    sha256(target_raw) == entry["raw_sha256"],
                    f"offline Source5 Soak typed symlink changed: {entry['path']}")
        else:
            require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
                    f"offline Source5 Soak evidence directory changed: {entry['path']}")


def _validate_host_origin_offline(
    receipt: dict[str, Any], prepared: dict[str, Any], binding: dict[str, Any],
) -> None:
    host_identity = exact(receipt["origin_host"], {
        "schema", "host_id", "observed_host_raw_sha256", "boot_id_sha256",
        "kernel_release", "allowed_cpu_affinity", "network_namespace_inode",
        "controls_sha256", "host_identity_sha256",
    }, "Source5 Soak origin host facts")
    body = {key: value for key, value in host_identity.items()
            if key != "host_identity_sha256"}
    require(host_identity["schema"] ==
            "allocatbelt.application-source5-soak-origin-host.v1" and
            host_identity["host_id"] == prepared["host_id"] and
            host_identity["host_identity_sha256"] ==
                sha256(canonical_bytes(body)),
            "Source5 Soak origin host facts have an invalid identity digest")
    host_pin = raw_pin(receipt["observed_host_pin"],
                       "Source5 Soak observed-host pin")
    require(host_pin == raw_pin(binding["prepared_host_context_pin"],
                                "Source5 prepared host context") and
            host_identity["observed_host_raw_sha256"] == host_pin["raw_sha256"],
            "Source5 Soak origin host facts changed the prepared observed-host bytes")
    observed, _raw, observed_sha = read_json(
        Path(host_pin["path"]), host_pin["raw_sha256"],
        "Source5 offline observed-host context", MAX_ARTIFACT_BYTES,
    )
    exact(observed, {
        "schema", "host_id", "boot_id_sha256", "controls_sha256", "controls",
        "kernel_release", "cpu_model", "cpu_affinity",
        "network_namespace_inode",
    }, "Source5 offline observed-host context")
    require(observed_sha == host_identity["observed_host_raw_sha256"] and
            observed["host_id"] == host_identity["host_id"] and
            observed["boot_id_sha256"] == host_identity["boot_id_sha256"] ==
                binding["boot_id_sha256"] and
            observed["kernel_release"] == host_identity["kernel_release"] ==
                binding["kernel_release"] and
            observed["cpu_affinity"] == host_identity["allowed_cpu_affinity"] ==
                binding["process_affinity"] and
            observed["network_namespace_inode"] ==
                host_identity["network_namespace_inode"] ==
                    binding["network_namespace_inode"] and
            observed["controls_sha256"] == host_identity["controls_sha256"] ==
                binding["controls_sha256"],
            "Source5 Soak origin host facts differ from the pinned prepared context")


def _validate_process_absence_offline(
    receipt: dict[str, Any], supervisor: dict[str, Any],
) -> None:
    app = supervisor["application_attestation"]["process"]
    driver = supervisor["pressure_driver"]
    expected = [{"role": "application", "pid": app["pid"],
                 "start_ticks": app["start_ticks"]},
                {"role": "pressure_driver", "pid": driver["pid"],
                 "start_ticks": driver["start_ticks"]}]
    for session in supervisor["pressure_worker_sessions"]:
        expected.append({
            "role": f"pressure_worker:{session['role']}:{'-' if session.get('cpu') is None else session['cpu']}",
            "pid": session["pid"], "start_ticks": session["start_ticks"],
        })
    expected.sort(key=lambda item: item["role"])
    actual = receipt["process_absence"]
    require(type(actual) is list and len(actual) == len(expected),
            "Source5 Soak origin process-absence count differs from its supervisor")
    for index, (row_value, identity) in enumerate(zip(actual, expected, strict=True)):
        row = exact(row_value, {
            "role", "pid", "start_ticks", "original_identity_absent",
            "observed_start_ticks", "observed_monotonic_ns",
        }, f"Source5 Soak origin process absence[{index}]")
        require({key: row[key] for key in ("role", "pid", "start_ticks")} == identity and
                row["original_identity_absent"] is True and
                type(row["observed_monotonic_ns"]) is int and
                row["observed_monotonic_ns"] > 0 and
                (row["observed_start_ticks"] is None or
                 type(row["observed_start_ticks"]) is int and
                 row["observed_start_ticks"] != row["start_ticks"]),
                f"Source5 Soak origin process absence[{index}] is not bound to its original PID/start")


def _offline_probe_context(
    receipt: dict[str, Any], prepared: dict[str, Any],
    readback: types.ModuleType,
    *, resource_budget: dict[str, Any] | None = None,
) -> dict[str, Any]:
    probe = exact(receipt["construction_probe"], {
        "receipt_pin", "capture_sha256", "probe_raw_sha256",
        "normal_binary_sha256", "owner_source_sha256",
    }, "Source5 Soak ProbeV1 host receipt binding")
    capture_pin = raw_pin(probe["receipt_pin"],
                          "Source5 Soak ProbeV1 capture receipt")
    capture, _capture_raw, capture_sha = read_json(
        Path(capture_pin["path"]), capture_pin["raw_sha256"],
        "Source5 Soak ProbeV1 capture receipt", MAX_RECEIPT_BYTES,
    )
    exact(capture, {
        "schema", "source_manifest_raw_sha256", "source_tree_sha256",
        "normal_binary_sha256", "probe_raw_sha256", "owner_source_sha256",
        "owner_source_path", "owner_result_pin", "stdout", "stderr", "argv",
        "environment", "cwd", "cpu_affinity", "network_namespace_inode",
        "tmpdir_path", "tmpdir_receipt", "capture_budgets",
        "process_absence", "capture_sha256",
    }, "Source5 Soak ProbeV1 capture receipt")
    capture_body = {key: value for key, value in capture.items()
                    if key != "capture_sha256"}
    require(capture_sha == capture_pin["raw_sha256"] and
            capture["schema"] == PROBE_CAPTURE_SCHEMA and
            capture["capture_sha256"] == probe["capture_sha256"] ==
                sha256(canonical_bytes(capture_body)) and
            capture["probe_raw_sha256"] == probe["probe_raw_sha256"] and
            capture["normal_binary_sha256"] == probe["normal_binary_sha256"] and
            capture["owner_source_sha256"] == probe["owner_source_sha256"],
            "Source5 Soak ProbeV1 capture receipt differs from the strict host pin")
    if resource_budget is not None:
        _verify_source5_probe_resource_budget(
            resource_budget, prepared,
            {"capture": capture, "capture_pin": capture_pin},
        )
    owner_pin = raw_pin(capture["owner_result_pin"],
                        "Source5 ProbeV1 direct process owner result")
    owner_result, _owner_raw, _owner_sha = read_json(
        Path(owner_pin["path"]), owner_pin["raw_sha256"],
        "Source5 ProbeV1 direct process owner result", MAX_RECEIPT_BYTES,
    )
    absence = exact(capture["process_absence"], {
        "pid", "start_ticks", "original_identity_absent",
        "observed_start_ticks",
    }, "Source5 ProbeV1 origin process absence")
    owner_start = exact(owner_result["start"], {
        "pid", "start_ticks", "requested_argv", "requested_argv_sha256",
        "environment_sha256",
    }, "Source5 ProbeV1 owner process start")
    require(absence["pid"] == owner_start["pid"] and
            absence["start_ticks"] == owner_start["start_ticks"] and
            absence["original_identity_absent"] is True and
            (absence["observed_start_ticks"] is None or
             type(absence["observed_start_ticks"]) is int and
             absence["observed_start_ticks"] != absence["start_ticks"]),
            "Source5 ProbeV1 origin absence is not bound to its owner PID/start")
    tmpdir_receipt = exact(capture["tmpdir_receipt"], {
        "initial", "final", "output_mount", "byte_limit", "inode_limit",
    }, "Source5 ProbeV1 TMPDIR origin proof")
    owner, owner_sha, owner_path = _load_fixed_pair_process_owner(prepared)
    require(owner_sha == capture["owner_source_sha256"] and
            str(owner_path) == capture["owner_source_path"],
            "Source5 ProbeV1 owner module differs from its captured SourceV5 bytes")
    capture_budgets = exact(capture["capture_budgets"], {
        "stdout_bytes", "stderr_bytes", "tmpdir_bytes", "tmpdir_inodes",
        "output_bytes", "output_inodes", "deadline_seconds",
        "owner_receipt_bytes", "capture_receipt_bytes",
    }, "Source5 ProbeV1 immutable capture budgets")
    owner_budgets = owner._artifact_budgets()
    require(capture_budgets == {
        "stdout_bytes": owner_budgets["construction_probe_stdout_bytes"],
        "stderr_bytes": owner_budgets["construction_probe_stderr_bytes"],
        "tmpdir_bytes": owner_budgets["tmpdir_bytes"],
        "tmpdir_inodes": owner_budgets["tmpdir_inodes"],
        "output_bytes": (owner_budgets["construction_probe_stdout_bytes"] +
                         owner_budgets["construction_probe_stderr_bytes"] +
                         2 * owner_budgets["runtime_receipt_bytes"]),
        "output_inodes": 4,
        "deadline_seconds": int(owner.PROBE_TIMEOUT_SECONDS),
        "owner_receipt_bytes": owner_budgets["runtime_receipt_bytes"],
        "capture_receipt_bytes": owner_budgets["runtime_receipt_bytes"],
    } and tmpdir_receipt["byte_limit"] == capture_budgets["tmpdir_bytes"] and
            tmpdir_receipt["inode_limit"] == capture_budgets["tmpdir_inodes"] and
            tmpdir_receipt["initial"]["available_bytes"] >=
                capture_budgets["tmpdir_bytes"] + capture_budgets["output_bytes"] and
            tmpdir_receipt["initial"]["available_inodes"] >=
                capture_budgets["tmpdir_inodes"] + capture_budgets["output_inodes"],
            "Source5 ProbeV1 capture exceeded its immutable source-owner storage/deadline budget")
    owner._verify_tmpdir_storage_offline(
        tmpdir_receipt["initial"], tmpdir_receipt["final"],
        capture["tmpdir_path"], tmpdir_receipt["byte_limit"],
        tmpdir_receipt["inode_limit"], tmpdir_receipt["output_mount"],
        "Source5 Soak construction probe",
    )
    return {
        "schema": capture["schema"],
        "source_manifest_raw_sha256": capture["source_manifest_raw_sha256"],
        "source_tree_sha256": capture["source_tree_sha256"],
        "normal_binary_sha256": capture["normal_binary_sha256"],
        "probe_raw_sha256": capture["probe_raw_sha256"],
        "owner_source_sha256": capture["owner_source_sha256"],
        "owner_result": owner_result,
        "stdout": capture["stdout"], "stderr": capture["stderr"],
        "argv": capture["argv"], "environment": capture["environment"],
        "cwd": capture["cwd"], "cpu_affinity": capture["cpu_affinity"],
        "network_namespace_inode": capture["network_namespace_inode"],
        "tmpdir_path": capture["tmpdir_path"],
        "tmpdir_receipt_sha256": sha256(canonical_bytes(tmpdir_receipt)),
    }


def verify_source5_soak_component_offline(
    component: dict[str, Any], prepared: dict[str, Any],
    job: dict[str, Any], authorization_context: dict[str, Any],
    host_receipt_pin: object, *, replay_context: object,
) -> dict[str, Any]:
    """Freshly replay the original Source5 Soak from identity-mapped evidence."""
    receipt_pin = exact(host_receipt_pin, {
        "path", "raw_sha256", "receipt_sha256",
    }, "Source5 Soak host-verification receipt pin")
    host_path_pin = raw_pin({"path": receipt_pin["path"],
                             "raw_sha256": receipt_pin["raw_sha256"]},
                            "Source5 Soak host-verification receipt")
    context = exact(replay_context, {
        "schema", "evidence_path_map",
    }, "Source5 Soak offline replay context")
    require(context["schema"] == SOAK_OFFLINE_CONTEXT_SCHEMA,
            "Source5 Soak offline replay context schema differs")
    mapped = _validate_evidence_path_map(context["evidence_path_map"])
    direct_paths = set(_raw_pins_in((
        component, prepared, job, authorization_context,
    )))
    direct_paths.add(host_path_pin["path"])
    direct_paths.add(str(Path(host_path_pin["path"]).parent))
    source_root_input = Path(prepared["source_root"])
    input_root_input = Path(prepared["prepared"]["spec_path"]).parent
    output_root_input = Path(component["pins"]["supervisor"]["path"]).parent
    direct_paths.update({
        str(source_root_input), str(input_root_input),
        str(output_root_input), str(output_root_input.parent),
    })
    _require_evidence_paths(mapped, direct_paths,
                            "top-level Source5 Soak replay")
    raw, receipt_raw_sha, receipt_info = read_stable(
        Path(host_path_pin["path"]), "Source5 Soak host-verification receipt",
        MAX_RECEIPT_BYTES,
    )
    require(receipt_info.st_uid == os.getuid() and
            stat.S_IMODE(receipt_info.st_mode) == 0o600 and
            receipt_raw_sha == host_path_pin["raw_sha256"],
            "Source5 Soak host-verification receipt mode/owner/raw pin differs")
    try:
        receipt = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise Source5SoakError(f"Source5 Soak host receipt is not bounded JSON: {error}") from error
    require(type(receipt) is dict and raw == canonical_bytes(receipt),
            "Source5 Soak host-verification receipt is not canonical JSON")
    expected_fields = {
        "schema", "campaign_id", "host_id", "run_id", "component_sha256",
        "component_pins", "generation", "prepared_host_context_pin",
        "fixed_spec_host_pin", "observed_host_pin",
        "prepared_host_binding_sha256", "helper_input_pin",
        "construction_probe", "pressure_origin", "origin_host",
        "process_absence", "tree_roots",
        "evidence_inventory", "evidence_bases", "readback_sha256",
        "bounded_execution_ready", "bounded_blockers",
        "qualification_eligible", "execution_ready", "receipt_sha256",
    }
    bounded = component.get("schema") == COMPONENT_SCHEMA_V2
    if bounded:
        expected_fields |= {"resource_budget", "resource_monitor", "final_usage"}
    exact(receipt, expected_fields, "Source5 Soak host-verification receipt")
    receipt_body = {key: value for key, value in receipt.items()
                    if key != "receipt_sha256"}
    require(receipt["schema"] == (HOST_VERIFICATION_SCHEMA_V3 if bounded else
                                   HOST_VERIFICATION_SCHEMA) and
            receipt["receipt_sha256"] == receipt_pin["receipt_sha256"] ==
                sha256(canonical_bytes(receipt_body)) and
            receipt["campaign_id"] == component["campaign_id"] ==
                prepared["campaign_id"] and
            receipt["host_id"] == component["host_id"] == prepared["host_id"] and
            receipt["run_id"] == component["run_id"] == job["run_id"] and
            receipt["component_sha256"] == sha256(canonical_bytes(component)) and
            receipt["component_pins"] == component["pins"] and
            receipt["bounded_execution_ready"] is bounded and
            receipt["bounded_blockers"] == ([] if bounded else [
                "prospective_bounded_soak_resource_budget_not_pinned",
            ]) and
            receipt["qualification_eligible"] is False and
            receipt["execution_ready"] is False,
            "Source5 Soak host receipt is not bound to the exact non-qualifying component")
    budget_document = None
    budget_pin = None
    if bounded:
        budget_document, budget_pin = _read_resource_budget_pin(
            receipt["resource_budget"],
        )
        host_monitor = exact(receipt["resource_monitor"], {
            "schema", "budget", "stream", "row_count", "high_water",
            "final_usage", "failure", "prefix_sha256",
        }, "Source5 bounded host monitor summary")
        component_monitor = exact(component["resource_monitor"], {
            "schema", "budget", "stream", "row_count", "high_water",
            "final_usage", "failure", "prefix_sha256",
        }, "Source5 bounded component monitor summary")
        require(budget_pin == component["resource_budget"] and
                host_monitor["schema"] ==
                    "allocatbelt.application-source5-soak-resource-monitor-summary.v1" and
                resource_budget_pin(host_monitor["budget"]) == budget_pin and
                host_monitor["stream"] == component_monitor["stream"] and
                host_monitor["row_count"] == component_monitor["row_count"] and
                host_monitor["prefix_sha256"] == component_monitor["prefix_sha256"] and
                host_monitor["failure"] is None,
                "Source5 bounded host receipt changed the budget/monitor stream")
    binding = _selected_prepared_host_binding(
        prepared["source5_prepared_input_completion"], prepared["host_id"],
    )
    require(receipt["prepared_host_binding_sha256"] == binding["binding_sha256"] and
            raw_pin(receipt["prepared_host_context_pin"],
                    "Source5 Soak prepared observed-host context") ==
                raw_pin(binding["prepared_host_context_pin"],
                        "Source5 dual-bound observed-host context") and
            raw_pin(receipt["fixed_spec_host_pin"],
                    "Source5 Soak fixed SpecV3 host") ==
                raw_pin(binding["fixed_spec_host_pin"],
                        "Source5 dual-bound SpecV3 host") and
            raw_pin(receipt["helper_input_pin"],
                    "Source5 Soak helper input") ==
                raw_pin(authorization_context["helper_input"],
                        "Source5 Soak authorization helper input"),
            "Source5 Soak host receipt changed its original generation/authorization")
    inventory_paths = {entry["path"] for entry in receipt["evidence_inventory"]
                       if type(entry) is dict and type(entry.get("path")) is str}
    base_paths = set(receipt["evidence_bases"])
    _require_evidence_paths(mapped, inventory_paths | base_paths,
                            "complete Source5 Soak dependency inventory")
    tree_roots = exact(receipt["tree_roots"], {
        "source", "input", "output", "probe_capture",
    }, "Source5 Soak evidence tree roots")
    require(tree_roots["source"] == str(source_root_input.resolve(strict=True)) and
            tree_roots["input"] == str(input_root_input.resolve(strict=True)) and
            tree_roots["output"] == str(output_root_input.resolve(strict=True)) and
            tree_roots["probe_capture"] ==
                str(Path(receipt["construction_probe"]["receipt_pin"]["path"]).parent.resolve(strict=True)),
            "Source5 Soak host receipt tree roots differ from the original evidence")
    _verify_evidence_inventory(receipt, mapped)
    if bounded:
        final_usage = _source5_resource_final_usage(
            budget_document, receipt["evidence_inventory"],
            component["resource_monitor"],
        )
        require(receipt["final_usage"] == final_usage and
                host_monitor["high_water"] == final_usage["high_water"] and
                host_monitor["final_usage"] ==
                    final_usage["domains"] and
                host_monitor["failure"] is None,
                "Source5 bounded host receipt final inventory/high-water differs")

    generation = _generation_projection(prepared, job, binding)
    require(receipt["generation"] == generation,
            "Source5 Soak host receipt changed its original generation pins")

    prepared_generation = prepared["source5_execution_manifest"][
        "prepared_input_generation"]
    completion_pin = exact(prepared_generation["completion"], {
        "path", "raw_sha256", "semantic_sha256",
    }, "Source5 Soak prepared-input completion pin")
    provenance = exact(prepared_generation["provenance"], {
        "schema", "preparation_pin", "final_spec_pin", "final_plan_pin",
    }, "Source5 Soak prepared-input provenance")
    preparation, _preparation_sha, _preparation_path = \
        _load_source5_preparation_verifier(prepared)
    try:
        replayed_completion = preparation.verify_prepared_inputs_completion(
            completion_pin, provenance, Path(tree_roots["source"]),
            Path(tree_roots["input"]),
        )
    except Exception as error:
        raise Source5SoakError(
            f"Source5 Soak offline prepared-input replay failed: {error}",
        ) from error
    require(type(replayed_completion) is dict and
            canonical_bytes(replayed_completion) == canonical_bytes(
                prepared["source5_prepared_input_completion"]),
            "Source5 Soak offline preparation replay changed its original completion")
    offline_prepared = dict(prepared)
    offline_prepared["source5_prepared_input_completion"] = replayed_completion

    _validate_host_origin_offline(receipt, prepared, binding)
    supervisor_pin = raw_pin(component["pins"]["supervisor"],
                             "Source5 Soak supervisor receipt")
    supervisor, _supervisor_raw, _supervisor_sha = read_json(
        Path(supervisor_pin["path"]), supervisor_pin["raw_sha256"],
        "Source5 Soak supervisor receipt", MAX_RECEIPT_BYTES,
    )
    _validate_process_absence_offline(receipt, supervisor)

    readback = _load_readback_module(offline_prepared)
    if bounded:
        material_pin = raw_pin(component["pins"]["materials_index"],
                               "Source5 bounded materials index")
        material_index, _material_raw, _material_sha = read_json(
            Path(material_pin["path"]), material_pin["raw_sha256"],
            "Source5 bounded materials index", MAX_ARTIFACT_BYTES,
        )
        offline_binding = _selected_prepared_host_binding(
            offline_prepared["source5_prepared_input_completion"],
            offline_prepared["host_id"],
        )
        offline_recipe, _offline_receipt, _offline_identities = \
            _verify_build_receipt(
                material_index, offline_prepared, job, offline_binding,
                readback,
            )
        if offline_recipe["feedback_expectation"]["policy"].get(
                "capacity_floor_policy_id") is not None:
            construction_probe_capture, _offline_probe_pin = \
                _source5_probe_v2_audit_context(
                    offline_prepared, offline_recipe,
                    component["probe_capture"],
                    evidence_path_map=context["evidence_path_map"],
                )
            _verify_source5_probe_resource_budget(
                budget_document, offline_prepared,
                construction_probe_capture,
            )
            probe_projection = exact(receipt["construction_probe"], {
                "schema", "receipt_pin", "capture_sha256", "probe_raw_sha256",
                "normal_binary_sha256", "owner_source_sha256",
                "capacity_bundle", "request",
            }, "Source5 bounded ProbeV2 host receipt binding")
            require(probe_projection["schema"] == PROBE_CAPTURE_SCHEMA_V2 and
                    probe_projection["receipt_pin"] == component["probe_capture"] and
                    probe_projection["capture_sha256"] ==
                        construction_probe_capture["capture"]["receipt_sha256"] and
                    probe_projection["probe_raw_sha256"] ==
                        construction_probe_capture["probe_raw_sha256"] and
                    probe_projection["normal_binary_sha256"] ==
                        construction_probe_capture["normal_binary_sha256"] and
                    probe_projection["owner_source_sha256"] ==
                        construction_probe_capture["capture"]["owner_modules"][
                            "fixed_pair"]["raw_sha256"] and
                    probe_projection["capacity_bundle"] ==
                        construction_probe_capture["capacity_bundle"] and
                    probe_projection["request"] ==
                        construction_probe_capture["request"],
                    "Source5 bounded host receipt ProbeV2 projection differs from its strict capture")
        else:
            construction_probe_capture = _offline_probe_context(
                receipt, offline_prepared, readback,
                resource_budget=budget_document,
            )
    else:
        construction_probe_capture = _offline_probe_context(
            receipt, offline_prepared, readback,
        )
    offline_readback_context = {
        "schema": (SOAK_OFFLINE_CONTEXT_SCHEMA_V2 if bounded else
                   SOAK_OFFLINE_CONTEXT_SCHEMA),
        "evidence_path_map": context["evidence_path_map"],
        "construction_probe_capture": construction_probe_capture,
        "application_environment": supervisor["details"]["environment"],
        "pressure_origin": receipt["pressure_origin"],
        "host_verification_pin": {
            "path": host_path_pin["path"],
            "raw_sha256": host_path_pin["raw_sha256"],
            "receipt_sha256": receipt_pin["receipt_sha256"],
        },
    }
    result = _verify_source5_soak_component_replay(
        component, offline_prepared, job, authorization_context, readback,
        offline_context=offline_readback_context,
    )
    require(sha256(canonical_bytes(result)) == receipt["readback_sha256"] and
            result == component["readback"],
            "Source5 Soak offline result differs from the strict host readback")
    if bounded:
        require(receipt["bounded_execution_ready"] is True and
                receipt["bounded_blockers"] == [] and
                receipt["resource_monitor"]["failure"] is None and
                receipt["final_usage"]["high_water"] ==
                    receipt["resource_monitor"]["high_water"],
                "Source5 bounded offline replay did not close every live resource blocker")
        return {
            "schema": SOAK_BOUNDED_OFFLINE_RESULT_SCHEMA,
            "campaign_id": component["campaign_id"],
            "host_id": component["host_id"],
            "run_id": component["run_id"],
            "component_sha256": sha256(canonical_bytes(component)),
            "host_verification": {
                "path": receipt_pin["path"],
                "raw_sha256": receipt_pin["raw_sha256"],
                "receipt_sha256": receipt_pin["receipt_sha256"],
            },
            "resource_budget": budget_pin,
            "resource_monitor": receipt["resource_monitor"],
            "final_usage": receipt["final_usage"],
            "readback_sha256": receipt["readback_sha256"],
            "validated": True,
            "passed": True,
            "bounded_execution_ready": True,
            "qualification_eligible": False,
            "execution_ready": False,
        }
    raise Source5SoakError(
        "source5_soak_bounded_acceptance_blocked: complete Soak and pressure replay passed, but no prospective bounded-Soak resource-budget document is pinned",
    )
