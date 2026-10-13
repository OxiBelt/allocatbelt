#!/usr/bin/env python3
"""Validate the prospective inputs for a SourceV5 application campaign.

This module owns only the source-bound qualification inputs. It deliberately
does not launch a process or treat a planned proof as an observed proof.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any


SOURCE_V5_SCHEMA = "allocatbelt.application-source-manifest.v5"
SPEC_V3_SCHEMA = "allocatbelt.application-campaign-spec.v3"
PLAN_V3_SCHEMA = "allocatbelt.application-campaign-plan.v3"
FEEDBACK_POLICY_SCHEMA = "allocatbelt.application-feedback-policy-artifact.v1"

HARNESS_PATHS = {
    "campaign_controller": "scripts/application-campaign.py",
    "feedback_validator": "scripts/application-feedback-readback.py",
    "byte_capacity_producer": "scripts/application-byte-capacity.py",
    "pressure_driver": "scripts/application-pressure-driver.py",
    "pressure_validator": "scripts/application-pressure-readback.py",
    "soak_recipe_builder": "scripts/application-soak-recipe.py",
    "soak_validator": "scripts/application-soak-readback.py",
    "soak_runner": "scripts/run-application-soak.sh",
}
FEEDBACK_RUNTIME_PATH = "bench/src/application/runtime_bindings.rs"
FEEDBACK_POLICY_PATH = "crates/allocatbelt/src/runtime/resource_feedback_policy.rs"
FEEDBACK_SENSOR_PATH = "crates/allocatbelt/src/runtime/resource_feedback_sensor.rs"
ALLOCATORS = ("allocatbelt", "mimalloc-secure", "mimalloc-standard", "system")
EXECUTORS = ("bounded", "tokio")
STANDALONE_PROFILES = ("steady", "burst", "oversubscribed")
MIXED_PROFILES = ("mixed", "burst", "oversubscribed")
MAX_INPUT_FILE_BYTES = 64 * 1024 * 1024
MAX_STAGE_RECEIPT_BYTES = 128 * 1024
PROSPECTIVE_NONCE_SCOPE = "reusable_template"
NONCE_INSTANTIATION_SCHEMA = "allocatbelt.application-process-nonce-instantiation.v1"
NONCE_INSTANTIATION_RULE = "sha256(template_nonce,campaign_id,job_run_id,pair_member,ordinal)"


class InputError(ValueError):
    """A prospective campaign input fails its exact contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise InputError(message)


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    _require(type(value) is dict, f"{label} must be an object")
    missing = keys - value.keys()
    extra = value.keys() - keys
    _require(not missing, f"{label} is missing keys: {sorted(missing)}")
    _require(not extra, f"{label} has unknown keys: {sorted(extra)}")
    return value


def _canonical(value: Any) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    except (TypeError, ValueError) as error:
        raise InputError(f"value is not canonical JSON: {error}") from error


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest_object(value: dict[str, Any], field: str) -> str:
    payload = dict(value)
    payload.pop(field, None)
    return _sha256(_canonical(payload))


def _is_sha(value: Any) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _token(value: Any, label: str) -> str:
    _require(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", value) is not None, f"{label} is not a canonical token")
    return value


def _relative_path(value: Any, label: str) -> str:
    _require(type(value) is str and value and "\\" not in value and "\x00" not in value, f"{label} path is malformed")
    _require(not any(ord(char) < 32 or ord(char) == 127 for char in value), f"{label} path contains a control character")
    path = Path(value)
    _require(not path.is_absolute() and ".." not in path.parts and path != Path(".") and path.as_posix() == value, f"{label} path must be portable and relative")
    return value


def _pin(value: Any, label: str) -> dict[str, Any]:
    pin = _exact(value, {"relative_path", "raw_sha256"}, label)
    _relative_path(pin["relative_path"], label)
    _require(_is_sha(pin["raw_sha256"]), f"{label} raw SHA-256 is malformed")
    return pin


def _read_regular(path: Path, label: str, maximum: int) -> tuple[bytes, str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise InputError(f"cannot safely open {label}: {error}") from error
    try:
        before = os.fstat(descriptor)
        _require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= maximum, f"{label} is not a bounded regular file")
        data = bytearray()
        while len(data) < before.st_size:
            block = os.read(descriptor, min(1024 * 1024, before.st_size - len(data)))
            _require(bool(block), f"{label} was truncated while reading")
            data.extend(block)
        after_fd = os.fstat(descriptor)
        after_path = path.stat(follow_symlinks=False)
        key = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        _require(key(before) == key(after_fd) == key(after_path), f"{label} changed during its stable read")
        raw = bytes(data)
        return raw, _sha256(raw)
    finally:
        os.close(descriptor)


def _safe_child(root: Path, relative: str, label: str) -> Path:
    relative = _relative_path(relative, label)
    try:
        resolved_root = root.resolve(strict=True)
    except OSError as error:
        raise InputError(f"{label} root is unavailable: {error}") from error
    candidate = resolved_root / relative
    cursor = resolved_root
    for part in Path(relative).parts:
        cursor = cursor / part
        _require(not cursor.is_symlink(), f"{label} path traverses a symlink: {relative}")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as error:
        raise InputError(f"{label} path is missing or escaped its root: {relative}") from error
    return resolved


def _inventory_map(records: Any) -> dict[str, dict[str, Any]]:
    _require(type(records) is list, "typed source inventory must be a list")
    result: dict[str, dict[str, Any]] = {}
    for index, record_value in enumerate(records):
        record = _exact(record_value, {"path", "kind", "mode", "sha256", "size"} if type(record_value) is dict and "target" not in record_value else {"path", "kind", "mode", "target", "sha256", "size"}, f"source inventory record[{index}]")
        path = _relative_path(record["path"], f"source inventory record[{index}]")
        _require(path not in result, f"source inventory repeats {path}")
        result[path] = record
    return result


def _source_file(root: Path, files: dict[str, dict[str, Any]], path: str, expected_sha: str | None = None) -> tuple[bytes, str]:
    record = files.get(path)
    _require(type(record) is dict and record.get("kind") == "file" and _is_sha(record.get("sha256")), f"source pin is not backed by a regular inventory entry: {path}")
    if expected_sha is not None:
        _require(record["sha256"] == expected_sha, f"source pin differs from typed inventory: {path}")
    candidate = _safe_child(root, path, f"pinned source file {path}")
    raw, digest = _read_regular(candidate, f"pinned source file {path}", MAX_INPUT_FILE_BYTES)
    _require(digest == record["sha256"], f"source bytes differ from typed inventory: {path}")
    return raw, digest


def validate_qualification_harness(value: Any, source_records: Any) -> dict[str, Any]:
    harness = _exact(value, set(HARNESS_PATHS), "qualification harness")
    files = _inventory_map(source_records)
    for name, expected_path in HARNESS_PATHS.items():
        pin = _exact(harness[name], {"path", "sha256"}, f"qualification harness {name}")
        _require(pin["path"] == expected_path and _is_sha(pin["sha256"]), f"qualification harness {name} path/digest is unsupported")
        record = files.get(expected_path)
        _require(type(record) is dict and record.get("kind") == "file" and record.get("sha256") == pin["sha256"], f"qualification harness {name} is not pinned to its exact regular inventory bytes")
    return harness


def _rust_constant(text: str, name: str) -> int:
    match = re.search(rf"\bconst\s+{re.escape(name)}\s*:\s*(?:u64|u32|u16|usize)\s*=\s*([0-9][0-9_]*(?:\s*\*\s*[0-9][0-9_]*)*)\s*;", text)
    _require(match is not None, f"Rust numeric constant is missing or changed: {name}")
    pieces = [part.strip().replace("_", "") for part in match.group(1).split("*")]
    result = 1
    for piece in pieces:
        _require(piece.isdecimal(), f"Rust numeric constant is not a literal product: {name}")
        result *= int(piece)
    return result


def _reader_policy_contract(reader_text: str, rust_policy_text: str) -> tuple[str, dict[str, int]]:
    version = re.search(r'policy\["version"\]\s*==\s*"([A-Za-z0-9._-]+)"', reader_text)
    _require(version is not None, "feedback reader has no explicit policy version check")
    tuple_source = re.search(r"for\s+key\s*,\s*expected\s+in\s*\((.*?)\)\s*:\s*\n\s*require\(uint\(policy\[key\]", reader_text, re.DOTALL)
    _require(tuple_source is not None, "feedback reader numeric policy contract cannot be extracted")
    numeric_constants = {
        name: int(raw.replace("_", ""))
        for name, raw in re.findall(r"^([A-Z][A-Z0-9_]*)\s*=\s*([0-9][0-9_]*)\s*$", reader_text, re.MULTILINE)
    }
    parsed = re.findall(r'\(\s*"([a-z_]+)"\s*,\s*([A-Z][A-Z0-9_]*|[0-9][0-9_]*)\s*\)', tuple_source.group(1))
    values: dict[str, int] = {}
    for key, raw in parsed:
        if raw.isdecimal() or ("_" in raw and raw.replace("_", "").isdecimal()):
            values[key] = int(raw.replace("_", ""))
        else:
            _require(raw in numeric_constants, f"feedback reader numeric policy contract references an unknown constant: {raw}")
            values[key] = numeric_constants[raw]
    required = {
        "sample_interval_ns", "max_dense_gap_ns", "telemetry_freshness_ns",
        "required_breach_samples", "actuation_cooldown_ns", "minimum_dense_observations",
    }
    _require(set(values) == required, "feedback reader numeric policy contract has an unexpected key set")
    runtime_version = re.search(r'pub\s+const\s+FEEDBACK_POLICY_VERSION\s*:\s*&str\s*=\s*"([A-Za-z0-9._-]+)"\s*;', rust_policy_text)
    _require(runtime_version is not None and runtime_version.group(1) == version.group(1), "feedback reader and Rust runtime policy versions differ")
    duration_specs = {
        "SAMPLE_INTERVAL": "sample_interval_ns",
        "MAX_DENSE_SAMPLE_GAP": "max_dense_gap_ns",
        "TELEMETRY_FRESHNESS": "telemetry_freshness_ns",
        "ACTUATION_COOLDOWN": "actuation_cooldown_ns",
    }
    duration_multipliers = {"millis": 1_000_000, "secs": 1_000_000_000}
    for constant, field in duration_specs.items():
        match = re.search(rf"pub\s+const\s+{constant}\s*:\s*Duration\s*=\s*Duration::from_(millis|secs)\(([0-9][0-9_]*)\)\s*;", rust_policy_text)
        _require(match is not None, f"Rust feedback duration constant is missing or changed: {constant}")
        actual = int(match.group(2).replace("_", "")) * duration_multipliers[match.group(1)]
        _require(actual == values[field], f"feedback reader and Rust runtime disagree on {field}")
    breach = re.search(r"pub\s+const\s+REQUIRED_BREACH_SAMPLES\s*:\s*u8\s*=\s*([0-9][0-9_]*)\s*;", rust_policy_text)
    _require(breach is not None and int(breach.group(1).replace("_", "")) == values["required_breach_samples"], "feedback reader and Rust runtime disagree on required_breach_samples")
    return version.group(1), values


def _feedback_controls(runtime_text: str) -> tuple[dict[str, dict[str, int]], dict[str, Any]]:
    match = re.search(
        r"fn\s+feedback_policy\(workers:\s*usize\)\s*->\s*ResourceFeedbackPolicyConfig\s*\{(?P<body>.*?)\n\}\n\n#\[cfg\(feature\s*=\s*\"resource-feedback\"\)\]\nfn\s+validate_initial_feedback_rates",
        runtime_text,
        re.DOTALL,
    )
    _require(match is not None, "application runtime feedback_policy(workers) builder has an unsupported shape")
    rate_floor = _rust_constant(runtime_text, "FEEDBACK_RATE_FLOOR")
    rate_ceiling = _rust_constant(runtime_text, "APPLICATION_RATE_CEILING_BYTES_PER_SECOND")
    low = _rust_constant(runtime_text, "FEEDBACK_LOW_UTILIZATION_BPS")
    high = _rust_constant(runtime_text, "FEEDBACK_HIGH_UTILIZATION_BPS")
    calls = re.findall(r"(cpu_concurrency|disk_rate|network_rate)\s*:\s*FeedbackControlConfig::new\(([^)]*)\)", match.group("body"), re.DOTALL)
    expected_fields = {"cpu_concurrency", "disk_rate", "network_rate"}
    _require(len(calls) == 3 and {name for name, _args in calls} == expected_fields, "runtime feedback builder does not define the exact three controls")
    expressions = {name: [re.sub(r"\s+", "", value) for value in args.split(",") if value.strip()] for name, args in calls}
    _require(re.search(r"let\s+cpu\s*=\s*workers\s+as\s+u64\s*;", match.group("body")) is not None, "runtime feedback CPU capacity no longer follows the selected worker count")
    _require(expressions["cpu_concurrency"] == ["1", "cpu", "cpu", "FEEDBACK_LOW_UTILIZATION_BPS", "FEEDBACK_HIGH_UTILIZATION_BPS"], "runtime CPU feedback builder differs from the supported workers policy")
    for name in ("disk_rate", "network_rate"):
        _require(expressions[name] == ["FEEDBACK_RATE_FLOOR", "APPLICATION_RATE_CEILING_BYTES_PER_SECOND", "APPLICATION_RATE_CEILING_BYTES_PER_SECOND", "FEEDBACK_LOW_UTILIZATION_BPS", "FEEDBACK_HIGH_UTILIZATION_BPS"], f"runtime {name} builder differs from its pinned numeric source")
    minimum_dense = _rust_constant(runtime_text, "FEEDBACK_MINIMUM_DENSE_OBSERVATIONS")
    cpu_rule = re.search(r'"feedback\.cpu_reduction_rule"\.to_owned\(\),\s*"([a-z0-9_]+)"\.to_owned\(\)', runtime_text)
    recovery = re.search(r'"feedback\.cpu_recovery_increment"\.to_owned\(\),\s*"([0-9]+)"\.to_owned\(\)', runtime_text)
    _require(cpu_rule is not None and recovery is not None, "runtime feedback receipt does not expose its numeric CPU policy")
    algorithm = {
        "cpu_reduction_rule": cpu_rule.group(1),
        "cpu_recovery_increment": int(recovery.group(1)),
        "network_sensor_source": "download_application_bytes_only",
        "upload_controlled": False,
    }
    controls: dict[str, dict[str, int]] = {}
    for workload, profiles in (("cpu", STANDALONE_PROFILES), ("memory", STANDALONE_PROFILES), ("http", STANDALONE_PROFILES), ("disk", STANDALONE_PROFILES), ("mixed", MIXED_PROFILES)):
        for profile in profiles:
            workers = 2 if profile == "oversubscribed" else 4
            controls[f"{workload}/{profile}"] = {
                "workers": workers,
                "minimum_dense_observations": minimum_dense,
                "controls": {
                    "cpu": {"floor": 1, "initial": workers, "ceiling": workers, "low_bps": low, "high_bps": high},
                    "disk": {"floor": rate_floor, "initial": rate_ceiling, "ceiling": rate_ceiling, "low_bps": low, "high_bps": high},
                    "download": {"floor": rate_floor, "initial": rate_ceiling, "ceiling": rate_ceiling, "low_bps": low, "high_bps": high},
                },
            }
    return controls, algorithm


def build_feedback_policy_artifact(root: Path, source_records: Any, harness: Any) -> dict[str, Any]:
    pins = validate_qualification_harness(harness, source_records)
    files = _inventory_map(source_records)
    reader_raw, reader_sha = _source_file(root, files, pins["feedback_validator"]["path"], pins["feedback_validator"]["sha256"])
    runtime_raw, runtime_sha = _source_file(root, files, FEEDBACK_RUNTIME_PATH)
    policy_raw, policy_sha = _source_file(root, files, FEEDBACK_POLICY_PATH)
    sensor_raw, sensor_sha = _source_file(root, files, FEEDBACK_SENSOR_PATH)
    try:
        reader_text = reader_raw.decode("utf-8")
        runtime_text = runtime_raw.decode("utf-8")
        policy_text = policy_raw.decode("utf-8")
        sensor_text = sensor_raw.decode("utf-8")
    except UnicodeError as error:
        raise InputError(f"feedback policy source is not UTF-8: {error}") from error
    version, reader_contract = _reader_policy_contract(reader_text, policy_text)
    _require("let density = NonZeroU32::new(" in sensor_text or "NonZeroU32::new(" in runtime_text, "runtime feedback sensor source lacks the pinned density control")
    contexts, algorithm = _feedback_controls(runtime_text)
    _require(contexts and all(item["minimum_dense_observations"] > 0 for item in contexts.values()), "runtime feedback density threshold is invalid")
    policy_body = {
        "schema": FEEDBACK_POLICY_SCHEMA,
        "version": version,
        "reader_contract": reader_contract,
        "algorithm": algorithm,
        "contexts": contexts,
        "source_pins": {
            "feedback_validator": {"path": pins["feedback_validator"]["path"], "sha256": reader_sha},
            "runtime_bindings": {"path": FEEDBACK_RUNTIME_PATH, "sha256": runtime_sha},
            "runtime_policy": {"path": FEEDBACK_POLICY_PATH, "sha256": policy_sha},
            "runtime_sensor": {"path": FEEDBACK_SENSOR_PATH, "sha256": sensor_sha},
        },
    }
    return {"schema": FEEDBACK_POLICY_SCHEMA, "policy": policy_body, "policy_sha256": _sha256(_canonical(policy_body))}


def validate_feedback_policy_artifact(value: Any, source_records: Any, harness: Any) -> dict[str, Any]:
    artifact = _exact(value, {"schema", "policy", "policy_sha256"}, "numeric feedback policy artifact")
    _require(artifact["schema"] == FEEDBACK_POLICY_SCHEMA, "unsupported feedback policy artifact schema")
    body = _exact(artifact["policy"], {"schema", "version", "reader_contract", "algorithm", "contexts", "source_pins"}, "feedback policy body")
    _require(body["schema"] == FEEDBACK_POLICY_SCHEMA and type(body["version"]) is str and body["version"], "feedback policy version is missing")
    reader_contract = _exact(body["reader_contract"], {
        "sample_interval_ns", "max_dense_gap_ns", "telemetry_freshness_ns", "required_breach_samples", "actuation_cooldown_ns", "minimum_dense_observations",
    }, "feedback reader numeric contract")
    for key, item in reader_contract.items():
        _require(type(item) is int and item > 0, f"feedback reader numeric value is invalid: {key}")
    _require(body["version"] == "runtime-feedback-policy-v1", "feedback policy version is not the reader/runtime version")
    _require(reader_contract == {
        "sample_interval_ns": 100_000_000,
        "max_dense_gap_ns": 200_000_000,
        "telemetry_freshness_ns": 500_000_000,
        "required_breach_samples": 3,
        "actuation_cooldown_ns": 1_000_000_000,
        "minimum_dense_observations": 1,
    }, "feedback reader numeric policy differs from the supported runtime contract")
    files = _inventory_map(source_records)
    pins = validate_qualification_harness(harness, source_records)
    source_pins = _exact(body["source_pins"], {"feedback_validator", "runtime_bindings", "runtime_policy", "runtime_sensor"}, "feedback policy source pins")
    expected_paths = {
        "feedback_validator": pins["feedback_validator"]["path"],
        "runtime_bindings": FEEDBACK_RUNTIME_PATH,
        "runtime_policy": FEEDBACK_POLICY_PATH,
        "runtime_sensor": FEEDBACK_SENSOR_PATH,
    }
    for name, path in expected_paths.items():
        pin = _exact(source_pins[name], {"path", "sha256"}, f"feedback policy {name} source pin")
        record = files.get(path)
        _require(pin["path"] == path and _is_sha(pin["sha256"]) and type(record) is dict and record.get("kind") == "file" and record.get("sha256") == pin["sha256"], f"feedback policy {name} is not bound to exact regular inventory bytes")
    _require(source_pins["feedback_validator"]["sha256"] == pins["feedback_validator"]["sha256"], "feedback policy artifact and qualification harness pin different readers")
    contexts = body["contexts"]
    _require(type(contexts) is dict and set(contexts) == {
        *(f"{workload}/{profile}" for workload in ("cpu", "memory", "http", "disk") for profile in STANDALONE_PROFILES),
        *(f"mixed/{profile}" for profile in MIXED_PROFILES),
    }, "feedback policy context matrix differs from the frozen 15-cell campaign")
    for key, context in contexts.items():
        _exact(context, {"workers", "minimum_dense_observations", "controls"}, f"feedback policy context {key}")
        workers = context["workers"]
        _require(type(workers) is int and workers in (2, 4), f"feedback policy worker count is invalid: {key}")
        _require(type(context["minimum_dense_observations"]) is int and context["minimum_dense_observations"] > 0, f"feedback policy density is invalid: {key}")
        controls = _exact(context["controls"], {"cpu", "disk", "download"}, f"feedback controls {key}")
        for resource, config_value in controls.items():
            config = _exact(config_value, {"floor", "initial", "ceiling", "low_bps", "high_bps"}, f"feedback {resource} control {key}")
            _require(all(type(config[name]) is int and config[name] >= 0 for name in config), f"feedback {resource} numeric configuration is invalid: {key}")
            _require(0 < config["floor"] <= config["initial"] <= config["ceiling"] and config["low_bps"] < config["high_bps"] <= 10_000, f"feedback {resource} bounds or thresholds are invalid: {key}")
        workload, profile = key.split("/", 1)
        expected_workers = 2 if profile == "oversubscribed" else 4
        expected_controls = {
            "cpu": {"floor": 1, "initial": expected_workers, "ceiling": expected_workers, "low_bps": 3000, "high_bps": 8000},
            "disk": {"floor": 64 * 1024 * 1024, "initial": 16 * 1024**3, "ceiling": 16 * 1024**3, "low_bps": 3000, "high_bps": 8000},
            "download": {"floor": 64 * 1024 * 1024, "initial": 16 * 1024**3, "ceiling": 16 * 1024**3, "low_bps": 3000, "high_bps": 8000},
        }
        _require(context["workers"] == expected_workers and context["minimum_dense_observations"] == 1 and controls == expected_controls, f"feedback policy numeric context differs from the runtime builder: {workload}/{profile}")
    algorithm = _exact(body["algorithm"], {"cpu_reduction_rule", "cpu_recovery_increment", "network_sensor_source", "upload_controlled"}, "feedback algorithm")
    _require(algorithm == {
        "cpu_reduction_rule": "floor_current_limit_over_10_zero_is_quantized",
        "cpu_recovery_increment": 1,
        "network_sensor_source": "download_application_bytes_only",
        "upload_controlled": False,
    }, "feedback algorithm record differs from the runtime build contract")
    _require(_is_sha(artifact["policy_sha256"]) and _sha256(_canonical(body)) == artifact["policy_sha256"], "numeric feedback policy digest mismatch")
    return artifact


def _verify_source_bytes(root: Path | None, pin: dict[str, Any], label: str) -> bool:
    if root is None:
        return False
    candidate = _safe_child(root, pin["relative_path"], label)
    raw, actual = _read_regular(candidate, label, MAX_INPUT_FILE_BYTES)
    _require(actual == pin["raw_sha256"], f"{label} bytes differ from their prospective raw pin")
    return True


def _capacity_key(host_id: str, workload: str, profile: str, calibration_id: str) -> dict[str, str]:
    return {"host_id": host_id, "workload": workload, "profile": profile, "calibration_id": calibration_id}


def validate_qualification_inputs(
    value: Any,
    host_ids: list[str],
    cells: list[dict[str, Any]],
    sources: dict[str, dict[str, Any]],
    input_root: Path | None = None,
) -> dict[str, Any]:
    inputs = _exact(value, {"capacity_templates", "pressure_conditions"}, "qualification_inputs")
    templates = inputs["capacity_templates"]
    conditions = inputs["pressure_conditions"]
    _require(type(templates) is list and type(conditions) is list, "qualification capacity templates and pressure conditions must be lists")
    cell_by_context: dict[tuple[str, str], dict[str, Any]] = {}
    for cell in cells:
        key = (cell["workload"], cell["profile"])
        _require(key not in cell_by_context, f"duplicate workload/profile qualification cell: {key}")
        cell_by_context[key] = cell
    expected = {(host_id, workload, profile) for host_id in host_ids for workload, profile in cell_by_context}
    seen: dict[tuple[str, str, str], dict[str, Any]] = {}
    calibration_ids: set[str] = set()
    evidence_supplied_count = 0
    capacity_evidence_pins_checked = True
    for index, item_value in enumerate(templates):
        item = _exact(item_value, {
            "host_id", "workload", "profile", "calibration_id", "calibrator", "request_template", "context_template", "evidence",
        }, f"capacity template[{index}]")
        host_id = _token(item["host_id"], f"capacity template[{index}] host id")
        workload = item["workload"]
        profile = item["profile"]
        key = (host_id, workload, profile)
        _require(key in expected and key not in seen, f"capacity template has an unknown or duplicate host/workload/profile key: {key}")
        calibration_id = _token(item["calibration_id"], f"capacity template[{index}] calibration id")
        _require(calibration_id not in calibration_ids, f"capacity calibration id is repeated: {calibration_id}")
        calibration_ids.add(calibration_id)
        calibrator = _exact(item["calibrator"], {"allocator", "executor"}, f"capacity template[{index}] calibrator")
        _require(calibrator["allocator"] in ALLOCATORS and calibrator["executor"] in EXECUTORS, f"capacity template[{index}] calibrator is unsupported")
        request = _pin(item["request_template"], f"capacity template[{index}] request template")
        context = _pin(item["context_template"], f"capacity template[{index}] context template")
        _require(request["relative_path"] != context["relative_path"], f"capacity template[{index}] aliases request and context files")
        if input_root is not None:
            _verify_source_bytes(input_root, request, f"capacity request template {request['relative_path']}")
            _verify_source_bytes(input_root, context, f"capacity context template {context['relative_path']}")
        evidence = item["evidence"]
        if evidence is None:
            capacity_evidence_pins_checked = False
        else:
            evidence_supplied_count += 1
            evidence = _exact(evidence, {"artifact", "receipt", "stage_receipt"}, f"capacity template[{index}] evidence")
            artifact_pin = _pin(evidence["artifact"], f"capacity template[{index}] artifact evidence")
            receipt_pin = _pin(evidence["receipt"], f"capacity template[{index}] capacity receipt")
            stage_pin = _pin(evidence["stage_receipt"], f"capacity template[{index}] stage receipt")
            _require(len({artifact_pin["relative_path"], receipt_pin["relative_path"], stage_pin["relative_path"]}) == 3, f"capacity template[{index}] evidence files must be distinct")
            if input_root is None:
                capacity_evidence_pins_checked = False
            else:
                _verify_source_bytes(input_root, artifact_pin, f"capacity artifact evidence {artifact_pin['relative_path']}")
                _verify_source_bytes(input_root, receipt_pin, f"capacity receipt evidence {receipt_pin['relative_path']}")
                stage_path = _safe_child(input_root, stage_pin["relative_path"], "capacity stage receipt")
                _stage_raw, stage_actual = _read_regular(stage_path, f"capacity stage receipt {stage_pin['relative_path']}", MAX_STAGE_RECEIPT_BYTES)
                _require(stage_actual == stage_pin["raw_sha256"], "capacity stage receipt differs from its raw pin")
        normalized = {**item, "request_template": request, "context_template": context, "evidence": evidence}
        seen[key] = normalized
    _require(set(seen) == expected, f"capacity template matrix is incomplete: missing={len(expected - set(seen))} extra={len(set(seen) - expected)}")

    pressure_seen: dict[tuple[str, str, str], dict[str, Any]] = {}
    pressure_condition_ids: set[str] = set()
    pressure_calibration_ids: set[str] = set()
    for index, item_value in enumerate(conditions):
        item = _exact(item_value, {
            "host_id", "condition_id", "condition_sha256", "capacity_key", "condition", "pressure_calibration", "readiness_thresholds", "schedule",
        }, f"pressure condition[{index}]")
        host_id = _token(item["host_id"], f"pressure condition[{index}] host id")
        condition_id = _token(item["condition_id"], f"pressure condition[{index}] condition id")
        _require(condition_id not in pressure_condition_ids, f"pressure condition id is repeated: {condition_id}")
        pressure_condition_ids.add(condition_id)
        capacity_key = _exact(item["capacity_key"], {"host_id", "workload", "profile", "calibration_id"}, f"pressure condition[{index}] capacity key")
        key = (host_id, capacity_key["workload"], capacity_key["profile"])
        _require(key in seen and key not in pressure_seen, f"pressure condition has an unknown or duplicate capacity key: {key}")
        cap = seen[key]
        _require(capacity_key == _capacity_key(*key, cap["calibration_id"]), f"pressure condition does not name its exact capacity calibration: {key}")
        condition = _pin(item["condition"], f"pressure condition[{index}] condition file")
        _require(_is_sha(item["condition_sha256"]) and item["condition_sha256"] == condition["raw_sha256"], f"pressure condition[{index}] raw digest does not match its condition file")
        if input_root is not None:
            _verify_source_bytes(input_root, condition, f"pressure condition file {condition['relative_path']}")
        pressure_calibration = _exact(item["pressure_calibration"], {"calibration_id", "artifact", "receipt", "validator_sha256"}, f"pressure condition[{index}] calibration")
        pressure_calibration_id = _token(pressure_calibration["calibration_id"], f"pressure condition[{index}] pressure calibration id")
        _require(pressure_calibration_id not in pressure_calibration_ids, f"pressure calibration id is repeated: {pressure_calibration_id}")
        pressure_calibration_ids.add(pressure_calibration_id)
        artifact_pin = _pin(pressure_calibration["artifact"], f"pressure condition[{index}] calibration artifact")
        receipt_pin = _pin(pressure_calibration["receipt"], f"pressure condition[{index}] calibration receipt")
        _require(artifact_pin["relative_path"] != receipt_pin["relative_path"], f"pressure condition[{index}] aliases its calibration files")
        _require(_is_sha(pressure_calibration["validator_sha256"]) and pressure_calibration["validator_sha256"] == sources[host_id]["qualification_harness"]["pressure_validator"]["sha256"], f"pressure condition[{index}] validator pin differs from SourceV5")
        if input_root is not None:
            _verify_source_bytes(input_root, artifact_pin, f"pressure calibration artifact {artifact_pin['relative_path']}")
            _verify_source_bytes(input_root, receipt_pin, f"pressure calibration receipt {receipt_pin['relative_path']}")
        thresholds = _exact(item["readiness_thresholds"], {"minimum_overlap_seconds", "minimum_ready_samples", "maximum_sample_gap_ms"}, f"pressure condition[{index}] readiness thresholds")
        for name, number in thresholds.items():
            _require(type(number) is int and number > 0, f"pressure condition[{index}] readiness threshold {name} must be positive")
        _require(thresholds["minimum_overlap_seconds"] >= 30 and thresholds["maximum_sample_gap_ms"] <= 200, f"pressure condition[{index}] readiness thresholds are below the campaign contract")
        schedule = _exact(item["schedule"], {"duration_seconds", "sample_interval_ms", "seed"}, f"pressure condition[{index}] schedule")
        _require(type(schedule["duration_seconds"]) is int and thresholds["minimum_overlap_seconds"] <= schedule["duration_seconds"] <= 10_800, f"pressure condition[{index}] schedule is outside its bounded readiness duration")
        _require(type(schedule["sample_interval_ms"]) is int and schedule["sample_interval_ms"] == 100, f"pressure condition[{index}] schedule sample interval must be 100ms")
        _require(type(thresholds["minimum_ready_samples"]) is int and thresholds["minimum_ready_samples"] <= schedule["duration_seconds"] * 1000 // schedule["sample_interval_ms"], f"pressure condition[{index}] readiness sample count exceeds its schedule")
        _require(type(schedule["seed"]) is int and 0 < schedule["seed"] <= (1 << 64) - 1, f"pressure condition[{index}] schedule seed must be a positive u64")
        pressure_seen[key] = {**item, "condition_id": condition_id, "capacity_key": capacity_key, "condition": condition, "pressure_calibration": {**pressure_calibration, "artifact": artifact_pin, "receipt": receipt_pin}}
    _require(set(pressure_seen) == expected, f"pressure-condition matrix is incomplete: missing={len(expected - set(pressure_seen))} extra={len(set(pressure_seen) - set(expected))}")
    return {
        "capacity_templates": [seen[key] for key in sorted(seen)],
        "pressure_conditions": [pressure_seen[key] for key in sorted(pressure_seen)],
        "evidence_supplied": evidence_supplied_count > 0,
        "capacity_evidence_supplied_count": evidence_supplied_count,
        "capacity_evidence_pins_checked": capacity_evidence_pins_checked,
        "capacity_evidence_validation_complete": False,
        "qualification_inputs_pins_checked": input_root is not None,
        "qualification_inputs_validation_complete": False,
    }


def _prospective_nonce(domain: str, identity: dict[str, Any]) -> str:
    return hashlib.sha256((domain + "\0").encode("ascii") + _canonical(identity)).hexdigest()[:32]


def build_qualification_plan_inputs(
    spec: dict[str, Any],
    sources: dict[str, dict[str, Any]],
    normalized_inputs: dict[str, Any],
) -> dict[str, Any]:
    capacity_templates: list[dict[str, Any]] = []
    pressure_by_key = {
        (item["host_id"], item["capacity_key"]["workload"], item["capacity_key"]["profile"]): item
        for item in normalized_inputs["pressure_conditions"]
    }
    for entry in normalized_inputs["capacity_templates"]:
        host_id = entry["host_id"]
        source = sources[host_id]
        allocator = entry["calibrator"]["allocator"]
        binary = source["artifacts"][allocator]
        identity = {
            "campaign_id": spec["campaign_id"], "host_id": host_id,
            "workload": entry["workload"], "profile": entry["profile"],
            "calibration_id": entry["calibration_id"], "allocator": allocator,
            "executor": entry["calibrator"]["executor"],
            "source_sha256": source["source"]["source_tree_sha256"],
            "binary_sha256": binary["sha256"],
            "request_template_sha256": entry["request_template"]["raw_sha256"],
            "context_template_sha256": entry["context_template"]["raw_sha256"],
        }
        body = {
            "capacity_key": _capacity_key(host_id, entry["workload"], entry["profile"], entry["calibration_id"]),
            "pressure_condition_id": pressure_by_key[(host_id, entry["workload"], entry["profile"])]["condition_id"],
            "calibrator": entry["calibrator"],
            "prospective_nonce": _prospective_nonce("allocatbelt.capacity-template-nonce.v1", identity),
            "nonce_scope": PROSPECTIVE_NONCE_SCOPE,
            "nonce_instantiation_schema": NONCE_INSTANTIATION_SCHEMA,
            "nonce_instantiation_rule": NONCE_INSTANTIATION_RULE,
            "source_manifest_sha256": source["manifest_sha256"],
            "source_sha256": source["source"]["source_tree_sha256"],
            "binary_sha256": binary["sha256"],
            "request_template": entry["request_template"],
            "context_template": entry["context_template"],
            "required_proofs": ["capacity_artifact", "capacity_receipt", "pre_confirmation_stage_receipt"],
        }
        capacity_templates.append({**body, "template_sha256": _sha256(_canonical(body))})

    feedback_templates: list[dict[str, Any]] = []
    capacity_by_key = {
        (item["host_id"], item["workload"], item["profile"]): item
        for item in normalized_inputs["capacity_templates"]
    }
    campaign_id = spec["campaign_id"]
    for host_id in sorted(sources):
        source = sources[host_id]
        source_sha = source["source"]["source_tree_sha256"]
        feedback_artifact = source["feedback_policy"]
        policy_body = feedback_artifact["policy"]
        for cell in sorted(spec["cells"], key=lambda item: (item["workload"], item["profile"])):
            workload, profile = cell["workload"], cell["profile"]
            context_key = f"{workload}/{profile}"
            feedback_context = policy_body["contexts"][context_key]
            policy_context = {"version": policy_body["version"], "reader_contract": policy_body["reader_contract"], "algorithm": policy_body["algorithm"], "context": feedback_context, "source_pins": policy_body["source_pins"]}
            context_policy_sha = _sha256(_canonical(policy_context))
            capacity = capacity_by_key[(host_id, workload, profile)]
            pressure = pressure_by_key[(host_id, workload, profile)]
            for allocator in ALLOCATORS:
                binary_sha = source["artifacts"][allocator]["sha256"]
                for executor in EXECUTORS:
                    executor_name = "allocatbelt" if executor == "bounded" else "tokio-1.53.1"
                    for comparison_family in ("fixed_policy", "external_pressure"):
                        condition_id = pressure["condition_id"] if comparison_family == "external_pressure" else None
                        identity = {
                            "campaign_id": campaign_id, "host_id": host_id,
                            "workload": workload, "profile": profile,
                            "comparison_family": comparison_family,
                            "capacity_calibration_id": capacity["calibration_id"],
                            "pressure_condition_id": condition_id,
                            "allocator": allocator, "executor": executor_name,
                            "source_sha256": source_sha, "binary_sha256": binary_sha,
                            "fixed_policy_sha256": source["fixed_runtime_policy"]["policy_sha256"],
                            "feedback_policy_sha256": feedback_artifact["policy_sha256"],
                            "context_policy_sha256": context_policy_sha,
                        }
                        required_proofs = ["feedback_validation_receipt", "post_release_runtime_binding_receipt"]
                        if comparison_family == "external_pressure":
                            required_proofs = [
                                "feedback_validation_receipt", "external_pressure_validation_receipt",
                                "pressure_readiness_interval_receipt", "successful_fixed_predecessor_receipt",
                                "post_release_runtime_binding_receipt",
                            ]
                        body = {
                            "identity": {**identity, "prospective_nonce": _prospective_nonce("allocatbelt.feedback-template-nonce.v1", identity)},
                            "nonce_scope": PROSPECTIVE_NONCE_SCOPE,
                            "nonce_instantiation_schema": NONCE_INSTANTIATION_SCHEMA,
                            "nonce_instantiation_rule": NONCE_INSTANTIATION_RULE,
                            "policy": policy_context,
                            "required_proofs": required_proofs,
                        }
                        feedback_templates.append({**body, "template_sha256": _sha256(_canonical(body))})
    capacity_digest = _sha256(_canonical(capacity_templates))
    feedback_digest = _sha256(_canonical(feedback_templates))
    return {
        "capacity_process_templates": capacity_templates,
        "capacity_process_templates_sha256": capacity_digest,
        "feedback_process_templates": feedback_templates,
        "feedback_process_templates_sha256": feedback_digest,
    }


def validate_qualification_plan_maps(value: dict[str, Any]) -> None:
    capacity = value["capacity_process_templates"]
    feedback = value["feedback_process_templates"]
    campaign_id = _token(value["campaign_id"], "campaign plan campaign ID")
    runtime_binding = value["runtime_binding"]
    _require(type(runtime_binding) is dict and _is_sha(runtime_binding.get("resource_policy_sha256")) and _is_sha(runtime_binding.get("feedback_policy_sha256")), "campaign plan policy bindings are malformed")
    _require(type(capacity) is list and type(feedback) is list, "campaign plan qualification process maps must be lists")
    _require(_is_sha(value["capacity_process_templates_sha256"]) and _sha256(_canonical(capacity)) == value["capacity_process_templates_sha256"], "campaign plan capacity process-template digest mismatch")
    _require(_is_sha(value["feedback_process_templates_sha256"]) and _sha256(_canonical(feedback)) == value["feedback_process_templates_sha256"], "campaign plan feedback process-template digest mismatch")
    _require(len(capacity) == 45 and len(feedback) == 720, "campaign plan prospective process maps do not cover three hosts, 15 contexts, and both comparison families")
    nonces: set[str] = set()
    capacity_bindings: dict[tuple[str, str, str], tuple[str, str]] = {}
    for index, item_value in enumerate(capacity):
        item = _exact(item_value, {
            "capacity_key", "pressure_condition_id", "calibrator", "prospective_nonce", "nonce_scope", "nonce_instantiation_schema", "nonce_instantiation_rule", "source_manifest_sha256", "source_sha256", "binary_sha256",
            "request_template", "context_template", "required_proofs", "template_sha256",
        }, f"capacity process template[{index}]")
        key = _exact(item["capacity_key"], {"host_id", "workload", "profile", "calibration_id"}, f"capacity process template[{index}] key")
        for field in key.values():
            _token(field, f"capacity process template[{index}] key field")
        valid_contexts = {
            *((workload, profile) for workload in ("cpu", "memory", "http", "disk") for profile in STANDALONE_PROFILES),
            *(("mixed", profile) for profile in MIXED_PROFILES),
        }
        _require((key["workload"], key["profile"]) in valid_contexts, f"capacity process template[{index}] names an unknown workload/profile")
        matrix_key = (key["host_id"], key["workload"], key["profile"])
        _require(matrix_key not in capacity_bindings, f"capacity process template[{index}] repeats a host/workload/profile")
        pressure_condition_id = _token(item["pressure_condition_id"], f"capacity process template[{index}] pressure condition id")
        capacity_bindings[matrix_key] = (key["calibration_id"], pressure_condition_id)
        _exact(item["calibrator"], {"allocator", "executor"}, f"capacity process template[{index}] calibrator")
        for field in ("source_manifest_sha256", "source_sha256", "binary_sha256"):
            _require(_is_sha(item[field]), f"capacity process template[{index}] {field} is malformed")
        request = _pin(item["request_template"], f"capacity process template[{index}] request template")
        context = _pin(item["context_template"], f"capacity process template[{index}] context template")
        _require(item["source_manifest_sha256"] == value["source_manifests"].get(key["host_id"]), f"capacity process template[{index}] source manifest differs from the campaign plan")
        _require(item["calibrator"]["allocator"] in ALLOCATORS and item["calibrator"]["executor"] in EXECUTORS, f"capacity process template[{index}] calibrator is unsupported")
        _require(item["nonce_scope"] == PROSPECTIVE_NONCE_SCOPE and item["nonce_instantiation_schema"] == NONCE_INSTANTIATION_SCHEMA and item["nonce_instantiation_rule"] == NONCE_INSTANTIATION_RULE, f"capacity process template[{index}] nonce is not marked as reusable-template scoped")
        _require(type(item["prospective_nonce"]) is str and re.fullmatch(r"[0-9a-f]{32}", item["prospective_nonce"]) is not None and item["prospective_nonce"] not in nonces, f"capacity process template[{index}] prospective nonce is malformed or repeated")
        expected_capacity_nonce = _prospective_nonce("allocatbelt.capacity-template-nonce.v1", {
            "campaign_id": campaign_id, "host_id": key["host_id"], "workload": key["workload"],
            "profile": key["profile"], "calibration_id": key["calibration_id"],
            "allocator": item["calibrator"]["allocator"], "executor": item["calibrator"]["executor"],
            "source_sha256": item["source_sha256"], "binary_sha256": item["binary_sha256"],
            "request_template_sha256": request["raw_sha256"], "context_template_sha256": context["raw_sha256"],
        })
        _require(item["prospective_nonce"] == expected_capacity_nonce, f"capacity process template[{index}] nonce differs from its frozen identity")
        nonces.add(item["prospective_nonce"])
        _require(item["required_proofs"] == ["capacity_artifact", "capacity_receipt", "pre_confirmation_stage_receipt"], f"capacity process template[{index}] proof requirements changed")
        body = {name: item[name] for name in item if name != "template_sha256"}
        _require(item["template_sha256"] == _sha256(_canonical(body)), f"capacity process template[{index}] digest mismatch")
    _require(len({key[0] for key in capacity_bindings}) == 3 and len(capacity_bindings) == 45, "capacity process templates do not cover exactly three hosts and all workload/profile contexts")
    feedback_nonces: set[str] = set()
    feedback_matrix: set[tuple[str, str, str, str, str, str]] = set()
    for index, item_value in enumerate(feedback):
        item = _exact(item_value, {"identity", "nonce_scope", "nonce_instantiation_schema", "nonce_instantiation_rule", "policy", "required_proofs", "template_sha256"}, f"feedback process template[{index}]")
        identity = _exact(item["identity"], {
            "campaign_id", "host_id", "workload", "profile", "comparison_family", "capacity_calibration_id",
            "pressure_condition_id", "allocator", "executor", "source_sha256", "binary_sha256",
            "fixed_policy_sha256", "feedback_policy_sha256", "context_policy_sha256", "prospective_nonce",
        }, f"feedback process template[{index}] prospective identity")
        for field in ("campaign_id", "host_id", "workload", "profile", "capacity_calibration_id", "allocator"):
            _token(identity[field], f"feedback process template[{index}] {field}")
        _require(identity["comparison_family"] in ("fixed_policy", "external_pressure"), f"feedback process template[{index}] comparison family is unknown")
        _require(identity["executor"] in ("allocatbelt", "tokio-1.53.1"), f"feedback process template[{index}] executor is unknown")
        matrix_key = (identity["host_id"], identity["workload"], identity["profile"])
        _require(matrix_key in capacity_bindings and identity["capacity_calibration_id"] == capacity_bindings[matrix_key][0], f"feedback process template[{index}] does not bind its capacity calibration")
        feedback_key = (*matrix_key, identity["comparison_family"], identity["allocator"], identity["executor"])
        _require(feedback_key not in feedback_matrix, f"feedback process template[{index}] repeats a prospective process identity")
        feedback_matrix.add(feedback_key)
        if identity["comparison_family"] == "fixed_policy":
            _require(identity["pressure_condition_id"] is None, f"fixed feedback template[{index}] unexpectedly binds a pressure condition")
            expected_proofs = ["feedback_validation_receipt", "post_release_runtime_binding_receipt"]
        else:
            _token(identity["pressure_condition_id"], f"pressure feedback template[{index}] condition id")
            _require(identity["pressure_condition_id"] == capacity_bindings[matrix_key][1], f"pressure feedback template[{index}] does not bind its exact pressure condition")
            expected_proofs = [
                "feedback_validation_receipt", "external_pressure_validation_receipt",
                "pressure_readiness_interval_receipt", "successful_fixed_predecessor_receipt",
                "post_release_runtime_binding_receipt",
            ]
        for field in ("source_sha256", "binary_sha256", "fixed_policy_sha256", "feedback_policy_sha256", "context_policy_sha256"):
            _require(_is_sha(identity[field]), f"feedback process template[{index}] {field} is malformed")
        _require(identity["fixed_policy_sha256"] == runtime_binding["resource_policy_sha256"], f"feedback process template[{index}] fixed-policy digest differs from the plan")
        _require(identity["feedback_policy_sha256"] == runtime_binding["feedback_policy_sha256"], f"feedback process template[{index}] feedback-policy digest differs from the plan")
        _require(item["nonce_scope"] == PROSPECTIVE_NONCE_SCOPE and item["nonce_instantiation_schema"] == NONCE_INSTANTIATION_SCHEMA and item["nonce_instantiation_rule"] == NONCE_INSTANTIATION_RULE, f"feedback process template[{index}] nonce is not marked as reusable-template scoped")
        nonce = identity["prospective_nonce"]
        _require(type(nonce) is str and re.fullmatch(r"[0-9a-f]{32}", nonce) is not None and nonce not in feedback_nonces, f"feedback process template[{index}] prospective nonce is malformed or repeated")
        feedback_nonces.add(nonce)
        policy = _exact(item["policy"], {"version", "reader_contract", "algorithm", "context", "source_pins"}, f"feedback process template[{index}] policy")
        _require(policy["version"] == "runtime-feedback-policy-v1", f"feedback process template[{index}] policy version is unsupported")
        reader_contract = _exact(policy["reader_contract"], {
            "sample_interval_ns", "max_dense_gap_ns", "telemetry_freshness_ns", "required_breach_samples", "actuation_cooldown_ns", "minimum_dense_observations",
        }, f"feedback process template[{index}] reader contract")
        _require(reader_contract == {
            "sample_interval_ns": 100_000_000, "max_dense_gap_ns": 200_000_000,
            "telemetry_freshness_ns": 500_000_000, "required_breach_samples": 3,
            "actuation_cooldown_ns": 1_000_000_000, "minimum_dense_observations": 1,
        }, f"feedback process template[{index}] reader timing contract changed")
        algorithm = _exact(policy["algorithm"], {"cpu_reduction_rule", "cpu_recovery_increment", "network_sensor_source", "upload_controlled"}, f"feedback process template[{index}] algorithm")
        _require(algorithm == {
            "cpu_reduction_rule": "floor_current_limit_over_10_zero_is_quantized",
            "cpu_recovery_increment": 1, "network_sensor_source": "download_application_bytes_only", "upload_controlled": False,
        }, f"feedback process template[{index}] algorithm changed")
        context = _exact(policy["context"], {"workers", "minimum_dense_observations", "controls"}, f"feedback process template[{index}] numeric context")
        workers = 2 if identity["profile"] == "oversubscribed" else 4
        expected_controls = {
            "cpu": {"floor": 1, "initial": workers, "ceiling": workers, "low_bps": 3000, "high_bps": 8000},
            "disk": {"floor": 64 * 1024 * 1024, "initial": 16 * 1024**3, "ceiling": 16 * 1024**3, "low_bps": 3000, "high_bps": 8000},
            "download": {"floor": 64 * 1024 * 1024, "initial": 16 * 1024**3, "ceiling": 16 * 1024**3, "low_bps": 3000, "high_bps": 8000},
        }
        _require(context == {"workers": workers, "minimum_dense_observations": 1, "controls": expected_controls}, f"feedback process template[{index}] numeric context differs from the supported runtime builder")
        source_pins = _exact(policy["source_pins"], {"feedback_validator", "runtime_bindings", "runtime_policy", "runtime_sensor"}, f"feedback process template[{index}] source pins")
        for name, expected_path in (("feedback_validator", HARNESS_PATHS["feedback_validator"]), ("runtime_bindings", FEEDBACK_RUNTIME_PATH), ("runtime_policy", FEEDBACK_POLICY_PATH), ("runtime_sensor", FEEDBACK_SENSOR_PATH)):
            pin = _exact(source_pins[name], {"path", "sha256"}, f"feedback process template[{index}] {name} source pin")
            _require(pin["path"] == expected_path and _is_sha(pin["sha256"]), f"feedback process template[{index}] {name} source pin is malformed")
        expected_context_policy_sha = _sha256(_canonical(policy))
        _require(identity["context_policy_sha256"] == expected_context_policy_sha, f"feedback process template[{index}] context policy digest mismatch")
        nonce_identity = {name: field for name, field in identity.items() if name != "prospective_nonce"}
        _require(nonce == _prospective_nonce("allocatbelt.feedback-template-nonce.v1", nonce_identity), f"feedback process template[{index}] nonce differs from its frozen identity")
        _require(type(item["required_proofs"]) is list and item["required_proofs"] == expected_proofs, f"feedback process template[{index}] proof requirements changed")
        body = {name: item[name] for name in item if name != "template_sha256"}
        _require(item["template_sha256"] == _sha256(_canonical(body)), f"feedback process template[{index}] digest mismatch")
    expected_feedback = {
        (*context, family, allocator, executor)
        for context in capacity_bindings
        for family in ("fixed_policy", "external_pressure")
        for allocator in ALLOCATORS
        for executor in ("allocatbelt", "tokio-1.53.1")
    }
    _require(feedback_matrix == expected_feedback, "feedback process templates do not cover the exact source/condition/allocator/executor matrix")
