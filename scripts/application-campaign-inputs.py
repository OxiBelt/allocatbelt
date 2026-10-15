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
FEEDBACK_POLICY_SCHEMA_V2 = "allocatbelt.application-feedback-policy-artifact.v2"
CAPACITY_FLOOR_POLICY_ID = "application_capacity_relative_tenth_v1"
SOURCE5_PREPARATION_SCHEMA = "allocatbelt.application-source5-preparation.v1"
SOURCE5_PREPARATION_CORE_SCHEMA = "allocatbelt.application-source5-preparation-core.v1"
SOURCE5_PREPARATION_CORE_SCHEMA_V2 = "allocatbelt.application-source5-preparation-core.v2"
SOURCE5_PREPARATION_RESOURCE_BUDGET_SCHEMA = "allocatbelt.application-source5-preparation-resource-budget.v1"
SOURCE5_PRESSURE_CONDITION_SCHEMA = "allocatbelt.application-source5-pressure-condition.v1"
SOURCE5_PRESSURE_READINESS_RULE = "allocatbelt.application-source5-pressure-readiness-threshold-rule.v1"

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
MAX_PREPARATION_BYTES = 64 * 1024 * 1024
U64_MAX = (1 << 64) - 1
PROSPECTIVE_NONCE_SCOPE = "reusable_template"
NONCE_INSTANTIATION_SCHEMA = "allocatbelt.application-process-nonce-instantiation.v1"
NONCE_INSTANTIATION_RULE = "sha256(template_nonce,campaign_id,job_run_id,pair_member,ordinal)"

# Source5 execution modules are ordinary typed inventory records.  The public
# SourceV5 qualification_harness keeps its original eight-key shape.
PREPARATION_MODULE_PATHS = {
    "source5_controller": "scripts/application-source5-campaign.py",
    "campaign_controller": "scripts/application-campaign.py",
    "campaign_chronology": "scripts/application-campaign-chronology.py",
    "campaign_inputs": "scripts/application-campaign-inputs.py",
    "capacity_stage": "scripts/application-capacity-stage.py",
    "fixed_pair": "scripts/application-fixed-pair.py",
    "feedback_composer": "scripts/application-feedback-composition.py",
    "preparation_helper": "scripts/application-source5-input-preparation.py",
    "pressure_driver": "scripts/application-pressure-driver.py",
    "pressure_pair": "scripts/application-pressure-pair.py",
    "pressure_readback": "scripts/application-pressure-readback.py",
    "soak_recipe_builder": "scripts/application-soak-recipe.py",
    "soak_readback": "scripts/application-soak-readback.py",
    "soak_runner": "scripts/run-application-soak.sh",
    "capacity_producer": "scripts/application-byte-capacity.py",
    "feedback_readback": "scripts/application-feedback-readback.py",
}


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


def _rust_string_constant(text: str, name: str) -> str:
    match = re.search(
        rf"\b(?:pub\(super\)\s+)?const\s+{re.escape(name)}\s*:\s*&str\s*=\s*\"([^\"]+)\"\s*;",
        text,
    )
    _require(match is not None, f"Rust policy string constant is missing or changed: {name}")
    return match.group(1)


def _capacity_floor_policy_from_runtime(runtime_text: str) -> dict[str, Any]:
    policy = {
        "capacity_divisor": _rust_constant(runtime_text, "CAPACITY_FLOOR_DIVISOR"),
        "minimum_floor_bytes_per_second": _rust_constant(runtime_text, "CAPACITY_FLOOR_MINIMUM_BYTES_PER_SECOND"),
        "policy_id": _rust_string_constant(runtime_text, "CAPACITY_FLOOR_POLICY_ID"),
        "probe_activation": _rust_string_constant(runtime_text, "CAPACITY_FLOOR_PROBE_ACTIVATION"),
        "rule": _rust_string_constant(runtime_text, "CAPACITY_FLOOR_RULE"),
        "rule_version": _rust_string_constant(runtime_text, "CAPACITY_FLOOR_RULE_VERSION"),
        "runtime_activation": _rust_string_constant(runtime_text, "CAPACITY_FLOOR_RUNTIME_ACTIVATION"),
        "static_floor_bytes_per_second": _rust_constant(runtime_text, "FEEDBACK_RATE_FLOOR"),
        "static_rate_roof_bytes_per_second": _rust_constant(runtime_text, "APPLICATION_RATE_CEILING_BYTES_PER_SECOND"),
    }
    _require(policy["policy_id"] == CAPACITY_FLOOR_POLICY_ID,
             "Rust runtime capacity-floor policy ID differs from the prospective caller contract")
    _require(policy["rule_version"] == "application-feedback-capacity-resolution-v2"
             and policy["rule"] == "max_one_min_static_floor_capacity_div_ten"
             and policy["probe_activation"] == "explicit_policy_id_and_capacity_artifact"
             and policy["runtime_activation"] == "explicit_pressure_qualification_and_policy_id_and_capacity_artifact"
             and policy["capacity_divisor"] == 10
             and policy["minimum_floor_bytes_per_second"] == 1,
             "Rust capacity-floor arithmetic or activation contract differs")
    _require(0 < policy["minimum_floor_bytes_per_second"] <= policy["static_floor_bytes_per_second"]
             < policy["static_rate_roof_bytes_per_second"],
             "Rust capacity-floor policy bounds are invalid")
    return policy


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


def build_feedback_policy_artifact(
    root: Path, source_records: Any, harness: Any, *,
    capacity_floor_policy_id: str | None = None,
) -> dict[str, Any]:
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
    floor_policy = None
    if capacity_floor_policy_id is not None:
        _require(capacity_floor_policy_id == CAPACITY_FLOOR_POLICY_ID,
                 "selected capacity-floor policy ID is unknown")
        floor_policy = _capacity_floor_policy_from_runtime(runtime_text)
    contexts, algorithm = _feedback_controls(runtime_text)
    _require(contexts and all(item["minimum_dense_observations"] > 0 for item in contexts.values()), "runtime feedback density threshold is invalid")
    policy_schema = FEEDBACK_POLICY_SCHEMA_V2 if floor_policy is not None else FEEDBACK_POLICY_SCHEMA
    policy_body = {
        "schema": policy_schema,
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
    if floor_policy is not None:
        policy_body["capacity_floor_policy"] = floor_policy
    return {"schema": policy_schema, "policy": policy_body, "policy_sha256": _sha256(_canonical(policy_body))}


def validate_feedback_policy_artifact(value: Any, source_records: Any, harness: Any) -> dict[str, Any]:
    artifact = _exact(value, {"schema", "policy", "policy_sha256"}, "numeric feedback policy artifact")
    _require(artifact["schema"] in (FEEDBACK_POLICY_SCHEMA, FEEDBACK_POLICY_SCHEMA_V2), "unsupported feedback policy artifact schema")
    body_keys = {"schema", "version", "reader_contract", "algorithm", "contexts", "source_pins"}
    if artifact["schema"] == FEEDBACK_POLICY_SCHEMA_V2:
        body_keys.add("capacity_floor_policy")
    body = _exact(artifact["policy"], body_keys, "feedback policy body")
    _require(body["schema"] == artifact["schema"] and type(body["version"]) is str and body["version"], "feedback policy version is missing")
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
    if artifact["schema"] == FEEDBACK_POLICY_SCHEMA_V2:
        descriptor = _exact(body["capacity_floor_policy"], {
            "capacity_divisor", "minimum_floor_bytes_per_second", "policy_id", "probe_activation",
            "rule", "rule_version", "runtime_activation", "static_floor_bytes_per_second",
            "static_rate_roof_bytes_per_second",
        }, "calibrated capacity-floor policy descriptor")
        for field in (
            "capacity_divisor", "minimum_floor_bytes_per_second",
            "static_floor_bytes_per_second", "static_rate_roof_bytes_per_second",
        ):
            _require(type(descriptor[field]) is int and descriptor[field] > 0,
                     f"capacity-floor descriptor {field} is not a positive integer")
        _require(descriptor["policy_id"] == CAPACITY_FLOOR_POLICY_ID and
                 descriptor["rule_version"] == "application-feedback-capacity-resolution-v2" and
                 descriptor["rule"] == "max_one_min_static_floor_capacity_div_ten" and
                 descriptor["probe_activation"] == "explicit_policy_id_and_capacity_artifact" and
                 descriptor["runtime_activation"] == "explicit_pressure_qualification_and_policy_id_and_capacity_artifact" and
                 descriptor["capacity_divisor"] == 10 and
                 descriptor["minimum_floor_bytes_per_second"] == 1 and
                 descriptor["static_floor_bytes_per_second"] == 64 * 1024 * 1024 and
                 descriptor["static_rate_roof_bytes_per_second"] == 16 * 1024**3,
                 "calibrated capacity-floor descriptor differs from the source-published v1 rule")
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


def _validate_selected_floor_source_manifest(
    manifest: dict[str, Any], selected_policy_id: str, host_id: str,
) -> dict[str, Any]:
    _require(selected_policy_id == CAPACITY_FLOOR_POLICY_ID,
             "selected capacity-floor policy ID is unknown")
    artifact = validate_feedback_policy_artifact(
        manifest.get("feedback_policy"), manifest["source"]["files"],
        manifest.get("qualification_harness"),
    )
    descriptor = artifact["policy"].get("capacity_floor_policy")
    _require(artifact["schema"] == FEEDBACK_POLICY_SCHEMA_V2 and
             type(descriptor) is dict and
             descriptor["policy_id"] == selected_policy_id,
             f"selected capacity-floor rule is not source-published for {host_id}")
    return artifact


def _verify_source_bytes(root: Path | None, pin: dict[str, Any], label: str) -> bool:
    if root is None:
        return False
    candidate = _safe_child(root, pin["relative_path"], label)
    raw, actual = _read_regular(candidate, label, MAX_INPUT_FILE_BYTES)
    _require(actual == pin["raw_sha256"], f"{label} bytes differ from their prospective raw pin")
    return True


def _preparation_json(raw: bytes, label: str) -> Any:
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise InputError(f"{label} is not bounded UTF-8 JSON: {error}") from error
    _require(_canonical(value) == raw, f"{label} is not canonical JSON")
    return value


def preparation_core_from_spec(spec: dict[str, Any]) -> dict[str, Any]:
    """Return the predeclared SpecV3 portion that preparation may not change."""
    keys = {
        "campaign_id", "runner_sha256", "hosts", "cells", "protocol",
        "runtime_binding", "phase_adapters", "aa_controls", "soak", "deadlines",
    }
    optional = {"capacity_floor_policy_id"} if "capacity_floor_policy_id" in spec else set()
    _exact(spec, keys | {"schema", "source_manifests", "rates", "oracles", "qualification_inputs"} | optional, "final SpecV3 for preparation bridge")
    _require(spec["schema"] == SPEC_V3_SCHEMA, "preparation can only bridge to SpecV3")
    policy_id = spec.get("capacity_floor_policy_id")
    if policy_id is None:
        return {"schema": SOURCE5_PREPARATION_CORE_SCHEMA, **{key: spec[key] for key in sorted(keys)}}
    _require(policy_id == CAPACITY_FLOOR_POLICY_ID,
             "SpecV3 capacity floor policy ID is unknown")
    return {
        "schema": SOURCE5_PREPARATION_CORE_SCHEMA_V2,
        **{key: spec[key] for key in sorted(keys)},
        "capacity_floor_policy_id": policy_id,
    }


def _validate_preparation_core(value: Any) -> dict[str, Any]:
    if type(value) is dict and value.get("schema") == SOURCE5_PREPARATION_CORE_SCHEMA:
        core = _exact(value, {
            "schema", "campaign_id", "runner_sha256", "hosts", "cells", "protocol",
            "runtime_binding", "phase_adapters", "aa_controls", "soak", "deadlines",
        }, "preparation core")
    elif type(value) is dict and value.get("schema") == SOURCE5_PREPARATION_CORE_SCHEMA_V2:
        core = _exact(value, {
            "schema", "campaign_id", "runner_sha256", "hosts", "cells", "protocol",
            "runtime_binding", "phase_adapters", "aa_controls", "soak", "deadlines",
            "capacity_floor_policy_id",
        }, "preparation core v2")
        _require(core["capacity_floor_policy_id"] == CAPACITY_FLOOR_POLICY_ID,
                 "preparation core capacity floor policy ID is unknown")
    else:
        raise InputError("unsupported preparation core schema")
    _token(core["campaign_id"], "preparation campaign ID")
    _require(_is_sha(core["runner_sha256"]), "preparation runner SHA-256 is malformed")

    host_keys = {
        "host_id", "venue", "host_fingerprint_sha256", "controls",
    }
    control_keys = {
        "cpu_model", "microcode_sha256", "kernel_release", "governor",
        "frequency_policy", "boost_policy", "cpu_set", "numa_policy",
        "cgroup_policy_sha256", "background_load_policy_sha256",
        "x86_64_v3_capability_sha256", "target_triple", "target_cpu",
    }
    hosts = core["hosts"]
    _require(type(hosts) is list and len(hosts) == 3, "preparation core must pin three genuine hosts")
    host_ids: list[str] = []
    venues: list[str] = []
    for index, host_value in enumerate(hosts):
        host = _exact(host_value, host_keys, f"preparation host[{index}]")
        host_id = _token(host["host_id"], f"preparation host[{index}] ID")
        _require(host_id not in host_ids, "preparation core repeats a host ID")
        host_ids.append(host_id)
        _require(host["venue"] in ("bare_metal", "kvm_guest"), f"preparation host {host_id} has an unsupported venue")
        venues.append(host["venue"])
        controls = _exact(host["controls"], control_keys, f"preparation host {host_id} controls")
        for field in ("microcode_sha256", "cgroup_policy_sha256", "background_load_policy_sha256", "x86_64_v3_capability_sha256"):
            _require(_is_sha(controls[field]), f"preparation host {host_id} has an unfrozen {field}")
        for field in ("cpu_model", "kernel_release", "governor", "frequency_policy", "boost_policy", "cpu_set", "numa_policy"):
            _require(type(controls[field]) is str and bool(controls[field]), f"preparation host {host_id} has unknown {field}")
        _require(controls["target_triple"] == "x86_64-unknown-linux-gnu" and controls["target_cpu"] == "x86-64-v3",
                 f"preparation host {host_id} is outside the frozen x86-64-v3 GNU target")
        _require(_is_sha(host["host_fingerprint_sha256"]) and
                 _sha256(_canonical(controls)) == host["host_fingerprint_sha256"],
                 f"preparation host {host_id} fingerprint differs from its controls")
    _require(venues.count("bare_metal") == 1 and venues.count("kvm_guest") == 2,
             "preparation core must contain one bare-metal host and two KVM guests")

    expected_contexts = {
        (workload, profile)
        for workload, profiles in (
            ("cpu", STANDALONE_PROFILES), ("memory", STANDALONE_PROFILES),
            ("http", STANDALONE_PROFILES), ("disk", STANDALONE_PROFILES),
            ("mixed", MIXED_PROFILES),
        )
        for profile in profiles
    }
    cells = core["cells"]
    _require(type(cells) is list and len(cells) == 15, "preparation core must pin all 15 workload/profile contexts")
    seen_cells: set[tuple[str, str]] = set()
    for index, cell_value in enumerate(cells):
        cell = _exact(cell_value, {
            "family", "workload", "profile", "arrivals", "async_workers",
            "resource_limits", "resource_ceiling_sha256", "capacity_horizon_seconds",
        }, f"preparation cell[{index}]")
        workload, profile = cell["workload"], cell["profile"]
        key = (workload, profile)
        _require(key in expected_contexts and key not in seen_cells, f"preparation cell[{index}] has an unknown or duplicate context")
        seen_cells.add(key)
        _require(cell["family"] == workload, f"preparation cell[{index}] family/workload differs")
        minimum_arrivals = 400_000 if workload == "mixed" else 100_000
        _require(type(cell["arrivals"]) is int and cell["arrivals"] >= minimum_arrivals,
                 f"preparation cell[{index}] reduces the frozen observation minimum")
        _require(type(cell["async_workers"]) is int and cell["async_workers"] == (2 if profile == "oversubscribed" else 4),
                 f"preparation cell[{index}] changes the fixed worker count")
        limits = _exact(cell["resource_limits"], {"managed_bytes", "disk_ops", "network_ops", "tasks", "cpu_charges"}, f"preparation cell[{index}] resource limits")
        for name, number in limits.items():
            _require(type(number) is int and 0 <= number <= (1 << 64) - 1, f"preparation cell[{index}] {name} is not a u64")
        _require(limits["tasks"] > 0 and limits["cpu_charges"] > 0, f"preparation cell[{index}] removes mandatory task/CPU limits")
        _require(_is_sha(cell["resource_ceiling_sha256"]) and _sha256(_canonical(limits)) == cell["resource_ceiling_sha256"],
                 f"preparation cell[{index}] resource ceiling digest differs")
        _require(cell["capacity_horizon_seconds"] == 30, f"preparation cell[{index}] changes the 30-second horizon")
    _require(seen_cells == expected_contexts, "preparation core does not cover the full 15-context matrix")

    protocol_keys = {
        "exploration_pairs", "confirmation_pairs", "standalone_min_successes", "mixed_min_successes",
        "family_min_successes", "bootstrap_draws", "bootstrap_block_arrivals", "bootstrap_seed",
        "bootstrap_prng", "comparison_family_order", "external_pressure_predecessor", "confidence",
        "simultaneous_adjustment", "bootstrap_hierarchy", "weighting", "gate_scope",
        "safety_overload_gate_eligible", "soak_seconds", "soak_rss_growth_percent", "schedule_seed",
        "allocator_min_capacity_ratio", "allocator_max_p99_ratio", "executor_min_capacity_ratio",
        "executor_max_p99_ratio", "max_workload_throughput_ratio", "max_workload_cpu_ratio",
        "max_workload_p99_ratio", "max_retained_rss_ratio",
    }
    protocol = _exact(core["protocol"], protocol_keys, "preparation protocol")
    fixed_protocol = {
        "exploration_pairs": 6, "confirmation_pairs": 36,
        "standalone_min_successes": 100_000, "mixed_min_successes": 400_000,
        "family_min_successes": 100_000, "bootstrap_draws": 50_000,
        "bootstrap_block_arrivals": 1000, "confidence": 0.95,
        "simultaneous_adjustment": "paired_contiguous_block_max_standardized_deviation",
        "bootstrap_hierarchy": "independent_pair_jobs_with_shared_indices_within_job_then_full_contiguous_block_pseudotraces",
        "bootstrap_prng": "splitmix64_v1_fnv1a_group_seed_rejection_uniform",
        "weighting": "equal_profile_then_family_then_equal_eligible_contexts",
        "gate_scope": "independent_per_host_no_pooling", "safety_overload_gate_eligible": False,
        "soak_seconds": 10_800, "soak_rss_growth_percent": 5,
        "allocator_min_capacity_ratio": 1.05, "allocator_max_p99_ratio": 0.95,
        "executor_min_capacity_ratio": 1.05, "executor_max_p99_ratio": 0.95,
        "max_workload_throughput_ratio": 0.98, "max_workload_cpu_ratio": 1.02,
        "max_workload_p99_ratio": 1.05, "max_retained_rss_ratio": 1.05,
    }
    for key, expected in fixed_protocol.items():
        _require(protocol[key] == expected, f"preparation protocol changes fixed qualification value {key}")
    _require(protocol["comparison_family_order"] == ["fixed_policy", "external_pressure"], "preparation protocol changes comparison order")
    _require(protocol["external_pressure_predecessor"] == "fixed_policy_successful_pair_receipt_same_host_workload_profile_allocator_executor_load_ordinal", "preparation protocol changes pressure predecessor rule")
    for field in ("bootstrap_seed", "schedule_seed"):
        _require(type(protocol[field]) is int and 0 < protocol[field] <= (1 << 64) - 1, f"preparation protocol {field} is malformed")

    deadlines = _exact(core["deadlines"], {
        "setup_seconds", "trace_seconds", "drain_seconds", "shutdown_seconds",
        "process_seconds", "pair_validation_seconds", "outer_seconds", "soak_outer_seconds",
    }, "preparation deadlines")
    for field, number in deadlines.items():
        _require(type(number) is int and number > 0, f"preparation deadline {field} must be positive")
    _require(deadlines["setup_seconds"] == 120 and deadlines["process_seconds"] >= 1200 and
             deadlines["trace_seconds"] <= 3600 and deadlines["drain_seconds"] <= 3600 and
             deadlines["shutdown_seconds"] <= 600 and deadlines["pair_validation_seconds"] <= 3600 and
             3 * deadlines["process_seconds"] + deadlines["setup_seconds"] + deadlines["pair_validation_seconds"] <= deadlines["outer_seconds"] <= 25_320,
             "preparation deadlines differ from the frozen finite campaign contract")
    _require(deadlines["soak_outer_seconds"] >= 10_800 + 1200 + deadlines["pair_validation_seconds"] and deadlines["soak_outer_seconds"] <= 14_400,
             "preparation soak deadline does not cover the full three-hour horizon")

    binding = _exact(core["runtime_binding"], {
        "resource_domain", "resource_policy_sha256", "feedback_policy_sha256", "feedback_match", "source_state",
    }, "preparation runtime binding")
    _require(binding["resource_domain"] in ("pending", "owning_global_tenant") and
             binding["feedback_match"] in ("fixed_same_policy", "external_same_policy") and
             binding["source_state"] in ("pending", "complete"), "preparation runtime binding is unsupported")
    _require(_is_sha(binding["resource_policy_sha256"]) and _is_sha(binding["feedback_policy_sha256"]),
             "preparation runtime policy pins are malformed")
    phase = _exact(core["phase_adapters"], {
        "same_executor_aa_sha256", "three_hour_soak_sha256", "simultaneous_analysis_sha256",
    }, "preparation phase adapters")
    _require(all(value is None or _is_sha(value) for value in phase.values()), "preparation phase adapter pin is malformed")
    _require(type(core["aa_controls"]) is list and bool(core["aa_controls"]), "preparation core has no A/A design")
    soak = _exact(core["soak"], {
        "workload", "profile", "allocator", "executor", "driver_relative_path", "driver_sha256", "interval_ms",
    }, "preparation Soak contract")
    _require(soak["workload"] == "mixed" and soak["profile"] in MIXED_PROFILES and
             soak["allocator"] == "allocatbelt" and soak["executor"] == "bounded" and
             soak["driver_relative_path"] == "scripts/run-application-soak.sh" and
             _is_sha(soak["driver_sha256"]) and soak["interval_ms"] == 100,
             "preparation core changes the mandatory candidate-only three-hour Soak")
    return core


def _validate_preparation_templates(
    templates: Any, conditions: Any, host_ids: list[str], cells: list[dict[str, Any]],
    input_root: Path | None, campaign_id: str, source_pins: dict[str, Any],
    observed_host_values: dict[str, dict[str, Any]] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    expected = {(host_id, cell["workload"], cell["profile"]) for host_id in host_ids for cell in cells}
    _require(type(templates) is list and len(templates) == len(expected), "preparation capacity template matrix must have 45 entries")
    _require(type(conditions) is list and len(conditions) == len(expected), "preparation condition intensity matrix must have 45 entries")
    template_seen: dict[tuple[str, str, str], dict[str, Any]] = {}
    calibration_ids: set[str] = set()
    run_ids: set[str] = set()
    nonces: set[str] = set()
    for index, value in enumerate(templates):
        item = _exact(value, {
            "host_id", "workload", "profile", "calibration_id", "calibrator",
            "request_template", "context_template", "template_index", "run_id",
            "prospective_nonce", "template_sha256", "source_manifest_sha256",
            "source_sha256", "binary_sha256",
        }, f"preparation capacity template[{index}]")
        host_id = _token(item["host_id"], f"preparation capacity template[{index}] host")
        workload, profile = item["workload"], item["profile"]
        key = (host_id, workload, profile)
        _require(key in expected and key not in template_seen, f"preparation capacity template[{index}] has an unknown or repeated context")
        calibration_id = _token(item["calibration_id"], f"preparation capacity template[{index}] calibration ID")
        _require(calibration_id not in calibration_ids, "preparation repeats a capacity calibration ID")
        calibration_ids.add(calibration_id)
        calibrator = _exact(item["calibrator"], {"allocator", "executor"}, f"preparation capacity template[{index}] calibrator")
        _require(calibrator["allocator"] in ALLOCATORS and calibrator["executor"] in EXECUTORS,
                 f"preparation capacity template[{index}] calibrator is unsupported")
        request = _pin(item["request_template"], f"preparation capacity template[{index}] request template")
        context = _pin(item["context_template"], f"preparation capacity template[{index}] context template")
        _require(request["relative_path"] != context["relative_path"], "preparation request and context templates alias")
        source_pin = source_pins[host_id]
        manifest_pin = source_pin["manifest"]
        artifact = source_pin["artifacts"][calibrator["allocator"]]
        identity = {
            "campaign_id": campaign_id, "host_id": host_id, "workload": workload,
            "profile": profile, "calibration_id": calibration_id,
            "template_index": index, "request_template": request,
            "context_template": context, "calibrator": calibrator,
            "source_manifest_sha256": manifest_pin["semantic_sha256"],
            "source_sha256": manifest_pin["source_tree_sha256"],
            "binary_sha256": artifact["sha256"],
        }
        identity_sha = _sha256(_canonical(identity))
        expected_run_id = "prep-cap-" + identity_sha[:32]
        expected_nonce = _sha256(b"allocatbelt.application-source5-capacity-nonce.v1\0" + _canonical({
            "identity_sha256": identity_sha, "run_id": expected_run_id,
        }))[:32]
        _require(item["template_index"] == index and item["run_id"] == expected_run_id and
                 item["prospective_nonce"] == expected_nonce and
                 item["source_manifest_sha256"] == identity["source_manifest_sha256"] and
                 item["source_sha256"] == identity["source_sha256"] and
                 item["binary_sha256"] == identity["binary_sha256"],
                 f"preparation capacity template[{index}] job/source identity was changed")
        _token(item["run_id"], f"preparation capacity template[{index}] run ID")
        _require(type(item["prospective_nonce"]) is str and re.fullmatch(r"[0-9a-f]{32}", item["prospective_nonce"]) is not None and
                 item["run_id"] not in run_ids and item["prospective_nonce"] not in nonces,
                 "preparation capacity run IDs/nonces are malformed or repeated")
        run_ids.add(item["run_id"])
        nonces.add(item["prospective_nonce"])
        template_body = {key: value for key, value in item.items() if key != "template_sha256"}
        _require(_is_sha(item["template_sha256"]) and _sha256(_canonical(template_body)) == item["template_sha256"],
                 f"preparation capacity template[{index}] self-digest differs")
        if input_root is not None:
            request_raw, _request_sha = _read_preparation_input(input_root, request, "capacity request template", MAX_INPUT_FILE_BYTES)
            context_raw, _context_sha = _read_preparation_input(input_root, context, "capacity context template", MAX_INPUT_FILE_BYTES)
            request_value = _preparation_json(request_raw, "capacity request template")
            context_value = _preparation_json(context_raw, "capacity context template")
            _validate_capacity_template_values(request_value, context_value, workload, profile)
        template_seen[key] = {**item, "request_template": request, "context_template": context}
    _require(set(template_seen) == expected, "preparation capacity templates do not cover all host/context keys")

    condition_seen: dict[tuple[str, str, str], dict[str, Any]] = {}
    condition_ids: set[str] = set()
    pressure_calibration_ids: set[str] = set()
    for index, value in enumerate(conditions):
        item = _exact(value, {
            "host_id", "workload", "profile", "condition_id", "capacity_key",
            "pressure_calibration_id", "condition", "readiness_threshold_rule",
            "readiness_thresholds", "pressure_thresholds", "schedule",
        }, f"preparation condition intensity[{index}]")
        host_id = _token(item["host_id"], f"preparation condition[{index}] host")
        key = (host_id, item["workload"], item["profile"])
        _require(key in expected and key not in condition_seen, f"preparation condition[{index}] has an unknown or repeated context")
        template = template_seen[key]
        capacity_key = _exact(item["capacity_key"], {"host_id", "workload", "profile", "calibration_id"}, f"preparation condition[{index}] capacity key")
        expected_key = _capacity_key(*key, template["calibration_id"])
        _require(capacity_key == expected_key, f"preparation condition[{index}] does not bind its exact capacity key")
        condition_id = _token(item["condition_id"], f"preparation condition[{index}] ID")
        pressure_id = _token(item["pressure_calibration_id"], f"preparation condition[{index}] pressure calibration ID")
        _require(pressure_id not in (condition_id, capacity_key["calibration_id"]),
                 f"preparation condition[{index}] pressure calibration ID aliases another context identity")
        _require(condition_id not in condition_ids and pressure_id not in pressure_calibration_ids,
                 "preparation condition/calibration IDs must be unique")
        condition_ids.add(condition_id)
        pressure_calibration_ids.add(pressure_id)
        condition_pin = _pin(item["condition"], f"preparation condition[{index}] raw condition")
        thresholds = _exact(item["pressure_thresholds"], {
            "cpu_busy_min_basis_points", "disk_write_min_bytes_per_second",
            "disk_queue_or_stall_min_microseconds", "loopback_requests_min_per_second",
            "loopback_latency_p99_max_nanoseconds", "loopback_tx_min_bytes_per_second",
            "loopback_rx_min_bytes_per_second",
        }, f"preparation condition[{index}] readiness thresholds")
        for field, threshold in thresholds.items():
            _require(type(threshold) is int and 0 < threshold <= (1 << 64) - 1,
                     f"preparation condition[{index}] threshold {field} must be a positive u64")
        _require(thresholds["cpu_busy_min_basis_points"] <= 10_000,
                 f"preparation condition[{index}] CPU readiness threshold exceeds 100 percent")
        _require(item["readiness_threshold_rule"] == SOURCE5_PRESSURE_READINESS_RULE,
                 f"preparation condition[{index}] readiness selection rule is unsupported")
        campaign_thresholds = _exact(item["readiness_thresholds"], {
            "minimum_overlap_seconds", "minimum_ready_samples", "maximum_sample_gap_ms",
        }, f"preparation condition[{index}] campaign readiness thresholds")
        for field, number in campaign_thresholds.items():
            _require(type(number) is int and number > 0, f"preparation condition[{index}] campaign readiness {field} must be positive")
        _require(campaign_thresholds["minimum_overlap_seconds"] >= 30 and
                 campaign_thresholds["maximum_sample_gap_ms"] <= 200,
                 f"preparation condition[{index}] campaign readiness is below the frozen floor")
        schedule = _exact(item["schedule"], {
            "seed", "duration_seconds", "sample_interval_ms", "startup_deadline_seconds",
            "total_deadline_seconds", "term_deadline_seconds", "kill_deadline_seconds",
            "minimum_overlap_seconds", "startup_ready_windows", "cpu_duty_basis_points",
            "pressure_cpu_affinity", "application_cpu_affinity", "disk_bytes_per_second",
            "scratch_file_bytes", "network_requests_per_second", "network_payload_bytes",
        }, f"preparation condition[{index}] pressure intensity")
        for field in ("seed", "duration_seconds", "sample_interval_ms", "startup_deadline_seconds", "total_deadline_seconds", "term_deadline_seconds", "kill_deadline_seconds", "minimum_overlap_seconds", "startup_ready_windows", "cpu_duty_basis_points", "disk_bytes_per_second", "scratch_file_bytes", "network_requests_per_second", "network_payload_bytes"):
            _require(type(schedule[field]) is int and schedule[field] > 0, f"preparation condition[{index}] intensity {field} must be positive")
        _require(schedule["duration_seconds"] == 30 and schedule["sample_interval_ms"] == 100 and
                 schedule["duration_seconds"] * 1000 % schedule["sample_interval_ms"] == 0,
                 f"preparation condition[{index}] must retain the original 30s horizon and 100ms cadence")
        _require(schedule["minimum_overlap_seconds"] == schedule["duration_seconds"] and
                 schedule["total_deadline_seconds"] >= schedule["startup_deadline_seconds"] + schedule["duration_seconds"] + schedule["term_deadline_seconds"] + schedule["kill_deadline_seconds"],
                 f"preparation condition[{index}] pressure deadline omits a bounded phase")
        _require(campaign_thresholds["minimum_overlap_seconds"] <= schedule["duration_seconds"] and
                 campaign_thresholds["minimum_ready_samples"] >= campaign_thresholds["minimum_overlap_seconds"] * 1000 // schedule["sample_interval_ms"] and
                 campaign_thresholds["minimum_ready_samples"] <= schedule["duration_seconds"] * 1000 // schedule["sample_interval_ms"],
                 f"preparation condition[{index}] campaign readiness does not cover the full overlap sample schedule")
        _require(schedule["cpu_duty_basis_points"] <= 10_000 and schedule["scratch_file_bytes"] <= 1024 ** 3 and
                 schedule["scratch_file_bytes"] >= 4096 and schedule["scratch_file_bytes"] % 4096 == 0 and
                 schedule["disk_bytes_per_second"] <= 512 * 1024 * 1024 and
                 schedule["network_requests_per_second"] <= 100_000 and
                 16 <= schedule["network_payload_bytes"] <= 65_536,
                 f"preparation condition[{index}] pressure intensity exceeds driver limits")
        for field in ("pressure_cpu_affinity", "application_cpu_affinity"):
            cpus = schedule[field]
            _require(type(cpus) is list and bool(cpus) and all(type(cpu) is int and 0 <= cpu <= 65_535 for cpu in cpus) and cpus == sorted(set(cpus)),
                     f"preparation condition[{index}] {field} is malformed")
        if observed_host_values is not None:
            observed_cpus = observed_host_values[host_id]["cpu_affinity"]
            _require(schedule["application_cpu_affinity"] == observed_cpus and
                     set(schedule["pressure_cpu_affinity"]) <= set(observed_cpus),
                     f"preparation condition[{index}] pressure/application affinity differs from its observed host")
        if input_root is not None:
            condition_raw, condition_sha = _read_preparation_input(input_root, condition_pin, "pressure condition", MAX_INPUT_FILE_BYTES)
            condition_value = _preparation_json(condition_raw, "pressure condition")
            _exact(condition_value, {
                "schema", "host_id", "condition_id", "capacity_key", "pressure_calibration_id",
                "readiness_threshold_rule", "readiness_thresholds", "pressure_thresholds", "schedule",
            }, "pinned Source5 pressure condition")
            _require(condition_value["schema"] == SOURCE5_PRESSURE_CONDITION_SCHEMA and
                     condition_value["host_id"] == host_id and
                     condition_value["condition_id"] == condition_id and
                     condition_value["capacity_key"] == capacity_key and
                     condition_value["pressure_calibration_id"] == pressure_id and
                     condition_value["readiness_threshold_rule"] == item["readiness_threshold_rule"] and
                     condition_value["readiness_thresholds"] == campaign_thresholds and
                     condition_value["pressure_thresholds"] == thresholds and
                     condition_value["schedule"] == schedule and
                     condition_sha == condition_pin["raw_sha256"],
                     f"preparation condition[{index}] raw file differs from its pinned identity/intensity")
        condition_seen[key] = {**item, "capacity_key": capacity_key, "condition": condition_pin,
                               "pressure_thresholds": thresholds,
                               "readiness_thresholds": campaign_thresholds, "schedule": schedule}
    _require(set(condition_seen) == expected, "preparation condition intensities do not cover all host/context keys")
    # The supplied order is part of the intent.  Do not sort or rebuild it.
    return list(templates), list(conditions)


def _read_preparation_input(root: Path, pin: dict[str, Any], label: str, maximum: int) -> tuple[bytes, str]:
    candidate = _safe_child(root, pin["relative_path"], label)
    raw, actual = _read_regular(candidate, label, maximum)
    _require(actual == pin["raw_sha256"], f"{label} differs from its frozen raw pin")
    return raw, actual


def _validate_capacity_template_values(request: Any, context: Any, workload: str, profile: str) -> None:
    _exact(request, {"schema", "minimum_interval_seconds"}, "preparation capacity request template")
    _require(request["schema"] == "allocatbelt.application-capacity-request-template.v1" and
             type(request["minimum_interval_seconds"]) is int and 10 <= request["minimum_interval_seconds"] <= 30,
             "preparation request template differs from the fixed producer contract")
    _exact(context, {"schema", "storage", "network"}, "preparation capacity context template")
    _require(context["schema"] == "allocatbelt.application-capacity-context-template.v1",
             "preparation context template schema is unsupported")
    if workload in ("disk", "mixed"):
        storage = _exact(context["storage"], {
            "scope", "root_path", "filesystem_type", "device_major_minor", "minimum_free_bytes",
        }, "preparation storage template")
        _require(storage["scope"] == "application_file_io" and type(storage["root_path"]) is str and
                 Path(storage["root_path"]).is_absolute() and Path(storage["root_path"]).resolve(strict=False) == Path(storage["root_path"]),
                 "preparation storage root is not a normalized absolute path")
        _require(type(storage["filesystem_type"]) is str and re.fullmatch(r"[A-Za-z0-9._+-]{1,64}", storage["filesystem_type"]) is not None and
                 type(storage["device_major_minor"]) is str and re.fullmatch(r"[0-9]{1,10}:[0-9]{1,10}", storage["device_major_minor"]) is not None and
                 type(storage["minimum_free_bytes"]) is int and storage["minimum_free_bytes"] > 0,
                 "preparation storage facts or free-space floor are malformed")
    else:
        _require(context["storage"] is None, f"{workload}/{profile} cannot claim a storage context")
    if workload in ("http", "mixed"):
        network = _exact(context["network"], {"scope", "interface", "address", "namespace_inode"}, "preparation network template")
        _require(network["scope"] == "ipv4_loopback_application_bytes" and network["interface"] == "lo" and
                 network["address"] == "127.0.0.1" and type(network["namespace_inode"]) is int and network["namespace_inode"] > 0,
                 "preparation network context is not a typed loopback namespace binding")
    else:
        _require(context["network"] is None, f"{workload}/{profile} cannot claim a network context")


def validate_preparation_intent(
    value: Any,
    source_manifest_values: dict[str, dict[str, Any]] | None = None,
    input_root: Path | None = None,
) -> dict[str, Any]:
    """Validate the separate pre-Spec intent without consulting SpecV3 readiness."""
    body = _exact(value, {
        "schema", "core", "source_pins", "observed_hosts", "capacity_templates",
        "condition_intensities", "deferred", "eligibility", "preparation_sha256",
    }, "Source5 preparation intent")
    _require(body["schema"] == SOURCE5_PREPARATION_SCHEMA, "unsupported Source5 preparation intent schema")
    _require(_is_sha(body["preparation_sha256"]) and body["preparation_sha256"] == _digest_object(body, "preparation_sha256"),
             "Source5 preparation semantic digest is invalid")
    core = _validate_preparation_core(body["core"])
    selected_floor_policy_id = core.get("capacity_floor_policy_id")
    _require(selected_floor_policy_id is None or
             input_root is not None or source_manifest_values is not None,
             "selected preparation core requires its SourceV5 policy evidence")
    host_ids = [item["host_id"] for item in core["hosts"]]
    source_pins = _exact(body["source_pins"], set(host_ids), "preparation source-manifest pins")
    observed_hosts = _exact(body["observed_hosts"], set(host_ids), "preparation observed-host pins")
    _require(source_manifest_values is None or set(source_manifest_values) == set(host_ids),
             "provided SourceV5 manifests do not cover exactly the three preparation hosts")
    common_build: tuple[Any, ...] | None = None
    common_source: tuple[Any, ...] | None = None
    observed_host_values: dict[str, dict[str, Any]] = {}
    for host in core["hosts"]:
        host_id = host["host_id"]
        source_pin = _exact(source_pins[host_id], {"manifest", "modules", "artifacts"}, f"preparation source pin {host_id}")
        manifest_pin = _exact(source_pin["manifest"], {
            "relative_path", "raw_sha256", "semantic_sha256", "source_tree_sha256",
        }, f"preparation manifest pin {host_id}")
        _relative_path(manifest_pin["relative_path"], f"preparation source manifest {host_id}")
        for field in ("raw_sha256", "semantic_sha256", "source_tree_sha256"):
            _require(_is_sha(manifest_pin[field]), f"preparation source {host_id} {field} is malformed")
        modules = _exact(source_pin["modules"], set(PREPARATION_MODULE_PATHS), f"preparation module pins {host_id}")
        for role, expected_path in PREPARATION_MODULE_PATHS.items():
            module_pin = _exact(modules[role], {"path", "sha256"}, f"preparation {host_id} module {role}")
            _require(module_pin["path"] == expected_path and _is_sha(module_pin["sha256"]),
                     f"preparation {host_id} module {role} path/digest is invalid")
        artifacts = _exact(source_pin["artifacts"], set(ALLOCATORS), f"preparation real APP artifact pins {host_id}")
        artifact_paths: set[str] = set()
        artifact_hashes: set[str] = set()
        for allocator in ALLOCATORS:
            artifact = _exact(artifacts[allocator], {"path", "sha256"}, f"preparation {host_id} {allocator} APP artifact")
            _relative_path(artifact["path"], f"preparation {host_id} {allocator} APP artifact path")
            _require(_is_sha(artifact["sha256"]) and artifact["path"] not in artifact_paths,
                     f"preparation {host_id} APP artifact path/hash is invalid or aliased")
            artifact_paths.add(artifact["path"])
            artifact_hashes.add(artifact["sha256"])
        _require(len(artifact_hashes) == len(ALLOCATORS),
                 f"preparation {host_id} normal APP allocator artifact hashes are aliased")
        observed_pin = _exact(observed_hosts[host_id], {"relative_path", "raw_sha256"}, f"preparation observed-host pin {host_id}")
        _relative_path(observed_pin["relative_path"], f"preparation observed-host path {host_id}")
        _require(_is_sha(observed_pin["raw_sha256"]), f"preparation observed-host pin {host_id} is malformed")
        if input_root is not None:
            manifest_raw, manifest_sha = _read_preparation_input(input_root, {
                "relative_path": manifest_pin["relative_path"], "raw_sha256": manifest_pin["raw_sha256"],
            }, f"{host_id} SourceV5 manifest", MAX_INPUT_FILE_BYTES)
            manifest = _preparation_json(manifest_raw, f"{host_id} SourceV5 manifest")
            _require(manifest_sha == manifest_pin["raw_sha256"] and
                     manifest.get("manifest_sha256") == manifest_pin["semantic_sha256"] and
                     manifest.get("source", {}).get("source_tree_sha256") == manifest_pin["source_tree_sha256"],
                     f"preparation SourceV5 raw/semantic/tree pins differ for {host_id}")
            if selected_floor_policy_id is not None:
                _validate_selected_floor_source_manifest(
                    manifest, selected_floor_policy_id, host_id,
                )
        else:
            manifest = None
        if source_manifest_values is not None:
            source = source_manifest_values[host_id]
            _require(type(source) is dict and source.get("schema") == SOURCE_V5_SCHEMA,
                     f"preparation host {host_id} is not backed by SourceV5")
            if selected_floor_policy_id is not None:
                selected_artifact = _validate_selected_floor_source_manifest(
                    source, selected_floor_policy_id, host_id,
                )
                if manifest is not None:
                    _require(manifest["feedback_policy"] == selected_artifact,
                             f"preparation selected SourceV5 feedback policy differs in raw and structured input for {host_id}")
            _require(source.get("manifest_sha256") == manifest_pin["semantic_sha256"] and
                     _digest_object(source, "manifest_sha256") == source["manifest_sha256"] and
                     source.get("source", {}).get("source_tree_sha256") == manifest_pin["source_tree_sha256"] and
                     source.get("build", {}).get("host_id") == host_id,
                     f"preparation SourceV5 value/pin differs for {host_id}")
            records = _inventory_map(source.get("source", {}).get("files"))
            for role, module_pin in modules.items():
                record = records.get(module_pin["path"])
                _require(type(record) is dict and record.get("kind") == "file" and
                         record.get("sha256") == module_pin["sha256"],
                         f"preparation module {role} is not its regular typed SourceV5 entry for {host_id}")
            if input_root is not None:
                _require(manifest == source, f"{host_id} manifest raw bytes decode to a different supplied SourceV5 value")
            build = source["build"]
            source_meta = source["source"]
            build_identity = tuple(build.get(key) for key in (
                "rustc_release", "rustc_verbose", "cargo_version", "target_triple",
                "target_cpu", "features_sha256", "build_inputs_sha256",
            ))
            source_identity = tuple(source_meta.get(key) for key in (
                "git_commit", "source_tree_sha256", "cargo_lock_sha256",
            ))
            _require(build.get("target_triple") == "x86_64-unknown-linux-gnu" and build.get("target_cpu") == "x86-64-v3" and
                     all(_is_sha(build.get(key)) for key in ("features_sha256", "build_inputs_sha256")),
                     f"preparation source build identity is incomplete for {host_id}")
            _require(common_build is None or common_build == build_identity,
                     "preparation SourceV5 manifests disagree on their frozen toolchain/build identity")
            _require(common_source is None or common_source == source_identity,
                     "preparation SourceV5 manifests disagree on source revision/tree/lock identity")
            common_build, common_source = build_identity, source_identity
            artifacts = source.get("artifacts")
            _require(type(artifacts) is dict and set(artifacts) == set(ALLOCATORS),
                     f"SourceV5 {host_id} does not pin all four real APP allocator variants")
            paths: set[str] = set()
            binary_hashes: set[str] = set()
            for allocator in ALLOCATORS:
                artifact = _exact(artifacts[allocator], {"path", "sha256"}, f"SourceV5 {host_id} {allocator} artifact")
                _relative_path(artifact["path"], f"SourceV5 {host_id} {allocator} artifact")
                _require(_is_sha(artifact["sha256"]) and artifact["path"] not in paths,
                         f"SourceV5 {host_id} real APP artifacts alias or lack hashes")
                _require(source_pin["artifacts"][allocator] == artifact,
                         f"preparation {host_id} {allocator} APP pin differs from SourceV5")
                paths.add(artifact["path"])
                binary_hashes.add(artifact["sha256"])
            _require(len(binary_hashes) == len(ALLOCATORS),
                     f"SourceV5 {host_id} allocator labels do not identify four distinct APP binaries")
            soak_artifacts = source.get("soak_artifacts")
            _require(type(soak_artifacts) is dict and set(soak_artifacts) == {"allocatbelt"},
                     f"SourceV5 {host_id} must pin the required candidate-only Soak artifact")
        if input_root is not None:
            observed_raw, _observed_sha = _read_preparation_input(input_root, observed_pin, f"{host_id} observed host context", MAX_INPUT_FILE_BYTES)
            observed = _preparation_json(observed_raw, f"{host_id} observed host context")
            _validate_observed_host_structure(observed, host, host_id)
            observed_host_values[host_id] = observed

    if source_manifest_values is not None:
        soak_hashes = {
            source.get("qualification_harness", {}).get("soak_runner", {}).get("sha256")
            for source in source_manifest_values.values()
        }
        policies = {source.get("feedback_policy", {}).get("policy_sha256") for source in source_manifest_values.values()}
        fixed_policies = {source.get("fixed_runtime_policy", {}).get("policy_sha256") for source in source_manifest_values.values()}
        _require(len(policies) == len(fixed_policies) == 1 and
                 core["runtime_binding"]["feedback_policy_sha256"] in policies and
                 core["runtime_binding"]["resource_policy_sha256"] in fixed_policies,
                 "preparation runtime policy pins differ from the common SourceV5 artifacts")
        _require(len(soak_hashes) == 1 and core["soak"]["driver_sha256"] in soak_hashes,
                 "preparation candidate Soak driver pin differs from SourceV5")

    normalized_templates, normalized_conditions = _validate_preparation_templates(
        body["capacity_templates"], body["condition_intensities"], host_ids, core["cells"], input_root,
        core["campaign_id"], source_pins,
        observed_host_values if input_root is not None else None,
    )
    deferred = _exact(body["deferred"], {"pressure_calibrations", "rates", "oracles"}, "preparation deferred inputs")
    _require(deferred == {
        "pressure_calibrations": "awaiting_measured_context_calibration",
        "rates": "awaiting_complete_three_host_six_pair_capacity_pilots",
        "oracles": "awaiting_complete_frozen_rate_matrix",
    }, "preparation deferred-input declaration changed")
    eligibility = _exact(body["eligibility"], {
        "capacity_evidence_complete", "pressure_calibration_complete", "rates_frozen",
        "oracles_frozen", "confirmation_ready", "qualification_eligible",
    }, "preparation eligibility")
    _require(all(value is False for value in eligibility.values()), "preparation intent cannot assert completion or qualification eligibility")
    return {
        "preparation_sha256": body["preparation_sha256"],
        "campaign_id": core["campaign_id"], "host_ids": host_ids,
        "capacity_template_count": len(normalized_templates),
        "condition_intensity_count": len(normalized_conditions),
        "source_pins_checked": source_manifest_values is not None,
        "raw_inputs_checked": input_root is not None,
        "capacity_evidence_complete": False, "pressure_calibration_complete": False,
        "rates_frozen": False, "oracles_frozen": False,
        "confirmation_ready": False, "qualification_eligible": False,
    }


PREPARATION_RESOURCE_CEILING_FIELDS = {
    "maximum_job_output_bytes", "maximum_job_output_inodes",
    "maximum_generation_bytes", "maximum_generation_inodes",
    "maximum_tmpdir_bytes", "maximum_tmpdir_inodes",
    "maximum_trace_file_bytes", "durable_receipt_reserve_bytes",
    "durable_receipt_reserve_inodes", "minimum_free_bytes",
    "minimum_free_inodes", "monitor_sample_interval_milliseconds",
    "process_deadline_seconds",
}


def _preparation_budget_uint(value: Any, label: str, *, zero_allowed: bool = False) -> int:
    minimum = 0 if zero_allowed else 1
    _require(type(value) is int and minimum <= value <= U64_MAX,
             f"{label} must be a finite {'nonnegative' if zero_allowed else 'positive'} u64")
    return value


def build_preparation_resource_budget(
    preparation: dict[str, Any], preparation_pin: dict[str, Any],
    host_id: str, ceilings: dict[str, Any],
) -> dict[str, Any]:
    """Build a separate caller-valued budget document for one original host."""
    _require(type(preparation) is dict and preparation.get("schema") == SOURCE5_PREPARATION_SCHEMA,
             "resource budget requires the original Source5 preparation intent")
    _require(preparation.get("preparation_sha256") == _digest_object(preparation, "preparation_sha256"),
             "resource budget preparation semantic digest is invalid")
    prep_pin = _exact(preparation_pin, {"path", "raw_sha256", "semantic_sha256"},
                      "resource budget preparation pin")
    _require(type(prep_pin["path"]) is str and Path(prep_pin["path"]).is_absolute() and
             _is_sha(prep_pin["raw_sha256"]) and
             prep_pin["semantic_sha256"] == preparation.get("preparation_sha256"),
             "resource budget preparation pin does not bind the original intent")
    host_id = _token(host_id, "resource budget host ID")
    _require(host_id in preparation.get("source_pins", {}),
             "resource budget host is outside the original preparation cohort")
    ceiling_values = _exact(ceilings, PREPARATION_RESOURCE_CEILING_FIELDS,
                            "caller-frozen preparation resource ceilings")
    for key, value in ceiling_values.items():
        _preparation_budget_uint(value, f"resource ceiling {key}")
    body = {
        "schema": SOURCE5_PREPARATION_RESOURCE_BUDGET_SCHEMA,
        "campaign_id": preparation["core"]["campaign_id"],
        "host_id": host_id,
        "preparation": {
            "path": prep_pin["path"], "raw_sha256": prep_pin["raw_sha256"],
            "semantic_sha256": prep_pin["semantic_sha256"],
        },
        "source_manifest": dict(preparation["source_pins"][host_id]["manifest"]),
        "capacity_preparation_templates_sha256": _sha256(_canonical(preparation["capacity_templates"])),
        "ceilings": ceiling_values,
    }
    budget = {**body, "resource_budget_sha256": _sha256(_canonical(body))}
    validate_preparation_resource_budget(budget, preparation, prep_pin)
    return budget


def validate_preparation_resource_budget(
    value: Any, preparation: dict[str, Any], preparation_pin: dict[str, Any],
) -> dict[str, Any]:
    """Replay the separate raw budget contract against immutable v1 intent pins."""
    body = _exact(value, {
        "schema", "campaign_id", "host_id", "preparation", "source_manifest",
        "capacity_preparation_templates_sha256", "ceilings", "resource_budget_sha256",
    }, "Source5 preparation resource budget")
    _require(body["schema"] == SOURCE5_PREPARATION_RESOURCE_BUDGET_SCHEMA and
             _is_sha(body["resource_budget_sha256"]) and
             body["resource_budget_sha256"] == _digest_object(body, "resource_budget_sha256"),
             "preparation resource budget schema or semantic digest is invalid")
    _require(type(preparation) is dict and preparation.get("schema") == SOURCE5_PREPARATION_SCHEMA,
             "resource budget replay requires the original v1 preparation intent")
    _require(preparation.get("preparation_sha256") == _digest_object(preparation, "preparation_sha256"),
             "resource budget replay preparation semantic digest is invalid")
    prep_pin = _exact(preparation_pin, {"path", "raw_sha256", "semantic_sha256"},
                      "resource budget preparation pin")
    _require(type(prep_pin["path"]) is str and Path(prep_pin["path"]).is_absolute() and
             _is_sha(prep_pin["raw_sha256"]) and
             prep_pin["semantic_sha256"] == preparation.get("preparation_sha256"),
             "resource budget preparation pin is malformed or names another generation")
    host_id = _token(body["host_id"], "resource budget host ID")
    _require(host_id in preparation.get("source_pins", {}) and
             body["campaign_id"] == preparation["core"]["campaign_id"],
             "resource budget campaign/host differs from the original preparation cohort")
    expected_preparation = {
        "path": prep_pin["path"], "raw_sha256": prep_pin["raw_sha256"],
        "semantic_sha256": prep_pin["semantic_sha256"],
    }
    source_manifest = _exact(body["source_manifest"], {
        "relative_path", "raw_sha256", "semantic_sha256", "source_tree_sha256",
    }, "resource budget SourceV5 manifest pin")
    _require(source_manifest == preparation["source_pins"][host_id]["manifest"],
             "resource budget SourceV5 manifest differs from the original intent")
    schedule_sha = _sha256(_canonical(preparation["capacity_templates"]))
    _require(body["preparation"] == expected_preparation and
             body["capacity_preparation_templates_sha256"] == schedule_sha,
             "resource budget raw preparation pin or original schedule digest differs")
    ceilings = _exact(body["ceilings"], PREPARATION_RESOURCE_CEILING_FIELDS,
                      "preparation resource ceilings")
    for key, ceiling in ceilings.items():
        _preparation_budget_uint(ceiling, f"resource ceiling {key}")
    _require(ceilings["maximum_job_output_bytes"] <= ceilings["maximum_generation_bytes"] and
             ceilings["maximum_job_output_inodes"] <= ceilings["maximum_generation_inodes"] and
             ceilings["maximum_trace_file_bytes"] <= ceilings["maximum_job_output_bytes"] and
             ceilings["durable_receipt_reserve_bytes"] <= ceilings["maximum_generation_bytes"] and
             ceilings["durable_receipt_reserve_inodes"] <= ceilings["maximum_generation_inodes"],
             "preparation resource ceilings cannot fit their job, generation, or receipt bounds")
    _require(ceilings["minimum_free_bytes"] + ceilings["maximum_generation_bytes"] +
             ceilings["maximum_tmpdir_bytes"] <= U64_MAX and
             ceilings["minimum_free_inodes"] + ceilings["maximum_generation_inodes"] +
             ceilings["maximum_tmpdir_inodes"] <= U64_MAX,
             "preparation free-space reserves overflow finite u64 accounting")
    original_deadline = _preparation_budget_uint(
        preparation["core"]["deadlines"]["process_seconds"],
        "original preparation process deadline",
    )
    _require(ceilings["process_deadline_seconds"] <= original_deadline and
             ceilings["monitor_sample_interval_milliseconds"] <=
                 ceilings["process_deadline_seconds"] * 1000,
             "preparation budget process/sample interval would relax or outlast the original deadline")
    return {
        "campaign_id": body["campaign_id"], "host_id": host_id,
        "preparation_raw_sha256": prep_pin["raw_sha256"],
        "preparation_semantic_sha256": prep_pin["semantic_sha256"],
        "source_manifest": source_manifest,
        "capacity_preparation_templates_sha256": schedule_sha,
        "ceilings": ceilings,
        "resource_budget_sha256": body["resource_budget_sha256"],
        "qualification_eligible": False,
    }


def _validate_observed_host_structure(value: Any, host: dict[str, Any], host_id: str) -> None:
    observed = _exact(value, {
        "schema", "host_id", "boot_id_sha256", "controls_sha256", "controls",
        "kernel_release", "cpu_model", "cpu_affinity", "network_namespace_inode",
    }, f"{host_id} observed host context")
    _require(observed["schema"] == "allocatbelt.application-capacity-host-context.v1" and observed["host_id"] == host_id,
             f"{host_id} observed host context schema/identity differs")
    _require(_is_sha(observed["boot_id_sha256"]) and observed["controls"] == host["controls"] and
             observed["controls_sha256"] == host["host_fingerprint_sha256"] and
             observed["kernel_release"] == host["controls"]["kernel_release"] and
             observed["cpu_model"] == host["controls"]["cpu_model"],
             f"{host_id} observed host context does not match its frozen controls")
    cpus = observed["cpu_affinity"]
    _require(type(cpus) is list and bool(cpus) and all(type(cpu) is int and 0 <= cpu <= 65_535 for cpu in cpus) and cpus == sorted(set(cpus)),
             f"{host_id} observed inherited CPU affinity is malformed")
    _require(type(observed["network_namespace_inode"]) is int and observed["network_namespace_inode"] > 0,
             f"{host_id} observed network namespace inode is malformed")


def build_preparation_intent(
    core: dict[str, Any],
    source_pins: dict[str, Any],
    observed_hosts: dict[str, Any],
    capacity_templates: list[dict[str, Any]],
    condition_intensities: list[dict[str, Any]],
    output: Path,
    *,
    source_manifest_values: dict[str, dict[str, Any]] | None = None,
    input_root: Path | None = None,
) -> dict[str, Any]:
    """Create an immutable prospective intent; no evidence or rates are implied."""
    if "schema" not in core:
        core_schema = (SOURCE5_PREPARATION_CORE_SCHEMA_V2
                       if core.get("capacity_floor_policy_id") is not None
                       else SOURCE5_PREPARATION_CORE_SCHEMA)
        core_value = {"schema": core_schema, **core}
    else:
        core_value = core
    host_ids = [host["host_id"] for host in core_value["hosts"]]
    _exact(source_pins, set(host_ids), "preparation source pins")
    bound_templates: list[dict[str, Any]] = []
    for index, template_value in enumerate(capacity_templates):
        template = _exact(template_value, {
            "host_id", "workload", "profile", "calibration_id", "calibrator",
            "request_template", "context_template",
        }, f"preparation capacity template request[{index}]")
        source_pin = source_pins[template["host_id"]]
        identity = {
            "campaign_id": core_value["campaign_id"], "host_id": template["host_id"],
            "workload": template["workload"], "profile": template["profile"],
            "calibration_id": template["calibration_id"], "template_index": index,
            "request_template": template["request_template"], "context_template": template["context_template"],
            "calibrator": template["calibrator"],
            "source_manifest_sha256": source_pin["manifest"]["semantic_sha256"],
            "source_sha256": source_pin["manifest"]["source_tree_sha256"],
            "binary_sha256": source_pin["artifacts"][template["calibrator"]["allocator"]]["sha256"],
        }
        identity_sha = _sha256(_canonical(identity))
        run_id = "prep-cap-" + identity_sha[:32]
        nonce = _sha256(b"allocatbelt.application-source5-capacity-nonce.v1\0" + _canonical({
            "identity_sha256": identity_sha, "run_id": run_id,
        }))[:32]
        bound = {
            **template, "template_index": index, "run_id": run_id,
            "prospective_nonce": nonce,
            "template_sha256": "0" * 64,
            "source_manifest_sha256": identity["source_manifest_sha256"],
            "source_sha256": identity["source_sha256"],
            "binary_sha256": identity["binary_sha256"],
        }
        bound["template_sha256"] = _sha256(_canonical({key: value for key, value in bound.items() if key != "template_sha256"}))
        bound_templates.append(bound)

    body: dict[str, Any] = {
        "schema": SOURCE5_PREPARATION_SCHEMA,
        "core": core_value,
        "source_pins": source_pins,
        "observed_hosts": observed_hosts,
        "capacity_templates": bound_templates,
        "condition_intensities": condition_intensities,
        "deferred": {
            "pressure_calibrations": "awaiting_measured_context_calibration",
            "rates": "awaiting_complete_three_host_six_pair_capacity_pilots",
            "oracles": "awaiting_complete_frozen_rate_matrix",
        },
        "eligibility": {
            "capacity_evidence_complete": False, "pressure_calibration_complete": False,
            "rates_frozen": False, "oracles_frozen": False,
            "confirmation_ready": False, "qualification_eligible": False,
        },
    }
    value = {**body, "preparation_sha256": _sha256(_canonical(body))}
    validate_preparation_intent(value, source_manifest_values, input_root)
    path = Path(output)
    _require(path.is_absolute(), "preparation intent output path must be absolute")
    _require(path.parent.is_dir() and not path.parent.is_symlink(), "preparation intent output parent must be a real existing directory")
    parent_info = path.parent.stat(follow_symlinks=False)
    _require(stat.S_ISDIR(parent_info.st_mode) and stat.S_IMODE(parent_info.st_mode) == 0o700 and parent_info.st_uid == os.getuid(),
             "preparation intent output parent must be owned mode 0700")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError as error:
        raise InputError(f"cannot create new preparation intent: {error}") from error
    raw = _canonical(value)
    try:
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            _require(count > 0, "preparation intent write stopped before completion")
            offset += count
        os.fsync(fd)
    finally:
        os.close(fd)
    _require(_sha256(_read_regular(path, "written preparation intent", MAX_PREPARATION_BYTES)[0]) == _sha256(raw),
             "written preparation intent differs from its canonical bytes")
    return {"path": str(path), "raw_sha256": _sha256(raw), "semantic_sha256": value["preparation_sha256"],
            "campaign_id": body["core"]["campaign_id"], "host_ids": host_ids,
            "eligibility": value["eligibility"]}


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
            capacity_floor_policy_id = spec.get("capacity_floor_policy_id")
            source_floor_policy: dict[str, Any] | None = None
            if capacity_floor_policy_id is not None:
                selected_artifact = _validate_selected_floor_source_manifest(
                    source, capacity_floor_policy_id, host_id,
                )
                _require(selected_artifact == feedback_artifact,
                         f"selected floor policy artifact differs for {host_id}")
                source_floor_policy = policy_body["capacity_floor_policy"]
            capacity = capacity_by_key[(host_id, workload, profile)]
            pressure = pressure_by_key[(host_id, workload, profile)]
            for allocator in ALLOCATORS:
                binary_sha = source["artifacts"][allocator]["sha256"]
                for executor in EXECUTORS:
                    executor_name = "allocatbelt" if executor == "bounded" else "tokio-1.53.1"
                    for comparison_family in ("fixed_policy", "external_pressure"):
                        policy_context = {
                            "version": policy_body["version"],
                            "reader_contract": policy_body["reader_contract"],
                            "algorithm": policy_body["algorithm"],
                            "context": feedback_context,
                            "source_pins": policy_body["source_pins"],
                        }
                        if comparison_family == "external_pressure" and capacity_floor_policy_id is not None:
                            policy_context["capacity_floor_policy"] = source_floor_policy
                            policy_context["capacity_floor_policy_id"] = capacity_floor_policy_id
                        context_policy_sha = _sha256(_canonical(policy_context))
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
        policy_keys = {"version", "reader_contract", "algorithm", "context", "source_pins"}
        if type(item["policy"]) is dict and "capacity_floor_policy_id" in item["policy"]:
            policy_keys.update({"capacity_floor_policy_id", "capacity_floor_policy"})
        policy = _exact(item["policy"], policy_keys, f"feedback process template[{index}] policy")
        selected_floor_policy_id = policy.get("capacity_floor_policy_id")
        _require(selected_floor_policy_id is None or selected_floor_policy_id == CAPACITY_FLOOR_POLICY_ID,
                 f"feedback process template[{index}] capacity floor policy ID is unknown")
        _require(identity["comparison_family"] == "external_pressure" or selected_floor_policy_id is None,
                 f"feedback process template[{index}] fixed-policy phase cannot select a pressure-only capacity floor")
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
        if selected_floor_policy_id is not None:
            descriptor = _exact(policy["capacity_floor_policy"], {
                "capacity_divisor", "minimum_floor_bytes_per_second", "policy_id", "probe_activation",
                "rule", "rule_version", "runtime_activation", "static_floor_bytes_per_second",
                "static_rate_roof_bytes_per_second",
            }, f"feedback process template[{index}] capacity floor policy")
            _require(all(type(descriptor[field]) is int and descriptor[field] > 0 for field in (
                         "capacity_divisor", "minimum_floor_bytes_per_second",
                         "static_floor_bytes_per_second", "static_rate_roof_bytes_per_second")),
                     f"feedback process template[{index}] capacity-floor numeric values are malformed")
            _require(descriptor["policy_id"] == selected_floor_policy_id and
                     descriptor["policy_id"] == CAPACITY_FLOOR_POLICY_ID and
                     descriptor["rule_version"] == "application-feedback-capacity-resolution-v2" and
                     descriptor["rule"] == "max_one_min_static_floor_capacity_div_ten" and
                     descriptor["probe_activation"] == "explicit_policy_id_and_capacity_artifact" and
                     descriptor["runtime_activation"] == "explicit_pressure_qualification_and_policy_id_and_capacity_artifact" and
                     descriptor["capacity_divisor"] == 10 and
                     descriptor["minimum_floor_bytes_per_second"] == 1 and
                     descriptor["static_floor_bytes_per_second"] == 64 * 1024 * 1024 and
                     descriptor["static_rate_roof_bytes_per_second"] == 16 * 1024**3,
                     f"feedback process template[{index}] selected capacity floor source rule is invalid")
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
