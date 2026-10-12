#!/usr/bin/env python3
"""Build and validate the fixed application runtime readback contract.

An expectation is built from the controller's frozen run recipe and an
independently audited build-specific Control baseline. Receipt values never
contribute to expectation construction. This schema validates fixed-policy
receipts; external-pressure receipts require a separate implemented contract.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

SCHEMA = "allocatbelt.application-runtime-binding.v1"
RECIPE_SCHEMA = "allocatbelt.application-runtime-recipe.v1"
EXPECTATION_SCHEMA = "allocatbelt.application-runtime-expectation.v2"
MAX_ARTIFACT_BYTES = 128 * 1024
MAX_RECEIPT_BYTES = MAX_ARTIFACT_BYTES
MAX_FIELDS = 1024
U64_MAX = (1 << 64) - 1

DIMENSIONS = ("cpu", "memory", "disk", "network", "tasks", "control")
APP_DIMENSIONS = ("cpu", "memory", "disk", "network", "tasks")
STAGES = ("setup", "after_drain", "after_shutdown")
OWNERS = ("global", "tenant")
DIRECTIONS = ("disk", "upload", "download")

ALLOCATORS = ("allocatbelt", "mimalloc-secure", "mimalloc-standard", "system")
EXECUTORS = ("allocatbelt", "tokio-1.53.1")
WORKLOADS = ("cpu", "memory", "http", "disk", "mixed")
PROFILES = ("steady", "mixed", "burst", "oversubscribed", "safety_overload")
MODES = ("capacity", "open_loop")

RATE_BYTES_PER_SECOND = 17_179_869_184
RATE_BURST_BYTES = 65_536
RATE_MAX_RESERVATIONS = 64
APPLICATION_TASK_CEILING = 64
DOMAIN_CONTROL_CEILING = 67_108_864
LOGICAL_WINDOW = 8
CAPACITY_HORIZON_NS = 30_000_000_000
CAPACITY_ARRIVALS = 5_000
MAX_OPEN_LOOP_ARRIVALS = 1_000_000
MAX_OPEN_LOOP_RATE = 1_000_000_000
MAX_BURST_RATE = 250_000_000

HASH_ECHO_BINDING = (
    "controller_must_independently_verify_source_binary_TSV_and_receipt_hashes"
)


class ReadbackError(ValueError):
    """A malformed recipe, expectation, or runtime receipt."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReadbackError(message)


def canonical_bytes(value: object) -> bytes:
    """Match application-campaign canonical JSON, including its final LF."""
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ReadbackError(f"value is not canonical JSON: {error}") from error
    return (encoded + "\n").encode("ascii")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReadbackError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ReadbackError(f"non-finite JSON number is forbidden: {value}")


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_ARTIFACT_BYTES + 1)
    except OSError as error:
        raise ReadbackError(f"cannot read {label}: {error}") from error
    require(len(raw) <= MAX_ARTIFACT_BYTES, f"{label} exceeds its finite size bound")
    try:
        text = raw.decode("utf-8")
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ReadbackError(f"{label} is not valid UTF-8 JSON: {error}") from error
    require(type(value) is dict, f"{label} must contain a JSON object")
    return value


def _exact_keys(value: object, keys: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict, f"{label} must be an object")
    require(set(value) == keys, f"{label} keys differ from the versioned contract")
    return value


def _string(value: object, label: str) -> str:
    require(type(value) is str, f"{label} must be a string")
    return value


def _unsigned(value: object, label: str, *, positive: bool = False) -> int:
    require(type(value) is int, f"{label} must be an integer, not a boolean or other JSON type")
    require(0 <= value <= U64_MAX, f"{label} is outside the u64 range")
    if positive:
        require(value > 0, f"{label} must be positive")
    return value


def _digest(value: object, label: str, length: int = 64) -> str:
    result = _string(value, label)
    require(re.fullmatch(rf"[a-f0-9]{{{length}}}", result) is not None, f"{label} is malformed")
    return result


def _workload_limits(workload: str) -> tuple[int, int, int]:
    if workload == "cpu":
        return (0, 0, 0)
    if workload == "memory":
        return (163_840, 0, 0)
    if workload == "http":
        return (141_312, 0, 16)
    if workload == "disk":
        return (1_573_000, 8, 0)
    if workload == "mixed":
        return (1_638_536, 8, 16)
    raise ReadbackError(f"unsupported workload: {workload}")


def _validate_recipe(recipe_value: object) -> tuple[dict[str, Any], dict[str, Any], int]:
    recipe = _exact_keys(
        recipe_value,
        {"schema", "identity", "run", "fixed_global_control_baseline"},
        "fixed runtime recipe",
    )
    require(recipe["schema"] == RECIPE_SCHEMA, "unknown fixed runtime recipe schema")

    identity = _exact_keys(
        recipe["identity"],
        {
            "report_nonce",
            "run_id",
            "allocator",
            "executor",
            "source_sha256",
            "binary_sha256",
            "comparison_family",
            "resource_ceiling_sha256",
            "policy_sha256",
        },
        "scheduled controller identity",
    )
    _digest(identity["report_nonce"], "report_nonce", 32)
    run_id = _string(identity["run_id"], "run_id")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", run_id) is not None, "run_id is malformed")
    require(identity["allocator"] in ALLOCATORS, "scheduled allocator label is unknown")
    require(identity["executor"] in EXECUTORS, "scheduled executor label is unknown")
    comparison_family = _string(identity["comparison_family"], "comparison_family")
    if comparison_family == "external_pressure":
        raise ReadbackError(
            "external-pressure runtime readback is unsupported; this validator supports fixed-policy receipts only"
        )
    require(comparison_family == "fixed_policy", "unknown runtime comparison family")
    for name in ("source_sha256", "binary_sha256", "resource_ceiling_sha256", "policy_sha256"):
        _digest(identity[name], name)

    run = _exact_keys(
        recipe["run"],
        {"workload", "profile", "mode", "rate_per_second", "arrivals"},
        "scheduled application run",
    )
    workload = _string(run["workload"], "workload")
    profile = _string(run["profile"], "profile")
    mode = _string(run["mode"], "mode")
    require(workload in WORKLOADS, "scheduled workload label is unknown")
    require(profile in PROFILES, "scheduled profile label is unknown")
    require(mode in MODES, "scheduled mode label is unknown")
    arrivals = _unsigned(run["arrivals"], "arrivals", positive=True)
    rate = run["rate_per_second"]

    if profile == "mixed":
        require(workload == "mixed", "mixed profile requires the mixed workload")
    if workload == "mixed":
        require(
            profile in ("mixed", "burst", "oversubscribed", "safety_overload"),
            "mixed workload requires a compatible profile",
        )
    if mode == "capacity":
        require(rate is None, "capacity mode must not carry an open-loop rate")
        require(arrivals == CAPACITY_ARRIVALS, "capacity mode must use the frozen arrival count")
        require(profile != "safety_overload", "safety_overload is not a capacity profile")
        normalized_rate = None
    else:
        normalized_rate = _unsigned(rate, "rate_per_second", positive=True)
        require(normalized_rate <= MAX_OPEN_LOOP_RATE, "open-loop rate exceeds the application bound")
        require(arrivals <= MAX_OPEN_LOOP_ARRIVALS, "open-loop arrivals exceed the application bound")
        if profile == "burst":
            require(normalized_rate <= MAX_BURST_RATE, "burst rate exceeds the application bound")

    baseline = _unsigned(
        recipe["fixed_global_control_baseline"], "fixed_global_control_baseline", positive=True
    )
    require(
        baseline < DOMAIN_CONTROL_CEILING,
        "audited global Control baseline must be below the frozen domain ceiling",
    )

    normalized_identity = {key: identity[key] for key in sorted(identity)}
    normalized_run = {
        "workload": workload,
        "profile": profile,
        "mode": mode,
        "rate_per_second": normalized_rate,
        "arrivals": arrivals,
    }
    return normalized_identity, normalized_run, baseline


def build_fixed_expectation(recipe: dict[str, Any]) -> dict[str, Any]:
    """Build the complete v2 expectation from controller-owned recipe input."""
    identity, run, baseline = _validate_recipe(recipe)
    workload = run["workload"]
    profile = run["profile"]
    mode = run["mode"]
    configured_rate = run["rate_per_second"]
    arrivals = run["arrivals"]
    rate = 1 if mode == "capacity" else configured_rate
    memory_limit, disk_limit, network_limit = _workload_limits(workload)
    workers = 2 if profile == "oversubscribed" else 4
    ceilings = {
        "cpu": workers,
        "memory": memory_limit,
        "disk": disk_limit,
        "network": network_limit,
        "tasks": APPLICATION_TASK_CEILING,
        "control": DOMAIN_CONTROL_CEILING,
    }
    scope_limits = {
        "managed_memory_limit": memory_limit,
        "disk_operation_limit": disk_limit,
        "network_operation_limit": network_limit,
    }
    if mode == "capacity":
        trace_duration_ns = CAPACITY_HORIZON_NS
        pulse_rate = 0
    elif profile == "burst":
        trace_duration_ns = ((arrivals + rate - 1) // rate) * 1_000_000_000
        pulse_rate = rate * 4
    else:
        trace_duration_ns = (arrivals * 1_000_000_000) // rate
        pulse_rate = rate
    require(trace_duration_ns <= U64_MAX, "frozen trace duration overflows u64")

    identity_rows = {
        **identity,
        "profile": profile,
        "workload": workload,
        "hashes_are_echoed_bindings_not_self_proof": HASH_ECHO_BINDING,
    }
    configuration = {
        "mode": mode,
        "rate_per_second": str(configured_rate if configured_rate is not None else 0),
        "arrivals": str(arrivals),
        "async_workers": str(workers),
        "logical_window": str(LOGICAL_WINDOW),
        "trace_duration_ns": str(trace_duration_ns),
        "pulse_rate_per_second": str(pulse_rate),
        "task_ceiling": str(APPLICATION_TASK_CEILING),
        "resource_policy": "fixed_primary_v1",
        "feedback_enabled": "false",
        "network_direction": "upload_and_download",
        "domain_ceiling": {name: str(value) for name, value in ceilings.items()},
        "managed_memory_limit_bytes": str(memory_limit),
        "disk_operation_limit": str(disk_limit),
        "network_operation_limit": str(network_limit),
        "fixed_global_control_baseline": str(baseline),
        "blocking_disk_adapter_constructed": str(
            identity["executor"] == "tokio-1.53.1" and disk_limit != 0
        ).lower(),
    }
    accounting = {
        "cpu": (
            "owning_scheduler_domain_cpu_tickets"
            if identity["executor"] == "allocatbelt"
            else "cpu_gate_per_tokio_future_poll_and_blocking_io"
        ),
        "tasks": (
            "owning_scheduler_tasks_plus_explicit_root_roles"
            if identity["executor"] == "allocatbelt"
            else "explicit_tokio_task_leases_plus_root_roles"
        ),
        "managed_payload": "ResourceScope_and_tenant_domain",
        "disk_operations": "ResourceScope_disk_permits",
        "disk_bytes": (
            "owning_FsRate_per_syscall"
            if identity["executor"] == "allocatbelt"
            else "shared_BlockingByteIo_per_syscall_inside_spawn_blocking"
        ),
        "network_operations": "ResourceScope_network_permits",
        "network_bytes": "IoBindings_directional_byte_buckets",
        "opaque_runtime_allocations": "excluded_from_managed_payload_and_measured_by_RSS",
        "receipt_writer_storage": "bounded_metadata_outside_application_ResourceScope",
    }
    kernel = {
        "cpu_rounds": "50000",
        "memory_initial_bytes": "4096",
        "memory_grown_bytes": "8192",
        "memory_seed": str(0x243F6A8885A308D3),
        "disk_bytes": "196625",
        "disk_offset": "4096",
        "disk_seed": str(0xA4093822299F31D0),
        "http_body_bytes": "4096",
        "mixed_interleave": "cpu,memory,http,disk",
    }
    byte_buckets = {
        direction: {
            "bytes_per_second": RATE_BYTES_PER_SECOND,
            "ceiling_bytes_per_second": RATE_BYTES_PER_SECOND,
            "burst_bytes": RATE_BURST_BYTES,
            "ceiling_burst_bytes": RATE_BURST_BYTES,
            "max_reservations": RATE_MAX_RESERVATIONS,
        }
        for direction in DIRECTIONS
    }
    contract = {
        "identity": identity_rows,
        "configuration": configuration,
        "accounting": accounting,
        "kernel": kernel,
        "ceilings": ceilings,
        "scope_limits": scope_limits,
        "byte_buckets": byte_buckets,
        "fixed_global_control_baseline": baseline,
    }
    return {
        "schema": EXPECTATION_SCHEMA,
        "recipe": {
            "schema": RECIPE_SCHEMA,
            "identity": identity,
            "run": run,
            "fixed_global_control_baseline": baseline,
        },
        "contract": contract,
    }


def read_receipt(path: Path) -> dict[str, str]:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_RECEIPT_BYTES + 1)
    except OSError as error:
        raise ReadbackError(f"cannot read runtime receipt: {error}") from error
    require(len(raw) <= MAX_RECEIPT_BYTES, "runtime receipt exceeds its finite size bound")
    try:
        text = raw.decode("utf-8")
    except UnicodeError as error:
        raise ReadbackError("runtime receipt is not UTF-8") from error
    require(text.endswith("\n") and "\r" not in text, "runtime receipt framing is incomplete")
    lines = text.splitlines()
    require(lines and lines[0] == f"schema\t{SCHEMA}", "unknown runtime receipt schema")
    require(0 < len(lines) - 1 <= MAX_FIELDS, "runtime receipt field count is invalid")
    fields: dict[str, str] = {}
    for line in lines[1:]:
        parts = line.split("\t")
        require(len(parts) == 2, "runtime receipt field is not a key/value pair")
        key, value = parts
        require(re.fullmatch(r"[a-z][a-z0-9_.]*", key) is not None, "runtime field name is malformed")
        require(key not in fields, f"duplicate runtime field: {key}")
        require(value and all(ord(char) >= 32 and ord(char) != 127 for char in value), f"unframed runtime value: {key}")
        fields[key] = value
    require(list(fields) == sorted(fields), "runtime receipt fields are not canonical")
    return fields


def _flatten(prefix: str, value: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, child in value.items():
        path = f"{prefix}.{key}"
        if type(child) is dict:
            result.update(_flatten(path, child))
        else:
            require(type(child) is str, f"built expectation field is not a string: {path}")
            result[path] = child
    return result


def _expectation_rows(expected: dict[str, Any]) -> dict[str, str]:
    contract = expected["contract"]
    rows = {f"identity.{key}": value for key, value in contract["identity"].items()}
    for section in ("configuration", "accounting", "kernel"):
        rows.update(_flatten(section, contract[section]))
    return rows


def integer(fields: dict[str, str], key: str) -> int:
    value = fields.get(key)
    require(
        type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", value) is not None,
        f"missing or invalid integer: {key}",
    )
    result = int(value)
    require(result <= U64_MAX, f"runtime integer overflows u64: {key}")
    return result


def validate_runtime_readback(fields: dict[str, str], expected: dict[str, Any]) -> dict[str, Any]:
    """Validate every emitted binding and runtime snapshot against v2 recipe."""
    require(type(fields) is dict, "runtime receipt fields must be an object")
    require(
        all(type(key) is str and type(value) is str for key, value in fields.items()),
        "runtime receipt fields must contain only string keys and values",
    )
    require(type(expected) is dict, "runtime expectation must be an object")
    require(
        set(expected) == {"schema", "recipe", "contract"},
        "runtime expectation keys differ from the versioned contract",
    )
    require(expected.get("schema") == EXPECTATION_SCHEMA, "unknown frozen runtime expectation schema")
    try:
        rebuilt = build_fixed_expectation(expected.get("recipe"))
        require(
            canonical_bytes(rebuilt) == canonical_bytes(expected),
            "runtime expectation differs from the independent fixed recipe builder",
        )
    except (TypeError, ValueError) as error:
        if isinstance(error, ReadbackError):
            raise
        raise ReadbackError(f"runtime expectation is not canonical: {error}") from error

    contract = expected["contract"]
    if fields.get("identity.comparison_family") == "external_pressure":
        raise ReadbackError(
            "external-pressure runtime readback is unsupported; this validator supports fixed-policy receipts only"
        )
    expected_rows = _expectation_rows(expected)
    expected_keys = set(expected_rows)
    for key, value in expected_rows.items():
        require(fields.get(key) == value, f"runtime binding differs from the frozen recipe: {key}")

    ceilings = contract["ceilings"]
    scope_limits = contract["scope_limits"]
    baseline = contract["fixed_global_control_baseline"]
    for stage in STAGES:
        for owner in OWNERS:
            prefix = f"{stage}.{owner}."
            for dimension in DIMENSIONS:
                ceiling_key = prefix + "ceiling." + dimension
                limit_key = prefix + "limit." + dimension
                used_key = prefix + "used." + dimension
                expected_keys.update((ceiling_key, limit_key, used_key))
                ceiling = integer(fields, ceiling_key)
                limit = integer(fields, limit_key)
                used = integer(fields, used_key)
                bound = ceilings[dimension]
                require(ceiling == bound, f"actual hard ceiling mismatch: {ceiling_key}")
                require(limit == bound, f"fixed policy changed its resource limit: {limit_key}")
                require(used <= limit, f"resource use exceeds its configured limit: {used_key}")
                if stage != "setup" and dimension in APP_DIMENSIONS:
                    require(used == 0, f"application charge remains after drain: {used_key}")
            tenants_key = prefix + "live_tenants"
            expected_keys.add(tenants_key)
            require(integer(fields, tenants_key) == 1, f"runtime did not retain exactly one expected tenant: {tenants_key}")

        global_control = integer(fields, f"{stage}.global.used.control")
        require(global_control >= baseline, f"global Control lost its fixed metadata baseline: {stage}")
        if stage == "after_shutdown":
            tenant_control = integer(fields, f"{stage}.tenant.used.control")
            require(
                global_control >= baseline + tenant_control,
                "joined global Control does not cover its baseline and tenant metadata",
            )

        for name, bound in scope_limits.items():
            key = f"{stage}.scope.{name}"
            expected_keys.add(key)
            require(integer(fields, key) == bound, f"scope limit mismatch: {key}")
        for dimension, limit_name in (
            ("managed_memory", "managed_memory_limit"),
            ("disk_operations", "disk_operation_limit"),
            ("network_operations", "network_operation_limit"),
        ):
            key = f"{stage}.scope.{dimension}_used"
            expected_keys.add(key)
            used = integer(fields, key)
            require(used <= scope_limits[limit_name], f"scope exceeds its limit: {key}")
            if stage != "setup":
                require(used == 0, f"scope charge remains after drain: {key}")

        for direction in DIRECTIONS:
            bucket = contract["byte_buckets"][direction]
            prefix = f"{stage}.io.{direction}_"
            rate_key = prefix + "bytes_per_second"
            rate_ceiling_key = prefix + "ceiling_bytes_per_second"
            burst_key = prefix + "burst_bytes"
            burst_ceiling_key = prefix + "ceiling_burst_bytes"
            available_key = prefix + "available_bytes"
            reserved_key = prefix + "reserved_bytes"
            reservations_key = prefix + "reservations"
            max_reservations_key = prefix + "max_reservations"
            expected_keys.update(
                (
                    rate_key,
                    rate_ceiling_key,
                    burst_key,
                    burst_ceiling_key,
                    available_key,
                    reserved_key,
                    reservations_key,
                    max_reservations_key,
                )
            )
            rate = integer(fields, rate_key)
            require(rate == bucket["bytes_per_second"], f"fixed byte rate changed: {direction}")
            require(
                integer(fields, rate_ceiling_key) == bucket["ceiling_bytes_per_second"],
                f"byte-rate ceiling changed: {direction}",
            )
            burst = integer(fields, burst_key)
            require(burst == bucket["burst_bytes"], f"byte burst changed: {direction}")
            require(
                integer(fields, burst_ceiling_key) == bucket["ceiling_burst_bytes"],
                f"byte-burst ceiling changed: {direction}",
            )
            available = integer(fields, available_key)
            reserved = integer(fields, reserved_key)
            reservations = integer(fields, reservations_key)
            max_reservations = integer(fields, max_reservations_key)
            require(available <= burst and reserved <= burst, f"byte credits exceed capacity: {direction}")
            require(available + reserved <= burst, f"byte credit conservation failed: {direction}")
            require(
                max_reservations == bucket["max_reservations"],
                f"reservation capacity changed: {direction}",
            )
            require(reservations <= max_reservations, f"byte reservation table exceeded: {direction}")
            if stage != "setup":
                require(reserved == 0 and reservations == 0, f"byte offers remain after drain: {direction}")

    setup_global_control = integer(fields, "configuration.setup_global_control")
    setup_global_used_control = integer(fields, "setup.global.used.control")
    setup_tenant_used_control = integer(fields, "setup.tenant.used.control")
    expected_keys.add("configuration.setup_global_control")
    require(
        setup_global_control == setup_global_used_control,
        "configured setup global Control does not match the actual global snapshot",
    )
    require(
        baseline <= setup_global_control <= baseline + ceilings["control"],
        "setup global Control is outside the independently bounded baseline",
    )
    require(
        setup_global_control - baseline >= setup_tenant_used_control,
        "setup global Control does not cover tenant Control use above the baseline",
    )

    final_fields = {
        "after_release.global.live_tenants": "0",
        "after_release.global.used.control": str(baseline),
        "after_release.expected_global_control_baseline": str(baseline),
        "after_release.control_matches_fixed_baseline": "true",
    }
    for key, value in final_fields.items():
        expected_keys.add(key)
        require(fields.get(key) == value, f"final owner cleanup mismatch: {key}")
    require(
        set(fields) == expected_keys,
        f"runtime receipt has missing or unexpected fields: {sorted(set(fields) ^ expected_keys)}",
    )
    digest = hashlib.sha256(canonical_bytes(expected)).hexdigest()
    return {
        "schema": EXPECTATION_SCHEMA,
        "validated": True,
        "expectation_sha256": digest,
        "field_count": len(fields),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--expected", type=Path)
    parser.add_argument("--build-expectation", type=Path, metavar="RECIPE")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if args.build_expectation is not None:
            require(args.receipt is None and args.expected is None, "expectation building cannot validate a receipt")
            require(args.output is not None, "--output is required when building an expectation")
            recipe = _read_json_object(args.build_expectation, "runtime recipe")
            expected = build_fixed_expectation(recipe)
            output = canonical_bytes(expected)
            require(len(output) <= MAX_ARTIFACT_BYTES, "built expectation exceeds its finite size bound")
            args.output.write_bytes(output)
            result = {
                "schema": EXPECTATION_SCHEMA,
                "expectation_sha256": hashlib.sha256(output).hexdigest(),
            }
        else:
            require(args.receipt is not None and args.expected is not None, "validation requires --receipt and --expected")
            require(args.output is None, "--output is only valid when building an expectation")
            fields = read_receipt(args.receipt)
            expected = _read_json_object(args.expected, "runtime expectation")
            result = validate_runtime_readback(fields, expected)
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, TypeError, KeyError) as error:
        parser.exit(1, f"runtime readback refused: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
