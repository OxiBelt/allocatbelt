#!/usr/bin/env python3
"""Build and verify the additive pre-Spec SourceV5 preparation generation.

The preparation intent freezes campaign parameters and real source/input pins
before a SpecV3 or PlanV3 exists.  It never manufactures capacity, pressure,
rate, oracle, or qualification evidence.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import hashlib
import json
import os
import stat
import sys
import types
from pathlib import Path
from typing import Any


SOURCE_ROOT = Path(__file__).resolve().parent.parent
SOURCE_MANIFEST_SCHEMA_V5 = "allocatbelt.application-source-manifest.v5"
SOURCE_INVENTORY_SCHEMA = "allocatbelt.application-source-inventory.v1"
SOURCE_INVENTORY_SHA256 = "09557087a64e83bc81e4116f8e8f6b59e42a59beb500108e57d66942bd05f950"
REQUEST_SCHEMA = "allocatbelt.application-source5-preparation-request.v1"
PREPARATION_SCHEMA = "allocatbelt.application-source5-preparation.v1"
CAPACITY_BUNDLE_PIN_SCHEMA = "allocatbelt.application-pressure-capacity-bundle-pin.v2"
PILOT_SCHEMA = "allocatbelt.application-capacity-pilot.v1"
FIXED_PAIR_OVERLAY_SCHEMA = "allocatbelt.application-fixed-pair-execution-overlay.v1"
PREPARED_FIXED_HOST_BINDING_SCHEMA = "allocatbelt.application-source5-fixed-pair-host-binding.v1"
PREPARED_COMPLETION_SCHEMA = "allocatbelt.application-source5-preparation-completion.v1"
PREPARED_BOUNDED_COMPLETION_SCHEMA = "allocatbelt.application-source5-preparation-completion.v2"
PRESSURE_SCOPE_RECEIPT_SCHEMA = "allocatbelt.application-pressure-calibration-scope-readback.v2"
PRESSURE_SCOPE_RECEIPT_KEYS = {
    "schema", "replay_success", "validated", "execution_ready", "qualification_eligible",
    "controller_chronology_proven", "calibration_raw_sha256", "calibration_sha256",
    "scope_sha256", "condition_id", "pressure_calibration_id", "capacity_key",
    "condition_sha256", "source_manifest_sha256",
    "source_manifest_semantic_sha256", "source_tree_sha256", "context_policy_bundle_raw_sha256",
    "context_policy_artifact_raw_sha256", "context_policy_sha256", "capacity_bundle_pins_sha256",
    "capacity_tsv_raw_sha256", "observed_host_raw_sha256", "host_verification", "driver_sha256", "reader_sha256",
    "capacity_producer_sha256", "feedback_composer_sha256", "feedback_reader_sha256",
    "sample_count", "samples_sha256", "summary", "pressure_thresholds", "readiness_thresholds",
    "suggested_readiness_thresholds", "worker_cleanup_sha256", "worker_session_count",
    "scratch_file_removed", "receipt_sha256",
}
MAX_REQUEST_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_PLAN_BYTES = 256 * 1024 * 1024
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_U64 = (1 << 64) - 1


class PreparationError(ValueError):
    """A Source5 preparation input or replay failed its frozen contract."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PreparationError(message)


def _canonical(value: Any) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    except (TypeError, ValueError) as error:
        raise PreparationError(f"value is not canonical JSON: {error}") from error


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == keys, f"{label} has an unexpected field set")
    return value


def _read_stable(path: Path, label: str, maximum: int) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        before_path = path.lstat()
        _require(stat.S_ISREG(before_path.st_mode), f"{label} must be a regular nonsymlink file")
        fd = os.open(path, flags)
    except OSError as error:
        raise PreparationError(f"cannot safely open {label}: {error}") from error
    try:
        before = os.fstat(fd)
        key = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        _require(stat.S_ISREG(before.st_mode) and key(before) == key(before_path) and 0 <= before.st_size <= maximum,
                 f"{label} changed while opening or exceeds its bound")
        chunks: list[bytes] = []
        count = 0
        while count < before.st_size:
            block = os.read(fd, min(1024 * 1024, before.st_size - count))
            _require(bool(block), f"{label} was truncated during its stable read")
            chunks.append(block)
            count += len(block)
        after_fd = os.fstat(fd)
        after_path = path.lstat()
        _require(key(before) == key(after_fd) == key(after_path) and count == before.st_size,
                 f"{label} changed during its stable read")
        return b"".join(chunks), after_fd
    finally:
        os.close(fd)


def _read_json(path: Path, label: str, maximum: int, expected_sha256: str | None = None) -> tuple[dict[str, Any], bytes, str]:
    raw, _info = _read_stable(path, label, maximum)
    actual = _sha256(raw)
    _require(expected_sha256 is None or actual == expected_sha256, f"{label} differs from its caller-pinned raw SHA-256")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise PreparationError(f"{label} is not bounded UTF-8 JSON: {error}") from error
    _require(type(value) is dict and _canonical(value) == raw, f"{label} is not canonical JSON")
    return value, raw, actual


def _safe_root(path: Path, label: str) -> Path:
    try:
        before = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise PreparationError(f"{label} is unavailable: {error}") from error
    _require(stat.S_ISDIR(before.st_mode) and resolved == path, f"{label} must be a real nonsymlink directory")
    return resolved


def _safe_child(root: Path, relative: str, label: str) -> Path:
    _require(type(relative) is str and relative and "\\" not in relative and "\x00" not in relative,
             f"{label} relative path is malformed")
    rel = Path(relative)
    _require(not rel.is_absolute() and ".." not in rel.parts and rel != Path(".") and rel.as_posix() == relative,
             f"{label} path must be normalized and relative")
    cursor = root
    for part in rel.parts:
        cursor = cursor / part
        try:
            info = cursor.lstat()
        except OSError as error:
            raise PreparationError(f"{label} is missing: {error}") from error
        _require(not stat.S_ISLNK(info.st_mode), f"{label} traverses a symlink")
    try:
        resolved = cursor.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise PreparationError(f"{label} is missing or escaped its root") from error
    return resolved


def _execute_captured_module(raw: bytes, path: Path, name: str) -> types.ModuleType:
    """Compile exactly the bytes already checked against a typed inventory."""
    module_name = f"allocatbelt_source5_{name}_{_sha256(raw)}_{id(raw):x}"
    module = types.ModuleType(module_name)
    module.__file__ = str(path)
    module.__package__ = ""
    sys.modules[module_name] = module
    try:
        code = compile(raw, str(path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except BaseException as error:
        sys.modules.pop(module_name, None)
        raise PreparationError(f"captured {name} bytes cannot be compiled/executed: {type(error).__name__}: {error}") from error
    return module


def _capture_typed_source_file(
    source: dict[str, Any], source_root: Path, relative: str, label: str,
    expected_sha256: str | None = None,
) -> tuple[bytes, Path, dict[str, Any]]:
    inventory = source.get("source", {}).get("files")
    _require(type(inventory) is list, "SourceV5 typed inventory is missing")
    matches = [item for item in inventory if type(item) is dict and item.get("path") == relative]
    _require(len(matches) == 1, f"SourceV5 inventory must contain one regular {label} entry")
    entry = _exact(matches[0], {"path", "kind", "mode", "sha256", "size"}, f"SourceV5 {label} inventory entry")
    _require(entry["kind"] == "file" and entry["mode"] in ("100644", "100755") and
             type(entry["size"]) is int and 0 <= entry["size"] <= MAX_SOURCE_BYTES and
             type(entry["sha256"]) is str and len(entry["sha256"]) == 64,
             f"SourceV5 {label} is not a bounded regular typed file")
    _require(expected_sha256 is None or entry["sha256"] == expected_sha256,
             f"SourceV5 {label} differs from its separately pinned module SHA-256")
    path = _safe_child(source_root, relative, f"SourceV5 {label}")
    raw, info = _read_stable(path, f"SourceV5 {label}", MAX_SOURCE_BYTES)
    actual_mode = f"{stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode):06o}"
    _require(len(raw) == entry["size"] and _sha256(raw) == entry["sha256"] and actual_mode == entry["mode"],
             f"SourceV5 {label} bytes, size, or mode differ from its verified inventory entry")
    return raw, path, entry


def _load_source5_stack(
    sources: dict[str, dict[str, Any]], source_root: Path,
    expected_module_pins: dict[str, dict[str, dict[str, str]]] | None = None,
) -> tuple[types.ModuleType, types.ModuleType, types.ModuleType, dict[str, dict[str, tuple[bytes, Path, dict[str, Any]]]]]:
    """Capture the inventory, inputs and controller before executing any of them."""
    _require(type(sources) is dict and len(sources) == 3, "SourceV5 stack requires all three source manifests")
    critical_paths = {
        "source_inventory": "scripts/application-source-inventory.py",
        "campaign_inputs": "scripts/application-campaign-inputs.py",
        "campaign_controller": "scripts/application-campaign.py",
    }
    captured_by_host: dict[str, dict[str, tuple[bytes, Path, dict[str, Any]]]] = {}
    for host_id, source in sources.items():
        _require(type(source) is dict and source.get("schema") == SOURCE_MANIFEST_SCHEMA_V5,
                 f"{host_id} is not a SourceV5 manifest")
        source_sha = source.get("manifest_sha256")
        source_body = {key: value for key, value in source.items() if key != "manifest_sha256"}
        _require(type(source_sha) is str and _sha256(_canonical(source_body)) == source_sha,
                 f"{host_id} SourceV5 semantic manifest digest is invalid before module loading")
        captured: dict[str, tuple[bytes, Path, dict[str, Any]]] = {}
        for role, relative in critical_paths.items():
            expected = None
            if expected_module_pins is not None and role != "source_inventory":
                prep_role = "campaign_inputs" if role == "campaign_inputs" else "campaign_controller"
                expected_record = expected_module_pins[host_id][prep_role]
                expected = _exact(expected_record, {"path", "sha256"}, f"{host_id} {prep_role} intent pin")["sha256"]
            captured[role] = _capture_typed_source_file(source, source_root, relative, role, expected)
        _require(captured["source_inventory"][2]["sha256"] == SOURCE_INVENTORY_SHA256,
                 "SourceV5 source-inventory verifier differs from its frozen controller pin")
        captured_by_host[host_id] = captured

    reference_host = next(iter(sources))
    reference = captured_by_host[reference_host]
    for host_id, captured in captured_by_host.items():
        _require({role: (entry[2]["sha256"], entry[2]["size"], entry[2]["mode"])
                  for role, entry in captured.items()} ==
                 {role: (entry[2]["sha256"], entry[2]["size"], entry[2]["mode"])
                  for role, entry in reference.items()},
                 f"SourceV5 executable roots differ across the cohort at {host_id}")

    inventory_raw, inventory_path, inventory_entry = reference["source_inventory"]
    inventory_module = _execute_captured_module(inventory_raw, inventory_path, "source_inventory")
    _require(getattr(inventory_module, "SCHEMA", None) == SOURCE_INVENTORY_SCHEMA and
             callable(getattr(inventory_module, "validate_records", None)) and
             callable(getattr(inventory_module, "digest_records", None)),
             "captured SourceV5 inventory verifier has an unsupported contract")
    for host_id, source in sources.items():
        try:
            validated = inventory_module.validate_records({
                "schema": SOURCE_INVENTORY_SCHEMA, "entries": source["source"]["files"],
            })
            tree_sha = inventory_module.digest_records(source["source"]["files"])
        except Exception as error:
            raise PreparationError(f"captured SourceV5 inventory verifier rejected {host_id}: {error}") from error
        _require(validated == source["source"]["files"] and
                 tree_sha == source["source"]["source_tree_sha256"],
                 f"{host_id} SourceV5 inventory/tree identity failed before controller execution")

    inputs_raw, inputs_path, inputs_entry = reference["campaign_inputs"]
    inputs = _execute_captured_module(inputs_raw, inputs_path, "campaign_inputs")
    _require(getattr(inputs, "SOURCE_V5_SCHEMA", None) == SOURCE_MANIFEST_SCHEMA_V5 and
             callable(getattr(inputs, "validate_preparation_intent", None)),
             "captured SourceV5 campaign-inputs module has an unsupported contract")
    controller_raw, controller_path, _controller_entry = reference["campaign_controller"]
    campaign = _execute_captured_module(controller_raw, controller_path, "campaign_controller")
    _require(getattr(campaign, "SOURCE_SCHEMA_V5", None) == SOURCE_MANIFEST_SCHEMA_V5 and
             getattr(campaign, "SOURCE_INVENTORY_MODULE_SHA256", None) == SOURCE_INVENTORY_SHA256 and
             callable(getattr(campaign, "verify_source_manifest", None)),
             "captured SourceV5 campaign controller has an unsupported contract")

    def pinned_inventory_module(expected_sha256: str | None = None) -> types.ModuleType:
        _require(expected_sha256 in (None, inventory_entry["sha256"]),
                 "campaign requested an inventory module outside the captured bytes")
        return inventory_module

    def pinned_campaign_inputs_module(expected_sha256: str | None = None) -> types.ModuleType:
        _require(expected_sha256 in (None, inputs_entry["sha256"]),
                 "campaign requested an inputs module outside the captured bytes")
        return inputs

    campaign.source_inventory_module = pinned_inventory_module
    campaign.campaign_inputs_module = pinned_campaign_inputs_module
    try:
        for host_id, source in sources.items():
            campaign.verify_source_manifest(
                source, source_root=source_root, verify_artifacts=True,
            )
    except Exception as error:
        raise PreparationError(f"captured SourceV5 full manifest verifier rejected the cohort: {error}") from error
    if expected_module_pins is not None:
        for host_id, source in sources.items():
            modules = expected_module_pins[host_id]
            _require(modules["campaign_controller"] == {
                "path": critical_paths["campaign_controller"], "sha256": reference["campaign_controller"][2]["sha256"],
            } and modules["campaign_inputs"] == {
                "path": critical_paths["campaign_inputs"], "sha256": reference["campaign_inputs"][2]["sha256"],
            }, f"{host_id} preparation module pins differ from the verified captured bytes")
    return campaign, inputs, inventory_module, captured_by_host


def _verify_frozen_core_resource_limits(
    campaign: Any, core: dict[str, Any], sources: dict[str, dict[str, Any]],
) -> None:
    validator_pins = {source["runtime_readback_validator"]["sha256"] for source in sources.values()}
    _require(len(validator_pins) == 1, "SourceV5 cohort does not share one fixed runtime validator")
    validator_sha = next(iter(validator_pins))
    for index, cell in enumerate(core["cells"]):
        try:
            expected = campaign.fixed_resource_limits_for_cell(cell["workload"], cell["profile"], validator_sha)
        except Exception as error:
            raise PreparationError(f"cannot derive original resource limits for core cell[{index}]: {error}") from error
        _require(_canonical(expected) == _canonical(cell["resource_limits"]),
                 f"preparation core cell[{index}] changed its fixed runtime resource limits")
        _require(_sha256(_canonical(expected)) == cell["resource_ceiling_sha256"],
                 f"preparation core cell[{index}] resource ceiling digest differs from the runtime recipe")


def _source_inputs(
    request: dict[str, Any], source_root: Path, input_root: Path,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any], dict[str, Any], types.ModuleType, types.ModuleType]:
    request = _exact(request, {
        "schema", "core", "source_manifests", "observed_hosts", "capacity_templates", "condition_intensities",
    }, "preparation request")
    _require(request["schema"] == REQUEST_SCHEMA, "unsupported Source5 preparation request schema")
    hosts = request["core"].get("hosts") if type(request["core"]) is dict else None
    _require(type(hosts) is list and len(hosts) == 3, "preparation request must pin the complete three-host core")
    host_ids = [host.get("host_id") for host in hosts if type(host) is dict]
    _require(len(host_ids) == 3 and len(set(host_ids)) == 3, "preparation request has missing or duplicate host IDs")
    manifest_pins = _exact(request["source_manifests"], set(host_ids), "preparation SourceV5 manifest pins")
    observed_pins = _exact(request["observed_hosts"], set(host_ids), "preparation observed-host pins")

    source_values: dict[str, dict[str, Any]] = {}
    source_raw_shas: dict[str, str] = {}
    source_pins: dict[str, dict[str, Any]] = {}
    for host_id in host_ids:
        pin = _exact(manifest_pins[host_id], {"relative_path", "raw_sha256"}, f"{host_id} SourceV5 manifest pin")
        manifest_path = _safe_child(input_root, pin["relative_path"], f"{host_id} SourceV5 manifest")
        source, raw, actual = _read_json(manifest_path, f"{host_id} SourceV5 manifest", MAX_MANIFEST_BYTES, pin["raw_sha256"])
        _require(source.get("schema") == SOURCE_MANIFEST_SCHEMA_V5, f"{host_id} source is not a SourceV5 manifest")
        source_values[host_id] = source
        _require(_sha256(raw) == actual, f"{host_id} source manifest changed during preparation preflight")
        source_raw_shas[host_id] = actual

    campaign, inputs, _inventory, _critical_modules = _load_source5_stack(source_values, source_root)
    for host_id in host_ids:
        source = source_values[host_id]
        modules: dict[str, dict[str, str]] = {}
        for role, relative in inputs.PREPARATION_MODULE_PATHS.items():
            raw, path, entry = _capture_typed_source_file(source, source_root, relative, role)
            modules[role] = {"path": relative, "sha256": entry["sha256"]}
            if role == "preparation_helper":
                active_raw, active_info = _read_stable(Path(__file__).resolve(strict=True),
                                                       "active Source5 preparation helper", MAX_SOURCE_BYTES)
                active_mode = f"{stat.S_IFMT(active_info.st_mode) | stat.S_IMODE(active_info.st_mode):06o}"
                _require(active_raw == raw and active_mode == entry["mode"],
                         "active Source5 preparation helper differs from its typed SourceV5 bytes")
            del path
        pin = _exact(manifest_pins[host_id], {"relative_path", "raw_sha256"}, f"{host_id} SourceV5 manifest pin")
        source_pins[host_id] = {
            "manifest": {
                "relative_path": pin["relative_path"], "raw_sha256": source_raw_shas[host_id],
                "semantic_sha256": source["manifest_sha256"],
                "source_tree_sha256": source["source"]["source_tree_sha256"],
            },
            "modules": modules,
            "artifacts": source["artifacts"],
        }
        _require(source_raw_shas[host_id] == pin["raw_sha256"], f"{host_id} SourceV5 manifest raw digest changed during preparation preflight")

    observed_values: dict[str, dict[str, str]] = {}
    for host in hosts:
        host_id = host["host_id"]
        pin = _exact(observed_pins[host_id], {"relative_path", "raw_sha256"}, f"{host_id} observed-host pin")
        observed_path = _safe_child(input_root, pin["relative_path"], f"{host_id} observed host context")
        _observed, _raw, actual = _read_json(observed_path, f"{host_id} observed host context", MAX_MANIFEST_BYTES, pin["raw_sha256"])
        observed_values[host_id] = {"relative_path": pin["relative_path"], "raw_sha256": actual}

    for host in hosts:
        host_id = host["host_id"]
        observed_pin = observed_pins[host_id]
        observed_path = _safe_child(input_root, observed_pin["relative_path"], f"{host_id} observed host context")
        observed, _raw, _actual = _read_json(observed_path, f"{host_id} observed host context", MAX_MANIFEST_BYTES, observed_pin["raw_sha256"])
        try:
            inputs._validate_observed_host_structure(observed, host, host_id)
        except inputs.InputError as error:
            raise PreparationError(f"{host_id} observed host context failed frozen controls validation: {error}") from error

    _verify_frozen_core_resource_limits(campaign, request["core"], source_values)

    return source_values, source_pins, observed_values, campaign, inputs


def build_preparation_intent(
    request_pin: dict[str, Any], source_root: Path, input_root: Path, output: Path,
) -> dict[str, Any]:
    """Verify genuine SourceV5 inputs and write one prospective preparation intent."""
    source_root = _safe_root(source_root, "SourceV5 root")
    input_root = _safe_root(input_root, "preparation input root")
    _require(source_root != input_root, "SourceV5 and preparation inputs must be separate roots")
    request_ref = _exact(request_pin, {"path", "sha256"}, "preparation request raw pin")
    request_path = Path(request_ref["path"])
    _require(request_path.is_absolute(), "preparation request path must be absolute")
    request, _request_raw, request_sha = _read_json(request_path, "Source5 preparation request", MAX_REQUEST_BYTES, request_ref["sha256"])
    source_values, source_pins, observed_hosts, _campaign, inputs = _source_inputs(request, source_root, input_root)
    output = Path(output)
    _require(output.is_absolute() and output.parent.resolve(strict=True) == input_root and
             not _within(source_root, output),
             "preparation intent must be a new file directly inside the private input root and outside SourceV5")
    try:
        return inputs.build_preparation_intent(
            request["core"], source_pins, observed_hosts, request["capacity_templates"],
            request["condition_intensities"], output,
            source_manifest_values=source_values, input_root=input_root,
        )
    except Exception as error:
        if isinstance(error, PreparationError):
            raise
        raise PreparationError(f"Source5 preparation intent validation/build failed: {error}") from error


def read_preparation_intent(
    preparation_pin: dict[str, Any], source_root: Path, input_root: Path,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """Load and recheck intent, all three SourceV5 manifests and host records."""
    source_root = _safe_root(source_root, "SourceV5 root")
    input_root = _safe_root(input_root, "preparation input root")
    pin = _exact(preparation_pin, {"path", "sha256"}, "preparation raw pin")
    path = Path(pin["path"])
    _require(path.is_absolute(), "preparation intent path must be absolute")
    value, _raw, actual = _read_json(path, "Source5 preparation intent", MAX_REQUEST_BYTES, pin["sha256"])
    source_values: dict[str, dict[str, Any]] = {}
    source_module_pins = value.get("source_pins")
    core_value = value.get("core")
    host_records = core_value.get("hosts") if type(core_value) is dict else None
    _require(type(source_module_pins) is dict and type(host_records) is list,
             "preparation source pins or core host list is malformed")
    host_ids = {item.get("host_id") for item in host_records if type(item) is dict}
    _require(len(host_ids) == 3 and set(source_module_pins) == host_ids,
             "preparation source pins do not cover exactly the frozen three-host cohort")
    expected_module_pins: dict[str, dict[str, Any]] = {}
    for host_id, source_pin in value["source_pins"].items():
        _exact(source_pin, {"manifest", "modules", "artifacts"}, f"{host_id} preparation source record")
        module_pins = _exact(source_pin["modules"], set({
            "source5_controller", "campaign_controller", "campaign_chronology", "campaign_inputs",
            "capacity_stage", "fixed_pair", "feedback_composer", "preparation_helper", "pressure_driver",
            "pressure_pair", "pressure_readback", "soak_recipe_builder", "soak_readback", "soak_runner",
            "capacity_producer", "feedback_readback",
        }), f"{host_id} preparation module pins")
        expected_module_pins[host_id] = module_pins
        manifest_pin = source_pin["manifest"]
        _exact(manifest_pin, {"relative_path", "raw_sha256", "semantic_sha256", "source_tree_sha256"},
               f"{host_id} preparation manifest pin")
        manifest_path = _safe_child(input_root, manifest_pin["relative_path"], f"{host_id} SourceV5 manifest")
        source, manifest_raw, manifest_raw_sha = _read_json(
            manifest_path, f"{host_id} SourceV5 manifest", MAX_MANIFEST_BYTES, manifest_pin["raw_sha256"],
        )
        _require(manifest_raw_sha == manifest_pin["raw_sha256"] and
                 source.get("manifest_sha256") == manifest_pin["semantic_sha256"] and
                 source.get("source", {}).get("source_tree_sha256") == manifest_pin["source_tree_sha256"],
                 f"{host_id} SourceV5 raw/semantic/tree preparation roles differ")
        _require(manifest_raw == _canonical(source), f"{host_id} SourceV5 manifest is not canonical")
        source_values[host_id] = source
    campaign, inputs, _inventory, _critical_modules = _load_source5_stack(
        source_values, source_root, expected_module_pins,
    )
    for host_id, source in source_values.items():
        for role, relative in inputs.PREPARATION_MODULE_PATHS.items():
            raw, _module_path, entry = _capture_typed_source_file(source, source_root, relative, role)
            expected = _exact(expected_module_pins[host_id][role], {"path", "sha256"},
                              f"{host_id} preparation {role} pin")
            _require(expected == {"path": relative, "sha256": entry["sha256"]},
                     f"{host_id} preparation {role} differs from the captured typed bytes")
            if role == "preparation_helper":
                active_raw, active_info = _read_stable(Path(__file__).resolve(strict=True),
                                                       "active Source5 preparation helper", MAX_SOURCE_BYTES)
                active_mode = f"{stat.S_IFMT(active_info.st_mode) | stat.S_IMODE(active_info.st_mode):06o}"
                _require(active_raw == raw and active_mode == entry["mode"],
                         "active Source5 preparation helper differs from its typed SourceV5 bytes")
    _verify_frozen_core_resource_limits(campaign, value["core"], source_values)
    try:
        validation = inputs.validate_preparation_intent(value, source_values, input_root)
    except Exception as error:
        raise PreparationError(f"Source5 preparation intent replay failed: {error}") from error
    _require(value["preparation_sha256"] == validation["preparation_sha256"], "preparation semantic digest differs after input replay")
    return value, source_values, campaign, inputs


def capacity_bundle_pin(entry: dict[str, Any], source_manifest_pin: dict[str, Any]) -> dict[str, Any]:
    """Map one verifier-reconstructed prep entry to the pressure V2 exact-bundle pin."""
    key = _exact(entry.get("capacity_key"), {"host_id", "workload", "profile", "calibration_id"}, "verified capacity entry key")
    manifest = _exact(source_manifest_pin, {"path", "raw_sha256"}, "prepared capacity SourceV5 raw pin")
    _require(Path(manifest["path"]).is_absolute() and type(manifest["raw_sha256"]) is str and len(manifest["raw_sha256"]) == 64,
             "prepared capacity SourceV5 pin is malformed")
    result: dict[str, Any] = {
        "schema": CAPACITY_BUNDLE_PIN_SCHEMA,
        "capacity_key": key,
        "source_manifest": dict(manifest),
    }
    for role in ("request", "artifact", "receipt"):
        pin = _exact(entry.get(role), {"path", "sha256"}, f"verified capacity {role} pin")
        _require(Path(pin["path"]).is_absolute() and type(pin["sha256"]) is str and len(pin["sha256"]) == 64,
                 f"verified capacity {role} pin is malformed")
        result[role] = {"path": pin["path"], "raw_sha256": pin["sha256"]}
    return result


def _read_pinned_json(
    pin_value: dict[str, Any], label: str, maximum: int = MAX_REQUEST_BYTES,
) -> tuple[dict[str, Any], bytes, str]:
    pin = _exact(pin_value, {"path", "sha256"}, f"{label} raw pin")
    path = Path(pin["path"])
    _require(path.is_absolute(), f"{label} path must be absolute")
    raw, _info = _read_stable(path, label, maximum)
    actual = _sha256(raw)
    _require(actual == pin["sha256"], f"{label} differs from its caller-pinned raw SHA-256")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise PreparationError(f"{label} is not bounded UTF-8 JSON: {error}") from error
    _require(type(value) is dict and _canonical(value) == raw, f"{label} is not canonical JSON")
    return value, raw, actual


def _verify_spec_source_refs(
    spec: dict[str, Any], preparation: dict[str, Any], sources: dict[str, dict[str, Any]],
) -> None:
    refs = spec.get("source_manifests")
    _require(type(refs) is list and len(refs) == 3, "SpecV3 source-manifest refs are incomplete")
    observed: dict[str, tuple[str, str]] = {}
    for index, value in enumerate(refs):
        ref = _exact(value, {"host_id", "relative_path", "sha256"}, f"SpecV3 source-manifest ref[{index}]")
        host_id = ref["host_id"]
        _require(host_id in sources and host_id not in observed and
                 ref["sha256"] == sources[host_id]["manifest_sha256"],
                 f"SpecV3 source-manifest ref[{index}] is not a pinned cohort manifest")
        observed[host_id] = (ref["relative_path"], ref["sha256"])
    expected = {
        host_id: (item["manifest"]["relative_path"], item["manifest"]["semantic_sha256"])
        for host_id, item in preparation["source_pins"].items()
    }
    _require(observed == expected, "SpecV3 source manifest paths/semantic pins differ from the preparation generation")


def _relative_input_pin(root: Path, absolute_path: str | Path, raw_sha256: str, label: str) -> dict[str, str]:
    path = Path(absolute_path)
    _require(path.is_absolute(), f"{label} path must be absolute")
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError as error:
        raise PreparationError(f"{label} is outside the original input root") from error
    candidate = _safe_child(root, relative, label)
    raw, _info = _read_stable(candidate, label, MAX_REQUEST_BYTES)
    actual = _sha256(raw)
    _require(actual == raw_sha256, f"{label} bytes differ from their original raw pin")
    return {"relative_path": relative, "raw_sha256": actual}


def _row_uint(row: dict[str, Any], field: str, label: str, *, positive: bool = False) -> int:
    value = row.get(field)
    if type(value) is str:
        _require(value.isascii() and value.isdigit() and (value == "0" or not value.startswith("0")),
                 f"{label} row count is not a canonical unsigned integer")
        _require(len(value) <= 20,
                 f"{label} row count exceeds its unsigned 64-bit source bound")
        parsed = int(value)
    else:
        _require(type(value) is int, f"{label} row count is malformed")
        parsed = value
    _require(0 <= parsed <= MAX_U64 and (not positive or parsed > 0),
             f"{label} row count is outside its unsigned 64-bit allowed range")
    return parsed


def capacity_pilot_maximum_bytes(
    spec: dict[str, Any], host_id: str, allocators: Any,
    spec_preregistration_sha256: str,
) -> int:
    """Return the exact canonical bound for one original 15×4×6 pilot file.

    The canonical size template preserves the selected Spec's actual
    family/profile and host strings, the Source-pinned allocator order, the
    original six ordinal values, valid status/hash fields, and maximum-width
    unsigned-counter slots. Rejected counters remain zero because the capacity
    exporter admits only zero-rejection pairs; this template is a byte bound,
    not a synthetic pilot result.
    """
    _require(type(spec) is dict and
             spec.get("schema") == "allocatbelt.application-campaign-spec.v3" and
             spec.get("rates") == [] and spec.get("oracles") == [],
             "capacity pilot byte bound requires the original empty-rate/oracle SpecV3")
    matching_hosts = [host for host in spec.get("hosts", [])
                      if type(host) is dict and host.get("host_id") == host_id]
    _require(type(host_id) is str and len(matching_hosts) == 1,
             "capacity pilot byte bound requires one known original host")
    _require(type(allocators) in (tuple, list) and len(allocators) == 4 and
             all(type(name) is str and name for name in allocators) and
             len(set(allocators)) == 4,
             "capacity pilot byte bound requires the exact four distinct Source allocators")
    _require(type(spec_preregistration_sha256) is str and
             len(spec_preregistration_sha256) == 64 and
             all(character in "0123456789abcdef"
                 for character in spec_preregistration_sha256),
             "capacity pilot byte bound requires the exact preregistration digest")
    cells = spec.get("cells")
    _require(type(cells) is list and len(cells) == 15 and all(
        type(cell) is dict and type(cell.get("family")) is str and
        type(cell.get("profile")) is str and cell["family"] and cell["profile"]
        for cell in cells
    ) and len({(cell["family"], cell["profile"]) for cell in cells}) == 15,
             "capacity pilot byte bound requires the exact fifteen original Spec cells")
    pairs = []
    maximum = MAX_U64
    for ordinal in range(1, 7):
        pairs.append({
            "ordinal": ordinal,
            "bounded_status": "valid", "tokio_status": "valid",
            "raw_pair_sha256": "f" * 64,
            "bounded_on_time": maximum, "bounded_late": maximum,
            "bounded_attempted": maximum, "bounded_admitted": maximum,
            "bounded_rejected": 0,
            "tokio_on_time": maximum, "tokio_late": maximum,
            "tokio_attempted": maximum, "tokio_admitted": maximum,
            "tokio_rejected": 0,
        })
    pilot = {
        "schema": PILOT_SCHEMA,
        "spec_sha256": spec_preregistration_sha256,
        "host_id": host_id,
        "cells": [
            {"family": cell["family"], "profile": cell["profile"],
             "allocator": allocator, "pairs": pairs}
            for cell in cells for allocator in allocators
        ],
    }
    _require(len(pilot["cells"]) == 15 * 4 and
             sum(len(cell["pairs"]) for cell in pilot["cells"]) == 15 * 4 * 6,
             "capacity pilot byte bound changed its original 15×4×6 schedule")
    return len(_canonical(pilot))


def _write_private_json_new(
    path: Path, value: dict[str, Any], source_root: Path, *, allow_existing_identical: bool = False,
) -> str:
    _require(path.is_absolute(), "new artifact path must be absolute")
    parent = path.parent
    name = path.name
    _require(name not in {"", ".", ".."},
             "new artifact path must name one exact child file")
    try:
        parent_info = parent.lstat()
        resolved_parent = parent.resolve(strict=True)
    except OSError as error:
        raise PreparationError(f"new artifact parent is unavailable: {error}") from error
    _require(stat.S_ISDIR(parent_info.st_mode) and resolved_parent == parent and
             stat.S_IMODE(parent_info.st_mode) == 0o700 and parent_info.st_uid == os.getuid(),
             "new artifact parent must be an owned real mode-0700 directory")
    _require(not _within(source_root, path), "new artifact destination must be outside SourceV5")
    raw = _canonical(value)
    checksum = _sha256(raw)
    _require(len(raw) <= MAX_REQUEST_BYTES, "new preparation artifact exceeds its finite size bound")
    directory_fd = -1
    try:
        directory_fd = os.open(
            parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
            getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as error:
        raise PreparationError(f"cannot safely open new artifact parent: {error}") from error
    created_fd = -1
    created_identity: tuple[int, int] | None = None

    def same_named_parent() -> bool:
        try:
            named = parent.lstat()
            resolved = parent.resolve(strict=True)
            check_fd = os.open(
                parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
        except OSError:
            return False
        try:
            checked = os.fstat(check_fd)
            anchored = os.fstat(directory_fd)
            return (stat.S_ISDIR(named.st_mode) and resolved == parent and
                    (named.st_dev, named.st_ino) == (anchored.st_dev, anchored.st_ino) ==
                    (checked.st_dev, checked.st_ino))
        finally:
            os.close(check_fd)

    def read_named_file(maximum: int) -> tuple[bytes, os.stat_result]:
        try:
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            _require(stat.S_ISREG(before.st_mode), "new artifact destination may not be a symlink")
            read_fd = os.open(
                name, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
                getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
                dir_fd=directory_fd,
            )
        except OSError as error:
            raise PreparationError(f"cannot safely open new artifact for readback: {error}") from error
        try:
            opened = os.fstat(read_fd)
            key = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                                info.st_mtime_ns, info.st_ctime_ns)
            _require(stat.S_ISREG(opened.st_mode) and key(opened) == key(before) and
                     0 <= opened.st_size <= maximum,
                     "new artifact changed while opening or exceeds its size bound")
            chunks: list[bytes] = []
            count = 0
            while count < opened.st_size:
                block = os.read(read_fd, min(1024 * 1024, opened.st_size - count))
                _require(bool(block), "new artifact was truncated during its stable readback")
                chunks.append(block)
                count += len(block)
            after_fd = os.fstat(read_fd)
            after_name = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            _require(key(opened) == key(after_fd) == key(after_name) and
                     count == opened.st_size,
                     "new artifact changed during its stable readback")
            return b"".join(chunks), after_fd
        finally:
            os.close(read_fd)

    try:
        anchored_parent = os.fstat(directory_fd)
        _require(stat.S_ISDIR(anchored_parent.st_mode) and
                 (anchored_parent.st_dev, anchored_parent.st_ino) ==
                     (parent_info.st_dev, parent_info.st_ino) and same_named_parent(),
                 "new artifact parent changed while opening its anchored directory")
        try:
            existing = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            _require(allow_existing_identical and stat.S_ISREG(existing.st_mode),
                     "immutable artifact destination already exists or is not regular")
            existing_raw, info = read_named_file(len(raw))
            _require(stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid() and
                     info.st_nlink == 1 and existing_raw == raw and same_named_parent(),
                     "existing immutable artifact differs from the exact replayed bytes or private mode")
            return checksum
        try:
            created_fd = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                0o600, dir_fd=directory_fd,
            )
        except OSError as error:
            raise PreparationError(f"cannot create immutable new artifact: {error}") from error
        created_info = os.fstat(created_fd)
        created_identity = (created_info.st_dev, created_info.st_ino)
        _require(stat.S_ISREG(created_info.st_mode) and created_info.st_uid == os.getuid() and
                 created_info.st_nlink == 1,
                 "new artifact descriptor is not the exact private regular inode")
        os.fchmod(created_fd, 0o600)
        offset = 0
        while offset < len(raw):
            count = os.write(created_fd, raw[offset:])
            _require(count > 0, "new artifact write stopped before completion")
            offset += count
        os.fsync(created_fd)
        written_info = os.fstat(created_fd)
        _require((written_info.st_dev, written_info.st_ino) == created_identity and
                 stat.S_ISREG(written_info.st_mode) and written_info.st_uid == os.getuid() and
                 stat.S_IMODE(written_info.st_mode) == 0o600 and written_info.st_nlink == 1 and
                 written_info.st_size == len(raw) and same_named_parent(),
                 "new artifact or its parent changed before durable publication")
        os.fsync(directory_fd)
        written, readback_info = read_named_file(len(raw))
        _require(written == raw and
                 (readback_info.st_dev, readback_info.st_ino) == created_identity and
                 stat.S_IMODE(readback_info.st_mode) == 0o600 and
                 readback_info.st_uid == os.getuid() and readback_info.st_nlink == 1 and
                 same_named_parent(),
                 "new immutable artifact differs from its canonical bytes or reserved inode")
        os.close(created_fd)
        created_fd = -1
        return checksum
    except BaseException:
        if created_identity is not None:
            try:
                current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == created_identity:
                    os.unlink(name, dir_fd=directory_fd)
                    os.fsync(directory_fd)
            except OSError:
                # Retain safety over cleanup: never unlink a pathname whose
                # inode cannot be proven to be the one this call created.
                pass
        raise
    finally:
        if created_fd >= 0:
            try:
                os.close(created_fd)
            except OSError:
                pass
        try:
            os.close(directory_fd)
        except OSError:
            pass


def _within(root: Path, path: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except ValueError:
        return False


def _validate_prepared_fixed_host_binding(value: Any) -> dict[str, Any]:
    binding = _exact(value, {
        "schema", "host_id", "fixed_spec_host_pin", "prepared_host_context_pin",
        "spec_host_semantic_sha256", "boot_id_sha256", "kernel_release",
        "controls_sha256", "process_affinity", "network_namespace_inode", "binding_sha256",
    }, "Source5/fixed-pair host binding adapter")
    body = {key: item for key, item in binding.items() if key != "binding_sha256"}
    _require(binding["schema"] == PREPARED_FIXED_HOST_BINDING_SCHEMA and
             binding["binding_sha256"] == _sha256(_canonical(body)),
             "Source5/fixed-pair host binding adapter schema or digest is invalid")
    fixed_pin = _exact(binding["fixed_spec_host_pin"], {"path", "raw_sha256"},
                       "fixed SpecV3 host-record pin")
    prepared_pin = _exact(binding["prepared_host_context_pin"], {"path", "raw_sha256"},
                          "prepared capacity-host-context pin")
    digest_values = (
        binding["spec_host_semantic_sha256"], binding["boot_id_sha256"],
        binding["controls_sha256"], fixed_pin["raw_sha256"], prepared_pin["raw_sha256"],
    )
    _require(Path(fixed_pin["path"]).is_absolute() and Path(prepared_pin["path"]).is_absolute() and
             type(binding["host_id"]) is str and binding["host_id"] and
             type(binding["kernel_release"]) is str and binding["kernel_release"] and
             type(binding["process_affinity"]) is list and binding["process_affinity"] and
             type(binding["network_namespace_inode"]) is int and binding["network_namespace_inode"] > 0 and
             all(type(digest) is str and len(digest) == 64 and
                 all(character in "0123456789abcdef" for character in digest)
                 for digest in digest_values) and
             binding["process_affinity"] == sorted(set(
                 cpu for cpu in binding["process_affinity"]
                 if type(cpu) is int and 0 <= cpu <= 65_535
             )),
             "Source5/fixed-pair host binding adapter contains malformed pins or host facts")
    return binding


def _prepared_host_binding_inputs(
    preparation_pin: dict[str, Any], spec_pin: dict[str, Any],
    source_root: Path, input_root: Path, host_id: str,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], Any, Any,
           dict[str, Any], dict[str, str]]:
    """Load the exact resident preparation and empty-rate Spec generation once."""
    source_root = _safe_root(Path(source_root), "SourceV5 root")
    input_root = _safe_root(Path(input_root), "preparation input root")
    _require(not _within(source_root, input_root),
             "preparation input root must remain outside SourceV5")
    preparation, sources, campaign_module, inputs = read_preparation_intent(
        preparation_pin, source_root, input_root,
    )
    spec_pin_value = _exact(spec_pin, {"path", "sha256"},
                            "original SpecV3 raw pin")
    spec, _spec_raw, spec_sha = _read_pinned_json(
        spec_pin_value, "original empty-rate SpecV3",
    )
    _require(spec_sha == spec_pin_value["sha256"] and
             spec.get("schema") == campaign_module.SPEC_SCHEMA_V3 and
             spec.get("rates") == [] and spec.get("oracles") == [],
             "prepared host binding requires the raw-pinned original empty-rate/oracle SpecV3")
    try:
        core = inputs.preparation_core_from_spec(spec)
        _require(core == preparation["core"],
                 "original SpecV3 differs from the frozen preparation core")
    except Exception as error:
        raise PreparationError(
            f"cannot project original SpecV3 onto preparation core: {error}",
        ) from error
    _verify_spec_source_refs(spec, preparation, sources)
    _require(host_id in sources and any(
        type(item) is dict and item.get("host_id") == host_id
        for item in spec.get("hosts", [])
    ), "prepared host binding selected an unknown SpecV3 host")
    return preparation, sources, campaign_module, inputs, spec, spec_pin_value


def _fixed_spec_host_path(input_root: Path, host_id: str) -> Path:
    _require(type(host_id) is str and bool(host_id) and
             host_id not in {".", ".."} and "/" not in host_id and
             "\\" not in host_id and "\x00" not in host_id,
             "fixed Spec host ID is not a safe deterministic child name")
    return input_root / "fixed-spec-hosts" / f"{host_id}.json"


def _directory_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid


def _assert_fixed_spec_host_directory_names(
    input_root: Path, root_fd: int, directory_fd: int,
    root_identity: tuple[int, int, int, int],
    directory_identity: tuple[int, int, int, int],
) -> None:
    """Prove both open directory descriptors still name their expected paths."""
    try:
        root_path_info = input_root.lstat()
        directory_path_info = os.stat(
            "fixed-spec-hosts", dir_fd=root_fd, follow_symlinks=False,
        )
        resolved_root = input_root.resolve(strict=True)
        opened_root_info = os.fstat(root_fd)
        opened_directory_info = os.fstat(directory_fd)
    except OSError as error:
        raise PreparationError(
            f"fixed Spec host parent changed during its anchored operation: {error}",
        ) from error
    _require(
        stat.S_ISDIR(root_path_info.st_mode) and resolved_root == input_root and
        _directory_identity(root_path_info) == root_identity ==
        _directory_identity(opened_root_info),
        "preparation input root changed during its fixed Spec host operation",
    )
    _require(
        stat.S_ISDIR(directory_path_info.st_mode) and
        _directory_identity(directory_path_info) == directory_identity ==
        _directory_identity(opened_directory_info),
        "fixed Spec host directory was replaced during its anchored operation",
    )


@contextlib.contextmanager
def _open_fixed_spec_host_directory(input_root: Path, *, create: bool):
    """Hold no-follow descriptors for the input root and its fixed-host child."""
    input_root = _safe_root(Path(input_root), "preparation input root")
    directory_name = "fixed-spec-hosts"
    directory_path = input_root / directory_name
    directory_flags = (
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
        getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    root_fd = -1
    directory_fd = -1
    created = False
    try:
        try:
            root_fd = os.open(input_root, directory_flags)
        except OSError as error:
            raise PreparationError(
                f"preparation input root cannot be safely opened: {error}",
            ) from error
        root_info = os.fstat(root_fd)
        try:
            root_path_info = input_root.lstat()
            _require(
                stat.S_ISDIR(root_path_info.st_mode) and
                input_root.resolve(strict=True) == input_root and
                _directory_identity(root_info) == _directory_identity(root_path_info),
                "preparation input root changed before fixed Spec host access",
            )
        except OSError as error:
            raise PreparationError(
                f"preparation input root changed before fixed Spec host access: {error}",
            ) from error
        root_identity = _directory_identity(root_info)
        if create:
            try:
                os.mkdir(directory_name, 0o700, dir_fd=root_fd)
                created = True
                os.fsync(root_fd)
            except FileExistsError:
                pass
            except OSError as error:
                raise PreparationError(
                    f"cannot create fixed Spec host directory: {error}",
                ) from error
        try:
            directory_fd = os.open(directory_name, directory_flags, dir_fd=root_fd)
        except FileNotFoundError as error:
            raise PreparationError("fixed Spec host directory is missing") from error
        except OSError as error:
            raise PreparationError(
                f"fixed Spec host directory is not a real nonsymlink directory: {error}",
            ) from error
        directory_info = os.fstat(directory_fd)
        _require(
            stat.S_ISDIR(directory_info.st_mode) and
            directory_info.st_uid == os.getuid(),
            "fixed Spec host directory must be owned mode-0700 storage",
        )
        if created and stat.S_IMODE(directory_info.st_mode) != 0o700:
            os.fchmod(directory_fd, 0o700)
            os.fsync(directory_fd)
            directory_info = os.fstat(directory_fd)
        _require(
            stat.S_IMODE(directory_info.st_mode) == 0o700,
            "fixed Spec host directory must be owned mode-0700 storage",
        )
        directory_identity = _directory_identity(directory_info)
        _assert_fixed_spec_host_directory_names(
            input_root, root_fd, directory_fd, root_identity, directory_identity,
        )
        yield (root_fd, directory_fd, root_identity, directory_identity,
               directory_path)
    finally:
        if directory_fd >= 0:
            os.close(directory_fd)
        if root_fd >= 0:
            os.close(root_fd)


def _read_fixed_spec_host_at(
    input_root: Path, root_fd: int, directory_fd: int,
    root_identity: tuple[int, int, int, int],
    directory_identity: tuple[int, int, int, int], name: str,
) -> tuple[dict[str, Any], bytes, str, os.stat_result]:
    """Read the deterministic JSON file relative to the held directory fd."""
    _assert_fixed_spec_host_directory_names(
        input_root, root_fd, directory_fd, root_identity, directory_identity,
    )
    try:
        named_before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        _require(stat.S_ISREG(named_before.st_mode),
                 "fixed Spec host record must be a regular nonsymlink file")
        fd = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
            getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory_fd,
        )
    except FileNotFoundError as error:
        raise PreparationError(f"fixed Spec host record is missing: {error}") from error
    except OSError as error:
        raise PreparationError(f"cannot safely open fixed Spec host record: {error}") from error
    try:
        before = os.fstat(fd)
        identity = lambda value: (
            value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns, value.st_nlink, value.st_uid,
        )
        _require(
            stat.S_ISREG(before.st_mode) and identity(before) == identity(named_before) and
            0 <= before.st_size <= MAX_MANIFEST_BYTES,
            "fixed Spec host record changed while opening or exceeds its bound",
        )
        chunks: list[bytes] = []
        count = 0
        while count < before.st_size:
            block = os.read(fd, min(1024 * 1024, before.st_size - count))
            _require(bool(block), "fixed Spec host record was truncated during its stable read")
            chunks.append(block)
            count += len(block)
        raw = b"".join(chunks)
        after = os.fstat(fd)
        named_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        _require(
            len(raw) == before.st_size and identity(before) == identity(after) and
            identity(after) == identity(named_after),
            "fixed Spec host record changed during its stable read",
        )
    finally:
        os.close(fd)
    _assert_fixed_spec_host_directory_names(
        input_root, root_fd, directory_fd, root_identity, directory_identity,
    )
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise PreparationError(f"fixed Spec host record is not bounded UTF-8 JSON: {error}") from error
    _require(type(value) is dict and _canonical(value) == raw,
             "fixed Spec host record is not canonical JSON")
    return value, raw, _sha256(raw), after


def _write_fixed_spec_host_at(
    input_root: Path, source_root: Path, root_fd: int, directory_fd: int,
    root_identity: tuple[int, int, int, int],
    directory_identity: tuple[int, int, int, int], name: str, raw: bytes,
) -> str:
    """Create/read back one immutable child without resolving its parent path."""
    _require(not _within(source_root, input_root / "fixed-spec-hosts" / name),
             "fixed Spec host destination must be outside SourceV5")
    _require(len(raw) <= MAX_MANIFEST_BYTES,
             "fixed Spec host record exceeds its finite size bound")
    _assert_fixed_spec_host_directory_names(
        input_root, root_fd, directory_fd, root_identity, directory_identity,
    )
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        exists = True
    except FileNotFoundError:
        exists = False
    except OSError as error:
        raise PreparationError(
            f"cannot safely inspect fixed Spec host record: {error}",
        ) from error
    if exists:
        existing, existing_raw, _existing_sha, info = _read_fixed_spec_host_at(
            input_root, root_fd, directory_fd, root_identity,
            directory_identity, name,
        )
        del existing
        _require(
            stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid() and
            info.st_nlink == 1 and existing_raw == raw,
            "existing immutable artifact differs from the exact replayed bytes or private mode",
        )
        return _sha256(raw)

    fd = -1
    created_identity: tuple[int, int, int, int, int, int, int, int] | None = None
    created_inode: tuple[int, int] | None = None
    try:
        _assert_fixed_spec_host_directory_names(
            input_root, root_fd, directory_fd, root_identity, directory_identity,
        )
        try:
            fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                0o600, dir_fd=directory_fd,
            )
        except OSError as error:
            raise PreparationError(f"cannot create immutable fixed Spec host record: {error}") from error
        opened = os.fstat(fd)
        created_inode = (opened.st_dev, opened.st_ino)
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            _require(count > 0, "fixed Spec host record write stopped before completion")
            offset += count
        os.fsync(fd)
        info = os.fstat(fd)
        created_identity = (
            info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns, info.st_nlink, info.st_uid,
        )
    except BaseException:
        if fd >= 0:
            os.close(fd)
            fd = -1
        try:
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if created_inode == (named.st_dev, named.st_ino):
                os.unlink(name, dir_fd=directory_fd)
                os.fsync(directory_fd)
        except OSError:
            pass
        raise
    finally:
        if fd >= 0:
            os.close(fd)
    try:
        _assert_fixed_spec_host_directory_names(
            input_root, root_fd, directory_fd, root_identity, directory_identity,
        )
        os.fsync(directory_fd)
        written, written_raw, _written_sha, info = _read_fixed_spec_host_at(
            input_root, root_fd, directory_fd, root_identity,
            directory_identity, name,
        )
        del written
        _require(
            written_raw == raw and stat.S_IMODE(info.st_mode) == 0o600 and
            info.st_uid == os.getuid() and info.st_nlink == 1,
            "new immutable fixed Spec host record differs from its canonical bytes",
        )
    except BaseException:
        try:
            named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            identity = (
                named.st_dev, named.st_ino, named.st_mode, named.st_size,
                named.st_mtime_ns, named.st_ctime_ns, named.st_nlink, named.st_uid,
            )
            if identity == created_identity:
                os.unlink(name, dir_fd=directory_fd)
                os.fsync(directory_fd)
        except OSError:
            pass
        raise
    return _sha256(raw)


def _prepared_fixed_host_binding_for_spec_host(
    preparation: dict[str, Any], spec: dict[str, Any], inputs: Any,
    input_root: Path, host_id: str,
    fixed_spec_host_pin: dict[str, Any],
    *, prepared_context: tuple[Path, dict[str, Any], str] | None = None,
    fixed_spec_host_record: tuple[dict[str, Any], bytes, str] | None = None,
) -> dict[str, Any]:
    """Bind one canonical Spec.host record to the separate capacity observation."""
    matches = [item for item in spec.get("hosts", [])
               if type(item) is dict and item.get("host_id") == host_id]
    _require(len(matches) == 1,
             "prepared generation does not have one selected SpecV3 host")
    spec_host = matches[0]
    prepared_path, prepared_value, prepared_sha = (
        _read_prepared_capacity_host_context(
            preparation, inputs, input_root, spec_host, host_id,
        ) if prepared_context is None else prepared_context
    )

    fixed_pin = _exact(fixed_spec_host_pin, {"path", "raw_sha256"},
                       "fixed SpecV3 host-record pin")
    fixed_path = Path(fixed_pin["path"])
    _require(fixed_path.is_absolute() and _within(input_root, fixed_path),
             "fixed Spec host record is outside the original private input tree")
    fixed_relative = fixed_path.relative_to(input_root).as_posix()
    pinned_fixed_path = (
        input_root / fixed_relative if fixed_spec_host_record is not None else
        _safe_child(input_root, fixed_relative, "fixed Spec host record")
    )
    _require(str(pinned_fixed_path) == fixed_pin["path"],
             "fixed Spec host path is not a normalized identity path")
    if fixed_spec_host_record is None:
        fixed_value, fixed_raw, fixed_sha = _read_json(
            pinned_fixed_path, "fixed Spec host record", MAX_MANIFEST_BYTES,
            fixed_pin["raw_sha256"],
        )
    else:
        fixed_value, fixed_raw, fixed_sha = fixed_spec_host_record
        _require(fixed_sha == fixed_pin["raw_sha256"] == _sha256(fixed_raw) and
                 _canonical(fixed_value) == fixed_raw,
                 "fixed Spec host record differs from its exact raw pin")
    spec_host_raw = _canonical(spec_host)
    _require(fixed_value == spec_host and fixed_raw == spec_host_raw and
             fixed_sha == fixed_pin["raw_sha256"],
             "fixed Spec host record differs from the canonical selected SpecV3 host")
    controls_sha = _sha256(_canonical(spec_host["controls"]))
    _require(spec_host["host_fingerprint_sha256"] == controls_sha ==
             prepared_value["controls_sha256"],
             "fixed Spec host and prepared capacity context disagree on controls")
    body = {
        "schema": PREPARED_FIXED_HOST_BINDING_SCHEMA,
        "host_id": host_id,
        "fixed_spec_host_pin": {"path": str(pinned_fixed_path),
                                 "raw_sha256": fixed_sha},
        "prepared_host_context_pin": {"path": str(prepared_path), "raw_sha256": prepared_sha},
        "spec_host_semantic_sha256": _sha256(spec_host_raw),
        "boot_id_sha256": prepared_value["boot_id_sha256"],
        "kernel_release": spec_host["controls"]["kernel_release"],
        "controls_sha256": controls_sha,
        "process_affinity": list(prepared_value["cpu_affinity"]),
        "network_namespace_inode": prepared_value["network_namespace_inode"],
    }
    return _validate_prepared_fixed_host_binding({
        **body, "binding_sha256": _sha256(_canonical(body)),
    })


def _prepared_fixed_host_binding_for_overlay(
    preparation: dict[str, Any], spec: dict[str, Any], overlay: dict[str, Any],
    inputs: Any, input_root: Path, host_id: str,
) -> dict[str, Any]:
    """Bind the legacy overlay host facts to the shared Spec/capacity bridge."""
    _require(host_id == overlay.get("host_id"),
             "fixed-pair overlay and prepared generations select different hosts")
    source_scope = _exact(overlay.get("sources"), {
        "manifests", "selected", "campaign_artifacts_root", "observed_host",
        "historical_runner_sha256", "output_mount",
    }, "fixed-pair source host bindings")
    fixed_observed = _exact(source_scope["observed_host"], {
        "pin", "host_fingerprint_sha256", "controls_sha256", "process_affinity",
        "network_namespace_inode",
    }, "fixed-pair legacy Spec host observation")
    overlay_pin = _exact(fixed_observed["pin"], {"path", "sha256"},
                         "fixed-pair legacy Spec host raw pin")
    binding = _prepared_fixed_host_binding_for_spec_host(
        preparation, spec, inputs, input_root, host_id,
        {"path": overlay_pin["path"], "raw_sha256": overlay_pin["sha256"]},
    )
    spec_host = next(item for item in spec["hosts"]
                     if item["host_id"] == host_id)
    _require(fixed_observed["host_fingerprint_sha256"] ==
             spec_host["host_fingerprint_sha256"] ==
                 binding["controls_sha256"] and
             fixed_observed["controls_sha256"] == binding["controls_sha256"] and
             fixed_observed["process_affinity"] == binding["process_affinity"] and
             fixed_observed["network_namespace_inode"] ==
                 binding["network_namespace_inode"],
             "fixed overlay and prepared capacity context differ on host identity/controls")
    return binding


def build_prepared_host_binding(
    preparation_pin: dict[str, Any], spec_pin: dict[str, Any], overlay_pin: dict[str, Any],
    source_root: Path, input_root: Path, host_id: str,
) -> dict[str, Any]:
    """Build the versioned bridge between original Spec host and prep observation bytes."""
    (preparation, sources, campaign, inputs, spec,
     spec_pin_value) = _prepared_host_binding_inputs(
        preparation_pin, spec_pin, source_root, input_root, host_id,
    )
    overlay, _overlay_raw, _overlay_sha = _read_pinned_json(overlay_pin, "original fixed-pair overlay")
    _exact(overlay, {
        "schema", "campaign_id", "host_id", "spec", "plan", "sources", "execution_source",
        "modules", "job", "runtime_bindings", "members", "deadlines", "artifact_budgets", "output_root",
    }, "original fixed-pair overlay")
    _require(overlay["schema"] == FIXED_PAIR_OVERLAY_SCHEMA and
             overlay["campaign_id"] == spec["campaign_id"] and overlay["host_id"] == host_id,
             "fixed-pair overlay campaign/host differs from the original preparation generation")
    spec_binding = _exact(overlay.get("spec"), {"pin", "semantic_sha256"},
                          "fixed-pair original SpecV3 binding")
    overlay_spec_pin = _exact(spec_binding["pin"], {"path", "sha256"},
                              "fixed-pair original SpecV3 raw pin")
    _require(overlay_spec_pin == spec_pin_value and
             spec_binding["semantic_sha256"] == campaign.digest_object(spec),
             "fixed-pair overlay belongs to another original SpecV3 generation")
    return _prepared_fixed_host_binding_for_overlay(
        preparation, spec, overlay, inputs, input_root, host_id,
    )


def _materialized_spec_host_record_at(
    input_root: Path, spec: dict[str, Any], host_id: str,
    root_fd: int, directory_fd: int,
    root_identity: tuple[int, int, int, int],
    directory_identity: tuple[int, int, int, int],
) -> tuple[dict[str, str], tuple[dict[str, Any], bytes, str]]:
    path = _fixed_spec_host_path(input_root, host_id)
    value, raw, raw_sha256, info = _read_fixed_spec_host_at(
        input_root, root_fd, directory_fd, root_identity,
        directory_identity, path.name,
    )
    spec_host = next((item for item in spec.get("hosts", [])
                      if type(item) is dict and item.get("host_id") == host_id), None)
    _require(type(spec_host) is dict and value == spec_host and
             stat.S_ISREG(info.st_mode) and
             info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600 and
             info.st_nlink == 1 and
             raw == _canonical(spec_host),
             f"{host_id} materialized Spec host bytes/mode/link identity differ")
    return ({"path": str(path), "raw_sha256": raw_sha256},
            (value, raw, raw_sha256))


def _read_prepared_capacity_host_context(
    preparation: dict[str, Any], inputs: Any, input_root: Path,
    spec_host: dict[str, Any], host_id: str,
) -> tuple[Path, dict[str, Any], str]:
    prepared_record = _exact(preparation.get("observed_hosts", {}).get(host_id),
                             {"relative_path", "raw_sha256"},
                             f"{host_id} prepared capacity-host-context pin")
    prepared_path = _safe_child(input_root, prepared_record["relative_path"],
                                f"{host_id} prepared capacity-host-context")
    prepared_value, _prepared_raw, prepared_sha = _read_json(
        prepared_path, f"{host_id} prepared capacity-host-context",
        MAX_MANIFEST_BYTES, prepared_record["raw_sha256"],
    )
    _require(prepared_sha == prepared_record["raw_sha256"],
             "prepared capacity-host-context raw pin changed")
    try:
        inputs._validate_observed_host_structure(prepared_value, spec_host, host_id)
    except Exception as error:
        raise PreparationError(
            f"{host_id} prepared capacity-host-context failed the unchanged SourceV5 host validator: {error}",
        ) from error
    return prepared_path, prepared_value, prepared_sha


def materialize_prepared_host_binding(
    preparation_pin: dict[str, Any], spec_pin: dict[str, Any],
    source_root: Path, input_root: Path, host_id: str,
) -> dict[str, Any]:
    """Materialize the selected Spec host and bind it to the capacity observation.

    This preparatory operation writes only the canonical ``Spec.host`` value at
    its deterministic private input-root path. It does not create or synthesize
    a fixed-pair overlay.
    """
    (preparation, _sources, campaign_module, inputs, spec,
     _spec_pin_value) = _prepared_host_binding_inputs(
        preparation_pin, spec_pin, source_root, input_root, host_id,
    )
    source_root = _safe_root(Path(source_root), "SourceV5 root")
    input_root = _safe_root(Path(input_root), "preparation input root")
    spec_host = next((item for item in spec["hosts"]
                      if item["host_id"] == host_id), None)
    _require(type(spec_host) is dict,
             "selected SpecV3 host disappeared before materialization")
    # Validate observed-host controls and canonical Spec.host bytes before
    # creating the resident directory or any file beneath it.
    prepared_context = _read_prepared_capacity_host_context(
        preparation, inputs, input_root, spec_host, host_id,
    )
    expected_raw = _canonical(spec_host)
    _require(campaign_module.canonical_bytes(spec_host) == expected_raw,
             "selected SpecV3 host canonical encoding changed")
    path = _fixed_spec_host_path(input_root, host_id)
    fixed_pin = {"path": str(path), "raw_sha256": _sha256(expected_raw)}
    binding = _prepared_fixed_host_binding_for_spec_host(
        preparation, spec, inputs, input_root, host_id, fixed_pin,
        prepared_context=prepared_context,
        fixed_spec_host_record=(spec_host, expected_raw, fixed_pin["raw_sha256"]),
    )
    with _open_fixed_spec_host_directory(input_root, create=True) as (
            root_fd, directory_fd, root_identity, directory_identity,
            directory_path):
        _require(path.parent == directory_path and fixed_pin["path"] == str(path),
                 "materialized Spec host escaped its deterministic private directory")
        _write_fixed_spec_host_at(
            input_root, source_root, root_fd, directory_fd,
            root_identity, directory_identity, path.name, expected_raw,
        )
        actual_pin, actual_record = _materialized_spec_host_record_at(
            input_root, spec, host_id, root_fd, directory_fd,
            root_identity, directory_identity,
        )
        _require(actual_pin == fixed_pin and actual_record ==
                 (spec_host, expected_raw, fixed_pin["raw_sha256"]),
                 "materialized Spec host changed before its returned pin")
    return {"fixed_spec_host_pin": fixed_pin,
            "prepared_host_binding": binding}


def verify_prepared_host_binding(
    preparation_pin: dict[str, Any], spec_pin: dict[str, Any],
    source_root: Path, input_root: Path, host_id: str,
) -> dict[str, Any]:
    """Read-only verification of a pre-materialized Spec host binding."""
    (preparation, _sources, _campaign, inputs, spec,
     _spec_pin_value) = _prepared_host_binding_inputs(
        preparation_pin, spec_pin, source_root, input_root, host_id,
    )
    input_root = _safe_root(Path(input_root), "preparation input root")
    path = _fixed_spec_host_path(input_root, host_id)
    spec_host = next((item for item in spec["hosts"]
                      if item["host_id"] == host_id), None)
    _require(type(spec_host) is dict,
             "selected SpecV3 host disappeared before verification")
    prepared_context = _read_prepared_capacity_host_context(
        preparation, inputs, input_root, spec_host, host_id,
    )
    with _open_fixed_spec_host_directory(input_root, create=False) as (
            root_fd, directory_fd, root_identity, directory_identity,
            directory_path):
        _require(path.parent == directory_path,
                 "read-only prepared host binding changed its deterministic Spec host path")
        fixed_pin, fixed_record = _materialized_spec_host_record_at(
            input_root, spec, host_id, root_fd, directory_fd,
            root_identity, directory_identity,
        )
        binding = _prepared_fixed_host_binding_for_spec_host(
            preparation, spec, inputs, input_root, host_id, fixed_pin,
            prepared_context=prepared_context,
            fixed_spec_host_record=fixed_record,
        )
    return {"fixed_spec_host_pin": fixed_pin,
            "prepared_host_binding": binding}


def _verify_pilot_overlay_generation(
    overlay: dict[str, Any], expected_job: dict[str, Any], spec: dict[str, Any], spec_path: Path, spec_raw_sha: str,
    plan: dict[str, Any], plan_path: Path, plan_raw_sha: str, preparation: dict[str, Any],
    sources: dict[str, dict[str, Any]], source_root: Path, input_root: Path,
    campaign: Any, inputs: Any, inventory_module: Any, fixed: types.ModuleType,
    prepared_host_binding: dict[str, Any],
    campaign_artifacts_root: Path,
) -> None:
    """Bind one internally valid overlay to this exact original generation."""
    _exact(overlay, {
        "schema", "campaign_id", "host_id", "spec", "plan", "sources", "execution_source", "modules",
        "job", "runtime_bindings", "members", "deadlines", "artifact_budgets", "output_root",
    }, "original fixed-pair overlay generation")
    _require(overlay["schema"] == FIXED_PAIR_OVERLAY_SCHEMA,
             "original fixed-pair overlay generation schema is unsupported")
    spec_pin = _exact(overlay["spec"], {"pin", "semantic_sha256"}, "fixed-pair overlay Spec generation")
    spec_raw_pin = _exact(spec_pin["pin"], {"path", "sha256"}, "fixed-pair overlay Spec raw pin")
    plan_pin = _exact(overlay["plan"], {"pin", "semantic_sha256"}, "fixed-pair overlay Plan generation")
    plan_raw_pin = _exact(plan_pin["pin"], {"path", "sha256"}, "fixed-pair overlay Plan raw pin")
    _require(spec_raw_pin == {"path": str(spec_path), "sha256": spec_raw_sha} and
             spec_pin["semantic_sha256"] == campaign.digest_object(spec),
             "fixed-pair overlay belongs to another original SpecV3 raw/semantic generation")
    _require(plan_raw_pin == {"path": str(plan_path), "sha256": plan_raw_sha} and
             plan_pin["semantic_sha256"] == plan["plan_sha256"],
             "fixed-pair overlay belongs to another original PlanV3 raw/semantic generation")
    _require(overlay["campaign_id"] == spec["campaign_id"] == plan["campaign_id"] and
             overlay["host_id"] == expected_job["host_id"] and
             overlay["job"] == {"value": expected_job, "sha256": _sha256(_canonical(expected_job))},
             "fixed-pair overlay campaign/host/job differs from the supplied original schedule row")

    source_scope = _exact(overlay["sources"], {
        "manifests", "selected", "campaign_artifacts_root", "observed_host", "historical_runner_sha256", "output_mount",
    }, "fixed-pair overlay source generation")
    _require(source_scope["campaign_artifacts_root"] == str(campaign_artifacts_root) and
             source_scope["historical_runner_sha256"] == spec["runner_sha256"],
             "fixed-pair overlay campaign-artifact root or historical runner differs from the supplied generation")
    manifest_pins = _exact(source_scope["manifests"], set(sources), "fixed-pair overlay three-host SourceV5 pins")
    expected_manifests: dict[str, Any] = {}
    for source_host, source_value in sources.items():
        manifest = preparation["source_pins"][source_host]["manifest"]
        expected_path = str(_safe_child(input_root, manifest["relative_path"], f"{source_host} original SourceV5 manifest"))
        expected_manifests[source_host] = {
            "pin": {"path": expected_path, "sha256": manifest["raw_sha256"]},
            "manifest_sha256": manifest["semantic_sha256"],
        }
    _require(manifest_pins == expected_manifests,
             "fixed-pair overlay SourceV5 raw/semantic pins differ from the prepared cohort")
    selected = _exact(source_scope["selected"], {
        "host_id", "root", "git_commit", "source_tree_sha256", "build_sha256",
    }, "fixed-pair overlay selected SourceV5 generation")
    selected_source = sources[expected_job["host_id"]]
    _require(selected == {
        "host_id": expected_job["host_id"], "root": str(source_root),
        "git_commit": selected_source["source"]["git_commit"],
        "source_tree_sha256": selected_source["source"]["source_tree_sha256"],
        "build_sha256": campaign.digest_object(selected_source["build"]),
    }, "fixed-pair overlay selected SourceV5 root/commit/tree/build differs from the prepared generation")

    expected_modules: dict[str, dict[str, str]] = {}
    inventory_by_path = {item["path"]: item for item in selected_source["source"]["files"]}
    for role, relative in fixed.MODULE_PATHS.items():
        entry = inventory_by_path.get(relative)
        _require(type(entry) is dict and entry.get("kind") == "file" and entry.get("mode") in ("100644", "100755"),
                 f"selected SourceV5 lacks the typed fixed-pair module {role}")
        expected_modules[role] = {"path": relative, "sha256": entry["sha256"]}
    _require(expected_modules["executor"]["sha256"] ==
             preparation["source_pins"][expected_job["host_id"]]["modules"]["fixed_pair"]["sha256"] and
             overlay["modules"] == expected_modules,
             "fixed-pair overlay execution-module identities differ from the prepared SourceV5 generation")
    execution_source = _exact(overlay["execution_source"], {
        "git_commit", "source_tree_sha256", "inventory_schema", "inventory", "inventory_sha256",
    }, "fixed-pair overlay execution-source inventory")
    execution_records = sorted(
        (inventory_by_path[path] for path in fixed.MODULE_PATHS.values()),
        key=lambda item: item["path"].encode("utf-8"),
    )
    _require(execution_source == {
        "git_commit": selected_source["source"]["git_commit"],
        "source_tree_sha256": selected_source["source"]["source_tree_sha256"],
        "inventory_schema": inventory_module.SCHEMA,
        "inventory": execution_records,
        "inventory_sha256": inventory_module.digest_records(execution_records),
    }, "fixed-pair overlay execution inventory differs from its typed SourceV5 records")

    planned_bindings = plan.get("runtime_process_bindings", {}).get(expected_job["run_id"])
    _require(type(planned_bindings) is list and len(planned_bindings) == 2,
             "original PlanV3 has no exact two-member runtime binding for this job")
    runtime = _exact(overlay["runtime_bindings"], {
        "pin", "manifest_sha256", "plan_entry_sha256", "value",
    }, "fixed-pair original runtime binding")
    runtime_pin = _exact(runtime["pin"], {"path", "sha256"}, "fixed-pair runtime binding raw pin")
    expected_runtime_path = str(Path(overlay["output_root"]) / ".fixed-pair-runtime-bindings.json")
    expected_runtime = campaign.runtime_binding_manifest_value(
        planned_bindings, expected_job, spec, selected_source,
    )
    _require(runtime_pin["path"] == expected_runtime_path and
             runtime["value"] == expected_runtime and
             runtime["manifest_sha256"] == expected_runtime["manifest_sha256"] and
             runtime["plan_entry_sha256"] == _sha256(_canonical(planned_bindings)),
             "fixed-pair overlay runtime/nonces differ from the exact original PlanV3 recipes")

    derived_host_binding = _prepared_fixed_host_binding_for_overlay(
        preparation, spec, overlay, inputs, input_root, expected_job["host_id"],
    )
    _require(_validate_prepared_fixed_host_binding(prepared_host_binding) == derived_host_binding,
             "fixed-pair Spec host and prepared capacity-host context differ from the declared versioned bridge")


@contextlib.contextmanager
def _capacity_pilot_read_window(provider: Any, job: dict[str, Any]):
    """Keep one byte-only capture window; providers cannot suppress failures."""
    if provider is None:
        yield None
        return
    _require(callable(getattr(provider, "open_view", None)),
             "captured capacity-pilot provider has no explicit read window")
    manager = provider.open_view(
        json.loads(_canonical(job)), "exploration", use="capacity_pilot_export",
    )
    view = manager.__enter__()
    try:
        _require(type(view) is dict and type(view.get("objects")) is dict and
                 type(view.get("stage_root")) is str,
                 "captured capacity-pilot window has no exact file references")
        yield view
    except BaseException:
        manager.__exit__(*sys.exc_info())
        raise
    else:
        manager.__exit__(None, None, None)


def _capacity_pilot_envelope_reader(
    fixed: Any, view: dict[str, Any] | None,
    overlay_pin: dict[str, Any], receipt_pin: dict[str, Any], host_pin: dict[str, Any],
) -> Any:
    if view is None:
        return None
    origins = {overlay_pin["path"], receipt_pin["path"], host_pin["path"]}
    _require(len(origins) == 3 and all(type(path) is str for path in origins) and
             origins <= set(view["objects"]),
             "captured capacity-pilot window omits an exact envelope origin")
    return fixed.CapturedFixedPairArtifactsV1(
        {origin: view["objects"][origin] for origin in origins},
        Path(view["stage_root"]),
    )


def _read_capacity_pilot_envelope(
    pin: dict[str, Any], label: str, reader: Any,
) -> tuple[dict[str, Any], bytes, str]:
    if reader is None:
        return _read_pinned_json(pin, label)
    raw, checksum = reader.read(pin["path"], label, MAX_REQUEST_BYTES)
    _require(checksum == pin["sha256"] == _sha256(raw),
             f"{label} differs from its caller-pinned raw SHA-256")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise PreparationError(f"{label} is not bounded UTF-8 JSON: {error}") from error
    _require(type(value) is dict and _canonical(value) == raw,
             f"{label} is not canonical JSON")
    return value, raw, checksum


def _verify_capacity_pilot_captured_pair(
    fixed: Any, view: dict[str, Any], overlay_pin: dict[str, Any],
    receipt_pin: dict[str, Any], host_pin: dict[str, Any],
    overlay: dict[str, Any], overlay_raw_sha: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    replay = fixed.verify_fixed_pair_overlay_captured_v1(
        overlay_pin, receipt_pin, host_pin,
        view["objects"], Path(view["stage_root"]),
    )
    _exact(replay, {
        "schema", "verification", "overlay", "execution_receipt",
        "host_verification_pin", "full_replay_verified", "qualification_eligible",
    }, "captured capacity-pilot owner replay")
    verification = _exact(replay["verification"], {
        "schema", "verified", "status", "qualification_eligible",
        "receipt_sha256", "overlay_sha256", "run_id",
    }, "captured capacity-pilot component projection")
    _require(replay["schema"] == fixed.CAPTURED_REPLAY_CONTEXT_SCHEMA_V1 and
             replay["full_replay_verified"] is True and
             replay["qualification_eligible"] is False and
             replay["overlay"] == overlay and
             replay["host_verification_pin"] == host_pin and
             verification["schema"] == fixed.RECEIPT_SCHEMA and
             verification["overlay_sha256"] == overlay_raw_sha and
             verification["receipt_sha256"] == receipt_pin["sha256"] and
             verification["run_id"] == overlay["job"]["value"]["run_id"],
             "captured capacity-pilot replay changed its original envelope or host pin")
    # This is a local compatibility check projection, never a replacement
    # component or digest. The owner's exact seven-field result is untouched.
    return ({**verification,
             "host_verification_sha256": replay["host_verification_pin"]["host_verification_sha256"]},
            replay["execution_receipt"])


def export_capacity_pilot(
    preparation_final_pins: dict[str, Any], verified_fixed_records: list[dict[str, Any]], host_id: str,
    *, captured_read_provider: Any = None, before_publication: Any = None,
) -> dict[str, Any]:
    """Replay six original fixed-pair receipts per context/allocator and export the rate pilot.

    The pin bundle contains the original preparation, empty-rate SpecV3 and
    PlanV3, SourceV5/input roots, campaign-artifact root and optional output.
    Each pair record includes the original overlay/receipt, strict host receipt
    and identity path map. The offline verifier replays the original generation
    before either APP member contributes to the rate pilot.
    """
    _require(before_publication is None or callable(before_publication),
             "capacity-pilot before-publication hook must be absent or callable")
    pins = _exact(preparation_final_pins, {
        "preparation", "spec", "plan", "source_root", "input_root", "campaign_artifacts_root",
        "prepared_host_binding", "output",
    }, "capacity-pilot original-generation pins")
    prepared_host_binding = _validate_prepared_fixed_host_binding(pins["prepared_host_binding"])
    source_root = _safe_root(Path(pins["source_root"]), "SourceV5 root")
    input_root = _safe_root(Path(pins["input_root"]), "original campaign input root")
    campaign_artifacts_root = _safe_root(Path(pins["campaign_artifacts_root"]), "original campaign artifact root")
    _require(type(pins["campaign_artifacts_root"]) is str and
             pins["campaign_artifacts_root"] == str(campaign_artifacts_root),
             "campaign-artifact root pin must be a normalized absolute path string")
    _require(not _within(source_root, campaign_artifacts_root),
             "capacity-pilot campaign artifact root must remain outside SourceV5")
    preparation, sources, campaign, inputs = read_preparation_intent(
        pins["preparation"], source_root, input_root,
    )
    _require(host_id in sources, "capacity-pilot host is not in the full SourceV5 cohort")
    spec, spec_raw, spec_raw_sha = _read_pinned_json(pins["spec"], "initial empty-rate SpecV3")
    plan, plan_raw, plan_raw_sha = _read_pinned_json(pins["plan"], "original initial PlanV3", MAX_PLAN_BYTES)
    _require(spec.get("schema") == campaign.SPEC_SCHEMA_V3 and spec.get("rates") == [] and spec.get("oracles") == [],
             "capacity-pilot export requires the original SpecV3 with both rate/oracle slots empty")
    try:
        core = inputs.preparation_core_from_spec(spec)
        _require(core == preparation["core"], "initial SpecV3 changed a prospectively frozen preparation field")
    except Exception as error:
        raise PreparationError(f"initial SpecV3 does not match the preparation core: {error}") from error
    _verify_spec_source_refs(spec, preparation, sources)
    _require(plan.get("spec_sha256") == campaign.digest_object(spec),
             "original initial PlanV3 was not frozen from the pinned initial SpecV3")
    runtime_sha = sources[host_id]["runtime_readback_validator"]["sha256"]
    inputs_sha = campaign.campaign_inputs_source_sha256(sources)
    try:
        campaign.verify_plan(plan, runtime_sha, inputs_sha)
        all_expected_jobs = campaign.build_jobs(spec, "exploration")
        expected_jobs = [item for item in all_expected_jobs if item["host_id"] == host_id]
    except Exception as error:
        raise PreparationError(f"original initial PlanV3 failed captured SourceV5 replay: {error}") from error
    _require(_canonical(plan.get("jobs", {}).get("exploration")) == _canonical(all_expected_jobs),
             "original initial PlanV3 exploration schedule differs from the unchanged controller")
    expected_by_run = {item["run_id"]: item for item in expected_jobs}
    _require(len(expected_by_run) == 15 * 4 * 6 and
             all(item.get("mode") == "capacity" and item.get("comparison_kind") == "capacity_pilot" for item in expected_jobs),
             "original PlanV3 does not contain the complete 15-context, four-allocator, six-pair capacity pilot")
    _require(type(verified_fixed_records) is list and len(verified_fixed_records) == len(expected_jobs),
             "fixed-pair receipt set does not contain every original capacity-pilot job")

    expected_fixed_sha = preparation["source_pins"][host_id]["modules"]["fixed_pair"]["sha256"]
    fixed_raw, fixed_path, fixed_record = _capture_typed_source_file(
        sources[host_id], source_root, "scripts/application-fixed-pair.py",
        "fixed-pair verifier", expected_fixed_sha,
    )
    _require(all(value["modules"]["fixed_pair"]["sha256"] == fixed_record["sha256"]
                 for value in preparation["source_pins"].values()),
             "SourceV5 fixed-pair module differs across the frozen cohort")
    fixed = _execute_captured_module(fixed_raw, fixed_path, "fixed_pair")

    rows_by_key: dict[tuple[str, str, str, int], dict[str, Any]] = {}
    raw_pair_pins: dict[str, str] = {}
    raw_pair_records: list[dict[str, Any]] = []
    for index, record_value in enumerate(verified_fixed_records):
        record = _exact(record_value, {
            "overlay", "receipt", "host_verification", "evidence_path_map",
        }, f"fixed-pair record[{index}]")
        overlay_pin = _exact(record["overlay"], {"path", "sha256"}, f"fixed-pair overlay pin[{index}]")
        receipt_pin = _exact(record["receipt"], {"path", "sha256"}, f"fixed-pair receipt pin[{index}]")
        host_verification_pin = _exact(record["host_verification"], {
            "path", "raw_sha256", "host_verification_sha256",
        }, f"fixed-pair strict host-verification receipt pin[{index}]")
        with _capacity_pilot_read_window(captured_read_provider, expected_jobs[index]) as captured_view:
            envelope_reader = _capacity_pilot_envelope_reader(
                fixed, captured_view, overlay_pin, receipt_pin, host_verification_pin,
            )
            overlay, overlay_raw, overlay_raw_sha = _read_capacity_pilot_envelope(overlay_pin, f"original fixed-pair overlay[{index}]", envelope_reader)
            _require(overlay.get("schema") == "allocatbelt.application-fixed-pair-execution-overlay.v1",
                     f"fixed-pair overlay[{index}] has an unsupported schema")
            job_record = overlay.get("job")
            _require(type(job_record) is dict and type(job_record.get("value")) is dict,
                     f"fixed-pair overlay[{index}] has no original scheduled job")
            job = job_record["value"]
            expected_job = expected_by_run.get(job.get("run_id"))
            _require(expected_job is not None and _canonical(job) == _canonical(expected_job),
                     f"fixed-pair overlay[{index}] is not one exact original exploration capacity-pilot job")
            _require(job["run_id"] == expected_jobs[index]["run_id"],
                     "fixed-pair records do not preserve the original PlanV3 job order")
            try:
                _verify_pilot_overlay_generation(
                    overlay, expected_job, spec, Path(pins["spec"]["path"]), spec_raw_sha,
                    plan, Path(pins["plan"]["path"]), plan_raw_sha, preparation, sources,
                    source_root, input_root, campaign, inputs, campaign.source_inventory_module(), fixed,
                    prepared_host_binding, campaign_artifacts_root,
                )
                if captured_view is None:
                    verified = fixed.verify_fixed_pair_overlay_offline(
                        overlay_pin, receipt_pin, host_verification_pin, record["evidence_path_map"],
                    )
                    captured_receipt = None
                else:
                    verified, captured_receipt = _verify_capacity_pilot_captured_pair(
                        fixed, captured_view, overlay_pin, receipt_pin,
                        host_verification_pin, overlay, overlay_raw_sha,
                    )
            except Exception as error:
                raise PreparationError(f"original fixed-pair receipt[{index}] failed generation-bound offline replay: {error}") from error
            _require(verified.get("verified") is True and verified.get("status") == "valid_pair" and
                     verified.get("qualification_eligible") is False and
                     verified.get("host_verification_sha256") == host_verification_pin["host_verification_sha256"],
                     f"original capacity-pilot fixed pair[{index}] is not a verified valid component receipt")
            receipt_value, receipt_raw, receipt_raw_sha = _read_capacity_pilot_envelope(receipt_pin, f"original fixed-pair receipt[{index}]", envelope_reader)
            _require(verified.get("receipt_sha256") == receipt_raw_sha,
                     f"fixed-pair receipt[{index}] replay did not bind the exact raw receipt")
            _require(captured_receipt is None or captured_receipt == receipt_value,
                     f"fixed-pair receipt[{index}] differs from the captured owner's execution receipt")
            run_id = job["run_id"]
            _require(run_id not in raw_pair_pins, "fixed-pair receipts repeat an original capacity-pilot run ID")
            _require(receipt_value.get("run_id") == run_id and receipt_value.get("host_id") == host_id and
                     receipt_value.get("status") == "valid_pair",
                     f"fixed-pair receipt[{index}] identity/status differs from its original job")
            metrics = receipt_value.get("process_metrics")
            rows = receipt_value.get("process_rows")
            _require(type(metrics) is list and len(metrics) == 2 and type(rows) is list and len(rows) == 2,
                     f"fixed-pair receipt[{index}] lacks both independently replayed APP members")
            metric_by_executor = {item.get("executor"): item for item in metrics if type(item) is dict}
            row_by_executor = {item.get("executor"): item for item in rows if type(item) is dict}
            _require(set(metric_by_executor) == {"bounded", "tokio"} and set(row_by_executor) == {"bounded", "tokio"},
                     f"fixed-pair receipt[{index}] is not one bounded/Tokio pair")
            pair: dict[str, Any] = {
                "ordinal": job["ordinal"],
                "bounded_status": "valid", "tokio_status": "valid",
                "raw_pair_sha256": _sha256(_canonical({
                    "overlay_raw_sha256": overlay_raw_sha,
                    "receipt_raw_sha256": receipt_raw_sha,
                    "verified_receipt_sha256": verified["receipt_sha256"],
                    "host_verification_raw_sha256": host_verification_pin["raw_sha256"],
                    "host_verification_sha256": host_verification_pin["host_verification_sha256"],
                    "prepared_host_binding_sha256": prepared_host_binding["binding_sha256"],
                    "run_id": run_id,
                })),
            }
            for executor in ("bounded", "tokio"):
                row = row_by_executor[executor]
                metric = metric_by_executor[executor]
                _require(row.get("allocator") == job["allocator"] and row.get("mode") == "capacity" and
                         metric.get("allocator") == job["allocator"] and metric.get("mode") == "capacity",
                         f"fixed-pair receipt[{index}] APP allocator/mode differs from its capacity-pilot job")
                try:
                    on_time = _row_uint(row, "completed_on_time", f"{executor} on-time")
                    late = _row_uint(row, "completed_late", f"{executor} late")
                    attempted = _row_uint(row, "attempted", f"{executor} attempted", positive=True)
                    admitted = _row_uint(row, "admitted", f"{executor} admitted", positive=True)
                    rejected = _row_uint(row, "rejected_full", f"{executor} full rejects") + _row_uint(
                        row, "rejected_resource", f"{executor} resource rejects",
                    )
                except PreparationError:
                    raise
                _require(on_time > 0 and admitted == on_time + late and attempted == admitted + rejected and rejected == 0 and
                         metric.get("completed_on_time") == on_time and metric.get("completed_late") == late,
                         f"fixed-pair receipt[{index}] {executor} capacity accounting does not reconcile")
                for field, number in (("on_time", on_time), ("late", late), ("attempted", attempted),
                                      ("admitted", admitted), ("rejected", rejected)):
                    pair[f"{executor}_{field}"] = number
        key = (job["family"], job["profile"], job["allocator"], job["ordinal"])
        _require(key not in rows_by_key, f"capacity-pilot original ordinal is duplicated: {key}")
        rows_by_key[key] = pair
        raw_pair_pins[run_id] = pair["raw_pair_sha256"]
        raw_pair_records.append({
            "host_id": host_id, "run_id": run_id,
            "family": job["family"], "profile": job["profile"],
            "allocator": job["allocator"], "ordinal": job["ordinal"],
            "overlay": {"path": overlay_pin["path"], "raw_sha256": overlay_raw_sha},
            "receipt": {"path": receipt_pin["path"], "raw_sha256": receipt_raw_sha},
            "host_verification": dict(host_verification_pin),
            "prepared_host_binding_sha256": prepared_host_binding["binding_sha256"],
            "evidence_path_map": record["evidence_path_map"],
            "raw_pair_sha256": pair["raw_pair_sha256"],
        })
        _require(_sha256(overlay_raw) == overlay_raw_sha, "fixed-pair overlay changed during replay")

    _require(set(raw_pair_pins) == set(expected_by_run), "fixed-pair receipts omit or replace original planned capacity-pilot jobs")
    cells: list[dict[str, Any]] = []
    cell_order = [(cell["family"], cell["profile"]) for cell in spec["cells"]]
    allocators = tuple(campaign.ALLOCATORS)
    for family, profile in cell_order:
        for allocator in allocators:
            pairs = []
            for ordinal in range(1, 7):
                key = (family, profile, allocator, ordinal)
                _require(key in rows_by_key, f"original capacity-pilot pair is missing: {key}")
                pairs.append(rows_by_key[key])
            cells.append({"family": family, "profile": profile, "allocator": allocator, "pairs": pairs})
    pilot = {
        "schema": PILOT_SCHEMA,
        "spec_sha256": campaign.preregistration_digest(spec),
        "host_id": host_id,
        "cells": cells,
    }
    try:
        campaign.freeze_rates(spec, pilot, "0" * 64)
    except Exception as error:
        raise PreparationError(f"exported six-pair capacity pilot does not satisfy the unchanged numerical rate validator: {error}") from error
    output_value = pins["output"]
    output = None if output_value is None else Path(output_value)
    pilot_raw = _canonical(pilot)
    raw_sha = _sha256(pilot_raw)
    prospective_result = {
        "path": None if output is None else str(output), "raw_sha256": raw_sha,
        "semantic_sha256": campaign.digest_object(pilot),
        "prepared_host_binding": prepared_host_binding,
        "host_id": host_id, "pair_count": len(raw_pair_pins),
        "context_allocator_count": len(cells), "spec_preregistration_sha256": pilot["spec_sha256"],
        "pair_evidence": raw_pair_records,
    }
    if before_publication is not None:
        hook_result = before_publication(pilot_raw, copy.deepcopy(prospective_result))
        _require(hook_result is None,
                 "capacity-pilot before-publication hook must return None")
    if output is not None:
        _write_private_json_new(output, pilot, source_root, allow_existing_identical=True)
    return prospective_result


def _replay_prepared_capacity_inputs(
    preparation_pin: dict[str, Any], capacity_completion_pins: list[dict[str, Any]],
    resource_budget_pins: dict[str, Any] | None,
) -> tuple:
    """Share the original complete pre-Spec capacity replay without a final gate."""
    prep_ref = _exact(preparation_pin, {"path", "sha256"}, "preparation input pin")
    prep_path = Path(prep_ref["path"])
    _require(prep_path.is_absolute(), "preparation input path must be absolute")
    input_root = _safe_root(prep_path.parent, "preparation input root")
    source_root = _safe_root(SOURCE_ROOT, "SourceV5 root")
    preparation, sources, campaign, inputs = read_preparation_intent(preparation_pin, source_root, input_root)
    host_ids = [host["host_id"] for host in preparation["core"]["hosts"]]
    require_three = len(host_ids) == 3
    _require(require_three, "prepared-input completion requires the full three-host cohort")
    bounded_preparation = resource_budget_pins is not None
    if bounded_preparation:
        resource_budget_pins = _exact(
            resource_budget_pins, set(host_ids), "caller-frozen per-host preparation budgets",
        )

    # Replay all three actual SourceV5 capacity-preparation completions before
    # accepting any final SpecV3 evidence pins.
    _require(type(capacity_completion_pins) is list and len(capacity_completion_pins) == 3,
             "capacity preparation completion set must cover all three hosts")
    stage_relative = "scripts/application-capacity-stage.py"
    stage_raw, stage_path, stage_record = _capture_typed_source_file(
        sources[host_ids[0]], source_root, stage_relative, "capacity-stage verifier",
    )
    stage_sha = stage_record["sha256"]
    _require(all(value["modules"]["capacity_stage"]["sha256"] == stage_sha for value in preparation["source_pins"].values()),
             "active capacity-stage verifier differs from the full SourceV5 module pins")
    stage = _execute_captured_module(stage_raw, stage_path, "capacity_stage")
    capacity_by_host: dict[str, dict[str, Any]] = {}
    completion_pin_by_host: dict[str, dict[str, str]] = {}
    capacity_entries: dict[tuple[str, str, str], dict[str, Any]] = {}
    capacity_completions: list[dict[str, Any]] = []
    completion_resource_budget_pins: dict[str, dict[str, str]] = {}
    for index, pin_value in enumerate(capacity_completion_pins):
        capacity_input_fields = {
            "host_id", "completion_pin", "verification_receipt_pin", "evidence_path_map",
        }
        if bounded_preparation:
            capacity_input_fields.add("resource_budget_pin")
        capacity_input = _exact(pin_value, capacity_input_fields,
                                f"capacity preparation input[{index}]")
        pin_raw = _exact(capacity_input["completion_pin"], {"path", "raw_sha256"},
                         f"capacity preparation completion pin[{index}]")
        origin_pin = {"path": pin_raw["path"], "sha256": pin_raw["raw_sha256"]}
        verified_path_map = None
        if bounded_preparation:
            verified_path_map = stage._validate_evidence_path_map(
                capacity_input["evidence_path_map"],
            )
            local_completion_path = stage._map_evidence_path(
                Path(origin_pin["path"]), verified_path_map,
            )
            replay_pin = {"path": str(local_completion_path), "sha256": origin_pin["sha256"]}
        else:
            replay_pin = origin_pin
        completion_value, _raw, raw_sha = _read_pinned_json(
            replay_pin, f"capacity preparation completion[{index}]",
        )
        host_id = completion_value.get("host_id")
        _require(host_id in host_ids and host_id not in capacity_by_host,
                 "capacity preparation completion host is unknown or duplicated")
        _require(host_id == host_ids[index], "capacity preparation completion list changed the frozen host order")
        _require(capacity_input["host_id"] == host_id,
                 "capacity preparation receipt input host differs from its frozen completion")
        host_context = preparation["observed_hosts"][host_id]
        observed_pin = {
            "path": str(_safe_child(input_root, host_context["relative_path"], f"{host_id} observed host context")),
            "sha256": host_context["raw_sha256"],
        }
        stage_dir = Path(completion_value.get("stage_directory", ""))
        _require(stage_dir.is_absolute(),
                 f"{host_id} capacity preparation output directory is not absolute")
        local_stage_dir = (stage._map_evidence_path(stage_dir, verified_path_map)
                           if verified_path_map is not None else stage_dir)
        _require(_within(input_root, local_stage_dir),
                 f"{host_id} capacity preparation output is outside the frozen private input tree")
        output_root = local_stage_dir.parents[2]
        try:
            if bounded_preparation:
                raw_budget_pin = _exact(
                    capacity_input["resource_budget_pin"],
                    {"path", "raw_sha256", "semantic_sha256"},
                    f"{host_id} caller-frozen resource budget pin",
                )
                expected_budget_pin = _exact(
                    resource_budget_pins[host_id],
                    {"path", "raw_sha256", "semantic_sha256"},
                    f"{host_id} resource budget map pin",
                )
                _require(raw_budget_pin == expected_budget_pin,
                         f"{host_id} preparation resource budget differs from the explicit host map")
                mapped_budget_path = stage._map_evidence_path(
                    Path(raw_budget_pin["path"]), verified_path_map,
                )
                verified_budget_pin = {
                    **raw_budget_pin, "path": str(mapped_budget_path),
                }
                result = stage.verify_capacity_preparation_bounded_offline(
                    preparation_pin,
                    {"path": verified_budget_pin["path"], "sha256": verified_budget_pin["raw_sha256"]},
                    source_root, input_root, host_id, observed_pin, output_root,
                    replay_pin, capacity_input["evidence_path_map"],
                    capacity_input["verification_receipt_pin"],
                )
                _require(result.get("resource_budget") == verified_budget_pin,
                         f"{host_id} bounded capacity replay returned a different budget pin")
                # Keep the caller-frozen origin path in the completion body;
                # the bounded verifier receives its map-local path above.
                # Replay therefore reconstructs identical completion bytes on
                # the host and in the coordinator's private evidence map.
                completion_resource_budget_pins[host_id] = raw_budget_pin
            else:
                result = stage.verify_capacity_preparation_offline(
                    preparation_pin, source_root, input_root, host_id, observed_pin,
                    output_root, origin_pin, capacity_input["evidence_path_map"],
                    capacity_input["verification_receipt_pin"],
                )
        except Exception as error:
            raise PreparationError(f"{host_id} capacity preparation failed complete offline replay: {error}") from error
        _require(result.get("complete") is True and result.get("qualification_eligible") is False and
                 result.get("preparation_raw_sha256") == prep_ref["sha256"] and
                 result.get("preparation_semantic_sha256") == preparation["preparation_sha256"] and
                 len(result.get("entries", [])) == 15,
                 f"{host_id} capacity completion is incomplete or bound to another generation")
        capacity_by_host[host_id] = result
        completion_output_path = (replay_pin["path"] if bounded_preparation
                                  else origin_pin["path"])
        completion_pin_by_host[host_id] = {"path": completion_output_path, "sha256": raw_sha}
        verification_pin = _exact(capacity_input["verification_receipt_pin"],
                                  {"path", "raw_sha256", "receipt_sha256"},
                                  f"{host_id} capacity host-local verification receipt pin")
        if bounded_preparation:
            verification_pin = {
                **verification_pin,
                "path": str(stage._map_evidence_path(
                    Path(verification_pin["path"]), verified_path_map,
                )),
            }
        entries = result["entries"]
        for entry in entries:
            key_value = _exact(entry.get("capacity_key"), {"host_id", "workload", "profile", "calibration_id"},
                               f"{host_id} verified capacity key")
            key = (key_value["host_id"], key_value["workload"], key_value["profile"])
            _require(key not in capacity_entries and key[0] == host_id, "capacity completion repeats or crosses a host key")
            capacity_entries[key] = entry
        capacity_record = {
            "host_id": host_id,
            "completion": {"path": completion_output_path, "raw_sha256": raw_sha},
            "host_verification": verification_pin,
            "evidence_path_map": capacity_input["evidence_path_map"],
            "completion_sha256": result["completion_sha256"],
            "ledger": {
            "path": str((local_stage_dir if bounded_preparation else stage_dir) /
                        ("capacity-preparation-bounded-ledger.jsonl"
                                     if bounded_preparation else "capacity-preparation-ledger.jsonl")),
                "raw_sha256": result["ledger_raw_sha256"],
                "terminal_head": result["terminal_head"],
            },
            "capacity_preparation_templates_sha256": result["capacity_preparation_templates_sha256"],
            "entries": entries,
        }
        if bounded_preparation:
            capacity_record["resource_budget"] = raw_budget_pin
            capacity_record["resource_monitor"] = completion_value["resource_monitor"]
        capacity_completions.append(capacity_record)
    expected_context_keys = {
        (host_id, cell["workload"], cell["profile"])
        for host_id in host_ids for cell in preparation["core"]["cells"]
    }
    _require(set(capacity_by_host) == set(host_ids) and set(capacity_entries) == expected_context_keys,
             "capacity preparation completions do not cover all three hosts and 45 contexts")

    return (
        prep_ref,
        input_root,
        source_root,
        preparation,
        sources,
        campaign,
        inputs,
        host_ids,
        bounded_preparation,
        capacity_by_host,
        completion_pin_by_host,
        capacity_entries,
        capacity_completions,
        completion_resource_budget_pins,
        expected_context_keys,
        prep_path,
    )


PREPARED_CAPACITY_GENERATION_SCHEMA = \
    "allocatbelt.application-source5-prepared-capacity-generation.v1"


def replay_prepared_capacity_inputs_bounded(
    preparation_pin: dict[str, Any],
    capacity_completion_pins: list[dict[str, Any]],
    resource_budget_pins: dict[str, Any],
    source_root: Path, input_root: Path,
) -> dict[str, Any]:
    """Replay the genuine three-host capacity cohort before rates or oracles exist.

    Completeness here covers only the original 45 capacity contexts. It does
    not authorize exploration, establish a final input generation, or pass
    any application qualification gate.
    """
    checked_source = _safe_root(source_root, "capacity generation SourceV5 root")
    checked_input = _safe_root(input_root, "capacity generation input root")
    preparation_ref = _exact(preparation_pin, {"path", "sha256"},
                             "capacity generation preparation pin")
    _require(checked_source == _safe_root(SOURCE_ROOT, "active SourceV5 root") and
             Path(preparation_ref["path"]).is_absolute() and
             Path(preparation_ref["path"]).parent == checked_input,
             "capacity generation differs from its actual Source/input roots")
    _require(type(capacity_completion_pins) is list and len(capacity_completion_pins) == 3 and
             type(resource_budget_pins) is dict and len(resource_budget_pins) == 3,
             "capacity generation requires all three caller-frozen bounded host inputs")
    bounded_inputs = []
    for index, value in enumerate(capacity_completion_pins):
        item = _exact(value, {
            "host_id", "completion_pin", "verification_receipt_pin", "evidence_path_map",
        }, f"capacity generation input[{index}]")
        budget_pin = _exact(resource_budget_pins.get(item["host_id"]), {
            "path", "raw_sha256", "semantic_sha256",
        }, f"capacity generation {item['host_id']} resource budget pin")
        bounded_inputs.append({**item, "resource_budget_pin": budget_pin})
    replay = _replay_prepared_capacity_inputs(
        preparation_ref, bounded_inputs, resource_budget_pins,
    )
    (prep_ref, replay_input, replay_source, preparation, _sources, _campaign, _inputs,
     host_ids, bounded, _capacity_by_host, _completion_pins, _entries,
     capacity_rows, verified_budgets, _expected_contexts, _preparation_path) = replay
    _require(bounded is True and checked_source == replay_source and
             checked_input == replay_input and
             set(verified_budgets) == set(host_ids),
             "capacity generation changed its bounded Source/input cohort")
    body = {
        "schema": PREPARED_CAPACITY_GENERATION_SCHEMA,
        "campaign_id": preparation["core"]["campaign_id"],
        "preparation": {"path": prep_ref["path"], "raw_sha256": prep_ref["sha256"],
                        "semantic_sha256": preparation["preparation_sha256"]},
        "capacity_preparations": capacity_rows,
        "resource_budgets": {host: verified_budgets[host] for host in host_ids},
        "complete": True, "qualification_eligible": False,
    }
    return {**body, "generation_sha256": _sha256(_canonical(body))}


def build_prepared_capacity_generation_bounded(
    preparation_pin: dict[str, Any],
    capacity_completion_pins: list[dict[str, Any]],
    resource_budget_pins: dict[str, Any],
    source_root: Path, input_root: Path, output: Path,
) -> dict[str, Any]:
    """Persist one independently replayed capacity-only preparation receipt."""
    checked_input = _safe_root(input_root, "capacity generation input root")
    _require(output == checked_input / "prepared-capacity-generation.json",
             "capacity generation output is outside its fixed private input location")
    value = replay_prepared_capacity_inputs_bounded(
        preparation_pin, capacity_completion_pins, resource_budget_pins,
        source_root, checked_input,
    )
    raw = _canonical(value)
    _require(len(raw) <= MAX_PLAN_BYTES,
             "capacity generation exceeds its finite metadata bound")
    _write_private_json_new(output, value, source_root, allow_existing_identical=True)
    return {"path": str(output), "raw_sha256": _sha256(raw),
            "semantic_sha256": value["generation_sha256"]}


def verify_prepared_capacity_generation_bounded(
    generation_pin: dict[str, Any], preparation_pin: dict[str, Any],
    source_root: Path, input_root: Path,
) -> dict[str, Any]:
    """Recompute the capacity-only receipt from every original producer input."""
    pin = _exact(generation_pin, {"path", "raw_sha256", "semantic_sha256"},
                 "prepared capacity generation pin")
    checked_input = _safe_root(input_root, "capacity generation input root")
    _require(pin["path"] == str(checked_input / "prepared-capacity-generation.json"),
             "capacity generation receipt is outside its fixed private input location")
    value, raw, raw_sha = _read_pinned_json(
        {"path": pin["path"], "sha256": pin["raw_sha256"]},
        "prepared capacity generation", MAX_PLAN_BYTES,
    )
    _exact(value, {"schema", "campaign_id", "preparation", "capacity_preparations",
                   "resource_budgets", "complete", "qualification_eligible",
                   "generation_sha256"}, "prepared capacity generation")
    body = {key: item for key, item in value.items() if key != "generation_sha256"}
    _require(value["schema"] == PREPARED_CAPACITY_GENERATION_SCHEMA and
             value["complete"] is True and value["qualification_eligible"] is False and
             raw == _canonical(value) and raw_sha == pin["raw_sha256"] and
             value["generation_sha256"] == pin["semantic_sha256"] == _sha256(_canonical(body)),
             "capacity generation schema, flags or raw/semantic pin differs")
    rows = value["capacity_preparations"]
    _require(type(rows) is list and len(rows) == 3,
             "capacity generation omits an original host")
    capacity_inputs = []
    for index, row in enumerate(rows):
        _exact(row, {"host_id", "completion", "host_verification", "evidence_path_map",
                     "completion_sha256", "ledger", "capacity_preparation_templates_sha256",
                     "entries", "resource_budget", "resource_monitor"},
               f"capacity generation host[{index}]")
        capacity_inputs.append({
            "host_id": row["host_id"], "completion_pin": row["completion"],
            "verification_receipt_pin": row["host_verification"],
            "evidence_path_map": row["evidence_path_map"],
        })
    replayed = replay_prepared_capacity_inputs_bounded(
        preparation_pin, capacity_inputs, value["resource_budgets"],
        source_root, checked_input,
    )
    _require(_canonical(replayed) == raw,
             "capacity generation differs from full original bounded capacity replay")
    return replayed


def _capacity_pilot_provider_map(
    providers: object, host_ids: list[str],
) -> Any:
    if providers is None:
        return None
    checked = _exact(providers, set(host_ids), "captured capacity-pilot provider cohort")
    _require(all(callable(getattr(value, "open_view", None)) for value in checked.values()),
             "captured capacity-pilot cohort contains an absent read provider")
    return types.MappingProxyType(dict(checked))


def complete_prepared_inputs(
    preparation_pin: dict[str, Any],
    capacity_completion_pins: list[dict[str, Any]],
    pressure_calibration_pins: list[dict[str, Any]],
    pilot_pins: list[dict[str, Any]],
    oracle_pins: list[dict[str, Any]],
    final_spec_pin: dict[str, Any],
    final_plan_pin: dict[str, Any],
    *, write_completion: bool = True,
    resource_budget_pins: dict[str, Any] | None = None,
    captured_pilot_read_providers: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Bridge independently replayed preparation evidence into final frozen inputs."""
    (
        prep_ref,
        input_root,
        source_root,
        preparation,
        sources,
        campaign,
        inputs,
        host_ids,
        bounded_preparation,
        capacity_by_host,
        completion_pin_by_host,
        capacity_entries,
        capacity_completions,
        completion_resource_budget_pins,
        expected_context_keys,
        prep_path,
    ) = _replay_prepared_capacity_inputs(
        preparation_pin, capacity_completion_pins, resource_budget_pins,
    )

    captured_pilot_providers = _capacity_pilot_provider_map(
        captured_pilot_read_providers, host_ids,
    )

    final_spec, final_spec_raw, final_spec_raw_sha = _read_pinned_json(final_spec_pin, "final completed SpecV3")
    final_plan, final_plan_raw, final_plan_raw_sha = _read_pinned_json(final_plan_pin, "final completed PlanV3", MAX_PLAN_BYTES)
    for label, pin_value in (("final SpecV3", final_spec_pin), ("final PlanV3", final_plan_pin)):
        final_path = Path(_exact(pin_value, {"path", "sha256"}, f"{label} raw pin")["path"])
        _require(final_path.is_absolute() and _within(input_root, final_path), f"{label} is outside the frozen private input root")
    _require(final_spec.get("schema") == campaign.SPEC_SCHEMA_V3 and final_plan.get("schema") == campaign.PLAN_SCHEMA_V3,
             "prepared-input bridge requires final SpecV3 and PlanV3")
    try:
        final_core = inputs.preparation_core_from_spec(final_spec)
    except Exception as error:
        raise PreparationError(f"final SpecV3 cannot be projected onto the frozen preparation core: {error}") from error
    _require(final_core == preparation["core"], "final SpecV3 changed a preparation-declared field")
    _verify_spec_source_refs(final_spec, preparation, sources)
    _require(final_spec.get("campaign_id") == preparation["core"]["campaign_id"] and
             final_plan.get("campaign_id") == final_spec["campaign_id"] and
             final_plan.get("spec_sha256") == campaign.digest_object(final_spec),
             "final SpecV3/PlanV3 campaign or raw semantic binding differs")
    try:
        final_validation = campaign.validate_spec(final_spec, sources, input_root)
        inputs_sha = campaign.campaign_inputs_source_sha256(sources)
        campaign.verify_plan(
            final_plan, sources[host_ids[0]]["runtime_readback_validator"]["sha256"], inputs_sha,
        )
        for phase in ("exploration", "aa", "confirmation"):
            _require(_canonical(final_plan.get("jobs", {}).get(phase)) == _canonical(campaign.build_jobs(final_spec, phase)),
                     f"final PlanV3 {phase} schedule differs from the unchanged controller")
    except Exception as error:
        raise PreparationError(f"final SpecV3/PlanV3 failed the unchanged SourceV5 validators: {error}") from error
    _require(final_validation.get("rates_frozen") is True and final_validation.get("oracles_frozen") is True and
             final_validation.get("plan_sha256") in (None, final_plan.get("plan_sha256")),
             "final SpecV3 rate/oracle slots are not complete")

    # Every final capacity input must cite the exact earlier TSV and producer
    # receipt, plus the host's complete pre-Spec ledger completion.
    final_templates = final_spec.get("qualification_inputs", {}).get("capacity_templates")
    _require(type(final_templates) is list and len(final_templates) == 45,
             "final SpecV3 capacity evidence matrix is incomplete")
    final_template_map: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in final_templates:
        key = (item["host_id"], item["workload"], item["profile"])
        _require(key not in final_template_map, "final SpecV3 capacity evidence repeats a context")
        final_template_map[key] = item
    preparation_template_map = {
        (item["host_id"], item["workload"], item["profile"]): item
        for item in preparation["capacity_templates"]
    }
    filled_capacity: list[dict[str, Any]] = []
    for frozen_template in preparation["capacity_templates"]:
        key = (frozen_template["host_id"], frozen_template["workload"], frozen_template["profile"])
        entry = capacity_entries[key]
        frozen_template = preparation_template_map[key]
        final_template = final_template_map.get(key)
        _require(final_template is not None and
                 final_template.get("calibration_id") == frozen_template["calibration_id"] and
                 final_template.get("calibrator") == frozen_template["calibrator"] and
                 final_template.get("request_template") == frozen_template["request_template"] and
                 final_template.get("context_template") == frozen_template["context_template"],
                 f"final SpecV3 changed the frozen capacity template for {key}")
        evidence = _exact(final_template.get("evidence"), {"artifact", "receipt", "stage_receipt"},
                           f"final SpecV3 capacity evidence {key}")
        prep_completion = completion_pin_by_host[key[0]]
        expected_evidence = {
            "artifact": _relative_input_pin(input_root, entry["artifact"]["path"], entry["artifact"]["sha256"], f"prepared TSV {key}"),
            "receipt": _relative_input_pin(input_root, entry["receipt"]["path"], entry["receipt"]["sha256"], f"prepared producer receipt {key}"),
            "stage_receipt": _relative_input_pin(input_root, prep_completion["path"], prep_completion["sha256"], f"prepared stage receipt {key}"),
        }
        _require(evidence == expected_evidence,
                 f"final SpecV3 capacity evidence does not register the exact prepared producer bytes for {key}")
        filled_capacity.append({
            "host_id": key[0], "capacity_key": entry["capacity_key"],
            "request_raw_sha256": entry["request"]["sha256"],
            "artifact_raw_sha256": entry["artifact"]["sha256"],
            "receipt_raw_sha256": entry["receipt"]["sha256"],
            "stage_completion_raw_sha256": prep_completion["sha256"],
        })

    # Replay the 45 host/context v2 scopes against each exact prepared TSV.
    _require(type(pressure_calibration_pins) is list and len(pressure_calibration_pins) == 45,
             "context pressure calibration set must cover all 45 host/workload/profile keys")
    pressure_reader_relative = "scripts/application-pressure-readback.py"
    pressure_reader_raw, pressure_reader_path, pressure_reader_record = _capture_typed_source_file(
        sources[host_ids[0]], source_root, pressure_reader_relative, "pressure-scope reader",
    )
    pressure_reader_sha = pressure_reader_record["sha256"]
    _require(all(value["modules"]["pressure_readback"]["sha256"] == pressure_reader_sha for value in preparation["source_pins"].values()),
             "active pressure reader differs from the full SourceV5 module pins")
    pressure_reader = _execute_captured_module(pressure_reader_raw, pressure_reader_path, "pressure_readback")
    verify_scope = getattr(pressure_reader, "verify_calibration_scope_v2_offline", None)
    _require(callable(verify_scope), "SourceV5 pressure reader has no mapped offline context-scope v2 replay")
    condition_map = {
        (item["host_id"], item["workload"], item["profile"]): item
        for item in preparation["condition_intensities"]
    }
    final_conditions = final_spec.get("qualification_inputs", {}).get("pressure_conditions")
    _require(type(final_conditions) is list and len(final_conditions) == 45,
             "final SpecV3 pressure-condition matrix is incomplete")
    final_condition_map = {
        (item["host_id"], item["capacity_key"]["workload"], item["capacity_key"]["profile"]): item
        for item in final_conditions
    }
    pressure_seen: set[tuple[str, str, str]] = set()
    pressure_records: list[dict[str, Any]] = []
    filled_pressure: list[dict[str, Any]] = []
    expected_pressure_order = [
        (item["host_id"], item["workload"], item["profile"])
        for item in preparation["condition_intensities"]
    ]
    for index, pin_value in enumerate(pressure_calibration_pins):
        record = _exact(pin_value, {
            "host_id", "condition_id", "capacity_key", "condition_pin", "context_policy_pin",
            "calibration_pin", "calibration_receipt_pin", "capacity_bundle_pin", "observed_host_pin",
            "evidence_path_map",
        }, f"context pressure calibration pin[{index}]")
        key = (record["host_id"], record["capacity_key"].get("workload"), record["capacity_key"].get("profile"))
        _require(key in expected_context_keys and key not in pressure_seen, "context calibration key is unknown or repeated")
        _require(key == expected_pressure_order[index], "context pressure calibration list changed the original intent condition order")
        pressure_seen.add(key)
        condition = condition_map[key]
        _require(record["condition_id"] == condition["condition_id"] and record["capacity_key"] == condition["capacity_key"],
                 f"context calibration[{index}] condition/key differs from the preparation")
        condition_abs = _safe_child(input_root, condition["condition"]["relative_path"], f"{key} frozen pressure condition")
        condition_pin = _exact(record["condition_pin"], {"path", "raw_sha256"}, f"{key} context condition raw pin")
        _require(Path(condition_pin["path"]).resolve(strict=True) == condition_abs and
                 condition_pin["raw_sha256"] == condition["condition"]["raw_sha256"],
                 f"{key} pressure scope changed the original condition file")
        context_policy_pin = _exact(record["context_policy_pin"], {"path", "raw_sha256"}, f"{key} context policy pin")
        calibration_pin = _exact(record["calibration_pin"], {"path", "raw_sha256"}, f"{key} context calibration pin")
        calibration_receipt_pin = _exact(record["calibration_receipt_pin"], {
            "path", "raw_sha256", "scope_sha256",
        }, f"{key} context-scope receipt pin")
        for role, pin in (("context policy", context_policy_pin), ("pressure calibration", calibration_pin), ("scope receipt", calibration_receipt_pin)):
            path = Path(pin["path"])
            _require(path.is_absolute() and type(pin["raw_sha256"]) is str and len(pin["raw_sha256"]) == 64,
                     f"{key} {role} raw pin is malformed")
            raw, _info = _read_stable(path, f"{key} {role}", MAX_REQUEST_BYTES)
            _require(_sha256(raw) == pin["raw_sha256"], f"{key} {role} bytes differ from the supplied raw pin")
        calibration_value, _calibration_raw, _calibration_raw_sha = _read_pinned_json(
            {"path": calibration_pin["path"], "sha256": calibration_pin["raw_sha256"]},
            f"{key} context pressure calibration",
        )
        _require(type(calibration_receipt_pin["scope_sha256"]) is str and len(calibration_receipt_pin["scope_sha256"]) == 64,
                 f"{key} context-scope semantic digest is malformed")
        observed_record = preparation["observed_hosts"][key[0]]
        observed_path = str(_safe_child(input_root, observed_record["relative_path"], f"{key[0]} observed host"))
        expected_observed_pin = {"path": observed_path, "raw_sha256": observed_record["raw_sha256"]}
        observed_pin = _exact(record["observed_host_pin"], {"path", "raw_sha256"}, f"{key} calibration observed-host pin")
        _require(observed_pin == expected_observed_pin, f"{key} calibration changed its original observed-host pin")
        entry = capacity_entries[key]
        source_manifest = preparation["source_pins"][key[0]]["manifest"]
        source_pin = {
            "path": str(_safe_child(input_root, source_manifest["relative_path"], f"{key[0]} SourceV5 manifest")),
            "raw_sha256": source_manifest["raw_sha256"],
        }
        expected_bundle_pin = capacity_bundle_pin(entry, source_pin)
        bundle_pin = _exact(record["capacity_bundle_pin"], {
            "schema", "capacity_key", "source_manifest", "request", "artifact", "receipt",
        }, f"{key} exact prepared capacity bundle pin")
        _require(bundle_pin == expected_bundle_pin,
                 f"{key} pressure calibration did not consume the exact earlier prepared TSV bundle")
        try:
            scope_receipt = verify_scope(
                calibration_pin, context_policy_pin, bundle_pin, observed_pin,
                source_root=str(source_root), evidence_path_map=record["evidence_path_map"],
                host_verification_pin=calibration_receipt_pin,
            )
        except Exception as error:
            raise PreparationError(f"{key} context pressure calibration failed independent v2 replay: {error}") from error
        scope_path = Path(calibration_receipt_pin["path"])
        scope_value, scope_raw, scope_actual = _read_pinned_json(
            {"path": str(scope_path), "sha256": calibration_receipt_pin["raw_sha256"]},
            f"{key} context pressure scope receipt",
        )
        scope_value = _exact(scope_value, PRESSURE_SCOPE_RECEIPT_KEYS, f"{key} v2 context-scope receipt")
        source_manifest_pin = preparation["source_pins"][key[0]]["manifest"]
        source_modules = preparation["source_pins"][key[0]]["modules"]
        source_harness = sources[key[0]]["qualification_harness"]
        observed_record = preparation["observed_hosts"][key[0]]
        calibration_body = {name: value for name, value in calibration_value.items() if name != "calibration_sha256"}
        expected_calibration_sha = _sha256(_canonical(calibration_body))
        expected_calibration_scope_sha = _sha256(_canonical(calibration_value["scope"]))
        receipt_body = {name: value for name, value in scope_value.items() if name != "receipt_sha256"}
        expected_scope_receipt_sha = _sha256(_canonical(receipt_body))
        expected_capacity_bundle_sha = _sha256(_canonical(bundle_pin))
        _require(type(scope_receipt) is dict and _canonical(scope_receipt) == scope_raw and
                 scope_value == scope_receipt and
                 scope_actual == calibration_receipt_pin["raw_sha256"] and
                 scope_value["schema"] == PRESSURE_SCOPE_RECEIPT_SCHEMA and
                 scope_value["replay_success"] is True and scope_value["validated"] is True and
                 scope_value["execution_ready"] is False and scope_value["qualification_eligible"] is False and
                 scope_value["controller_chronology_proven"] is False and
                 scope_value["receipt_sha256"] == expected_scope_receipt_sha and
                 scope_value["calibration_raw_sha256"] == calibration_pin["raw_sha256"] and
                 scope_value["scope_sha256"] == calibration_receipt_pin["scope_sha256"] and
                 scope_value["scope_sha256"] == expected_calibration_scope_sha and
                 scope_value["condition_id"] == condition["condition_id"] and
                 scope_value["pressure_calibration_id"] == condition["pressure_calibration_id"] and
                 scope_value["condition_sha256"] == condition_pin["raw_sha256"] and
                 scope_value["capacity_key"] == condition["capacity_key"] and
                 scope_value["source_manifest_sha256"] == bundle_pin["source_manifest"]["raw_sha256"] == source_manifest_pin["raw_sha256"] and
                 scope_value["source_manifest_semantic_sha256"] == source_manifest_pin["semantic_sha256"] and
                 scope_value["source_tree_sha256"] == source_manifest_pin["source_tree_sha256"] and
                 scope_value["context_policy_bundle_raw_sha256"] == context_policy_pin["raw_sha256"] and
                 type(scope_value["context_policy_artifact_raw_sha256"]) is str and len(scope_value["context_policy_artifact_raw_sha256"]) == 64 and
                 scope_value["capacity_bundle_pins_sha256"] == expected_capacity_bundle_sha and
                 scope_value["capacity_tsv_raw_sha256"] == bundle_pin["artifact"]["raw_sha256"] and
                 scope_value["observed_host_raw_sha256"] == observed_record["raw_sha256"] and
                 scope_value["driver_sha256"] == source_harness["pressure_driver"]["sha256"] and
                 scope_value["reader_sha256"] == source_harness["pressure_validator"]["sha256"] and
                 scope_value["capacity_producer_sha256"] == source_harness["byte_capacity_producer"]["sha256"] and
                 scope_value["feedback_reader_sha256"] == source_harness["feedback_validator"]["sha256"] and
                 scope_value["feedback_composer_sha256"] == source_modules["feedback_composer"]["sha256"] and
                 scope_value["calibration_sha256"] == calibration_value.get("calibration_sha256") == expected_calibration_sha and
                 scope_value["pressure_thresholds"] == condition["pressure_thresholds"] and
                 scope_value["readiness_thresholds"] == condition["readiness_thresholds"] and
                 type(scope_value["sample_count"]) is int and scope_value["sample_count"] > 0 and
                 type(scope_value["samples_sha256"]) is str and len(scope_value["samples_sha256"]) == 64 and
                 type(scope_value["summary"]) is dict and
                 type(scope_value["suggested_readiness_thresholds"]) is dict and
                 type(scope_value["worker_cleanup_sha256"]) is str and len(scope_value["worker_cleanup_sha256"]) == 64 and
                 scope_value["worker_session_count"] == len(condition["schedule"]["pressure_cpu_affinity"]) + 2 and
                 scope_value["scratch_file_removed"] is True,
                 f"{key} context-scope receipt file differs from independent v2 replay or original pins")
        context_policy_sha = scope_value["context_policy_sha256"]
        _require(type(context_policy_sha) is str and len(context_policy_sha) == 64 and
                 all(character in "0123456789abcdef" for character in context_policy_sha),
                 f"{key} verified scope receipt omits its stable numeric-policy/context digest")
        final_condition = final_condition_map.get(key)
        _require(final_condition is not None and
                 final_condition.get("condition_id") == condition["condition_id"] and
                 final_condition.get("condition_sha256") == condition["condition"]["raw_sha256"] and
                 final_condition.get("condition") == condition["condition"] and
                 final_condition.get("capacity_key") == condition["capacity_key"] and
                 final_condition.get("schedule") == {
                     "duration_seconds": condition["schedule"]["duration_seconds"],
                     "sample_interval_ms": condition["schedule"]["sample_interval_ms"],
                     "seed": condition["schedule"]["seed"],
                 } and final_condition.get("readiness_thresholds") == condition["readiness_thresholds"],
                 f"final SpecV3 changed the predeclared pressure condition identity/intensity for {key}")
        final_pressure_pin = final_condition.get("pressure_calibration")
        _require(type(final_pressure_pin) is dict and
                 final_pressure_pin.get("calibration_id") == condition["pressure_calibration_id"],
                 f"final SpecV3 pressure calibration ID differs for {key}")
        _require(final_pressure_pin.get("artifact") == _relative_input_pin(
                     input_root, calibration_pin["path"], calibration_pin["raw_sha256"], f"{key} v2 calibration artifact",
                 ) and final_pressure_pin.get("receipt") == _relative_input_pin(
                     input_root, scope_path, scope_actual, f"{key} v2 scope receipt",
                 ), f"final SpecV3 pressure calibration pins differ from the replayed v2 scope for {key}")
        pressure_output = {
            "host_id": key[0], "condition_id": condition["condition_id"],
            "pressure_calibration_id": condition["pressure_calibration_id"],
            "capacity_key": condition["capacity_key"],
            "condition_pin": condition_pin,
            "context_policy_pin": context_policy_pin,
            "calibration_pin": calibration_pin,
            "calibration_receipt_pin": calibration_receipt_pin,
            "observed_host_pin": observed_pin,
            "preparation_condition": {"path": condition_pin["path"], "raw_sha256": condition_pin["raw_sha256"]},
            "readiness_threshold_rule": condition["readiness_threshold_rule"],
            "readiness_thresholds": condition["readiness_thresholds"],
            "pressure_thresholds": condition["pressure_thresholds"],
            "context_policy": {
                "path": context_policy_pin["path"], "raw_sha256": context_policy_pin["raw_sha256"],
                "context_policy_sha256": context_policy_sha,
            },
            "calibration": {"path": calibration_pin["path"], "raw_sha256": calibration_pin["raw_sha256"]},
            "receipt": {"path": str(scope_path), "raw_sha256": scope_actual},
            "scope_receipt": {
                "path": str(scope_path), "raw_sha256": scope_actual,
                "scope_sha256": calibration_receipt_pin["scope_sha256"],
            },
            "evidence_path_map": record["evidence_path_map"],
            "context_policy_sha256": context_policy_sha,
            "capacity_bundle_pin": bundle_pin,
        }
        pressure_records.append(pressure_output)
        filled_pressure.append({
            "host_id": key[0], "condition_id": condition["condition_id"],
            "pressure_calibration_id": condition["pressure_calibration_id"],
            "capacity_key": condition["capacity_key"],
            "calibration_raw_sha256": calibration_pin["raw_sha256"],
            "scope_receipt_raw_sha256": scope_actual,
            "scope_sha256": calibration_receipt_pin["scope_sha256"],
            "capacity_artifact_raw_sha256": entry["artifact"]["sha256"],
        })
    _require(pressure_seen == expected_context_keys,
             "context pressure calibration set omits a host/workload/profile condition")

    # Replay each host's original 360 APP fixed-pair records through the same
    # exporter, then derive the unchanged six-pair 70/90 percent medians.
    _require(type(pilot_pins) is list and len(pilot_pins) == 3, "capacity pilot set must cover all three hosts")
    pilot_seen: set[str] = set()
    pilot_outputs: list[dict[str, Any]] = []
    derived_rates: dict[tuple[str, str, str, int], dict[str, Any]] = {}
    initial_spec_identity: tuple[str, str] | None = None
    for index, pin_value in enumerate(pilot_pins):
        pilot_input = _exact(pin_value, {
            "host_id", "manifest", "initial_spec", "initial_plan", "campaign_artifacts_root",
            "prepared_host_binding", "verified_fixed_records",
        }, f"capacity pilot pin[{index}]")
        host_id = pilot_input["host_id"]
        _require(host_id in sources and host_id not in pilot_seen, "capacity pilot host is unknown or repeated")
        _require(host_id == host_ids[index], "capacity pilot list changed the frozen host order")
        pilot_seen.add(host_id)
        manifest_pin = _exact(pilot_input["manifest"], {"path", "sha256"}, f"{host_id} pilot manifest pin")
        pilot, _pilot_raw, pilot_raw_sha = _read_pinned_json(manifest_pin, f"{host_id} capacity pilot manifest", MAX_MANIFEST_BYTES)
        initial_spec_pin = _exact(pilot_input["initial_spec"], {"path", "sha256"}, f"{host_id} original SpecV3 pin")
        initial_plan_pin = _exact(pilot_input["initial_plan"], {"path", "sha256"}, f"{host_id} original PlanV3 pin")
        initial_spec_value, _initial_spec_raw, initial_spec_sha = _read_pinned_json(initial_spec_pin, f"{host_id} original SpecV3")
        initial_plan_value, _initial_plan_raw, initial_plan_sha = _read_pinned_json(initial_plan_pin, f"{host_id} original PlanV3", MAX_PLAN_BYTES)
        identity = (initial_spec_sha, initial_plan_sha)
        _require(initial_spec_identity is None or initial_spec_identity == identity,
                 "host capacity pilots do not preserve one common original SpecV3/PlanV3 generation")
        initial_spec_identity = identity
        pilot_replay_kwargs = ({} if captured_pilot_providers is None else
                               {"captured_read_provider": captured_pilot_providers[host_id]})
        replayed_pin = export_capacity_pilot({
            "preparation": preparation_pin,
            "spec": initial_spec_pin,
            "plan": initial_plan_pin,
            "source_root": str(source_root),
            "input_root": str(input_root),
            "campaign_artifacts_root": pilot_input["campaign_artifacts_root"],
            "prepared_host_binding": pilot_input["prepared_host_binding"],
            "output": None,
        }, pilot_input["verified_fixed_records"], host_id, **pilot_replay_kwargs)
        _require(replayed_pin["raw_sha256"] == pilot_raw_sha and
                 replayed_pin["semantic_sha256"] == campaign.digest_object(pilot),
                 f"{host_id} pilot manifest differs from complete replay of its original fixed-pair receipts")
        rate_manifest = campaign.freeze_rates(final_spec, pilot, pilot_raw_sha)
        for rate in rate_manifest["rates"]:
            key = (host_id, rate["family"], rate["profile"], rate["load_percent"])
            _require(key not in derived_rates, f"capacity pilots repeat a frozen rate key: {key}")
            derived_rates[key] = {
                "host_id": host_id, "family": rate["family"], "profile": rate["profile"],
                "load_percent": rate["load_percent"], "arrivals_per_second": rate["arrivals_per_second"],
                "pilot_manifest_sha256": pilot_raw_sha,
            }
        pilot_outputs.append({
            "host_id": host_id,
            "campaign_artifacts_root": pilot_input["campaign_artifacts_root"],
            "prepared_host_binding": replayed_pin["prepared_host_binding"],
            "manifest": {"path": manifest_pin["path"], "raw_sha256": pilot_raw_sha},
            "semantic_sha256": campaign.digest_object(pilot),
            "initial_spec": {"path": initial_spec_pin["path"], "raw_sha256": initial_spec_sha,
                             "semantic_sha256": campaign.digest_object(initial_spec_value)},
            "initial_plan": {"path": initial_plan_pin["path"], "raw_sha256": initial_plan_sha,
                             "semantic_sha256": initial_plan_value["plan_sha256"]},
            "spec_preregistration_sha256": pilot["spec_sha256"],
            "fixed_pair_count": 360,
            "fixed_pair_evidence": replayed_pin["pair_evidence"],
            "fixed_pair_evidence_sha256": _sha256(_canonical(replayed_pin["pair_evidence"])),
            "replay_raw_sha256": replayed_pin["raw_sha256"],
        })
    _require(pilot_seen == set(host_ids) and len(derived_rates) == 3 * 15 * 2,
             "capacity pilot set does not produce the complete three-host 70/90 rate matrix")
    final_rate_map = {
        (item["host_id"], item["family"], item["profile"], item["load_percent"]): item
        for item in final_spec["rates"]
    }
    _require(final_rate_map == derived_rates,
             "final SpecV3 rates are not the deterministic original six-pair median/floor outputs")

    # Verify all producer-generated oracle rows and bind the complete 360-row
    # map by the original host manifest raw provenance.
    _require(type(oracle_pins) is list and len(oracle_pins) == 3, "oracle manifest set must cover all three hosts")
    oracle_seen: set[str] = set()
    oracle_outputs: list[dict[str, Any]] = []
    verified_oracles: dict[tuple[str, str, str, str, int], dict[str, Any]] = {}
    final_oracles = {
        (item["host_id"], item["allocator"], item["family"], item["profile"], item["load_percent"]): item
        for item in final_spec["oracles"]
    }
    for index, oracle_input_value in enumerate(oracle_pins):
        oracle_input = _exact(oracle_input_value, {"host_id", "manifest", "artifact_root"}, f"oracle pin[{index}]")
        host_id = oracle_input["host_id"]
        _require(host_id in sources and host_id not in oracle_seen, "oracle host is unknown or repeated")
        _require(host_id == host_ids[index], "oracle manifest list changed the frozen host order")
        oracle_seen.add(host_id)
        manifest_pin = _exact(oracle_input["manifest"], {"path", "sha256"}, f"{host_id} oracle manifest pin")
        manifest, _manifest_raw, manifest_raw_sha = _read_pinned_json(manifest_pin, f"{host_id} oracle manifest", MAX_MANIFEST_BYTES)
        body = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
        _require(manifest.get("schema") == "allocatbelt.application-oracle-manifest.v1" and
                 manifest.get("manifest_sha256") == campaign.digest_object(manifest) and
                 manifest.get("host_id") == host_id and manifest.get("campaign_id") == final_spec["campaign_id"] and
                 manifest.get("spec_preregistration_sha256") == campaign.preregistration_digest(final_spec) and
                 manifest.get("source_manifest_sha256") == sources[host_id]["manifest_sha256"],
                 f"{host_id} oracle manifest schema/source/spec identity is invalid")
        oracle_root = _safe_root(Path(oracle_input["artifact_root"]), f"{host_id} oracle artifact root")
        host_rates = {
            (item["family"], item["profile"], item["load_percent"]): item["arrivals_per_second"]
            for item in final_spec["rates"] if item["host_id"] == host_id
        }
        cell_map = {(cell["family"], cell["profile"]): cell for cell in final_spec["cells"]}
        expected_keys = {
            (host_id, allocator, cell["family"], cell["profile"], load)
            for cell in final_spec["cells"] for allocator in campaign.ALLOCATORS for load in campaign.LOADS
        }
        rows_by_key: dict[tuple[str, str, str, str, int], dict[str, Any]] = {}
        entries = manifest.get("oracles")
        _require(type(entries) is list and len(entries) == len(expected_keys), f"{host_id} oracle manifest does not contain all 120 references")
        for oracle_index, oracle_value in enumerate(entries):
            oracle = _exact(oracle_value, {"host_id", "allocator", "family", "profile", "load_percent", "relative_path", "sha256"}, f"{host_id} oracle[{oracle_index}]")
            key = (oracle["host_id"], oracle["allocator"], oracle["family"], oracle["profile"], oracle["load_percent"])
            _require(key in expected_keys and key not in rows_by_key, f"{host_id} oracle has an unknown or duplicate key")
            cell = cell_map[(oracle["family"], oracle["profile"])]
            rate = host_rates[(oracle["family"], oracle["profile"], oracle["load_percent"])]
            oracle_path = _safe_child(oracle_root, oracle["relative_path"], f"{host_id} oracle artifact")
            binary_sha = sources[host_id]["artifacts"][oracle["allocator"]]["sha256"]
            try:
                campaign.validate_oracle(
                    oracle_path, sources[host_id]["source"]["source_tree_sha256"], binary_sha,
                    cell["workload"], cell["profile"], rate, cell["arrivals"],
                )
            except Exception as error:
                raise PreparationError(f"{host_id} {oracle['allocator']} {oracle['family']}/{oracle['profile']}/{oracle['load_percent']} oracle failed deterministic producer validation: {error}") from error
            actual_sha = hashlib.sha256(oracle_path.read_bytes()).hexdigest()
            _require(actual_sha == oracle["sha256"], f"{host_id} oracle artifact raw bytes differ from its manifest")
            _require(final_oracles.get(key) == oracle, f"final SpecV3 oracle map differs from {host_id}'s producer manifest")
            rows_by_key[key] = oracle
            verified_oracles[key] = oracle
        _require(set(rows_by_key) == expected_keys, f"{host_id} oracle manifest matrix is incomplete")
        oracle_outputs.append({
            "host_id": host_id,
            "manifest": {"path": manifest_pin["path"], "raw_sha256": manifest_raw_sha},
            "artifact_root": str(oracle_root),
            "semantic_sha256": campaign.digest_object(manifest),
            "source_manifest_semantic_sha256": sources[host_id]["manifest_sha256"],
            "preregistration_sha256": manifest["spec_preregistration_sha256"],
            "oracle_count": len(rows_by_key), "oracles": list(entries),
        })
    _require(oracle_seen == set(host_ids) and len(verified_oracles) == 3 * 15 * 4 * 2,
             "oracle manifests do not establish the full 360-reference matrix")
    _require(final_oracles == verified_oracles, "final SpecV3 oracle map contains an unverified or substituted reference")

    final_plan_path = Path(_exact(final_plan_pin, {"path", "sha256"}, "final PlanV3 raw pin")["path"])
    output = final_plan_path.parent / "prepared-inputs-completion.json"
    source_outputs = {
        host_id: {
            "path": str(_safe_child(input_root, preparation["source_pins"][host_id]["manifest"]["relative_path"], f"{host_id} SourceV5 manifest")),
            "raw_sha256": preparation["source_pins"][host_id]["manifest"]["raw_sha256"],
            "semantic_sha256": preparation["source_pins"][host_id]["manifest"]["semantic_sha256"],
            "source_tree_sha256": preparation["source_pins"][host_id]["manifest"]["source_tree_sha256"],
        }
        for host_id in host_ids
    }
    all_final_rates = [dict(item) for item in final_spec["rates"]]
    all_final_oracles = [dict(item) for item in final_spec["oracles"]]
    body: dict[str, Any] = {
        "schema": (PREPARED_BOUNDED_COMPLETION_SCHEMA if bounded_preparation
                   else PREPARED_COMPLETION_SCHEMA),
        "complete": True,
        "qualification_eligible": False,
        "campaign_id": preparation["core"]["campaign_id"],
        "preparation": {
            "path": str(prep_path), "raw_sha256": prep_ref["sha256"],
            "semantic_sha256": preparation["preparation_sha256"],
        },
        "final_spec": {
            "path": final_spec_pin["path"], "raw_sha256": final_spec_raw_sha,
            "semantic_sha256": campaign.digest_object(final_spec),
            "preregistration_sha256": campaign.preregistration_digest(final_spec),
        },
        "final_plan": {
            "path": final_plan_pin["path"], "raw_sha256": final_plan_raw_sha,
            "semantic_sha256": final_plan["plan_sha256"],
        },
        "source_manifests": source_outputs,
        "capacity_preparations": capacity_completions,
        "pressure_calibrations": pressure_records,
        "pilots": pilot_outputs,
        "oracles": oracle_outputs,
        "filled_slots": {
            "capacity_evidence": filled_capacity,
            "pressure_calibrations": filled_pressure,
            "rates": all_final_rates,
            "oracles": all_final_oracles,
        },
        "ledger_heads": [
            {"host_id": item["host_id"],
             "schema": ("allocatbelt.application-capacity-preparation-event.v2"
                        if bounded_preparation else
                        "allocatbelt.application-capacity-preparation-event.v1"),
             "raw_sha256": item["ledger"]["raw_sha256"], "terminal_head": item["ledger"]["terminal_head"]}
            for item in capacity_completions
        ],
    }
    if bounded_preparation:
        body["resource_budgets"] = {
            host_id: completion_resource_budget_pins[host_id]
            for host_id in host_ids
        }
    completion = {**body, "completion_sha256": _sha256(_canonical(body))}
    if write_completion:
        _write_private_json_new(output, completion, source_root, allow_existing_identical=True)
    raw_sha = _sha256(_canonical(completion))
    result = {"path": str(output), "raw_sha256": raw_sha, "semantic_sha256": completion["completion_sha256"],
              "schema": completion["schema"], "campaign_id": completion["campaign_id"],
              "complete": True, "qualification_eligible": False}
    if not write_completion:
        result["replayed_completion"] = completion
    return result


def complete_prepared_inputs_bounded(
    preparation_pin: dict[str, Any],
    capacity_completion_pins: list[dict[str, Any]],
    resource_budget_pins: dict[str, Any],
    pressure_calibration_pins: list[dict[str, Any]],
    pilot_pins: list[dict[str, Any]],
    oracle_pins: list[dict[str, Any]],
    final_spec_pin: dict[str, Any], final_plan_pin: dict[str, Any],
    *, write_completion: bool = True,
    captured_pilot_read_providers: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Bridge only independently replayed v2 bounded capacity completions."""
    _require(type(capacity_completion_pins) is list and len(capacity_completion_pins) == 3,
             "bounded preparation bridge requires the complete three-host capacity set")
    _require(type(resource_budget_pins) is dict and len(resource_budget_pins) == 3,
             "bounded preparation bridge requires one caller-frozen budget per host")
    bounded_capacity_inputs: list[dict[str, Any]] = []
    for index, value in enumerate(capacity_completion_pins):
        item = _exact(value, {
            "host_id", "completion_pin", "verification_receipt_pin", "evidence_path_map",
        }, f"bounded capacity preparation input[{index}]")
        host_id = item["host_id"]
        budget_pin = _exact(resource_budget_pins.get(host_id),
                            {"path", "raw_sha256", "semantic_sha256"},
                            f"{host_id} bounded resource budget pin")
        bounded_capacity_inputs.append({**item, "resource_budget_pin": budget_pin})
    captured_kwargs = ({} if captured_pilot_read_providers is None else
                       {"captured_pilot_read_providers": captured_pilot_read_providers})
    return complete_prepared_inputs(
        preparation_pin, bounded_capacity_inputs, pressure_calibration_pins,
        pilot_pins, oracle_pins, final_spec_pin, final_plan_pin,
        write_completion=write_completion, resource_budget_pins=resource_budget_pins,
        **captured_kwargs,
    )


def _prepared_input_replay_arguments(completion: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Reconstruct original verifier inputs without changing any raw pin."""
    _require(type(completion.get("capacity_preparations")) is list and len(completion["capacity_preparations"]) == 3 and
             type(completion.get("pressure_calibrations")) is list and len(completion["pressure_calibrations"]) == 45 and
             type(completion.get("pilots")) is list and len(completion["pilots"]) == 3 and
             type(completion.get("oracles")) is list and len(completion["oracles"]) == 3,
             "prepared-input completion omits a host or context evidence generation")
    capacity_inputs: list[dict[str, Any]] = []
    resource_budget_pins: dict[str, Any] = {}
    bounded_completion = completion.get("schema") == PREPARED_BOUNDED_COMPLETION_SCHEMA
    for index, record_value in enumerate(completion["capacity_preparations"]):
        record_fields = {
            "host_id", "completion", "host_verification", "evidence_path_map", "completion_sha256",
            "ledger", "capacity_preparation_templates_sha256", "entries",
        }
        if bounded_completion:
            record_fields |= {"resource_budget", "resource_monitor"}
        record = _exact(record_value, record_fields,
                        f"prepared-input capacity completion[{index}]")
        completion_file = _exact(record["completion"], {"path", "raw_sha256"}, f"capacity completion[{index}] raw pin")
        host_receipt = _exact(record["host_verification"], {
            "path", "raw_sha256", "receipt_sha256",
        }, f"capacity host-local verifier receipt[{index}] pin")
        capacity_input = {
            "host_id": record["host_id"],
            "completion_pin": {"path": completion_file["path"], "raw_sha256": completion_file["raw_sha256"]},
            "verification_receipt_pin": host_receipt,
            "evidence_path_map": record["evidence_path_map"],
        }
        if bounded_completion:
            budget_pin = _exact(record["resource_budget"],
                                {"path", "raw_sha256", "semantic_sha256"},
                                f"prepared-input capacity budget[{index}]")
            _require(record["resource_monitor"].get("schema") ==
                     "allocatbelt.application-capacity-preparation-resource-monitor.v1",
                     f"prepared-input capacity monitor[{index}] schema is unsupported")
            capacity_input["resource_budget_pin"] = budget_pin
            _require(record["host_id"] not in resource_budget_pins,
                     "prepared-input completion repeats a host resource budget")
            resource_budget_pins[record["host_id"]] = budget_pin
        capacity_inputs.append(capacity_input)

    pressure_inputs: list[dict[str, Any]] = []
    pressure_input_fields = {
        "host_id", "condition_id", "capacity_key", "condition_pin", "context_policy_pin",
        "calibration_pin", "calibration_receipt_pin", "observed_host_pin", "capacity_bundle_pin",
        "evidence_path_map",
    }
    for index, record_value in enumerate(completion["pressure_calibrations"]):
        record = _exact(record_value, {
            "host_id", "condition_id", "pressure_calibration_id", "capacity_key", "condition_pin",
            "context_policy_pin", "calibration_pin", "calibration_receipt_pin", "observed_host_pin",
            "preparation_condition", "readiness_threshold_rule", "readiness_thresholds", "pressure_thresholds",
            "context_policy", "calibration", "receipt", "scope_receipt", "context_policy_sha256",
            "capacity_bundle_pin", "evidence_path_map",
        }, f"prepared-input pressure calibration[{index}]")
        reconstructed = {key: record[key] for key in pressure_input_fields if key in record}
        _require(set(reconstructed) == pressure_input_fields,
                 f"prepared-input pressure calibration[{index}] omits original raw pins")
        pressure_inputs.append(reconstructed)

    pilot_inputs: list[dict[str, Any]] = []
    for index, record_value in enumerate(completion["pilots"]):
        record = _exact(record_value, {
            "host_id", "campaign_artifacts_root", "manifest", "semantic_sha256", "initial_spec", "initial_plan",
            "prepared_host_binding", "spec_preregistration_sha256", "fixed_pair_count", "fixed_pair_evidence",
            "fixed_pair_evidence_sha256", "replay_raw_sha256",
        }, f"prepared-input pilot[{index}]")
        prepared_host_binding = _validate_prepared_fixed_host_binding(record["prepared_host_binding"])
        pair_evidence = record["fixed_pair_evidence"]
        _require(type(pair_evidence) is list and len(pair_evidence) == 360,
                 f"prepared-input pilot[{index}] does not preserve every original pair pin")
        verified_fixed_records = []
        for pair_index, pair_value in enumerate(pair_evidence):
            pair = _exact(pair_value, {
                "host_id", "run_id", "family", "profile", "allocator", "ordinal",
                "overlay", "receipt", "host_verification", "prepared_host_binding_sha256",
                "evidence_path_map", "raw_pair_sha256",
            }, f"pilot[{index}] fixed-pair evidence[{pair_index}]")
            _require(pair["prepared_host_binding_sha256"] == prepared_host_binding["binding_sha256"],
                     f"pilot[{index}] pair[{pair_index}] lost its dual observed-host binding")
            overlay = _exact(pair["overlay"], {"path", "raw_sha256"}, "fixed-pair overlay raw pin")
            receipt = _exact(pair["receipt"], {"path", "raw_sha256"}, "fixed-pair receipt raw pin")
            host_verification = _exact(pair["host_verification"], {
                "path", "raw_sha256", "host_verification_sha256",
            }, "fixed-pair host-verification raw pin")
            verified_fixed_records.append({
                "overlay": {"path": overlay["path"], "sha256": overlay["raw_sha256"]},
                "receipt": {"path": receipt["path"], "sha256": receipt["raw_sha256"]},
                "host_verification": host_verification,
                "evidence_path_map": pair["evidence_path_map"],
            })
        manifest = _exact(record["manifest"], {"path", "raw_sha256"}, f"pilot[{index}] manifest pin")
        initial_spec = _exact(record["initial_spec"], {"path", "raw_sha256", "semantic_sha256"}, f"pilot[{index}] original Spec pin")
        initial_plan = _exact(record["initial_plan"], {"path", "raw_sha256", "semantic_sha256"}, f"pilot[{index}] original Plan pin")
        pilot_inputs.append({
            "host_id": record["host_id"],
            "campaign_artifacts_root": record["campaign_artifacts_root"],
            "prepared_host_binding": record["prepared_host_binding"],
            "manifest": {"path": manifest["path"], "sha256": manifest["raw_sha256"]},
            "initial_spec": {"path": initial_spec["path"], "sha256": initial_spec["raw_sha256"]},
            "initial_plan": {"path": initial_plan["path"], "sha256": initial_plan["raw_sha256"]},
            "verified_fixed_records": verified_fixed_records,
        })

    oracle_inputs: list[dict[str, Any]] = []
    for index, record_value in enumerate(completion["oracles"]):
        record = _exact(record_value, {
            "host_id", "manifest", "artifact_root", "semantic_sha256", "source_manifest_semantic_sha256",
            "preregistration_sha256", "oracle_count", "oracles",
        }, f"prepared-input oracle manifest[{index}]")
        manifest = _exact(record["manifest"], {"path", "raw_sha256"}, f"oracle manifest[{index}] raw pin")
        oracle_inputs.append({
            "host_id": record["host_id"],
            "manifest": {"path": manifest["path"], "sha256": manifest["raw_sha256"]},
            "artifact_root": record["artifact_root"],
        })
    result = {
        "capacity_completion_pins": capacity_inputs,
        "pressure_calibration_pins": pressure_inputs,
        "pilot_pins": pilot_inputs,
        "oracle_pins": oracle_inputs,
    }
    if bounded_completion:
        result["resource_budget_pins"] = resource_budget_pins
    return result


def verify_prepared_inputs_completion(
    completion_pin: dict[str, Any], provenance_pins: dict[str, Any],
    source_root: Path, input_root: Path, *,
    captured_pilot_read_providers: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Read-only replay of a frozen preparation-completion receipt.

    All producer and host-verification pins are reconstructed from the closed
    completion body, while the caller separately supplies the original
    preparation, final SpecV3 and final PlanV3 raw pins. The normal completion
    replay then revalidates every capacity, pressure, six-pair pilot and oracle
    artifact before comparing the complete canonical body byte-for-byte.
    """
    completion_ref = _exact(completion_pin, {
        "path", "raw_sha256", "semantic_sha256",
    }, "prepared-input completion pin")
    completion, completion_raw, completion_raw_sha = _read_pinned_json(
        {"path": completion_ref["path"], "sha256": completion_ref["raw_sha256"]},
        "prepared-input completion", MAX_PLAN_BYTES,
    )
    exact_completion_keys = {
        "schema", "complete", "qualification_eligible", "campaign_id", "preparation",
        "final_spec", "final_plan", "source_manifests", "capacity_preparations",
        "pressure_calibrations", "pilots", "oracles", "filled_slots", "ledger_heads",
        "completion_sha256",
    }
    bounded_completion = completion.get("schema") == PREPARED_BOUNDED_COMPLETION_SCHEMA
    if bounded_completion:
        exact_completion_keys.add("resource_budgets")
    _exact(completion, exact_completion_keys, "prepared-input completion body")
    body = {key: value for key, value in completion.items() if key != "completion_sha256"}
    expected_completion_schema = (PREPARED_BOUNDED_COMPLETION_SCHEMA if bounded_completion
                                  else PREPARED_COMPLETION_SCHEMA)
    _require(completion["schema"] == expected_completion_schema and completion["complete"] is True and
             completion["qualification_eligible"] is False and
             completion["completion_sha256"] == completion_ref["semantic_sha256"] == _sha256(_canonical(body)) and
             completion_raw_sha == completion_ref["raw_sha256"],
             "prepared-input completion schema, raw/semantic digest or ineligibility differs")
    provenance = _exact(provenance_pins, {
        "schema", "preparation_pin", "final_spec_pin", "final_plan_pin",
    }, "prepared-input provenance pins")
    _require(provenance["schema"] == "allocatbelt.application-source5-prepared-inputs-provenance.v1",
             "unsupported prepared-input provenance schema")
    preparation_pin = _exact(provenance["preparation_pin"], {"path", "raw_sha256"}, "preparation raw pin")
    final_spec_pin = _exact(provenance["final_spec_pin"], {"path", "raw_sha256"}, "final SpecV3 raw pin")
    final_plan_pin = _exact(provenance["final_plan_pin"], {"path", "raw_sha256"}, "final PlanV3 raw pin")
    source_root_checked = _safe_root(source_root, "prepared-input replay SourceV5 root")
    input_root_checked = _safe_root(input_root, "prepared-input replay input root")
    preparation_path = Path(preparation_pin["path"])
    _require(source_root_checked == _safe_root(SOURCE_ROOT, "active SourceV5 root") and
             preparation_path.is_absolute(),
             "prepared-input replay SourceV5 root or preparation path is invalid")
    _require(input_root_checked == preparation_path.parent.resolve(strict=True),
             "prepared-input replay input root differs from the pinned preparation generation")
    for role, pin_value, recorded in (
        ("preparation", preparation_pin, completion["preparation"]),
        ("final SpecV3", final_spec_pin, completion["final_spec"]),
        ("final PlanV3", final_plan_pin, completion["final_plan"]),
    ):
        _require(pin_value["path"] == recorded["path"] and pin_value["raw_sha256"] == recorded["raw_sha256"],
                 f"prepared-input completion {role} path/raw pin differs from supplied generation provenance")

    replay_arguments = _prepared_input_replay_arguments(completion)
    try:
        replay_kwargs = {"write_completion": False}
        if captured_pilot_read_providers is not None:
            replay_kwargs["captured_pilot_read_providers"] = captured_pilot_read_providers
        if bounded_completion:
            _require(replay_arguments.get("resource_budget_pins") == completion["resource_budgets"],
                     "prepared-input bounded budget map differs from its per-host capacity records")
            replay_kwargs["resource_budget_pins"] = completion["resource_budgets"]
        replay = complete_prepared_inputs(
            {"path": preparation_pin["path"], "sha256": preparation_pin["raw_sha256"]},
            replay_arguments["capacity_completion_pins"],
            replay_arguments["pressure_calibration_pins"],
            replay_arguments["pilot_pins"], replay_arguments["oracle_pins"],
            {"path": final_spec_pin["path"], "sha256": final_spec_pin["raw_sha256"]},
            {"path": final_plan_pin["path"], "sha256": final_plan_pin["raw_sha256"]},
            **replay_kwargs,
        )
    except Exception as error:
        raise PreparationError(f"prepared-input completion failed its independent offline evidence replay: {error}") from error
    expected = replay.get("replayed_completion")
    _require(type(expected) is dict and _canonical(expected) == completion_raw and
             replay.get("raw_sha256") == completion_raw_sha and
             replay.get("semantic_sha256") == completion_ref["semantic_sha256"] and
             replay.get("path") == completion_ref["path"],
             "prepared-input completion differs from deterministic replay of its frozen provenance pins")
    return completion


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build-intent", help="verify SourceV5 and freeze the pre-Spec intent")
    build.add_argument("--request", type=Path, required=True)
    build.add_argument("--request-sha256", required=True)
    build.add_argument("--source-root", type=Path, required=True)
    build.add_argument("--input-root", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify-intent", help="replay the preparation intent and its real source pins")
    verify.add_argument("--intent", type=Path, required=True)
    verify.add_argument("--intent-sha256", required=True)
    verify.add_argument("--source-root", type=Path, required=True)
    verify.add_argument("--input-root", type=Path, required=True)
    completion = commands.add_parser("verify-completion", help="offline replay the prepared final input generation")
    completion.add_argument("--completion", type=Path, required=True)
    completion.add_argument("--completion-raw-sha256", required=True)
    completion.add_argument("--completion-semantic-sha256", required=True)
    completion.add_argument("--preparation", type=Path, required=True)
    completion.add_argument("--preparation-sha256", required=True)
    completion.add_argument("--final-spec", type=Path, required=True)
    completion.add_argument("--final-spec-sha256", required=True)
    completion.add_argument("--final-plan", type=Path, required=True)
    completion.add_argument("--final-plan-sha256", required=True)
    completion.add_argument("--source-root", type=Path, required=True)
    completion.add_argument("--input-root", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "build-intent":
            result = build_preparation_intent(
                {"path": str(args.request), "sha256": args.request_sha256},
                args.source_root, args.input_root, args.output,
            )
        elif args.command == "verify-intent":
            intent, sources, _campaign, inputs = read_preparation_intent(
                {"path": str(args.intent), "sha256": args.intent_sha256}, args.source_root, args.input_root,
            )
            result = inputs.validate_preparation_intent(intent, sources, args.input_root)
        else:
            result = verify_prepared_inputs_completion(
                {
                    "path": str(args.completion),
                    "raw_sha256": args.completion_raw_sha256,
                    "semantic_sha256": args.completion_semantic_sha256,
                },
                {
                    "schema": "allocatbelt.application-source5-prepared-inputs-provenance.v1",
                    "preparation_pin": {"path": str(args.preparation), "raw_sha256": args.preparation_sha256},
                    "final_spec_pin": {"path": str(args.final_spec), "raw_sha256": args.final_spec_sha256},
                    "final_plan_pin": {"path": str(args.final_plan), "raw_sha256": args.final_plan_sha256},
                },
                args.source_root, args.input_root,
            )
        sys.stdout.buffer.write(_canonical(result))
        return 0
    except (PreparationError, OSError, ValueError, TypeError, KeyError, UnicodeError) as error:
        print(f"application Source5 input preparation: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
