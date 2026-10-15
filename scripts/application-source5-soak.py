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
import time
import types
from pathlib import Path, PurePosixPath
from typing import Any


MATERIALS_SCHEMA = "allocatbelt.application-source5-soak-materials.v1"
MATERIALS_INDEX_SCHEMA = "allocatbelt.application-source5-soak-materials-index.v1"
COMPONENT_SCHEMA = "allocatbelt.application-source5-soak-component.v1"
LAUNCH_AUTHORIZATION_SCHEMA = "allocatbelt.application-source5-soak-launch-authorization.v1"
LAUNCH_AUTHORIZATION_SCHEMA_V2 = "allocatbelt.application-source5-soak-launch-authorization.v2"
POSTFLIGHT_SCHEMA = "allocatbelt.application-source5-soak-postflight.v1"
AUDIT_PROJECTION_SCHEMA = "allocatbelt.application-source5-soak-audit-projection.v1"
MODULE_CLOSURE_SCHEMA = "allocatbelt.application-source5-captured-module-closure.v1"
READBACK_SCHEMA = "allocatbelt.application-soak-readback.v2"
RECIPE_SCHEMA = "allocatbelt.application-soak-parent-recipe.v2"
BUILD_RECEIPT_SCHEMA = "allocatbelt.application-soak-recipe-build-receipt.v2"
HOST_VERIFICATION_SCHEMA = "allocatbelt.application-source5-soak-host-verification.v2"
PROBE_CAPTURE_SCHEMA = "allocatbelt.application-source5-soak-probe-capture.v1"
SOAK_OFFLINE_CONTEXT_SCHEMA = "allocatbelt.application-source5-soak-offline-replay-context.v1"
EVIDENCE_PATH_MAP_SCHEMA = "allocatbelt.application-pressure-evidence-path-map.v1"
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_SCRIPT_BYTES = 8 * 1024 * 1024
MAX_RECIPE_BYTES = 16 * 1024 * 1024
MAX_RECEIPT_BYTES = 32 * 1024 * 1024
MAX_EVIDENCE_ENTRIES = 250_000


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
) -> dict[str, Any]:
    """Make the closed index from the exact externally built original recipe."""
    recipe_pin = raw_pin(parent_recipe_pin, "Source5 parent Soak recipe")
    receipt_pin = raw_pin(build_receipt_pin, "Source5 Soak recipe-build receipt")
    digest(prepared_host_binding_sha256, "prepared fixed-pair host-binding SHA-256")
    body = {
        "schema": MATERIALS_INDEX_SCHEMA,
        "campaign_id": campaign_id,
        "host_id": host_id,
        "job": job,
        "job_sha256": sha256(canonical_bytes(job)),
        "parent_recipe": recipe_pin,
        "build_receipt": receipt_pin,
        "prepared_host_binding_sha256": prepared_host_binding_sha256,
    }
    return {**body, "materials_sha256": sha256(canonical_bytes(body))}


def validate_material_index(
    value: object, campaign_id: str, host_id: str, job: dict[str, Any],
    prepared_host_binding_sha256: str,
) -> dict[str, Any]:
    """Validate the complete closed ordinal/material binding before preflight."""
    index = exact(value, {
        "schema", "campaign_id", "host_id", "job", "job_sha256",
        "parent_recipe", "build_receipt", "prepared_host_binding_sha256",
        "materials_sha256",
    }, "Source5 Soak materials index")
    body = {key: item for key, item in index.items()
            if key != "materials_sha256"}
    digest(prepared_host_binding_sha256,
           "prepared fixed-pair host-binding SHA-256")
    require(index["schema"] == MATERIALS_INDEX_SCHEMA and
            index["campaign_id"] == campaign_id and
            index["host_id"] == host_id and index["job"] == job and
            index["job_sha256"] == sha256(canonical_bytes(job)) and
            index["prepared_host_binding_sha256"] == prepared_host_binding_sha256 and
            index["materials_sha256"] == sha256(canonical_bytes(body)),
            "Source5 Soak materials index does not bind its exact original host/job/preparation")
    raw_pin(index["parent_recipe"], "Source5 parent Soak recipe")
    raw_pin(index["build_receipt"], "Source5 Soak recipe-build receipt")
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
    require(recipe["schema"] == RECIPE_SCHEMA and
            recipe["runtime"]["mode"] == "qualified" and
            recipe["runtime"]["duration_seconds"] == 10_800 and
            job["duration_seconds"] == 10_800 and
            job["phase"] == "soak" and job["host_id"] == prepared["host_id"] and
            job["run_id"] == recipe["identity"]["run_id"] and
            details["phase"] == "soak" and
            details["members"] == [soak_descriptor(job)],
            "Source5 launch overlay is outside the exact original qualified Soak job")
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
    require(launch_descriptor.get("launch_enabled") is True and
            launch_descriptor.get("execution_scope") == "qualification" and
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
        "schema": (LAUNCH_AUTHORIZATION_SCHEMA_V2
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
    # The captured reader independently rebuilds Spec/Plan/source/ring/probe/
    # pressure context and persists its preflight. This path does not launch.
    with contextlib.redirect_stdout(io.StringIO()):
        status = readback.command_preflight(args)
    require(status == 0, "captured Soak V2 preflight refused the original inputs")
    audit, preflight = readback._current_audit(args)
    require(audit["recipe"]["schema"] == RECIPE_SCHEMA and
            audit["identity"]["run_id"] == job["run_id"] and
            audit["launch_enabled"] is False and
            audit["mode"] == "qualified" and
            audit["duration_seconds"] == 10_800,
            "captured Soak V2 legacy audit is not false for the exact original 10,800-second job")
    preflight_path = output_dir / "soak-preflight.json"
    preflight_pin_raw, preflight_sha, _preflight_info = read_stable(
        preflight_path, "Source5 Soak preflight receipt", MAX_RECEIPT_BYTES,
    )
    require(json.loads(preflight_pin_raw) == readback._preflight_report(audit) and
            preflight_pin_raw == canonical_bytes(json.loads(preflight_pin_raw)),
            "captured Soak V2 preflight file differs from its recomputed report")
    launch_overlay, overlay_audit, overlay_preflight = \
        build_source5_launch_overlay(
            helper_input, prepared, details, material_index, binding, recipe,
            identities, args, audit, preflight, readback,
        )
    overlay_path = output_dir / "source5-soak-launch-authorization.json"
    launch_overlay_pin = _write_exclusive_json(
        overlay_path, launch_overlay,
        "Source5 Soak-only launch authorization overlay",
    )
    launch_args = types.SimpleNamespace(**vars(args))
    launch_args.command = ["--", *overlay_audit["launch_descriptor"]["argv"]]
    launch_args.timeout_seconds = overlay_audit["source"]["application_supervision"][
        "application_wall_timeout_seconds"]
    launch_args.term_grace_seconds = 1.5
    return {
        "schema": "allocatbelt.application-source5-soak-preflight.v1",
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
                 "_bounded_tmpdir_monitor", "_mount_identity", "_mount_static"):
        require(callable(getattr(module, name, None)),
                f"SourceV5 fixed process owner omits {name}")
    return module, actual, path


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
            callable(getattr(module, "_pressure_absolute_json_paths", None)) and
            type(getattr(module, "MAX_EVENTS_BYTES", None)) is int,
            "Source5 pressure reader lacks its typed Soak replay APIs")
    return module, actual, path


def _capture_source5_soak_probe(
    prepared: dict[str, Any], job: dict[str, Any], binding: dict[str, Any],
    recipe: dict[str, Any], readback: types.ModuleType, capture_root_value: object,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Capture the SourceV5 ProbeV1 on-origin with the accepted process owner."""
    capture_root = Path(str(capture_root_value))
    require(capture_root.is_absolute() and ".." not in capture_root.parts and
            not capture_root.exists() and not capture_root.is_symlink(),
            "Source5 Soak probe capture root must be fresh and normalized")
    parent = capture_root.parent
    parent_info = parent.stat()
    require(stat.S_ISDIR(parent_info.st_mode) and parent_info.st_uid == os.getuid() and
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
    tmpdir_initial = owner._prepare_member_tmpdir(tmpdir, capture_root, budgets)
    byte_limit = budgets["tmpdir_bytes"]
    inode_limit = budgets["tmpdir_inodes"]
    output_byte_bound = (
        budgets["construction_probe_stdout_bytes"] +
        budgets["construction_probe_stderr_bytes"] +
        2 * budgets["runtime_receipt_bytes"]
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
    direct = owner._run_direct_process(
        argv, normal_path, normal_sha, source_root, environment, affinity,
        stdout_path, stderr_path, owner.MAX_PROBE_STDOUT_BYTES,
        owner.MAX_PROBE_STDERR_BYTES, owner.PROBE_TIMEOUT_SECONDS, readback,
        expected_tmpdir=tmpdir, expected_network_inode=network_inode,
        capture_identity=False,
        resource_monitor=owner._bounded_tmpdir_monitor(
            tmpdir, byte_limit, inode_limit, tmpdir_initial,
        ),
    )
    stdout_raw, stdout_sha, _stdout_info = read_stable(
        stdout_path, "Source5 Soak captured ProbeV1 stdout",
        owner.MAX_PROBE_STDOUT_BYTES,
    )
    stderr_raw, stderr_sha, _stderr_info = read_stable(
        stderr_path, "Source5 Soak captured ProbeV1 stderr",
        owner.MAX_PROBE_STDERR_BYTES,
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
            "owner_receipt_bytes": budgets["runtime_receipt_bytes"],
            "capture_receipt_bytes": budgets["runtime_receipt_bytes"],
        },
        "process_absence": {
            "pid": direct["start"]["pid"],
            "start_ticks": direct["start"]["start_ticks"],
            "original_identity_absent": True,
            "observed_start_ticks": probe_after_start,
        },
    }
    capture["capture_sha256"] = sha256(canonical_bytes(capture))
    require(len(canonical_bytes(capture)) <= budgets["runtime_receipt_bytes"],
            "Source5 ProbeV1 capture receipt exceeded its frozen receipt budget")
    capture_pin = _write_exclusive_json(
        capture_root / "probe-capture.json", capture,
        "Source5 Soak ProbeV1 capture receipt",
    )
    capture_pin["capture_sha256"] = capture["capture_sha256"]
    return capture, capture_pin


def run_source5_soak(
    preflight_value: dict[str, Any], on_started, on_cleanup,
) -> dict[str, Any]:
    """Launch the one original APP through the captured V2 callback API."""
    preflight = exact(preflight_value, {
        "schema", "materials_index", "materials_index_pin", "helper_input",
        "parent_recipe",
        "parent_recipe_pin", "build_receipt_pin", "identities", "audit",
        "preflight", "preflight_pin", "launch_overlay", "launch_overlay_pin",
        "base_audit", "base_audit_sha256", "args", "output_dir",
        "readback_module", "prepared", "details",
    }, "Source5 Soak preflight context")
    require(preflight["schema"] ==
            "allocatbelt.application-source5-soak-preflight.v1" and
            callable(on_started) and callable(on_cleanup),
            "Source5 Soak launch lacks its preflight or lifecycle callbacks")
    readback = preflight["readback_module"]
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
    launch_path = output_dir / "soak-launch.json"
    if launch_path.exists() and not launch_path.is_symlink():
        _raw, launch_sha, _info = read_stable(
            launch_path, "Source5 Soak launch receipt", MAX_RECEIPT_BYTES,
        )
        pins["launch"] = {"path": str(launch_path), "raw_sha256": launch_sha}

    validated = False
    passed = False
    readback_value: dict[str, Any] | None = None
    if receipt["status"] == 0 and receipt["interrupted"] is False and \
            receipt["application_cleanup"]["status"] == "verified" and \
            receipt["pressure_cleanup"] == "verified" and pins["launch"] is not None:
        audit_after, preflight_after = readback._current_audit(args)
        require(_base_readback_audit_sha256(audit_after) ==
                preflight["base_audit_sha256"],
                "captured legacy SourceV5 audit changed after the one-use Soak launch")
        overlay_after, overlay_audit_after, overlay_preflight_after = \
            build_source5_launch_overlay(
                preflight["helper_input"], preflight["prepared"],
                preflight["details"], preflight["materials_index"],
                _selected_prepared_host_binding(
                    preflight["prepared"]["source5_prepared_input_completion"],
                    preflight["prepared"]["host_id"],
                ),
                preflight["parent_recipe"], preflight["identities"], args,
                audit_after, preflight_after, readback,
            )
        require(overlay_after == preflight["launch_overlay"] and
                _base_readback_audit_sha256(preflight["base_audit"]) ==
                    preflight["base_audit_sha256"],
                "Source5 Soak launch authorization overlay changed after APP cleanup")
        launch_receipt, launch_sha = readback._verify_launch_receipt(
            readback._check_private_output_directory(output_dir),
            overlay_audit_after, overlay_preflight_after,
            require_success=True,
        )
        overlay_audit_after["launch_receipt"] = launch_receipt
        readback_value = readback._validate_artifacts(
            readback._check_private_output_directory(output_dir),
            overlay_audit_after,
        )
        require(readback_value.get("schema") == READBACK_SCHEMA and
                readback_value.get("validated") is True and
                readback_value.get("passed") is True and
                readback_value.get("qualification_eligible") is True,
                "captured Soak V2 failed its original full-horizon numeric/RSS gates")
        readback_path = output_dir / "soak-readback.json"
        readback_pin = _write_exclusive_json(
            readback_path, readback_value, "Source5 Soak V2 readback result",
        )
        pins["readback"] = readback_pin
        postflight_body = {
            "schema": POSTFLIGHT_SCHEMA,
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
        postflight_body["postflight_sha256"] = sha256(canonical_bytes(postflight_body))
        pins["postflight"] = _write_exclusive_json(
            output_dir / "source5-soak-postflight.json", postflight_body,
            "Source5 Soak-only postflight receipt",
        )
        validated = True
        passed = readback_value["passed"]

    component = {
        "schema": COMPONENT_SCHEMA,
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
    return component


def _verify_source5_soak_component_replay(
    component: dict[str, Any], prepared: dict[str, Any],
    job: dict[str, Any], authorization_context: dict[str, Any],
    readback: types.ModuleType, *,
    offline_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Replay the raw false legacy audit, Soak-only authorization and full V2 gate."""
    exact(component, {
        "schema", "campaign_id", "host_id", "run_id", "validated", "passed",
        "qualification_eligible", "launch_enabled", "prepared_host_binding_sha256",
        "pins", "application_attestation", "application_cleanup", "pressure_cleanup",
        "terminal_event", "readback", "supervisor_sha256",
    }, "Source5 Soak component")
    require(component["schema"] == COMPONENT_SCHEMA and
            component["campaign_id"] == prepared["campaign_id"] and
            component["host_id"] == prepared["host_id"] and
            component["run_id"] == job["run_id"] and
            component["validated"] is True and component["passed"] is True and
            component["qualification_eligible"] is False and
            component["launch_enabled"] is True,
            "Source5 Soak component identity/status/outer eligibility differs")
    pins = exact(component["pins"], {
        "materials_index", "parent_recipe", "build_receipt", "preflight",
        "launch_authorization", "supervisor", "launch", "postflight", "readback",
    }, "Source5 Soak component pins")
    materials_pin = raw_pin(pins["materials_index"], "Source5 Soak materials index")
    material_index, _index_raw, _index_sha = read_json(
        Path(materials_pin["path"]), materials_pin["raw_sha256"],
        "Source5 Soak materials index", MAX_ARTIFACT_BYTES,
    )
    binding = _selected_prepared_host_binding(
        prepared["source5_prepared_input_completion"], prepared["host_id"],
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
        base_audit, base_preflight = readback._current_audit(args)
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
    require(pins["launch"] == {
        "path": str(output_dir / "soak-launch.json"), "raw_sha256": launch_sha,
    }, "Source5 Soak launch receipt differs from its raw pin")
    postflight_pin = raw_pin(pins["postflight"], "Source5 Soak-only postflight")
    postflight, postflight_raw, _postflight_sha = read_json(
        Path(postflight_pin["path"]), postflight_pin["raw_sha256"],
        "Source5 Soak-only postflight", MAX_RECEIPT_BYTES,
    )
    postflight_body = {key: value for key, value in postflight.items()
                       if key != "postflight_sha256"}
    require(postflight_pin["path"] ==
                str(output_dir / "source5-soak-postflight.json") and
            postflight["schema"] == POSTFLIGHT_SCHEMA and
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
            readback_value.get("qualification_eligible") is True,
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
    details = exact(supervisor["details"], {
        "status", "child_return_code", "timed_out", "artifact_budget_exceeded",
        "received_signal", "started_monotonic_ns", "ended_monotonic_ns",
        "binary_path", "binary_sha256", "binary_device", "binary_inode",
        "binary_size", "requested_argv", "requested_argv_sha256",
        "executed_argv", "executed_file_descriptor", "environment",
        "environment_sha256", "cwd", "cpu_set",
    }, "Source5 Soak supervisor terminal details")
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
    expected_direct = {
        "soak-preflight.json", "soak-postflight.json", "soak-launch.json",
        "soak-readback.json", "source5-soak-launch-authorization.json",
        "source5-soak-postflight.json", "source5-soak-supervisor.json",
        "soak-receipt.json", "pressure-readback.json", "stdout.log",
        "stderr.log", "time.txt",
        "pressure-driver.stdout.log", "pressure-driver.stderr.log", "pressure",
    }
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
    pressure_filenames = {
        "run.json": "run", "events.jsonl": "events",
        "launch-record.json": "launch",
        "process-binding.json": "process_binding",
        "pressure-ready.json": "ready",
    }
    expected_pressure = set(pressure_filenames)
    try:
        pressure_children = sorted(os.scandir(pressure_dir), key=lambda item: item.name)
    except OSError as error:
        raise Source5SoakError(f"cannot enumerate declared pressure outputs: {error}") from error
    require({item.name for item in pressure_children} == expected_pressure,
            "Source5 pressure output directory has missing or undeclared artifacts")

    paths: dict[str, str | None] = {}
    for name in expected_direct - {"pressure"}:
        paths[str(output_root / name)] = None
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
        require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode),
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
    expected_files = {
        "probe.stdout": probe_capture["stdout"]["raw_sha256"],
        "probe.stderr": probe_capture["stderr"]["raw_sha256"],
        "process-owner.json": probe_capture["owner_result_pin"]["raw_sha256"],
        "probe-capture.json": probe_capture_pin["raw_sha256"],
    }
    for name, expected_sha in expected_files.items():
        path = probe_root / name
        record = _stable_file_inventory(
            path, f"Source5 ProbeV1 output {name}", MAX_RECEIPT_BYTES,
        )
        require(record["raw_sha256"] == expected_sha,
                f"Source5 ProbeV1 output raw pin differs: {name}")
        entries[str(path)] = record
    return sorted(entries.values(), key=lambda item: item["path"])


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


def _host_receipt_value(
    component: dict[str, Any], prepared: dict[str, Any], job: dict[str, Any],
    authorization_context: dict[str, Any], binding: dict[str, Any],
    generation: dict[str, Any], host_identity: dict[str, Any],
    observed_host_pin: dict[str, str], absence: list[dict[str, Any]],
    probe_capture: dict[str, Any], probe_capture_pin: dict[str, str],
    pressure_origin: dict[str, Any],
    evidence_inventory: list[dict[str, Any]], evidence_bases: list[str],
    source_root: Path, input_root: Path, output_root: Path,
    probe_root: Path, result: dict[str, Any],
) -> dict[str, Any]:
    helper_pin = raw_pin(authorization_context["helper_input"],
                         "Source5 Soak original helper input")
    body = {
        "schema": HOST_VERIFICATION_SCHEMA,
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
        "construction_probe": {
            "receipt_pin": {
                "path": probe_capture_pin["path"],
                "raw_sha256": probe_capture_pin["raw_sha256"],
            },
            "capture_sha256": probe_capture["capture_sha256"],
            "probe_raw_sha256": probe_capture["probe_raw_sha256"],
            "normal_binary_sha256": probe_capture["normal_binary_sha256"],
            "owner_source_sha256": probe_capture["owner_source_sha256"],
        },
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
        "bounded_execution_ready": False,
        "bounded_blockers": [
            "prospective_bounded_soak_resource_budget_not_pinned",
        ],
        "qualification_eligible": False,
        "execution_ready": False,
    }
    body["receipt_sha256"] = sha256(canonical_bytes(body))
    return body


def verify_source5_soak_component_with_host_receipt(
    component: dict[str, Any], prepared: dict[str, Any],
    job: dict[str, Any], authorization_context: dict[str, Any],
    readback: types.ModuleType, host_receipt_path: str | Path, *,
    probe_capture_root: str | Path,
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
    probe_capture, probe_capture_pin = _capture_source5_soak_probe(
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
    )
    require(len(canonical_bytes(receipt)) <= MAX_RECEIPT_BYTES,
            "Source5 Soak host-verification receipt exceeds its finite byte bound")
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
    for role in ("output", "probe_capture"):
        root = Path(tree_roots[role])
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
                f"offline Source5 Soak {role} tree membership/modes differ from the origin receipt")
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
    exact(receipt, expected_fields, "Source5 Soak host-verification receipt")
    receipt_body = {key: value for key, value in receipt.items()
                    if key != "receipt_sha256"}
    require(receipt["schema"] == HOST_VERIFICATION_SCHEMA and
            receipt["receipt_sha256"] == receipt_pin["receipt_sha256"] ==
                sha256(canonical_bytes(receipt_body)) and
            receipt["campaign_id"] == component["campaign_id"] ==
                prepared["campaign_id"] and
            receipt["host_id"] == component["host_id"] == prepared["host_id"] and
            receipt["run_id"] == component["run_id"] == job["run_id"] and
            receipt["component_sha256"] == sha256(canonical_bytes(component)) and
            receipt["component_pins"] == component["pins"] and
            receipt["bounded_execution_ready"] is False and
            receipt["bounded_blockers"] == [
                "prospective_bounded_soak_resource_budget_not_pinned",
            ] and
            receipt["qualification_eligible"] is False and
            receipt["execution_ready"] is False,
            "Source5 Soak host receipt is not bound to the exact non-qualifying component")
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
    construction_probe_capture = _offline_probe_context(
        receipt, offline_prepared, readback,
    )
    offline_readback_context = {
        "schema": "allocatbelt.application-source5-soak-offline-replay-context.v1",
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
    raise Source5SoakError(
        "source5_soak_bounded_acceptance_blocked: complete Soak and pressure replay passed, but no prospective bounded-Soak resource-budget document is pinned",
    )
