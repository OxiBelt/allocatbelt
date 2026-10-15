#!/usr/bin/env python3
"""Build a pinned, prospective recipe for one fixed-policy soak context.

This builder creates no process and enables no qualification gate. The current
campaign soak remains an external-pressure job; the fixed-policy job supplied
here is a separate context for the recipe and never replaces that soak job.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import types
from pathlib import Path, PurePosixPath
from typing import Any


SOURCE_SCHEMA = "allocatbelt.application-source-manifest.v4"
SPEC_SCHEMA = "allocatbelt.application-campaign-spec.v2"
PLAN_SCHEMA = "allocatbelt.application-campaign-plan.v2"
RECIPE_RECEIPT_SCHEMA = "allocatbelt.application-soak-recipe-build-receipt.v1"
RECIPE_RECEIPT_SCHEMA_V2 = "allocatbelt.application-soak-recipe-build-receipt.v2"
SOURCE_INVENTORY_SCHEMA = "allocatbelt.application-source-inventory.v1"
SOURCE_INVENTORY_PATH = "scripts/application-source-inventory.py"
SOAK_READER_PATH = "scripts/application-soak-readback.py"
SOAK_RUNNER_PATH = "scripts/run-application-soak.sh"
RUNTIME_READBACK_PATH = "scripts/application-runtime-readback.py"
ALLOCATORS = ("allocatbelt", "mimalloc-secure", "mimalloc-standard", "system")
HOST_CONTROL_KEYS = {
    "cpu_model", "microcode_sha256", "kernel_release", "governor", "frequency_policy",
    "boost_policy", "cpu_set", "numa_policy", "cgroup_policy_sha256",
    "background_load_policy_sha256", "x86_64_v3_capability_sha256", "target_triple", "target_cpu",
}
SOAK_SECONDS = 10_800
SOURCE_V5_SCHEMA = "allocatbelt.application-source-manifest.v5"
SPEC_SCHEMA_V3 = "allocatbelt.application-campaign-spec.v3"
PLAN_SCHEMA_V3 = "allocatbelt.application-campaign-plan.v3"
RSS_GROWTH_PERCENT = 5
MAX_SPEC_BYTES = 32 * 1024 * 1024
MAX_PLAN_BYTES = 256 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 64 * 1024 * 1024
MAX_SCRIPT_BYTES = 4 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
MAX_EXTERNAL_ORACLE_BYTES = 512 * 1024 * 1024
SOURCE_V5_APP_SETUP_BUDGET_SECONDS = 120
SOURCE_V5_TRACE_OVERRUN_SECONDS = 5
SOURCE_V5_DRAIN_BUDGET_SECONDS = 5
SOURCE_V5_SHUTDOWN_BUDGET_SECONDS = 60
SOURCE_V5_POSTPROCESS_BUDGET_SECONDS = 60
SOURCE_V5_PRESSURE_EXIT_OBSERVATION_SECONDS = 1
SOURCE_V5_PRESSURE_MAX_DURATION_SECONDS = 12_000
SOURCE_V5_PRESSURE_MAX_SAMPLES = 120_000
SOURCE_V5_PRESSURE_MAX_TOTAL_SECONDS = 14_400


class RecipeBuildError(ValueError):
    """Frozen inputs cannot produce a valid fixed-policy soak recipe."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RecipeBuildError(message)


def canonical_bytes(value: object) -> bytes:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise RecipeBuildError(f"value cannot be encoded as canonical JSON: {error}") from error
    return (encoded + "\n").encode("ascii")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_sha256(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RecipeBuildError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise RecipeBuildError(f"nonstandard JSON number is forbidden: {value}")


def parse_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise RecipeBuildError(f"{label} is not bounded UTF-8 JSON: {error}") from error
    require(type(value) is dict, f"{label} must be a JSON object")
    return value


def read_stable(path: Path, label: str, maximum: int) -> tuple[bytes, str]:
    try:
        before_path = path.lstat()
        require(stat.S_ISREG(before_path.st_mode), f"{label} must be a regular nonsymlink file")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RecipeBuildError(f"cannot safely open {label}: {error}") from error
    try:
        before_fd = os.fstat(descriptor)
        require(stat.S_ISREG(before_fd.st_mode), f"{label} descriptor is not regular")
        require(_stat_key(before_fd) == _stat_key(before_path), f"{label} changed while opening")
        require(before_fd.st_size <= maximum, f"{label} exceeds its {maximum}-byte bound")
        chunks: list[bytes] = []
        count = 0
        while count < before_fd.st_size:
            block = os.read(descriptor, min(1024 * 1024, before_fd.st_size - count))
            require(block, f"{label} was truncated during its stable read")
            chunks.append(block)
            count += len(block)
        after_fd = os.fstat(descriptor)
        after_path = path.lstat()
        require(_stat_key(before_fd) == _stat_key(after_fd) == _stat_key(after_path), f"{label} changed during its stable read")
        require(count == before_fd.st_size, f"{label} size changed during its stable read")
        raw = b"".join(chunks)
        return raw, sha256(raw)
    finally:
        os.close(descriptor)


def _stat_key(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def hash_file(path: Path, label: str, maximum: int = MAX_EXECUTABLE_BYTES) -> str:
    try:
        before_path = path.lstat()
        require(stat.S_ISREG(before_path.st_mode), f"{label} must be a regular nonsymlink file")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
    except OSError as error:
        raise RecipeBuildError(f"cannot safely hash {label}: {error}") from error
    try:
        before_fd = os.fstat(descriptor)
        require(stat.S_ISREG(before_fd.st_mode), f"{label} descriptor is not a regular file")
        require(_stat_key(before_fd) == _stat_key(before_path), f"{label} changed while opening")
        require(before_fd.st_size <= maximum, f"{label} exceeds its {maximum}-byte bound")
        digest = hashlib.sha256()
        count = 0
        while count < before_fd.st_size:
            block = os.read(descriptor, min(1024 * 1024, before_fd.st_size - count))
            require(block, f"{label} was truncated while hashing")
            count += len(block)
            digest.update(block)
        after_fd = os.fstat(descriptor)
        after_path = path.lstat()
        require(_stat_key(before_fd) == _stat_key(after_fd) == _stat_key(after_path) and count == before_fd.st_size, f"{label} changed while hashing")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def exact_object(value: object, keys: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == keys, f"{label} has an unexpected shape")
    return value


def uint(value: object, label: str, *, positive: bool = False, maximum: int = (1 << 64) - 1) -> int:
    require(type(value) is int and 0 <= value <= maximum, f"{label} must be a finite unsigned integer")
    require(not positive or value > 0, f"{label} must be positive")
    return value


def token(value: object, label: str, maximum: int = 128) -> str:
    require(type(value) is str and len(value) <= maximum and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value) is not None, f"{label} is malformed")
    return value


def safe_relative(value: object, label: str) -> PurePosixPath:
    require(type(value) is str and value and "\\" not in value and "\x00" not in value, f"{label} is malformed")
    path = PurePosixPath(value)
    require(not path.is_absolute() and ".." not in path.parts and all(part not in ("", ".") for part in path.parts), f"{label} must be a normalized relative path")
    require(not any(ord(char) < 32 or ord(char) == 127 for char in value), f"{label} contains a control character")
    return path


def safe_directory(path: Path, label: str) -> Path:
    require(path.is_absolute(), f"{label} must be absolute")
    try:
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode), f"{label} must be a real nonsymlink directory")
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise RecipeBuildError(f"{label} is unavailable: {error}") from error
    return resolved


def safe_child(root: Path, relative: object, label: str) -> Path:
    rel = safe_relative(relative, label)
    current = root
    for component in rel.parts:
        current = current / component
        try:
            info = current.lstat()
        except OSError as error:
            raise RecipeBuildError(f"{label} is missing: {error}") from error
        require(not stat.S_ISLNK(info.st_mode), f"{label} path traverses a symlink")
    try:
        resolved = current.resolve(strict=True)
    except OSError as error:
        raise RecipeBuildError(f"{label} does not resolve: {error}") from error
    require(resolved.is_relative_to(root), f"{label} escapes its pinned root")
    require(resolved.is_file(), f"{label} is not a regular file")
    return resolved


def load_pinned_module(path: Path, expected_sha256: str, label: str, maximum: int, module_name: str) -> types.ModuleType:
    raw, actual_sha256 = read_stable(path, label, maximum)
    require(actual_sha256 == expected_sha256, f"{label} differs from its independent source-manifest pin")
    module = types.ModuleType(f"{module_name}_{actual_sha256}")
    module.__file__ = str(path)
    module.__package__ = ""
    try:
        code = compile(raw, str(path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except (SyntaxError, ValueError, TypeError) as error:
        raise RecipeBuildError(f"{label} cannot be compiled from its pinned bytes: {error}") from error
    return module


def run_git_commit(root: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RecipeBuildError(f"cannot verify source Git identity: {error}") from error
    require(completed.returncode == 0 and len(completed.stdout) <= 256, "source Git identity query failed")
    try:
        return completed.stdout.decode("ascii").strip()
    except UnicodeError as error:
        raise RecipeBuildError("source Git identity is not ASCII") from error


def _manifest_records(manifest: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    source = exact_object(manifest.get("source"), {"git_commit", "source_tree_sha256", "cargo_lock_sha256", "files"}, "SourceSchemaV4 source identity")
    files = source["files"]
    require(type(files) is list and files, "SourceSchemaV4 file inventory is missing")
    records: dict[str, dict[str, Any]] = {}
    for item in files:
        require(type(item) is dict and type(item.get("path")) is str, "source inventory entry is malformed")
        require(item["path"] not in records, "source inventory contains a duplicate path")
        records[item["path"]] = item
    return files, records


def _verify_source_manifest(
    manifest_path: Path,
    expected_manifest_semantic_sha256: str,
    source_root: Path,
    host_id: str,
    profile: str,
) -> dict[str, Any]:
    raw, manifest_file_sha256 = read_stable(manifest_path, "host SourceSchemaV4 manifest", MAX_MANIFEST_BYTES)
    manifest = parse_json(raw, "host SourceSchemaV4 manifest")
    require(raw == canonical_bytes(manifest), "host source manifest is not canonical JSON")
    manifest = exact_object(manifest, {
        "schema", "source", "build", "artifacts", "soak_artifacts", "analysis_artifact",
        "fixed_runtime_policy", "runtime_readback_validator", "resource_domain_calibration", "manifest_sha256",
    }, "SourceSchemaV4 manifest")
    require(manifest["schema"] == SOURCE_SCHEMA, "unsupported source manifest schema")
    manifest_without_hash = dict(manifest)
    internal_sha256 = manifest_without_hash.pop("manifest_sha256")
    require(is_sha256(internal_sha256) and sha256(canonical_bytes(manifest_without_hash)) == internal_sha256, "source manifest internal digest is invalid")
    require(internal_sha256 == expected_manifest_semantic_sha256, "source manifest semantic digest differs from its frozen spec reference")
    source = exact_object(manifest["source"], {"git_commit", "source_tree_sha256", "cargo_lock_sha256", "files"}, "source identity")
    for field in ("source_tree_sha256", "cargo_lock_sha256"):
        require(is_sha256(source[field]), f"source {field} is malformed")
    build = exact_object(manifest["build"], {
        "host_id", "rustc_release", "rustc_verbose", "cargo_version", "target_triple", "target_cpu",
        "profile", "features_sha256", "build_inputs_sha256",
    }, "source build identity")
    require(build["host_id"] == host_id, "source build host differs from the selected host")
    require(build["rustc_release"] == "1.99.0" and build["target_triple"] == "x86_64-unknown-linux-gnu" and build["target_cpu"] == "x86-64-v3" and build["profile"] == "release", "source build differs from the frozen Rust 1.99 amd64-v3 release contract")
    require(type(build["rustc_verbose"]) is list and all(type(item) is str for item in build["rustc_verbose"]), "build rustc version record is malformed")
    require(type(build["cargo_version"]) is str and build["cargo_version"], "build Cargo version record is missing")
    require(is_sha256(build["features_sha256"]) and is_sha256(build["build_inputs_sha256"]), "build feature/input hash is malformed")

    files, records = _manifest_records(manifest)
    engine_record = records.get(SOURCE_INVENTORY_PATH)
    require(type(engine_record) is dict and engine_record.get("kind") == "file" and is_sha256(engine_record.get("sha256")), "source inventory does not pin a regular shared engine")
    engine_path = safe_child(source_root, SOURCE_INVENTORY_PATH, "shared source inventory engine")
    inventory_module = load_pinned_module(engine_path, engine_record["sha256"], "shared source inventory engine", MAX_SOURCE_FILE_BYTES, "soak_recipe_source_inventory")
    require(inventory_module.SCHEMA == SOURCE_INVENTORY_SCHEMA, "source inventory engine has an unexpected schema")
    try:
        validated_files = inventory_module.validate_records({"schema": inventory_module.SCHEMA, "entries": files})
    except inventory_module.InventoryError as error:
        raise RecipeBuildError(f"SourceSchemaV4 file records are invalid: {error}") from error
    require(validated_files == files, "SourceSchemaV4 file records are not canonical")
    require(inventory_module.digest_records(validated_files) == source["source_tree_sha256"], "SourceSchemaV4 inventory digest differs")
    try:
        inventory_module.verify_source_tree(source_root, source["source_tree_sha256"], validated_files)
    except inventory_module.InventoryError as error:
        raise RecipeBuildError(f"live source tree differs from SourceSchemaV4: {error}") from error
    require(run_git_commit(source_root) == source["git_commit"], "live source commit differs from SourceSchemaV4")
    cargo_lock = safe_child(source_root, "Cargo.lock", "Cargo.lock")
    require(hash_file(cargo_lock, "Cargo.lock", MAX_SOURCE_FILE_BYTES) == source["cargo_lock_sha256"], "live Cargo.lock differs from SourceSchemaV4")

    reader_record = records.get(SOAK_READER_PATH)
    require(type(reader_record) is dict and reader_record.get("kind") == "file" and is_sha256(reader_record.get("sha256")), "source manifest does not pin the soak readback source")
    reader_path = safe_child(source_root, SOAK_READER_PATH, "soak readback source")
    reader_module = load_pinned_module(reader_path, reader_record["sha256"], "soak readback source", MAX_SCRIPT_BYTES, "soak_readback")
    require(reader_module.SOURCE_SCHEMA == SOURCE_SCHEMA, "pinned soak reader does not support SourceSchemaV4")

    campaign_record = records.get("scripts/application-campaign.py")
    require(type(campaign_record) is dict and campaign_record.get("kind") == "file" and is_sha256(campaign_record.get("sha256")), "source manifest does not pin the SourceSchemaV4 controller")
    campaign_path = safe_child(source_root, "scripts/application-campaign.py", "SourceSchemaV4 controller source")
    campaign_module = load_pinned_module(campaign_path, campaign_record["sha256"], "SourceSchemaV4 controller source", MAX_SCRIPT_BYTES, "application_campaign")
    require(campaign_module.SOURCE_SCHEMA == SOURCE_SCHEMA, "pinned campaign controller does not support SourceSchemaV4")
    require(reader_module.SOURCE_INVENTORY_MODULE_SHA256 == engine_record["sha256"], "pinned soak reader has a stale shared inventory engine SHA")
    require(campaign_module.SOURCE_INVENTORY_MODULE_SHA256 == engine_record["sha256"], "pinned SourceSchemaV4 controller has a stale shared inventory engine SHA")

    runtime_validator = exact_object(manifest["runtime_readback_validator"], {"path", "sha256"}, "fixed runtime readback validator pin")
    require(runtime_validator["path"] == RUNTIME_READBACK_PATH and is_sha256(runtime_validator["sha256"]), "fixed runtime readback validator path/pin is unsupported")
    runtime_record = records.get(RUNTIME_READBACK_PATH)
    require(type(runtime_record) is dict and runtime_record.get("kind") == "file" and runtime_record.get("sha256") == runtime_validator["sha256"], "fixed runtime validator is not bound by the typed source inventory")
    runtime_path = safe_child(source_root, RUNTIME_READBACK_PATH, "fixed runtime readback validator")
    require(hash_file(runtime_path, "fixed runtime readback validator", MAX_SCRIPT_BYTES) == runtime_validator["sha256"], "fixed runtime readback validator bytes differ from their source pin")

    try:
        campaign_module.validate_fixed_runtime_policy_artifact(manifest["fixed_runtime_policy"], runtime_validator["sha256"])
    except (campaign_module.CampaignError, TypeError, ValueError) as error:
        raise RecipeBuildError(f"numeric fixed-policy artifact is invalid: {error}") from error
    try:
        _limits, _domain, _scope, _buckets, policy_sha256 = reader_module._check_policy(manifest["fixed_runtime_policy"], profile)
    except (reader_module.SoakReadbackError, TypeError, ValueError) as error:
        raise RecipeBuildError(f"fixed soak policy is unsupported: {error}") from error

    artifacts = manifest["artifacts"]
    require(type(artifacts) is dict and set(artifacts) == set(ALLOCATORS), "SourceSchemaV4 does not pin all four application producers")
    soak_artifacts = manifest["soak_artifacts"]
    require(type(soak_artifacts) is dict and "allocatbelt" in soak_artifacts and set(soak_artifacts).issubset(ALLOCATORS), "SourceSchemaV4 must pin the actual candidate soak artifact and only declared optional artifacts")
    analysis = exact_object(manifest["analysis_artifact"], {"path", "sha256"}, "analysis artifact")
    calibration = exact_object(manifest["resource_domain_calibration"], {"binary", "output", "record", "source", "build", "build_sha256"}, "resource-domain calibration")
    calibration_binary = exact_object(calibration["binary"], {"path", "sha256"}, "calibration binary")
    calibration_output = exact_object(calibration["output"], {"path", "sha256"}, "calibration output")
    candidate_soak = exact_object(soak_artifacts["allocatbelt"], {"path", "sha256"}, "candidate soak artifact")
    producer = exact_object(artifacts["allocatbelt"], {"path", "sha256"}, "candidate oracle producer")
    unique_paths: set[str] = set()
    artifact_pins: list[tuple[str, dict[str, Any]]] = []
    artifact_pins.extend((f"application producer {name}", exact_object(value, {"path", "sha256"}, f"application producer {name}")) for name, value in artifacts.items())
    artifact_pins.extend((f"soak artifact {name}", exact_object(value, {"path", "sha256"}, f"soak artifact {name}")) for name, value in soak_artifacts.items())
    artifact_pins.extend((
        ("analysis artifact", analysis), ("calibration binary", calibration_binary),
        ("calibration output", calibration_output),
    ))
    for label, artifact in artifact_pins:
        rel = safe_relative(artifact["path"], f"{label} path")
        require(is_sha256(artifact["sha256"]), f"{label} SHA-256 is malformed")
        path_text = rel.as_posix()
        require(path_text not in unique_paths, "SourceSchemaV4 reuses an artifact path")
        unique_paths.add(path_text)
        artifact_path = safe_child(source_root, path_text, label)
        if label.startswith("application producer ") or label.startswith("soak artifact "):
            require(artifact_path.stat().st_mode & 0o111 != 0, f"{label} is not executable")
        require(hash_file(artifact_path, label) == artifact["sha256"], f"{label} differs from its SourceSchemaV4 pin")

    for artifact in (candidate_soak, producer):
        safe_relative(artifact["path"], "candidate artifact path")
    require(calibration["source"] == {name: source[name] for name in ("git_commit", "source_tree_sha256", "cargo_lock_sha256")}, "calibration source identity differs from SourceSchemaV4")
    require(calibration["build"] == build and calibration["build_sha256"] == sha256(canonical_bytes(build)), "calibration build identity differs from SourceSchemaV4")
    try:
        calibration_record = campaign_module.validate_calibration_record(calibration["record"])
        output_path = safe_child(source_root, calibration_output["path"], "calibration output")
        output_raw, output_sha256 = read_stable(output_path, "resource-domain calibration output", MAX_MANIFEST_BYTES)
        output_record = parse_json(output_raw, "resource-domain calibration output")
        require(output_raw == canonical_bytes(output_record) and output_record == calibration_record, "calibration output is not the exact canonical numeric record")
        require(output_sha256 == calibration_output["sha256"], "calibration output bytes differ from their frozen pin")
    except (campaign_module.CampaignError, OSError, TypeError, ValueError) as error:
        raise RecipeBuildError(f"resource-domain calibration is invalid: {error}") from error
    baseline = calibration_record["fixed_global_control_baseline"]
    require(type(baseline) is int and baseline > 0, "calibrated global Control baseline is not an exact positive integer")
    try:
        campaign_module.verify_source_manifest(manifest, source_root=None, verify_artifacts=False)
    except (campaign_module.CampaignError, OSError, TypeError, ValueError) as error:
        raise RecipeBuildError(f"SourceSchemaV4 manifest fails the pinned campaign validator: {error}") from error

    return {
        "manifest": manifest,
        "manifest_semantic_sha256": internal_sha256,
        "manifest_file_sha256": manifest_file_sha256,
        "source": source,
        "build": build,
        "build_sha256": sha256(canonical_bytes(build)),
        "files": records,
        "reader": reader_module,
        "campaign_module": campaign_module,
        "policy_sha256": policy_sha256,
        "calibration": calibration,
        "calibration_record": calibration_record,
        "fixed_global_control_baseline": baseline,
        "candidate_soak": candidate_soak,
        "candidate_producer": producer,
    }


def _check_spec_and_plan(
    spec: dict[str, Any], plan: dict[str, Any], job: dict[str, Any],
    expected_spec_sha256: str, expected_plan_sha256: str,
) -> tuple[str, dict[str, Any], dict[str, dict[str, Any]], dict[str, Any]]:
    require(is_sha256(expected_spec_sha256) and is_sha256(expected_plan_sha256), "spec and plan need independent frozen SHA-256 pins")
    require(type(spec) is dict and spec.get("schema") == SPEC_SCHEMA, "unsupported campaign-spec schema")
    spec_sha256 = sha256(canonical_bytes(spec))
    require(spec_sha256 == expected_spec_sha256, "campaign spec differs from its frozen SHA-256")
    plan = exact_object(plan, {
        "schema", "campaign_id", "spec_sha256", "source_manifests", "protocol", "runtime_binding",
        "execution_ready", "full_gate_ready", "full_gate_gaps", "host_ids", "cell_count", "jobs",
        "runtime_process_bindings", "plan_sha256",
    }, "frozen campaign plan")
    require(plan["schema"] == PLAN_SCHEMA and plan["spec_sha256"] == spec_sha256, "campaign plan schema/spec identity differs")
    plan_without_hash = dict(plan)
    recorded_plan_sha = plan_without_hash.pop("plan_sha256")
    plan_sha256 = sha256(canonical_bytes(plan_without_hash))
    require(is_sha256(recorded_plan_sha) and recorded_plan_sha == plan_sha256 == expected_plan_sha256, "campaign plan differs from its frozen SHA-256")
    require(plan["campaign_id"] == spec.get("campaign_id"), "campaign plan and spec IDs differ")
    campaign_id = token(spec.get("campaign_id"), "campaign ID")

    hosts = spec.get("hosts")
    require(type(hosts) is list and len(hosts) == 3, "the original soak requires exactly three pinned hosts")
    hosts_by_id: dict[str, dict[str, Any]] = {}
    venues: list[str] = []
    for host_value in hosts:
        host = exact_object(host_value, {"host_id", "venue", "host_fingerprint_sha256", "controls"}, "campaign host")
        host_id = token(host["host_id"], "host ID")
        require(host_id not in hosts_by_id, "campaign spec repeats a host")
        require(host["venue"] in ("bare_metal", "kvm_guest") and is_sha256(host["host_fingerprint_sha256"]), "campaign host venue/fingerprint is malformed")
        controls = exact_object(host["controls"], HOST_CONTROL_KEYS, "campaign host controls")
        require(controls["target_triple"] == "x86_64-unknown-linux-gnu" and controls["target_cpu"] == "x86-64-v3", "campaign host is not an amd64-v3 target")
        for field in ("microcode_sha256", "cgroup_policy_sha256", "background_load_policy_sha256", "x86_64_v3_capability_sha256"):
            require(is_sha256(controls[field]), f"campaign host control {field} is not pinned")
        for field in ("cpu_model", "kernel_release", "governor", "frequency_policy", "boost_policy", "cpu_set", "numa_policy"):
            require(type(controls[field]) is str and controls[field], f"campaign host control {field} is missing")
        require(sha256(canonical_bytes(controls)) == host["host_fingerprint_sha256"], "campaign host fingerprint does not bind its controls")
        hosts_by_id[host_id] = host
        venues.append(host["venue"])
    require(venues.count("bare_metal") == 1 and venues.count("kvm_guest") == 2, "the original one-bare-metal/two-guest host matrix is required")
    require(type(plan["host_ids"]) is list and len(plan["host_ids"]) == 3 and set(plan["host_ids"]) == set(hosts_by_id), "frozen plan does not cover all three spec hosts")

    source_refs = spec.get("source_manifests")
    require(type(source_refs) is list and len(source_refs) == 3, "one SourceSchemaV4 manifest reference per host is required")
    refs_by_host: dict[str, dict[str, Any]] = {}
    for ref_value in source_refs:
        ref = exact_object(ref_value, {"host_id", "relative_path", "sha256"}, "host source-manifest reference")
        host_id = token(ref["host_id"], "source-manifest host ID")
        safe_relative(ref["relative_path"], "host source-manifest path")
        require(host_id in hosts_by_id and host_id not in refs_by_host and is_sha256(ref["sha256"]), "host source-manifest ref is unknown, duplicated, or unpinned")
        refs_by_host[host_id] = ref
    require(set(refs_by_host) == set(hosts_by_id), "source manifests do not cover the exact three-host matrix")
    require(type(plan["source_manifests"]) is dict and plan["source_manifests"] == {host: ref["sha256"] for host, ref in refs_by_host.items()}, "frozen plan source pins differ from the campaign spec")

    protocol = spec.get("protocol")
    require(type(protocol) is dict and type(protocol.get("soak_seconds")) is int and protocol["soak_seconds"] == SOAK_SECONDS, "the original 10,800-second qualification horizon must remain frozen")
    require(type(protocol.get("soak_rss_growth_percent")) is int and protocol["soak_rss_growth_percent"] == RSS_GROWTH_PERCENT, "the original five-percent RSS bound must remain frozen")
    soak = exact_object(spec.get("soak"), {"workload", "profile", "allocator", "executor", "driver_relative_path", "driver_sha256", "interval_ms"}, "campaign soak contract")
    require(soak["workload"] == "mixed" and soak["profile"] in ("mixed", "burst", "oversubscribed"), "campaign soak workload/profile is unsupported")
    require(soak["allocator"] == "allocatbelt" and soak["executor"] == "bounded", "soak builder supports only the actual allocatbelt/bounded candidate artifact")
    require(soak["driver_relative_path"] == SOAK_RUNNER_PATH and is_sha256(soak["driver_sha256"]), "campaign does not pin the canonical soak runner")
    require(type(soak["interval_ms"]) is int and soak["interval_ms"] == 100, "soak sample interval differs from the fixed 100ms contract")

    jobs = plan.get("jobs")
    require(type(jobs) is dict and type(jobs.get("confirmation")) is list and type(jobs.get("soak")) is list, "frozen plan omits fixed context or original soak jobs")
    run_id = token(job.get("run_id"), "fixed context job run ID") if type(job) is dict else ""
    if type(job) is dict and job.get("comparison_family") == "external_pressure":
        raise RecipeBuildError("external-pressure jobs are unsupported by the fixed-policy soak reader")
    matches = [item for item in jobs["confirmation"] if type(item) is dict and item.get("run_id") == run_id]
    require(len(matches) == 1 and canonical_bytes(matches[0]) == canonical_bytes(job), "fixed context job is not the exact unique frozen confirmation job")
    require(job.get("phase") == "confirmation" and job.get("comparison_family") == "fixed_policy", "soak context must be a separate fixed-policy confirmation job")
    require(job.get("host_id") in hosts_by_id, "fixed context job host is outside the pinned matrix")

    pressure_by_host: dict[str, dict[str, Any]] = {}
    for item in jobs["soak"]:
        require(type(item) is dict, "planned soak job is malformed")
        host_id = item.get("host_id")
        require(host_id in hosts_by_id and host_id not in pressure_by_host, "planned soak jobs have an unknown or duplicate host")
        expected_run_id = f"{campaign_id}-{host_id}-mixed-{soak['profile']}-soak-allocatbelt-01"
        require(
            item.get("phase") == "soak" and item.get("comparison_family") == "external_pressure"
            and item.get("run_id") == expected_run_id and item.get("family") == "mixed"
            and item.get("workload") == "mixed" and item.get("profile") == soak["profile"]
            and item.get("allocator") == "allocatbelt" and item.get("executor") == "bounded",
            "the original external-pressure soak job is missing, changed, or relabelled",
        )
        pressure_by_host[host_id] = item
    require(set(pressure_by_host) == set(hosts_by_id), "the original pressure soak job must remain scheduled on all three hosts")
    require(job["host_id"] in pressure_by_host and job["run_id"] != pressure_by_host[job["host_id"]]["run_id"], "fixed context and planned pressure soak identities must remain distinct")

    return campaign_id, hosts_by_id[job["host_id"]], refs_by_host, soak


def build_recipe(
    spec: dict[str, Any],
    plan: dict[str, Any],
    job: dict[str, Any],
    *,
    spec_sha256: str,
    plan_sha256: str,
    spec_path: Path,
    source_root: Path,
    oracle_root: Path,
    ring_relative_path: str,
    ring_sha256: str,
    mode: str,
    duration_seconds: int,
    terminal_budget_bytes: int,
    sample_budget_bytes: int,
    construction_probe_path: Path | None = None,
    construction_probe_sha256: str | None = None,
    plan_path: Path | None = None,
    plan_file_sha256: str | None = None,
    pressure_recipe_path: Path | None = None,
    pressure_recipe_raw_sha256: str | None = None,
    pressure_recipe_semantic_sha256: str | None = None,
) -> dict[str, Any]:
    """Build and reader-validate one immutable soak recipe without launching."""
    spec_raw, spec_file_sha256 = read_stable(spec_path, "campaign spec", MAX_SPEC_BYTES)
    require(spec_file_sha256 == spec_sha256, "campaign spec file differs from its caller-frozen SHA-256")
    require(parse_json(spec_raw, "campaign spec") == spec and spec_raw == canonical_bytes(spec), "campaign spec object differs from its canonical frozen file")
    if spec.get("schema") == SPEC_SCHEMA_V3 and type(job) is dict and job.get("phase") == "soak":
        require(construction_probe_path is not None and is_sha256(construction_probe_sha256), "SourceV5 soak recipe requires the actual compiled application construction probe path and raw SHA")
        return build_external_pressure_recipe(
            spec, plan, job,
            spec_sha256=spec_sha256,
            plan_sha256=plan_sha256,
            spec_path=spec_path,
            source_root=source_root,
            oracle_root=oracle_root,
            ring_relative_path=ring_relative_path,
            ring_sha256=ring_sha256,
            mode=mode,
            duration_seconds=duration_seconds,
            terminal_budget_bytes=terminal_budget_bytes,
            sample_budget_bytes=sample_budget_bytes,
            construction_probe_path=construction_probe_path,
            construction_probe_sha256=construction_probe_sha256,
            plan_path=plan_path,
            plan_file_sha256=plan_file_sha256,
            pressure_recipe_path=pressure_recipe_path,
            pressure_recipe_raw_sha256=pressure_recipe_raw_sha256,
            pressure_recipe_semantic_sha256=pressure_recipe_semantic_sha256,
        )
    campaign_id, _host, source_refs, soak = _check_spec_and_plan(spec, plan, job, spec_sha256, plan_sha256)
    require(mode in ("qualified", "functional"), "recipe mode must be qualified or functional")
    duration = uint(duration_seconds, "recipe duration", positive=True)
    require(duration <= SOAK_SECONDS, "recipe duration exceeds the fixed 10,800-second horizon")
    require((mode == "qualified" and duration == SOAK_SECONDS) or (mode == "functional" and duration < SOAK_SECONDS), "recipe mode and duration disagree")
    terminal_budget = uint(terminal_budget_bytes, "terminal artifact budget", positive=True)
    sample_budget = uint(sample_budget_bytes, "sample artifact budget", positive=True)

    source_base = safe_directory(source_root, "source root")
    try:
        spec_info = spec_path.lstat()
        require(stat.S_ISREG(spec_info.st_mode), "campaign spec path must be a regular nonsymlink file")
        spec_file = spec_path.resolve(strict=True)
    except OSError as error:
        raise RecipeBuildError(f"campaign spec path is unavailable: {error}") from error
    spec_base = safe_directory(spec_file.parent, "campaign spec directory")
    source_ref = source_refs[job["host_id"]]
    manifest_path = safe_child(spec_base, source_ref["relative_path"], "host source manifest")
    manifest = parse_json(read_stable(manifest_path, "host source manifest", MAX_MANIFEST_BYTES)[0], "host source manifest")
    host_id = job["host_id"]
    source_info = _verify_source_manifest(manifest_path, source_ref["sha256"], source_base, host_id, soak["profile"])
    reader = source_info["reader"]
    campaign = source_info["manifest"]
    source = source_info["source"]
    files = source_info["files"]

    for other_host, other_ref in source_refs.items():
        if other_host == host_id:
            continue
        other_path = safe_child(spec_base, other_ref["relative_path"], f"{other_host} source manifest")
        other_raw, other_file_sha256 = read_stable(other_path, f"{other_host} source manifest", MAX_MANIFEST_BYTES)
        other_manifest = parse_json(other_raw, f"{other_host} source manifest")
        require(other_raw == canonical_bytes(other_manifest), f"{other_host} source manifest is not canonical JSON")
        require(is_sha256(other_manifest.get("manifest_sha256")) and other_manifest["manifest_sha256"] == other_ref["sha256"], f"{other_host} source manifest semantic digest differs from its frozen spec reference")
        try:
            source_info["campaign_module"].verify_source_manifest(other_manifest, source_root=None, verify_artifacts=False)
        except (source_info["campaign_module"].CampaignError, OSError, TypeError, ValueError) as error:
            raise RecipeBuildError(f"{other_host} SourceSchemaV4 manifest is invalid: {error}") from error
        require(other_manifest["build"]["host_id"] == other_host, f"{other_host} SourceSchemaV4 build host differs")
        require(other_manifest["source"] == source, f"{other_host} SourceSchemaV4 source tree differs from the selected host")
        require(canonical_bytes(other_manifest["fixed_runtime_policy"]) == canonical_bytes(campaign["fixed_runtime_policy"]), f"{other_host} numeric fixed policy differs from the selected host")
        require(canonical_bytes(other_manifest["runtime_readback_validator"]) == canonical_bytes(campaign["runtime_readback_validator"]), f"{other_host} fixed runtime validator pin differs from the selected host")
        selected_build = {key: value for key, value in source_info["build"].items() if key != "host_id"}
        other_build = {key: value for key, value in other_manifest["build"].items() if key != "host_id"}
        require(canonical_bytes(other_build) == canonical_bytes(selected_build), f"{other_host} build contract differs from the selected host")
        require(is_sha256(other_file_sha256), f"{other_host} raw source-manifest file digest is malformed")

    cell_matches = [
        cell for cell in spec.get("cells", [])
        if type(cell) is dict and cell.get("family") == "mixed" and cell.get("workload") == "mixed" and cell.get("profile") == soak["profile"]
    ]
    require(len(cell_matches) == 1, "campaign spec must contain one matching mixed workload/profile cell")
    cell = cell_matches[0]
    limits = exact_object(cell.get("resource_limits"), {"managed_bytes", "disk_ops", "network_ops", "tasks", "cpu_charges"}, "fixed mixed cell resource limits")
    for name, value in limits.items():
        uint(value, f"cell resource limit {name}")
    _policy_limits, _domain, _scope, _buckets, _policy_sha = reader._check_policy(campaign["fixed_runtime_policy"], soak["profile"])
    validator_pin = campaign["runtime_readback_validator"]["sha256"]
    try:
        expected_limits = source_info["campaign_module"].fixed_resource_limits_for_cell("mixed", soak["profile"], validator_pin)
    except (source_info["campaign_module"].CampaignError, TypeError, ValueError) as error:
        raise RecipeBuildError(f"campaign fixed-limit recipe is unavailable: {error}") from error
    require(canonical_bytes(limits) == canonical_bytes(expected_limits), "mixed cell limits differ from the frozen numeric fixed policy")
    require(canonical_bytes(limits) == canonical_bytes(_policy_limits), "mixed cell limits differ from the soak reader's numeric policy")
    ceiling_sha256 = sha256(canonical_bytes(limits))
    require(is_sha256(cell.get("resource_ceiling_sha256")) and cell["resource_ceiling_sha256"] == ceiling_sha256, "resource ceiling digest does not bind the numeric mixed cell limits")
    if "resource_limits" in job:
        require(canonical_bytes(job["resource_limits"]) == canonical_bytes(limits), "fixed context job limits differ from its frozen spec cell")
    if "resource_ceiling_sha256" in job:
        require(job["resource_ceiling_sha256"] == ceiling_sha256, "fixed context job ceiling differs from its frozen spec cell")

    require(job.get("family") == "mixed" and job.get("workload") == "mixed" and job.get("profile") == soak["profile"], "fixed context job workload/profile differs from the campaign soak cell")
    require(job.get("mode") == "open_loop" and job.get("load_percent") in (70, 90), "fixed context job must be a frozen 70/90 open-loop job")
    require(job.get("allocator") == "allocatbelt" and job.get("executor") == "bounded" and job.get("comparison_kind") == "allocator" and job.get("pair_kind") == "allocator-match", "fixed context job is not the candidate bounded allocator comparison")
    require(job.get("baseline_allocator") in ("mimalloc-secure", "mimalloc-standard"), "fixed context job baseline is not a pinned comparison allocator")
    rate_per_second = uint(job.get("rate_per_second"), "fixed context arrival rate", positive=True)
    arrivals = uint(job.get("arrivals"), "fixed context arrivals", positive=True)
    require(arrivals == cell.get("arrivals"), "fixed context job arrivals differ from its frozen spec cell")
    rate_matches = [
        rate for rate in spec.get("rates", [])
        if type(rate) is dict and rate.get("host_id") == host_id and rate.get("family") == "mixed"
        and rate.get("profile") == soak["profile"] and rate.get("load_percent") == job["load_percent"]
    ]
    require(len(rate_matches) == 1 and type(rate_matches[0].get("arrivals_per_second")) is int and rate_matches[0]["arrivals_per_second"] == rate_per_second, "fixed context job rate is not the unique frozen spec rate")
    candidate_oracles = job.get("oracles")
    require(type(candidate_oracles) is dict and set(candidate_oracles) == {"allocatbelt", job["baseline_allocator"]}, "fixed context job must carry separate candidate and baseline oracle bindings")
    oracle_base = safe_directory(oracle_root, "external oracle root")
    spec_oracle_by_allocator: dict[str, dict[str, Any]] = {}
    for allocator, oracle_value in candidate_oracles.items():
        oracle_ref = exact_object(oracle_value, {"host_id", "allocator", "family", "profile", "load_percent", "relative_path", "sha256"}, f"{allocator} external oracle binding")
        require(oracle_ref["host_id"] == host_id and oracle_ref["allocator"] == allocator and oracle_ref["family"] == "mixed" and oracle_ref["profile"] == soak["profile"] and oracle_ref["load_percent"] == job["load_percent"], f"{allocator} oracle context differs from the fixed job")
        require(is_sha256(oracle_ref["sha256"]), f"{allocator} external oracle digest is malformed")
        spec_oracle_by_allocator[allocator] = oracle_ref
    candidate_oracle = spec_oracle_by_allocator["allocatbelt"]
    spec_oracles = [
        item for item in spec.get("oracles", [])
        if type(item) is dict and item.get("host_id") == host_id and item.get("allocator") == "allocatbelt"
        and item.get("family") == "mixed" and item.get("profile") == soak["profile"]
        and item.get("load_percent") == job["load_percent"]
    ]
    require(len(spec_oracles) == 1 and canonical_bytes(spec_oracles[0]) == canonical_bytes(candidate_oracle), "candidate oracle binding differs from the frozen spec")
    for allocator, oracle_ref in spec_oracle_by_allocator.items():
        spec_match = [
            item for item in spec.get("oracles", [])
            if type(item) is dict and item.get("host_id") == host_id and item.get("allocator") == allocator
            and item.get("family") == "mixed" and item.get("profile") == soak["profile"]
            and item.get("load_percent") == job["load_percent"]
        ]
        require(len(spec_match) == 1 and canonical_bytes(spec_match[0]) == canonical_bytes(oracle_ref), f"{allocator} oracle binding differs from the frozen spec")
        oracle_path = safe_child(oracle_base, oracle_ref["relative_path"], f"{allocator} campaign oracle")
        require(hash_file(oracle_path, f"{allocator} campaign oracle", MAX_EXTERNAL_ORACLE_BYTES) == oracle_ref["sha256"], f"{allocator} campaign oracle differs from its frozen spec pin")
    require(is_sha256(ring_sha256), "external soak ring needs an independent frozen SHA-256")
    ring_path = safe_child(oracle_base, ring_relative_path, "external soak oracle ring")
    actual_ring_sha256 = hash_file(ring_path, "external soak oracle ring", MAX_MANIFEST_BYTES)
    require(actual_ring_sha256 == ring_sha256, "external soak oracle ring differs from its independent frozen pin")

    candidate_soak_path = safe_child(source_base, source_info["candidate_soak"]["path"], "candidate soak binary")
    producer_path = safe_child(source_base, source_info["candidate_producer"]["path"], "candidate oracle producer")
    runner_record = files.get(soak["driver_relative_path"])
    require(type(runner_record) is dict and runner_record.get("kind") == "file" and runner_record.get("sha256") == soak["driver_sha256"], "SourceSchemaV4 does not bind the exact soak runner source")
    runner_path = safe_child(source_base, soak["driver_relative_path"], "soak runner source")
    require(hash_file(runner_path, "soak runner source", MAX_SCRIPT_BYTES) == soak["driver_sha256"], "soak runner bytes differ from the spec pin")
    validator_path = safe_child(source_base, SOAK_READER_PATH, "soak readback source")
    validator_sha256 = files[SOAK_READER_PATH]["sha256"]
    require(is_sha256(validator_sha256), "soak readback source pin is malformed")
    require(candidate_soak_path != producer_path and ring_path != candidate_soak_path and ring_path != producer_path, "candidate, oracle producer, and external ring must be separate artifacts")
    require(hash_file(candidate_soak_path, "candidate soak binary") == source_info["candidate_soak"]["sha256"], "candidate soak binary changed after SourceSchemaV4 verification")
    require(hash_file(producer_path, "candidate oracle producer") == source_info["candidate_producer"]["sha256"], "candidate oracle producer changed after SourceSchemaV4 verification")

    ring = reader._validate_ring(
        {
            "identity": {"profile": soak["profile"]},
            "oracle": {"ring_path": str(ring_path), "ring_sha256": ring_sha256},
        },
        source["source_tree_sha256"],
        source_info["candidate_soak"]["sha256"],
    )
    require(ring["average_rate_per_second"] == rate_per_second, "oracle ring rate differs from the frozen fixed context job")
    baseline = source_info["fixed_global_control_baseline"]
    nonce_material = {
        "schema": "allocatbelt.application-soak-recipe-nonce-material.v1",
        "campaign_id": campaign_id,
        "host_id": host_id,
        "source_manifest_semantic_sha256": source_info["manifest_semantic_sha256"],
        "source_manifest_file_sha256": source_info["manifest_file_sha256"],
        "source_tree_sha256": source["source_tree_sha256"],
        "spec_sha256": spec_sha256,
        "plan_sha256": plan_sha256,
        "context_job": job,
        "profile": soak["profile"],
        "mode": mode,
        "duration_seconds": duration,
        "resource_ceiling_sha256": ceiling_sha256,
        "candidate_soak_sha256": source_info["candidate_soak"]["sha256"],
        "oracle_producer_sha256": source_info["candidate_producer"]["sha256"],
        "oracle_ring_sha256": ring_sha256,
        "terminal_budget_bytes": terminal_budget,
        "sample_budget_bytes": sample_budget,
    }
    nonce = sha256(b"allocatbelt.application-soak-parent-recipe-nonce.v1\0" + canonical_bytes(nonce_material))[:32]
    soak_run_id = f"soak-{nonce}"
    recipe = {
        "schema": reader.RECIPE_SCHEMA,
        "identity": {
            "campaign_id": campaign_id,
            "host_id": host_id,
            "run_id": soak_run_id,
            "nonce": nonce,
            "allocator": "allocatbelt",
            "executor": "bounded",
            "workload": "mixed",
            "profile": soak["profile"],
            "comparison_family": "fixed_policy",
            "source_sha256": source["source_tree_sha256"],
            "build_sha256": source_info["build_sha256"],
            "binary_sha256": source_info["candidate_soak"]["sha256"],
            "resource_ceiling_sha256": ceiling_sha256,
        },
        "source": {
            "root": str(source_base),
            "manifest_path": str(manifest_path.resolve(strict=True)),
            "manifest_sha256": source_info["manifest_file_sha256"],
        },
        "oracle": {
            "producer_path": str(producer_path),
            "producer_sha256": source_info["candidate_producer"]["sha256"],
            "ring_path": str(ring_path),
            "ring_sha256": ring_sha256,
        },
        "runtime": {
            "mode": mode,
            "duration_seconds": duration,
            "sample_interval_ms": 100,
            "resource_limits": limits,
            "fixed_global_control_baseline": baseline,
            "terminal_budget_bytes": terminal_budget,
            "sample_budget_bytes": sample_budget,
        },
        "validator": {"path": SOAK_READER_PATH, "sha256": validator_sha256},
        "runner": {"path": SOAK_RUNNER_PATH, "sha256": soak["driver_sha256"]},
    }
    recipe_bytes = canonical_bytes(recipe)
    recipe_sha256 = sha256(recipe_bytes)
    try:
        validated, identity = reader._validate_recipe(recipe, recipe_sha256)
    except (reader.SoakReadbackError, TypeError, ValueError) as error:
        raise RecipeBuildError(f"generated recipe does not satisfy the pinned soak reader contract: {error}") from error
    require(canonical_bytes(validated) == recipe_bytes and identity == recipe["identity"], "pinned soak reader normalized the generated recipe unexpectedly")
    pressure_job = next(item for item in plan["jobs"]["soak"] if item["host_id"] == host_id)
    require(pressure_job["run_id"] != soak_run_id and pressure_job["run_id"] != job["run_id"], "new fixed recipe identity collides with context or planned pressure soak")
    return {
        "recipe": recipe,
        "recipe_bytes": recipe_bytes,
        "recipe_sha256": recipe_sha256,
        "soak_run_id": soak_run_id,
        "context_job_run_id": job["run_id"],
        "planned_pressure_soak_run_id": pressure_job["run_id"],
        "source_manifest_semantic_sha256": source_info["manifest_semantic_sha256"],
        "source_manifest_file_sha256": source_info["manifest_file_sha256"],
        "source_tree_sha256": source["source_tree_sha256"],
        "spec_sha256": spec_sha256,
        "plan_sha256": plan_sha256,
        "mode": mode,
        "duration_seconds": duration,
        "execution_started": False,
        "qualification_enabled": False,
    }


def process_nonce(template_nonce: str, campaign_id: str, job_run_id: str, pair_member: str, ordinal: int) -> str:
    """Instantiate one reusable SourceV5 nonce with its job/member/ordinal scope."""
    material = {
        "template_nonce": template_nonce,
        "campaign_id": campaign_id,
        "job_run_id": job_run_id,
        "pair_member": pair_member,
        "ordinal": ordinal,
    }
    return sha256(b"allocatbelt.application-process-nonce-instantiation.v1\0" + canonical_bytes(material))[:32]


def _derive_v5_pressure_schedule(duration_seconds: int, request: dict[str, Any], condition_schedule: dict[str, Any]) -> dict[str, Any]:
    """Derive a pressure window enclosing startup, the soak and bounded cleanup."""
    schedule_keys = {
        "seed", "duration_seconds", "sample_interval_ms", "startup_deadline_seconds",
        "total_deadline_seconds", "term_deadline_seconds", "kill_deadline_seconds",
        "minimum_overlap_seconds", "startup_ready_windows", "cpu_duty_basis_points",
        "pressure_cpu_affinity", "application_cpu_affinity", "disk_bytes_per_second",
        "scratch_file_bytes", "network_requests_per_second", "network_payload_bytes",
    }
    require(request.get("schema") == "allocatbelt.application-pressure-request.v1", "SourceV5 pressure template is not the canonical pressure-request schema")
    base = exact_object(request.get("schedule"), schedule_keys, "SourceV5 raw pressure request schedule")
    template_schedule = exact_object(condition_schedule, {"duration_seconds", "sample_interval_ms", "seed"}, "SourceV5 typed pressure condition schedule")
    base_duration = uint(base["duration_seconds"], "SourceV5 request-template pressure duration", positive=True, maximum=SOURCE_V5_PRESSURE_MAX_DURATION_SECONDS)
    template_duration = uint(template_schedule["duration_seconds"], "SourceV5 typed pressure duration", positive=True, maximum=SOURCE_V5_PRESSURE_MAX_DURATION_SECONDS)
    base_interval = uint(base["sample_interval_ms"], "SourceV5 request-template pressure interval", positive=True, maximum=1000)
    template_interval = uint(template_schedule["sample_interval_ms"], "SourceV5 typed pressure interval", positive=True, maximum=1000)
    base_seed = uint(base["seed"], "SourceV5 request-template pressure seed", positive=True, maximum=(1 << 63) - 1)
    template_seed = uint(template_schedule["seed"], "SourceV5 typed pressure seed", positive=True, maximum=(1 << 63) - 1)
    require(
        base_duration == template_duration
        and base_interval == template_interval == 100
        and base_seed == template_seed,
        "SourceV5 typed pressure schedule differs from the immutable request template or fixed sample interval",
    )
    startup = uint(base["startup_deadline_seconds"], "SourceV5 pressure startup deadline", positive=True, maximum=10)
    term = uint(base["term_deadline_seconds"], "SourceV5 pressure TERM deadline", positive=True, maximum=30)
    kill = uint(base["kill_deadline_seconds"], "SourceV5 pressure KILL deadline", positive=True, maximum=15)
    raw_total = uint(base["total_deadline_seconds"], "SourceV5 pressure total deadline", positive=True, maximum=SOURCE_V5_PRESSURE_MAX_TOTAL_SECONDS)
    duration = uint(duration_seconds, "SourceV5 timed app horizon", positive=True, maximum=SOAK_SECONDS)
    app_wall = (
        SOURCE_V5_APP_SETUP_BUDGET_SECONDS
        + duration
        + SOURCE_V5_TRACE_OVERRUN_SECONDS
        + SOURCE_V5_DRAIN_BUDGET_SECONDS
        + SOURCE_V5_SHUTDOWN_BUDGET_SECONDS
        + SOURCE_V5_POSTPROCESS_BUDGET_SECONDS
    )
    pressure_duration = startup + app_wall + SOURCE_V5_PRESSURE_EXIT_OBSERVATION_SECONDS
    interval = base_interval
    require(interval >= 100 and pressure_duration * 1000 % interval == 0, "derived SourceV5 pressure horizon does not align to its frozen sample interval")
    require(pressure_duration <= SOURCE_V5_PRESSURE_MAX_DURATION_SECONDS, "derived SourceV5 pressure horizon exceeds the driver duration bound")
    require(pressure_duration * 1000 // interval <= SOURCE_V5_PRESSURE_MAX_SAMPLES, "derived SourceV5 pressure horizon exceeds the driver sample bound")
    derived = dict(base)
    derived["duration_seconds"] = pressure_duration
    derived["total_deadline_seconds"] = max(raw_total, startup + pressure_duration + term + kill)
    require(derived["total_deadline_seconds"] <= SOURCE_V5_PRESSURE_MAX_TOTAL_SECONDS, "derived SourceV5 pressure total deadline exceeds the driver bound")
    return {"application_wall_timeout_seconds": app_wall, "pressure_duration_seconds": pressure_duration, "pressure_schedule": derived}


def _v5_manifest_context(
    spec: dict[str, Any], plan: dict[str, Any], spec_path: Path, plan_path: Path,
    source_root: Path,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]], dict[str, Path], dict[str, str], Any, dict[str, Any]]:
    source_base = safe_directory(source_root, "SourceV5 source root")
    input_root = safe_directory(spec_path.resolve(strict=True).parent, "SourceV5 frozen input directory")
    controller: types.ModuleType | None = None
    sources: dict[str, dict[str, Any]] = {}
    paths: dict[str, Path] = {}
    raw_shas: dict[str, str] = {}
    references = spec.get("source_manifests")
    require(type(references) is list and len(references) == 3, "SourceV5 spec must name exactly three source manifests")
    for index, ref_value in enumerate(references):
        ref = exact_object(ref_value, {"host_id", "relative_path", "sha256"}, f"SourceV5 source ref[{index}]")
        host = token(ref["host_id"], f"SourceV5 source ref[{index}] host")
        require(host not in sources, "SourceV5 spec repeats a host source manifest")
        path = safe_child(input_root, ref["relative_path"], f"SourceV5 {host} source manifest")
        raw, raw_sha = read_stable(path, f"SourceV5 {host} source manifest", MAX_MANIFEST_BYTES)
        manifest = parse_json(raw, f"SourceV5 {host} source manifest")
        require(raw == canonical_bytes(manifest) and manifest.get("schema") == SOURCE_V5_SCHEMA and manifest.get("manifest_sha256") == ref["sha256"], f"SourceV5 {host} source manifest is noncanonical or differs from its semantic pin")
        records = manifest.get("source", {}).get("files")
        require(type(records) is list, f"SourceV5 {host} source inventory is missing")
        controller_pin = manifest.get("qualification_harness", {}).get("campaign_controller")
        controller_pin = exact_object(controller_pin, {"path", "sha256"}, f"SourceV5 {host} campaign controller pin")
        if controller is None:
            controller = _source_v5_module(source_base, records, controller_pin["path"], controller_pin["sha256"], "soak_builder_source_v5_controller")
        sources[host] = manifest
        paths[host] = path
        raw_shas[host] = raw_sha
    require(controller is not None, "SourceV5 full controller was not loaded")
    return {"root": source_base, "input_root": input_root}, sources, paths, raw_shas, controller, {"spec": spec, "plan": plan}


def _source_v5_module(
    source_root: Path, source_records: list[dict[str, Any]], path_text: str,
    expected_sha256: str, module_name: str,
) -> types.ModuleType:
    record = next((item for item in source_records if type(item) is dict and item.get("path") == path_text), None)
    require(type(record) is dict and record.get("kind") == "file" and record.get("sha256") == expected_sha256, f"SourceV5 source module {path_text} is not pinned to a regular inventory entry")
    module_path = safe_child(source_root, path_text, f"SourceV5 module {path_text}")
    return load_pinned_module(module_path, expected_sha256, f"SourceV5 module {path_text}", MAX_SCRIPT_BYTES, module_name)


def _source_v5_feedback_policy(
    manifest: dict[str, Any], probe: dict[str, Any],
) -> dict[str, Any]:
    policy_body = manifest["feedback_policy"]["policy"]
    context = policy_body["contexts"][f"mixed/{probe['context']['profile']}"]
    reader_context = probe["reader_context"]
    rust_context = probe["rust_control_context"]
    return {
        "version": policy_body["version"],
        "sample_interval_ns": reader_context["sample_interval_ns"],
        "max_dense_gap_ns": reader_context["max_dense_gap_ns"],
        "telemetry_freshness_ns": reader_context["telemetry_freshness_ns"],
        "required_breach_samples": reader_context["required_breach_samples"],
        "actuation_cooldown_ns": reader_context["actuation_cooldown_ns"],
        "minimum_dense_observations": context["minimum_dense_observations"],
        "controls": context["controls"],
        "capacity_sources": rust_context["required_byte_sources"],
        "global_ceilings": rust_context["global_ceilings"],
        "tenant_ceilings": rust_context["tenant_ceilings"],
        "scope_limits": rust_context["scope_limits"],
        "rate_buckets": rust_context["rate_buckets"],
        "collector": {
            "task_lease_count": probe["collector"]["task_lease_count"],
            "control_charge_bytes": probe["collector"]["control_charge_bytes"],
            "expected_global_control_baseline": probe["baseline"]["expected_global_control_baseline"],
        },
        "meter_source_bounds": probe["meter_source_bounds"],
    }


def build_external_pressure_recipe(
    spec: dict[str, Any], plan: dict[str, Any], job: dict[str, Any], *,
    spec_sha256: str, plan_sha256: str, spec_path: Path, source_root: Path,
    oracle_root: Path, ring_relative_path: str, ring_sha256: str,
    mode: str, duration_seconds: int, terminal_budget_bytes: int, sample_budget_bytes: int,
    construction_probe_path: Path, construction_probe_sha256: str,
    plan_path: Path | None, plan_file_sha256: str | None,
    pressure_recipe_path: Path | None, pressure_recipe_raw_sha256: str | None,
    pressure_recipe_semantic_sha256: str | None,
) -> dict[str, Any]:
    require(isinstance(plan_path, Path) and is_sha256(plan_file_sha256), "SourceV5 builder requires the frozen plan path and raw SHA-256")
    require(type(job) is dict and job.get("phase") == "soak" and job.get("comparison_family") == "external_pressure", "SourceV5 builder accepts only the original external-pressure soak job")
    require(mode in ("qualified", "functional"), "SourceV5 soak mode is unsupported")
    duration = uint(duration_seconds, "SourceV5 duration", positive=True)
    require((mode == "qualified" and duration == SOAK_SECONDS) or (mode == "functional" and 0 < duration < SOAK_SECONDS), "SourceV5 soak mode and duration differ")
    terminal_budget = uint(terminal_budget_bytes, "SourceV5 terminal budget", positive=True)
    sample_budget = uint(sample_budget_bytes, "SourceV5 sample budget", positive=True)

    spec_raw, spec_raw_sha = read_stable(spec_path, "SourceV5 campaign spec", MAX_SPEC_BYTES)
    plan_raw, plan_raw_sha = read_stable(plan_path, "SourceV5 campaign plan", MAX_PLAN_BYTES)
    require(spec_raw_sha == sha256(canonical_bytes(spec)) == spec_sha256, "SourceV5 spec raw/semantic pin differs")
    require(plan_raw_sha == plan_file_sha256 and plan_raw == canonical_bytes(plan), "SourceV5 plan raw pin or canonical bytes differ")
    require(plan.get("schema") == PLAN_SCHEMA_V3 and spec.get("schema") == SPEC_SCHEMA_V3, "SourceV5 recipe requires spec/plan v3")
    plan_body = dict(plan)
    plan_semantic = plan_body.pop("plan_sha256", None)
    require(is_sha256(plan_semantic) and plan_semantic == sha256(canonical_bytes(plan_body)) == plan_sha256, "SourceV5 plan semantic SHA differs")

    roots, sources, manifest_paths, manifest_raw_shas, controller, _loaded = _v5_manifest_context(spec, plan, spec_path, plan_path, source_root)
    input_root = roots["input_root"]
    source_base = roots["root"]
    selected_host = token(job.get("host_id"), "SourceV5 soak host")
    require(selected_host in sources, "SourceV5 soak host is outside the exact source matrix")
    selected_manifest = sources[selected_host]
    harness = selected_manifest["qualification_harness"]
    try:
        for host, manifest in sources.items():
            controller.verify_source_manifest(manifest, source_root=source_base if host == selected_host else None, verify_artifacts=host == selected_host)
        validation = controller.validate_spec(spec, sources, input_root=input_root)
        input_module_sha = plan.get("campaign_inputs_module_sha256")
        require(is_sha256(input_module_sha), "SourceV5 plan omits its campaign-inputs module pin")
        controller.verify_plan(plan, selected_manifest["runtime_readback_validator"]["sha256"], input_module_sha)
        input_module = controller.campaign_inputs_module(input_module_sha)
        normalized = input_module.validate_qualification_inputs(spec["qualification_inputs"], validation["host_ids"], spec["cells"], sources, input_root)
    except (OSError, TypeError, ValueError, getattr(controller, "CampaignError", ValueError)) as error:
        raise RecipeBuildError(f"captured SourceV5 controller rejected a manifest/spec/plan input: {error}") from error

    soak = exact_object(spec["soak"], {"workload", "profile", "allocator", "executor", "driver_relative_path", "driver_sha256", "interval_ms"}, "SourceV5 soak contract")
    require(soak == {
        "workload": "mixed", "profile": soak["profile"], "allocator": "allocatbelt", "executor": "bounded",
        "driver_relative_path": SOAK_RUNNER_PATH, "driver_sha256": harness["soak_runner"]["sha256"], "interval_ms": 100,
    }, "SourceV5 soak contract differs from the original role/cadence")
    host_id = selected_host
    planned = [item for item in plan["jobs"]["soak"] if type(item) is dict and item.get("run_id") == job.get("run_id")]
    require(len(planned) == 1 and canonical_bytes(planned[0]) == canonical_bytes(job), "selected external soak job is not the exact unique frozen SourceV5 job")
    require(job.get("workload") == "mixed" and job.get("family") == "mixed" and job.get("profile") == soak["profile"] and job.get("allocator") == "allocatbelt" and job.get("executor") == "bounded" and job.get("duration_seconds") == SOAK_SECONDS, "selected SourceV5 soak job differs from the frozen original schedule")

    cells = [cell for cell in spec["cells"] if type(cell) is dict and cell.get("family") == "mixed" and cell.get("workload") == "mixed" and cell.get("profile") == soak["profile"]]
    require(len(cells) == 1, "SourceV5 soak does not have one mixed workload/profile resource cell")
    cell = cells[0]
    limits = exact_object(cell["resource_limits"], {"managed_bytes", "disk_ops", "network_ops", "tasks", "cpu_charges"}, "SourceV5 soak resource limits")
    ceiling_sha = sha256(canonical_bytes(limits))
    require(cell["resource_ceiling_sha256"] == ceiling_sha, "SourceV5 soak ceiling SHA differs from the exact cell limits")

    capacity_rows = [item for item in normalized["capacity_templates"] if item["host_id"] == host_id and item["workload"] == "mixed" and item["profile"] == soak["profile"]]
    condition_rows = [item for item in normalized["pressure_conditions"] if item["host_id"] == host_id and item["capacity_key"]["workload"] == "mixed" and item["capacity_key"]["profile"] == soak["profile"]]
    require(len(capacity_rows) == len(condition_rows) == 1, "SourceV5 soak capacity or pressure input is ambiguous")
    capacity, pressure_condition = capacity_rows[0], condition_rows[0]
    require(pressure_condition["capacity_key"]["calibration_id"] == capacity["calibration_id"], "SourceV5 soak pressure condition does not bind its exact capacity calibration")

    app_pin = exact_object(selected_manifest["artifacts"]["allocatbelt"], {"path", "sha256"}, "SourceV5 normal allocatbelt application artifact")
    soak_pin = exact_object(selected_manifest["soak_artifacts"]["allocatbelt"], {"path", "sha256"}, "SourceV5 timed allocatbelt soak artifact")
    app_binary = safe_child(source_base, app_pin["path"], "SourceV5 application emitter binary")
    soak_binary = safe_child(source_base, soak_pin["path"], "SourceV5 timed soak binary")
    app_sha = app_pin["sha256"]
    soak_sha = soak_pin["sha256"]
    require(is_sha256(app_sha), "SourceV5 application binary SHA-256 is malformed")
    require(is_sha256(soak_sha), "SourceV5 soak binary SHA-256 is malformed")
    require(app_binary != soak_binary and app_sha != soak_sha, "SourceV5 app emitter and timed soak artifacts must be distinct")

    capacity_floor_policy_id = spec.get("capacity_floor_policy_id")
    require(capacity_floor_policy_id is None or capacity_floor_policy_id == getattr(controller, "CAPACITY_FLOOR_POLICY_ID", None),
            "SourceV5 soak floor policy ID is unknown to the pinned source controller")
    capacity_evidence = capacity.get("evidence")
    calibrated_probe = capacity_floor_policy_id is not None
    require(not calibrated_probe or type(capacity_evidence) is dict,
            "selected capacity-floor policy requires a validated SourceV5 capacity artifact")
    probe_command = [str(app_binary), "--emit-feedback-policy-only", "--workload", "mixed", "--profile", soak["profile"]]
    capacity_artifact_pin: dict[str, str] | None = None
    if calibrated_probe:
        capacity_path = safe_child(input_root, capacity_evidence["artifact"]["relative_path"], "SourceV5 calibrated capacity artifact")
        _capacity_raw, capacity_raw_sha = read_stable(capacity_path, "SourceV5 calibrated capacity artifact", MAX_MANIFEST_BYTES)
        require(capacity_raw_sha == capacity_evidence["artifact"]["raw_sha256"],
                "SourceV5 calibrated capacity artifact differs from its frozen evidence pin")
        capacity_artifact_pin = {"path": str(capacity_path.resolve(strict=True)), "raw_sha256": capacity_raw_sha}
        probe_command.extend([
            "--capacity-calibration-file", capacity_artifact_pin["path"],
            "--capacity-calibration-sha256", capacity_raw_sha,
            "--host-id", host_id,
            "--source-sha256", selected_manifest["source"]["source_tree_sha256"],
        ])
        if capacity_floor_policy_id is not None:
            probe_command.extend(["--capacity-floor-policy-id", capacity_floor_policy_id])
    construction_probe_raw, construction_probe_raw_sha = read_stable(construction_probe_path, "caller-pinned app construction probe", 512 * 1024)
    require(construction_probe_raw_sha == construction_probe_sha256, "caller-pinned construction probe raw SHA differs")
    probe = parse_json(construction_probe_raw, "caller-pinned app construction probe")
    require(construction_probe_raw == canonical_bytes(probe), "caller-pinned construction probe is not canonical JSON")
    require(probe.get("context") == {"workload": "mixed", "profile": soak["profile"], "workers": 2 if soak["profile"] == "oversubscribed" else 4}, "app construction probe workload/profile differs")
    if calibrated_probe:
        require(probe.get("schema") == "allocatbelt.application-feedback-policy-probe.v2",
                "SourceV5 capacity evidence requires the calibrated ProbeV2 schema")
    else:
        require(probe.get("schema") == "allocatbelt.application-feedback-policy-probe.v1",
                "launch-disabled SourceV5 without capacity evidence requires the legacy ProbeV1 schema")
    probe_run = subprocess.run(
        probe_command,
        cwd=source_base,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C", "LC_ALL": "C"},
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
    )
    require(len(probe_run.stdout) <= 512 * 1024 and len(probe_run.stderr) <= 64 * 1024, "compiled app construction probe exceeded its bound")
    require(probe_run.returncode == 0 and probe_run.stdout == construction_probe_raw, "caller-pinned construction probe is not the exact output of the SourceV5 application binary")
    feedback_validator_pin = harness["feedback_validator"]
    feedback_module = _source_v5_module(source_base, selected_manifest["source"]["files"], feedback_validator_pin["path"], feedback_validator_pin["sha256"], "source_v5_feedback_validator")
    construction_probe_pin = {
        "path": str(construction_probe_path.resolve(strict=True)), "raw_sha256": construction_probe_raw_sha,
        "allocator": "allocatbelt", "binary_sha256": app_sha,
    }
    if not calibrated_probe:
        feedback_policy = _source_v5_feedback_policy(selected_manifest, probe)
        probe_context = {
            "schema": feedback_module.EXPECTATION_SCHEMA_V3,
            "identity": {"allocator": "allocatbelt", "binary_sha256": soak_sha, "workload": "mixed", "profile": soak["profile"]},
            "construction_probe": construction_probe_pin,
            "policy": feedback_policy,
        }
        try:
            feedback_module.validate_construction_probe(probe_context, selected_manifest)
        except (OSError, TypeError, ValueError, getattr(feedback_module, "ValidationError", ValueError)) as error:
            raise RecipeBuildError(f"captured SourceV5 feedback reader rejected the actual construction probe: {error}") from error
    else:
        require(capacity_artifact_pin is not None and probe.get("schema") == feedback_module.CALIBRATED_PROBE_SCHEMA_V2,
                "SourceV5 capacity evidence requires the exact calibrated ProbeV2 schema")
        identity = {
            "host_id": host_id, "workload": "mixed", "profile": soak["profile"],
            "allocator": "allocatbelt", "source_sha256": selected_manifest["source"]["source_tree_sha256"],
            "binary_sha256": app_sha,
        }
        feedback_policy = feedback_module.resolve_calibrated_feedback_policy_v5(
            selected_manifest, probe, capacity_artifact_pin, identity,
            capacity_floor_policy_id=capacity_floor_policy_id,
        )
        try:
            feedback_module._check_calibrated_construction_probe_v2_inputs(
                construction_probe_pin, selected_manifest, capacity_artifact_pin,
                identity, feedback_policy, capacity_floor_policy_id,
            )
        except (OSError, TypeError, ValueError, getattr(feedback_module, "ValidationError", ValueError)) as error:
            raise RecipeBuildError(f"captured SourceV5 reader rejected the calibrated construction probe: {error}") from error
    probe_baseline = probe["baseline"]["expected_global_control_baseline"]
    require(probe_baseline == selected_manifest["resource_domain_calibration"]["record"]["fixed_global_control_baseline"], "compiled construction probe Control baseline differs from SourceV5 calibration")

    feedback_templates = [item for item in plan["feedback_process_templates"] if (
        type(item) is dict and type(item.get("identity")) is dict
        and item["identity"].get("host_id") == host_id
        and item["identity"].get("workload") == "mixed"
        and item["identity"].get("profile") == soak["profile"]
        and item["identity"].get("comparison_family") == "external_pressure"
        and item["identity"].get("allocator") == "allocatbelt"
        and item["identity"].get("executor") == "allocatbelt"
        and item["identity"].get("pressure_condition_id") == pressure_condition["condition_id"]
    )]
    require(len(feedback_templates) == 1, "SourceV5 plan lacks one exact external mixed feedback template")
    feedback_template = feedback_templates[0]
    template_identity = feedback_template["identity"]
    require(template_identity["binary_sha256"] == app_sha and feedback_template["policy"]["context"] == selected_manifest["feedback_policy"]["policy"]["contexts"][f"mixed/{soak['profile']}"] , "SourceV5 feedback template differs from source application/policy pins")
    require(feedback_template["policy"].get("capacity_floor_policy_id") == capacity_floor_policy_id,
            "SourceV5 external-pressure template selector differs from the frozen campaign epoch")
    if capacity_floor_policy_id is not None:
        require(feedback_template["policy"].get("capacity_floor_policy") == selected_manifest["feedback_policy"]["policy"].get("capacity_floor_policy"),
                "SourceV5 external-pressure template floor descriptor differs from its source manifest")
    ordinal = uint(job.get("ordinal"), "SourceV5 soak ordinal", positive=True)
    nonce = process_nonce(template_identity["prospective_nonce"], spec["campaign_id"], job["run_id"], "soak", ordinal)
    nonce_material = {
        "schema": "allocatbelt.application-process-nonce-instantiation.v1",
        "template_nonce": template_identity["prospective_nonce"],
        "campaign_id": spec["campaign_id"], "job_run_id": job["run_id"], "pair_member": "soak",
        "ordinal": ordinal, "nonce": nonce,
    }
    soak_identity = {
        "campaign_id": spec["campaign_id"], "host_id": host_id, "run_id": job["run_id"], "nonce": nonce,
        "allocator": "allocatbelt", "executor": "bounded", "workload": "mixed", "profile": soak["profile"],
        "comparison_family": "external_pressure", "source_sha256": selected_manifest["source"]["source_tree_sha256"],
        "build_sha256": sha256(canonical_bytes(selected_manifest["build"])), "binary_sha256": soak_sha,
        "resource_ceiling_sha256": ceiling_sha,
    }
    trace_identity = {
        "host_id": host_id, "run_id": job["run_id"], "report_nonce": nonce, "allocator": "allocatbelt",
        "executor": "allocatbelt", "workload": "mixed", "profile": soak["profile"],
        "mode": "pressure_soak_validation", "source_sha256": selected_manifest["source"]["source_tree_sha256"],
        "binary_sha256": soak_sha, "pressure_qualification": True,
    }

    source_manifest_path = manifest_paths[host_id]
    source_manifest_raw_sha = manifest_raw_shas[host_id]
    inventory_record = next((item for item in selected_manifest["source"]["files"] if type(item) is dict and item.get("path") == SOURCE_INVENTORY_PATH), None)
    require(type(inventory_record) is dict and inventory_record.get("kind") == "file" and is_sha256(inventory_record.get("sha256")), "SourceV5 source inventory does not pin its shared inventory engine")
    source_inventory = load_pinned_module(
        safe_child(source_base, SOURCE_INVENTORY_PATH, "SourceV5 source inventory"),
        inventory_record["sha256"],
        "SourceV5 source inventory", MAX_SOURCE_FILE_BYTES, "source_v5_soak_inventory",
    )
    require(source_inventory.digest_records(selected_manifest["source"]["files"]) == selected_manifest["source"]["source_tree_sha256"], "SourceV5 inventory digest differs")
    require(run_git_commit(source_base) == selected_manifest["source"]["git_commit"], "live SourceV5 Git commit differs")
    require(hash_file(safe_child(source_base, "Cargo.lock", "SourceV5 Cargo.lock"), "SourceV5 Cargo.lock", MAX_SOURCE_FILE_BYTES) == selected_manifest["source"]["cargo_lock_sha256"], "SourceV5 Cargo.lock differs")

    oracle_base = safe_directory(oracle_root, "SourceV5 oracle root")
    ring_path = safe_child(oracle_base, ring_relative_path, "SourceV5 mixed soak oracle ring")
    require(hash_file(ring_path, "SourceV5 mixed soak oracle ring", MAX_MANIFEST_BYTES) == ring_sha256, "SourceV5 mixed soak ring differs from its independent raw pin")
    reader_record = next((item for item in selected_manifest["source"]["files"] if item.get("path") == SOAK_READER_PATH), None)
    require(type(reader_record) is dict and reader_record.get("kind") == "file", "SourceV5 inventory omits its soak reader")
    soak_reader = load_pinned_module(safe_child(source_base, SOAK_READER_PATH, "SourceV5 soak reader"), reader_record["sha256"], "SourceV5 soak reader", MAX_SCRIPT_BYTES, "source_v5_soak_reader")
    _fixed_limits, expected_domain, expected_scope, expected_buckets, _fixed_policy_sha = soak_reader._check_policy(selected_manifest["fixed_runtime_policy"], soak["profile"])
    rust_probe_context = probe["rust_control_context"]
    require(rust_probe_context["global_ceilings"] == expected_domain and rust_probe_context["tenant_ceilings"] == expected_domain, "compiled construction probe hard ceilings differ from SourceV5 numeric resource policy")
    require(rust_probe_context["scope_limits"] == {
        "managed_memory": expected_scope["managed_memory_limit"],
        "disk_operations": expected_scope["disk_operation_limit"],
        "network_operations": expected_scope["network_operation_limit"],
    }, "compiled construction probe scope limits differ from SourceV5 numeric resource policy")
    require(rust_probe_context["rate_buckets"] == {
        direction: {
            "ceiling_bytes_per_second": bucket["ceiling_bytes_per_second"],
            "ceiling_burst_bytes": bucket["ceiling_burst_bytes"],
            "max_reservations": bucket["max_reservations"],
        }
        for direction, bucket in expected_buckets.items()
    }, "compiled construction probe rate buckets differ from SourceV5 numeric resource policy")
    ring_info = soak_reader._validate_ring({"identity": {"profile": soak["profile"]}, "oracle": {"ring_path": str(ring_path), "ring_sha256": ring_sha256}}, selected_manifest["source"]["source_tree_sha256"], soak_sha)
    rate_rows = [row for row in spec["rates"] if row.get("host_id") == host_id and row.get("family") == "mixed" and row.get("profile") == soak["profile"] and row.get("load_percent") == 70]
    require(len(rate_rows) == 1 and rate_rows[0]["arrivals_per_second"] == ring_info["average_rate_per_second"], "SourceV5 soak ring is not the canonical 70-percent mixed oracle")

    condition_path = safe_child(input_root, pressure_condition["condition"]["relative_path"], "SourceV5 pressure condition template")
    condition_raw, condition_raw_sha = read_stable(condition_path, "SourceV5 pressure condition template", MAX_SPEC_BYTES)
    require(condition_raw_sha == pressure_condition["condition_sha256"] and condition_raw == canonical_bytes(parse_json(condition_raw, "SourceV5 pressure condition template")), "SourceV5 pressure condition raw bytes differ")
    condition_value = parse_json(condition_raw, "SourceV5 pressure condition template")
    require(condition_value.get("schema") == "allocatbelt.application-pressure-request.v1" and condition_value.get("identity", {}).get("condition_id") == pressure_condition["condition_id"], "SourceV5 pressure condition is not the exact pressure request template")
    supervision = _derive_v5_pressure_schedule(duration, condition_value, pressure_condition["schedule"])

    pressure_pin: dict[str, Any] | None = None
    pressure_semantic_sha: str | None = None
    if pressure_recipe_path is not None:
        require(type(pressure_recipe_raw_sha256) is str and is_sha256(pressure_recipe_raw_sha256) and is_sha256(pressure_recipe_semantic_sha256), "SourceV5 pressure recipe requires both raw and semantic SHA pins")
        require(capacity["evidence"] is not None, "SourceV5 pressure recipe cannot be frozen without app-byte capacity evidence")
        raw, raw_sha = read_stable(pressure_recipe_path, "SourceV5 instantiated pressure recipe", MAX_MANIFEST_BYTES)
        require(raw_sha == pressure_recipe_raw_sha256, "SourceV5 pressure recipe raw bytes differ from caller pin")
        pressure_value = parse_json(raw, "SourceV5 instantiated pressure recipe")
        require(raw == canonical_bytes(pressure_value), "SourceV5 instantiated pressure recipe is not canonical JSON")
        pressure_module = _source_v5_module(source_base, selected_manifest["source"]["files"], harness["pressure_validator"]["path"], harness["pressure_validator"]["sha256"], "source_v5_pressure_validator")
        try:
            pressure_info = pressure_module._validate_recipe(pressure_value, pressure_recipe_semantic_sha256)
        except (TypeError, ValueError, getattr(pressure_module, "ReadbackError", ValueError)) as error:
            raise RecipeBuildError(f"captured SourceV5 pressure validator rejected its final recipe: {error}") from error
        identity = pressure_info["identity"]
        require(identity["host_id"] == host_id and identity["run_id"] == job["run_id"] and identity["nonce"] == nonce and identity["condition_id"] == pressure_condition["condition_id"], "SourceV5 pressure recipe host/run/nonce/condition differs")
        require(identity["allocator"] == "allocatbelt" and identity["executor"] == "allocatbelt", "SourceV5 pressure recipe application role differs")
        require(pressure_value["files"]["source_manifest"]["raw_sha256"] == source_manifest_raw_sha and pressure_value["files"]["application_binary"]["raw_sha256"] == soak_sha, "SourceV5 pressure source/binary pins differ from the timed soak")
        evidence = capacity["evidence"]
        capacity_artifact_path = safe_child(input_root, evidence["artifact"]["relative_path"], "SourceV5 app-byte capacity evidence")
        pressure_calibration_path = safe_child(input_root, pressure_condition["pressure_calibration"]["artifact"]["relative_path"], "SourceV5 pressure calibration evidence")
        require(pressure_info["files"]["application_capacity_calibration"]["raw_sha256"] == evidence["artifact"]["raw_sha256"], "SourceV5 pressure recipe app-byte calibration differs from the capacity evidence pin")
        require(pressure_info["files"]["application_capacity_calibration"]["path"] == str(capacity_artifact_path), "SourceV5 pressure recipe app-byte calibration path differs from its capacity artifact")
        require(pressure_info["calibration_sha256"] == pressure_condition["pressure_calibration"]["artifact"]["raw_sha256"], "SourceV5 pressure recipe calibration digest differs from its exact evidence pin")
        require(pressure_info["schedule"]["seed"] == pressure_condition["schedule"]["seed"], "SourceV5 pressure recipe seed differs from its condition schedule")
        require(pressure_info["schedule"] == supervision["pressure_schedule"], "SourceV5 pressure recipe does not preserve the raw condition while extending the complete soak/process-cleanup horizon")
        require(pressure_info["schedule"]["duration_seconds"] == supervision["pressure_duration_seconds"] and pressure_info["schedule"]["sample_interval_ms"] == pressure_condition["schedule"]["sample_interval_ms"] == 100, "SourceV5 pressure recipe differs from its independently derived enclosing horizon")
        require(pressure_info["schedule"]["minimum_overlap_seconds"] >= pressure_condition["readiness_thresholds"]["minimum_overlap_seconds"], "SourceV5 pressure overlap is below the pinned condition threshold")
        require(pressure_info["schedule"]["duration_seconds"] * 1000 // pressure_info["schedule"]["sample_interval_ms"] >= pressure_condition["readiness_thresholds"]["minimum_ready_samples"], "SourceV5 pressure schedule cannot provide the pinned readiness sample count")
        require(pressure_info["schedule"]["sample_interval_ms"] <= pressure_condition["readiness_thresholds"]["maximum_sample_gap_ms"], "SourceV5 pressure cadence exceeds the pinned maximum sample gap")
        require(pressure_info["condition_sha256"] == pressure_value["condition_sha256"], "SourceV5 pressure condition semantic digest differs from its full validator")
        pressure_pin = {"path": str(pressure_recipe_path.resolve(strict=True)), "raw_sha256": raw_sha, "semantic_sha256": pressure_recipe_semantic_sha256}
        pressure_semantic_sha = pressure_info["condition_sha256"]
    elif any(value is not None for value in (pressure_recipe_raw_sha256, pressure_recipe_semantic_sha256)):
        raise RecipeBuildError("SourceV5 pressure recipe path and both SHA pins must be supplied together")

    qualification = {
        "spec": {"path": str(spec_path.resolve(strict=True)), "raw_sha256": spec_raw_sha, "semantic_sha256": spec_sha256},
        "plan": {"path": str(plan_path.resolve(strict=True)), "raw_sha256": plan_raw_sha, "semantic_sha256": plan_sha256},
        "campaign_inputs_module_sha256": input_module_sha,
        "capacity_template": {
            "template_sha256": next(item["template_sha256"] for item in plan["capacity_process_templates"] if item["capacity_key"]["host_id"] == host_id and item["capacity_key"]["workload"] == "mixed" and item["capacity_key"]["profile"] == soak["profile"]),
            "calibration_id": capacity["calibration_id"], "request_template": capacity["request_template"],
            "context_template": capacity["context_template"], "evidence": capacity["evidence"],
        },
        "pressure_condition": {
            "condition_id": pressure_condition["condition_id"], "condition_sha256": pressure_condition["condition_sha256"],
            "condition": pressure_condition["condition"], "pressure_calibration": pressure_condition["pressure_calibration"],
            "readiness_thresholds": pressure_condition["readiness_thresholds"], "schedule": pressure_condition["schedule"],
        },
        "feedback_process_template": {
            **feedback_template,
        },
        "nonce_instantiation": nonce_material,
        "capacity_evidence_ready": bool(validation["capacity_evidence_ready"]),
        "feedback_runtime_composition_ready": bool(validation["feedback_runtime_composition_ready"]),
        "execution_ready": bool(validation["execution_ready"]), "full_gate_ready": bool(validation["full_gate_ready"]),
        "launch_enabled": bool(validation["execution_ready"] and validation["capacity_evidence_ready"] and validation["feedback_runtime_composition_ready"] and pressure_pin is not None),
        "full_gate_gaps": validation["full_gate_gaps"],
    }
    pressure_binding = {
        "request_template": {"path": str(condition_path.resolve(strict=True)), "raw_sha256": condition_raw_sha},
        "recipe": pressure_pin,
        "condition_sha256": pressure_semantic_sha,
        "driver": harness["pressure_driver"], "validator": harness["pressure_validator"],
    }
    feedback_expectation = {
        "template": qualification["feedback_process_template"],
        "template_sha256": feedback_template["template_sha256"],
        "trace_identity": trace_identity,
        "policy": feedback_policy,
        "validator": harness["feedback_validator"],
    }
    recipe = {
        "schema": "allocatbelt.application-soak-parent-recipe.v2",
        "identity": soak_identity,
        "source": {"root": str(source_base), "manifest_path": str(manifest_paths[host_id].resolve(strict=True)), "manifest_sha256": source_manifest_raw_sha},
        "oracle": {"producer_path": str(app_binary), "producer_sha256": app_sha, "ring_path": str(ring_path), "ring_sha256": ring_sha256},
        "runtime": {
            "mode": mode, "duration_seconds": duration, "sample_interval_ms": 100,
            "resource_limits": limits, "fixed_global_control_baseline": selected_manifest["resource_domain_calibration"]["record"]["fixed_global_control_baseline"],
            "terminal_budget_bytes": terminal_budget, "sample_budget_bytes": sample_budget,
        },
        "qualification": qualification,
        "construction_probe": construction_probe_pin,
        "pressure": pressure_binding,
        "feedback_expectation": feedback_expectation,
        "validator": harness["soak_validator"],
        "runner": harness["soak_runner"],
    }
    reader = load_pinned_module(safe_child(source_base, SOAK_READER_PATH, "SourceV5 soak reader"), harness["soak_validator"]["sha256"], "SourceV5 soak reader", MAX_SCRIPT_BYTES, "source_v5_soak_recipe_reader")
    recipe_bytes = canonical_bytes(recipe)
    recipe_raw_sha = sha256(recipe_bytes)
    try:
        normalized_recipe, normalized_identity = reader._validate_recipe(recipe, recipe_raw_sha)
    except (OSError, TypeError, ValueError) as error:
        raise RecipeBuildError(f"captured SourceV5 soak validator rejected generated recipe: {error}") from error
    require(canonical_bytes(normalized_recipe) == recipe_bytes and normalized_identity == soak_identity, "captured SourceV5 soak reader normalized its frozen recipe")
    return {
        "recipe": recipe, "recipe_bytes": recipe_bytes, "recipe_sha256": recipe_raw_sha,
        "soak_run_id": job["run_id"], "context_job_run_id": job["run_id"],
        "planned_pressure_soak_run_id": job["run_id"],
        "source_manifest_semantic_sha256": selected_manifest["manifest_sha256"],
        "source_manifest_file_sha256": source_manifest_raw_sha, "source_tree_sha256": selected_manifest["source"]["source_tree_sha256"],
        "spec_sha256": spec_sha256, "plan_sha256": plan_sha256, "mode": mode, "duration_seconds": duration,
        "execution_started": False, "qualification_enabled": False, "launch_enabled": qualification["launch_enabled"],
    }


def write_exclusive(path: Path, data: bytes) -> None:
    require(path.is_absolute(), "recipe output path must be absolute")
    parent = safe_directory(path.parent, "recipe output directory")
    output = parent / path.name
    try:
        info = output.lstat()
        raise RecipeBuildError(f"refusing to replace existing recipe output ({stat.S_IFMT(info.st_mode):#o})")
    except FileNotFoundError:
        pass
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(output, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            require(written > 0, "recipe output stopped accepting bytes")
            offset += written
        os.fsync(descriptor)
        require(stat.S_IMODE(os.fstat(descriptor).st_mode) == 0o600, "recipe output permissions are not exactly 0600")
    except BaseException:
        os.close(descriptor)
        raise
    else:
        os.close(descriptor)
    directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _load_json_pin(path: Path, expected_sha256: str, label: str, maximum: int) -> dict[str, Any]:
    raw, actual_sha = read_stable(path, label, maximum)
    require(actual_sha == expected_sha256, f"{label} file differs from its caller-frozen SHA-256")
    value = parse_json(raw, label)
    require(raw == canonical_bytes(value), f"{label} file is not canonical JSON")
    return value


def command_build(args: argparse.Namespace) -> int:
    spec = _load_json_pin(args.spec, args.spec_sha256, "campaign spec", MAX_SPEC_BYTES)
    plan = _load_json_pin(args.plan, args.plan_file_sha256, "campaign plan", MAX_PLAN_BYTES)
    jobs = plan.get("jobs")
    require(type(jobs) is dict, "campaign plan has no phase job map")
    if spec.get("schema") == SPEC_SCHEMA_V3 and plan.get("schema") == PLAN_SCHEMA_V3:
        selected_jobs = jobs.get("soak")
        label = "SourceV5 external-pressure soak"
    else:
        selected_jobs = jobs.get("confirmation")
        label = "fixed context"
    require(type(selected_jobs) is list, f"campaign plan has no {label} jobs")
    matching_jobs = [job for job in selected_jobs if type(job) is dict and job.get("run_id") == args.job_run_id]
    require(len(matching_jobs) == 1, f"requested {label} run ID is missing or duplicated in the frozen plan")
    result = build_recipe(
        spec, plan, matching_jobs[0],
        spec_sha256=args.spec_sha256,
        plan_sha256=args.plan_sha256,
        spec_path=args.spec,
        source_root=args.source_root,
        oracle_root=args.oracle_root,
        ring_relative_path=args.ring_relative_path,
        ring_sha256=args.ring_sha256,
        mode=args.mode,
        duration_seconds=args.duration_seconds,
        terminal_budget_bytes=args.terminal_budget_bytes,
        sample_budget_bytes=args.sample_budget_bytes,
        construction_probe_path=None if args.construction_probe is None else args.construction_probe.resolve(strict=True),
        construction_probe_sha256=args.construction_probe_sha256,
        plan_path=args.plan,
        plan_file_sha256=args.plan_file_sha256,
        pressure_recipe_path=args.pressure_recipe,
        pressure_recipe_raw_sha256=args.pressure_recipe_raw_sha256,
        pressure_recipe_semantic_sha256=args.pressure_recipe_semantic_sha256,
    )
    require(args.output.is_absolute(), "recipe output path must be absolute")
    output_parent = safe_directory(args.output.parent, "recipe output directory")
    output_mode = output_parent.stat().st_mode
    require(output_mode & 0o077 == 0 and output_mode & 0o300 == 0o300, "recipe output directory must be private and owner-writable")
    output_path = output_parent / args.output.name
    source_root = Path(result["recipe"]["source"]["root"]).resolve(strict=True)
    require(not output_path.resolve(strict=False).is_relative_to(source_root), "recipe output must be outside the captured source root")
    write_exclusive(args.output, result["recipe_bytes"])
    saved_recipe, saved_recipe_sha256 = read_stable(args.output, "new parent recipe", MAX_SPEC_BYTES)
    require(saved_recipe == result["recipe_bytes"] and saved_recipe_sha256 == result["recipe_sha256"], "written recipe differs from its preflighted canonical bytes")
    v2_recipe = result["recipe"]["schema"] == "allocatbelt.application-soak-parent-recipe.v2"
    receipt = {
        "schema": RECIPE_RECEIPT_SCHEMA_V2 if v2_recipe else RECIPE_RECEIPT_SCHEMA,
        "recipe_path": str(args.output.resolve(strict=True)),
        "recipe_sha256": result["recipe_sha256"],
        "soak_run_id": result["soak_run_id"],
        "context_job_run_id": result["context_job_run_id"],
        "planned_pressure_soak_run_id": result["planned_pressure_soak_run_id"],
        "source_manifest_semantic_sha256": result["source_manifest_semantic_sha256"],
        "source_manifest_file_sha256": result["source_manifest_file_sha256"],
        "source_tree_sha256": result["source_tree_sha256"],
        "spec_sha256": result["spec_sha256"],
        "plan_sha256": result["plan_sha256"],
        "mode": result["mode"],
        "duration_seconds": result["duration_seconds"],
        "execution_started": False,
        "qualification_enabled": False,
    }
    if v2_recipe:
        receipt.update({
            "launch_enabled": result["launch_enabled"],
            "construction_probe_raw_sha256": result["recipe"]["construction_probe"]["raw_sha256"],
            "construction_probe_binary_sha256": result["recipe"]["construction_probe"]["binary_sha256"],
            "pressure_recipe_raw_sha256": result["recipe"]["pressure"]["recipe"]["raw_sha256"] if result["recipe"]["pressure"]["recipe"] is not None else None,
            "pressure_recipe_semantic_sha256": result["recipe"]["pressure"]["recipe"]["semantic_sha256"] if result["recipe"]["pressure"]["recipe"] is not None else None,
            "pressure_condition_sha256": result["recipe"]["pressure"]["condition_sha256"],
            "capacity_evidence_ready": result["recipe"]["qualification"]["capacity_evidence_ready"],
            "feedback_runtime_composition_ready": result["recipe"]["qualification"]["feedback_runtime_composition_ready"],
        })
    sys.stdout.buffer.write(canonical_bytes(receipt))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build", help="build a pinned prospective fixed-policy soak recipe")
    build.add_argument("--spec", type=Path, required=True)
    build.add_argument("--spec-sha256", required=True)
    build.add_argument("--plan", type=Path, required=True)
    build.add_argument("--plan-sha256", required=True)
    build.add_argument("--plan-file-sha256", required=True)
    build.add_argument("--job-run-id", required=True)
    build.add_argument("--source-root", type=Path, required=True)
    build.add_argument("--oracle-root", type=Path, required=True)
    build.add_argument("--ring-relative-path", required=True)
    build.add_argument("--ring-sha256", required=True)
    build.add_argument("--mode", choices=("qualified", "functional"), required=True)
    build.add_argument("--duration-seconds", type=int, required=True)
    build.add_argument("--terminal-budget-bytes", type=int, required=True)
    build.add_argument("--sample-budget-bytes", type=int, required=True)
    build.add_argument("--construction-probe", type=Path)
    build.add_argument("--construction-probe-sha256")
    build.add_argument("--pressure-recipe", type=Path)
    build.add_argument("--pressure-recipe-raw-sha256")
    build.add_argument("--pressure-recipe-semantic-sha256")
    build.add_argument("--output", type=Path, required=True)
    build.set_defaults(handler=command_build)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return args.handler(args)
    except RecipeBuildError as error:
        print(f"application soak recipe: {error}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"application soak recipe: I/O failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
