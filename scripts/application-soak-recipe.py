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
import types
from pathlib import Path, PurePosixPath
from typing import Any


SOURCE_SCHEMA = "allocatbelt.application-source-manifest.v4"
SPEC_SCHEMA = "allocatbelt.application-campaign-spec.v2"
PLAN_SCHEMA = "allocatbelt.application-campaign-plan.v2"
RECIPE_RECEIPT_SCHEMA = "allocatbelt.application-soak-recipe-build-receipt.v1"
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
RSS_GROWTH_PERCENT = 5
MAX_SPEC_BYTES = 32 * 1024 * 1024
MAX_PLAN_BYTES = 256 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 64 * 1024 * 1024
MAX_SCRIPT_BYTES = 4 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
MAX_EXTERNAL_ORACLE_BYTES = 512 * 1024 * 1024


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
) -> dict[str, Any]:
    """Build and reader-validate one immutable soak recipe without launching."""
    spec_raw, spec_file_sha256 = read_stable(spec_path, "campaign spec", MAX_SPEC_BYTES)
    require(spec_file_sha256 == spec_sha256, "campaign spec file differs from its caller-frozen SHA-256")
    require(parse_json(spec_raw, "campaign spec") == spec and spec_raw == canonical_bytes(spec), "campaign spec object differs from its canonical frozen file")
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
    require(type(jobs) is dict and type(jobs.get("confirmation")) is list, "campaign plan has no fixed confirmation jobs")
    matching_jobs = [job for job in jobs["confirmation"] if type(job) is dict and job.get("run_id") == args.job_run_id]
    require(len(matching_jobs) == 1, "requested fixed context run ID is missing or duplicated in the frozen plan")
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
    receipt = {
        "schema": RECIPE_RECEIPT_SCHEMA,
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
