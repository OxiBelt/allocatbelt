#!/usr/bin/env python3
"""Focused offline tests for the context-scoped pressure readback contract."""
from __future__ import annotations

import argparse
import ast
import inspect
import importlib.util
import builtins
import contextlib
import json
import io
import os
import stat
import sys
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch


SCRIPT_DIR = Path(__file__).resolve().parent
READER_PATH = SCRIPT_DIR / "application-pressure-readback.py"
DRIVER_PATH = SCRIPT_DIR / "application-pressure-driver.py"
FEEDBACK_READER_PATH = SCRIPT_DIR / "application-feedback-readback.py"


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


readback = _load_module("pressure_readback_v2_test_target", READER_PATH)
driver = _load_module("pressure_driver_v2_test_target", DRIVER_PATH)
feedback_reader = _load_module("pressure_feedback_readback_floor_test_target", FEEDBACK_READER_PATH)
SCOPE_FIXTURE_SCHEMA = "allocatbelt.application-pressure-calibration-v2-native-fixture.v1"
PRESSURE_OFFLINE_FIXTURE_SCHEMA = "allocatbelt.application-pressure-offline-fixture.v1"
SOAK_PRESSURE_OFFLINE_FIXTURE_SCHEMA = "allocatbelt.application-source5-soak-pressure-offline-fixture.v1"
CLOSED_RECORDED_SCOPE_FIXTURE_SCHEMA = \
    "allocatbelt.application-pressure-closed-recorded-scope-fixture.v1"
SCOPE_FIXTURE_EXPECTED_KEYS = {
    "host_id", "condition_id", "pressure_calibration_id", "capacity_key",
    "calibration_raw_sha256", "calibration_sha256", "scope_sha256",
    "condition_sha256", "source_manifest_sha256", "source_manifest_semantic_sha256",
    "source_tree_sha256", "capacity_tsv_raw_sha256", "capacity_bundle_pins_sha256",
    "context_policy_sha256", "context_policy_artifact_raw_sha256",
    "sample_count", "samples_sha256", "summary", "pressure_thresholds",
    "readiness_thresholds", "driver_sha256", "reader_sha256", "capacity_producer_sha256",
    "feedback_composer_sha256", "feedback_reader_sha256", "host_verification_sha256",
    "calibration_context_policy_bundle_raw_sha256", "per_job_context_policy_bundle_raw_sha256",
    "worker_cleanup_sha256", "worker_session_count", "scratch_file_removed",
}


def run_genuine_scope_fixture(path: Path) -> dict[str, Any]:
    fixture, _, _ = readback.read_canonical(path, "genuine SourceV5 pressure scope fixture", 4 * 1024 * 1024)
    fixture = readback.exact(fixture, {
        "schema", "source_root", "evidence_path_map", "calibration_pin", "context_policy_pin",
        "capacity_bundle_pins", "observed_host_pin", "host_verification_pin", "expected",
    }, "genuine SourceV5 pressure scope fixture")
    if fixture["schema"] != SCOPE_FIXTURE_SCHEMA:
        raise readback.ReadbackError("unsupported genuine SourceV5 pressure scope fixture schema")
    expected = readback.exact(fixture["expected"], SCOPE_FIXTURE_EXPECTED_KEYS, "genuine pressure scope expected pins")
    calibration_pin = readback._raw_pin(fixture["calibration_pin"], "fixture calibration pin")
    context_policy_pin = readback._raw_pin(fixture["context_policy_pin"], "fixture per-job context-policy pin")
    observed_host_pin = readback._raw_pin(fixture["observed_host_pin"], "fixture observed-host pin")
    capacity_bundle = readback.exact(fixture["capacity_bundle_pins"], {
        "schema", "capacity_key", "source_manifest", "request", "artifact", "receipt",
    }, "fixture complete capacity bundle")
    for name in ("source_manifest", "request", "artifact", "receipt"):
        readback._raw_pin(capacity_bundle[name], f"fixture capacity {name} pin")
    host_receipt_pin = readback._scope_receipt_pin_v2(
        fixture["host_verification_pin"], "fixture strict host-verification receipt",
    )
    calibration, _, calibration_raw_sha = readback.read_canonical(
        Path(calibration_pin["path"]), "fixture context calibration", 64 * 1024 * 1024,
    )
    if calibration_raw_sha != calibration_pin["raw_sha256"]:
        raise readback.ReadbackError("fixture calibration bytes differ from their pin")
    calibration = readback._validate_calibration_v2_body(calibration)
    original_policy_sha = calibration["scope"]["context_policy_bundle"]["raw_sha256"]
    if context_policy_pin["raw_sha256"] == original_policy_sha:
        raise readback.ReadbackError("fixture does not include distinct per-job composer references")
    original_bundle, _, _ = readback.read_canonical(
        Path(calibration["scope"]["context_policy_bundle"]["path"]),
        "fixture calibration context-policy bundle", 8 * 1024 * 1024,
    )
    current_bundle, _, _ = readback.read_canonical(
        Path(context_policy_pin["path"]), "fixture per-job context-policy bundle", 8 * 1024 * 1024,
    )
    original_members = readback.exact(original_bundle, {"schema", "artifact", "members"}, "fixture calibration context bundle")["members"]
    current_members = readback.exact(current_bundle, {"schema", "artifact", "members"}, "fixture per-job context bundle")["members"]
    if type(original_members) is not list or type(current_members) is not list or len(original_members) != 2 or len(current_members) != 2:
        raise readback.ReadbackError("fixture context-policy bundles do not each contain two genuine members")
    for index, (original_member, current_member) in enumerate(zip(original_members, current_members)):
        original_member = readback.exact(
            original_member,
            {"descriptor", "request", "construction_probe", "resolved_policy", "composition_receipt"},
            f"fixture calibration member[{index}]",
        )
        current_member = readback.exact(
            current_member,
            {"descriptor", "request", "construction_probe", "resolved_policy", "composition_receipt"},
            f"fixture per-job member[{index}]",
        )
        for field in ("request", "construction_probe", "resolved_policy", "composition_receipt"):
            if field == "construction_probe":
                original_pin = readback.exact(original_member[field], {"path", "raw_sha256", "allocator", "binary_sha256"}, f"fixture original member[{index}] probe")
                current_pin = readback.exact(current_member[field], {"path", "raw_sha256", "allocator", "binary_sha256"}, f"fixture current member[{index}] probe")
                original_reference = (original_pin["path"], original_pin["raw_sha256"])
                current_reference = (current_pin["path"], current_pin["raw_sha256"])
            else:
                original_pin = readback._raw_pin(original_member[field], f"fixture original member[{index}] {field}")
                current_pin = readback._raw_pin(current_member[field], f"fixture current member[{index}] {field}")
                original_reference = (original_pin["path"], original_pin["raw_sha256"])
                current_reference = (current_pin["path"], current_pin["raw_sha256"])
            if current_reference == original_reference:
                raise readback.ReadbackError(f"fixture per-job member[{index}] reuses calibration {field} references")
    result = readback.verify_calibration_scope_v2_offline(
        calibration_pin, context_policy_pin, capacity_bundle, observed_host_pin,
        source_root=fixture["source_root"], evidence_path_map=fixture["evidence_path_map"],
        host_verification_pin=host_receipt_pin,
    )
    require_values = {
        "host_id": result["capacity_key"]["host_id"],
        "condition_id": result["condition_id"],
        "pressure_calibration_id": result["pressure_calibration_id"],
        "capacity_key": result["capacity_key"],
        "calibration_raw_sha256": result["calibration_raw_sha256"],
        "calibration_sha256": result["calibration_sha256"],
        "scope_sha256": result["scope_sha256"],
        "condition_sha256": result["condition_sha256"],
        "source_manifest_sha256": result["source_manifest_sha256"],
        "source_manifest_semantic_sha256": result["source_manifest_semantic_sha256"],
        "source_tree_sha256": result["source_tree_sha256"],
        "capacity_tsv_raw_sha256": result["capacity_tsv_raw_sha256"],
        "capacity_bundle_pins_sha256": result["capacity_bundle_pins_sha256"],
        "context_policy_sha256": result["context_policy_sha256"],
        "context_policy_artifact_raw_sha256": result["context_policy_artifact_raw_sha256"],
        "sample_count": result["sample_count"],
        "samples_sha256": result["samples_sha256"],
        "summary": result["summary"],
        "pressure_thresholds": result["pressure_thresholds"],
        "readiness_thresholds": result["readiness_thresholds"],
        "driver_sha256": result["driver_sha256"],
        "reader_sha256": result["reader_sha256"],
        "capacity_producer_sha256": result["capacity_producer_sha256"],
        "feedback_composer_sha256": result["feedback_composer_sha256"],
        "feedback_reader_sha256": result["feedback_reader_sha256"],
        "host_verification_sha256": result["host_verification"]["host_verification_sha256"],
        "calibration_context_policy_bundle_raw_sha256": original_policy_sha,
        "per_job_context_policy_bundle_raw_sha256": context_policy_pin["raw_sha256"],
        "worker_cleanup_sha256": result["worker_cleanup_sha256"],
        "worker_session_count": result["worker_session_count"],
        "scratch_file_removed": result["scratch_file_removed"],
    }
    if require_values != expected:
        raise readback.ReadbackError("genuine SourceV5 scope fixture expected pins differ from full public replay")

    def evidence_map_with(directory: Path) -> dict[str, Any]:
        entries = list(fixture["evidence_path_map"]["entries"])
        entry = {"origin": str(directory), "local": str(directory)}
        if all(item["origin"] != entry["origin"] for item in entries):
            entries.append(entry)
        entries.sort(key=lambda item: item["origin"])
        return {"schema": readback.EVIDENCE_PATH_MAP_SCHEMA_V1, "entries": entries}

    def write_canonical(directory: Path, name: str, value: object) -> tuple[Path, str]:
        target = directory / name
        raw = readback.canonical_bytes(value)
        target.write_bytes(raw)
        return target, readback.sha256_bytes(raw)

    def expect_rejected(
        *, calibration: dict[str, str] = calibration_pin,
        context_policy: dict[str, str] = context_policy_pin,
        capacity: dict[str, Any] = capacity_bundle,
        host_receipt: dict[str, str] = host_receipt_pin,
        evidence_map: dict[str, Any],
    ) -> None:
        try:
            readback.verify_calibration_scope_v2_offline(
                calibration, context_policy, capacity, observed_host_pin,
                source_root=fixture["source_root"], evidence_path_map=evidence_map,
                host_verification_pin=host_receipt,
            )
        except readback.ReadbackError:
            return
        raise AssertionError("mutated genuine SourceV5 scope inputs unexpectedly replayed")

    def identity_map_with_file_paths(paths: list[Path]) -> dict[str, Any]:
        entries = list(fixture["evidence_path_map"]["entries"])
        origins = {item["origin"] for item in entries}
        for path_value in paths:
            target = readback.absolute_path(str(path_value), "additional identity evidence path")
            info = target.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise readback.ReadbackError("additional identity evidence path is not a regular file")
            if str(target) not in origins:
                entries.append({"origin": str(target), "local": str(target)})
                origins.add(str(target))
        entries.sort(key=lambda item: item["origin"])
        return {"schema": readback.EVIDENCE_PATH_MAP_SCHEMA_V1, "entries": entries}

    def identity_map_without_file_path(path_value: str) -> dict[str, Any]:
        target = readback.absolute_path(path_value, "nested evidence path under test")
        original = list(fixture["evidence_path_map"]["entries"])
        directory_origins = []
        for entry in original:
            origin = Path(entry["origin"])
            try:
                info = origin.lstat()
            except OSError:
                continue
            if stat.S_ISDIR(info.st_mode) and (target == origin or origin in target.parents):
                directory_origins.append(origin)
        exact_target = [entry for entry in original if entry["origin"] == str(target)]
        if not directory_origins:
            if not exact_target:
                raise readback.ReadbackError("fixture path map does not authorize the selected nested path")
            remaining = [entry for entry in original if entry["origin"] != str(target)]
        else:
            root = min(directory_origins, key=lambda item: len(item.parts))
            source_root = readback.absolute_path(fixture["source_root"], "fixture SourceV5 source root")
            if target == source_root or source_root in target.parents:
                raise readback.ReadbackError("fixture nested evidence path is covered by the required SourceV5 root mapping")
            remaining = [
                entry for entry in original
                if entry["origin"] != str(root) and not entry["origin"].startswith(str(root).rstrip("/") + "/")
            ]
            try:
                relative_parts = target.relative_to(root).parts
            except ValueError as error:
                raise readback.ReadbackError("selected nested path escaped its mapped evidence directory") from error
            current = root
            for index, component in enumerate(relative_parts):
                next_directory: Path | None = None
                for child in current.iterdir():
                    if child.name == component:
                        if index == len(relative_parts) - 1:
                            if child != target or not child.is_file() or child.is_symlink():
                                raise readback.ReadbackError("selected nested evidence path is not the expected regular file")
                            continue
                        if not child.is_dir() or child.is_symlink():
                            raise readback.ReadbackError("selected nested evidence path traverses a non-directory")
                        next_directory = child
                        continue
                    if child.is_symlink():
                        continue
                    info = child.lstat()
                    if stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode):
                        remaining.append({"origin": str(child), "local": str(child)})
                if index < len(relative_parts) - 1:
                    if next_directory is None:
                        raise readback.ReadbackError("selected nested evidence path has a missing directory")
                    current = next_directory
            if (source_root == root or root in source_root.parents) and not any(
                entry["origin"] == str(source_root) for entry in remaining
            ):
                remaining.append({"origin": str(source_root), "local": str(source_root)})
        remaining.sort(key=lambda item: item["origin"])
        if len(remaining) > 4096:
            raise readback.ReadbackError("fixture path-map narrowing exceeds its closed entry bound")
        narrowed = {"schema": readback.EVIDENCE_PATH_MAP_SCHEMA_V1, "entries": remaining}
        readback._normalize_evidence_path_map(narrowed, fixture["source_root"])
        return narrowed

    def expect_missing_path_map(path_value: str) -> None:
        narrowed = identity_map_without_file_path(path_value)
        try:
            readback.verify_calibration_scope_v2_offline(
                calibration_pin, context_policy_pin, capacity_bundle, observed_host_pin,
                source_root=fixture["source_root"], evidence_path_map=narrowed,
                host_verification_pin=host_receipt_pin,
            )
        except readback.ReadbackError as error:
            if "absent from the explicit identity path map" not in str(error):
                raise AssertionError(f"nested path omission did not fail at the map boundary: {error}") from error
            return
        raise AssertionError("offline replay accepted a nested canonical input omitted from its identity map")

    capacity_request, _, _ = readback.read_canonical(
        Path(capacity_bundle["request"]["path"]), "fixture capacity producer request", 2 * 1024 * 1024,
    )
    expectation_pin = readback.exact(capacity_request["expectation"], {"path", "sha256"}, "fixture capacity expectation pin")
    expectation, _, expectation_sha = readback.read_canonical(
        Path(expectation_pin["path"]), "fixture capacity expectation", 2 * 1024 * 1024,
    )
    if expectation_sha != expectation_pin["sha256"] or "construction_probe" not in expectation:
        raise readback.ReadbackError("genuine capacity fixture lacks its pinned V4 construction probe")
    composer_probe = readback.exact(
        current_members[0]["construction_probe"],
        {"path", "raw_sha256", "allocator", "binary_sha256"},
        "fixture first per-job composer probe pin",
    )
    expectation_probe = readback.exact(
        expectation["construction_probe"],
        {"path", "raw_sha256", "allocator", "binary_sha256"},
        "fixture capacity expectation construction-probe pin",
    )
    for omitted_path in (expectation_pin["path"], expectation_probe["path"], composer_probe["path"]):
        expect_missing_path_map(omitted_path)
    authorized_path_map = identity_map_with_file_paths([
        Path(expectation_pin["path"]), Path(expectation_probe["path"]), Path(composer_probe["path"]),
    ])
    repeated = readback.verify_calibration_scope_v2_offline(
        calibration_pin, context_policy_pin, capacity_bundle, observed_host_pin,
        source_root=fixture["source_root"], evidence_path_map=authorized_path_map,
        host_verification_pin=host_receipt_pin,
    )
    strict_receipt, _, strict_receipt_sha = readback.read_canonical(
        Path(host_receipt_pin["path"]), "fixture strict host verification receipt", 8 * 1024 * 1024,
    )
    if strict_receipt_sha != host_receipt_pin["raw_sha256"] or repeated != strict_receipt:
        raise readback.ReadbackError("offline replay did not succeed after restoring explicit nested identity entries")

    with tempfile.TemporaryDirectory(prefix="pressure-v2-resealed-negatives-") as temporary:
        temp_root = Path(temporary).resolve()
        extra_map = evidence_map_with(temp_root)

        current_bundle, _, _ = readback.read_canonical(
            Path(context_policy_pin["path"]), "fixture current context-policy bundle", 8 * 1024 * 1024,
        )
        policy_pin = readback._raw_pin(current_bundle["artifact"], "fixture current shared policy artifact")
        policy, _, _ = readback.read_canonical(
            Path(policy_pin["path"]), "fixture current shared policy", 8 * 1024 * 1024,
        )
        collector = policy["numeric_policy"]["collector"]
        if type(collector.get("control_charge_bytes")) is not int:
            raise readback.ReadbackError("genuine fixture lacks the SourceV5 collector charge field")
        collector["control_charge_bytes"] += 1
        policy_body = {key: item for key, item in policy.items() if key != "policy_sha256"}
        policy["policy_sha256"] = readback.digest_object(policy_body)
        mutated_policy_path = temp_root / "mutated-shared-policy.json"
        mutated_policy_raw = readback.canonical_bytes(policy)
        mutated_policy_path.write_bytes(mutated_policy_raw)
        mutated_bundle = dict(current_bundle)
        mutated_bundle["artifact"] = {
            "path": str(mutated_policy_path),
            "raw_sha256": readback.sha256_bytes(mutated_policy_raw),
        }
        mutated_bundle_path = temp_root / "mutated-context-policy-bundle.json"
        mutated_bundle_raw = readback.canonical_bytes(mutated_bundle)
        mutated_bundle_path.write_bytes(mutated_bundle_raw)
        expect_rejected(
            context_policy={
                "path": str(mutated_bundle_path),
                "raw_sha256": readback.sha256_bytes(mutated_bundle_raw),
            },
            evidence_map=extra_map,
        )

        source_manifest, _, _ = readback.read_canonical(
            Path(calibration["scope"]["source_manifest"]["path"]),
            "fixture SourceV5 manifest", readback.MAX_SOURCE_BYTES,
        )
        original_commit = source_manifest["source"]["git_commit"]
        changed_commit = ("0" if original_commit[0] != "0" else "1") + original_commit[1:]
        source_manifest["source"]["git_commit"] = changed_commit
        source_manifest_body = {key: item for key, item in source_manifest.items() if key != "manifest_sha256"}
        source_manifest["manifest_sha256"] = readback.digest_object(source_manifest_body)
        changed_source_path, changed_source_sha = write_canonical(
            temp_root, "mutated-source-manifest.json", source_manifest,
        )
        source_calibration = json.loads(readback.canonical_bytes(calibration))
        source_calibration["scope"]["source_manifest"] = {
            "path": str(changed_source_path), "raw_sha256": changed_source_sha,
        }
        source_calibration["scope"]["source_manifest_semantic_sha256"] = source_manifest["manifest_sha256"]
        source_calibration["raw_inputs"]["source_manifest_raw_sha256"] = changed_source_sha
        source_calibration_body = {
            key: item for key, item in source_calibration.items() if key != "calibration_sha256"
        }
        source_calibration["calibration_sha256"] = readback.digest_object(source_calibration_body)
        changed_source_calibration_path, changed_source_calibration_sha = write_canonical(
            temp_root, "mutated-source-calibration.json", source_calibration,
        )
        expect_rejected(
            calibration={
                "path": str(changed_source_calibration_path),
                "raw_sha256": changed_source_calibration_sha,
            },
            evidence_map=extra_map,
        )

        receipt, _, _ = readback.read_canonical(
            Path(host_receipt_pin["path"]), "fixture strict host receipt", 8 * 1024 * 1024,
        )
        mutated_thresholds = dict(receipt["pressure_thresholds"])
        cpu_minimum = mutated_thresholds["cpu_busy_min_basis_points"]
        mutated_thresholds["cpu_busy_min_basis_points"] = cpu_minimum + 1 if cpu_minimum < 10000 else cpu_minimum - 1
        receipt["pressure_thresholds"] = mutated_thresholds
        receipt_body = {key: item for key, item in receipt.items() if key != "receipt_sha256"}
        receipt["receipt_sha256"] = readback.digest_object(receipt_body)
        mutated_receipt_path = temp_root / "mutated-host-receipt.json"
        mutated_receipt_raw = readback.canonical_bytes(receipt)
        mutated_receipt_path.write_bytes(mutated_receipt_raw)
        expect_rejected(
            host_receipt={
                "path": str(mutated_receipt_path),
                "raw_sha256": readback.sha256_bytes(mutated_receipt_raw),
                "scope_sha256": host_receipt_pin["scope_sha256"],
            },
            evidence_map=extra_map,
        )

        condition_value, _, _ = readback.read_canonical(
            Path(calibration["scope"]["condition"]["path"]), "fixture prospective condition", 1 * 1024 * 1024,
        )
        condition_value["pressure_thresholds"]["disk_write_min_bytes_per_second"] = readback.U64_MAX
        mutated_condition_path, mutated_condition_sha = write_canonical(
            temp_root, "mutated-pressure-condition.json", condition_value,
        )
        condition_calibration = json.loads(readback.canonical_bytes(calibration))
        condition_calibration["scope"]["condition"] = {
            "path": str(mutated_condition_path), "raw_sha256": mutated_condition_sha,
        }
        condition_calibration["scope"]["pressure_thresholds"] = dict(condition_value["pressure_thresholds"])
        condition_calibration["raw_inputs"]["condition_raw_sha256"] = mutated_condition_sha
        condition_calibration_body = {
            key: value for key, value in condition_calibration.items() if key != "calibration_sha256"
        }
        condition_calibration["calibration_sha256"] = readback.digest_object(condition_calibration_body)
        condition_calibration_path, condition_calibration_sha = write_canonical(
            temp_root, "mutated-condition-calibration.json", condition_calibration,
        )
        expect_rejected(
            calibration={"path": str(condition_calibration_path), "raw_sha256": condition_calibration_sha},
            evidence_map=extra_map,
        )

        capacity_artifact_path = Path(capacity_bundle["artifact"]["path"])
        capacity_artifact_raw, _ = readback.read_stable(
            capacity_artifact_path, "fixture prepared capacity TSV", 4096,
        )
        mutated_capacity_raw = capacity_artifact_raw[:-1] + bytes([capacity_artifact_raw[-1] ^ 1])
        mutated_capacity_path = temp_root / "mutated-capacity.tsv"
        mutated_capacity_path.write_bytes(mutated_capacity_raw)
        mutated_capacity_bundle = json.loads(readback.canonical_bytes(capacity_bundle))
        mutated_capacity_sha = readback.sha256_bytes(mutated_capacity_raw)
        mutated_capacity_bundle["artifact"] = {
            "path": str(mutated_capacity_path), "raw_sha256": mutated_capacity_sha,
        }
        capacity_calibration = json.loads(readback.canonical_bytes(calibration))
        capacity_calibration["scope"]["capacity_bundle_pins"] = mutated_capacity_bundle
        capacity_calibration["raw_inputs"]["capacity_bundle_pins_sha256"] = readback.digest_object(mutated_capacity_bundle)
        capacity_calibration["raw_inputs"]["application_capacity_calibration_sha256"] = mutated_capacity_sha
        capacity_calibration_body = {
            key: value for key, value in capacity_calibration.items() if key != "calibration_sha256"
        }
        capacity_calibration["calibration_sha256"] = readback.digest_object(capacity_calibration_body)
        capacity_calibration_path, capacity_calibration_sha = write_canonical(
            temp_root, "mutated-capacity-calibration.json", capacity_calibration,
        )
        expect_rejected(
            calibration={"path": str(capacity_calibration_path), "raw_sha256": capacity_calibration_sha},
            capacity=mutated_capacity_bundle,
            evidence_map=extra_map,
        )

        calibration_bad = json.loads(readback.canonical_bytes(calibration))
        calibration_bad["worker_cleanup"][0]["alive_after_cleanup"] = True
        calibration_body = {key: item for key, item in calibration_bad.items() if key != "calibration_sha256"}
        calibration_bad["calibration_sha256"] = readback.digest_object(calibration_body)
        mutated_calibration_path = temp_root / "mutated-worker-cleanup-calibration.json"
        mutated_calibration_raw = readback.canonical_bytes(calibration_bad)
        mutated_calibration_path.write_bytes(mutated_calibration_raw)
        expect_rejected(
            calibration={
                "path": str(mutated_calibration_path),
                "raw_sha256": readback.sha256_bytes(mutated_calibration_raw),
            },
            evidence_map=extra_map,
        )
    return result


def run_genuine_closed_recorded_scope_fixture(
    path: Path, expected_request_raw_sha256: str,
) -> dict[str, Any]:
    """Replay actual capture.v2 output while forbidding peer-ELF access and Popen."""
    fixture, _, fixture_sha = readback.read_canonical(
        path, "closed-recorded pressure fixture", 4 * 1024 * 1024,
    )
    if fixture_sha != expected_request_raw_sha256:
        raise readback.ReadbackError("closed-recorded pressure fixture raw pin differs")
    fixture = readback.exact(fixture, {
        "schema", "source_root", "evidence_path_map", "calibration_pin",
        "context_policy_pin", "capacity_bundle_pins", "observed_host_pin",
        "host_verification_pin", "probe_capture_pins", "expected",
    }, "closed-recorded pressure fixture")
    if fixture["schema"] != CLOSED_RECORDED_SCOPE_FIXTURE_SCHEMA:
        raise readback.ReadbackError("unsupported closed-recorded pressure fixture schema")
    expected = readback.exact(fixture["expected"], {
        "host_id", "condition_id", "pressure_calibration_id", "capacity_key",
        "calibration_raw_sha256", "scope_sha256", "receipt_sha256",
        "context_policy_bundle_raw_sha256", "context_policy_artifact_raw_sha256",
        "context_policy_sha256", "capacity_bundle_pins_sha256",
        "capacity_tsv_raw_sha256", "sample_count", "members",
    }, "closed-recorded pressure expected replay")
    source_root = readback.absolute_path(fixture["source_root"],
                                         "closed-recorded fixture SourceV5 root")
    calibration_pin = readback._raw_pin(fixture["calibration_pin"],
                                         "closed-recorded fixture calibration")
    context_policy_pin = readback._raw_pin(fixture["context_policy_pin"],
                                            "closed-recorded fixture context bundle")
    observed_host_pin = readback._raw_pin(fixture["observed_host_pin"],
                                           "closed-recorded fixture observed host")
    capacity_bundle = readback.exact(fixture["capacity_bundle_pins"], {
        "schema", "capacity_key", "source_manifest", "request", "artifact", "receipt",
    }, "closed-recorded fixture capacity bundle")
    source_pin = readback._raw_pin(capacity_bundle["source_manifest"],
                                    "closed-recorded fixture SourceV5 pin")
    source_manifest, _, source_sha = readback.read_canonical(
        Path(source_pin["path"]), "closed-recorded fixture SourceV5 manifest",
        readback.MAX_SOURCE_BYTES,
    )
    if source_sha != source_pin["raw_sha256"]:
        raise readback.ReadbackError("closed-recorded fixture SourceV5 manifest pin differs")
    capture_rows = fixture["probe_capture_pins"]
    if type(capture_rows) is not list or len(capture_rows) != 2:
        raise readback.ReadbackError("closed-recorded fixture omits its exact two capture rows")

    artifact_paths: set[str] = set()
    artifact_sha_by_path: dict[str, str] = {}
    for index, value in enumerate(capture_rows):
        row = readback.exact(value, {
            "descriptor", "request_pin", "probe_capture_pin",
        }, f"closed-recorded fixture member[{index}]")
        descriptor = readback.exact(row["descriptor"], {
            "pair", "executor", "allocator",
        }, f"closed-recorded fixture descriptor[{index}]")
        artifact = readback.exact(
            source_manifest.get("artifacts", {}).get(descriptor["allocator"]),
            {"path", "sha256"},
            f"closed-recorded fixture SourceV5 artifact[{index}]",
        )
        relative = Path(artifact["path"])
        if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != artifact["path"]:
            raise readback.ReadbackError("closed-recorded fixture SourceV5 artifact path is not portable")
        artifact_path = str(source_root.joinpath(*relative.parts))
        artifact_paths.add(artifact_path)
        artifact_sha_by_path[artifact_path] = artifact["sha256"]
    mapped_origins = {
        entry["origin"]
        for entry in readback.exact(fixture["evidence_path_map"], {
            "schema", "entries",
        }, "closed-recorded fixture evidence map")["entries"]
        if type(entry) is dict and type(entry.get("origin")) is str
    }
    if mapped_origins.intersection(artifact_paths):
        raise readback.ReadbackError("closed-recorded fixture path map includes a peer SourceV5 ELF")

    peer_elf_state: dict[str, str] = {}
    for artifact_path in sorted(artifact_paths):
        candidate = Path(artifact_path)
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            peer_elf_state[artifact_path] = "absent"
            continue
        if not stat.S_ISREG(info.st_mode):
            raise readback.ReadbackError("closed-recorded fixture peer artifact is neither absent nor a regular decoy")
        actual_sha, _size, _mode = feedback_reader._stable_file_sha256(
            candidate, "closed-recorded fixture peer artifact precondition",
            feedback_reader.MAX_APP_BINARY_BYTES,
        )
        if actual_sha == artifact_sha_by_path[artifact_path]:
            raise readback.ReadbackError("closed-recorded fixture still contains the original peer ELF")
        peer_elf_state[artifact_path] = "decoy"

    receipt_pin = readback._scope_receipt_pin_v2(
        fixture["host_verification_pin"],
        "closed-recorded fixture strict scope receipt",
    )
    context_bundle, _, bundle_sha = readback.read_canonical(
        Path(context_policy_pin["path"]),
        "closed-recorded fixture context-policy bundle", 8 * 1024 * 1024,
    )
    if bundle_sha != context_policy_pin["raw_sha256"]:
        raise readback.ReadbackError("closed-recorded fixture context bundle pin differs")
    members = readback.exact(context_bundle, {
        "schema", "artifact", "members",
    }, "closed-recorded fixture context bundle")["members"]
    if type(members) is not list or len(members) != 2:
        raise readback.ReadbackError("closed-recorded fixture context bundle is not two-member")
    member_expected = []
    for index, (bundle_member_value, capture_row_value) in enumerate(zip(members, capture_rows)):
        member = readback.exact(bundle_member_value, {
            "descriptor", "request", "construction_probe", "resolved_policy",
            "composition_receipt",
        }, f"closed-recorded fixture bundle member[{index}]")
        capture_row = readback.exact(capture_row_value, {
            "descriptor", "request_pin", "probe_capture_pin",
        }, f"closed-recorded fixture capture row[{index}]")
        request_pin = readback._raw_pin(member["request"],
                                         f"closed-recorded fixture request[{index}]")
        indexed_request = readback._raw_pin(capture_row["request_pin"],
                                             f"closed-recorded fixture indexed request[{index}]")
        if member["descriptor"] != capture_row["descriptor"] or request_pin != indexed_request:
            raise readback.ReadbackError("closed-recorded fixture capture row differs from its context bundle order")
        resolved_pin = readback._raw_pin(member["resolved_policy"],
                                          f"closed-recorded fixture resolved policy[{index}]")
        composition_pin = readback._raw_pin(member["composition_receipt"],
                                              f"closed-recorded fixture composition receipt[{index}]")
        resolved_raw, resolved_sha = readback.read_stable(
            Path(resolved_pin["path"]), "closed-recorded fixture resolved policy",
            readback.MAX_POLICY_BYTES,
        )
        composition_raw, composition_sha = readback.read_stable(
            Path(composition_pin["path"]), "closed-recorded fixture composition receipt",
            readback.MAX_CONTEXT_POLICY_BUNDLE_BYTES,
        )
        if resolved_sha != resolved_pin["raw_sha256"] or composition_sha != composition_pin["raw_sha256"]:
            raise readback.ReadbackError("closed-recorded fixture policy outputs differ from their pins")
        member_expected.append({
            "descriptor": member["descriptor"],
            "resolved_policy_raw_sha256": resolved_sha,
            "composition_receipt_raw_sha256": composition_sha,
        })
    if expected["members"] != member_expected:
        raise readback.ReadbackError("closed-recorded fixture member outputs differ from the origin pins")

    real_path_methods = {
        "stat": Path.stat,
        "lstat": Path.lstat,
        "resolve": Path.resolve,
        "open": Path.open,
    }

    def deny_elf_path(
        value: object, label: str, dir_fd: int | None = None,
    ) -> None:
        try:
            rendered = os.fsdecode(os.fspath(value))
        except (TypeError, ValueError):
            return
        candidates = {rendered}
        if dir_fd is not None and not os.path.isabs(rendered):
            try:
                base = os.fsdecode(os.readlink(f"/proc/self/fd/{dir_fd}"))
            except OSError:
                base = ""
            if base:
                candidates.add(os.path.normpath(os.path.join(base, rendered)))
        if candidates.intersection(artifact_paths):
            raise AssertionError(f"closed-recorded replay attempted peer ELF {label}")

    def guarded_path_method(label: str):
        original = real_path_methods[label]

        def guarded(path_value: Path, *args: Any, **kwargs: Any) -> Any:
            deny_elf_path(path_value, label)
            return original(path_value, *args, **kwargs)
        return guarded

    real_builtins_open = builtins.open
    real_io_open = io.open
    real_os_open = os.open
    real_os_stat = os.stat
    real_os_lstat = os.lstat
    real_os_readlink = os.readlink

    def guarded_open(file: object, *args: Any, **kwargs: Any) -> Any:
        deny_elf_path(file, "open")
        return real_builtins_open(file, *args, **kwargs)

    def guarded_io_open(file: object, *args: Any, **kwargs: Any) -> Any:
        deny_elf_path(file, "open")
        return real_io_open(file, *args, **kwargs)

    def guarded_os_open(file: object, *args: Any, **kwargs: Any) -> Any:
        deny_elf_path(file, "open", kwargs.get("dir_fd"))
        return real_os_open(file, *args, **kwargs)

    def guarded_os_stat(file: object, *args: Any, **kwargs: Any) -> Any:
        deny_elf_path(file, "stat", kwargs.get("dir_fd"))
        return real_os_stat(file, *args, **kwargs)

    def guarded_os_lstat(file: object, *args: Any, **kwargs: Any) -> Any:
        deny_elf_path(file, "lstat", kwargs.get("dir_fd"))
        return real_os_lstat(file, *args, **kwargs)

    def guarded_os_readlink(file: object, *args: Any, **kwargs: Any) -> Any:
        deny_elf_path(file, "readlink", kwargs.get("dir_fd"))
        return real_os_readlink(file, *args, **kwargs)

    with patch.object(Path, "stat", new=guarded_path_method("stat")), \
            patch.object(Path, "lstat", new=guarded_path_method("lstat")), \
            patch.object(Path, "resolve", new=guarded_path_method("resolve")), \
            patch.object(Path, "open", new=guarded_path_method("open")), \
            patch.object(builtins, "open", new=guarded_open), \
            patch.object(io, "open", new=guarded_io_open), \
            patch.object(os, "open", new=guarded_os_open), \
            patch.object(os, "stat", new=guarded_os_stat), \
            patch.object(os, "lstat", new=guarded_os_lstat), \
            patch.object(os, "readlink", new=guarded_os_readlink), \
            patch.object(subprocess, "Popen",
                         side_effect=AssertionError("closed-recorded replay attempted Popen")):
        result = readback.verify_calibration_scope_v2_closed_recorded_v1(
            calibration_pin, context_policy_pin, capacity_bundle, observed_host_pin,
            source_root=str(source_root), evidence_path_map=fixture["evidence_path_map"],
            host_verification_pin=receipt_pin,
            probe_capture_pins=capture_rows,
        )

    projection = {
        "host_id": result["capacity_key"]["host_id"],
        "condition_id": result["condition_id"],
        "pressure_calibration_id": result["pressure_calibration_id"],
        "capacity_key": result["capacity_key"],
        "calibration_raw_sha256": result["calibration_raw_sha256"],
        "scope_sha256": result["scope_sha256"],
        "receipt_sha256": result["receipt_sha256"],
        "context_policy_bundle_raw_sha256": result["context_policy_bundle_raw_sha256"],
        "context_policy_artifact_raw_sha256": result["context_policy_artifact_raw_sha256"],
        "context_policy_sha256": result["context_policy_sha256"],
        "capacity_bundle_pins_sha256": result["capacity_bundle_pins_sha256"],
        "capacity_tsv_raw_sha256": result["capacity_tsv_raw_sha256"],
        "sample_count": result["sample_count"],
        "members": member_expected,
    }
    if projection != expected:
        raise readback.ReadbackError("closed-recorded pressure replay differs from its pinned origin outputs")

    try:
        readback.verify_calibration_scope_v2_offline(
            calibration_pin, context_policy_pin, capacity_bundle, observed_host_pin,
            source_root=str(source_root), evidence_path_map=fixture["evidence_path_map"],
            host_verification_pin=receipt_pin,
        )
    except readback.ReadbackError:
        pass
    else:
        raise AssertionError("ordinary pressure replay accepted peer evidence without its historical ELF")
    return {
        "request_raw_sha256": fixture_sha,
        "scope_sha256": result["scope_sha256"],
        "receipt_sha256": result["receipt_sha256"],
        "peer_elf_state": peer_elf_state,
        "qualification_eligible": result["qualification_eligible"],
    }


class PressureReadbackV2Tests(unittest.TestCase):
    def test_preflights_traverse_nested_construction_probe_evidence_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-probe-preflight-") as temporary:
            root = Path(temporary).resolve()
            allowed_paths: set[str] = set()

            def write_document(name: str, value: object) -> dict[str, str]:
                path = root / name
                raw = readback.canonical_bytes(value)
                path.write_bytes(raw)
                allowed_paths.add(str(path))
                return {"path": str(path), "raw_sha256": readback.sha256_bytes(raw)}

            nested_path = root / "nested-evidence.json"
            nested_path.write_bytes(readback.canonical_bytes({"kind": "nested evidence"}))
            allowed_paths.add(str(nested_path))
            probes = []
            for index in range(2):
                probe_pin = write_document(
                    f"probe-{index}.json",
                    {"evidence": {"nested": {"path": str(nested_path)}}},
                )
                probe_pin.update({"allocator": "allocatbelt", "binary_sha256": "a" * 64})
                probes.append(probe_pin)

            source_pin = write_document("source-manifest.json", {})
            context_pin = write_document("context.json", {})
            validation_pin = write_document("validation.json", {})
            expectation = {"construction_probe": probes[0]}
            expectation_pin = write_document("expectation.json", expectation)
            capacity_request = {
                "source_manifest": {
                    "path": source_pin["path"], "sha256": source_pin["raw_sha256"],
                },
                "context": {
                    "path": context_pin["path"], "sha256": context_pin["raw_sha256"],
                },
                "validation": {
                    "path": validation_pin["path"], "sha256": validation_pin["raw_sha256"],
                },
                "expectation": {
                    "path": expectation_pin["path"], "sha256": expectation_pin["raw_sha256"],
                },
                "expectation_sha256": expectation_pin["raw_sha256"],
            }

            shared_policy_pin = write_document("shared-policy.json", {})
            members = []
            for index, probe_pin in enumerate(probes):
                request_pin = write_document(
                    f"composer-request-{index}.json",
                    {"construction_probe": probe_pin},
                )
                resolved_pin = write_document(f"resolved-policy-{index}.json", {})
                receipt_pin = write_document(f"composition-receipt-{index}.json", {})
                members.append({
                    "descriptor": {},
                    "request": request_pin,
                    "construction_probe": probe_pin,
                    "resolved_policy": resolved_pin,
                    "composition_receipt": receipt_pin,
                })
            context_bundle_pin = write_document("context-policy-bundle.json", {
                "schema": readback.CONTEXT_POLICY_BUNDLE_SCHEMA_V2,
                "artifact": shared_policy_pin,
                "members": members,
            })
            mapped = {path: path for path in allowed_paths}

            def run_with_mapping(mapping: dict[str, str], callback) -> None:
                token = readback._EVIDENCE_PATH_MAP_CONTEXT.set((mapping, set()))
                try:
                    callback()
                finally:
                    readback._EVIDENCE_PATH_MAP_CONTEXT.reset(token)

            def capacity_preflight() -> None:
                readback._preflight_capacity_request_paths_v2(capacity_request)

            def context_policy_preflight() -> None:
                readback._preflight_context_policy_bundle_paths_v2(context_bundle_pin)

            with self.subTest(preflight="capacity"):
                run_with_mapping(mapped, capacity_preflight)
                with self.assertRaisesRegex(
                        readback.ReadbackError,
                        "absent from the explicit identity path map"):
                    run_with_mapping(
                        {path: path for path in allowed_paths if path != str(nested_path)},
                        capacity_preflight,
                    )

            with self.subTest(preflight="context-policy"):
                run_with_mapping(mapped, context_policy_preflight)
                with self.assertRaisesRegex(
                        readback.ReadbackError,
                        "absent from the explicit identity path map"):
                    run_with_mapping(
                        {path: path for path in allowed_paths if path != str(nested_path)},
                        context_policy_preflight,
                    )

    def test_context_policy_verification_reads_probe_before_composer_replay(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-context-probe-replay-") as temporary:
            root = Path(temporary).resolve()

            def write_document(name: str, value: object) -> dict[str, str]:
                path = root / name
                raw = readback.canonical_bytes(value)
                path.write_bytes(raw)
                return {"path": str(path), "raw_sha256": readback.sha256_bytes(raw)}

            source_pin = write_document("source-manifest.json", {})
            capacity_key = {
                "host_id": "host", "workload": "workload",
                "profile": "profile", "calibration_id": "calibration",
            }
            capacity_pins = {
                "request": {"path": str(root / "capacity-request.json"), "raw_sha256": "b" * 64},
                "artifact": {"path": str(root / "capacity.tsv"), "raw_sha256": "c" * 64},
                "receipt": {"path": str(root / "capacity-receipt.json"), "raw_sha256": "d" * 64},
            }
            expected_capacity = {
                name: capacity_pins[name] for name in ("request", "artifact", "receipt")
            }
            members = []
            for index, pair in enumerate(("bounded", "tokio")):
                probe_pin = write_document(f"probe-{index}.json", {"probe": "read"})
                probe_pin.update({"allocator": "allocatbelt", "binary_sha256": "a" * 64})
                request = {
                    "schema": "test-composer-request-v1",
                    "source_root": str(root),
                    "source_manifest": source_pin,
                    "context": capacity_key,
                    "construction_probe": probe_pin,
                    "capacity_bundle": expected_capacity,
                }
                request_pin = write_document(f"request-{index}.json", request)
                resolved_pin = write_document(f"resolved-{index}.json", {})
                receipt_pin = write_document(f"receipt-{index}.json", {})
                members.append({
                    "descriptor": {
                        "pair": pair, "executor": pair, "allocator": "allocatbelt",
                    },
                    "request": request_pin,
                    "construction_probe": probe_pin,
                    "resolved_policy": resolved_pin,
                    "composition_receipt": receipt_pin,
                })

            policy = {
                "schema": readback.SOURCE5_PRESSURE_POLICY_SCHEMA,
                "source_manifest": source_pin,
                "context": capacity_key,
                "capacity_bundle": expected_capacity,
                "base_policy_artifact_sha256": "1" * 64,
                "base_policy_sha256": "2" * 64,
                "base_context_sha256": "3" * 64,
                "resolution_rule_version": "test-rule-v1",
                "numeric_policy": {},
                "baseline": {},
                "hard_ceilings": {},
                "normalization_denominators": {},
                "member_resolutions": [],
            }
            policy["policy_sha256"] = readback.digest_object(policy)
            policy_pin = write_document("shared-policy.json", policy)
            context_bundle = {
                "schema": readback.CONTEXT_POLICY_BUNDLE_SCHEMA_V2,
                "artifact": policy_pin,
                "members": members,
            }
            context_bundle_pin = write_document("context-policy-bundle.json", context_bundle)

            class Composer:
                REQUEST_SCHEMA = "test-composer-request-v1"

                @staticmethod
                def compose_calibrated_policy_v5(request: object, request_sha: str) -> object:
                    raise RuntimeError("reached mocked composer")

            source_stack = {
                "source_pin": source_pin,
                "source_root": root,
                "composer": Composer(),
            }
            capacity = {"capacity_key": capacity_key, "pins": capacity_pins}
            with patch.object(readback, "_source5_capacity_floor_policy_id", return_value=None):
                with self.assertRaisesRegex(
                        readback.ReadbackError,
                        r"pinned SourceV5 composer replay failed for member\[0\]: RuntimeError: reached mocked composer"):
                    readback._verify_context_policy_bundle_v2(
                        source_stack, context_bundle_pin, capacity, source_pin,
                    )

    def test_closed_recorded_pressure_api_requires_two_capture_members(self) -> None:
        parameters = inspect.signature(
            readback.verify_calibration_scope_v2_closed_recorded_v1,
        ).parameters
        self.assertEqual(tuple(parameters), (
            "calibration_pin", "context_policy_pin", "capacity_bundle_pins",
            "observed_host_pin", "source_root", "evidence_path_map",
            "host_verification_pin", "probe_capture_pins",
        ))
        self.assertIs(parameters["probe_capture_pins"].default,
                      inspect.Parameter.empty)

    def test_closed_recorded_capacity_projection_uses_typed_pin_roles(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-closed-capacity-pins-") as temporary:
            root = Path(temporary).resolve()

            def write_document(name: str, value: object) -> dict[str, str]:
                path = root / name
                raw = readback.canonical_bytes(value)
                path.write_bytes(raw)
                return {"path": str(path), "raw_sha256": readback.sha256_bytes(raw)}

            source_pin = write_document("source-manifest.json", {"source": "r14"})
            capacity_key = {
                "host_id": "host-r14", "workload": "cpu",
                "profile": "steady", "calibration_id": "capacity-r14-01",
            }
            capacity_pins = {
                "schema": readback.CAPACITY_BUNDLE_PIN_SCHEMA_V2,
                "capacity_key": capacity_key,
                "source_manifest": source_pin,
                "request": {"path": str(root / "capacity-request.json"), "raw_sha256": "b" * 64},
                "artifact": {"path": str(root / "capacity.tsv"), "raw_sha256": "c" * 64},
                "receipt": {"path": str(root / "capacity-receipt.json"), "raw_sha256": "d" * 64},
            }
            capacity_bundle = {
                "schema": capacity_pins["schema"], "capacity_key": capacity_key,
                "source_manifest": source_pin, "request": capacity_pins["request"],
                "artifact": capacity_pins["artifact"], "receipt": capacity_pins["receipt"],
            }
            expected_capacity = {
                name: capacity_pins[name] for name in ("request", "artifact", "receipt")
            }
            binary_path = root / "bin" / "allocatbelt"
            binary_sha = "a" * 64
            captures: dict[str, dict[str, Any]] = {}
            capture_rows = []
            members = []
            for index, pair in enumerate(("bounded", "tokio")):
                probe_pin = write_document(f"probe-{index}.json", {"probe": index})
                probe_pin.update({"allocator": "allocatbelt", "binary_sha256": binary_sha})
                request = {
                    "schema": "test-composer-request-v1",
                    "source_root": str(root), "source_manifest": source_pin,
                    "context": capacity_key, "construction_probe": probe_pin,
                    "capacity_bundle": expected_capacity,
                }
                request_pin = write_document(f"composer-request-{index}.json", request)
                resolved_pin = write_document(f"resolved-policy-{index}.json", {})
                composition_pin = write_document(f"composition-{index}.json", {})
                descriptor = {"pair": pair, "executor": pair, "allocator": "allocatbelt"}
                members.append({
                    "descriptor": descriptor, "request": request_pin,
                    "construction_probe": probe_pin,
                    "resolved_policy": resolved_pin,
                    "composition_receipt": composition_pin,
                })

                inventory = write_document(f"inventory-{index}.json", {"entries": []})
                stdout = write_document(f"stdout-{index}.json", {})
                stderr = write_document(f"stderr-{index}.json", {})
                capture_doc = write_document(f"capture-{index}.json", {"capture": index})
                argv = [str(binary_path)]
                direct = {name: None for name in feedback_reader.DIRECT_CAPTURE_FIELDS}
                direct.update({
                    "binary_path": str(binary_path), "binary_sha256": binary_sha,
                    "binary_size": 1, "requested_argv": argv,
                })
                owner_raw = readback.canonical_bytes({"direct": direct})
                owner_path = root / f"owner-result-{index}.json"
                owner_path.write_bytes(owner_raw)
                owner_result = {"path": str(owner_path),
                                "raw_sha256": readback.sha256_bytes(owner_raw),
                                "owner_result_sha256": "e" * 64}
                capture = {
                    "probe_pin": probe_pin,
                    "binary": {"path": str(binary_path), "raw_sha256": binary_sha},
                    "probe_argv": argv,
                    "owner_result_pin": owner_result,
                    "tmpdir_inventory_pin": {
                        "path": inventory["path"], "raw_sha256": inventory["raw_sha256"],
                        "inventory_sha256": "f" * 64,
                    },
                    "stdout": stdout, "stderr": stderr,
                }
                captures[capture_doc["raw_sha256"]] = capture
                capture_rows.append({
                    "descriptor": descriptor,
                    "request_pin": request_pin,
                    "probe_capture_pin": {
                        "path": capture_doc["path"],
                        "raw_sha256": capture_doc["raw_sha256"],
                        "receipt_sha256": "1" * 64,
                    },
                })

            policy = {
                "schema": readback.SOURCE5_PRESSURE_POLICY_SCHEMA,
                "source_manifest": source_pin, "context": capacity_key,
                "capacity_bundle": expected_capacity,
                "base_policy_artifact_sha256": "2" * 64,
                "base_policy_sha256": "3" * 64,
                "base_context_sha256": "4" * 64,
                "resolution_rule_version": "test-rule-v1",
                "numeric_policy": {}, "baseline": {}, "hard_ceilings": {},
                "normalization_denominators": {}, "member_resolutions": [],
            }
            policy["policy_sha256"] = readback.digest_object(policy)
            policy_pin = write_document("shared-policy.json", policy)
            context_bundle = {
                "schema": readback.CONTEXT_POLICY_BUNDLE_SCHEMA_V2,
                "artifact": policy_pin, "members": members,
            }
            context_bundle_pin = write_document("context-policy-bundle.json", context_bundle)

            class Composer:
                REQUEST_SCHEMA = "test-composer-request-v1"

                @staticmethod
                def compose_calibrated_policy_v5_closed_recorded_v1(
                    request: object, request_sha: str, *, replay_context: object,
                ) -> object:
                    raise RuntimeError("reached closed composer boundary")

            class FeedbackReader:
                DIRECT_CAPTURE_FIELDS = feedback_reader.DIRECT_CAPTURE_FIELDS
                MAX_APP_BINARY_BYTES = feedback_reader.MAX_APP_BINARY_BYTES
                MAX_PROBE_CAPTURE_RECEIPT_BYTES = feedback_reader.MAX_PROBE_CAPTURE_RECEIPT_BYTES
                MAX_PROBE_OWNER_RESULT_BYTES = feedback_reader.MAX_PROBE_OWNER_RESULT_BYTES
                MAX_PROBE_TMPDIR_INVENTORY_BYTES = feedback_reader.MAX_PROBE_TMPDIR_INVENTORY_BYTES

                @staticmethod
                def validate_probe_capture_receipt_envelope(
                    raw: bytes, expected_raw_sha256: str,
                    expected_receipt_sha256: str,
                ) -> dict[str, Any]:
                    return captures[expected_raw_sha256]

            feedback_policy = {
                "schema": "allocatbelt.application-feedback-policy-artifact.v1",
                "version": "test-v1", "reader_contract": {}, "algorithm": {},
                "contexts": [], "source_pins": {},
            }
            source_stack = {
                "source_pin": source_pin, "source_root": root,
                "source": {"artifacts": {"allocatbelt": {
                    "path": "bin/allocatbelt", "sha256": binary_sha,
                }}, "feedback_policy": {
                    "schema": feedback_policy["schema"],
                    "policy": feedback_policy,
                    "policy_sha256": readback.digest_object(feedback_policy),
                }},
                "composer": Composer(), "feedback_reader": FeedbackReader(),
            }
            capacity = {
                "capacity_key": capacity_key, "pins": capacity_pins,
                "request": {}, "context": {}, "capacity_receipt": {},
                "closed_replay_documents": {
                    "validation": {"closure_role": "validation"},
                    "expectation": {"closure_role": "expectation"},
                    "construction_probe": {"closure_role": "probe"},
                },
            }
            captured: dict[str, Any] = {}

            def intercept_feedback_context(
                _source_stack: object, _evidence_map: object, _source_root: object,
                _documents: object, evidence_files: set[str], *_rest: object,
            ) -> dict[str, Any]:
                captured["evidence_files"] = set(evidence_files)
                captured["documents"] = list(_documents)
                return {"test": "intercepted after closed replay file closure"}

            with patch.object(readback, "_closed_probe_capture_mountpoints_v1", return_value=set()), \
                    patch.object(readback, "_closed_recorded_feedback_context_v1",
                                 side_effect=intercept_feedback_context):
                with self.assertRaisesRegex(
                        readback.ReadbackError,
                        r"pinned SourceV5 composer replay failed for member\[0\]: RuntimeError: reached closed composer boundary",
                ):
                    readback._verify_context_policy_bundle_v2(
                        source_stack, context_bundle_pin, capacity, source_pin,
                        closed_recorded=True, probe_capture_pins=capture_rows,
                        evidence_path_map={
                            "schema": readback.EVIDENCE_PATH_MAP_SCHEMA_V1,
                            "entries": [],
                        },
                    )

            mapped_inputs = captured["evidence_files"]
            for role in ("source_manifest", "request", "artifact", "receipt"):
                self.assertIn(capacity_pins[role]["path"], mapped_inputs)
            for document in capacity["closed_replay_documents"].values():
                self.assertIn(document, captured["documents"])
            self.assertEqual(
                mapped_inputs.intersection({capacity_pins["schema"], str(capacity_key)}),
                set(),
            )

    def test_closed_capacity_expectation_probe_closure_reaches_real_cfb_map(self) -> None:
        composer = _load_module(
            "pressure_feedback_composition_capacity_closure_test_target",
            SCRIPT_DIR / "application-feedback-composition.py",
        )
        with tempfile.TemporaryDirectory(prefix="pressure-capacity-closure-") as temporary:
            root = Path(temporary).resolve()
            input_root, source_root = root / "input", root / "source"
            input_root.mkdir()
            source_root.mkdir()

            def write_document(name: str, value: object, *, under_input: bool = True) -> dict[str, str]:
                path = (input_root if under_input else source_root) / name
                raw = readback.canonical_bytes(value)
                path.write_bytes(raw)
                return {"path": str(path), "sha256": readback.sha256_bytes(raw)}

            binary_sha = "a" * 64
            source_tree_sha = "b" * 64
            capacity_key = {
                "host_id": "host-fixture", "workload": "cpu",
                "profile": "steady", "calibration_id": "capacity-fixture-01",
            }
            identity = {
                "host_id": capacity_key["host_id"], "run_id": "run-fixture-01",
                "report_nonce": "nonce-fixture-01", "process_id": 123,
                "allocator": "allocatbelt", "executor": "allocatbelt",
                "workload": capacity_key["workload"], "profile": capacity_key["profile"],
                "mode": "capacity", "source_sha256": source_tree_sha,
                "binary_sha256": binary_sha, "pressure_qualification": False,
            }
            source_document = {
                "source": {"git_commit": "1" * 40, "source_tree_sha256": source_tree_sha,
                           "cargo_lock_sha256": "2" * 64, "files": []},
                "artifacts": {"allocatbelt": {"path": "bin/allocatbelt",
                                                "sha256": binary_sha}},
                "feedback_policy": {
                    "schema": "allocatbelt.application-feedback-policy-artifact.v1",
                    "policy": {"schema": "allocatbelt.application-feedback-policy-artifact.v1",
                               "version": "fixture-v1", "reader_contract": {},
                               "algorithm": {}, "contexts": [], "source_pins": {}},
                },
            }
            source_document["feedback_policy"]["policy_sha256"] = readback.digest_object(
                source_document["feedback_policy"]["policy"],
            )
            source_pin_value = write_document("source-manifest.json", source_document)
            source_pin = {"path": source_pin_value["path"],
                          "raw_sha256": source_pin_value["sha256"]}
            request_source_pin = {"path": source_pin["path"],
                                  "sha256": source_pin["raw_sha256"]}
            context_pin_value = write_document("capacity-context.json", {
                "schema": "allocatbelt.application-capacity-context.v1",
                "identity": identity, "stage": "pre_confirmation",
                "storage": None, "network": None,
            })
            context_pin = {"path": context_pin_value["path"],
                           "sha256": context_pin_value["sha256"]}
            validation_pin_value = write_document("capacity-validation.json", {})
            validation_pin = {"path": validation_pin_value["path"],
                              "sha256": validation_pin_value["sha256"]}
            probe_pin = write_document("policy-probe.json", {"probe": "pinned"})
            expectation_value = {
                "host_binding": source_pin,
                "construction_probe": {
                    "path": probe_pin["path"], "raw_sha256": probe_pin["sha256"],
                    "allocator": "allocatbelt", "binary_sha256": binary_sha,
                },
            }
            expectation_pin = write_document("feedback-expectation.json", expectation_value)
            for trace_name in feedback_reader.CAPACITY_TRACE_FILES:
                (input_root / trace_name).write_bytes(b"")
            request = {
                "schema": readback.SOURCE5_CAPACITY_BUNDLE_SCHEMA,
                "trace_directory": str(input_root),
                "calibration_id": capacity_key["calibration_id"],
                "identity": identity,
                "source_manifest": request_source_pin, "context": context_pin,
                "validation": validation_pin, "expectation": expectation_pin,
                "expectation_sha256": expectation_pin["sha256"],
            }
            request_pin = write_document("capacity-request.json", request)
            mapping = {str(path): str(path) for path in (input_root, source_root)}
            directories = set(mapping)

            def preflight(value: dict[str, Any]) -> dict[str, Any] | None:
                token = readback._EVIDENCE_PATH_MAP_CONTEXT.set((mapping, directories))
                try:
                    return readback._preflight_capacity_request_paths_v2(value)
                finally:
                    readback._EVIDENCE_PATH_MAP_CONTEXT.reset(token)

            validated = preflight(request)
            if validated is not None:
                self.assertEqual(validated["expectation"], expectation_value)
                self.assertEqual(validated["construction_probe"], {"probe": "pinned"})

            missing_expectation = dict(request)
            missing_expectation["expectation"] = {
                "path": str(input_root / "missing-expectation.json"), "sha256": "0" * 64,
            }
            missing_expectation["expectation_sha256"] = "0" * 64
            with self.assertRaises(readback.ReadbackError):
                preflight(missing_expectation)
            no_map_token = readback._EVIDENCE_PATH_MAP_CONTEXT.set(None)
            try:
                self.assertIsNone(
                    readback._preflight_capacity_request_paths_v2(missing_expectation),
                )
            finally:
                readback._EVIDENCE_PATH_MAP_CONTEXT.reset(no_map_token)
            expectation_path = Path(expectation_pin["path"])
            expectation_raw = readback.canonical_bytes(expectation_value)
            expectation_path.write_bytes(readback.canonical_bytes({"tampered": True}))
            with self.assertRaisesRegex(readback.ReadbackError, "expectation"):
                preflight(request)
            expectation_path.write_bytes(expectation_raw)

            missing_probe = dict(expectation_value)
            missing_probe["construction_probe"] = dict(expectation_value["construction_probe"])
            missing_probe["construction_probe"]["path"] = str(input_root / "missing-policy-probe.json")
            missing_probe_pin = write_document("missing-probe-expectation.json", missing_probe)
            bad_probe_request = dict(request, expectation=missing_probe_pin,
                                     expectation_sha256=missing_probe_pin["sha256"])
            with self.assertRaises(readback.ReadbackError):
                preflight(bad_probe_request)
            outside_path = root / "outside" / "policy-probe.json"
            outside_path.parent.mkdir()
            outside_raw = readback.canonical_bytes({"probe": "outside-root"})
            outside_path.write_bytes(outside_raw)
            outside_expectation = dict(expectation_value)
            outside_expectation["construction_probe"] = dict(expectation_value["construction_probe"])
            outside_expectation["construction_probe"].update({
                "path": str(outside_path),
                "raw_sha256": readback.sha256_bytes(outside_raw),
            })
            outside_expectation_pin = write_document("outside-expectation.json", outside_expectation)
            outside_request = dict(request, expectation=outside_expectation_pin,
                                   expectation_sha256=outside_expectation_pin["sha256"])
            with self.assertRaisesRegex(
                    readback.ReadbackError,
                    "absent from the explicit identity path map",
            ):
                preflight(outside_request)
            probe_path = Path(probe_pin["path"])
            probe_raw = readback.canonical_bytes({"probe": "pinned"})
            probe_path.write_bytes(readback.canonical_bytes({"tampered": True}))
            with self.assertRaises(readback.ReadbackError):
                preflight(request)
            probe_path.write_bytes(probe_raw)

            artifact_path = input_root / "capacity.tsv"
            artifact_raw = b"capacity\n"
            artifact_path.write_bytes(artifact_raw)
            artifact_sha = readback.sha256_bytes(artifact_raw)
            capacity_receipt_value = {
                "schema": "allocatbelt.application-byte-capacity-receipt.v1",
                "qualification_eligible": False,
                "identity": identity,
                "calibration_id": capacity_key["calibration_id"],
                "source_manifest_raw_sha256": source_pin["raw_sha256"],
                "capacity_artifact_raw_sha256": artifact_sha,
            }
            receipt_pin = write_document("capacity-receipt.json", capacity_receipt_value)
            capture_pin = write_document("capture-receipt.json", {"capture": "pinned"})
            arbitrary = input_root / "unreferenced.json"
            arbitrary.write_bytes(b"{}\n")
            probe_path = Path(probe_pin["path"])
            unlisted_link = input_root / "unlisted-link"
            unlisted_link.symlink_to(probe_path)
            capacity_pins = {
                "schema": readback.CAPACITY_BUNDLE_PIN_SCHEMA_V2,
                "capacity_key": capacity_key,
                "source_manifest": source_pin,
                "request": {"path": request_pin["path"], "raw_sha256": request_pin["sha256"]},
                "artifact": {"path": str(artifact_path), "raw_sha256": artifact_sha},
                "receipt": {"path": receipt_pin["path"], "raw_sha256": receipt_pin["sha256"]},
            }
            class Producer:
                @staticmethod
                def verify_capacity_bundle(*_args: object) -> bool:
                    return True

            class CapacityReader:
                def __init__(self, fields: dict[str, Any]) -> None:
                    self.fields = fields

                def _read_capacity_artifact_v5(
                    self, pin: dict[str, str],
                ) -> tuple[dict[str, Any], str]:
                    return self.fields, pin["raw_sha256"]

            capacity_source_stack = {
                "source_pin": source_pin, "source_tree_sha256": source_tree_sha,
                "producer": Producer(),
                "feedback_reader": CapacityReader({
                    "host_id": capacity_key["host_id"],
                    "workload": capacity_key["workload"],
                    "profile": capacity_key["profile"],
                    "calibration_id": capacity_key["calibration_id"],
                    "source_sha256": source_tree_sha,
                }),
            }
            bad_request = dict(request)
            bad_request["expectation"] = {
                "path": str(input_root / "missing-expectation-before-hash-check.json"),
                "sha256": "0" * 64,
            }
            bad_request["expectation_sha256"] = "0" * 64
            bad_request_pin = write_document("bad-capacity-request.json", bad_request)
            bad_capacity_pins = dict(capacity_pins)
            bad_capacity_pins["request"] = {
                "path": bad_request_pin["path"], "raw_sha256": "0" * 64,
            }
            map_token = readback._EVIDENCE_PATH_MAP_CONTEXT.set((mapping, directories))
            try:
                with self.assertRaisesRegex(
                        readback.ReadbackError,
                        "capacity producer request raw digest differs",
                ):
                    readback._verify_capacity_bundle_v2(
                        {"source_pin": source_pin}, bad_capacity_pins, source_pin, {},
                    )
                capacity = readback._verify_capacity_bundle_v2(
                    capacity_source_stack, capacity_pins, source_pin, {},
                )
            finally:
                readback._EVIDENCE_PATH_MAP_CONTEXT.reset(map_token)
            capacity_bundle = {name: capacity["pins"][name]
                               for name in ("request", "artifact", "receipt")}
            evidence_files = {
                source_pin["path"], request_pin["path"], context_pin["path"],
                validation_pin["path"], expectation_pin["path"],
                capacity_bundle["artifact"]["path"], capacity_bundle["receipt"]["path"],
                capture_pin["path"],
            }
            self.assertNotIn(str(probe_path), evidence_files)
            closed_documents = capacity.get("closed_replay_documents") or {}
            documents = [source_document, capacity["request"], capacity["context"],
                         capacity["capacity_receipt"]]
            documents.extend(
                closed_documents[name]
                for name in ("validation", "expectation", "construction_probe")
                if name in closed_documents
            )
            evidence_map = {
                "schema": readback.EVIDENCE_PATH_MAP_SCHEMA_V1,
                "entries": [{"origin": path, "local": path} for path in sorted(mapping)],
            }
            token = readback._EVIDENCE_PATH_MAP_CONTEXT.set((mapping, directories))
            try:
                replay_context = readback._closed_recorded_feedback_context_v1(
                    {"source": source_document, "composer": composer,
                     "feedback_reader": feedback_reader}, evidence_map, source_root,
                    documents, evidence_files,
                    {"path": capture_pin["path"], "raw_sha256": capture_pin["sha256"],
                     "receipt_sha256": "f" * 64},
                    capacity_bundle, str(source_root / "bin" / "allocatbelt"), set(),
                )
            finally:
                readback._EVIDENCE_PATH_MAP_CONTEXT.reset(token)
            inner = composer._offline_context(replay_context)
            nested_paths = {expectation_pin["path"], probe_pin["path"]}
            composer._require_mapped_files(inner, nested_paths,
                                           "nested capacity expectation/probe closure")
            self.assertTrue(nested_paths <= inner["mapped_files"])

            elf = str(source_root / "bin" / "allocatbelt")
            self.assertNotIn(str(arbitrary), inner["mapped_paths"])
            self.assertNotIn(str(unlisted_link), inner["mapped_paths"])
            self.assertNotIn(elf, inner["mapped_paths"])
            with self.assertRaises(composer.CompositionError):
                composer._require_mapped_files(inner, {str(arbitrary)}, "unreferenced input")
            with self.assertRaises(composer.CompositionError):
                composer._require_mapped_files(inner, {elf}, "SourceV5 executable")

    def test_closed_recorded_source_inventory_checks_literal_symlink_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-closed-symlink-") as temporary:
            root = Path(temporary).resolve()
            target = root / "LICENSE-MIT"
            target.write_bytes(b"license bytes\n")
            target.chmod(0o644)
            link = root / "LICENSE"
            link.symlink_to("LICENSE-MIT")
            link_bytes = b"LICENSE-MIT"
            records = [
                {
                    "path": "LICENSE", "kind": "symlink", "mode": "120000",
                    "target": "LICENSE-MIT",
                    "sha256": readback.sha256_bytes(link_bytes),
                    "size": len(link_bytes),
                },
                {
                    "path": "LICENSE-MIT", "kind": "file", "mode": "100644",
                    "sha256": readback.sha256_bytes(b"license bytes\n"),
                    "size": len(b"license bytes\n"),
                },
            ]
            self.assertEqual(
                readback._capture_closed_recorded_typed_inventory_v1(root, records),
                records,
            )
            link.unlink()
            link.symlink_to("changed-target")
            with self.assertRaisesRegex(readback.ReadbackError, "symlink literal"):
                readback._capture_closed_recorded_typed_inventory_v1(root, records)

    def test_ordinary_offline_inventory_accepts_full_source_tree_and_rejects_link_mutations(self) -> None:
        inventory_module = _load_module(
            "pressure_ordinary_full_source_inventory_target",
            SCRIPT_DIR / "application-source-inventory.py",
        )
        source_root = SCRIPT_DIR.parent.resolve()
        complete = inventory_module.inventory(source_root, timeout_seconds=120.0)
        records = complete["entries"]
        license_link = next((
            item for item in records
            if item.get("path") == "crates/allocatbelt/LICENSE"
        ))
        self.assertEqual(license_link["kind"], "symlink")
        self.assertEqual(license_link["target"], "../../LICENSE")
        self.assertEqual(readback._capture_offline_typed_inventory(source_root, records),
                         records)

        wrong_literal = json.loads(json.dumps(records))
        wrong = next(item for item in wrong_literal
                     if item.get("path") == "crates/allocatbelt/LICENSE")
        wrong["target"] = "../../../LICENSE"
        with self.assertRaisesRegex(readback.ReadbackError, "symlink literal"):
            readback._capture_offline_typed_inventory(source_root, wrong_literal)

        escaping = json.loads(json.dumps(records))
        escape = next(item for item in escaping
                      if item.get("path") == "crates/allocatbelt/LICENSE")
        escape_target = "../../../escape"
        escape_raw = escape_target.encode("utf-8")
        escape["target"] = escape_target
        escape["size"] = len(escape_raw)
        escape["sha256"] = readback.sha256_bytes(escape_raw)
        with self.assertRaises(inventory_module.InventoryError):
            inventory_module.validate_records({
                "schema": readback.SOURCE5_INVENTORY_SCHEMA,
                "entries": escaping,
            })

        wrong_mode = json.loads(json.dumps(records))
        mode_link = next(item for item in wrong_mode
                         if item.get("path") == "crates/allocatbelt/LICENSE")
        mode_link["mode"] = "100644"
        with self.assertRaisesRegex(readback.ReadbackError, "symlink mode/type"):
            readback._capture_offline_typed_inventory(source_root, wrong_mode)

        wrong_hash = json.loads(json.dumps(records))
        hash_link = next(item for item in wrong_hash
                         if item.get("path") == "crates/allocatbelt/LICENSE")
        hash_link["sha256"] = "0" * 64
        with self.assertRaisesRegex(readback.ReadbackError, "symlink literal"):
            readback._capture_offline_typed_inventory(source_root, wrong_hash)

    def test_closed_pressure_api_rejects_selected_and_unused_elf_map_entries_before_io(self) -> None:
        fixture_builder = _load_module(
            "pressure_closed_elf_map_source_fixture",
            SCRIPT_DIR / "test-application-feedback-readback.py",
        )
        source_root = SCRIPT_DIR.parent.resolve()
        with tempfile.TemporaryDirectory(prefix="pressure-closed-map-") as temporary:
            input_root = Path(temporary).resolve()
            identity = {
                "host_id": "closed-map-host", "workload": "mixed",
                "profile": "mixed", "binary_sha256": "a" * 64,
            }
            source_manifest = fixture_builder._source_v5_manifest(identity)
            source_manifest["source"]["git_commit"] = "a" * 40
            composer_relative = "scripts/application-feedback-composition.py"
            composer_path = source_root / composer_relative
            composer_raw = composer_path.read_bytes()
            composer_info = composer_path.stat(follow_symlinks=False)
            composer_record = {
                "path": composer_relative,
                "kind": "file",
                "mode": "100755" if composer_info.st_mode & 0o111 else "100644",
                "sha256": readback.sha256_bytes(composer_raw),
                "size": len(composer_raw),
            }
            source_files = source_manifest["source"]["files"]
            source_files.append(composer_record)
            source_files.sort(key=lambda item: item["path"].encode("utf-8"))
            campaign = fixture_builder.campaign
            inventory_module = campaign.source_inventory_module()
            source_tree_sha256 = inventory_module.digest_records(source_files)
            source_manifest["source"]["source_tree_sha256"] = source_tree_sha256
            identity["source_sha256"] = source_tree_sha256
            calibration = source_manifest["resource_domain_calibration"]
            calibration["source"] = {
                key: source_manifest["source"][key]
                for key in ("git_commit", "source_tree_sha256", "cargo_lock_sha256")
            }
            inputs = campaign.campaign_inputs_module()
            source_manifest["feedback_policy"] = inputs.build_feedback_policy_artifact(
                source_root, source_files, source_manifest["qualification_harness"],
            )
            source_manifest["manifest_sha256"] = readback.digest_object({
                key: value for key, value in source_manifest.items()
                if key != "manifest_sha256"
            })
            source_raw = readback.canonical_bytes(source_manifest)
            source_path = input_root / "source-manifest.json"
            source_path.write_bytes(source_raw)
            source_pin = {"path": str(source_path),
                          "raw_sha256": readback.sha256_bytes(source_raw)}
            capacity_key = {
                "host_id": identity["host_id"], "workload": identity["workload"],
                "profile": identity["profile"], "calibration_id": "capacity-1",
            }
            capacity_bundle = {
                "schema": readback.CAPACITY_BUNDLE_PIN_SCHEMA_V2,
                "capacity_key": capacity_key,
                "source_manifest": source_pin,
                "request": {"path": str(input_root / "capacity-request.json"),
                            "raw_sha256": "b" * 64},
                "artifact": {"path": str(input_root / "capacity.tsv"),
                             "raw_sha256": "c" * 64},
                "receipt": {"path": str(input_root / "capacity-receipt.json"),
                            "raw_sha256": "d" * 64},
            }
            calibration_value = {
                "scope": {"source_root": str(source_root),
                          "source_manifest": source_pin},
            }
            calibration_raw = readback.canonical_bytes(calibration_value)
            calibration_path = input_root / "calibration.json"
            calibration_path.write_bytes(calibration_raw)
            calibration_pin = {
                "path": str(calibration_path),
                "raw_sha256": readback.sha256_bytes(calibration_raw),
            }
            context_policy_pin = {
                "path": str(input_root / "context-policy.json"),
                "raw_sha256": "e" * 64,
            }
            observed_host_pin = {
                "path": str(input_root / "observed-host.json"),
                "raw_sha256": "f" * 64,
            }
            host_receipt_pin = {
                "path": str(input_root / "scope-receipt.json"),
                "raw_sha256": "1" * 64, "scope_sha256": "2" * 64,
            }
            capture_rows = [
                {
                    "descriptor": {"pair": "bounded", "executor": "bounded",
                                   "allocator": "allocatbelt"},
                    "request_pin": {"path": str(input_root / "member-0-request.json"),
                                    "raw_sha256": "3" * 64},
                    "probe_capture_pin": {
                        "path": str(input_root / "member-0-capture.json"),
                        "raw_sha256": "4" * 64, "receipt_sha256": "5" * 64,
                    },
                },
                {
                    "descriptor": {"pair": "tokio", "executor": "tokio",
                                   "allocator": "allocatbelt"},
                    "request_pin": {"path": str(input_root / "member-1-request.json"),
                                    "raw_sha256": "6" * 64},
                    "probe_capture_pin": {
                        "path": str(input_root / "member-1-capture.json"),
                        "raw_sha256": "7" * 64, "receipt_sha256": "8" * 64,
                    },
                },
            ]
            original_methods = {
                "lstat": Path.lstat, "stat": Path.stat,
                "resolve": Path.resolve, "open": Path.open,
            }

            def path_method(name: str, forbidden: set[str]):
                original = original_methods[name]

                def guarded(path_value: Path, *args: Any, **kwargs: Any):
                    if str(path_value) in forbidden:
                        raise AssertionError(f"closed pressure API touched an ELF with {name}")
                    return original(path_value, *args, **kwargs)
                return guarded

            def deny_os(path_value: object, label: str) -> None:
                try:
                    rendered = os.fsdecode(os.fspath(path_value))
                except (TypeError, ValueError):
                    return
                if rendered in forbidden:
                    raise AssertionError(f"closed pressure API touched an ELF with {label}")

            real_os_open, real_os_stat, real_os_lstat = os.open, os.stat, os.lstat
            real_builtin_open, real_io_open = builtins.open, io.open

            def guarded_os(method, label: str):
                def guarded(path_value: object, *args: Any, **kwargs: Any):
                    deny_os(path_value, label)
                    return method(path_value, *args, **kwargs)
                return guarded

            artifact_records = {
                label: source_manifest["artifacts"][label]
                for label in ("allocatbelt", "mimalloc-secure", "mimalloc-standard", "system")
            }
            artifact_records.update({
                "soak-allocatbelt": source_manifest["soak_artifacts"]["allocatbelt"],
                "analyzer": source_manifest["analysis_artifact"],
                "resource-domain-calibration": source_manifest["resource_domain_calibration"]["binary"],
            })
            forbidden = {
                str(source_root / artifact["path"])
                for artifact in artifact_records.values()
            }
            for artifact_name, artifact in artifact_records.items():
                artifact_path = str(source_root / artifact["path"])
                path_map = {
                    "schema": readback.EVIDENCE_PATH_MAP_SCHEMA_V1,
                    "entries": [{"origin": artifact_path, "local": artifact_path}],
                }
                with self.subTest(artifact=artifact_name):
                    with patch.object(Path, "lstat", new=path_method("lstat", forbidden)), \
                            patch.object(Path, "stat", new=path_method("stat", forbidden)), \
                            patch.object(Path, "resolve", new=path_method("resolve", forbidden)), \
                            patch.object(Path, "open", new=path_method("open", forbidden)), \
                            patch.object(os, "open", new=guarded_os(real_os_open, "open")), \
                            patch.object(os, "stat", new=guarded_os(real_os_stat, "stat")), \
                            patch.object(os, "lstat", new=guarded_os(real_os_lstat, "lstat")), \
                            patch("builtins.open", new=guarded_os(real_builtin_open, "open")), \
                            patch.object(io, "open", new=guarded_os(real_io_open, "open")), \
                            patch.object(subprocess, "Popen",
                                         side_effect=AssertionError("closed pressure preflight attempted Popen")):
                        with self.assertRaisesRegex(
                                readback.ReadbackError, "application ELF path"):
                            readback.verify_calibration_scope_v2_closed_recorded_v1(
                                calibration_pin, context_policy_pin, capacity_bundle,
                                observed_host_pin, source_root=str(source_root),
                                evidence_path_map=path_map,
                                host_verification_pin=host_receipt_pin,
                                probe_capture_pins=capture_rows,
                            )

    def test_selected_floor_policy_is_bound_through_exact_shared_and_member_contexts(self) -> None:
        tree = ast.parse(READER_PATH.read_bytes(), filename=str(READER_PATH))
        matches = [node for node in tree.body
                   if isinstance(node, ast.FunctionDef) and
                   node.name == "_verify_context_policy_bundle_v2"]
        self.assertEqual(len(matches), 1)
        source = ast.unparse(matches[0])
        self.assertIn("_source5_capacity_floor_policy_id(source_stack)", source)
        self.assertIn("shared_context_keys.add", source)
        self.assertIn("expected_request_schema", source)
        self.assertIn("request.get('capacity_floor_policy_id')", source)
        self.assertIn("resolved_context_keys.add", source)
        self.assertIn("project_shared_context_policy_v2", source)
        fixtures = _load_module(
            "pressure_shared_floor_projection_fixtures",
            SCRIPT_DIR / "test-application-source5-initial-spec-export.py",
        )
        source_pin, capacity, members = fixtures._context_policy_fixture()
        floor = feedback_reader.CAPACITY_FLOOR_POLICY_ID
        for member in members:
            member["policy"]["context"]["capacity_floor_policy_id"] = floor
        shared = readback.project_shared_context_policy_v2(
            source_pin, capacity, members, floor,
        )
        self.assertEqual(shared["context"]["capacity_floor_policy_id"], floor)
        for index in (0, 1):
            source_pin, capacity, members = fixtures._context_policy_fixture()
            for member in members:
                member["policy"]["context"]["capacity_floor_policy_id"] = floor
            members[index]["policy"]["context"]["capacity_floor_policy_id"] = "unknown-floor"
            with self.subTest(member=index), self.assertRaises(readback.ReadbackError):
                readback.project_shared_context_policy_v2(source_pin, capacity, members, floor)

    def test_pressure_policy_floor_selector_is_derived_from_exact_source_artifact(self) -> None:
        descriptor = {
            "capacity_divisor": feedback_reader.CAPACITY_FLOOR_DIVISOR,
            "minimum_floor_bytes_per_second": feedback_reader.CAPACITY_FLOOR_MINIMUM_BYTES_PER_SECOND,
            "policy_id": feedback_reader.CAPACITY_FLOOR_POLICY_ID,
            "probe_activation": feedback_reader.CAPACITY_FLOOR_PROBE_ACTIVATION,
            "rule": feedback_reader.CAPACITY_FLOOR_RULE,
            "rule_version": feedback_reader.CAPACITY_RESOLUTION_VERSION,
            "runtime_activation": feedback_reader.CAPACITY_FLOOR_RUNTIME_ACTIVATION,
            "static_floor_bytes_per_second": feedback_reader.CAPACITY_RATE_FLOOR,
            "static_rate_roof_bytes_per_second": feedback_reader.CAPACITY_RATE_ROOF,
        }
        policy_body = {
            "schema": "allocatbelt.application-feedback-policy-artifact.v2",
            "version": "runtime-feedback-policy-v1",
            "reader_contract": {}, "algorithm": {}, "contexts": {},
            "source_pins": {}, "capacity_floor_policy": descriptor,
        }
        artifact = {
            "schema": "allocatbelt.application-feedback-policy-artifact.v2",
            "policy": policy_body,
            "policy_sha256": readback.digest_object(policy_body),
        }
        source_stack = {
            "source": {"feedback_policy": artifact},
            "feedback_reader": feedback_reader,
        }
        self.assertEqual(
            readback._source5_capacity_floor_policy_id(source_stack),
            feedback_reader.CAPACITY_FLOOR_POLICY_ID,
        )

        static_body = {key: value for key, value in policy_body.items()
                       if key != "capacity_floor_policy"}
        static_body["schema"] = "allocatbelt.application-feedback-policy-artifact.v1"
        static_artifact = {
            "schema": "allocatbelt.application-feedback-policy-artifact.v1",
            "policy": static_body,
            "policy_sha256": readback.digest_object(static_body),
        }
        self.assertIsNone(readback._source5_capacity_floor_policy_id({
            "source": {"feedback_policy": static_artifact},
            "feedback_reader": feedback_reader,
        }))

        bad_descriptor = {**descriptor, "policy_id": "unknown_floor_policy"}
        bad_body = {**policy_body, "capacity_floor_policy": bad_descriptor}
        bad_artifact = {**artifact, "policy": bad_body,
                        "policy_sha256": readback.digest_object(bad_body)}
        with self.assertRaisesRegex(feedback_reader.ValidationError,
                                    "independent reader contract"):
            readback._source5_capacity_floor_policy_id({
                "source": {"feedback_policy": bad_artifact},
                "feedback_reader": feedback_reader,
            })

    def test_driver_context_preflight_passes_canonical_source_root_text_to_reader(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-v2-source-boundary-") as temporary:
            root = Path(temporary)
            pins = {}
            for name in ("source", "policy", "capacity", "condition", "bundle", "host", "request", "receipt"):
                path = root / name
                raw = readback.canonical_bytes({"fixture": name})
                path.write_bytes(raw)
                pins[name] = {"path": str(path), "raw_sha256": readback.sha256_bytes(raw)}
            key = {"host_id": "host", "workload": "mixed", "profile": "mixed", "calibration_id": "capacity"}
            request = {
                "schema": driver.CALIBRATION_REQUEST_SCHEMA_V2,
                "identity": {"host_id": "host", "run_id": "run", "condition_id": "condition", "nonce": "a" * 32},
                "files": {
                    name: {"path": pins[pin]["path"], "sha256": pins[pin]["raw_sha256"]}
                    for name, pin in (("source_manifest", "source"), ("policy", "policy"), ("application_capacity_calibration", "capacity"))
                },
                "storage": {},
                "schedule": {
                    "seed": 7, "duration_seconds": 30, "sample_interval_ms": 100,
                    "startup_deadline_seconds": 2, "total_deadline_seconds": 40,
                    "term_deadline_seconds": 2, "kill_deadline_seconds": 2,
                    "minimum_overlap_seconds": 30, "startup_ready_windows": 1,
                    "cpu_duty_basis_points": 7000, "pressure_cpu_affinity": [0],
                    "application_cpu_affinity": [0], "disk_bytes_per_second": 1024 * 1024,
                    "scratch_file_bytes": 65536, "network_requests_per_second": 100,
                    "network_payload_bytes": 256,
                },
                "scope": {
                    "schema": driver.CALIBRATION_SCOPE_SCHEMA_V2, "condition": pins["condition"],
                    "source_root": str(root), "source_manifest": pins["source"],
                    "context_policy": pins["bundle"], "observed_host": pins["host"], "capacity_key": key,
                    "capacity_bundle_pins": {
                        "schema": driver.CAPACITY_BUNDLE_PIN_SCHEMA_V2, "capacity_key": key,
                        "source_manifest": pins["source"], "request": pins["request"],
                        "artifact": pins["capacity"], "receipt": pins["receipt"],
                    },
                },
            }

            def reader_source_boundary(_pin: dict[str, Any], source_root: object) -> None:
                self.assertEqual(readback.absolute_path(source_root, "SourceV5 source root"), root)
                raise readback.ReadbackError("source boundary reached with canonical text")

            with patch.object(driver, "_load_scope_readback_module", return_value=readback), \
                 patch.object(readback, "_verify_condition_file_v2", return_value=(pins["condition"], {})), \
                 patch.object(readback, "_source5_stack", side_effect=reader_source_boundary) as source_check, \
                 patch.object(readback, "_verify_capacity_bundle_v2") as capacity_check:
                with self.assertRaisesRegex(driver.PressureError, "source boundary reached with canonical text"):
                    driver._source5_context_calibration_request_v2(request)
                source_check.assert_called_once_with(pins["source"], str(root))
                capacity_check.assert_not_called()

    def test_numeric_context_projection_ignores_only_member_references(self) -> None:
        policy = {
            "schema": readback.SOURCE5_PRESSURE_POLICY_SCHEMA,
            "source_manifest": {"path": "/source/manifest.json", "raw_sha256": "a" * 64},
            "context": {"host_id": "host", "workload": "work", "profile": "profile", "calibration_id": "capacity-cal"},
            "capacity_bundle": {"request": {}, "artifact": {}, "receipt": {}},
            "base_policy_artifact_sha256": "b" * 64,
            "base_policy_sha256": "c" * 64,
            "base_context_sha256": "d" * 64,
            "resolution_rule_version": "rule-v1",
            "numeric_policy": {"collector": {"control_charge_bytes": 48}},
            "baseline": {"expected_global_control_baseline": 10},
            "hard_ceilings": {"global": {}, "tenant": {}},
            "normalization_denominators": {"capacity_sources": {}, "scope_limits": {}, "rate_buckets": {}},
            "member_resolutions": [{"request_raw_sha256": "e" * 64}, {"request_raw_sha256": "f" * 64}],
            "policy_sha256": "0" * 64,
        }

        def reseal(value: dict[str, Any]) -> dict[str, Any]:
            sealed = dict(value)
            body = {key: item for key, item in sealed.items() if key != "policy_sha256"}
            sealed["policy_sha256"] = readback.digest_object(body)
            return sealed

        policy = reseal(policy)
        original = readback._context_policy_numeric_projection_digest_v2(policy)
        changed_references = dict(policy)
        changed_references["member_resolutions"] = [
            {"request_raw_sha256": "1" * 64}, {"request_raw_sha256": "2" * 64},
        ]
        changed_references = reseal(changed_references)
        self.assertEqual(readback._context_policy_numeric_projection_digest_v2(changed_references), original)

        changed_numeric = dict(changed_references)
        changed_numeric["numeric_policy"] = {"collector": {"control_charge_bytes": 49}}
        changed_numeric = reseal(changed_numeric)
        self.assertNotEqual(readback._context_policy_numeric_projection_digest_v2(changed_numeric), original)
        with self.assertRaises(readback.ReadbackError):
            readback._context_policy_numeric_projection_digest_v2(dict(policy, unexpected_numeric_field=1))

        stored_receipt = {
            "context_policy_bundle_raw_sha256": "a" * 64,
            "context_policy_artifact_raw_sha256": "b" * 64,
            "context_policy_sha256": original,
            "capacity_bundle_pins_sha256": "c" * 64,
            "scope_sha256": "d" * 64,
            "host_verification": {"host_id": "host"},
            "receipt_sha256": "e" * 64,
        }
        current_replay = dict(stored_receipt)
        current_replay["context_policy_bundle_raw_sha256"] = "f" * 64
        current_replay["context_policy_artifact_raw_sha256"] = "1" * 64
        current_replay["receipt_sha256"] = "2" * 64
        self.assertTrue(readback._scope_receipts_match_replay_v2(stored_receipt, current_replay))
        current_replay["capacity_bundle_pins_sha256"] = "3" * 64
        self.assertFalse(readback._scope_receipts_match_replay_v2(stored_receipt, current_replay))

    def test_source5_condition_freezes_exact_numeric_thresholds_and_distinct_identity(self) -> None:
        calibration_schedule = {
            "seed": 7,
            "duration_seconds": 30,
            "sample_interval_ms": 100,
            "startup_deadline_seconds": 2,
            "total_deadline_seconds": 40,
            "term_deadline_seconds": 2,
            "kill_deadline_seconds": 2,
            "minimum_overlap_seconds": 30,
            "startup_ready_windows": 1,
            "cpu_duty_basis_points": 7000,
            "pressure_cpu_affinity": [0],
            "application_cpu_affinity": [0],
            "disk_bytes_per_second": 1024 * 1024,
            "scratch_file_bytes": 65536,
            "network_requests_per_second": 100,
            "network_payload_bytes": 256,
        }
        capacity_key = {"host_id": "host", "workload": "app", "profile": "default", "calibration_id": "capacity-cal"}
        condition = {
            "schema": readback.SOURCE5_PRESSURE_CONDITION_SCHEMA,
            "host_id": "host",
            "condition_id": "condition-v2",
            "capacity_key": capacity_key,
            "pressure_calibration_id": "pressure-cal-v2",
            "readiness_threshold_rule": readback.SOURCE5_PRESSURE_READINESS_RULE_V1,
            "readiness_thresholds": {
                "minimum_overlap_seconds": 30,
                "minimum_ready_samples": 300,
                "maximum_sample_gap_ms": 200,
            },
            "pressure_thresholds": {
                "cpu_busy_min_basis_points": 6000,
                "disk_write_min_bytes_per_second": 100_000,
                "disk_queue_or_stall_min_microseconds": 10,
                "loopback_requests_min_per_second": 50,
                "loopback_latency_p99_max_nanoseconds": 1_000_000,
                "loopback_tx_min_bytes_per_second": 10_000,
                "loopback_rx_min_bytes_per_second": 10_000,
            },
            "schedule": dict(calibration_schedule, duration_seconds=10800, total_deadline_seconds=12000),
        }
        with tempfile.TemporaryDirectory(prefix="pressure-condition-v2-") as temporary:
            root = Path(temporary)
            path = root / "condition.json"
            raw = readback.canonical_bytes(condition)
            path.write_bytes(raw)
            pin = {"path": str(path), "raw_sha256": readback.sha256_bytes(raw)}
            normalized_pin, normalized = readback._verify_condition_file_v2(
                pin, capacity_key, "condition-v2", calibration_schedule,
            )
            self.assertEqual(normalized_pin, pin)
            self.assertEqual(normalized["pressure_thresholds"], condition["pressure_thresholds"])
            self.assertEqual(normalized["pressure_calibration_id"], "pressure-cal-v2")

            mutations = (
                {"pressure_thresholds": dict(condition["pressure_thresholds"], cpu_busy_min_basis_points=True)},
                {"pressure_thresholds": dict(condition["pressure_thresholds"], cpu_busy_min_basis_points=10001)},
                {"pressure_calibration_id": "capacity-cal"},
                {"schedule": dict(condition["schedule"], disk_bytes_per_second=2 * 1024 * 1024)},
            )
            for index, mutation in enumerate(mutations):
                invalid = dict(condition, **mutation)
                bad_path = root / f"invalid-{index}.json"
                bad_raw = readback.canonical_bytes(invalid)
                bad_path.write_bytes(bad_raw)
                bad_pin = {"path": str(bad_path), "raw_sha256": readback.sha256_bytes(bad_raw)}
                with self.assertRaises(readback.ReadbackError):
                    readback._verify_condition_file_v2(bad_pin, capacity_key, "condition-v2", calibration_schedule)

            oversized = dict(condition, schedule=dict(condition["schedule"], duration_seconds=12001))
            bad_path = root / "oversized.json"
            bad_raw = readback.canonical_bytes(oversized)
            bad_path.write_bytes(bad_raw)
            bad_pin = {"path": str(bad_path), "raw_sha256": readback.sha256_bytes(bad_raw)}
            with self.assertRaises(readback.ReadbackError):
                readback._verify_condition_file_v2(bad_pin, capacity_key, "condition-v2", calibration_schedule)
            with self.assertRaises(readback.ReadbackError):
                readback._validate_calibration_schedule_v2(condition["schedule"])

    def test_every_measured_window_must_meet_frozen_thresholds(self) -> None:
        thresholds = {
            "cpu_busy_min_basis_points": 6000,
            "disk_write_min_bytes_per_second": 100_000,
            "disk_queue_or_stall_min_microseconds": 10,
            "loopback_requests_min_per_second": 50,
            "loopback_latency_p99_max_nanoseconds": 100,
            "loopback_tx_min_bytes_per_second": 10_000,
            "loopback_rx_min_bytes_per_second": 10_000,
        }
        sample = {
            "interval_start_monotonic_ns": 10_000_000_000,
            "interval_end_monotonic_ns": 11_000_000_000,
            "cpu": {"busy_basis_points": 7000},
            "block": {
                "write_bytes": 200_000,
                "writes_completed": 1,
                "weighted_io_milliseconds": 1,
                "in_flight": 0,
            },
            "io_psi_delta_microseconds": 0,
            "loopback": {"requests_completed": 200, "p99_upper_latency_nanoseconds": 64},
            "loopback_counters": {
                "tx_bytes": 20_000, "rx_bytes": 20_000,
                "rx_errors": 0, "tx_errors": 0, "rx_dropped": 0, "tx_dropped": 0,
            },
        }
        readback._validate_samples_meet_pressure_thresholds_v2([sample], thresholds)
        failed = dict(sample, loopback={"requests_completed": 200, "p99_upper_latency_nanoseconds": 128})
        with self.assertRaises(readback.ReadbackError):
            readback._validate_samples_meet_pressure_thresholds_v2([sample, failed], thresholds)
        with self.assertRaises(readback.ReadbackError):
            readback._pressure_thresholds_v2(dict(thresholds, cpu_busy_min_basis_points=True), "fixture thresholds")

    def test_offline_path_map_is_closed_sorted_identity_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-evidence-map-") as temporary:
            root = Path(temporary).resolve()
            payload = root / "receipt.json"
            payload.write_bytes(b"{}\n")
            entries = [
                {"origin": str(root), "local": str(root)},
                {"origin": str(payload), "local": str(payload)},
            ]
            normalized, directories = readback._normalize_evidence_path_map({
                "schema": readback.EVIDENCE_PATH_MAP_SCHEMA_V1,
                "entries": entries,
            }, root)
            self.assertEqual(normalized[str(root)], str(root))
            self.assertIn(str(root), directories)
            token = readback._EVIDENCE_PATH_MAP_CONTEXT.set((normalized, directories))
            try:
                readback._require_absolute_evidence_paths_mapped({"source": str(root / "source.json")})
                with self.assertRaises(readback.ReadbackError):
                    readback._require_absolute_evidence_paths_mapped({"source": str(Path(temporary).parent / "outside.json")})
            finally:
                readback._EVIDENCE_PATH_MAP_CONTEXT.reset(token)

            with self.assertRaises(readback.ReadbackError):
                readback._normalize_evidence_path_map({
                    "schema": readback.EVIDENCE_PATH_MAP_SCHEMA_V1,
                    "entries": [
                        {"origin": str(root), "local": str(root)},
                        {"origin": str(payload), "local": str(root / "renamed.json")},
                    ],
                }, root)

    def test_host_verification_binds_original_observed_host_and_worker_reap(self) -> None:
        observed = {
            "host_id": "host",
            "boot_id_sha256": "a" * 64,
            "kernel_release": "7.0.0-test",
            "cpu_affinity": [2, 4],
            "cpu_model": "test-cpu",
            "network_namespace_inode": 98765,
        }
        observed_pin = {"path": "/evidence/observed-host.json", "raw_sha256": "b" * 64}
        calibration = {
            "host": {
                "boot_id_sha256": observed["boot_id_sha256"],
                "kernel_release": observed["kernel_release"],
                "allowed_cpu_affinity": observed["cpu_affinity"],
            },
            "network": {"network_namespace_inode": observed["network_namespace_inode"]},
        }
        proof = readback._host_verification_v2(calibration, observed_pin, observed, require_live=False)
        self.assertEqual(proof["schema"], readback.CALIBRATION_HOST_VERIFICATION_SCHEMA_V2)
        self.assertEqual(proof["host_id"], "host")
        self.assertEqual(proof["observed_host_raw_sha256"], observed_pin["raw_sha256"])
        self.assertIs(proof["owned_worker_pids_reaped"], True)
        body = {key: value for key, value in proof.items() if key != "host_verification_sha256"}
        self.assertEqual(proof["host_verification_sha256"], readback.digest_object(body))

    def test_source_module_executes_hashed_bytes_after_path_swap_and_ignores_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-captured-module-") as temporary:
            root = Path(temporary).resolve()
            source_path = root / "scripts" / "pinned-helper.py"
            source_path.parent.mkdir()
            captured = b'CAPTURED_VALUE = "verified-source-bytes"\n'
            replacement = b'CAPTURED_VALUE = "changed-after-hash"\n'
            source_path.write_bytes(captured)
            source_path.chmod(0o644)
            cache = source_path.parent / "__pycache__" / "pinned-helper.cpython-999.pyc"
            cache.parent.mkdir()
            cache.write_bytes(b"untrusted stale bytecode")
            record = {
                "path": "scripts/pinned-helper.py",
                "kind": "file",
                "mode": "100644",
                "sha256": readback.sha256_bytes(captured),
                "size": len(captured),
            }
            source = {"source": {"files": [record]}}
            actual_compile = builtins.compile

            def replace_before_compile(code: bytes, filename: str, mode: str, **kwargs: Any):
                source_path.write_bytes(replacement)
                return actual_compile(code, filename, mode, **kwargs)

            with patch.object(readback, "compile", side_effect=replace_before_compile, create=True):
                module, actual = readback._load_source_module(root, source, record["path"], "captured-helper")
            self.assertEqual(actual, record["sha256"])
            self.assertEqual(module.CAPTURED_VALUE, "verified-source-bytes")
            self.assertEqual(source_path.read_bytes(), replacement)

    def test_driver_loads_captured_reader_bytes_after_path_swap(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-captured-reader-") as temporary:
            path = Path(temporary) / "application-pressure-readback.py"
            captured = (
                b'CALIBRATION_SCOPE_RECEIPT_SCHEMA_V2 = '
                b'"allocatbelt.application-pressure-calibration-scope-readback.v2"\n'
            )
            replacement = b'CALIBRATION_SCOPE_RECEIPT_SCHEMA_V2 = "replaced-reader"\n'
            path.write_bytes(captured)
            path.chmod(0o644)
            original_reader = driver.read_stable

            def replace_after_capture(candidate: Path, label: str, maximum: int):
                if candidate == path:
                    path.write_bytes(replacement)
                    return captured, driver.digest_bytes(captured)
                return original_reader(candidate, label, maximum)

            with patch.object(driver, "READER_PATH", path), patch.object(
                driver, "read_stable", side_effect=replace_after_capture,
            ):
                module = driver._load_scope_readback_module()
            self.assertEqual(
                module.CALIBRATION_SCOPE_RECEIPT_SCHEMA_V2,
                driver.CALIBRATION_SCOPE_RECEIPT_SCHEMA_V2,
            )
            self.assertEqual(path.read_bytes(), replacement)


class PressureStartupReadyTimelineTests(unittest.TestCase):
    """Timeline fixtures only; sample counters and process reaping are separate checks."""

    def _timeline_fixture(self, pending_windows: int = 2) -> dict[str, Any]:
        interval = 1_000_000_000
        start_ns = interval
        ready_count = 2
        before_application = ready_count + pending_windows
        application_start = start_ns + before_application * interval
        application_exit = application_start + interval
        readiness = {"all_ready": True, "cpu_busy_basis_points": 7000}
        process = {"pid": 12345, "start_ticks": 6789}
        binding = {
            "observed_monotonic_ns": application_start,
            "pressure_ready_monotonic_ns": start_ns + ready_count * interval,
            "readiness_snapshot": dict(readiness),
            "launch_record_sha256": "a" * 64,
        }
        cleanup = [{"role": "disk", "pid": 23456}]
        events = []
        for sequence in range(before_application + 1):
            if sequence == before_application:
                events.append({
                    "schema": readback.EVENT_SCHEMA, "kind": "application_start",
                    "sequence": sequence - 1, "monotonic_ns": application_start,
                    **process, "launch_record_sha256": binding["launch_record_sha256"],
                })
            events.append({
                "schema": readback.EVENT_SCHEMA, "kind": "sample", "sequence": sequence,
                "start": start_ns + sequence * interval,
                "end": start_ns + (sequence + 1) * interval,
                "app_active": sequence == before_application,
                "readiness": dict(readiness),
            })
        events.extend([
            {
                "schema": readback.EVENT_SCHEMA, "kind": "application_exit",
                "sequence": before_application, "monotonic_ns": application_exit,
                **process, "exit_observed": True,
            },
            {
                "schema": readback.EVENT_SCHEMA, "kind": "pressure_cleanup",
                "monotonic_ns": application_exit + 1, "workers": cleanup,
                "scratch_file_removed": True, "cleanup_ok": True,
            },
        ])
        return {
            "events": events,
            "start_event": {"monotonic_ns": start_ns},
            "recipe": {"schedule": {
                "sample_interval_ms": 1000, "startup_ready_windows": ready_count,
                "minimum_overlap_seconds": 1,
            }},
            "process": process, "binding": binding,
            "run": {
                "sample_count": before_application + 1,
                "finish_monotonic_ns": application_exit + 2,
                "worker_cleanup": cleanup, "application_overlap_nanoseconds": interval,
            },
            "workers": {("disk", None): cleanup[0]},
        }

    def _validate_timeline(self, fixture: dict[str, Any]) -> dict[str, Any]:
        def validated_sample(event, recipe, sequence):
            self.assertEqual(event["sequence"], sequence)
            return {key: event[key] for key in ("start", "end", "app_active", "readiness")}

        with patch.object(readback, "_validate_sample", side_effect=validated_sample), patch.object(
            readback, "_require_pid_reaped",
        ):
            return readback._validate_event_timeline(
                iter(fixture["events"]), fixture["start_event"], fixture["recipe"],
                fixture["process"], fixture["binding"], fixture["run"], fixture["workers"],
            )

    def test_original_ready_anchor_accepts_immediate_or_delayed_launch(self) -> None:
        for pending_windows in (0, 1, 3):
            with self.subTest(pending_windows=pending_windows):
                fixture = self._timeline_fixture(pending_windows)
                result = self._validate_timeline(fixture)
                self.assertEqual(result["application_window"], {
                    "observed_start_monotonic_ns": fixture["binding"]["observed_monotonic_ns"],
                    "observed_exit_monotonic_ns": fixture["binding"]["observed_monotonic_ns"]
                    + fixture["run"]["application_overlap_nanoseconds"],
                })
                self.assertEqual(result["continuous_ready_window"]["start_monotonic_ns"],
                                 fixture["binding"]["observed_monotonic_ns"])

    def test_ready_anchor_cannot_move_to_a_later_pending_sample(self) -> None:
        fixture = self._timeline_fixture()
        fixture["binding"]["pressure_ready_monotonic_ns"] = \
            fixture["binding"]["observed_monotonic_ns"]
        with self.assertRaisesRegex(readback.ReadbackError, "first complete startup windows"):
            self._validate_timeline(fixture)

    def test_ready_anchor_preserves_the_original_numeric_snapshot(self) -> None:
        fixture = self._timeline_fixture()
        fixture["binding"]["readiness_snapshot"]["cpu_busy_basis_points"] = 6999
        with self.assertRaisesRegex(readback.ReadbackError, "first complete startup windows"):
            self._validate_timeline(fixture)

    def test_unready_pending_sample_is_rejected_after_later_recovery(self) -> None:
        fixture = self._timeline_fixture(pending_windows=3)
        fixture["events"][2]["readiness"]["all_ready"] = False
        with self.assertRaisesRegex(readback.ReadbackError, "before application start is unready"):
            self._validate_timeline(fixture)

    def test_latest_pending_sample_must_precede_observed_application_start(self) -> None:
        fixture = self._timeline_fixture()
        fixture["binding"]["observed_monotonic_ns"] -= 1
        for event in fixture["events"]:
            if event["kind"] == "application_start":
                event["monotonic_ns"] -= 1
        with self.assertRaisesRegex(readback.ReadbackError, "does not follow its measured readiness window"):
            self._validate_timeline(fixture)


class PressurePairHostReceiptSchemaTests(unittest.TestCase):
    """Synthetic schema fixture only; this is not a host-cleanup witness."""

    def _receipt(self) -> dict[str, Any]:
        deps = {
            name: {"path": f"scripts/{name}.py", "raw_sha256": f"{index:064x}"}
            for index, name in enumerate((
                "application-campaign", "application-campaign-chronology",
                "application-feedback-composition", "application-feedback-readback",
                "application-pressure-readback", "application-soak-readback",
                "application-byte-capacity", "application-pressure-pair",
                "application-pressure-driver", "application-source-inventory",
                "application-fixed-pair",
            ), 1)
        }
        roles = dict(zip(("application-campaign", "application-campaign-chronology",
                          "application-feedback-composition", "application-feedback-readback",
                          "application-pressure-readback", "application-soak-readback",
                          "application-byte-capacity", "application-pressure-pair",
                          "application-pressure-driver", "application-source-inventory",
                          "application-fixed-pair"),
                         ("campaign_controller", "campaign_chronology", "feedback_composition",
                          "feedback_validator", "pressure_validator", "soak_supervisor",
                          "capacity_producer", "pressure_pair", "pressure_driver",
                          "source_inventory", "fixed_pair"), strict=True))
        deps = {roles[name]: pin for name, pin in deps.items()}
        deps["source5_helper_input"] = {
            "path": "/evidence/helper-input.json", "raw_sha256": "2" * 64,
        }
        deps["source5_helper_module"] = deps["pressure_pair"]
        facts = {
            "boot_id_sha256": "a" * 64, "kernel_release": "fixture-kernel",
            "cpu_affinity": [0, 1], "network_namespace_inode": 7,
        }
        origin = {
            "schema": readback.PRESSURE_PAIR_ORIGIN_FACTS_SCHEMA,
            "host_id": "host-a", "observed_host_raw_sha256": "f" * 64,
            "before": facts, "after": facts, "storage_sha256": "c" * 64,
        }
        origin["origin_facts_sha256"] = readback.digest_object(origin)
        rows = []
        for index, pair_name in enumerate(("bounded", "tokio")):
            app = {"pid": 100 + index * 10, "start_ticks": 1000 + index * 10}
            worker = {
                "role": "loopback", "cpu": None, "pid": app["pid"] + 1,
                "start_ticks": app["start_ticks"] + 1,
                "pgid": app["pid"] + 1, "session_id": app["pid"] + 1,
            }
            artifacts = {
                "directory": f"/evidence/member-{index}/pressure",
                "pins": {name: f"{index + 1:064x}" for name in (
                    "events", "launch", "process_binding", "ready", "run",
                )},
                "proof": {"path": f"/evidence/member-{index}/pressure-readback.json",
                          "raw_sha256": f"{index + 11:064x}"},
                "ready_sha256": f"{index + 21:064x}", "driver": {},
                "worker_sessions": [worker], "driver_logs": {},
            }
            rows.append({
                "ordinal": index,
                "descriptor": {"pair": pair_name,
                               "executor": "bounded" if index == 0 else "tokio",
                               "allocator": "allocatbelt"},
                "identity": {"host_id": "host-a", "run_id": "run-a",
                             "allocator": "allocatbelt"},
                "pressure_recipe": {
                    "path": f"/evidence/member-{index}/recipe.json",
                    "raw_sha256": f"{index + 31:064x}",
                    "semantic_sha256": f"{index + 41:064x}",
                    "condition_sha256": f"{index + 51:064x}",
                },
                "pressure_artifacts": artifacts,
                "application_identity": app,
                "worker_identities": [worker],
                "pid_absence": [
                    {"pid": app["pid"], "start_ticks": app["start_ticks"],
                     "absent": True, "observed_monotonic_ns": 5000},
                    {"pid": worker["pid"], "start_ticks": worker["start_ticks"],
                     "absent": True, "observed_monotonic_ns": 5001},
                ],
                "probe_capture": {
                    "construction_probe": {
                        "path": f"/evidence/member-{index}/probe.json",
                        "raw_sha256": f"{index + 91:064x}", "allocator": "allocatbelt",
                        "binary_sha256": f"{index + 101:064x}",
                    },
                    "capture_receipt": {
                        "path": f"/evidence/member-{index}/capture.json",
                        "raw_sha256": f"{index + 111:064x}",
                        "receipt_sha256": f"{index + 121:064x}",
                    },
                    "capacity_bundle": {
                        name: {"path": f"/evidence/member-{index}/capacity-{name}.json",
                               "raw_sha256": f"{index + 131 + offset:064x}"}
                        for offset, name in enumerate(("request", "artifact", "receipt"))
                    },
                },
                "application_launch_attestation": {
                    "path": f"/evidence/member-{index}/attestation.json",
                    "raw_sha256": f"{index + 61:064x}"},
                "application_cleanup": {
                    "path": f"/evidence/member-{index}/cleanup.json",
                    "raw_sha256": f"{index + 71:064x}"},
                "supervision_receipt": {
                    "path": f"/evidence/member-{index}/supervision.json",
                    "raw_sha256": f"{index + 81:064x}"},
                "storage_proof": {
                    "application_tmpdir_path": f"/evidence/member-{index}/tmp",
                    "pressure_scratch_path": f"/storage/member-{index}/scratch.bin",
                    "application_mount_id": 3, "storage_sha256": "d" * 64,
                },
            })
        origin["storage_sha256"] = readback.digest_object([
            row["storage_proof"]["storage_sha256"] for row in rows
        ])
        origin_body = {key: value for key, value in origin.items()
                       if key != "origin_facts_sha256"}
        origin["origin_facts_sha256"] = readback.digest_object(origin_body)
        body = {
            "schema": readback.PRESSURE_PAIR_HOST_VERIFICATION_SCHEMA,
            "campaign_id": "campaign-a", "host_id": "host-a",
            "job": {"run_id": "run-a", "ordinal": 9, "job_index": 4,
                    "semantic_sha256": "e" * 64},
            "recipe": {"path": "/evidence/recipe.json", "raw_sha256": "f" * 64,
                       "semantic_sha256": "1" * 64},
            "readback": {"path": "/evidence/pressure-pair-readback.json",
                         "raw_sha256": "2" * 64, "semantic_sha256": "3" * 64},
            "source_manifest": {"path": "/evidence/source-manifest.json",
                                 "raw_sha256": "4" * 64, "semantic_sha256": "5" * 64,
                                 "source_tree_sha256": "6" * 64},
            "spec": {"path": "/evidence/spec.json", "raw_sha256": "7" * 64,
                     "semantic_sha256": "8" * 64},
            "plan": {"path": "/evidence/plan.json", "raw_sha256": "9" * 64,
                     "semantic_sha256": "a" * 64},
            "execution_manifest": {"path": "/evidence/overlay.json",
                                   "raw_sha256": "b" * 64,
                                   "semantic_sha256": "c" * 64},
            "authorization_id": "auth-a", "journal_head": "d" * 64,
            "registration_head": "e" * 64,
            "observed_host": {"path": "/evidence/observed-host.json",
                               "raw_sha256": "f" * 64},
            "origin_facts": origin, "dependency_pins": deps,
            "member_facts": rows, "strict_result_sha256": "1" * 64,
            "qualification_eligible": False, "execution_ready": False,
        }
        return {**body, "receipt_sha256": readback.digest_object(body)}

    def test_receipt_validator_checks_separate_raw_and_semantic_pins(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-host-receipt-") as directory:
            root = Path(directory)
            root.chmod(0o700)
            path = root / "host-receipt.json"
            receipt = self._receipt()
            raw = readback.canonical_bytes(receipt)
            path.write_bytes(raw)
            path.chmod(0o600)
            pin = {"path": str(path), "raw_sha256": readback.sha256_bytes(raw),
                   "receipt_sha256": receipt["receipt_sha256"]}
            checked, actual_raw, checked_pin = readback._validate_pressure_pair_host_receipt(pin)
            self.assertEqual(checked, receipt)
            self.assertEqual(actual_raw, pin["raw_sha256"])
            self.assertEqual(checked_pin["receipt_sha256"], receipt["receipt_sha256"])

            archived_path = Path("/reclaimed/pressure-host-receipt.json")

            class CapturedReceiptView:
                def has_file(self, origin):
                    return str(origin) == str(archived_path)

                def read(self, origin, label, maximum):
                    if str(origin) != str(archived_path) or len(raw) > maximum:
                        raise AssertionError(f"unexpected captured receipt read: {label}")
                    return raw, readback.sha256_bytes(raw)

            with patch.object(
                    Path, "lstat",
                    side_effect=AssertionError("captured receipt consulted its origin path")):
                captured, captured_sha, captured_pin = \
                    readback._validate_pressure_pair_host_receipt(
                        {**pin, "path": str(archived_path)},
                        artifact_view=CapturedReceiptView(),
                    )
            self.assertEqual(captured, receipt)
            self.assertEqual(captured_sha, pin["raw_sha256"])
            self.assertEqual(captured_pin["path"], str(archived_path))
            with self.assertRaisesRegex(readback.ReadbackError,
                                        "captured pressure-pair host receipt"):
                readback._validate_pressure_pair_host_receipt(
                    {**pin, "path": str(archived_path),
                     "raw_sha256": "0" * 64},
                    artifact_view=CapturedReceiptView(),
                )

            wrong_role = dict(pin, receipt_sha256=pin["raw_sha256"])
            with self.assertRaisesRegex(readback.ReadbackError, "raw/semantic digest roles"):
                readback._validate_pressure_pair_host_receipt(wrong_role)

            mutated = dict(receipt, execution_ready=True)
            mutated_body = {key: value for key, value in mutated.items() if key != "receipt_sha256"}
            mutated["receipt_sha256"] = readback.digest_object(mutated_body)
            path.write_bytes(readback.canonical_bytes(mutated))
            with self.assertRaisesRegex(readback.ReadbackError, "false eligibility fields"):
                readback._validate_pressure_pair_host_receipt({
                    "path": str(path), "raw_sha256": readback.sha256_bytes(path.read_bytes()),
                    "receipt_sha256": mutated["receipt_sha256"],
                })

    def test_bounded_v2_receipt_requires_immediate_zero_tmpdir_owner_return(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-host-tmpdir-v2-") as directory:
            root = Path(directory)
            root.chmod(0o700)
            path = root / "host-receipt.json"
            receipt = self._receipt()
            receipt["schema"] = readback.PRESSURE_PAIR_HOST_VERIFICATION_SCHEMA_V2
            for index, row in enumerate(receipt["member_facts"]):
                tmp_path = row["storage_proof"]["application_tmpdir_path"]
                mount = {
                    "mount_id": 3, "major_minor": "8:1", "mount_root": "/",
                    "mount_point": "/tmp", "filesystem_type": "ext4",
                    "mount_source": "/dev/sda", "device": 8,
                }
                initial = {
                    "path": tmp_path, "device": 8, "inode": 100 + index,
                    "mode": 0o700, "mount": mount,
                    "available_bytes": 8192, "available_inodes": 1024,
                    "bytes_limit": 4096, "inode_limit": 64,
                }
                final = {
                    "path": tmp_path, "device": 8, "inode": 100 + index,
                    "mode": 0o700, "mount": mount,
                    "bytes_used": 0, "file_count": 0, "directory_count": 0,
                    "bytes_limit": 4096, "inode_limit": 64,
                    "available_bytes": 4096, "available_inodes": 100,
                }
                storage = row["storage_proof"]
                storage["application_tmpdir_initial"] = initial
                storage["application_tmpdir_final"] = final
                storage["storage_sha256"] = readback.digest_object({
                    "application_tmpdir_initial": initial,
                    "application_tmpdir_final": final,
                    "prior_storage_sha256": "d" * 64,
                })
            origin = receipt["origin_facts"]
            origin["storage_sha256"] = readback.digest_object([
                row["storage_proof"]["storage_sha256"]
                for row in receipt["member_facts"]
            ])
            origin_body = {key: value for key, value in origin.items()
                           if key != "origin_facts_sha256"}
            origin["origin_facts_sha256"] = readback.digest_object(origin_body)
            receipt_body = {key: value for key, value in receipt.items()
                            if key != "receipt_sha256"}
            receipt["receipt_sha256"] = readback.digest_object(receipt_body)
            raw = readback.canonical_bytes(receipt)
            path.write_bytes(raw)
            path.chmod(0o600)
            pin = {"path": str(path),
                   "raw_sha256": readback.sha256_bytes(raw),
                   "receipt_sha256": receipt["receipt_sha256"]}
            checked, actual_raw, _checked_pin = \
                readback._validate_pressure_pair_host_receipt(pin)
            self.assertEqual(checked, receipt)
            self.assertEqual(actual_raw, pin["raw_sha256"])

            receipt["member_facts"][0]["storage_proof"][
                "application_tmpdir_final"]["file_count"] = 1
            changed_body = {key: value for key, value in receipt.items()
                            if key != "receipt_sha256"}
            receipt["receipt_sha256"] = readback.digest_object(changed_body)
            changed_raw = readback.canonical_bytes(receipt)
            path.write_bytes(changed_raw)
            with self.assertRaisesRegex(
                    readback.ReadbackError,
                    "not the exact empty original directory"):
                readback._validate_pressure_pair_host_receipt({
                    "path": str(path),
                    "raw_sha256": readback.sha256_bytes(changed_raw),
                    "receipt_sha256": receipt["receipt_sha256"],
                })

    def test_soak_single_app_api_has_its_own_three_pin_boundary(self) -> None:
        signature = inspect.signature(readback.verify_source5_soak_pressure_offline)
        positional = [
            parameter.name for parameter in signature.parameters.values()
            if parameter.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
        ]
        keyword_only = {
            parameter.name for parameter in signature.parameters.values()
            if parameter.kind is inspect.Parameter.KEYWORD_ONLY
        }
        self.assertEqual(positional, [
            "pressure_recipe_pin", "pressure_artifacts",
            "soak_host_verification_pin",
        ])
        self.assertEqual(keyword_only, {
            "evidence_path_map", "source_root", "artifact_view",
            "captured_origin_paths", "evidence_file_paths",
            "evidence_directory_paths",
        })

    def test_captured_pressure_event_stream_uses_pinned_snapshot_without_origin_stat(self) -> None:
        origin = Path("/reclaimed/source5/soak/pressure/events.jsonl")
        raw = readback.canonical_bytes({"kind": "captured-event-fixture"})
        raw_sha = readback.sha256_bytes(raw)

        class MemoryView:
            def has_file(self, path):
                return path == origin

            @contextlib.contextmanager
            def open_snapshot(self, path, label, maximum):
                self.calls = getattr(self, "calls", []) + [(path, label, maximum)]
                if len(raw) > maximum:
                    raise ValueError("capture ceiling")
                yield io.BytesIO(raw), raw_sha, len(raw)

        view = MemoryView()
        state = {"event_count": 0}
        with patch.object(
                readback.Path, "lstat",
                side_effect=AssertionError("captured origin path was statted")):
            events = list(readback._iter_events(
                origin, raw_sha, len(raw), len(raw), state,
                artifact_view=view,
            ))
        self.assertEqual(events, [{"kind": "captured-event-fixture"}])
        self.assertEqual(state["event_count"], 1)
        self.assertEqual(state["events_sha256"], raw_sha)
        self.assertEqual(state["events_bytes"], len(raw))
        self.assertEqual(view.calls, [(origin, "pressure events", len(raw))])

    def test_captured_pressure_event_stream_rejects_mismatched_archive_pin(self) -> None:
        origin = Path("/reclaimed/source5/soak/pressure/events.jsonl")
        raw = readback.canonical_bytes({"kind": "captured-event-fixture"})

        class MemoryView:
            def has_file(self, path):
                return path == origin

            @contextlib.contextmanager
            def open_snapshot(self, path, label, maximum):
                yield io.BytesIO(raw), "0" * 64, len(raw)

        with self.assertRaisesRegex(readback.ReadbackError,
                                    "captured pressure event size/raw pin"):
            list(readback._iter_events(
                origin, readback.sha256_bytes(raw), len(raw), len(raw),
                {"event_count": 0}, artifact_view=MemoryView(),
            ))

    def test_soak_pressure_calls_match_the_actual_reader_api_signatures(self) -> None:
        """Bind new direct calls to parsed definitions and loaded functions."""
        def assert_call_shapes(owner: ast.AST,
                               definitions: dict[str, ast.AST],
                               functions: dict[str, Any]) -> None:
            seen = {name: 0 for name in functions}
            for call in ast.walk(owner):
                if not isinstance(call, ast.Call):
                    continue
                if isinstance(call.func, ast.Name):
                    target_name = call.func.id
                elif isinstance(call.func, ast.Attribute):
                    target_name = call.func.attr
                else:
                    continue
                runtime_target = functions.get(target_name)
                if runtime_target is None:
                    continue
                definition = definitions[target_name]
                args = definition.args
                positional_ast = args.posonlyargs + args.args
                positional_names = [argument.arg for argument in positional_ast]
                positional_defaults = [None] * (
                    len(positional_names) - len(args.defaults)
                ) + list(args.defaults)
                keyword_only_names = [argument.arg for argument in args.kwonlyargs]
                keyword_only_required = {
                    name for name, default in zip(
                        keyword_only_names, args.kw_defaults, strict=True,
                    ) if default is None
                }
                signature = inspect.signature(runtime_target)
                runtime_positional = [
                    parameter.name for parameter in signature.parameters.values()
                    if parameter.kind in (
                        inspect.Parameter.POSITIONAL_ONLY,
                        inspect.Parameter.POSITIONAL_OR_KEYWORD,
                    )
                ]
                runtime_keyword_only = [
                    parameter.name for parameter in signature.parameters.values()
                    if parameter.kind is inspect.Parameter.KEYWORD_ONLY
                ]
                self.assertEqual(
                    runtime_positional, positional_names,
                    f"{target_name} loaded positional signature differs from its parsed definition",
                )
                self.assertEqual(
                    runtime_keyword_only, keyword_only_names,
                    f"{target_name} loaded keyword-only signature differs from its parsed definition",
                )
                self.assertIsNone(args.vararg,
                                  f"{target_name} must not hide call arity in *args")
                self.assertIsNone(args.kwarg,
                                  f"{target_name} must not hide call names in **kwargs")
                seen[target_name] += 1
                self.assertLessEqual(
                    len(call.args), len(positional_names),
                    f"{target_name} call passes too many positional arguments",
                )
                supplied = set(positional_names[:len(call.args)])
                self.assertFalse(
                    any(keyword.arg is None for keyword in call.keywords),
                    f"{target_name} call uses **kwargs without an accepting parameter",
                )
                keyword_names = {keyword.arg for keyword in call.keywords
                                 if keyword.arg is not None}
                keywordable = {
                    argument.arg for argument in args.args
                } | set(keyword_only_names)
                self.assertTrue(
                    keyword_names <= keywordable,
                    f"{target_name} call uses an unknown keyword argument",
                )
                self.assertFalse(
                    supplied & keyword_names,
                    f"{target_name} call supplies an argument twice",
                )
                required_positional = {
                    name for name, default in zip(
                        positional_names, positional_defaults, strict=True,
                    ) if default is None
                }
                self.assertTrue(
                    required_positional | keyword_only_required <=
                    supplied | keyword_names,
                    f"{target_name} call omits a required argument",
                )
            for name, count in seen.items():
                self.assertGreater(count, 0, f"expected a direct {name} call")

        reader_tree = ast.parse(READER_PATH.read_text(encoding="utf-8"))
        reader_functions = {
            node.name: node for node in reader_tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        offline = reader_functions["_verify_source5_soak_pressure_offline_impl"]
        assert_call_shapes(offline, reader_functions, {
            "read_canonical": readback.read_canonical,
            "_validate_recipe": readback._validate_recipe,
            "verify_pressure": readback.verify_pressure,
        })
        for wrapper_name, bounded_v3 in (
            ("verify_source5_soak_pressure_offline", False),
            ("verify_source5_soak_pressure_offline_v3", True),
        ):
            wrapper = reader_functions[wrapper_name]
            assert_call_shapes(wrapper, reader_functions, {
                "_verify_source5_soak_pressure_offline_impl":
                    readback._verify_source5_soak_pressure_offline_impl,
            })
            public = getattr(readback, wrapper_name)
            arguments = (object(), object(), object())
            keywords = {"evidence_path_map": object(), "source_root": object()}
            inspect.signature(public).bind(*arguments, **keywords)
            marker = object()
            with patch.object(readback, "_verify_source5_soak_pressure_offline_impl",
                              autospec=True, return_value=marker) as implementation:
                self.assertIs(public(*arguments, **keywords), marker)
                implementation.assert_called_once_with(
                    *arguments, **keywords, bounded_v3=bounded_v3,
                    artifact_view=None, captured_origin_paths=None,
                    evidence_file_paths=None,
                    evidence_directory_paths=None,
                )

        test_tree = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        test_functions = {
            node.name: node for node in test_tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        fixture_functions = [
            test_functions["run_pressure_offline_fixture"],
            test_functions["run_source5_soak_pressure_offline_fixture"],
        ]
        for fixture_function in fixture_functions:
            assert_call_shapes(fixture_function, reader_functions, {
                "read_canonical": readback.read_canonical,
            })

    def test_soak_single_app_receipt_validator_rejects_pair_receipt_schema(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-soak-receipt-schema-") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            path = root / "pair-host-receipt.json"
            receipt = self._receipt()
            raw = readback.canonical_bytes(receipt)
            path.write_bytes(raw)
            path.chmod(0o600)
            with self.assertRaisesRegex(readback.ReadbackError, "unexpected shape"):
                readback._validate_source5_soak_host_receipt_v2({
                    "path": str(path), "raw_sha256": readback.sha256_bytes(raw),
                    "receipt_sha256": receipt["receipt_sha256"],
                })

    def test_soak_single_app_pressure_rejects_missing_host_receipt_map_before_reads(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-soak-map-preflight-") as temporary:
            root = Path(temporary).resolve()
            source_root = root / "source"
            artifact_root = root / "pressure"
            source_root.mkdir(mode=0o700)
            artifact_root.mkdir(mode=0o700)
            recipe = source_root / "pressure-recipe.json"
            proof = root / "pressure-readback.json"
            logs = [root / "pressure-driver.stdout.log",
                    root / "pressure-driver.stderr.log"]
            artifact_files = [
                artifact_root / "events.jsonl",
                artifact_root / "launch-record.json",
                artifact_root / "process-binding.json",
                artifact_root / "pressure-ready.json",
                artifact_root / "run.json",
            ]
            for path in [recipe, proof, *logs, *artifact_files]:
                path.write_bytes(b"placeholder\n")
                path.chmod(0o600)
            pins = {
                name: "a" * 64 for name in (
                    "events", "launch", "process_binding", "ready", "run",
                )
            }
            artifacts = {
                "directory": str(artifact_root), "pins": pins,
                "proof": {"path": str(proof), "raw_sha256": "b" * 64},
                "ready_sha256": pins["ready"], "driver": {},
                "worker_sessions": [],
                "driver_logs": {
                    "stdout": {"path": str(logs[0]), "raw_sha256": "c" * 64},
                    "stderr": {"path": str(logs[1]), "raw_sha256": "d" * 64},
                },
            }
            mapped = [source_root, artifact_root, recipe, proof, *logs,
                      *artifact_files]
            entries = [
                {"origin": str(path), "local": str(path)}
                for path in sorted(mapped, key=str)
            ]
            with patch.object(
                readback, "read_canonical",
                side_effect=AssertionError("read before top-level map closure"),
            ) as read_canonical:
                with self.assertRaisesRegex(
                    readback.ReadbackError,
                    "path map omits a direct pinned input",
                ):
                    readback.verify_source5_soak_pressure_offline(
                        {
                            "path": str(recipe), "raw_sha256": "e" * 64,
                            "semantic_sha256": "f" * 64,
                            "condition_sha256": "1" * 64,
                        }, artifacts,
                        {"path": str(root / "unmapped-host.json"),
                         "raw_sha256": "2" * 64,
                         "receipt_sha256": "3" * 64},
                        evidence_path_map={
                            "schema": readback.EVIDENCE_PATH_MAP_SCHEMA_V1,
                            "entries": entries,
                        },
                        source_root=str(source_root),
                    )
                read_canonical.assert_not_called()




def run_pressure_offline_fixture(request_path: Path, expected_request_raw_sha256: str) -> dict[str, Any]:
    """Public replay entrypoint for genuine copied pressure evidence."""
    request, _request_raw, request_sha = readback.read_canonical(
        request_path, "pressure offline fixture request", 2 * 1024 * 1024,
    )
    if request_sha != expected_request_raw_sha256:
        raise readback.ReadbackError("pressure offline fixture request raw pin differs")
    readback.exact(request, {
        "schema", "pressure_recipe", "pressure_artifacts", "host_verification",
        "evidence_path_map", "source_root",
    }, "pressure offline fixture request")
    if request["schema"] != PRESSURE_OFFLINE_FIXTURE_SCHEMA:
        raise readback.ReadbackError("unsupported pressure offline fixture request schema")
    result = readback.verify_pressure_offline(
        request["pressure_recipe"], request["pressure_artifacts"],
        request["host_verification"], evidence_path_map=request["evidence_path_map"],
        source_root=request["source_root"],
    )
    if result.get("status") != "valid" or "qualification_eligible" in result:
        raise readback.ReadbackError("offline pressure fixture returned an invalid or readiness-bearing result")
    return {"request_raw_sha256": request_sha, "readback": result}


def run_source5_soak_pressure_offline_fixture(
    request_path: Path, expected_request_raw_sha256: str,
) -> dict[str, Any]:
    """Replay a genuine one-APP Soak pressure receipt and its raw event set."""
    request, _request_raw, request_sha = readback.read_canonical(
        request_path, "Source5 Soak pressure offline fixture request",
        2 * 1024 * 1024,
    )
    if request_sha != expected_request_raw_sha256:
        raise readback.ReadbackError(
            "Source5 Soak pressure offline fixture request raw pin differs",
        )
    readback.exact(request, {
        "schema", "pressure_recipe", "pressure_artifacts",
        "soak_host_verification", "evidence_path_map", "source_root",
        "expected",
    }, "Source5 Soak pressure offline fixture request")
    if request["schema"] != SOAK_PRESSURE_OFFLINE_FIXTURE_SCHEMA:
        raise readback.ReadbackError(
            "unsupported Source5 Soak pressure offline fixture schema",
        )
    result = readback.verify_source5_soak_pressure_offline(
        request["pressure_recipe"], request["pressure_artifacts"],
        request["soak_host_verification"],
        evidence_path_map=request["evidence_path_map"],
        source_root=request["source_root"],
    )
    expected = readback.exact(request["expected"], {
        "host_id", "run_id", "recipe_raw_sha256", "condition_sha256",
        "readback_sha256", "sample_count", "application_overlap_nanoseconds",
    }, "Source5 Soak pressure offline fixture expected replay pins")
    projection = {
        "host_id": result["identity"]["host_id"],
        "run_id": result["identity"]["run_id"],
        "recipe_raw_sha256": result["recipe_raw_sha256"],
        "condition_sha256": result["condition_sha256"],
        "readback_sha256": result["readback_sha256"],
        "sample_count": result["sample_count"],
        "application_overlap_nanoseconds":
            result["application_overlap_nanoseconds"],
    }
    if projection != expected:
        raise readback.ReadbackError(
            "Source5 Soak pressure offline replay differs from the pinned fixture result",
        )
    if "qualification_eligible" in result or "execution_ready" in result:
        raise readback.ReadbackError(
            "Source5 Soak pressure replay returned a qualification-bearing result",
        )
    return {"request_raw_sha256": request_sha, "readback": result}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scope-fixture", type=Path,
        help="run full replay and mutation checks against a raw-pinned genuine SourceV5 fixture",
    )
    parser.add_argument("--closed-recorded-scope-fixture", type=Path,
                        help="replay genuine capture.v2 pressure evidence with peer-ELF reads denied")
    parser.add_argument("--expected-closed-recorded-scope-fixture-sha256")
    parser.add_argument("--pressure-offline-fixture", type=Path,
                        help="replay pressure output using a genuine strict host receipt")
    parser.add_argument("--expected-pressure-fixture-sha256")
    parser.add_argument("--source5-soak-pressure-offline-fixture", type=Path,
                        help="replay pressure output using a genuine strict single-APP Soak receipt")
    parser.add_argument("--expected-source5-soak-pressure-fixture-sha256")
    args = parser.parse_args(argv)
    if args.closed_recorded_scope_fixture is not None:
        if args.expected_closed_recorded_scope_fixture_sha256 is None:
            parser.error(
                "--closed-recorded-scope-fixture requires "
                "--expected-closed-recorded-scope-fixture-sha256",
            )
        result = run_genuine_closed_recorded_scope_fixture(
            args.closed_recorded_scope_fixture,
            args.expected_closed_recorded_scope_fixture_sha256,
        )
        sys.stdout.buffer.write(readback.canonical_bytes({
            "schema": CLOSED_RECORDED_SCOPE_FIXTURE_SCHEMA,
            "status": "closed_recorded_scope_replay_passed",
            "request_raw_sha256": result["request_raw_sha256"],
            "scope_sha256": result["scope_sha256"],
            "receipt_sha256": result["receipt_sha256"],
            "peer_elf_state": result["peer_elf_state"],
            "qualification_eligible": False,
        }))
        return 0
    if args.source5_soak_pressure_offline_fixture is not None:
        if args.expected_source5_soak_pressure_fixture_sha256 is None:
            parser.error(
                "--source5-soak-pressure-offline-fixture requires "
                "--expected-source5-soak-pressure-fixture-sha256",
            )
        result = run_source5_soak_pressure_offline_fixture(
            args.source5_soak_pressure_offline_fixture,
            args.expected_source5_soak_pressure_fixture_sha256,
        )
        sys.stdout.buffer.write(readback.canonical_bytes({
            "schema": SOAK_PRESSURE_OFFLINE_FIXTURE_SCHEMA,
            "status": "single_app_pressure_offline_replay_passed",
            "request_raw_sha256": result["request_raw_sha256"],
            "readback_sha256": result["readback"]["readback_sha256"],
            "qualification_eligible": False,
        }))
        return 0
    if args.pressure_offline_fixture is not None:
        if args.expected_pressure_fixture_sha256 is None:
            parser.error("--pressure-offline-fixture requires --expected-pressure-fixture-sha256")
        result = run_pressure_offline_fixture(
            args.pressure_offline_fixture, args.expected_pressure_fixture_sha256,
        )
        sys.stdout.buffer.write(readback.canonical_bytes({
            "schema": PRESSURE_OFFLINE_FIXTURE_SCHEMA,
            "status": "full_pressure_offline_replay_passed",
            "request_raw_sha256": result["request_raw_sha256"],
            "readback_sha256": result["readback"]["readback_sha256"],
            "qualification_eligible": False,
        }))
        return 0
    if args.scope_fixture is not None:
        result = run_genuine_scope_fixture(args.scope_fixture)
        sys.stdout.buffer.write(readback.canonical_bytes({
            "schema": SCOPE_FIXTURE_SCHEMA,
            "status": "full_replay_and_mutations_passed",
            "scope_sha256": result["scope_sha256"],
            "calibration_raw_sha256": result["calibration_raw_sha256"],
            "receipt_sha256": result["receipt_sha256"],
            "qualification_eligible": result["qualification_eligible"],
        }))
        return 0
    result = unittest.main(argv=[sys.argv[0]], exit=False)
    return 0 if result.result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
