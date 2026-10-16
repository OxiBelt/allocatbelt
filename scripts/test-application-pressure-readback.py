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
import stat
import sys
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


class PressureReadbackV2Tests(unittest.TestCase):
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
        self.assertIn("expected_shared_context['capacity_floor_policy_id']", source)

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
    parser.add_argument("--pressure-offline-fixture", type=Path,
                        help="replay pressure output using a genuine strict host receipt")
    parser.add_argument("--expected-pressure-fixture-sha256")
    parser.add_argument("--source5-soak-pressure-offline-fixture", type=Path,
                        help="replay pressure output using a genuine strict single-APP Soak receipt")
    parser.add_argument("--expected-source5-soak-pressure-fixture-sha256")
    args = parser.parse_args(argv)
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
