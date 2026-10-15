#!/usr/bin/env python3
"""Schema fixtures for additive pre-Spec Source5 preparation inputs."""

from __future__ import annotations

import copy
from contextlib import contextmanager
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import stat
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import patch


SCRIPT_DIR = Path(__file__).resolve().parent


def load_script(path: Path, name: str):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


inputs = load_script(SCRIPT_DIR / "application-campaign-inputs.py", "source5_preparation_inputs_test_target")
capacity_stage = load_script(SCRIPT_DIR / "application-capacity-stage.py", "source5_preparation_stage_test_target")
legacy_fixtures = load_script(SCRIPT_DIR / "test-application-campaign.py", "source5_preparation_legacy_fixtures")
campaign = legacy_fixtures.campaign


def _pin(path: str, digit: str) -> dict[str, str]:
    return {"relative_path": path, "raw_sha256": digit * 64}


def preparation_fixture() -> tuple[dict, dict]:
    spec, _sources = legacy_fixtures.spec_fixture()
    core = {
        key: spec[key]
        for key in (
            "campaign_id", "runner_sha256", "hosts", "cells", "protocol",
            "runtime_binding", "phase_adapters", "aa_controls", "soak", "deadlines",
        )
    }
    source_pins: dict[str, dict] = {}
    observed_hosts: dict[str, dict] = {}
    for index, host in enumerate(spec["hosts"], 1):
        host_id = host["host_id"]
        source_pins[host_id] = {
            "manifest": {
                "relative_path": f"sources/{host_id}.json",
                "raw_sha256": str(index) * 64,
                "semantic_sha256": str(index + 1) * 64,
                "source_tree_sha256": str(index + 2) * 64,
            },
            "modules": {
                role: {"path": path, "sha256": str(index + 3) * 64}
                for role, path in inputs.PREPARATION_MODULE_PATHS.items()
            },
            "artifacts": {
                allocator: {"path": f"target/{host_id}/{allocator}", "sha256": str(((index + allocator_index + 2) % 9) + 1) * 64}
                for allocator_index, allocator in enumerate(inputs.ALLOCATORS)
            },
        }
        observed_hosts[host_id] = _pin(f"hosts/{host_id}.json", str(index + 5))

    capacity_templates: list[dict] = []
    condition_intensities: list[dict] = []
    for host in spec["hosts"]:
        host_id = host["host_id"]
        for index, cell in enumerate(spec["cells"], 1):
            workload, profile = cell["workload"], cell["profile"]
            calibration_id = f"capacity-{host_id}-{workload}-{profile}"
            capacity_templates.append({
                "host_id": host_id,
                "workload": workload,
                "profile": profile,
                "calibration_id": calibration_id,
                "calibrator": {"allocator": "allocatbelt", "executor": "bounded"},
                "request_template": _pin(f"templates/{host_id}/{workload}-{profile}-request.json", str((index % 9) + 1)),
                "context_template": _pin(f"templates/{host_id}/{workload}-{profile}-context.json", str(((index + 1) % 9) + 1)),
            })
            schedule = {
                "seed": 20261013 + index,
                "duration_seconds": 30,
                "sample_interval_ms": 100,
                "startup_deadline_seconds": 10,
                "total_deadline_seconds": 50,
                "term_deadline_seconds": 2,
                "kill_deadline_seconds": 2,
                "minimum_overlap_seconds": 30,
                "startup_ready_windows": 2,
                "cpu_duty_basis_points": 7000,
                "pressure_cpu_affinity": [0],
                "application_cpu_affinity": [0],
                "disk_bytes_per_second": 1_048_576,
                "scratch_file_bytes": 65_536,
                "network_requests_per_second": 100,
                "network_payload_bytes": 256,
            }
            pressure_thresholds = {
                "cpu_busy_min_basis_points": 3500,
                "disk_write_min_bytes_per_second": 200_000,
                "disk_queue_or_stall_min_microseconds": 10,
                "loopback_requests_min_per_second": 25,
                "loopback_latency_p99_max_nanoseconds": 100_000,
                "loopback_tx_min_bytes_per_second": 5000,
                "loopback_rx_min_bytes_per_second": 5000,
            }
            readiness_thresholds = {
                "minimum_overlap_seconds": 30,
                "minimum_ready_samples": 300,
                "maximum_sample_gap_ms": 200,
            }
            key = {
                "host_id": host_id, "workload": workload, "profile": profile,
                "calibration_id": calibration_id,
            }
            condition_id = f"condition-{host_id}-{workload}-{profile}"
            pressure_calibration_id = f"pressure-{host_id}-{workload}-{profile}"
            condition_intensities.append({
                "host_id": host_id,
                "workload": workload,
                "profile": profile,
                "condition_id": condition_id,
                "capacity_key": key,
                "pressure_calibration_id": pressure_calibration_id,
                "condition": _pin(f"conditions/{host_id}/{workload}-{profile}.json", str((index % 9) + 1)),
                "readiness_threshold_rule": inputs.SOURCE5_PRESSURE_READINESS_RULE,
                "readiness_thresholds": readiness_thresholds,
                "pressure_thresholds": pressure_thresholds,
                "schedule": schedule,
            })
    return {
        "core": core,
        "source_pins": source_pins,
        "observed_hosts": observed_hosts,
        "capacity_templates": capacity_templates,
        "condition_intensities": condition_intensities,
    }, spec


class Source5PreparationInputTests(unittest.TestCase):
    def test_build_pins_full_pre_spec_matrix_and_keeps_all_eligibility_false(self) -> None:
        fixture, _spec = preparation_fixture()
        with tempfile.TemporaryDirectory(prefix="source5-preparation-inputs-") as temporary:
            output = Path(temporary) / "preparation.json"
            result = inputs.build_preparation_intent(
                fixture["core"], fixture["source_pins"], fixture["observed_hosts"],
                fixture["capacity_templates"], fixture["condition_intensities"], output,
            )
            value = inputs.json.loads(output.read_text(encoding="utf-8"))
        checked = inputs.validate_preparation_intent(value)
        self.assertEqual(result["semantic_sha256"], value["preparation_sha256"])
        self.assertEqual(checked["capacity_template_count"], 45)
        self.assertEqual(checked["condition_intensity_count"], 45)
        self.assertEqual([item["template_index"] for item in value["capacity_templates"]], list(range(45)))
        self.assertEqual(len({item["run_id"] for item in value["capacity_templates"]}), 45)
        self.assertEqual(len({item["prospective_nonce"] for item in value["capacity_templates"]}), 45)
        self.assertTrue(all(value is False for value in value["eligibility"].values()))

    def test_resource_budget_is_separate_caller_frozen_and_bound_to_v1_intent(self) -> None:
        self.assertEqual(
            capacity_stage.PREPARATION_FIXED_PAIR_R4_WALKER_SHA256,
            hashlib.sha256((SCRIPT_DIR / "application-fixed-pair.py").read_bytes()).hexdigest(),
        )
        fixture, _spec = preparation_fixture()
        with tempfile.TemporaryDirectory(prefix="source5-preparation-budget-") as temporary:
            input_root = Path(temporary)
            preparation_path = input_root / "preparation.json"
            inputs.build_preparation_intent(
                fixture["core"], fixture["source_pins"], fixture["observed_hosts"],
                fixture["capacity_templates"], fixture["condition_intensities"],
                preparation_path,
            )
            preparation_raw = preparation_path.read_bytes()
            preparation = inputs.json.loads(preparation_raw)
            preparation_pin = {
                "path": str(preparation_path),
                "raw_sha256": inputs._sha256(preparation_raw),
                "semantic_sha256": preparation["preparation_sha256"],
            }
            host_id = preparation["core"]["hosts"][0]["host_id"]
            original_deadline = preparation["core"]["deadlines"]["process_seconds"]
            ceilings = {
                "maximum_job_output_bytes": 1_073_741_824,
                "maximum_job_output_inodes": 1024,
                "maximum_generation_bytes": 2_147_483_648,
                "maximum_generation_inodes": 8192,
                "maximum_tmpdir_bytes": 1_073_741_824,
                "maximum_tmpdir_inodes": 4096,
                "maximum_trace_file_bytes": 536_870_912,
                "durable_receipt_reserve_bytes": 1_048_576,
                "durable_receipt_reserve_inodes": 8,
                "minimum_free_bytes": 2_147_483_648,
                "minimum_free_inodes": 10_000,
                "monitor_sample_interval_milliseconds": 100,
                "process_deadline_seconds": original_deadline,
            }
            budget = inputs.build_preparation_resource_budget(
                preparation, preparation_pin, host_id, ceilings,
            )
            budget_path = input_root / "resource-budget.json"
            budget_raw = inputs._canonical(budget)
            budget_path.write_bytes(budget_raw)
            verified = inputs.validate_preparation_resource_budget(
                inputs.json.loads(budget_raw), preparation, preparation_pin,
            )
        self.assertEqual(budget["schema"], inputs.SOURCE5_PREPARATION_RESOURCE_BUDGET_SCHEMA)
        self.assertEqual(verified["preparation_raw_sha256"], preparation_pin["raw_sha256"])
        self.assertEqual(verified["preparation_semantic_sha256"], preparation_pin["semantic_sha256"])
        self.assertEqual(
            verified["capacity_preparation_templates_sha256"],
            inputs._sha256(inputs._canonical(preparation["capacity_templates"])),
        )
        self.assertEqual(budget["ceilings"], ceilings)

        mutated = copy.deepcopy(budget)
        mutated["source_manifest"]["raw_sha256"] = "f" * 64
        mutated["resource_budget_sha256"] = inputs._digest_object(mutated, "resource_budget_sha256")
        with self.assertRaisesRegex(inputs.InputError, "SourceV5 manifest differs"):
            inputs.validate_preparation_resource_budget(mutated, preparation, preparation_pin)

        mutated = copy.deepcopy(budget)
        mutated["ceilings"]["maximum_job_output_inodes"] = True
        mutated["resource_budget_sha256"] = inputs._digest_object(mutated, "resource_budget_sha256")
        with self.assertRaisesRegex(inputs.InputError, "finite positive u64"):
            inputs.validate_preparation_resource_budget(mutated, preparation, preparation_pin)

        mutated = copy.deepcopy(budget)
        mutated["ceilings"]["maximum_generation_bytes"] = 1
        mutated["resource_budget_sha256"] = inputs._digest_object(mutated, "resource_budget_sha256")
        with self.assertRaisesRegex(inputs.InputError, "cannot fit"):
            inputs.validate_preparation_resource_budget(mutated, preparation, preparation_pin)

    def test_mutated_protocol_gate_or_completion_flag_is_rejected(self) -> None:
        fixture, _spec = preparation_fixture()
        with tempfile.TemporaryDirectory(prefix="source5-preparation-mutation-") as temporary:
            path = Path(temporary) / "preparation.json"
            inputs.build_preparation_intent(
                fixture["core"], fixture["source_pins"], fixture["observed_hosts"],
                fixture["capacity_templates"], fixture["condition_intensities"], path,
            )
            original = inputs.json.loads(path.read_text(encoding="utf-8"))
        changed = copy.deepcopy(original)
        changed["core"]["protocol"]["allocator_min_capacity_ratio"] = 1.0
        changed["preparation_sha256"] = inputs._digest_object(changed, "preparation_sha256")
        with self.assertRaisesRegex(inputs.InputError, "fixed qualification value"):
            inputs.validate_preparation_intent(changed)
        changed = copy.deepcopy(original)
        changed["eligibility"]["rates_frozen"] = True
        changed["preparation_sha256"] = inputs._digest_object(changed, "preparation_sha256")
        with self.assertRaisesRegex(inputs.InputError, "cannot assert completion"):
            inputs.validate_preparation_intent(changed)

    def test_core_bridge_copies_only_the_frozen_spec_fields(self) -> None:
        _fixture, spec = preparation_fixture()
        spec["schema"] = campaign.SPEC_SCHEMA_V3
        spec["qualification_inputs"] = {"capacity_templates": [], "pressure_conditions": []}
        core = inputs.preparation_core_from_spec(spec)
        self.assertEqual(core["schema"], inputs.SOURCE5_PREPARATION_CORE_SCHEMA)
        self.assertEqual(core["protocol"], spec["protocol"])
        self.assertNotIn("rates", core)
        self.assertNotIn("oracles", core)

    def test_capacity_preparation_schedule_reuses_original_intent_order_and_nonces(self) -> None:
        fixture, _spec = preparation_fixture()
        with tempfile.TemporaryDirectory(prefix="source5-preparation-schedule-") as temporary:
            path = Path(temporary) / "preparation.json"
            inputs.build_preparation_intent(
                fixture["core"], fixture["source_pins"], fixture["observed_hosts"],
                fixture["capacity_templates"], fixture["condition_intensities"], path,
            )
            intent = inputs.json.loads(path.read_text(encoding="utf-8"))
        intent["preparation_raw_sha256"] = "a" * 64
        host_id = intent["core"]["hosts"][1]["host_id"]
        jobs = capacity_stage.derive_capacity_preparation_jobs(intent, host_id)
        expected = [item for item in intent["capacity_templates"] if item["host_id"] == host_id]
        self.assertEqual(len(jobs), 15)
        self.assertEqual([job["template_index"] for job in jobs], [item["template_index"] for item in expected])
        self.assertEqual([job["run_id"] for job in jobs], [item["run_id"] for item in expected])
        self.assertEqual([job["nonce"] for job in jobs], [item["prospective_nonce"] for item in expected])
        self.assertTrue(all(job["nonce_instantiation"]["schema"] == capacity_stage.PREPARATION_NONCE_SCHEMA for job in jobs))

    def test_capacity_bundle_pin_preserves_exact_producer_raw_bytes(self) -> None:
        preparation = load_script(
            SCRIPT_DIR / "application-source5-input-preparation.py",
            "source5_preparation_bundle_pin_test_target",
        )
        entry = {
            "capacity_key": {"host_id": "host-1", "workload": "cpu", "profile": "steady", "calibration_id": "cal-cpu"},
            "request": {"path": "/private/job/request.json", "sha256": "1" * 64},
            "artifact": {"path": "/private/job/application-byte-capacity.tsv", "sha256": "2" * 64},
            "receipt": {"path": "/private/job/capacity-receipt.json", "sha256": "3" * 64},
        }
        source = {"path": "/inputs/source-host-1.json", "raw_sha256": "4" * 64}
        pin = preparation.capacity_bundle_pin(entry, source)
        self.assertEqual(pin["schema"], preparation.CAPACITY_BUNDLE_PIN_SCHEMA)
        self.assertEqual(pin["artifact"], {"path": entry["artifact"]["path"], "raw_sha256": "2" * 64})
        self.assertEqual(pin["source_manifest"], source)

    def test_static_host_replay_uses_the_original_frozen_observation(self) -> None:
        _fixture, spec = preparation_fixture()
        host = spec["hosts"][0]
        observed = {
            "schema": capacity_stage.HOST_CONTEXT_SCHEMA,
            "host_id": host["host_id"],
            "boot_id_sha256": "a" * 64,
            "controls_sha256": host["host_fingerprint_sha256"],
            "controls": host["controls"],
            "kernel_release": host["controls"]["kernel_release"],
            "cpu_model": host["controls"]["cpu_model"],
            "cpu_affinity": list(range(8)),
            "network_namespace_inode": 72141,
        }
        replay = capacity_stage._verify_observed_host_static(observed, host, host["host_id"])
        self.assertEqual(replay["boot_id_sha256"], observed["boot_id_sha256"])
        self.assertEqual(replay["cpu_affinity"], list(range(8)))
        self.assertEqual(replay["network_namespace_inode"], 72141)
        changed = copy.deepcopy(observed)
        changed["cpu_affinity"].pop()
        with self.assertRaisesRegex(capacity_stage.CapacityStageError, "CPU affinity"):
            capacity_stage._verify_observed_host_static(changed, host, host["host_id"])

    def test_offline_path_map_requires_sorted_identity_copy_roots(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-evidence-path-map-") as temporary:
            root = Path(temporary)
            source = root / "source"
            inputs_root = root / "inputs"
            source.mkdir()
            inputs_root.mkdir()
            mapping = {
                "schema": capacity_stage.EVIDENCE_PATH_MAP_SCHEMA,
                "entries": [
                    {"origin": str(inputs_root), "local": str(inputs_root)},
                    {"origin": str(source), "local": str(source)},
                ],
            }
            # Lexical order is part of the closed reader contract.
            mapping["entries"].sort(key=lambda row: row["origin"])
            parsed = capacity_stage._validate_evidence_path_map(mapping)
            self.assertEqual({str(origin) for origin, _local in parsed}, {str(source), str(inputs_root)})
            translated = copy.deepcopy(mapping)
            translated["entries"][0]["local"] = str(source)
            with self.assertRaisesRegex(
                    capacity_stage.CapacityStageError,
                    "preserve every original absolute path",
            ):
                capacity_stage._validate_evidence_path_map(translated)

    def test_captured_module_exec_ignores_replaced_source_and_conflicting_cache(self) -> None:
        preparation = load_script(
            SCRIPT_DIR / "application-source5-input-preparation.py",
            "source5_preparation_captured_module_test_target",
        )
        with tempfile.TemporaryDirectory(prefix="source5-captured-module-") as temporary:
            root = Path(temporary)
            path = root / "captured-helper.py"
            path.write_text("VALUE = 'disk-before-capture'\n", encoding="utf-8")
            raw = b"VALUE = 'captured-inventory-bytes'\n"
            cache = root / "__pycache__"
            cache.mkdir(mode=0o700)
            (cache / "captured-helper.cpython-311.pyc").write_bytes(b"conflicting cached code")
            path.write_text("VALUE = 'replaced-after-capture'\n", encoding="utf-8")
            module = preparation._execute_captured_module(raw, path, "loader_identity_fixture")
        self.assertEqual(module.VALUE, "captured-inventory-bytes")
        self.assertEqual(module.__file__, str(path))
        self.assertIs(__import__("sys").modules[module.__name__], module)

    def test_typed_source_capture_rejects_replaced_regular_bytes(self) -> None:
        preparation = load_script(
            SCRIPT_DIR / "application-source5-input-preparation.py",
            "source5_preparation_typed_capture_test_target",
        )
        with tempfile.TemporaryDirectory(prefix="source5-typed-source-") as temporary:
            root = Path(temporary)
            path = root / "scripts" / "typed-helper.py"
            path.parent.mkdir(mode=0o700)
            original = b"VALUE = 1\n"
            path.write_bytes(original)
            path.chmod(0o644)
            record = {
                "path": "scripts/typed-helper.py", "kind": "file", "mode": "100644",
                "sha256": preparation._sha256(original), "size": len(original),
            }
            source = {"source": {"files": [record]}}
            captured, captured_path, checked = preparation._capture_typed_source_file(
                source, root, "scripts/typed-helper.py", "typed helper", preparation._sha256(original),
            )
            self.assertEqual((captured, captured_path, checked), (original, path, record))
            path.write_bytes(b"VALUE = 2\n")
            with self.assertRaisesRegex(preparation.PreparationError, "bytes, size, or mode"):
                preparation._capture_typed_source_file(
                    source, root, "scripts/typed-helper.py", "typed helper", preparation._sha256(original),
                )

    def test_completion_replay_reconstructs_original_host_and_pair_pins(self) -> None:
        preparation = load_script(
            SCRIPT_DIR / "application-source5-input-preparation.py",
            "source5_preparation_completion_pin_test_target",
        )
        evidence_map = {
            "schema": capacity_stage.EVIDENCE_PATH_MAP_SCHEMA,
            "entries": [{"origin": "/private/source", "local": "/private/source"}],
        }
        completion = {
            "capacity_preparations": [], "pressure_calibrations": [], "pilots": [], "oracles": [],
        }
        for index in range(3):
            host = f"host-{index + 1}"
            completion["capacity_preparations"].append({
                "host_id": host,
                "completion": {"path": f"/private/{host}/capacity.json", "raw_sha256": str(index + 1) * 64},
                "host_verification": {"path": f"/private/{host}/verified.json", "raw_sha256": str(index + 2) * 64,
                                      "receipt_sha256": str(index + 3) * 64},
                "evidence_path_map": evidence_map,
                "completion_sha256": "4" * 64, "ledger": {},
                "capacity_preparation_templates_sha256": "5" * 64, "entries": [],
            })
            for ordinal in range(15):
                pair_index = index * 15 + ordinal
                completion["pressure_calibrations"].append({
                    "host_id": host, "condition_id": f"condition-{host}-{ordinal}",
                    "pressure_calibration_id": f"pressure-{host}-{ordinal}",
                    "capacity_key": {"host_id": host, "workload": "cpu", "profile": "steady",
                                     "calibration_id": f"capacity-{host}-{ordinal}"},
                    "condition_pin": {"path": f"/private/{host}/condition-{ordinal}.json", "raw_sha256": "6" * 64},
                    "context_policy_pin": {"path": f"/private/{host}/policy-{ordinal}.json", "raw_sha256": "7" * 64},
                    "calibration_pin": {"path": f"/private/{host}/calibration-{ordinal}.json", "raw_sha256": "8" * 64},
                    "calibration_receipt_pin": {"path": f"/private/{host}/scope-{ordinal}.json", "raw_sha256": "9" * 64,
                                                 "scope_sha256": "a" * 64},
                    "observed_host_pin": {"path": f"/private/{host}/observed.json", "raw_sha256": "b" * 64},
                    "capacity_bundle_pin": {"schema": "bundle", "capacity_key": {}, "source_manifest": {},
                                            "request": {}, "artifact": {}, "receipt": {}},
                    "evidence_path_map": evidence_map,
                    "preparation_condition": {}, "readiness_threshold_rule": "rule",
                    "readiness_thresholds": {}, "pressure_thresholds": {}, "context_policy": {},
                    "calibration": {}, "receipt": {}, "scope_receipt": {}, "context_policy_sha256": "c" * 64,
                })
            fixed_pair_evidence = []
            for ordinal in range(360):
                fixed_pair_evidence.append({
                    "host_id": host, "run_id": f"run-{host}-{ordinal}", "family": "cpu",
                    "profile": "steady", "allocator": "allocatbelt", "ordinal": ordinal + 1,
                    "overlay": {"path": f"/private/{host}/overlay-{ordinal}.json", "raw_sha256": "d" * 64},
                    "receipt": {"path": f"/private/{host}/pair-{ordinal}.json", "raw_sha256": "e" * 64},
                    "host_verification": {"path": f"/private/{host}/host-{ordinal}.json", "raw_sha256": "a" * 64,
                                          "host_verification_sha256": "b" * 64},
                    "evidence_path_map": evidence_map,
                    "raw_pair_sha256": "f" * 64,
                })
            prepared_host_binding_body = {
                "schema": "allocatbelt.application-source5-fixed-pair-host-binding.v1",
                "host_id": host,
                "fixed_spec_host_pin": {"path": f"/private/{host}/spec-host.json", "raw_sha256": "1" * 64},
                "prepared_host_context_pin": {"path": f"/private/{host}/observed.json", "raw_sha256": "b" * 64},
                "spec_host_semantic_sha256": "2" * 64,
                "boot_id_sha256": "3" * 64, "kernel_release": "Linux-fixture",
                "controls_sha256": "4" * 64, "process_affinity": [0],
                "network_namespace_inode": 77,
            }
            prepared_host_binding = {
                **prepared_host_binding_body,
                "binding_sha256": hashlib.sha256(preparation._canonical(prepared_host_binding_body)).hexdigest(),
            }
            for pair in fixed_pair_evidence:
                pair["prepared_host_binding_sha256"] = prepared_host_binding["binding_sha256"]
            completion["pilots"].append({
                "host_id": host,
                "campaign_artifacts_root": f"/private/{host}/oracles",
                "prepared_host_binding": prepared_host_binding,
                "manifest": {"path": f"/private/{host}/pilot.json", "raw_sha256": "1" * 64},
                "semantic_sha256": "2" * 64,
                "initial_spec": {"path": f"/private/{host}/initial-spec.json", "raw_sha256": "3" * 64,
                                 "semantic_sha256": "4" * 64},
                "initial_plan": {"path": f"/private/{host}/initial-plan.json", "raw_sha256": "5" * 64,
                                 "semantic_sha256": "6" * 64},
                "spec_preregistration_sha256": "7" * 64, "fixed_pair_count": 360,
                "fixed_pair_evidence": fixed_pair_evidence,
                "fixed_pair_evidence_sha256": "8" * 64, "replay_raw_sha256": "9" * 64,
            })
            completion["oracles"].append({
                "host_id": host,
                "manifest": {"path": f"/private/{host}/oracle-manifest.json", "raw_sha256": "a" * 64},
                "artifact_root": f"/private/{host}/oracles", "semantic_sha256": "b" * 64,
                "source_manifest_semantic_sha256": "c" * 64, "preregistration_sha256": "d" * 64,
                "oracle_count": 120, "oracles": [],
            })
        replay = preparation._prepared_input_replay_arguments(completion)
        self.assertEqual(len(replay["capacity_completion_pins"]), 3)
        self.assertEqual(len(replay["pressure_calibration_pins"]), 45)
        self.assertEqual(len(replay["pilot_pins"]), 3)
        self.assertEqual(len(replay["pilot_pins"][0]["verified_fixed_records"]), 360)
        self.assertEqual(replay["pilot_pins"][0]["campaign_artifacts_root"], "/private/host-1/oracles")
        self.assertEqual(replay["pilot_pins"][0]["prepared_host_binding"]["host_id"], "host-1")
        self.assertEqual(replay["pilot_pins"][0]["verified_fixed_records"][0]["host_verification"]["raw_sha256"], "a" * 64)
        self.assertEqual(len(replay["oracle_pins"]), 3)
        self.assertEqual(replay["pilot_pins"][0]["verified_fixed_records"][0]["overlay"]["sha256"], "d" * 64)
        self.assertEqual(replay["capacity_completion_pins"][0]["completion_pin"]["raw_sha256"], "1" * 64)

        with tempfile.TemporaryDirectory(prefix="source5-public-completion-replay-") as temporary:
            root = Path(temporary)
            input_root = root / "inputs"
            input_root.mkdir(mode=0o700)
            preparation_path = input_root / "preparation.json"
            spec_path = input_root / "final-spec.json"
            plan_path = input_root / "final-plan.json"
            for path in (preparation_path, spec_path, plan_path):
                path.write_bytes(b"{}\n")
            preparation_sha = hashlib.sha256(preparation_path.read_bytes()).hexdigest()
            spec_sha = hashlib.sha256(spec_path.read_bytes()).hexdigest()
            plan_sha = hashlib.sha256(plan_path.read_bytes()).hexdigest()
            completion_value = {
                "schema": preparation.PREPARED_COMPLETION_SCHEMA,
                "complete": True, "qualification_eligible": False, "campaign_id": "campaign-fixture",
                "preparation": {"path": str(preparation_path), "raw_sha256": preparation_sha,
                                "semantic_sha256": "a" * 64},
                "final_spec": {"path": str(spec_path), "raw_sha256": spec_sha,
                               "semantic_sha256": "b" * 64, "preregistration_sha256": "c" * 64},
                "final_plan": {"path": str(plan_path), "raw_sha256": plan_sha, "semantic_sha256": "d" * 64},
                "source_manifests": {},
                "capacity_preparations": completion["capacity_preparations"],
                "pressure_calibrations": completion["pressure_calibrations"],
                "pilots": completion["pilots"], "oracles": completion["oracles"],
                "filled_slots": {"capacity_evidence": [], "pressure_calibrations": [], "rates": [], "oracles": []},
                "ledger_heads": [],
            }
            completion_body = dict(completion_value)
            completion_value["completion_sha256"] = hashlib.sha256(
                preparation._canonical(completion_body),
            ).hexdigest()
            completion_path = input_root / "prepared-inputs-completion.json"
            completion_raw = preparation._canonical(completion_value)
            completion_path.write_bytes(completion_raw)
            completion_raw_sha = hashlib.sha256(completion_raw).hexdigest()
            provenance = {
                "schema": "allocatbelt.application-source5-prepared-inputs-provenance.v1",
                "preparation_pin": {"path": str(preparation_path), "raw_sha256": preparation_sha},
                "final_spec_pin": {"path": str(spec_path), "raw_sha256": spec_sha},
                "final_plan_pin": {"path": str(plan_path), "raw_sha256": plan_sha},
            }
            expected_replay = {
                "replayed_completion": completion_value,
                "raw_sha256": completion_raw_sha,
                "semantic_sha256": completion_value["completion_sha256"],
                "path": str(completion_path),
            }
            completion_pin = {
                "path": str(completion_path), "raw_sha256": completion_raw_sha,
                "semantic_sha256": completion_value["completion_sha256"],
            }
            with patch.object(preparation, "complete_prepared_inputs", return_value=expected_replay) as replay_call:
                verified = preparation.verify_prepared_inputs_completion(
                    completion_pin, provenance, preparation.SOURCE_ROOT, input_root,
                )
            self.assertEqual(verified, completion_value)
            self.assertEqual(replay_call.call_args.kwargs, {"write_completion": False})

            substituted = copy.deepcopy(completion_value)
            substituted["filled_slots"]["rates"] = [{"arrivals_per_second": 999}]
            with patch.object(preparation, "complete_prepared_inputs", return_value={
                **expected_replay, "replayed_completion": substituted,
            }):
                with self.assertRaisesRegex(preparation.PreparationError, "differs from deterministic replay"):
                    preparation.verify_prepared_inputs_completion(
                        completion_pin, provenance, preparation.SOURCE_ROOT, input_root,
                    )

            bounded = copy.deepcopy(completion_value)
            bounded["schema"] = preparation.PREPARED_BOUNDED_COMPLETION_SCHEMA
            bounded_budgets = {}
            for index, record in enumerate(bounded["capacity_preparations"]):
                host = record["host_id"]
                budget_pin = {
                    "path": f"/private/{host}/resource-budget.json",
                    "raw_sha256": str(index + 3) * 64,
                    "semantic_sha256": str(index + 4) * 64,
                }
                bounded_budgets[host] = budget_pin
                record["resource_budget"] = budget_pin
                record["resource_monitor"] = {
                    "schema": "allocatbelt.application-capacity-preparation-resource-monitor.v1",
                    "fixed_pair_sha256": "f" * 64,
                    "report_count": 30,
                    "high_water": {}, "final_usage": {},
                }
            bounded["resource_budgets"] = bounded_budgets
            bounded_body = {key: value for key, value in bounded.items()
                            if key != "completion_sha256"}
            bounded["completion_sha256"] = hashlib.sha256(
                preparation._canonical(bounded_body),
            ).hexdigest()
            bounded_raw = preparation._canonical(bounded)
            completion_path.write_bytes(bounded_raw)
            bounded_raw_sha = hashlib.sha256(bounded_raw).hexdigest()
            bounded_pin = {
                "path": str(completion_path), "raw_sha256": bounded_raw_sha,
                "semantic_sha256": bounded["completion_sha256"],
            }
            bounded_replay = {
                "replayed_completion": bounded,
                "raw_sha256": bounded_raw_sha,
                "semantic_sha256": bounded["completion_sha256"],
                "path": str(completion_path),
            }
            with patch.object(preparation, "complete_prepared_inputs",
                              return_value=bounded_replay) as bounded_call:
                checked = preparation.verify_prepared_inputs_completion(
                    bounded_pin, provenance, preparation.SOURCE_ROOT, input_root,
                )
            self.assertEqual(checked, bounded)
            self.assertEqual(bounded_call.call_args.kwargs, {
                "write_completion": False,
                "resource_budget_pins": bounded_budgets,
            })
            replay_args = preparation._prepared_input_replay_arguments(bounded)
            self.assertEqual(replay_args["resource_budget_pins"], bounded_budgets)
            self.assertEqual(
                replay_args["capacity_completion_pins"][0]["resource_budget_pin"],
                bounded_budgets["host-1"],
            )

            altered_budget = copy.deepcopy(bounded)
            altered_budget["resource_budgets"]["host-2"]["raw_sha256"] = "e" * 64
            altered_budget["capacity_preparations"][1]["resource_budget"]["raw_sha256"] = "e" * 64
            altered_body = {key: value for key, value in altered_budget.items()
                            if key != "completion_sha256"}
            altered_budget["completion_sha256"] = hashlib.sha256(
                preparation._canonical(altered_body),
            ).hexdigest()
            altered_raw = preparation._canonical(altered_budget)
            completion_path.write_bytes(altered_raw)
            altered_pin = {
                "path": str(completion_path),
                "raw_sha256": hashlib.sha256(altered_raw).hexdigest(),
                "semantic_sha256": altered_budget["completion_sha256"],
            }
            with patch.object(preparation, "complete_prepared_inputs",
                              return_value=bounded_replay):
                with self.assertRaisesRegex(preparation.PreparationError,
                                            "differs from deterministic replay"):
                    preparation.verify_prepared_inputs_completion(
                        altered_pin, provenance, preparation.SOURCE_ROOT, input_root,
                    )

            omitted_budget = copy.deepcopy(bounded)
            omitted_budget["resource_budgets"].pop("host-1")
            omitted_body = {key: value for key, value in omitted_budget.items()
                            if key != "completion_sha256"}
            omitted_budget["completion_sha256"] = hashlib.sha256(
                preparation._canonical(omitted_body),
            ).hexdigest()
            omitted_raw = preparation._canonical(omitted_budget)
            completion_path.write_bytes(omitted_raw)
            omitted_pin = {
                "path": str(completion_path),
                "raw_sha256": hashlib.sha256(omitted_raw).hexdigest(),
                "semantic_sha256": omitted_budget["completion_sha256"],
            }
            with self.assertRaisesRegex(preparation.PreparationError,
                                        "bounded budget map differs"):
                preparation.verify_prepared_inputs_completion(
                    omitted_pin, provenance, preparation.SOURCE_ROOT, input_root,
                )

    def test_public_exporter_derives_rate_matrix_after_each_original_job_replay(self) -> None:
        preparation = load_script(
            SCRIPT_DIR / "application-source5-input-preparation.py",
            "source5_preparation_public_export_test_target",
        )
        spec, _legacy_sources = legacy_fixtures.spec_fixture()
        host_ids = [host["host_id"] for host in spec["hosts"]]
        selected_host = host_ids[0]
        spec["schema"] = campaign.SPEC_SCHEMA_V3
        spec["rates"] = []
        spec["oracles"] = []
        spec["source_manifests"] = [
            {"host_id": host_id, "relative_path": f"sources/{host_id}.json", "sha256": str(index + 1) * 64}
            for index, host_id in enumerate(host_ids)
        ]
        core = {"campaign_id": spec["campaign_id"]}

        with tempfile.TemporaryDirectory(prefix="source5-public-pilot-export-") as temporary:
            root = Path(temporary)
            input_root = root / "inputs"
            artifact_root = root / "campaign-artifacts"
            input_root.mkdir(mode=0o700)
            artifact_root.mkdir(mode=0o700)
            source_root = SCRIPT_DIR.parent
            fixed_path = source_root / "scripts" / "application-fixed-pair.py"
            fixed_raw = fixed_path.read_bytes()
            fixed_sha = hashlib.sha256(fixed_raw).hexdigest()
            fixed_info = fixed_path.stat()
            fixed_entry = {
                "path": "scripts/application-fixed-pair.py", "kind": "file",
                "mode": f"{stat.S_IFMT(fixed_info.st_mode) | stat.S_IMODE(fixed_info.st_mode):06o}", "sha256": fixed_sha,
                "size": len(fixed_raw),
            }
            sources = {}
            source_pins = {}
            for index, host_id in enumerate(host_ids):
                semantic_sha = str(index + 1) * 64
                tree_sha = str(index + 4) * 64
                sources[host_id] = {
                    "manifest_sha256": semantic_sha,
                    "source": {"source_tree_sha256": tree_sha, "files": [fixed_entry]},
                    "runtime_readback_validator": {"sha256": "c" * 64},
                }
                source_pins[host_id] = {
                    "manifest": {
                        "relative_path": f"sources/{host_id}.json",
                        "raw_sha256": str(index + 7) * 64,
                        "semantic_sha256": semantic_sha,
                        "source_tree_sha256": tree_sha,
                    },
                    "modules": {"fixed_pair": {"path": fixed_entry["path"], "sha256": fixed_sha}},
                }

            cells = [(family, profile, workload) for family, workload, profile in sorted(campaign.expected_profile_cells())]
            spec["cells"] = [
                {"family": family, "profile": profile, "workload": workload}
                for family, profile, workload in cells
            ]
            jobs = []
            for family, profile, workload in cells:
                for allocator in campaign.ALLOCATORS:
                    for ordinal in range(1, 7):
                        jobs.append({
                            "host_id": selected_host, "family": family, "profile": profile,
                            "workload": workload, "mode": "capacity", "comparison_kind": "capacity_pilot",
                            "allocator": allocator, "ordinal": ordinal,
                            "run_id": f"{selected_host}-{family}-{profile}-{allocator}-{ordinal:02d}",
                        })
            spec_path = input_root / "initial-spec.json"
            spec_raw = campaign.canonical_bytes(spec)
            spec_path.write_bytes(spec_raw)
            plan = {
                "spec_sha256": campaign.digest_object(spec),
                "jobs": {"exploration": jobs}, "plan_sha256": "plan-semantic-fixture",
            }
            plan_path = input_root / "initial-plan.json"
            plan_raw = campaign.canonical_bytes(plan)
            plan_path.write_bytes(plan_raw)

            preparation_value = {
                "core": core,
                "source_pins": source_pins,
            }
            input_adapter = types.SimpleNamespace(preparation_core_from_spec=lambda _spec: core)
            record_values = []
            replayed_run_ids = []
            for index, job in enumerate(jobs):
                overlay_path = input_root / f"overlay-{index:03d}.json"
                overlay = {
                    "schema": "allocatbelt.application-fixed-pair-execution-overlay.v1",
                    "job": {"value": job},
                }
                overlay_raw = campaign.canonical_bytes(overlay)
                overlay_path.write_bytes(overlay_raw)
                receipt_path = input_root / f"receipt-{index:03d}.json"
                metrics = [
                    {"executor": executor, "allocator": job["allocator"], "mode": "capacity",
                     "completed_on_time": 100, "completed_late": 0}
                    for executor in ("bounded", "tokio")
                ]
                rows = [
                    {"executor": executor, "allocator": job["allocator"], "mode": "capacity",
                     "completed_on_time": "100", "completed_late": "0", "attempted": "100",
                     "admitted": "100", "rejected_full": "0", "rejected_resource": "0"}
                    for executor in ("bounded", "tokio")
                ]
                receipt = {
                    "receipt_sha256": str((index % 9) + 1) * 64,
                    "run_id": job["run_id"], "host_id": selected_host, "status": "valid_pair",
                    "process_metrics": metrics, "process_rows": rows,
                }
                receipt_path.write_bytes(campaign.canonical_bytes(receipt))
                overlay_sha = hashlib.sha256(overlay_raw).hexdigest()
                receipt_sha = hashlib.sha256(campaign.canonical_bytes(receipt)).hexdigest()
                host_pin = {
                    "path": str(input_root / f"host-verification-{index:03d}.json"),
                    "raw_sha256": "a" * 64, "host_verification_sha256": "b" * 64,
                }
                record_values.append({
                    "overlay": {"path": str(overlay_path), "sha256": overlay_sha},
                    "receipt": {"path": str(receipt_path), "sha256": receipt_sha},
                    "host_verification": host_pin,
                    "evidence_path_map": {"schema": "fixture-only", "entries": []},
                })
                replayed_run_ids.append(job["run_id"])

            def execute_captured(raw: bytes, path: Path, name: str) -> types.ModuleType:
                if name == "fixed_pair":
                    def offline_verify(overlay_pin, receipt_pin, host_pin, _path_map):
                        return {
                            "verified": True, "status": "valid_pair", "qualification_eligible": False,
                            "receipt_sha256": receipt_pin["sha256"],
                            "host_verification_sha256": host_pin["host_verification_sha256"],
                        }
                    fake = types.ModuleType("synthetic_fixed_pair_replay")
                    fake.verify_fixed_pair_overlay_offline = offline_verify
                    return fake
                return preparation._execute_captured_module(raw, path, name)

            with (
                patch.object(preparation, "read_preparation_intent",
                             return_value=(preparation_value, sources, campaign, input_adapter)),
                patch.object(preparation, "_verify_pilot_overlay_generation"),
                patch.object(preparation, "_execute_captured_module", side_effect=execute_captured),
                patch.object(campaign, "campaign_inputs_source_sha256", return_value="d" * 64),
                patch.object(campaign, "verify_plan"),
                patch.object(campaign, "build_jobs", return_value=jobs),
                patch.object(campaign, "source_inventory_module", return_value=types.SimpleNamespace()),
            ):
                host_binding_body = {
                    "schema": preparation.PREPARED_FIXED_HOST_BINDING_SCHEMA,
                    "host_id": selected_host,
                    "fixed_spec_host_pin": {"path": str(input_root / "spec-host.json"), "raw_sha256": "1" * 64},
                    "prepared_host_context_pin": {"path": str(input_root / "prepared-host.json"), "raw_sha256": "2" * 64},
                    "spec_host_semantic_sha256": "3" * 64,
                    "boot_id_sha256": "4" * 64, "kernel_release": "Linux-fixture",
                    "controls_sha256": "5" * 64, "process_affinity": [0],
                    "network_namespace_inode": 77,
                }
                host_binding = {
                    **host_binding_body,
                    "binding_sha256": hashlib.sha256(preparation._canonical(host_binding_body)).hexdigest(),
                }
                pilot_pins = {
                    "preparation": {"path": str(input_root / "preparation.json"), "sha256": "e" * 64},
                    "spec": {"path": str(spec_path), "sha256": hashlib.sha256(spec_raw).hexdigest()},
                    "plan": {"path": str(plan_path), "sha256": hashlib.sha256(plan_raw).hexdigest()},
                    "source_root": str(source_root), "input_root": str(input_root),
                    "campaign_artifacts_root": str(artifact_root),
                    "prepared_host_binding": host_binding, "output": None,
                }
                output = preparation.export_capacity_pilot(
                    pilot_pins, record_values, selected_host,
                )

            self.assertEqual(output["pair_count"], 360)
            self.assertEqual(output["context_allocator_count"], 15 * len(campaign.ALLOCATORS))
            self.assertEqual([row["run_id"] for row in output["pair_evidence"]], replayed_run_ids)
            self.assertEqual(output["prepared_host_binding"], host_binding)
            self.assertTrue(all(row["prepared_host_binding_sha256"] == host_binding["binding_sha256"]
                                for row in output["pair_evidence"]))
            self.assertEqual(output["path"], pilot_pins["output"])
            self.assertFalse(any(path.name.startswith(".capacity-pilot-replay-") for path in input_root.iterdir()))

    def test_pilot_export_rejects_other_valid_spec_or_plan_generation(self) -> None:
        preparation = load_script(
            SCRIPT_DIR / "application-source5-input-preparation.py",
            "source5_preparation_generation_binding_test_target",
        )
        with tempfile.TemporaryDirectory(prefix="source5-generation-binding-") as temporary:
            root = Path(temporary)
            spec_path = root / "initial-spec.json"
            later_spec_path = root / "filled-spec.json"
            plan_path = root / "initial-plan.json"
            later_plan_path = root / "later-plan.json"
            source_root = root / "source"
            input_root = root / "input"
            artifact_root = root / "artifacts"
            for path in (source_root, input_root, artifact_root):
                path.mkdir(mode=0o700)
            original_spec = {"schema": campaign.SPEC_SCHEMA_V3, "campaign_id": "same-job-ids", "rates": [], "oracles": []}
            filled_spec = {**original_spec, "rates": [{"host_id": "host-a", "arrivals_per_second": 7}],
                           "oracles": [{"host_id": "host-a", "sha256": "f" * 64}]}
            original_plan_body = {
                "schema": campaign.PLAN_SCHEMA_V3,
                "spec_sha256": campaign.digest_object(original_spec),
                "source_manifests": {"host-a": "1" * 64},
                "jobs": {"exploration": [{"run_id": "same-job-id"}]},
            }
            later_plan_body = {**original_plan_body, "source_manifests": {"host-a": "2" * 64}}
            original_plan = {
                **original_plan_body,
                "plan_sha256": campaign.digest_object(original_plan_body, "plan_sha256"),
            }
            later_plan = {
                **later_plan_body,
                "plan_sha256": campaign.digest_object(later_plan_body, "plan_sha256"),
            }
            spec_raw = campaign.canonical_bytes(original_spec)
            filled_spec_raw = campaign.canonical_bytes(filled_spec)
            plan_raw = campaign.canonical_bytes(original_plan)
            later_plan_raw = campaign.canonical_bytes(later_plan)
            _ = (spec_path, later_spec_path, plan_path, later_plan_path)
            expected_job = {"run_id": "same-job-id", "host_id": "host-a"}

            def overlay_for(selected_spec: dict, selected_spec_path: Path, selected_spec_raw: bytes,
                            selected_plan: dict, selected_plan_path: Path, selected_plan_raw: bytes) -> dict:
                return {
                    "schema": "allocatbelt.application-fixed-pair-execution-overlay.v1",
                    "campaign_id": "same-job-ids", "host_id": "host-a",
                    "spec": {"pin": {"path": str(selected_spec_path), "sha256": hashlib.sha256(selected_spec_raw).hexdigest()},
                             "semantic_sha256": campaign.digest_object(selected_spec)},
                    "plan": {"pin": {"path": str(selected_plan_path), "sha256": hashlib.sha256(selected_plan_raw).hexdigest()},
                             "semantic_sha256": selected_plan["plan_sha256"]},
                    "sources": {}, "execution_source": {}, "modules": {},
                    "job": {"value": expected_job}, "runtime_bindings": {}, "members": [],
                    "deadlines": {}, "artifact_budgets": {}, "output_root": str(root / "pair"),
                }

            with self.assertRaisesRegex(preparation.PreparationError, "another original SpecV3"):
                preparation._verify_pilot_overlay_generation(
                    overlay_for(filled_spec, later_spec_path, filled_spec_raw, original_plan, plan_path, plan_raw),
                    expected_job, original_spec, spec_path, hashlib.sha256(spec_raw).hexdigest(),
                    original_plan, plan_path, hashlib.sha256(plan_raw).hexdigest(), {}, {},
                    source_root, input_root, campaign, object(), object(), object(), object(), artifact_root,
                )
            with self.assertRaisesRegex(preparation.PreparationError, "another original PlanV3"):
                preparation._verify_pilot_overlay_generation(
                    overlay_for(original_spec, spec_path, spec_raw, later_plan, later_plan_path, later_plan_raw),
                    expected_job, original_spec, spec_path, hashlib.sha256(spec_raw).hexdigest(),
                    original_plan, plan_path, hashlib.sha256(plan_raw).hexdigest(), {}, {},
                    source_root, input_root, campaign, object(), object(), object(), object(), artifact_root,
                )

    def test_pilot_overlay_generation_accepts_exact_original_pins(self) -> None:
        preparation = load_script(
            SCRIPT_DIR / "application-source5-input-preparation.py",
            "source5_preparation_generation_positive_test_target",
        )
        fixed = load_script(SCRIPT_DIR / "application-fixed-pair.py", "source5_generation_fixed_pair_fixture")
        inventory_schema = "allocatbelt.application-source-inventory.v1"
        digest_records = lambda records: hashlib.sha256(campaign.canonical_bytes({
            "schema": inventory_schema, "entries": records,
        })).hexdigest()

        with tempfile.TemporaryDirectory(prefix="source5-generation-positive-") as temporary:
            root = Path(temporary)
            source_root, input_root, artifact_root = root / "source", root / "input", root / "artifacts"
            source_root.mkdir(mode=0o700)
            input_root.mkdir(mode=0o700)
            (input_root / "sources").mkdir(mode=0o700)
            artifact_root.mkdir(mode=0o700)
            entries = []
            for relative in fixed.MODULE_PATHS.values():
                module_path = SCRIPT_DIR.parent / relative
                info = module_path.stat()
                module_raw = module_path.read_bytes()
                entries.append({
                    "path": relative, "kind": "file",
                    "mode": f"{stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode):06o}",
                    "sha256": hashlib.sha256(module_raw).hexdigest(), "size": len(module_raw),
                })
            entries.sort(key=lambda value: value["path"].encode("utf-8"))
            tree_sha = digest_records(entries)
            spec, _legacy_sources = legacy_fixtures.spec_fixture()
            host_ids = [host["host_id"] for host in spec["hosts"]]
            selected_host = host_ids[0]
            selected_spec_host = next(host for host in spec["hosts"] if host["host_id"] == selected_host)
            sources = {}
            source_pins = {}
            source_manifest_refs = []
            overlay_manifest_pins = {}
            for index, host_id in enumerate(host_ids):
                source_body = {
                    "schema": "allocatbelt.application-source-manifest.v5",
                    "source": {"git_commit": "a" * 40, "source_tree_sha256": tree_sha,
                               "files": entries},
                    "build": {"host_id": host_id, "build_inputs": str(index)},
                }
                semantic_sha = campaign.digest_object(source_body)
                source_value = {**source_body, "manifest_sha256": semantic_sha}
                source_path = input_root / "sources" / f"{host_id}.json"
                source_raw = campaign.canonical_bytes(source_value)
                source_path.write_bytes(source_raw)
                raw_sha = hashlib.sha256(source_raw).hexdigest()
                sources[host_id] = source_value
                source_pins[host_id] = {
                    "manifest": {
                        "relative_path": f"sources/{host_id}.json", "raw_sha256": raw_sha,
                        "semantic_sha256": semantic_sha, "source_tree_sha256": tree_sha,
                    },
                    "modules": {"fixed_pair": {
                        "path": "scripts/application-fixed-pair.py",
                        "sha256": next(item["sha256"] for item in entries
                                        if item["path"] == "scripts/application-fixed-pair.py"),
                    }},
                    "artifacts": {},
                }
                source_manifest_refs.append({
                    "host_id": host_id, "relative_path": f"sources/{host_id}.json",
                    "sha256": semantic_sha,
                })
                overlay_manifest_pins[host_id] = {
                    "pin": {"path": str(source_path), "sha256": raw_sha},
                    "manifest_sha256": semantic_sha,
                }

            spec["schema"] = campaign.SPEC_SCHEMA_V3
            spec["source_manifests"] = source_manifest_refs
            controls = selected_spec_host["controls"]
            prepared_observed = {
                "schema": "allocatbelt.application-capacity-host-context.v1",
                "host_id": selected_host, "boot_id_sha256": "b" * 64,
                "controls_sha256": selected_spec_host["host_fingerprint_sha256"],
                "controls": controls, "kernel_release": controls["kernel_release"],
                "cpu_model": controls["cpu_model"], "cpu_affinity": [0],
                "network_namespace_inode": 77,
            }
            prepared_observed_path = input_root / "capacity-host-context.json"
            prepared_observed_raw = campaign.canonical_bytes(prepared_observed)
            prepared_observed_path.write_bytes(prepared_observed_raw)
            prepared_observed_sha = hashlib.sha256(prepared_observed_raw).hexdigest()
            spec_observed_path = input_root / "spec-host-record.json"
            spec_observed_raw = campaign.canonical_bytes(selected_spec_host)
            spec_observed_path.write_bytes(spec_observed_raw)
            host_fingerprint = selected_spec_host["host_fingerprint_sha256"]
            spec_path = input_root / "initial-spec.json"
            spec_raw = campaign.canonical_bytes(spec)
            spec_path.write_bytes(spec_raw)
            spec_sha = hashlib.sha256(spec_raw).hexdigest()
            planned_bindings = [{"process": "bounded"}, {"process": "tokio"}]
            expected_job = {
                "host_id": selected_host, "run_id": "generation-run", "family": "cpu",
                "workload": "cpu", "profile": "steady", "mode": "capacity",
                "comparison_kind": "capacity_pilot", "ordinal": 1, "allocator": "allocatbelt",
            }
            plan_body = {"campaign_id": spec["campaign_id"], "runtime_process_bindings": {
                expected_job["run_id"]: planned_bindings,
            }}
            plan = {**plan_body, "plan_sha256": campaign.digest_object(plan_body, "plan_sha256")}
            plan_path = input_root / "initial-plan.json"
            plan_raw = campaign.canonical_bytes(plan)
            plan_path.write_bytes(plan_raw)
            plan_sha = hashlib.sha256(plan_raw).hexdigest()
            runtime_value = {"manifest_sha256": "e" * 64, "processes": planned_bindings}
            runtime_pin_path = str(root / "pair" / ".fixed-pair-runtime-bindings.json")
            overlay = {
                "schema": "allocatbelt.application-fixed-pair-execution-overlay.v1",
                "campaign_id": spec["campaign_id"], "host_id": selected_host,
                "spec": {"pin": {"path": str(spec_path), "sha256": spec_sha},
                         "semantic_sha256": campaign.digest_object(spec)},
                "plan": {"pin": {"path": str(plan_path), "sha256": plan_sha},
                         "semantic_sha256": plan["plan_sha256"]},
                "sources": {
                    "manifests": overlay_manifest_pins,
                    "selected": {
                        "host_id": selected_host, "root": str(source_root),
                        "git_commit": sources[selected_host]["source"]["git_commit"],
                        "source_tree_sha256": tree_sha,
                        "build_sha256": campaign.digest_object(sources[selected_host]["build"]),
                    },
                    "campaign_artifacts_root": str(artifact_root),
                    "observed_host": {
                        "pin": {"path": str(spec_observed_path),
                                "sha256": hashlib.sha256(spec_observed_raw).hexdigest()},
                        "host_fingerprint_sha256": host_fingerprint,
                        "controls_sha256": prepared_observed["controls_sha256"],
                        "process_affinity": list(prepared_observed["cpu_affinity"]),
                        "network_namespace_inode": prepared_observed["network_namespace_inode"],
                    },
                    "historical_runner_sha256": spec["runner_sha256"], "output_mount": {},
                },
                "execution_source": {
                    "git_commit": "a" * 40, "source_tree_sha256": tree_sha,
                    "inventory_schema": inventory_schema, "inventory": entries,
                    "inventory_sha256": digest_records(entries),
                },
                "modules": {
                    name: {"path": relative, "sha256": next(item["sha256"] for item in entries
                                                              if item["path"] == relative)}
                    for name, relative in fixed.MODULE_PATHS.items()
                },
                "job": {"value": expected_job, "sha256": hashlib.sha256(
                    campaign.canonical_bytes(expected_job),
                ).hexdigest()},
                "runtime_bindings": {
                    "pin": {"path": runtime_pin_path, "sha256": "d" * 64},
                    "manifest_sha256": runtime_value["manifest_sha256"],
                    "plan_entry_sha256": hashlib.sha256(campaign.canonical_bytes(planned_bindings)).hexdigest(),
                    "value": runtime_value,
                },
                "members": [], "deadlines": {}, "artifact_budgets": {}, "output_root": str(root / "pair"),
            }
            preparation_value = {
                "source_pins": source_pins,
                "observed_hosts": {selected_host: {
                    "relative_path": "capacity-host-context.json", "raw_sha256": prepared_observed_sha,
                }},
            }
            fake_inventory = types.SimpleNamespace(SCHEMA=inventory_schema, digest_records=digest_records)
            prepared_host_binding = preparation._prepared_fixed_host_binding_for_overlay(
                preparation_value, spec, overlay, inputs, input_root, selected_host,
            )
            with patch.object(campaign, "runtime_binding_manifest_value", return_value=runtime_value):
                preparation._verify_pilot_overlay_generation(
                    overlay, expected_job, spec, spec_path, spec_sha, plan, plan_path, plan_sha,
                    preparation_value, sources, source_root, input_root, campaign, inputs,
                    fake_inventory, fixed, prepared_host_binding, artifact_root,
                )

    def test_public_prepared_host_binding_keeps_spec_and_capacity_context_pins_distinct(self) -> None:
        preparation = load_script(
            SCRIPT_DIR / "application-source5-input-preparation.py",
            "source5_preparation_dual_host_binding_test_target",
        )
        source5_fixtures = load_script(
            SCRIPT_DIR / "test-application-campaign-inputs.py",
            "source5_preparation_dual_host_v3_fixtures",
        )
        spec, sources = source5_fixtures.spec_v3_fixture()
        campaign_v3 = source5_fixtures.campaign
        inputs_v3 = source5_fixtures.inputs
        host_ids = [host["host_id"] for host in spec["hosts"]]
        host_id = host_ids[0]
        host = next(item for item in spec["hosts"] if item["host_id"] == host_id)
        controls = host["controls"]
        context = {
            "schema": "allocatbelt.application-capacity-host-context.v1",
            "host_id": host_id, "boot_id_sha256": "a" * 64,
            "controls_sha256": host["host_fingerprint_sha256"], "controls": controls,
            "kernel_release": controls["kernel_release"], "cpu_model": controls["cpu_model"],
            "cpu_affinity": [0], "network_namespace_inode": 77,
        }
        with tempfile.TemporaryDirectory(prefix="source5-dual-host-binding-") as temporary:
            root = Path(temporary)
            input_root = root / "inputs"
            input_root.mkdir(mode=0o700)
            spec_host_path = input_root / "spec-host-record.json"
            spec_host_raw = campaign_v3.canonical_bytes(host)
            spec_host_path.write_bytes(spec_host_raw)
            context_path = input_root / "capacity-host-context.json"
            context_raw = campaign_v3.canonical_bytes(context)
            context_path.write_bytes(context_raw)
            spec_path = input_root / "initial-spec.json"
            spec_raw = campaign_v3.canonical_bytes(spec)
            spec_path.write_bytes(spec_raw)
            source_pins = {}
            for index, selected in enumerate(host_ids, 1):
                source = sources[selected]
                spec_ref = next(item for item in spec["source_manifests"] if item["host_id"] == selected)
                source_pins[selected] = {
                    "manifest": {"relative_path": spec_ref["relative_path"],
                                 "raw_sha256": str(index + 3) * 64,
                                 "semantic_sha256": source["manifest_sha256"],
                                 "source_tree_sha256": source["source"]["source_tree_sha256"]},
                }
            observed_hosts = {host_id: {
                "relative_path": "capacity-host-context.json",
                "raw_sha256": hashlib.sha256(context_raw).hexdigest(),
            }}
            core = inputs_v3.preparation_core_from_spec(spec)
            preparation_value = {"core": core, "source_pins": source_pins,
                                 "observed_hosts": observed_hosts}
            overlay = {
                "schema": "allocatbelt.application-fixed-pair-execution-overlay.v1",
                "campaign_id": spec["campaign_id"], "host_id": host_id,
                "spec": {"pin": {"path": str(spec_path), "sha256": hashlib.sha256(spec_raw).hexdigest()},
                         "semantic_sha256": campaign_v3.digest_object(spec)},
                "plan": {"pin": {"path": str(root / "plan.json"), "sha256": "e" * 64},
                         "semantic_sha256": "f" * 64},
                "sources": {
                    "manifests": {},
                    "selected": {"host_id": host_id, "root": str(SCRIPT_DIR.parent),
                                 "git_commit": "a" * 40, "source_tree_sha256": "c" * 64,
                                 "build_sha256": "d" * 64},
                    "campaign_artifacts_root": str(root / "artifacts"),
                    "observed_host": {
                        "pin": {"path": str(spec_host_path),
                                "sha256": hashlib.sha256(spec_host_raw).hexdigest()},
                        "host_fingerprint_sha256": host["host_fingerprint_sha256"],
                        "controls_sha256": context["controls_sha256"],
                        "process_affinity": [0], "network_namespace_inode": 77,
                    },
                    "historical_runner_sha256": spec["runner_sha256"], "output_mount": {},
                },
                "execution_source": {}, "modules": {}, "job": {}, "runtime_bindings": {},
                "members": [], "deadlines": {}, "artifact_budgets": {},
                "output_root": str(root / "fixed-pair-output"),
            }
            overlay_path = input_root / "fixed-overlay.json"
            overlay_raw = campaign_v3.canonical_bytes(overlay)
            overlay_path.write_bytes(overlay_raw)
            source_root = SCRIPT_DIR.parent
            prep_pin = {"path": str(input_root / "preparation.json"), "sha256": "b" * 64}
            spec_pin = {"path": str(spec_path), "sha256": hashlib.sha256(spec_raw).hexdigest()}
            overlay_pin = {"path": str(overlay_path), "sha256": hashlib.sha256(overlay_raw).hexdigest()}
            with patch.object(preparation, "read_preparation_intent",
                              return_value=(preparation_value, sources, campaign_v3, inputs_v3)):
                binding = preparation.build_prepared_host_binding(
                    prep_pin, spec_pin, overlay_pin, source_root, input_root, host_id,
                )
            self.assertEqual(binding["schema"], preparation.PREPARED_FIXED_HOST_BINDING_SCHEMA)
            self.assertEqual(binding["fixed_spec_host_pin"], {
                "path": str(spec_host_path), "raw_sha256": hashlib.sha256(spec_host_raw).hexdigest(),
            })
            self.assertEqual(binding["prepared_host_context_pin"], {
                "path": str(context_path), "raw_sha256": hashlib.sha256(context_raw).hexdigest(),
            })
            self.assertEqual(binding["process_affinity"], [0])
            self.assertEqual(binding["network_namespace_inode"], 77)

            for pin_field in ("fixed_spec_host_pin", "prepared_host_context_pin"):
                malformed = copy.deepcopy(binding)
                malformed[pin_field]["raw_sha256"] = "0" * 63
                malformed_body = {key: value for key, value in malformed.items()
                                  if key != "binding_sha256"}
                malformed["binding_sha256"] = hashlib.sha256(
                    preparation._canonical(malformed_body),
                ).hexdigest()
                with self.subTest(pin_field=pin_field), self.assertRaisesRegex(
                    preparation.PreparationError, "malformed pins or host facts",
                ):
                    preparation._validate_prepared_fixed_host_binding(malformed)

            changed_spec_host = copy.deepcopy(host)
            changed_spec_host["controls"]["kernel_release"] = "Linux-other"
            changed_spec_host_raw = campaign.canonical_bytes(changed_spec_host)
            changed_spec_host_path = input_root / "other-spec-host-record.json"
            changed_spec_host_path.write_bytes(changed_spec_host_raw)
            overlay["sources"]["observed_host"]["pin"] = {
                "path": str(changed_spec_host_path),
                "sha256": hashlib.sha256(changed_spec_host_raw).hexdigest(),
            }
            overlay_raw = campaign.canonical_bytes(overlay)
            overlay_path.write_bytes(overlay_raw)
            overlay_pin = {"path": str(overlay_path), "sha256": hashlib.sha256(overlay_raw).hexdigest()}
            with patch.object(preparation, "read_preparation_intent",
                              return_value=(preparation_value, sources, campaign_v3, inputs_v3)):
                with self.assertRaisesRegex(
                        preparation.PreparationError,
                        "fixed Spec host record differs from the canonical selected SpecV3 host"):
                    preparation.build_prepared_host_binding(
                        prep_pin, spec_pin, overlay_pin, source_root, input_root, host_id,
                    )

            changed_context = {**context, "cpu_affinity": [1]}
            changed_context_raw = campaign.canonical_bytes(changed_context)
            context_path.write_bytes(changed_context_raw)
            preparation_value["observed_hosts"][host_id]["raw_sha256"] = hashlib.sha256(changed_context_raw).hexdigest()
            overlay["sources"]["observed_host"]["pin"] = {
                "path": str(spec_host_path), "sha256": hashlib.sha256(spec_host_raw).hexdigest(),
            }
            overlay_raw = campaign.canonical_bytes(overlay)
            overlay_path.write_bytes(overlay_raw)
            overlay_pin = {"path": str(overlay_path), "sha256": hashlib.sha256(overlay_raw).hexdigest()}
            with patch.object(preparation, "read_preparation_intent",
                              return_value=(preparation_value, sources, campaign_v3, inputs_v3)):
                with self.assertRaisesRegex(
                        preparation.PreparationError,
                        "fixed overlay and prepared capacity context differ on host identity/controls"):
                    preparation.build_prepared_host_binding(
                        prep_pin, spec_pin, overlay_pin, source_root, input_root, host_id,
                    )


class MaterializedPreparedHostBindingTests(unittest.TestCase):
    """Use synthetic Spec/Source fixtures without fabricating an overlay or host fact."""

    def _fixture(self, root: Path):
        preparation = load_script(
            SCRIPT_DIR / "application-source5-input-preparation.py",
            "source5_materialized_host_binding_target",
        )
        source_fixtures = load_script(
            SCRIPT_DIR / "test-application-campaign-inputs.py",
            "source5_materialized_host_binding_source_fixtures",
        )
        spec, sources = source_fixtures.spec_v3_fixture()
        campaign_v3 = source_fixtures.campaign
        inputs_v3 = source_fixtures.inputs
        host_id = spec["hosts"][0]["host_id"]
        input_root = root / "inputs"
        input_root.mkdir(mode=0o700)
        source_root = root / "source"
        source_root.mkdir(mode=0o700)
        spec_path = input_root / "initial-spec.json"
        spec_raw = campaign_v3.canonical_bytes(spec)
        spec_path.write_bytes(spec_raw)
        spec_path.chmod(0o600)

        selected_host = next(item for item in spec["hosts"]
                             if item["host_id"] == host_id)
        controls = selected_host["controls"]
        observed = {
            "schema": "allocatbelt.application-capacity-host-context.v1",
            "host_id": host_id, "boot_id_sha256": "a" * 64,
            "controls_sha256": selected_host["host_fingerprint_sha256"],
            "controls": controls, "kernel_release": controls["kernel_release"],
            "cpu_model": controls["cpu_model"], "cpu_affinity": [0],
            "network_namespace_inode": 77,
        }
        observed_path = input_root / "capacity-host-context.json"
        observed_raw = campaign_v3.canonical_bytes(observed)
        observed_path.write_bytes(observed_raw)
        observed_path.chmod(0o600)

        source_pins = {}
        for selected in spec["hosts"]:
            selected_id = selected["host_id"]
            source = sources[selected_id]
            source_ref = next(row for row in spec["source_manifests"]
                              if row["host_id"] == selected_id)
            source_pins[selected_id] = {"manifest": {
                "relative_path": source_ref["relative_path"],
                "raw_sha256": hashlib.sha256(
                    campaign_v3.canonical_bytes(source),
                ).hexdigest(),
                "semantic_sha256": source_ref["sha256"],
                "source_tree_sha256": source["source"]["source_tree_sha256"],
            }}
        preparation_value = {
            "core": inputs_v3.preparation_core_from_spec(spec),
            "source_pins": source_pins,
            "observed_hosts": {host_id: {
                "relative_path": "capacity-host-context.json",
                "raw_sha256": hashlib.sha256(observed_raw).hexdigest(),
            }},
        }
        preparation_pin = {
            "path": str(input_root / "preparation.json"),
            "sha256": "b" * 64,
        }
        spec_pin = {
            "path": str(spec_path),
            "sha256": hashlib.sha256(spec_raw).hexdigest(),
        }
        return (preparation, preparation_value, sources, campaign_v3,
                inputs_v3, preparation_pin, spec_pin, source_root,
                input_root, host_id, spec)

    def _read_preparation(self, fixture):
        preparation, value, sources, campaign_v3, inputs_v3 = fixture[:5]
        return patch.object(
            preparation, "read_preparation_intent",
            return_value=(value, sources, campaign_v3, inputs_v3),
        )

    def _materialize(self, fixture):
        preparation, _, _, _, _, preparation_pin, spec_pin, source_root, \
            input_root, host_id, _spec = fixture
        with self._read_preparation(fixture):
            return preparation.materialize_prepared_host_binding(
                preparation_pin, spec_pin, source_root, input_root, host_id,
            )

    def _verify(self, fixture):
        preparation, _, _, _, _, preparation_pin, spec_pin, source_root, \
            input_root, host_id, _spec = fixture
        with self._read_preparation(fixture):
            return preparation.verify_prepared_host_binding(
                preparation_pin, spec_pin, source_root, input_root, host_id,
            )

    def test_materializer_and_readonly_verifier_share_the_existing_binding(self):
        with tempfile.TemporaryDirectory(prefix="source5-spec-host-materializer-") as temp:
            fixture = self._fixture(Path(temp))
            preparation, _, _, campaign_v3, _, _, _, _, input_root, host_id, spec = fixture
            result = self._materialize(fixture)
            self.assertEqual(set(result), {
                "fixed_spec_host_pin", "prepared_host_binding",
            })
            host = next(item for item in spec["hosts"]
                        if item["host_id"] == host_id)
            expected_raw = campaign_v3.canonical_bytes(host)
            spec_host_pin = result["fixed_spec_host_pin"]
            self.assertEqual(spec_host_pin, {
                "path": str(input_root / "fixed-spec-hosts" / f"{host_id}.json"),
                "raw_sha256": hashlib.sha256(expected_raw).hexdigest(),
            })
            path = Path(spec_host_pin["path"])
            self.assertEqual(path.read_bytes(), expected_raw)
            self.assertEqual(stat.S_IMODE(path.stat(follow_symlinks=False).st_mode), 0o600)
            self.assertEqual(path.stat(follow_symlinks=False).st_nlink, 1)
            self.assertEqual(
                stat.S_IMODE(path.parent.stat(follow_symlinks=False).st_mode),
                0o700,
            )
            binding = result["prepared_host_binding"]
            self.assertEqual(binding["schema"],
                             preparation.PREPARED_FIXED_HOST_BINDING_SCHEMA)
            self.assertEqual(binding["fixed_spec_host_pin"], {
                "path": spec_host_pin["path"],
                "raw_sha256": spec_host_pin["raw_sha256"],
            })
            self.assertEqual(
                binding["prepared_host_context_pin"]["path"],
                str(input_root / "capacity-host-context.json"),
            )
            self.assertEqual(
                binding["prepared_host_context_pin"]["raw_sha256"],
                fixture[1]["observed_hosts"][host_id]["raw_sha256"],
            )
            self.assertNotEqual(
                binding["fixed_spec_host_pin"]["path"],
                binding["prepared_host_context_pin"]["path"],
            )
            self.assertEqual(self._materialize(fixture), result)
            self.assertEqual(self._verify(fixture), result)
            self.assertFalse(any(
                child.name.endswith("overlay.json")
                for child in input_root.iterdir()
            ))

    def test_readonly_verifier_never_creates_a_missing_spec_host_file(self):
        with tempfile.TemporaryDirectory(prefix="source5-spec-host-readonly-") as temp:
            fixture = self._fixture(Path(temp))
            input_root = fixture[8]
            with self.assertRaisesRegex(
                    fixture[0].PreparationError, "is missing"):
                self._verify(fixture)
            self.assertFalse((input_root / "fixed-spec-hosts").exists())

    def test_readonly_verifier_rejects_changed_spec_host_without_restoration(self):
        with tempfile.TemporaryDirectory(prefix="source5-spec-host-mutated-") as temp:
            fixture = self._fixture(Path(temp))
            result = self._materialize(fixture)
            path = Path(result["fixed_spec_host_pin"]["path"])
            altered = b"{}\n"
            path.write_bytes(altered)
            path.chmod(0o600)
            with self.assertRaisesRegex(
                    fixture[0].PreparationError,
                    "differs from its exact raw pin|bytes/mode/link identity differ"):
                self._verify(fixture)
            self.assertEqual(path.read_bytes(), altered)

    def test_materializer_refuses_conflicting_existing_file_without_replacement(self):
        with tempfile.TemporaryDirectory(prefix="source5-spec-host-conflict-") as temp:
            fixture = self._fixture(Path(temp))
            input_root = fixture[8]
            directory = input_root / "fixed-spec-hosts"
            directory.mkdir(mode=0o700)
            wrong = directory / f"{fixture[9]}.json"
            wrong_raw = b"{}\n"
            wrong.write_bytes(wrong_raw)
            wrong.chmod(0o600)
            with self.assertRaisesRegex(
                    fixture[0].PreparationError,
                    "existing immutable artifact differs"):
                self._materialize(fixture)
            self.assertEqual(wrong.read_bytes(), wrong_raw)

    def test_source_validator_rejects_changed_capacity_controls_before_write(self):
        with tempfile.TemporaryDirectory(prefix="source5-spec-host-controls-") as temp:
            fixture = self._fixture(Path(temp))
            preparation, prep_value, _sources, campaign_v3, _inputs_v3 = fixture[:5]
            input_root, host_id = fixture[8], fixture[9]
            observed_row = prep_value["observed_hosts"][host_id]
            observed_path = input_root / observed_row["relative_path"]
            observed = json.loads(observed_path.read_text(encoding="utf-8"))
            observed["controls_sha256"] = "0" * 64
            observed_raw = campaign_v3.canonical_bytes(observed)
            observed_path.write_bytes(observed_raw)
            observed_path.chmod(0o600)
            observed_row["raw_sha256"] = hashlib.sha256(observed_raw).hexdigest()
            with self.assertRaisesRegex(
                    preparation.PreparationError,
                    "does not match its frozen controls"):
                self._materialize(fixture)
            self.assertFalse((input_root / "fixed-spec-hosts").exists())

    def test_materializer_rejects_swapped_parent_without_writing_outside_input_root(self):
        with tempfile.TemporaryDirectory(prefix="source5-spec-host-parent-swap-") as temp:
            root = Path(temp)
            fixture = self._fixture(root)
            preparation, input_root = fixture[0], fixture[8]
            outside = root / "outside"
            outside.mkdir(mode=0o700)
            directory = input_root / "fixed-spec-hosts"
            original_check = preparation._assert_fixed_spec_host_directory_names
            swapped = False

            def swap_before_parent_recheck(*args):
                nonlocal swapped
                if not swapped:
                    displaced = input_root / "fixed-spec-hosts-displaced"
                    directory.rename(displaced)
                    directory.symlink_to(outside, target_is_directory=True)
                    swapped = True
                return original_check(*args)

            with patch.object(
                    preparation, "_assert_fixed_spec_host_directory_names",
                    side_effect=swap_before_parent_recheck):
                with self.assertRaisesRegex(
                        preparation.PreparationError,
                        "fixed Spec host directory was replaced"):
                    self._materialize(fixture)
            self.assertTrue(swapped)
            self.assertEqual(list(outside.iterdir()), [])
            self.assertFalse((outside / f"{fixture[9]}.json").exists())

    def test_materializer_anchors_openat_and_removes_new_inode_after_parent_swap(self):
        with tempfile.TemporaryDirectory(prefix="source5-spec-host-openat-swap-") as temp:
            root = Path(temp)
            fixture = self._fixture(root)
            preparation, input_root, host_id = fixture[0], fixture[8], fixture[9]
            outside = root / "outside"
            outside.mkdir(mode=0o700)
            directory = input_root / "fixed-spec-hosts"
            displaced = input_root / "fixed-spec-hosts-displaced"
            original_open = preparation.os.open
            intercepted = False

            def swap_at_create(file, flags, mode=0o777, *, dir_fd=None):
                nonlocal intercepted
                if (not intercepted and file == f"{host_id}.json" and
                        flags & preparation.os.O_CREAT):
                    self.assertIsNotNone(dir_fd)
                    self.assertTrue(flags & preparation.os.O_EXCL)
                    self.assertTrue(flags & preparation.os.O_NOFOLLOW)
                    directory.rename(displaced)
                    directory.symlink_to(outside, target_is_directory=True)
                    intercepted = True
                if dir_fd is None:
                    return original_open(file, flags, mode)
                return original_open(file, flags, mode, dir_fd=dir_fd)

            with patch.object(preparation.os, "open", side_effect=swap_at_create):
                with self.assertRaisesRegex(
                        preparation.PreparationError,
                        "fixed Spec host directory was replaced"):
                    self._materialize(fixture)
            self.assertTrue(intercepted)
            self.assertTrue(directory.is_symlink())
            self.assertEqual(list(outside.iterdir()), [])
            self.assertEqual(list(displaced.iterdir()), [])


class CapturedCapacityPilotExportTests(unittest.TestCase):
    """Exercise captured pilot IO with synthetic generation/owner boundaries.

    The 360 planned rows and rate validator are the existing public exporter
    fixture. Its Source preparation and fixed-owner numeric replay remain
    explicit stubs. Capture IO is real: exact bytes are staged in private 0400
    files, original output paths are removed, and the adopted fixed-pair reader
    verifies the raw pins and receipt-derived origin file identities. This is
    component plumbing evidence, not an APP, host, or qualification run. The
    strict host envelope and returned owner projection are test-only fixtures,
    not verified host facts.
    """

    _PUBLIC_METHOD = (
        "test_public_exporter_derives_rate_matrix_after_each_original_job_replay"
    )

    def _prepare_records(
        self, preparation, fixed_owner, records, expected_jobs, *,
        fault=None, record_count=None,
    ):
        count = len(records) if record_count is None else record_count
        output_rows = []
        for index, record in enumerate(records[:count]):
            overlay_path = Path(record["overlay"]["path"])
            overlay = preparation.json.loads(overlay_path.read_bytes())
            if fault == "wrong_job" and index == 0:
                overlay["job"]["value"] = expected_jobs[1]
            elif fault == "wrong_host" and index == 0:
                overlay["job"]["value"]["host_id"] = "foreign-host"
            job = overlay["job"]["value"]
            pair_root = overlay_path.parent / f"captured-pair-output-{index:03d}"
            pair_root.mkdir(mode=0o700)
            pair_root.chmod(0o700)
            runtime_path = pair_root / ".fixed-pair-runtime-bindings.json"
            event_path = pair_root / "app-events.jsonl"
            output_bytes = {
                str(runtime_path): f"runtime binding bytes {index}\n".encode(),
                str(event_path): f"captured event bytes {index}\n".encode(),
            }
            facts = {}
            for path_text, raw in output_bytes.items():
                path = Path(path_text)
                path.write_bytes(raw)
                path.chmod(0o600)
                info = path.stat()
                facts[path.relative_to(pair_root).as_posix()] = {
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "size": len(raw), "device": info.st_dev,
                    "inode": info.st_ino, "mode": stat.S_IMODE(info.st_mode),
                }
            overlay.update({
                "host_id": job["host_id"],
                "output_root": str(pair_root), "members": [],
                "runtime_bindings": {"pin": {"path": str(runtime_path)}},
            })
            overlay_raw = campaign.canonical_bytes(overlay)
            overlay_path.write_bytes(overlay_raw)
            overlay_path.chmod(0o600)
            record["overlay"]["sha256"] = hashlib.sha256(overlay_raw).hexdigest()

            old_receipt_path = Path(record["receipt"]["path"])
            receipt = preparation.json.loads(old_receipt_path.read_bytes())
            receipt_body = {
                key: value for key, value in receipt.items()
                if key not in {"receipt_sha256", "output_artifacts"}
            }
            receipt_body["output_artifacts"] = {
                "files": facts,
                "total_bytes": sum(row["size"] for row in facts.values()),
                "maximum_bytes": fixed_owner.MAX_PAIR_OUTPUT_BYTES,
            }
            receipt = {
                **receipt_body,
                "receipt_sha256": hashlib.sha256(
                    campaign.canonical_bytes(receipt_body),
                ).hexdigest(),
            }
            receipt_raw = campaign.canonical_bytes(receipt)
            receipt_path = pair_root / "fixed-pair-execution-receipt.json"
            receipt_path.write_bytes(receipt_raw)
            receipt_path.chmod(0o600)
            old_receipt_path.unlink()
            record["receipt"] = {
                "path": str(receipt_path),
                "sha256": hashlib.sha256(receipt_raw).hexdigest(),
            }

            host_path = Path(record["host_verification"]["path"])
            host_body = {
                "schema": fixed_owner.HOST_VERIFICATION_SCHEMA,
                "strict_verified": True, "qualification_eligible": False,
                "execution_ready": False, "campaign_chronology_complete": False,
                "overlay_raw_sha256": record["overlay"]["sha256"],
                "execution_receipt_raw_sha256": record["receipt"]["sha256"],
                "execution_receipt_sha256": receipt["receipt_sha256"],
                "status": "valid_pair", "run_id": job["run_id"],
            }
            if fault == "swapped_host_receipt" and index == 0:
                host_body["run_id"] = "another-original-run"
            host_doc = {
                **host_body,
                "receipt_sha256": hashlib.sha256(
                    campaign.canonical_bytes(host_body),
                ).hexdigest(),
            }
            host_raw = campaign.canonical_bytes(host_doc)
            host_path.write_bytes(host_raw)
            host_path.chmod(0o600)
            record["host_verification"] = {
                "path": str(host_path),
                "raw_sha256": hashlib.sha256(host_raw).hexdigest(),
                "host_verification_sha256": host_doc["receipt_sha256"],
            }
            output_rows.append({
                "overlay": overlay, "overlay_raw": overlay_raw,
                "receipt": receipt, "receipt_raw": receipt_raw,
                "host": host_doc, "host_raw": host_raw,
                "output_root": pair_root, "output_bytes": output_bytes,
                "run_id": job["run_id"],
            })
        return output_rows

    def _provider(self, preparation, fixed_owner, records, expected_jobs,
                  output_rows, *, fault=None):
        class CaptureProvider:
            def __init__(self):
                self.opened = []
                self.closed = []
                self.active = 0
                self.active_index = None
                self.maximum_active = 0
                self.next_index = 0
                self.fault = fault
                self.output_rows = output_rows
                self.snapshot_fault_index = len(output_rows) - 1
                self.snapshot_fault_origin = (
                    list(output_rows[-1]["output_bytes"])[-1]
                    if output_rows else None
                )

            def open_view(self, job, phase, *, use):
                if self.fault == "provider_exception":
                    raise RuntimeError("injected captured provider failure")
                if phase != "exploration" or use != "capacity_pilot_export":
                    raise AssertionError("captured pilot requested the wrong IO purpose")
                index = self.next_index
                if preparation._canonical(job) != preparation._canonical(expected_jobs[index]):
                    raise AssertionError("captured provider received a nonoriginal job order")
                return self.Window(self, index, job)

            def _reader_type(self):
                base = fixed_owner.CapturedFixedPairArtifactsV1
                provider = self
                if self.fault != "snapshot_exit":
                    return base

                class SnapshotExitReader(base):
                    @contextmanager
                    def open_snapshot(self, origin, label, maximum):
                        with super().open_snapshot(origin, label, maximum) as snapshot:
                            yield snapshot
                            if (provider.active_index == provider.snapshot_fault_index and
                                    str(origin) == provider.snapshot_fault_origin):
                                local = Path(self._references[str(origin)]["path"])
                                before = local.read_bytes()
                                changed = before[:-1] + bytes([before[-1] ^ 1])
                                local.chmod(0o600)
                                local.write_bytes(changed)
                                local.chmod(0o400)

                return SnapshotExitReader

            def _stage_view(self, index):
                record = records[index]
                output = self.output_rows[index]
                overlay_origin = record["overlay"]["path"]
                receipt_origin = record["receipt"]["path"]
                host_origin = record["host_verification"]["path"]
                rows = [
                    (overlay_origin, output["overlay_raw"], "fixed_pair_artifact", None),
                    (receipt_origin, output["receipt_raw"], "component_receipt",
                     output["receipt"]["receipt_sha256"]),
                    (host_origin, output["host_raw"], "fixed_pair_host_receipt",
                     record["host_verification"]["host_verification_sha256"]),
                    *[(path, raw, "normal_app_output", None)
                      for path, raw in output["output_bytes"].items()],
                ]
                scope = tempfile.TemporaryDirectory(
                    prefix="capacity-pilot-capture-window-",
                )
                stage_root = Path(scope.name) / "stage"
                stage_root.mkdir(mode=0o700)
                stage_root.chmod(0o700)
                references = {}
                try:
                    for ref_index, (origin, raw, role, semantic) in enumerate(rows):
                        if self.fault == "missing_host_receipt" and index == 0 and origin == host_origin:
                            continue
                        if (self.fault == "missing_runtime_output" and index == 0 and
                                ".fixed-pair-runtime-bindings.json" in origin):
                            continue
                        local_raw = raw
                        if self.fault == "altered_raw_pin" and index == 0 and origin == overlay_origin:
                            local_raw = raw[:-1] + bytes([raw[-1] ^ 1])
                        local = stage_root / f"{ref_index:06d}"
                        local.write_bytes(local_raw)
                        local.chmod(0o400)
                        references[origin] = {
                            "origin_path": origin, "path": str(local),
                            "role": role, "host_id": output["overlay"]["job"]["value"]["host_id"],
                            "raw_sha256": hashlib.sha256(raw).hexdigest(),
                            "semantic_sha256": semantic,
                            "byte_count": len(local_raw),
                            "maximum_bytes": fixed_owner.MAX_PAIR_OUTPUT_BYTES,
                        }
                        if self.fault == "byte_bound" and index == 0 and role == "normal_app_output":
                            references[origin]["maximum_bytes"] = len(local_raw) - 1
                    if self.fault == "extra_under_root" and index == 0:
                        extra_origin = str(output["output_root"] / "unexpected.json")
                        local = stage_root / f"{len(references):06d}"
                        local.write_bytes(b"unexpected captured pair member")
                        local.chmod(0o400)
                        extra_raw = local.read_bytes()
                        references[extra_origin] = {
                            "origin_path": extra_origin, "path": str(local),
                            "role": "normal_app_output",
                            "host_id": output["overlay"]["job"]["value"]["host_id"],
                            "raw_sha256": hashlib.sha256(extra_raw).hexdigest(),
                            "semantic_sha256": None, "byte_count": len(extra_raw),
                            "maximum_bytes": fixed_owner.MAX_PAIR_OUTPUT_BYTES,
                        }
                    for path_text in [overlay_origin, receipt_origin, host_origin,
                                      *output["output_bytes"]]:
                        path = Path(path_text)
                        if path.exists():
                            path.unlink()
                    return scope, {
                        "stage_root": str(stage_root), "objects": references,
                    }
                except BaseException:
                    scope.cleanup()
                    raise

            class Window:
                def __init__(self, owner, index, job):
                    self.owner = owner
                    self.index = index
                    self.job = job
                    self.scope = None

                def __enter__(self):
                    owner = self.owner
                    if owner.active:
                        raise AssertionError("capacity-pilot read windows overlapped")
                    owner.active = 1
                    owner.active_index = self.index
                    owner.maximum_active = max(owner.maximum_active, owner.active)
                    owner.opened.append(self.job["run_id"])
                    try:
                        self.scope, view = owner._stage_view(self.index)
                        owner.next_index += 1
                        return view
                    except BaseException:
                        owner.active = 0
                        owner.active_index = None
                        raise

                def __exit__(self, exc_type, exc, tb):
                    owner = self.owner
                    owner.closed.append(self.job["run_id"])
                    owner.active = 0
                    owner.active_index = None
                    if self.scope is not None:
                        self.scope.cleanup()
                    if owner.fault == "window_exit_failure" and self.index == 0 and exc_type is None:
                        raise RuntimeError("injected captured window exit failure")
                    return False

        return CaptureProvider()

    def _run_public_exporter(self, *, fault=None, compare=False, complete=False,
                             before_publication=None,
                             before_publication_state=None):
        method = Source5PreparationInputTests.test_public_exporter_derives_rate_matrix_after_each_original_job_replay
        namespace = method.__globals__
        original_loader = namespace["load_script"]
        result = {
            "outputs": [], "pilots": [], "provider": None, "exception": None,
            "preparation": None, "output_path": None,
            "before_publication": before_publication,
        }

        def patched_loader(path, name):
            module = original_loader(path, name)
            if Path(path).name != "application-source5-input-preparation.py":
                return module
            fixed_owner = original_loader(
                Path(path).with_name("application-fixed-pair.py"),
                f"captured_pilot_fixed_owner_{name}",
            )
            result["preparation"] = module
            result["fixed_owner"] = fixed_owner
            real_export = module.export_capacity_pilot

            def export_wrapper(pins, records, selected_host):
                if not compare:
                    output_path = Path(pins["input_root"]) / "must-not-publish-pilot.json"
                    pins["output"] = str(output_path)
                    result["output_path"] = output_path
                    if before_publication_state is not None:
                        before_publication_state["output_path"] = output_path
                expected_jobs = [
                    module.json.loads(Path(row["overlay"]["path"]).read_bytes())["job"]["value"]
                    for row in records
                ]
                if fault == "wrong_order":
                    records[0], records[1] = records[1], records[0]
                    record_count = 2
                elif compare or complete or fault == "snapshot_exit":
                    record_count = len(records)
                else:
                    record_count = 1
                output_rows = self._prepare_records(
                    module, fixed_owner, records, expected_jobs,
                    fault=fault, record_count=record_count,
                )
                result["output_rows"] = output_rows
                if fault == "prepared_binding":
                    pins["prepared_host_binding"] = dict(pins["prepared_host_binding"])
                    pins["prepared_host_binding"]["binding_sha256"] = "0" * 64
                provider = self._provider(
                    module, fixed_owner, records, expected_jobs, output_rows,
                    fault=fault,
                )
                result["provider"] = provider
                if compare:
                    legacy = self._export_once(
                        module, fixed_owner, real_export, pins, records,
                        selected_host, None, result,
                    )
                    captured = self._export_once(
                        module, fixed_owner, real_export, pins, records,
                        selected_host, provider, result,
                        before_publication=before_publication,
                    )
                    result["outputs"] = [legacy, captured]
                    result["captured_result"] = captured
                    return captured
                captured = self._export_once(
                    module, fixed_owner, real_export, pins, records,
                    selected_host, provider, result,
                    before_publication=before_publication,
                )
                result["captured_result"] = captured
                return captured

            module.export_capacity_pilot = export_wrapper
            return module

        with patch.dict(namespace, {"load_script": patched_loader}):
            test_case = Source5PreparationInputTests(self._PUBLIC_METHOD)
            try:
                getattr(test_case, self._PUBLIC_METHOD)()
            except Exception as error:
                result["exception"] = error
        return result

    def _export_once(self, module, fixed_owner, export_fn, pins, records,
                     selected_host, provider, result, *, before_publication=None):
        real_module_type = types.ModuleType

        def module_factory(name):
            if name != "synthetic_fixed_pair_replay":
                return real_module_type(name)
            fake = real_module_type(name)
            reader_type = fixed_owner.CapturedFixedPairArtifactsV1
            if provider is not None and provider.fault == "snapshot_exit":
                capture_provider = provider
                base_reader = reader_type

                class SnapshotExitReader(base_reader):
                    @contextmanager
                    def open_snapshot(self, origin, label, maximum):
                        with super().open_snapshot(origin, label, maximum) as snapshot:
                            yield snapshot
                            if (capture_provider.active_index ==
                                    capture_provider.snapshot_fault_index and
                                    str(origin) ==
                                    capture_provider.snapshot_fault_origin):
                                local = Path(self._references[str(origin)]["path"])
                                before = local.read_bytes()
                                changed = before[:-1] + bytes([before[-1] ^ 1])
                                local.chmod(0o600)
                                local.write_bytes(changed)
                                local.chmod(0o400)

                reader_type = SnapshotExitReader
            fake.CapturedFixedPairArtifactsV1 = reader_type
            fake.CAPTURED_REPLAY_CONTEXT_SCHEMA_V1 = fixed_owner.CAPTURED_REPLAY_CONTEXT_SCHEMA_V1
            fake.RECEIPT_SCHEMA = fixed_owner.RECEIPT_SCHEMA

            def offline_verify(overlay_pin, receipt_pin, host_pin, _path_map):
                return {
                    "verified": True, "status": "valid_pair",
                    "qualification_eligible": False,
                    "receipt_sha256": receipt_pin["sha256"],
                    "host_verification_sha256": host_pin["host_verification_sha256"],
                }

            def captured_verify(overlay_pin, receipt_pin, host_pin,
                                references, stage_root):
                view = fake.CapturedFixedPairArtifactsV1(
                    references, Path(stage_root),
                )
                overlay_raw, overlay_sha = view.read(
                    overlay_pin["path"], "pilot fixture overlay",
                    module.MAX_REQUEST_BYTES,
                )
                receipt_raw, receipt_sha = view.read(
                    receipt_pin["path"], "pilot fixture receipt",
                    module.MAX_REQUEST_BYTES,
                )
                host_raw, host_sha = view.read(
                    host_pin["path"], "pilot fixture host receipt",
                    module.MAX_REQUEST_BYTES,
                )
                if (overlay_sha != overlay_pin["sha256"] or
                        receipt_sha != receipt_pin["sha256"] or
                        host_sha != host_pin["raw_sha256"]):
                    raise fixed_owner.FixedPairError(
                        "captured pilot fixture envelope pin differs",
                    )
                overlay = module.json.loads(overlay_raw)
                receipt = module.json.loads(receipt_raw)
                host = module.json.loads(host_raw)
                host_body = {key: value for key, value in host.items()
                             if key != "receipt_sha256"}
                if (host.get("schema") != fixed_owner.HOST_VERIFICATION_SCHEMA or
                        host.get("run_id") != overlay["job"]["value"]["run_id"] or
                        host.get("receipt_sha256") != fixed_owner.sha256_bytes(
                            fixed_owner.canonical_bytes(host_body),
                        ) or host.get("receipt_sha256") !=
                            host_pin["host_verification_sha256"]):
                    raise fixed_owner.FixedPairError(
                        "captured pilot strict host receipt differs",
                    )
                view.bind_output_inventory(overlay, receipt, host_pin["path"])
                if view.output_tree() != receipt["output_artifacts"]:
                    raise fixed_owner.FixedPairError(
                        "captured pilot output inventory differs",
                    )
                verification = {
                    "schema": fixed_owner.RECEIPT_SCHEMA,
                    "verified": True, "status": "valid_pair",
                    "qualification_eligible": False,
                    "receipt_sha256": receipt_pin["sha256"],
                    "overlay_sha256": overlay_sha,
                    "run_id": overlay["job"]["value"]["run_id"],
                }
                captured_receipt = receipt
                if provider.fault == "receipt_parity" and provider.active_index == 0:
                    captured_receipt = dict(receipt)
                    captured_receipt["status"] = "failed_or_invalid"
                return {
                    "schema": fixed_owner.CAPTURED_REPLAY_CONTEXT_SCHEMA_V1,
                    "verification": verification, "overlay": overlay,
                    "execution_receipt": captured_receipt,
                    "host_verification_pin": host_pin,
                    "full_replay_verified": True,
                    "qualification_eligible": False,
                }

            fake.verify_fixed_pair_overlay_offline = offline_verify
            fake.verify_fixed_pair_overlay_captured_v1 = captured_verify
            return fake

        original_canonical = module._canonical

        def recording_canonical(value, *args, **kwargs):
            raw = original_canonical(value, *args, **kwargs)
            if type(value) is dict and value.get("schema") == module.PILOT_SCHEMA:
                result["pilots"].append(raw)
            return raw

        original_read = module._read_pinned_json
        record_origins = set()
        for row in records:
            for key in ("overlay", "receipt", "host_verification"):
                pin = row.get(key)
                if type(pin) is dict and type(pin.get("path")) is str:
                    record_origins.add(pin["path"])
        for row in result.get("output_rows", []):
            record_origins.update(row["output_bytes"])

        def deny_captured_origin(pin, label, maximum=module.MAX_REQUEST_BYTES):
            if provider is not None and pin.get("path") in record_origins:
                raise AssertionError("captured pilot reopened an original pair output")
            return original_read(pin, label, maximum)

        try:
            with patch.object(types, "ModuleType", side_effect=module_factory), \
                 patch.object(module, "_canonical", side_effect=recording_canonical):
                if provider is None:
                    return export_fn(pins, records, selected_host)
                with patch.object(module, "_read_pinned_json",
                                  side_effect=deny_captured_origin):
                    return export_fn(
                        pins, records, selected_host,
                        captured_read_provider=provider,
                        before_publication=before_publication,
                    )
        finally:
            # Observe the real output before the nested base fixture removes
            # its TemporaryDirectory; post-cleanup absence is not evidence.
            output_path = result.get("output_path")
            if output_path is not None:
                observation = {"parent_exists": output_path.parent.is_dir(),
                               "exists": False, "raw": None}
                try:
                    info = output_path.lstat()
                except FileNotFoundError:
                    pass
                else:
                    self.assertTrue(stat.S_ISREG(info.st_mode))
                    observation["exists"] = True
                    observation["raw"] = output_path.read_bytes()
                    observation["identity"] = (info.st_dev, info.st_ino)
                result["output_observation"] = observation

    def _assert_refusal_before_publication(self, fault, *, runtime_error=False):
        result = self._run_public_exporter(fault=fault)
        error = result["exception"]
        self.assertIsNotNone(error, f"fault {fault} unexpectedly returned a pilot")
        if runtime_error:
            self.assertIsInstance(error, RuntimeError)
        elif fault == "altered_raw_pin":
            self.assertIsInstance(error, result["fixed_owner"].FixedPairError)
        else:
            self.assertIsInstance(error, result["preparation"].PreparationError)
        self.assertIsNotNone(result["output_path"])
        self.assertTrue(result["output_observation"]["parent_exists"])
        self.assertFalse(result["output_observation"]["exists"])
        provider = result["provider"]
        if provider is not None:
            self.assertEqual(provider.active, 0)
            self.assertEqual(provider.opened, provider.closed)

    def test_captured_export_matches_legacy_bytes_and_closes_360_windows(self):
        result = self._run_public_exporter(compare=True)
        self.assertIsNone(result["exception"], str(result["exception"]))
        legacy, captured = result["outputs"]
        self.assertEqual(legacy, captured)
        self.assertEqual(len(result["pilots"]), 2)
        self.assertEqual(result["pilots"][0], result["pilots"][1])
        self.assertEqual(legacy["pair_count"], 360)
        self.assertEqual(len(legacy["pair_evidence"]), 360)
        provider = result["provider"]
        expected = [row["run_id"] for row in captured["pair_evidence"]]
        self.assertEqual(provider.opened, expected)
        self.assertEqual(provider.closed, expected)
        self.assertEqual(provider.maximum_active, 1)
        self.assertEqual(provider.active, 0)
        self.assertNotIn("capacity-pilot-capture-window",
                         result["preparation"]._canonical(captured).decode("ascii"))

    def test_captured_export_rejects_identity_receipt_and_object_faults(self):
        for fault in (
            "wrong_job", "wrong_host", "wrong_order",
            "missing_host_receipt", "swapped_host_receipt",
            "altered_raw_pin", "extra_under_root",
            "missing_runtime_output", "receipt_parity", "byte_bound",
            "prepared_binding",
        ):
            with self.subTest(fault=fault):
                self._assert_refusal_before_publication(fault)

    def test_provider_and_window_exit_errors_are_not_suppressed(self):
        self._assert_refusal_before_publication(
            "provider_exception", runtime_error=True,
        )
        self._assert_refusal_before_publication(
            "window_exit_failure", runtime_error=True,
        )

    def test_final_capture_snapshot_exit_failure_prevents_publication(self):
        result = self._run_public_exporter(fault="snapshot_exit")
        self.assertIsInstance(
            result["exception"], result["preparation"].PreparationError,
        )
        self.assertTrue(result["output_observation"]["parent_exists"])
        self.assertFalse(result["output_observation"]["exists"])
        self.assertEqual(len(result["provider"].opened), 360)
        self.assertEqual(result["provider"].opened, result["provider"].closed)
        self.assertEqual(result["provider"].active, 0)

    def test_before_publication_hook_sees_exact_bytes_after_rate_check(self):
        observations = {}
        ordered = []
        configured_output = {}
        campaign_module = Source5PreparationInputTests.test_public_exporter_derives_rate_matrix_after_each_original_job_replay.__globals__["campaign"]
        original_freeze_rates = campaign_module.freeze_rates

        def recorded_freeze_rates(*args, **kwargs):
            result = original_freeze_rates(*args, **kwargs)
            ordered.append("numeric_validator")
            return result

        def before_publication(raw, prospective):
            ordered.append("before_publication")
            result_path = configured_output["output_path"]
            self.assertEqual(prospective["path"], str(result_path))
            with self.assertRaises(FileNotFoundError):
                result_path.lstat()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), prospective["raw_sha256"])
            self.assertEqual(prospective["pair_count"], 360)
            observations["raw"] = raw
            observations["dto"] = copy.deepcopy(prospective)
            prospective["host_id"] = "mutated-private-copy"
            prospective["pair_evidence"][0]["run_id"] = "mutated-nested-copy"
            return None

        with mock.patch.object(campaign_module, "freeze_rates",
                               side_effect=recorded_freeze_rates):
            result = self._run_public_exporter(
                complete=True, before_publication=before_publication,
                before_publication_state=configured_output,
            )
        self.assertIsNone(result["exception"], str(result["exception"]))
        self.assertEqual(ordered[-2:], ["numeric_validator", "before_publication"])
        self.assertEqual(result["captured_result"]["path"], str(configured_output["output_path"]))
        self.assertTrue(result["output_observation"]["parent_exists"])
        self.assertTrue(result["output_observation"]["exists"])
        self.assertEqual(result["output_observation"]["raw"], observations["raw"])
        self.assertEqual(hashlib.sha256(result["output_observation"]["raw"]).hexdigest(),
                         observations["dto"]["raw_sha256"])
        self.assertEqual(result["captured_result"]["host_id"],
                         result["output_rows"][0]["overlay"]["job"]["value"]["host_id"])
        self.assertNotEqual(result["captured_result"]["pair_evidence"][0]["run_id"],
                            "mutated-nested-copy")
        self.assertEqual(result["provider"].opened, result["provider"].closed)
        self.assertEqual(result["provider"].active, 0)

    def test_hook_exception_or_non_none_return_prevents_publication(self):
        def fail_before_publish(_raw, _prospective):
            raise RuntimeError("prepublication rejected")

        rejected = self._run_public_exporter(
            complete=True, before_publication=fail_before_publish,
        )
        self.assertIsInstance(rejected["exception"], RuntimeError)
        self.assertTrue(rejected["output_observation"]["parent_exists"])
        self.assertFalse(rejected["output_observation"]["exists"])
        self.assertEqual(rejected["provider"].opened, rejected["provider"].closed)

        returned = self._run_public_exporter(
            complete=True,
            before_publication=lambda _raw, _prospective: True,
        )
        self.assertIsInstance(returned["exception"], returned["preparation"].PreparationError)
        self.assertTrue(returned["output_observation"]["parent_exists"])
        self.assertFalse(returned["output_observation"]["exists"])
        self.assertEqual(returned["provider"].opened, returned["provider"].closed)

    def test_noncallable_hook_is_rejected_before_captured_views(self):
        result = self._run_public_exporter(before_publication="not callable")
        self.assertIsInstance(result["exception"], result["preparation"].PreparationError)
        self.assertTrue(result["output_observation"]["parent_exists"])
        self.assertFalse(result["output_observation"]["exists"])
        self.assertEqual(result["provider"].opened, [])
        self.assertEqual(result["provider"].closed, [])

    def test_new_output_inode_is_removed_after_writer_io_failure(self):
        module = load_script(
            SCRIPT_DIR / "application-source5-input-preparation.py",
            "capacity_pilot_writer_cleanup_target",
        )
        with tempfile.TemporaryDirectory(prefix="capacity-pilot-writer-cleanup-") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            destination = root / "pilot.json"
            original_write = os.write
            writes = 0

            def partial_then_fail(fd, raw):
                nonlocal writes
                writes += 1
                if writes == 1:
                    return original_write(fd, raw[: max(1, len(raw) // 3)])
                raise OSError("injected short publication write")

            with mock.patch.object(module.os, "write", side_effect=partial_then_fail):
                with self.assertRaisesRegex(OSError, "injected"):
                    module._write_private_json_new(
                        destination, {"schema": "writer-cleanup"}, root / "source",
                    )
            self.assertFalse(destination.exists())
            self.assertEqual(list(root.iterdir()), [])

    def test_new_output_inode_is_removed_after_readback_failure(self):
        module = load_script(
            SCRIPT_DIR / "application-source5-input-preparation.py",
            "capacity_pilot_writer_readback_cleanup_target",
        )
        with tempfile.TemporaryDirectory(prefix="capacity-pilot-readback-cleanup-") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            destination = root / "pilot.json"
            with mock.patch.object(module.os, "read",
                                   side_effect=OSError("injected readback failure")):
                with self.assertRaisesRegex(OSError, "readback failure"):
                    module._write_private_json_new(
                        destination, {"schema": "writer-readback-cleanup"}, root / "source",
                    )
            self.assertFalse(destination.exists())
            self.assertEqual(list(root.iterdir()), [])

    def test_existing_identical_private_output_is_never_replaced_or_deleted(self):
        module = load_script(
            SCRIPT_DIR / "application-source5-input-preparation.py",
            "capacity_pilot_existing_output_target",
        )
        with tempfile.TemporaryDirectory(prefix="capacity-pilot-existing-output-") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            destination = root / "pilot.json"
            body = {"schema": "existing-identical"}
            raw = module._canonical(body)
            destination.write_bytes(raw)
            destination.chmod(0o600)
            digest = module._write_private_json_new(
                destination, body, root / "source", allow_existing_identical=True,
            )
            self.assertEqual(digest, hashlib.sha256(raw).hexdigest())
            self.assertEqual(destination.read_bytes(), raw)
            with self.assertRaises(module.PreparationError):
                module._write_private_json_new(
                    destination, {"schema": "different"}, root / "source",
                    allow_existing_identical=True,
                )
            self.assertEqual(destination.read_bytes(), raw)


class CapturedCapacityPilotProviderCohortTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.preparation = load_script(
            SCRIPT_DIR / "application-source5-input-preparation.py",
            "captured_capacity_pilot_provider_cohort_target",
        )

    def test_validated_host_provider_selection_survives_caller_map_mutation(self):
        class Provider:
            def open_view(self, *args, **kwargs):
                raise AssertionError("validating provider selection must not open a view")

        hosts = ["host-a", "host-b", "host-c"]
        providers = {host: Provider() for host in hosts}
        selected = self.preparation._capacity_pilot_provider_map(providers, hosts)
        original = providers["host-a"]
        providers["host-a"] = providers["host-b"]
        self.assertIs(selected["host-a"], original)
        self.assertIsNot(selected["host-a"], selected["host-b"])
        with self.assertRaises(TypeError):
            selected["host-a"] = providers["host-b"]

    def test_partial_or_invalid_explicit_cohort_cannot_fall_back_to_origin_reads(self):
        class Provider:
            def open_view(self, *args, **kwargs):
                raise AssertionError("invalid provider cohort must be rejected before IO")

        hosts = ["host-a", "host-b", "host-c"]
        providers = {host: Provider() for host in hosts}
        mutants = [
            {host: value for host, value in providers.items() if host != "host-c"},
            {**providers, "other-host": Provider()},
            {**providers, "host-c": None},
            {**providers, "host-c": types.SimpleNamespace(open_view=False)},
        ]
        for mutant in mutants:
            with self.subTest(keys=tuple(mutant)):
                with self.assertRaises(self.preparation.PreparationError):
                    self.preparation._capacity_pilot_provider_map(mutant, hosts)


class CapacityPilotByteBoundTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.preparation = load_script(
            SCRIPT_DIR / "application-source5-input-preparation.py",
            "capacity_pilot_byte_bound_target",
        )
        cls.source_fixtures = load_script(
            SCRIPT_DIR / "test-application-campaign-inputs.py",
            "capacity_pilot_byte_bound_source_fixtures",
        )

    def test_source_bound_matches_full_15_by_4_by_6_max_width_witness(self):
        spec, _sources = self.source_fixtures.spec_v3_fixture()
        campaign = self.source_fixtures.campaign
        host_id = spec["hosts"][0]["host_id"]
        spec_digest = campaign.preregistration_digest(spec)
        bound = self.preparation.capacity_pilot_maximum_bytes(
            spec, host_id, campaign.ALLOCATORS, spec_digest,
        )
        pairs = []
        maximum = (1 << 64) - 1
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
        witness = {
            "schema": self.preparation.PILOT_SCHEMA,
            "spec_sha256": spec_digest,
            "host_id": host_id,
            "cells": [
                {"family": cell["family"], "profile": cell["profile"],
                 "allocator": allocator, "pairs": pairs}
                for cell in spec["cells"] for allocator in campaign.ALLOCATORS
            ],
        }
        self.assertEqual(len(witness["cells"]), 15 * 4)
        self.assertEqual(sum(len(cell["pairs"]) for cell in witness["cells"]), 15 * 4 * 6)
        self.assertEqual(bound, len(self.preparation._canonical(witness)))

    def test_pilot_bound_rejects_changed_host_cell_or_allocator_cardinality(self):
        spec, _sources = self.source_fixtures.spec_v3_fixture()
        campaign = self.source_fixtures.campaign
        host_id = spec["hosts"][0]["host_id"]
        digest = campaign.preregistration_digest(spec)
        with self.assertRaisesRegex(
                self.preparation.PreparationError, "one known original host"):
            self.preparation.capacity_pilot_maximum_bytes(
                spec, "not-a-host", campaign.ALLOCATORS, digest,
            )
        with self.assertRaisesRegex(
                self.preparation.PreparationError, "four distinct Source allocators"):
            self.preparation.capacity_pilot_maximum_bytes(
                spec, host_id, campaign.ALLOCATORS[:-1], digest,
            )
        changed = {**spec, "cells": spec["cells"][:-1]}
        with self.assertRaisesRegex(
                self.preparation.PreparationError, "fifteen original Spec cells"):
            self.preparation.capacity_pilot_maximum_bytes(
                changed, host_id, campaign.ALLOCATORS, digest,
            )

    def test_exported_unsigned_row_counts_stop_at_u64_before_use(self):
        maximum = (1 << 64) - 1
        row = {"count": maximum}
        self.assertEqual(
            self.preparation._row_uint(row, "count", "test count"), maximum,
        )
        self.assertEqual(
            self.preparation._row_uint(
                {"count": str(maximum)}, "count", "test count",
            ), maximum,
        )
        for value in (maximum + 1, str(maximum + 1), "9" * 21):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                        self.preparation.PreparationError, "64-bit"):
                    self.preparation._row_uint(
                        {"count": value}, "count", "test count",
                    )


if __name__ == "__main__":
    unittest.main()
