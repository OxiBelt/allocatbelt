#!/usr/bin/env python3
"""Schema fixtures for additive pre-Spec Source5 preparation inputs."""

from __future__ import annotations

import copy
import hashlib
import importlib.machinery
import importlib.util
import stat
import tempfile
import types
import unittest
from pathlib import Path
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
                output = preparation.export_capacity_pilot({
                    "preparation": {"path": str(input_root / "preparation.json"), "sha256": "e" * 64},
                    "spec": {"path": str(spec_path), "sha256": hashlib.sha256(spec_raw).hexdigest()},
                    "plan": {"path": str(plan_path), "sha256": hashlib.sha256(plan_raw).hexdigest()},
                    "source_root": str(source_root), "input_root": str(input_root),
                    "campaign_artifacts_root": str(artifact_root),
                    "prepared_host_binding": host_binding, "output": None,
                }, record_values, selected_host)

            self.assertEqual(output["pair_count"], 360)
            self.assertEqual(output["context_allocator_count"], 15 * len(campaign.ALLOCATORS))
            self.assertEqual([row["run_id"] for row in output["pair_evidence"]], replayed_run_ids)
            self.assertEqual(output["prepared_host_binding"], host_binding)
            self.assertTrue(all(row["prepared_host_binding_sha256"] == host_binding["binding_sha256"]
                                for row in output["pair_evidence"]))
            self.assertIsNone(output["path"])
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
                with self.assertRaisesRegex(preparation.PreparationError, "do not share exact host controls/affinity/namespace"):
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
                with self.assertRaisesRegex(preparation.PreparationError, "do not share exact host controls/affinity/namespace"):
                    preparation.build_prepared_host_binding(
                        prep_pin, spec_pin, overlay_pin, source_root, input_root, host_id,
                    )


if __name__ == "__main__":
    unittest.main()
