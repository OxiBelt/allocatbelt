#!/usr/bin/env python3
"""Focused tests for SourceV5 and prospective campaign input bindings."""

from __future__ import annotations

import copy
import importlib.machinery
import importlib.util
import json
from functools import lru_cache
import os
import platform
from pathlib import Path
import tempfile
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
SOURCE_ROOT = SCRIPT_DIR.parent


def load_script(path: Path, name: str):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


campaign = load_script(SCRIPT_DIR / "application-campaign.py", "application_campaign_inputs_tests_campaign")
fixtures = load_script(SCRIPT_DIR / "test-application-campaign.py", "application_campaign_inputs_tests_legacy_fixtures")
inputs = campaign.campaign_inputs_module()


@lru_cache(maxsize=1)
def source_inventory_records() -> list[dict]:
    _tree_sha, records = campaign.source_inventory(SOURCE_ROOT)
    return records


def source_v5_for(host_id: str) -> dict:
    source = fixtures.source_for(host_id)
    records = copy.deepcopy(source_inventory_records())
    by_path = {entry["path"]: entry for entry in records}
    source["schema"] = campaign.SOURCE_SCHEMA_V5
    source["source"]["files"] = records
    source["source"]["source_tree_sha256"] = campaign.source_inventory_module().digest_records(records)
    source["source"]["cargo_lock_sha256"] = by_path["Cargo.lock"]["sha256"]
    source["resource_domain_calibration"]["source"] = {
        key: source["source"][key] for key in ("git_commit", "source_tree_sha256", "cargo_lock_sha256")
    }
    harness = {
        name: {"path": path, "sha256": by_path[path]["sha256"]}
        for name, path in inputs.HARNESS_PATHS.items()
    }
    source["qualification_harness"] = harness
    source["feedback_policy"] = inputs.build_feedback_policy_artifact(SOURCE_ROOT, records, harness)
    source["manifest_sha256"] = campaign.digest_object(source)
    return source


def spec_v3_fixture() -> tuple[dict, dict[str, dict]]:
    spec, legacy_sources = fixtures.spec_fixture()
    sources = {host_id: source_v5_for(host_id) for host_id in legacy_sources}
    spec["schema"] = campaign.SPEC_SCHEMA_V3
    for ref in spec["source_manifests"]:
        ref["sha256"] = sources[ref["host_id"]]["manifest_sha256"]
    spec["runtime_binding"]["feedback_policy_sha256"] = sources["host-1"]["feedback_policy"]["policy_sha256"]
    spec["soak"]["driver_sha256"] = sources["host-1"]["qualification_harness"]["soak_runner"]["sha256"]
    capacity_templates: list[dict] = []
    pressure_conditions: list[dict] = []
    for host in spec["hosts"]:
        host_id = host["host_id"]
        for cell in spec["cells"]:
            workload, profile = cell["workload"], cell["profile"]
            calibration_id = f"cal-{host_id}-{workload}-{profile}"
            capacity_templates.append({
                "host_id": host_id,
                "workload": workload,
                "profile": profile,
                "calibration_id": calibration_id,
                "calibrator": {"allocator": "allocatbelt", "executor": "bounded"},
                "request_template": {
                    "relative_path": f"templates/{host_id}/{workload}-{profile}-request.json",
                    "raw_sha256": "1" * 64,
                },
                "context_template": {
                    "relative_path": f"templates/{host_id}/{workload}-{profile}-context.json",
                    "raw_sha256": "2" * 64,
                },
                "evidence": None,
            })
            pressure_conditions.append({
                "host_id": host_id,
                "condition_id": f"pressure-{host_id}-{workload}-{profile}",
                "condition_sha256": "3" * 64,
                "capacity_key": {
                    "host_id": host_id,
                    "workload": workload,
                    "profile": profile,
                    "calibration_id": calibration_id,
                },
                "condition": {
                    "relative_path": f"conditions/{host_id}/{workload}-{profile}.json",
                    "raw_sha256": "3" * 64,
                },
                "pressure_calibration": {
                    "calibration_id": f"pressure-cal-{host_id}-{workload}-{profile}",
                    "artifact": {"relative_path": f"pressure/{host_id}/{workload}-{profile}.tsv", "raw_sha256": "4" * 64},
                    "receipt": {"relative_path": f"pressure/{host_id}/{workload}-{profile}.json", "raw_sha256": "5" * 64},
                    "validator_sha256": sources[host_id]["qualification_harness"]["pressure_validator"]["sha256"],
                },
                "readiness_thresholds": {
                    "minimum_overlap_seconds": 30,
                    "minimum_ready_samples": 1,
                    "maximum_sample_gap_ms": 200,
                },
                "schedule": {"duration_seconds": 30, "sample_interval_ms": 100, "seed": 20261013},
            })
    spec["qualification_inputs"] = {
        "capacity_templates": capacity_templates,
        "pressure_conditions": pressure_conditions,
    }
    return spec, sources


class ApplicationCampaignInputTests(unittest.TestCase):
    def test_source_v5_inputs_module_drift_is_rejected_before_execution(self) -> None:
        source = source_v5_for("host-1")
        expected = campaign.campaign_inputs_source_sha256({"host-1": source, "host-2": source, "host-3": source})
        original_file = campaign.__file__
        with tempfile.TemporaryDirectory(prefix="campaign-input-module-drift-") as temporary:
            root = Path(temporary)
            (root / "application-campaign.py").write_text("# module path anchor\n", encoding="utf-8")
            (root / "application-campaign-inputs.py").write_text('raise AssertionError("drifted module executed")\n', encoding="utf-8")
            campaign.__file__ = str(root / "application-campaign.py")
            try:
                with self.assertRaisesRegex(campaign.CampaignError, "typed-inventory SHA-256"):
                    campaign.campaign_inputs_module(expected)
            finally:
                campaign.__file__ = original_file

    def test_v4_remains_accepted_and_manifest_generation_defaults_to_v5(self) -> None:
        legacy = fixtures.source_for("host-1")
        campaign.verify_source_manifest(legacy, verify_artifacts=False)
        self.assertEqual(legacy["schema"], "allocatbelt.application-source-manifest.v4")

        args = [
            "source-manifest", "--source-root", str(SOURCE_ROOT), "--host-id", "host-1",
            "--target-triple", "x86_64-unknown-linux-gnu", "--target-cpu", "x86-64-v3",
            "--features-sha256", "1" * 64, "--build-inputs-sha256", "2" * 64,
            "--allocator-binary", "allocatbelt=bin/allocatbelt",
            "--allocator-binary", "mimalloc-secure=bin/mimalloc-secure",
            "--allocator-binary", "mimalloc-standard=bin/mimalloc-standard",
            "--allocator-binary", "system=bin/system",
            "--soak-binary", "allocatbelt=bin/soak-allocatbelt",
            "--analysis-binary", "bin/analyzer",
            "--resource-domain-calibration-binary", "bin/calibrator",
            "--resource-domain-calibration-output", "calibration.json", "--output", "source.json",
        ]
        self.assertFalse(campaign.build_parser().parse_args(args).legacy_v4)
        self.assertTrue(campaign.build_parser().parse_args([*args[:-2], "--legacy-v4", *args[-2:]]).legacy_v4)

    def test_source_v5_binds_exact_harness_inventory_and_numeric_feedback_policy(self) -> None:
        source = source_v5_for("host-1")
        campaign.verify_source_manifest(source, verify_artifacts=False)
        self.assertEqual(source["schema"], campaign.SOURCE_SCHEMA_V5)
        self.assertEqual(set(source["qualification_harness"]), set(inputs.HARNESS_PATHS))
        policy = source["feedback_policy"]
        self.assertEqual(policy["policy"]["version"], "runtime-feedback-policy-v1")
        self.assertEqual(policy["policy"]["reader_contract"]["sample_interval_ns"], 100_000_000)
        self.assertEqual(policy["policy"]["contexts"]["cpu/steady"]["controls"]["cpu"]["initial"], 4)
        self.assertEqual(policy["policy"]["contexts"]["cpu/oversubscribed"]["controls"]["cpu"]["initial"], 2)
        self.assertEqual(policy["policy"]["contexts"]["disk/steady"]["controls"]["disk"]["floor"], 64 * 1024 * 1024)
        self.assertEqual(policy["policy"]["contexts"]["mixed/mixed"]["controls"]["download"]["ceiling"], 16 * 1024 * 1024 * 1024)

        reader_text = (SCRIPT_DIR / "application-feedback-readback.py").read_text(encoding="utf-8")
        rust_policy_text = (SOURCE_ROOT / "crates/allocatbelt/src/runtime/resource_feedback_policy.rs").read_text(encoding="utf-8")
        wrong_unit = rust_policy_text.replace(
            "ACTUATION_COOLDOWN: Duration = Duration::from_secs(1);",
            "ACTUATION_COOLDOWN: Duration = Duration::from_millis(1);",
            1,
        )
        self.assertNotEqual(wrong_unit, rust_policy_text)
        with self.assertRaisesRegex(inputs.InputError, "disagree on actuation_cooldown_ns"):
            inputs._reader_policy_contract(reader_text, wrong_unit)

        damaged = copy.deepcopy(source)
        damaged["qualification_harness"]["pressure_validator"]["path"] = "scripts/other.py"
        damaged["manifest_sha256"] = campaign.digest_object(damaged)
        with self.assertRaisesRegex(campaign.CampaignError, "qualification harness"):
            campaign.verify_source_manifest(damaged, verify_artifacts=False)

        damaged = copy.deepcopy(source)
        damaged["feedback_policy"]["policy"]["contexts"]["cpu/steady"]["controls"]["cpu"]["initial"] = 99
        damaged["feedback_policy"]["policy_sha256"] = campaign.hashlib.sha256(
            campaign.canonical_bytes(damaged["feedback_policy"]["policy"])
        ).hexdigest()
        damaged["manifest_sha256"] = campaign.digest_object(damaged)
        with self.assertRaisesRegex(campaign.CampaignError, "bounds or thresholds|numeric context"):
            campaign.verify_source_manifest(damaged, verify_artifacts=False)

    def test_spec_v3_null_capacity_evidence_blocks_confirmation_and_plan_contains_only_prospective_bindings(self) -> None:
        spec, sources = spec_v3_fixture()
        fixtures.add_frozen_rates(spec, include_oracles=True)
        summary = campaign.validate_spec(spec, sources)
        self.assertTrue(summary["rates_frozen"])
        self.assertTrue(summary["oracles_frozen"])
        self.assertFalse(summary["capacity_evidence_supplied"])
        self.assertFalse(summary["capacity_evidence_pins_checked"])
        self.assertFalse(summary["capacity_evidence_validation_complete"])
        self.assertFalse(summary["capacity_evidence_ready"])
        self.assertFalse(summary["confirmation_ready"])
        self.assertFalse(summary["feedback_runtime_composition_ready"])
        self.assertFalse(summary["execution_ready"])
        self.assertTrue(any("collector Control charge" in gap for gap in summary["full_gate_gaps"]))

        spec["rates"] = []
        spec["oracles"] = []
        plan = campaign.freeze_plan(spec, sources)
        self.assertEqual(plan["schema"], inputs.PLAN_V3_SCHEMA)
        self.assertEqual(len(plan["capacity_process_templates"]), 45)
        self.assertEqual(len(plan["feedback_process_templates"]), 3 * 15 * 4 * 2 * 2)
        self.assertEqual(
            plan["capacity_process_templates_sha256"],
            campaign.hashlib.sha256(campaign.canonical_bytes(plan["capacity_process_templates"])).hexdigest(),
        )
        first_cell = [item for item in plan["feedback_process_templates"] if item["identity"]["host_id"] == "host-1" and item["identity"]["workload"] == "cpu" and item["identity"]["profile"] == "steady"]
        self.assertEqual(len(first_cell), 16)
        self.assertEqual({item["identity"]["comparison_family"] for item in first_cell}, {"fixed_policy", "external_pressure"})
        self.assertEqual(len({item["identity"]["prospective_nonce"] for item in first_cell}), 16)
        self.assertTrue(all(item["nonce_scope"] == inputs.PROSPECTIVE_NONCE_SCOPE for item in first_cell))
        self.assertTrue(all(item["nonce_instantiation_schema"] == inputs.NONCE_INSTANTIATION_SCHEMA for item in first_cell))
        pressure_templates = [item for item in first_cell if item["identity"]["comparison_family"] == "external_pressure"]
        self.assertTrue(all("successful_fixed_predecessor_receipt" in item["required_proofs"] for item in pressure_templates))
        condition_ids = {
            item["condition_id"]
            for item in spec["qualification_inputs"]["pressure_conditions"]
            if item["host_id"] == "host-1" and item["capacity_key"]["workload"] == "cpu" and item["capacity_key"]["profile"] == "steady"
        }
        self.assertEqual({item["identity"]["pressure_condition_id"] for item in pressure_templates}, condition_ids)
        self.assertTrue(all("process_id" not in item["identity"] and "runtime_proof" not in item for item in first_cell))
        campaign.verify_plan(
            plan, sources["host-1"]["runtime_readback_validator"]["sha256"],
            campaign.campaign_inputs_source_sha256(sources),
        )
        with self.assertRaisesRegex(campaign.CampaignError, "differs from the verified SourceV5 pin"):
            campaign.verify_plan(plan, sources["host-1"]["runtime_readback_validator"]["sha256"], "0" * 64)

    def test_full_v3_original_matrix_round_trips_serialized_plan(self) -> None:
        spec, sources = spec_v3_fixture()
        fixtures.add_frozen_rates(spec, include_oracles=True)
        self.assertEqual(campaign.validate_spec(spec, sources)["confirmation_ready"], False)
        plan = campaign.freeze_plan(spec, sources)
        self.assertEqual(len(plan["jobs"]["confirmation"]), 24_300)
        self.assertEqual(len(plan["jobs"]["pressure"]), 24_300)
        self.assertEqual(len(plan["jobs"]["exploration"]), 1_080)
        fixed_ids = {job["run_id"] for job in plan["jobs"]["confirmation"]}
        self.assertTrue(all(len(job["predecessor_run_ids"]) == 1 and job["predecessor_run_ids"][0] in fixed_ids for job in plan["jobs"]["pressure"]))
        encoded = campaign.campaign_plan_bytes(plan)
        print(f"complete_v3_frozen_plan_bytes={len(encoded)}")
        self.assertGreater(len(encoded), campaign.MAX_SOURCE_MANIFEST_BYTES)
        with tempfile.TemporaryDirectory(prefix="application-v3-full-plan-roundtrip-") as temporary:
            plan_path = Path(temporary) / "complete-v3-plan.json"
            plan_path.write_bytes(encoded)
            reopened = campaign.read_campaign_plan(plan_path)
            campaign.verify_plan(
                reopened, sources["host-1"]["runtime_readback_validator"]["sha256"],
                campaign.campaign_inputs_source_sha256(sources),
            )
            self.assertEqual(reopened, plan)
        artifact_directory = os.environ.get("ALLOCATBELT_CAMPAIGN_TEST_ARTIFACTS")
        if artifact_directory:
            artifact_root = Path(artifact_directory).resolve()
            try:
                artifact_root.relative_to(SOURCE_ROOT)
            except ValueError:
                pass
            else:
                self.fail("native round-trip witness artifacts must be outside the source inventory root")
            artifact_root.mkdir(parents=True, exist_ok=True)
            plan_path = artifact_root / "complete-v3-plan.json"
            witness_path = artifact_root / "complete-v3-plan-witness.json"
            self.assertFalse(plan_path.exists() or witness_path.exists(), "refusing to replace a prior native plan witness")
            plan_path.write_bytes(encoded)
            source_records = source_inventory_records()
            source_tree_sha256 = campaign.source_inventory_module().digest_records(source_records)
            fixed_ids = {job["run_id"] for job in plan["jobs"]["confirmation"]}
            pressure_predecessors = [job.get("predecessor_run_ids", []) for job in plan["jobs"]["pressure"]]
            witness = {
                "schema": "allocatbelt.application-campaign-v3-plan-roundtrip-witness.v1",
                "campaign_id": spec["campaign_id"],
                "spec_sha256": plan["spec_sha256"],
                "plan_sha256": plan["plan_sha256"],
                "plan_raw_sha256": campaign.hashlib.sha256(encoded).hexdigest(),
                "plan_bytes": len(encoded),
                "plan_maximum_bytes": campaign.MAX_CAMPAIGN_PLAN_BYTES,
                "roundtrip_equal": True,
                "confirmation_ready": campaign.validate_spec(spec, sources)["confirmation_ready"],
                "execution_ready": plan["execution_ready"],
                "full_gate_ready": plan["full_gate_ready"],
                "job_counts": {name: len(rows) for name, rows in plan["jobs"].items()},
                "pressure_jobs_with_one_fixed_predecessor": sum(len(items) == 1 and items[0] in fixed_ids for items in pressure_predecessors),
                "campaign_inputs_module_sha256": plan["campaign_inputs_module_sha256"],
                "source_manifest_sha256_by_host": plan["source_manifests"],
                "source_inventory_sha256": source_tree_sha256,
                "source_inventory_module_sha256": campaign.SOURCE_INVENTORY_MODULE_SHA256,
                "source_files": source_records,
                "native_host": os.uname().nodename,
                "platform_machine": platform.machine(),
                "python_version": platform.python_version(),
            }
            witness_path.write_bytes(campaign.canonical_bytes(witness))

    def test_pressure_condition_must_bind_a_unique_matching_capacity_template(self) -> None:
        spec, sources = spec_v3_fixture()
        spec["qualification_inputs"]["pressure_conditions"][0]["condition_sha256"] = "f" * 64
        with self.assertRaisesRegex(campaign.CampaignError, "raw digest"):
            campaign.validate_spec(spec, sources)

        spec, sources = spec_v3_fixture()
        duplicate = copy.deepcopy(spec["qualification_inputs"]["pressure_conditions"][0])
        duplicate["condition_id"] += "-duplicate"
        duplicate["pressure_calibration"]["calibration_id"] += "-duplicate"
        spec["qualification_inputs"]["pressure_conditions"].append(duplicate)
        with self.assertRaisesRegex(campaign.CampaignError, "duplicate capacity key"):
            campaign.validate_spec(spec, sources)

    def test_nonnull_capacity_evidence_pins_do_not_enable_readiness(self) -> None:
        spec, sources = spec_v3_fixture()
        for index, template in enumerate(spec["qualification_inputs"]["capacity_templates"]):
            prefix = f"evidence/{template['host_id']}/{template['workload']}-{template['profile']}-{index}"
            template["evidence"] = {
                "artifact": {"relative_path": f"{prefix}-artifact.tsv", "raw_sha256": "a" * 64},
                "receipt": {"relative_path": f"{prefix}-receipt.json", "raw_sha256": "b" * 64},
                "stage_receipt": {"relative_path": f"{prefix}-stage.json", "raw_sha256": "c" * 64},
            }
        fixtures.add_frozen_rates(spec, include_oracles=True)
        summary = campaign.validate_spec(spec, sources)
        self.assertTrue(summary["capacity_evidence_supplied"])
        self.assertEqual(summary["capacity_evidence_supplied_count"], 45)
        self.assertFalse(summary["capacity_evidence_pins_checked"])
        self.assertFalse(summary["capacity_evidence_validation_complete"])
        self.assertFalse(summary["capacity_evidence_ready"])
        self.assertFalse(summary["confirmation_ready"])
        self.assertTrue(any("raw file pins have not been checked" in gap for gap in summary["full_gate_gaps"]))

    def test_checked_capacity_raw_pins_still_do_not_assert_producer_or_ledger_validity(self) -> None:
        spec, sources = spec_v3_fixture()
        with tempfile.TemporaryDirectory(prefix="application-capacity-pins-only-") as temporary:
            root = Path(temporary)

            def write_pin(pin: dict, label: str) -> str:
                path = root / pin["relative_path"]
                path.parent.mkdir(parents=True, exist_ok=True)
                # A self-asserted controller hash and reversed chronology are
                # deliberately just pinned bytes in this prospective phase.
                raw = (
                    b'{"controller_sha256":"' + b"0" * 64
                    + b'","calibration_completed_monotonic_ns":9,"confirmation_dispatch_monotonic_ns":3}'
                    if label == "stage" else f"pinned {label} {pin['relative_path']}\n".encode()
                )
                path.write_bytes(raw)
                pin["raw_sha256"] = campaign.hashlib.sha256(raw).hexdigest()
                return pin["raw_sha256"]

            for index, template in enumerate(spec["qualification_inputs"]["capacity_templates"]):
                prefix = f"complete/{template['host_id']}/{template['workload']}-{template['profile']}-{index}"
                template["request_template"]["relative_path"] = f"{prefix}-request.json"
                template["context_template"]["relative_path"] = f"{prefix}-context.json"
                write_pin(template["request_template"], "request")
                write_pin(template["context_template"], "context")
                template["evidence"] = {
                    "artifact": {"relative_path": f"{prefix}-capacity.tsv", "raw_sha256": "0" * 64},
                    "receipt": {"relative_path": f"{prefix}-capacity.json", "raw_sha256": "0" * 64},
                    "stage_receipt": {"relative_path": f"{prefix}-stage.json", "raw_sha256": "0" * 64},
                }
                for name, pin in template["evidence"].items():
                    write_pin(pin, "stage" if name == "stage_receipt" else name)

            for condition in spec["qualification_inputs"]["pressure_conditions"]:
                condition["condition_sha256"] = write_pin(condition["condition"], "condition")
                write_pin(condition["pressure_calibration"]["artifact"], "pressure artifact")
                write_pin(condition["pressure_calibration"]["receipt"], "pressure receipt")
            fixtures.add_frozen_rates(spec, include_oracles=True)
            summary = campaign.validate_spec(spec, sources, root)
        self.assertTrue(summary["capacity_evidence_supplied"])
        self.assertEqual(summary["capacity_evidence_supplied_count"], 45)
        self.assertTrue(summary["capacity_evidence_pins_checked"])
        self.assertTrue(summary["qualification_inputs_pins_checked"])
        self.assertFalse(summary["capacity_evidence_validation_complete"])
        self.assertFalse(summary["capacity_evidence_ready"])
        self.assertFalse(summary["confirmation_ready"])
        self.assertTrue(any("pinned only" in gap for gap in summary["full_gate_gaps"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
