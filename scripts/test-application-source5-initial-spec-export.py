"""Pure contract tests for prospective initial SpecV3 export projections.

These fixtures exercise only canonical DTO projection and matrix rejection;
they are not host, APP, capacity, or pressure evidence.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


SCRIPTS = Path(__file__).resolve().parent


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


preparation = _load(
    "initial_spec_export_preparation_component",
    "application-source5-input-preparation.py",
)
pressure = _load(
    "initial_spec_export_pressure_reader_component",
    "application-pressure-readback.py",
)
campaign = _load(
    "initial_spec_export_campaign_component",
    "application-campaign.py",
)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _pin(path: str, label: str) -> dict[str, str]:
    return {"path": path, "raw_sha256": _sha(label)}


def _context_policy_fixture():
    source_pin = _pin("/input/source.json", "source")
    capacity = {
        "schema": pressure.CAPACITY_BUNDLE_PIN_SCHEMA_V2,
        "capacity_key": {
            "host_id": "kvm-a", "workload": "cpu",
            "profile": "steady", "calibration_id": "cap-cpu-steady",
        },
        "source_manifest": source_pin,
        "request": _pin("/input/capacity-request.json", "request"),
        "artifact": _pin("/input/capacity.tsv", "artifact"),
        "receipt": _pin("/input/capacity-receipt.json", "receipt"),
    }
    numeric_policy = {
        "collector": {"expected_global_control_baseline": 17},
        "global_ceilings": {"cpu": 50},
        "tenant_ceilings": {"cpu": 25},
        "capacity_sources": {"cpu": "prepared"},
        "scope_limits": {"cpu": 10},
        "rate_buckets": {"cpu": 3},
    }
    replayed = []
    for index, executor in enumerate(("bounded", "tokio")):
        allocator = "allocatbelt"
        resolved = {
            "context": {
                **capacity["capacity_key"], "allocator": allocator,
            },
            "policy": copy.deepcopy(numeric_policy),
            "source_manifest_raw_sha256": source_pin["raw_sha256"],
            "source_manifest_sha256": _sha("source semantic"),
            "source_tree_sha256": _sha("source tree"),
            "build_sha256": _sha("build"),
            "base_policy_artifact_sha256": _sha("base artifact"),
            "base_policy_sha256": _sha("base policy"),
            "base_context_sha256": _sha("base context"),
            "capacity_request_raw_sha256": capacity["request"]["raw_sha256"],
            "capacity_artifact_raw_sha256": capacity["artifact"]["raw_sha256"],
            "capacity_receipt_raw_sha256": capacity["receipt"]["raw_sha256"],
            "resolution_rule_version": "static-v1",
            "policy_sha256": _sha(f"resolved-{index}"),
        }
        replayed.append({
            "pair": executor, "executor": executor, "allocator": allocator,
            "binary_sha256": _sha("binary"),
            "probe_raw_sha256": _sha(f"probe-{index}"),
            "request_raw_sha256": _sha(f"request-{index}"),
            "resolved_policy_raw_sha256": _sha(f"resolved-raw-{index}"),
            "resolved_policy_sha256": resolved["policy_sha256"],
            "composition_receipt_raw_sha256": _sha(f"receipt-{index}"),
            "policy": resolved,
        })
    return source_pin, capacity, replayed


def _pressure_binding_rows(preparation_value: dict[str, object]):
    rows = []
    for condition in preparation_value["condition_intensities"]:
        key = condition["capacity_key"]
        rows.append({
            "host_id": condition["host_id"],
            "condition_id": condition["condition_id"],
            "capacity_key": key,
            "condition_pin": {"path": "/input/condition.json", "raw_sha256": _sha(condition["condition_id"])},
            "context_policy_pin": {"path": "/input/context-policy.json", "raw_sha256": _sha("context")},
            "calibration_pin": {"path": "/input/calibration.json", "raw_sha256": _sha("calibration")},
            "calibration_receipt_pin": {"path": "/input/receipt.json", "raw_sha256": _sha("receipt"), "scope_sha256": _sha("scope")},
            "capacity_bundle_pin": {},
            "observed_host_pin": {"path": "/input/observed.json", "raw_sha256": _sha("observed")},
            "evidence_path_map": {"schema": "fixture-only", "entries": []},
        })
    return rows


def _preparation_matrix():
    host_ids = ["kvm-a", "kvm-b"]
    cells = [
        {"workload": f"workload-{index}", "profile": f"profile-{index}"}
        for index in range(15)
    ]
    conditions = []
    for host_id in host_ids:
        for cell in cells:
            context = {**cell, "host_id": host_id}
            conditions.append({
                "host_id": host_id,
                "condition_id": f"condition-{host_id}-{cell['workload']}",
                "capacity_key": {**context, "calibration_id": "cap-id"},
                "condition": {"relative_path": "conditions/fixture.json",
                              "raw_sha256": _sha(str(context))},
                "pressure_calibration_id": "pressure-id",
                "readiness_thresholds": {}, "schedule": {},
            })
    return {"core": {"hosts": [{"host_id": host} for host in host_ids],
                     "cells": cells},
            "condition_intensities": conditions}


class InitialSpecExportProjectionTests(unittest.TestCase):
    def test_shared_policy_projection_matches_the_existing_v2_schema(self) -> None:
        source_pin, capacity, replayed = _context_policy_fixture()
        policy = pressure.project_shared_context_policy_v2(
            source_pin, capacity, replayed,
        )
        self.assertEqual(policy["schema"], pressure.SOURCE5_PRESSURE_POLICY_SCHEMA)
        self.assertEqual(policy["source_manifest"], source_pin)
        self.assertEqual(policy["capacity_bundle"], {
            key: capacity[key] for key in ("request", "artifact", "receipt")
        })
        self.assertEqual(
            [row["executor"] for row in policy["member_resolutions"]],
            ["bounded", "tokio"],
        )
        self.assertEqual(policy["baseline"], 17)
        body = {key: value for key, value in policy.items()
                if key != "policy_sha256"}
        self.assertEqual(policy["policy_sha256"], pressure.digest_object(body))

    def test_shared_policy_projection_refuses_context_or_numeric_divergence(self) -> None:
        source_pin, capacity, replayed = _context_policy_fixture()
        replayed[1]["policy"]["policy"]["global_ceilings"]["cpu"] += 1
        with self.assertRaises(pressure.ReadbackError):
            pressure.project_shared_context_policy_v2(source_pin, capacity, replayed)

    def test_initial_host_order_comes_from_the_verified_cohort(self) -> None:
        self.assertTrue(preparation._is_initial_two_kvm_host_order(["kvm-a", "kvm-b"]))
        for value in (["kvm-b", "kvm-a"], ["kvm-a", "kvm-a"], ["kvm-a"],
                      ["kvm-a", "kvm-b", "kvm-c"], [True, "kvm-b"], None):
            with self.subTest(value=value):
                self.assertFalse(preparation._is_initial_two_kvm_host_order(value))

    def test_initial_pressure_bindings_must_be_exact_and_in_intent_order(self) -> None:
        value = _preparation_matrix()
        rows = _pressure_binding_rows(value)
        host_ids, expected, condition_map, order = \
            preparation._validate_initial_pressure_binding_matrix(value, rows)
        self.assertEqual(host_ids, ["kvm-a", "kvm-b"])
        self.assertEqual(len(expected), 30)
        self.assertEqual(set(condition_map), expected)
        self.assertEqual(len(order), 30)
        swapped = list(rows)
        swapped[0], swapped[1] = swapped[1], swapped[0]
        with self.assertRaises(preparation.PreparationError):
            preparation._validate_initial_pressure_binding_matrix(value, swapped)
        with self.assertRaises(preparation.PreparationError):
            preparation._validate_initial_pressure_binding_matrix(value, rows[:-1])

    def test_initial_spec_projection_keeps_capacity_evidence_empty(self) -> None:
        host_ids = ["kvm-a", "kvm-b"]
        core = {
            "schema": "allocatbelt.application-source5-preparation-core.v3",
            "campaign_id": "fixture-campaign", "runner_sha256": _sha("runner"),
            "qualification_profile": "two_kvm_hosts_v1",
            "hosts": [{"host_id": host, "venue": "kvm_guest"} for host in host_ids],
            "cells": [], "protocol": {}, "runtime_binding": {},
            "phase_adapters": {}, "aa_controls": [], "soak": {}, "deadlines": {},
        }
        templates = []
        for index in range(30):
            host_id = host_ids[index // 15]
            templates.append({
                "host_id": host_id, "workload": f"w{index}", "profile": "steady",
                "calibration_id": f"cap-{index}",
                "calibrator": {"allocator": "allocatbelt", "executor": "bounded"},
                "request_template": {"relative_path": f"request-{index}.json",
                                     "raw_sha256": _sha(f"request-{index}")},
                "context_template": {"relative_path": f"context-{index}.json",
                                     "raw_sha256": _sha(f"context-{index}")},
                "template_index": index, "run_id": f"prep-{index}",
                "prospective_nonce": f"nonce-{index}", "template_sha256": _sha("template"),
                "source_manifest_sha256": _sha(host_id),
                "source_sha256": _sha("tree"), "binary_sha256": _sha("binary"),
            })
        sources = {
            host: {"manifest_sha256": _sha(f"manifest-{host}"),
                   "source": {"source_tree_sha256": _sha(f"tree-{host}")}}
            for host in host_ids
        }
        source_pins = {
            host: {"manifest": {
                "relative_path": f"source-{host}.json",
                "raw_sha256": _sha(f"raw-{host}"),
                "semantic_sha256": sources[host]["manifest_sha256"],
                "source_tree_sha256": sources[host]["source"]["source_tree_sha256"],
            }} for host in host_ids
        }
        preparation_value = {
            "core": core, "source_pins": source_pins,
            "capacity_templates": templates,
        }
        pressure_rows = [{"condition_id": f"condition-{i}"} for i in range(30)]
        core_schema = "allocatbelt.application-source5-preparation-core.v3"

        def project_preparation_core(spec_value):
            core_keys = {
                "campaign_id", "runner_sha256", "hosts", "cells", "protocol",
                "runtime_binding", "phase_adapters", "aa_controls", "soak", "deadlines",
            }
            projected = {
                "schema": core_schema,
                **{key: spec_value[key] for key in sorted(core_keys)},
                "qualification_profile": spec_value["qualification_profile"],
            }
            if "capacity_floor_policy_id" in spec_value:
                projected["capacity_floor_policy_id"] = spec_value["capacity_floor_policy_id"]
            return projected

        # This is a structural projection fixture; production loads the real
        # Source-pinned input module and calls this complete V3 API.
        inputs = SimpleNamespace(
            SOURCE5_PREPARATION_CORE_SCHEMA_V3=core_schema,
            _validate_preparation_core=lambda value: value,
            preparation_core_from_spec=project_preparation_core,
        )
        campaign = SimpleNamespace(SPEC_SCHEMA_V3="allocatbelt.application-campaign-spec.v3")
        spec = preparation._initial_spec_value(
            preparation_value, sources, campaign, inputs, pressure_rows,
        )
        self.assertEqual(spec["rates"], [])
        self.assertEqual(spec["oracles"], [])
        self.assertEqual(len(spec["qualification_inputs"]["capacity_templates"]), 30)
        self.assertTrue(all(row["evidence"] is None
                            for row in spec["qualification_inputs"]["capacity_templates"]))
        self.assertEqual(spec["qualification_inputs"]["pressure_conditions"], pressure_rows)

    def test_plan_bound_failure_leaves_both_initial_outputs_absent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "source"
            output_root = root / "private-inputs"
            source_root.mkdir(mode=0o700)
            output_root.mkdir(mode=0o700)
            spec_path = output_root / "initial-spec-v3.json"
            plan_path = output_root / "initial-plan-v3.json"
            original_limit = campaign.MAX_CAMPAIGN_PLAN_BYTES
            campaign.MAX_CAMPAIGN_PLAN_BYTES = 1
            try:
                with self.assertRaisesRegex(
                    preparation.PreparationError,
                    "complete frozen campaign plan exceeds its finite matrix-sized bound",
                ):
                    preparation._publish_initial_spec_plan_new(
                        spec_path, plan_path, {"schema": "spec-v3"},
                        {"schema": "plan-v3"}, source_root, campaign,
                    )
            finally:
                campaign.MAX_CAMPAIGN_PLAN_BYTES = original_limit
            self.assertEqual(list(output_root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
