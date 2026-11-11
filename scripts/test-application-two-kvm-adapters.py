#!/usr/bin/env python3
"""Profile propagation and static Source5 schedule cardinality witnesses."""
from __future__ import annotations

import importlib.machinery
import importlib.util
import sys
import unittest
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent


def load_script(name: str, relative_path: str):
    loader = importlib.machinery.SourceFileLoader(
        name, str(SCRIPT_DIR / relative_path),
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None:
        raise RuntimeError(f"cannot load {relative_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = module
    loader.exec_module(module)
    return module


campaign = load_script("two_kvm_campaign", "application-campaign.py")
chronology = load_script(
    "two_kvm_chronology", "application-campaign-chronology.py",
)
evidence_budget = load_script(
    "two_kvm_evidence_budget", "application-source5-evidence-budget.py",
)
preparation = load_script(
    "two_kvm_preparation", "application-source5-input-preparation.py",
)


class TwoKvmProfilePropagationTests(unittest.TestCase):
    @staticmethod
    def horizon_aa_controls() -> list[dict[str, Any]]:
        """Eight synthetic controls witness the unchanged 48-job A/A horizon."""
        return [{
            "control_id": f"fixture-aa-{allocator}-{executor}",
            "allocator": allocator,
            "executor": executor,
            "family": "mixed",
            "profile": "mixed",
            "mode": "capacity",
            "load_percent": None,
            "pairs": 6,
            "purpose": "synthetic A/A plan cardinality witness",
        } for allocator in campaign.ALLOCATORS
          for executor in ("bounded", "tokio")]

    @staticmethod
    def core_spec(
        *, profile: object = "two_kvm_hosts_v1",
        include_profile: bool = True,
        floor: object = ...,
    ) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema": campaign.SPEC_SCHEMA_V3,
            "campaign_id": "two-kvm-cardinality",
            "runner_sha256": "1" * 64,
            "hosts": [],
            "cells": [],
            "protocol": {},
            "runtime_binding": {},
            "phase_adapters": {},
            "aa_controls": [],
            "soak": {},
            "deadlines": {},
        }
        if include_profile:
            value["qualification_profile"] = profile
        if floor is not ...:
            value["capacity_floor_policy_id"] = floor
        return value

    @staticmethod
    def full_horizon_spec() -> dict[str, Any]:
        hosts = ["kvm-a", "kvm-b"]
        cells = [
            {"family": family, "workload": family, "profile": profile,
             "arrivals": 100_000}
            for family in ("cpu", "memory", "http", "disk")
            for profile in ("steady", "burst", "oversubscribed")
        ]
        cells.extend({
            "family": "mixed", "workload": "mixed", "profile": profile,
            "arrivals": 400_000,
        } for profile in ("mixed", "burst", "oversubscribed"))
        rates = [{
            "host_id": host_id, "family": cell["family"],
            "profile": cell["profile"], "load_percent": load,
            "arrivals_per_second": 1000,
        } for host_id in hosts for cell in cells for load in (70, 90)]
        oracles = [{
            "host_id": host_id, "allocator": allocator,
            "family": cell["family"], "profile": cell["profile"],
            "load_percent": load,
            "relative_path": f"{host_id}/{cell['family']}/{cell['profile']}/{load}/{allocator}.tsv",
            "sha256": "a" * 64,
        } for host_id in hosts for cell in cells for allocator in campaign.ALLOCATORS
          for load in (70, 90)]
        return {
            "schema": campaign.SPEC_SCHEMA_V3,
            "qualification_profile": "two_kvm_hosts_v1",
            "campaign_id": "two-kvm-full-horizon",
            "hosts": [{"host_id": host_id, "venue": "kvm_guest"}
                      for host_id in hosts],
            "cells": cells,
            "rates": rates,
            "oracles": oracles,
            "aa_controls": TwoKvmProfilePropagationTests.horizon_aa_controls(),
            "protocol": {
                "exploration_pairs": 6,
                "confirmation_pairs": 36,
                "schedule_seed": "static-two-kvm-horizon",
                "soak_seconds": 10800,
            },
            "soak": {
                "workload": "mixed", "profile": "mixed",
                "allocator": "allocatbelt", "executor": "bounded",
                "driver_relative_path": "scripts/run-application-soak.sh",
                "driver_sha256": "b" * 64, "interval_ms": 100,
            },
        }

    def test_profile_selector_and_venues_bind_exact_host_count(self):
        legacy = {
            "schema": campaign.SPEC_SCHEMA_V3,
            "hosts": [
                {"host_id": "bare", "venue": "bare_metal"},
                {"host_id": "guest-a", "venue": "kvm_guest"},
                {"host_id": "guest-b", "venue": "kvm_guest"},
            ],
        }
        two_kvm = {
            "schema": campaign.SPEC_SCHEMA_V3,
            "qualification_profile": "two_kvm_hosts_v1",
            "hosts": [
                {"host_id": "guest-a", "venue": "kvm_guest"},
                {"host_id": "guest-b", "venue": "kvm_guest"},
            ],
        }
        self.assertEqual(campaign.qualification_host_count(legacy), 3)
        self.assertEqual(campaign.qualification_host_count(two_kvm), 2)
        self.assertEqual(evidence_budget._validated_spec_host_ids(two_kvm),
                         ["guest-a", "guest-b"])
        self.assertEqual(evidence_budget._validated_spec_host_ids(legacy),
                         ["bare", "guest-a", "guest-b"])
        with self.assertRaises(campaign.CampaignError):
            campaign.qualification_host_count({
                **two_kvm, "qualification_profile": None,
            })
        with self.assertRaises(campaign.CampaignError):
            campaign.qualification_host_count({
                **two_kvm, "qualification_profile": "unknown_profile",
            })
        with self.assertRaises(evidence_budget.BudgetPlanError):
            evidence_budget._validated_spec_host_ids({
                **two_kvm, "hosts": [
                    {"host_id": "bare", "venue": "bare_metal"},
                    {"host_id": "guest-b", "venue": "kvm_guest"},
                ],
            })
        with self.assertRaises(evidence_budget.BudgetPlanError):
            evidence_budget._validated_spec_host_ids({
                **two_kvm, "hosts": two_kvm["hosts"][:1],
            })

    def test_preparation_core_v3_preserves_optional_floor_selector(self):
        keys = {
            "campaign_id", "runner_sha256", "hosts", "cells", "protocol",
            "runtime_binding", "phase_adapters", "aa_controls", "soak", "deadlines",
        }
        legacy_spec_v1 = self.core_spec(include_profile=False)
        legacy_v1 = chronology._source5_preparation_core_projection(
            legacy_spec_v1, None,
        )
        self.assertEqual(legacy_v1, {
            "schema": "allocatbelt.application-source5-preparation-core.v1",
            **{key: legacy_spec_v1[key] for key in sorted(keys)},
        })
        self.assertEqual(
            legacy_v1["schema"],
            "allocatbelt.application-source5-preparation-core.v1",
        )
        self.assertNotIn("qualification_profile", legacy_v1)
        legacy_spec_v2 = self.core_spec(
            include_profile=False,
            floor=chronology.CAPACITY_FLOOR_POLICY_ID,
        )
        legacy_v2 = chronology._source5_preparation_core_projection(
            legacy_spec_v2,
            chronology.CAPACITY_FLOOR_POLICY_ID,
        )
        self.assertEqual(legacy_v2, {
            "schema": "allocatbelt.application-source5-preparation-core.v2",
            **{key: legacy_spec_v2[key] for key in sorted(keys)},
            "capacity_floor_policy_id": chronology.CAPACITY_FLOOR_POLICY_ID,
        })
        self.assertEqual(
            legacy_v2["schema"],
            "allocatbelt.application-source5-preparation-core.v2",
        )
        self.assertEqual(legacy_v2["capacity_floor_policy_id"],
                         chronology.CAPACITY_FLOOR_POLICY_ID)

        no_floor_spec = self.core_spec()
        no_floor = chronology._source5_preparation_core_projection(
            no_floor_spec, None,
        )
        self.assertEqual(no_floor, {
            "schema": "allocatbelt.application-source5-preparation-core.v3",
            **{key: no_floor_spec[key] for key in sorted(keys)},
            "qualification_profile": "two_kvm_hosts_v1",
        })
        self.assertEqual(
            no_floor["schema"],
            "allocatbelt.application-source5-preparation-core.v3",
        )
        self.assertEqual(no_floor["qualification_profile"], "two_kvm_hosts_v1")
        self.assertNotIn("capacity_floor_policy_id", no_floor)

        explicit_none_spec = self.core_spec(floor=None)
        explicit_none = chronology._source5_preparation_core_projection(
            explicit_none_spec, None,
        )
        self.assertEqual(explicit_none, {
            "schema": "allocatbelt.application-source5-preparation-core.v3",
            **{key: explicit_none_spec[key] for key in sorted(keys)},
            "qualification_profile": "two_kvm_hosts_v1",
            "capacity_floor_policy_id": None,
        })
        self.assertIn("capacity_floor_policy_id", explicit_none)
        self.assertIsNone(explicit_none["capacity_floor_policy_id"])

        with self.assertRaises(chronology.ChronologyError):
            chronology._source5_preparation_core_projection(
                self.core_spec(profile=None), None,
            )

    def test_unselected_pressure_templates_keep_the_floor_fields_absent(self):
        hosts = ("kvm-a", "kvm-b")
        contexts = [
            (family, profile)
            for family, profiles in (
                ("cpu", ("steady", "burst", "oversubscribed")),
                ("memory", ("steady", "burst", "oversubscribed")),
                ("http", ("steady", "burst", "oversubscribed")),
                ("disk", ("steady", "burst", "oversubscribed")),
                ("mixed", ("mixed", "burst", "oversubscribed")),
            ) for profile in profiles
        ]
        sources: dict[str, dict[str, Any]] = {}
        for host_id_index, host_id in enumerate(hosts, 1):
            source_sha = str(host_id_index) * 64
            fixed_sha = str(host_id_index + 2) * 64
            feedback_sha = str(host_id_index + 4) * 64
            sources[host_id] = {
                "source": {"source_tree_sha256": source_sha},
                "artifacts": {
                    allocator: {"sha256": str(index + 1) * 64}
                    for index, allocator in enumerate(campaign.ALLOCATORS)
                },
                "fixed_runtime_policy": {"policy_sha256": fixed_sha},
                "feedback_policy": {
                    "policy_sha256": feedback_sha,
                    "policy": {
                        "version": "feedback-v1",
                        "reader_contract": "reader-v1",
                        "algorithm": "fixed-reciprocal-v1",
                        "source_pins": {"reader": "7" * 64},
                        "contexts": {
                            f"{workload}/{profile}": {
                                "workload": workload, "profile": profile,
                            } for workload, profile in contexts
                        },
                    },
                },
            }
        capacity_templates = []
        capacity_by_context = {}
        for host_id in hosts:
            for workload, profile in contexts:
                calibration_id = f"cal-{host_id}-{workload}-{profile}"
                condition_id = f"cond-{host_id}-{workload}-{profile}"
                capacity_by_context[(host_id, workload, profile)] = (
                    calibration_id, condition_id,
                )
                capacity_templates.append({
                    "capacity_key": {
                        "host_id": host_id, "workload": workload,
                        "profile": profile, "calibration_id": calibration_id,
                    },
                    "pressure_condition_id": condition_id,
                })
        templates = []
        for host_id in hosts:
            for workload, profile in contexts:
                calibration_id, condition_id = capacity_by_context[
                    (host_id, workload, profile)
                ]
                source = sources[host_id]
                for family in ("fixed_policy", "external_pressure"):
                    for allocator in campaign.ALLOCATORS:
                        for executor in ("allocatbelt", "tokio-1.53.3"):
                            source_policy = source["feedback_policy"]["policy"]
                            policy = {
                                "version": source_policy["version"],
                                "reader_contract": source_policy["reader_contract"],
                                "algorithm": source_policy["algorithm"],
                                "context": source_policy["contexts"][f"{workload}/{profile}"],
                                "source_pins": source_policy["source_pins"],
                            }
                            identity = {
                                "campaign_id": "two-kvm-template-test",
                                "host_id": host_id,
                                "workload": workload,
                                "profile": profile,
                                "comparison_family": family,
                                "capacity_calibration_id": calibration_id,
                                "pressure_condition_id": (
                                    None if family == "fixed_policy" else condition_id
                                ),
                                "allocator": allocator,
                                "executor": executor,
                                "source_sha256": source["source"]["source_tree_sha256"],
                                "binary_sha256": source["artifacts"][allocator]["sha256"],
                                "fixed_policy_sha256": source["fixed_runtime_policy"]["policy_sha256"],
                                "feedback_policy_sha256": source["feedback_policy"]["policy_sha256"],
                                "context_policy_sha256": chronology.sha256_bytes(
                                    chronology.canonical_bytes(policy),
                                ),
                                "prospective_nonce": "0" * 32,
                            }
                            template = {
                                "identity": identity,
                                "nonce_scope": "reusable_template",
                                "nonce_instantiation_schema": "nonce-v1",
                                "nonce_instantiation_rule": "template_nonce+campaign+job+pair+ordinal",
                                "policy": policy,
                                "required_proofs": ["component_receipt"],
                            }
                            template["template_sha256"] = chronology.sha256_bytes(
                                chronology.canonical_bytes(template),
                            )
                            templates.append(template)
        plan = {
            "campaign_id": "two-kvm-template-test",
            "host_ids": list(hosts),
            "capacity_process_templates": capacity_templates,
            "feedback_process_templates": templates,
            "feedback_process_templates_sha256": chronology.sha256_bytes(
                chronology.canonical_bytes(templates),
            ),
        }
        chronology._source5_validate_selected_plan_templates(
            plan, sources, None, None,
        )

    def test_completion_bridge_validates_the_exact_30_context_matrix(self):
        contexts = [
            (family, profile)
            for family, profiles in (
                ("cpu", ("steady", "burst", "oversubscribed")),
                ("memory", ("steady", "burst", "oversubscribed")),
                ("http", ("steady", "burst", "oversubscribed")),
                ("disk", ("steady", "burst", "oversubscribed")),
                ("mixed", ("mixed", "burst", "oversubscribed")),
            ) for profile in profiles
        ]
        expected = {
            (host_id, workload, profile)
            for host_id in ("kvm-a", "kvm-b")
            for workload, profile in contexts
        }
        rows = [{
            "host_id": host_id, "workload": workload, "profile": profile,
        } for host_id, workload, profile in sorted(expected)]
        validated = preparation._validate_prepared_context_matrix(
            rows, expected, "test capacity matrix",
        )
        self.assertEqual(set(validated), expected)
        self.assertEqual(len(validated), 30)

        with self.assertRaises(preparation.PreparationError):
            preparation._validate_prepared_context_matrix(
                rows[:-1], expected, "29-row capacity matrix",
            )
        duplicate_rows = [dict(row) for row in rows]
        duplicate_rows[-1] = dict(duplicate_rows[0])
        with self.assertRaises(preparation.PreparationError):
            preparation._validate_prepared_context_matrix(
                duplicate_rows, expected, "duplicate capacity matrix",
            )
        unknown_rows = [dict(row) for row in rows]
        unknown_rows[-1]["host_id"] = "kvm-c"
        with self.assertRaises(preparation.PreparationError):
            preparation._validate_prepared_context_matrix(
                unknown_rows, expected, "unknown-host capacity matrix",
            )

    def test_campaign_builder_preserves_each_host_full_horizon(self):
        """Build cardinality only; this fixture contains no application measurements."""
        spec = self.full_horizon_spec()
        self.assertEqual(campaign.qualification_host_count(spec), 2)
        self.assertEqual(len(spec["cells"]), 15)
        self.assertEqual(len(spec["rates"]), 60)
        self.assertEqual(len(spec["oracles"]), 240)

        expected_per_host = {
            "exploration": 360,
            "aa": 48,
            "confirmation": 8100,
            "pressure": 8100,
            "soak": 1,
        }
        for host_id in ("kvm-a", "kvm-b"):
            for phase, expected_count in expected_per_host.items():
                jobs = campaign.build_jobs(spec, phase, host_id)
                self.assertEqual(len(jobs), expected_count, (host_id, phase))
                for job in jobs:
                    if job.get("mode") == "open_loop":
                        self.assertEqual(job["arrivals"], 400_000 if job["family"] == "mixed" else 100_000)
        aggregate = {
            phase: len(campaign.build_jobs(spec, phase))
            for phase in expected_per_host
        }
        self.assertEqual(
            aggregate,
            {phase: count * 2 for phase, count in expected_per_host.items()},
        )
        per_host_jobs = sum(expected_per_host.values())
        self.assertEqual(per_host_jobs, 16609)
        self.assertEqual(1 + 6 + 6 * (per_host_jobs - 1) + 4, 99659)
        self.assertEqual(sum(aggregate.values()), 33218)
        self.assertEqual(2 * 99659, 199318)


if __name__ == "__main__":
    unittest.main()
