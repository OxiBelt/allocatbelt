#!/usr/bin/env python3
"""Synthetic tests for the application campaign manifest/controller."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import contextlib
import io
import math
import random
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("application-campaign.py")
LOADER = importlib.machinery.SourceFileLoader("application_campaign", str(SCRIPT))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
assert SPEC is not None
campaign = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(campaign)


def source_for(host_id: str) -> dict:
    file_sha = "1" * 64
    soak_sha = "b" * 64
    source = {
        "git_commit": "a" * 40,
        "source_tree_sha256": campaign.hashlib.sha256(f"{file_sha}  Cargo.lock\n{soak_sha}  scripts/run-application-soak.sh\n".encode()).hexdigest(),
        "cargo_lock_sha256": file_sha,
        "files": [{"path": "Cargo.lock", "sha256": file_sha, "size": 1}, {"path": "scripts/run-application-soak.sh", "sha256": soak_sha, "size": 1}],
    }
    build = {
        "host_id": host_id,
        "rustc_release": "1.99.0",
        "rustc_verbose": ["release: 1.99.0"],
        "cargo_version": "cargo 1.99.0",
        "target_triple": "x86_64-unknown-linux-gnu",
        "target_cpu": "x86-64-v3",
        "profile": "release",
        "features_sha256": "2" * 64,
        "build_inputs_sha256": "3" * 64,
    }
    artifacts = {name: {"path": f"bin/{name}", "sha256": str(index + 1) * 64} for index, name in enumerate(campaign.ALLOCATORS)}
    soak_artifacts = {name: {"path": f"bin/soak-{name}", "sha256": str(index + 5) * 64} for index, name in enumerate(campaign.ALLOCATORS)}
    result = {
        "schema": campaign.SOURCE_SCHEMA, "source": source, "build": build,
        "artifacts": artifacts, "soak_artifacts": soak_artifacts,
        "analysis_artifact": {"path": "bin/application-analyze", "sha256": "c" * 64},
    }
    result["manifest_sha256"] = campaign.digest_object(result)
    return result


def spec_fixture() -> tuple[dict, dict[str, dict]]:
    hosts = []
    sources = {}
    source_refs = []
    for index, venue in enumerate(("bare_metal", "kvm_guest", "kvm_guest")):
        host_id = f"host-{index + 1}"
        controls = {
            "cpu_model": "AMD x86-64-v3",
            "microcode_sha256": "4" * 64,
            "kernel_release": "7.0.0",
            "governor": "performance",
            "frequency_policy": "fixed",
            "boost_policy": "enabled",
            "cpu_set": "0-7",
            "numa_policy": "node0",
            "cgroup_policy_sha256": "5" * 64,
            "background_load_policy_sha256": "6" * 64,
            "x86_64_v3_capability_sha256": "e" * 64,
            "target_triple": "x86_64-unknown-linux-gnu",
            "target_cpu": "x86-64-v3",
        }
        hosts.append({
            "host_id": host_id,
            "venue": venue,
            "host_fingerprint_sha256": campaign.hashlib.sha256(campaign.canonical_bytes(controls)).hexdigest(),
            "controls": controls,
        })
        sources[host_id] = source_for(host_id)
        source_refs.append({"host_id": host_id, "relative_path": f"source/{host_id}.json", "sha256": sources[host_id]["manifest_sha256"]})
    resource_limits = {"managed_bytes": 1_000_000, "disk_ops": 16, "network_ops": 16, "tasks": 17, "cpu_charges": 17}
    resource_ceiling_sha256 = campaign.hashlib.sha256(campaign.canonical_bytes(resource_limits)).hexdigest()
    cells = [
        {"family": family, "workload": workload, "profile": profile, "arrivals": 400_000 if workload == "mixed" else 100_000,
         "async_workers": 2 if profile == "oversubscribed" else 4, "resource_limits": resource_limits, "resource_ceiling_sha256": resource_ceiling_sha256, "capacity_horizon_seconds": 30}
        for family, workload, profile in sorted(campaign.expected_profile_cells())
    ]
    spec = {
        "schema": campaign.SPEC_SCHEMA,
        "campaign_id": "campaign-v1",
        "source_manifests": source_refs,
        "runner_sha256": "8" * 64,
        "hosts": hosts,
        "cells": cells,
        "rates": [],
        "oracles": [],
        "protocol": {
            "exploration_pairs": 6,
            "confirmation_pairs": 36,
            "standalone_min_successes": 100_000,
            "mixed_min_successes": 400_000,
            "family_min_successes": 100_000,
            "bootstrap_draws": 50_000,
            "bootstrap_block_arrivals": 1000,
            "bootstrap_seed": 20261012,
            "bootstrap_prng": "splitmix64_v1_fnv1a_group_seed_rejection_uniform",
            "comparison_family_order": list(campaign.COMPARISON_FAMILY_ORDER),
            "external_pressure_predecessor": campaign.PRESSURE_PREDECESSOR_CONTRACT,
            "confidence": 0.95,
            "simultaneous_adjustment": "paired_contiguous_block_max_standardized_deviation",
            "bootstrap_hierarchy": "independent_pair_jobs_with_shared_indices_within_job_then_full_contiguous_block_pseudotraces",
            "weighting": "equal_profile_then_family_then_equal_eligible_contexts",
            "gate_scope": "independent_per_host_no_pooling",
            "safety_overload_gate_eligible": False,
            "soak_seconds": 10_800,
            "soak_rss_growth_percent": 5,
            "schedule_seed": 11,
            "allocator_min_capacity_ratio": 1.05,
            "allocator_max_p99_ratio": 0.95,
            "executor_min_capacity_ratio": 1.05,
            "executor_max_p99_ratio": 0.95,
            "max_workload_throughput_ratio": 0.98,
            "max_workload_cpu_ratio": 1.02,
            "max_workload_p99_ratio": 1.05,
            "max_retained_rss_ratio": 1.05,
        },
        "runtime_binding": {
            "resource_domain": "pending",
            "resource_policy_sha256": "9" * 64,
            "feedback_policy_sha256": "a" * 64,
            "feedback_match": "fixed_same_policy",
            "source_state": "pending",
        },
        "phase_adapters": {"same_executor_aa_sha256": None, "three_hour_soak_sha256": None, "simultaneous_analysis_sha256": None},
        "aa_controls": [{"control_id": "aa-bounded-cpu", "allocator": "allocatbelt", "family": "cpu", "profile": "steady", "mode": "capacity", "load_percent": None, "executor": "bounded", "pairs": 6, "purpose": "measurement-system A/A"}],
        "soak": {"workload": "mixed", "profile": "mixed", "allocator": "allocatbelt", "executor": "bounded", "driver_relative_path": "scripts/run-application-soak.sh", "driver_sha256": "b" * 64, "interval_ms": 100},
        "deadlines": {"setup_seconds": 120, "trace_seconds": 300, "drain_seconds": 300, "shutdown_seconds": 60, "process_seconds": 1200, "pair_validation_seconds": 300, "outer_seconds": 4020, "soak_outer_seconds": 12_300},
    }
    return spec, sources


def add_frozen_rates(spec: dict, include_oracles: bool) -> None:
    spec["rates"] = [
        {"host_id": host["host_id"], "family": cell["family"], "profile": cell["profile"], "load_percent": load,
         "arrivals_per_second": 2000, "pilot_manifest_sha256": "d" * 64}
        for host in spec["hosts"] for cell in spec["cells"] for load in campaign.LOADS
    ]
    if include_oracles:
        spec["oracles"] = [
            {"host_id": host["host_id"], "allocator": allocator, "family": cell["family"], "profile": cell["profile"],
             "load_percent": load, "relative_path": f"oracle/{host['host_id']}/{cell['family']}/{cell['profile']}/{allocator}/{load}.tsv", "sha256": "e" * 64}
            for host in spec["hosts"] for cell in spec["cells"] for allocator in campaign.ALLOCATORS for load in campaign.LOADS
        ]


class ApplicationCampaignTests(unittest.TestCase):
    def test_three_host_manifest_requires_amd64_v3_and_full_family_profile_matrix(self) -> None:
        spec, sources = spec_fixture()
        summary = campaign.validate_spec(spec, sources)
        self.assertEqual(summary["cell_count"], 15)
        self.assertEqual(summary["host_ids"], ["host-1", "host-2", "host-3"])
        self.assertFalse(summary["execution_ready"])
        self.assertFalse(summary["full_gate_ready"])
        self.assertFalse(campaign.RUNTIME_QUALIFICATION_READBACK_SUPPORTED)
        spec["hosts"][0]["controls"]["target_cpu"] = "generic"
        spec["hosts"][0]["host_fingerprint_sha256"] = campaign.hashlib.sha256(campaign.canonical_bytes(spec["hosts"][0]["controls"])).hexdigest()
        with self.assertRaises(campaign.CampaignError):
            campaign.validate_spec(spec, sources)

    def test_soak_receipts_cannot_claim_qualification_without_production_readback(self) -> None:
        spec, sources = spec_fixture()
        job = {"allocator": "allocatbelt", "executor": "bounded", "profile": "mixed", "run_id": "fake-soak"}
        with self.assertRaisesRegex(campaign.CampaignError, "hard-disabled"):
            campaign.validate_soak_receipt(
                Path("missing-receipt.json"), Path("missing-soak-directory"), job,
                sources["host-1"], spec, "host-1",
            )

    def test_exploration_schedule_is_fixed_six_pairs_and_confirmation_is_not_ready_before_rates(self) -> None:
        spec, sources = spec_fixture()
        plan = campaign.freeze_plan(spec, sources)
        self.assertEqual(len(plan["jobs"]["exploration"]), 3 * 15 * 4 * 6)
        self.assertEqual(plan["jobs"]["confirmation"], [])
        self.assertEqual(len(plan["jobs"]["aa"]), 3 * 6)
        self.assertEqual(len(plan["jobs"]["soak"]), 3)
        self.assertFalse(plan["full_gate_ready"])
        self.assertEqual(plan["jobs"]["exploration"], campaign.freeze_plan(spec, sources)["jobs"]["exploration"])

    def test_confirmation_uses_explicit_allocator_and_executor_process_pairs(self) -> None:
        spec, sources = spec_fixture()
        add_frozen_rates(spec, include_oracles=True)
        plan = campaign.freeze_plan(spec, sources)
        jobs = [job for job in plan["jobs"]["confirmation"] if job["host_id"] == "host-1"]
        self.assertEqual(len(jobs), 15 * 3 * 5 * 36)
        allocator_jobs = [job for job in jobs if job["comparison_kind"] == "allocator"]
        executor_jobs = [job for job in jobs if job["comparison_kind"] == "executor"]
        self.assertEqual(len(allocator_jobs), 15 * 3 * 2 * 36)
        self.assertEqual(len(executor_jobs), 15 * 3 * 3 * 36)
        self.assertTrue(all(job["allocator"] == "allocatbelt" and job["executor"] == "bounded" and job["pair_kind"] == "allocator-match" for job in allocator_jobs))
        self.assertEqual({job["baseline_allocator"] for job in allocator_jobs}, {"mimalloc-secure", "mimalloc-standard"})
        self.assertTrue(all(set(job["oracles"]) == {"allocatbelt", job["baseline_allocator"]} for job in allocator_jobs if job["mode"] == "open_loop"))
        self.assertEqual(sum(job["gate_role"] == "primary" for job in executor_jobs), 15 * 3 * 36)
        self.assertEqual(sum(job["gate_role"] == "secondary_sanity" for job in executor_jobs), 15 * 3 * 2 * 36)
        self.assertTrue(all(job["pair_kind"] == "matched" for job in executor_jobs))
        self.assertTrue(all(job["comparison_family"] == "fixed_policy" and job["predecessor_run_ids"] == [] for job in jobs))
        pressure_jobs = [job for job in plan["jobs"]["pressure"] if job["host_id"] == "host-1"]
        self.assertEqual(len(pressure_jobs), len(jobs))
        fixed_by_key = {
            (job["family"], job["profile"], job["mode"], job["load_percent"], job["comparison_kind"], job.get("baseline_allocator", job["allocator"]), job["pair_kind"], job["ordinal"]): job
            for job in jobs
        }
        for pressure in pressure_jobs:
            self.assertEqual(pressure["comparison_family"], "external_pressure")
            self.assertTrue(pressure["pair_kind"].startswith("pressure-"))
            self.assertEqual(len(pressure["predecessor_run_ids"]), 1)
            key = (pressure["family"], pressure["profile"], pressure["mode"], pressure["load_percent"], pressure["comparison_kind"], pressure.get("baseline_allocator", pressure["allocator"]), pressure["pair_kind"].removeprefix("pressure-"), pressure["ordinal"])
            self.assertEqual(fixed_by_key[key]["run_id"], pressure["predecessor_run_ids"][0])

    def test_oracles_are_generated_after_rates_and_confirmation_waits_for_both(self) -> None:
        spec, sources = spec_fixture()
        add_frozen_rates(spec, include_oracles=False)
        summary = campaign.validate_spec(spec, sources)
        self.assertTrue(summary["rates_frozen"])
        self.assertFalse(summary["oracles_frozen"])
        self.assertFalse(summary["confirmation_ready"])
        plan = campaign.freeze_plan(spec, sources)
        self.assertEqual(plan["jobs"]["confirmation"], [])

    def test_rate_freeze_uses_six_original_pairs_and_exact_floor(self) -> None:
        spec, _sources = spec_fixture()
        host_id = spec["hosts"][0]["host_id"]
        cells = []
        for family, _workload, profile in sorted(campaign.expected_profile_cells()):
            for allocator in campaign.ALLOCATORS:
                pairs = []
                for ordinal in range(1, 7):
                    pairs.append({
                        "ordinal": ordinal,
                        "bounded_status": "valid",
                        "tokio_status": "valid",
                        "bounded_on_time": 3_000_000 + ordinal,
                        "bounded_late": 1,
                        "bounded_attempted": 3_000_001 + ordinal,
                        "bounded_admitted": 3_000_001 + ordinal,
                        "bounded_rejected": 0,
                        "tokio_on_time": 3_000_000,
                        "tokio_late": 0,
                        "tokio_attempted": 3_000_000,
                        "tokio_admitted": 3_000_000,
                        "tokio_rejected": 0,
                        "raw_pair_sha256": "c" * 64,
                    })
                cells.append({"family": family, "profile": profile, "allocator": allocator, "pairs": pairs})
        pilot = {"schema": "allocatbelt.application-capacity-pilot.v1", "spec_sha256": campaign.preregistration_digest(spec), "host_id": host_id, "cells": cells}
        frozen = campaign.freeze_rates(spec, pilot, "d" * 64)
        self.assertEqual(len(frozen["rates"]), 30)
        cpu_steady_70 = next(row for row in frozen["rates"] if row["family"] == "cpu" and row["profile"] == "steady" and row["load_percent"] == 70)
        self.assertEqual(cpu_steady_70["arrivals_per_second"], 70_000)
        pilot["cells"][0]["pairs"].pop()
        with self.assertRaises(campaign.CampaignError):
            campaign.freeze_rates(spec, pilot, "d" * 64)

    def test_mixed_source_families_keep_the_same_contiguous_global_arrival_blocks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="application-arrival-blocks-") as temporary:
            directory = Path(temporary)
            sidecar = directory / "arrivals.tsv"
            families = ("cpu", "memory", "http", "disk")
            rows = ["schema\tallocatbelt-app-arrivals-v3", "identity\t" + "\t".join(["n" * 32, "run-1", "allocatbelt", "system", "mixed", "mixed", "s" * 64, "b" * 64]), "id\tworkload\tscheduled_ns\tcompletion_ns\tterminal\tchecksum\texpected_checksum"]
            for arrival_id in range(8):
                family = families[arrival_id % 4]
                latency = (arrival_id % 4 + 1) * (10 if arrival_id < 4 else 100)
                rows.append(f"{arrival_id}\t{family}\t{arrival_id * 1000}\t{arrival_id * 1000 + latency}\tcompleted\t1\t1")
            sidecar.write_text("\n".join(rows) + "\n", encoding="utf-8")
            metric = {"ids_path": sidecar.name, "ids_sha256": campaign.hashlib.sha256(sidecar.read_bytes()).hexdigest()}
            blocks = campaign.latency_blocks_by_family(directory, metric, families, 4)
            self.assertEqual(
                [blocks[family] for family in families],
                [[[(10 * (index + 1), 1)], [(100 * (index + 1), 1)]] for index in range(4)],
            )
            self.assertEqual(
                [campaign.exact_pseudotrace_p99(blocks[family], [0, 1]) for family in families],
                [100, 200, 300, 400],
            )

    def test_paired_bootstrap_detects_known_gain_and_per_cell_regression_guard(self) -> None:
        samples = [[1.10, 1.10, 1.10] for _ in range(36)]
        point, lower, upper = campaign.bootstrap_ratio_interval(samples, 500, 20261012, 0.025)
        self.assertAlmostEqual(point, 1.10)
        self.assertAlmostEqual(lower, 1.10)
        self.assertAlmostEqual(upper, 1.10)
        self.assertTrue(campaign.ratio_gate(lower, upper, 1.05, "lower"))
        self.assertFalse(campaign.ratio_gate(0.97, 0.97, 0.98, "lower"))

    def test_joint_max_standardized_bootstrap_checks_suite_and_cell_gates(self) -> None:
        tests = [
            {"name": "cell-a", "ratios": [1.10] * 36, "threshold": 0.98, "direction": "lower", "pair_group": "cell-a", "blocks": None, "block_group": None, "suite_components": None},
            {"name": "cell-b-regression", "ratios": [0.97] * 36, "threshold": 0.98, "direction": "lower", "pair_group": "cell-b", "blocks": None, "block_group": None, "suite_components": None},
            {"name": "equal-suite", "ratios": [math.sqrt(1.10 * 0.97)] * 36, "threshold": 1.05, "direction": "lower", "pair_group": None, "blocks": None, "block_group": None, "suite_components": [0, 1], "suite_weights": [0.5, 0.5]},
        ]
        intervals, metadata = campaign.joint_simultaneous_bootstrap(tests, 50_000, 19)
        self.assertEqual(metadata["method"], "paired_contiguous_block_max_standardized_deviation")
        self.assertEqual(metadata["endpoint_count"], 3)
        self.assertEqual(intervals[0]["lower"], 1.10)
        self.assertEqual(intervals[1]["lower"], 0.97)
        self.assertTrue(campaign.ratio_gate(intervals[0]["lower"], intervals[0]["upper"], 0.98, "lower"))
        self.assertFalse(campaign.ratio_gate(intervals[1]["lower"], intervals[1]["upper"], 0.98, "lower"))
        self.assertAlmostEqual(intervals[2]["point"], math.sqrt(1.10 * 0.97))

    def test_joint_bootstrap_preserves_cross_endpoint_correlation(self) -> None:
        base = [0.8 + (index % 9) * 0.05 for index in range(36)]
        correlated = [
            {"name": f"same-{index}", "ratios": base[:], "threshold": 0.5, "direction": "lower", "pair_group": "shared", "blocks": None, "block_group": None, "suite_components": None}
            for index in range(4)
        ]
        independent = [
            {"name": f"rotated-{shift}", "ratios": base[shift:] + base[:shift], "threshold": 0.5, "direction": "lower", "pair_group": f"independent-{shift}", "blocks": None, "block_group": None, "suite_components": None}
            for shift in range(4)
        ]
        _, correlated_meta = campaign.joint_simultaneous_bootstrap(correlated, 50_000, 29)
        _, independent_meta = campaign.joint_simultaneous_bootstrap(independent, 50_000, 29)
        self.assertGreaterEqual(independent_meta["critical_value"], correlated_meta["critical_value"])

    def test_joint_bootstrap_has_synthetic_familywise_coverage_sanity(self) -> None:
        generator = random.Random(20261012)
        covered = 0
        repetitions = 40
        for repetition in range(repetitions):
            noise = [generator.gauss(0.0, 0.18) for _ in range(36)]
            first = [math.exp(value) for value in noise]
            second = [math.exp(0.6 * value + generator.gauss(0.0, 0.10)) for value in noise]
            tests = [
                {"name": "correlated-a", "ratios": first, "threshold": 0.1, "direction": "lower", "pair_group": "shared", "blocks": None, "block_group": None, "suite_components": None},
                {"name": "correlated-b", "ratios": second, "threshold": 0.1, "direction": "lower", "pair_group": "shared", "blocks": None, "block_group": None, "suite_components": None},
            ]
            intervals, _ = campaign.joint_simultaneous_bootstrap(tests, 2000, 1000 + repetition)
            covered += int(all(interval["lower"] <= 1.0 <= interval["upper"] for interval in intervals))
        self.assertGreaterEqual(covered, 32)

    def test_exact_full_pseudotrace_p99_is_not_the_mean_of_block_p99s(self) -> None:
        candidate = [[(1, 1000)], [(100, 1000)]]
        control = [[(2, 1000)], [(100, 1000)]]
        sampled_blocks = [0, 1]
        candidate_p99 = campaign.exact_pseudotrace_p99(candidate, sampled_blocks)
        control_p99 = campaign.exact_pseudotrace_p99(control, sampled_blocks)
        self.assertEqual(candidate_p99, 100)
        self.assertEqual(control_p99, 100)
        self.assertEqual(candidate_p99 / control_p99, 1.0)
        block_p99_ratio_mean = ((1 / 2) + (100 / 100)) / 2
        self.assertEqual(block_p99_ratio_mean, 0.75)

    def test_exact_pseudotrace_p99_weights_full_and_partial_blocks_without_truncation(self) -> None:
        # The first block has three IDs and the final block has one. Sampling
        # the first block twice and the final block once yields seven values;
        # exact nearest-rank p99 must use the full multiplicity of every ID.
        blocks = [[(100, 1), (10, 1), (1, 1)], [(50, 1)]]
        self.assertEqual(campaign.exact_pseudotrace_p99(blocks, [0, 0, 1]), 100)
        # An empty source-family block remains part of the fixed horizon but
        # contributes no observations when selected.
        self.assertEqual(campaign.exact_pseudotrace_p99([[(9, 1)], []], [0, 1]), 9)

    def test_exact_pseudotrace_full_standalone_and_mixed_family_cardinality(self) -> None:
        standalone_blocks = [[(100, 1000)] if index >= 98 else [(1, 1000)] for index in range(100)]
        standalone = campaign.exact_pseudotrace_p99(standalone_blocks, list(range(100)))
        self.assertEqual(standalone, 100)
        mixed_family_blocks = [[(100, 250)] if index >= 395 else [(1, 250)] for index in range(400)]
        mixed = campaign.exact_pseudotrace_p99(mixed_family_blocks, list(range(400)))
        self.assertEqual(mixed, 100)

    def test_suite_weights_are_equal_by_profile_family_then_eligible_context(self) -> None:
        keys = []
        for profile in ("steady", "mixed", "burst", "oversubscribed"):
            for family in campaign.STANDALONE:
                contexts = ("mixed",) if profile == "mixed" else (family,) if profile == "steady" else (family, "mixed")
                keys.extend((profile, family, context) for context in contexts)
        weights = campaign.equal_profile_family_context_weights(keys)
        self.assertEqual(len(weights), 24)
        self.assertAlmostEqual(sum(weight for key, weight in zip(keys, weights, strict=True) if key[0] == "steady"), 0.25)
        self.assertAlmostEqual(sum(weight for key, weight in zip(keys, weights, strict=True) if key[0] == "mixed"), 0.25)
        self.assertAlmostEqual(sum(weight for key, weight in zip(keys, weights, strict=True) if key[0] == "burst"), 0.25)
        self.assertAlmostEqual(sum(weight for key, weight in zip(keys, weights, strict=True) if key[0] == "oversubscribed"), 0.25)
        for key, weight in zip(keys, weights, strict=True):
            self.assertAlmostEqual(weight, 1 / 16 if key[0] in ("steady", "mixed") else 1 / 32)

    def test_missing_horizon_and_cross_host_rows_are_rejected(self) -> None:
        expected = [
            {"phase": "confirmation", "host_id": "host-1", "run_id": "host-1-1"},
            {"phase": "confirmation", "host_id": "host-1", "run_id": "host-1-2"},
        ]
        one_valid = [{"state": "valid_pair", "job": expected[0]}]
        with self.assertRaises(campaign.CampaignError):
            campaign.validate_phase_ledger(one_valid, expected, "confirmation", "host-1")
        foreign = [
            {"state": "valid_pair", "job": expected[0]},
            {"state": "valid_pair", "job": {**expected[1], "host_id": "host-2"}},
        ]
        with self.assertRaises(campaign.CampaignError):
            campaign.validate_phase_ledger(foreign, expected, "confirmation", "host-1")

    def test_pair_command_has_fixed_capacity_oracle_placeholders_and_allocator_pair_arguments(self) -> None:
        deadlines = {"trace_seconds": 300, "drain_seconds": 300, "shutdown_seconds": 60, "process_seconds": 1200}
        capacity_job = {"allocator": "allocatbelt", "workload": "cpu", "mode": "capacity", "rate_per_second": None, "run_id": "capacity-01", "profile": "steady", "pair_kind": "matched"}
        capacity = campaign.build_pair_runner_argv(Path("runner"), Path("binary"), capacity_job, "0-3", Path("result"), deadlines, 5000)
        self.assertEqual(len(capacity), 18)
        self.assertEqual(capacity[14:18], ["", "", "steady", "matched"])
        open_job = {"allocator": "allocatbelt", "workload": "mixed", "mode": "open_loop", "rate_per_second": 100, "run_id": "mixed-01", "profile": "mixed", "pair_kind": "allocator-match", "comparison_kind": "allocator"}
        paired = campaign.build_pair_runner_argv(
            Path("runner"), Path("allocatbelt"), open_job, "0-3", Path("result"), deadlines, 400_000,
            (Path("candidate-oracle"), "a" * 64), Path("secure-binary"), "mimalloc-secure",
            (Path("baseline-oracle"), "b" * 64),
        )
        self.assertEqual(len(paired), 22)
        self.assertEqual(paired[14:18], ["candidate-oracle", "a" * 64, "mixed", "allocator-match"])
        self.assertEqual(paired[18:], ["secure-binary", "mimalloc-secure", "baseline-oracle", "b" * 64])

    def test_real_53_column_tsv_extraction_and_identity_sidecar(self) -> None:
        with tempfile.TemporaryDirectory(prefix="application-real-row-") as temporary:
            pair_dir = Path(temporary)
            job = {
                "run_id": "campaign-host1-cpu-steady-cap-01", "allocator": "allocatbelt",
                "workload": "cpu", "mode": "capacity", "profile": "steady", "arrivals": None,
                "rate_per_second": None, "comparison_family": "fixed_policy",
            }
            row_header = ("schema allocator executor workload mode async_workers blocking_workers topology logical_window global_task_limit retained_window arrival_rate_per_second requested_arrivals attempted admitted rejected_full rejected_resource completed_on_time completed_late errors cancellations unresolved lost result_digest expected_digest capacity_publications_per_second successful_throughput_through_drain_per_second setup_ns timer_pair_median_ns wall_through_drain_ns drain_tail_ns response_p50_ns response_p95_ns response_p99_ns producer_lateness_mean_ns producer_lateness_max_ns max_observed_managed_bytes retained_managed_bytes managed_limit_bytes disk_limit_ops network_limit_ops final_managed_bytes final_disk_ops final_network_ops rss_before_kib rss_after_drain_kib rss_after_shutdown_kib hwm_before_kib hwm_after_drain_kib hwm_after_shutdown_kib shutdown_ns rejected_logical_window rejected_backend_full").split()
            self.assertEqual(len(row_header), 53)
            row = {name: "0" for name in row_header}
            row.update(
                schema="2", allocator="allocatbelt", executor="allocatbelt", workload="cpu", mode="capacity",
                attempted="1", admitted="1", completed_on_time="1", result_digest="77", expected_digest="77",
                capacity_publications_per_second="0.03333333333333333",
                successful_throughput_through_drain_per_second="1",
                rss_after_drain_kib="100", rss_after_shutdown_kib="100",
            )
            stdout_path = pair_dir / "left-bounded.stdout.tsv"
            stdout_path.write_text(
                "\t".join(row_header) + "\n" + "\t".join(row[name] for name in row_header) + "\n",
                encoding="utf-8",
            )
            nonce = "n" * 32
            (pair_dir / "metadata.tsv").write_text(
                f"key\tvalue\ncomparison_family\tfixed_policy\nreport_nonce_left_bounded\t{nonce}\n", encoding="utf-8"
            )
            source = source_for("host-1")
            binary_sha = source["artifacts"]["allocatbelt"]["sha256"]
            phases = {
                "production_trace": 30_000_000_000,
                "production_cpu_started_ns": 100,
                "production_cpu_ended_ns": 300,
                "production_through_drain_cpu_ns": 200,
                "successful_completions": 1,
                "cpu_ns_per_successful_completion": 200,
            }
            report = ["schema\tallocatbelt-app-phase-v1\t"]
            report.extend(
                f"identity\t{key}\t{value}"
                for key, value in (
                    ("report_nonce", nonce), ("run_id", job["run_id"]),
                    ("executor", "allocatbelt"), ("allocator", "allocatbelt"),
                    ("workload", "cpu"), ("profile", "steady"),
                    ("source_sha256", source["source"]["source_tree_sha256"]),
                    ("binary_sha256", binary_sha),
                )
            )
            report.extend(f"phase\t{name}\t{value}" for name, value in phases.items())
            shutdown_path = pair_dir / "left-bounded.shutdown.tsv"
            shutdown_path.write_text("\n".join(report) + "\n", encoding="utf-8")
            process_row = {
                "pair": "left", "executor": "bounded", "allocator": "allocatbelt",
                "stdout": stdout_path.name,
                "shutdown_sha256": campaign.hashlib.sha256(shutdown_path.read_bytes()).hexdigest(),
                "capacity_family_sha256": "not_applicable",
            }
            metrics = campaign.extract_process_metrics(pair_dir, process_row, job, source, spec_fixture()[0], Path(temporary))
            self.assertEqual(metrics["completed"], 1)
            self.assertEqual(metrics["cpu_ns_per_completion"], 200)
            self.assertAlmostEqual(metrics["capacity_per_second"], 1 / 30)

    def test_public_analyzer_constructs_all_capacity_and_latency_suite_endpoints(self) -> None:
        spec, _sources = spec_fixture()
        add_frozen_rates(spec, include_oracles=True)
        spec["protocol"]["confirmation_pairs"] = 1
        spec["protocol"]["bootstrap_draws"] = 4
        expected = campaign.build_jobs(spec, "confirmation", "host-1")
        self.assertEqual(len(expected), 15 * 3 * 5)
        with tempfile.TemporaryDirectory(prefix="application-host-analyzer-") as temporary:
            root = Path(temporary)
            pair_dir = root / "pairs"
            pair_dir.mkdir()
            ids_for_workload: dict[str, tuple[str, str]] = {}
            for workload in ("cpu", "memory", "http", "disk", "mixed"):
                families = campaign.STANDALONE if workload == "mixed" else (workload,)
                count = 8 if workload == "mixed" else 4
                rows = [
                    "schema\tallocatbelt-app-arrivals-v3",
                    "identity\t" + "\t".join(["n" * 32, "synthetic", "allocatbelt", "system", workload, "mixed" if workload == "mixed" else "steady", "s" * 64, "b" * 64]),
                    "id\tworkload\tscheduled_ns\tcompletion_ns\tterminal\tchecksum\texpected_checksum",
                ]
                for arrival_id in range(count):
                    family = families[arrival_id % len(families)]
                    scheduled = arrival_id * 1000
                    latency = 100 + arrival_id
                    rows.append(f"{arrival_id}\t{family}\t{scheduled}\t{scheduled + latency}\tcompleted\t1\t1")
                path = pair_dir / f"{workload}.ids.tsv"
                path.write_text("\n".join(rows) + "\n", encoding="utf-8")
                ids_for_workload[workload] = (path.name, campaign.sha256_file(path))

            records = []
            for job in expected:
                if job["comparison_kind"] == "allocator":
                    treatments = [("allocatbelt", "bounded"), (job["baseline_allocator"], "bounded")]
                else:
                    treatments = [(job["allocator"], "bounded"), (job["allocator"], "tokio")]
                process_metrics = []
                for allocator, executor in treatments:
                    metric = {
                        "allocator": allocator, "executor": executor,
                        "capacity_per_second": 100.0,
                        "capacity_throughput_by_family": {family: 100.0 for family in campaign.STANDALONE},
                        "cpu_ns_per_completion": 100,
                        "rss_after_drain_kib": 100,
                        "latency_p99_by_family_ns": {family: 100 for family in campaign.STANDALONE},
                        "ids_path": None, "ids_sha256": None,
                    }
                    if job["mode"] == "open_loop":
                        metric["ids_path"], metric["ids_sha256"] = ids_for_workload[job["workload"]]
                    process_metrics.append(metric)
                records.append({
                    "state": "valid_pair", "job": job, "pair_directory": "pairs",
                    "process_metrics": process_metrics,
                })
            result = campaign.analyze_confirmation_host_gated(spec, "host-1", records, root)
            self.assertGreater(result["family_size"], 100)
            self.assertTrue(any(test["name"].startswith("allocator-throughput-suite:") for test in result["tests"]))
            self.assertTrue(any(test["name"].startswith("allocator-p99-suite:") for test in result["tests"]))
            self.assertTrue(any(test["name"] == "executor-throughput-suite" for test in result["tests"]))
            self.assertTrue(any(test["name"].startswith("executor-p99-suite:") for test in result["tests"]))
            self.assertFalse(result["qualification_eligible"])
            self.assertFalse(result["passed"])
            pressure_expected = campaign.build_jobs(spec, "pressure", "host-1")
            fixed_by_key = {
                (job["family"], job["profile"], job["mode"], job["load_percent"], job["comparison_kind"], job.get("baseline_allocator", job["allocator"]), job["pair_kind"], job["ordinal"]): record
                for record in records for job in [record["job"]]
            }
            pressure_records = []
            for pressure_job in pressure_expected:
                key = (pressure_job["family"], pressure_job["profile"], pressure_job["mode"], pressure_job["load_percent"], pressure_job["comparison_kind"], pressure_job.get("baseline_allocator", pressure_job["allocator"]), pressure_job["pair_kind"].removeprefix("pressure-"), pressure_job["ordinal"])
                fixed_record = fixed_by_key[key]
                pressure_records.append({**fixed_record, "job": pressure_job})
            pressure_result = campaign.analyze_confirmation_host_gated(spec, "host-1", pressure_records, root, phase="pressure")
            self.assertEqual(pressure_result["comparison_family"], "external_pressure")
            self.assertEqual(pressure_result["family_size"], result["family_size"])
            self.assertFalse(pressure_result["passed"])

    def test_prepare_oracles_cli_runs_pinned_fake_generators(self) -> None:
        with tempfile.TemporaryDirectory(prefix="application-prepare-cli-") as temporary:
            root = Path(temporary)
            source_root = root / "source"
            binary_root = source_root / "bin"
            binary_root.mkdir(parents=True)
            manifests_root = root / "spec" / "source-manifests"
            manifests_root.mkdir(parents=True)
            spec, sources = spec_fixture()
            spec["cells"] = [{
                "family": "cpu", "workload": "cpu", "profile": "steady", "arrivals": 2,
                "async_workers": 4, "resource_limits": {"managed_bytes": 0, "disk_ops": 8, "network_ops": 8, "tasks": 8, "cpu_charges": 8},
                "resource_ceiling_sha256": "0" * 64, "capacity_horizon_seconds": 30,
            }]
            spec["rates"] = [{
                "host_id": "host-1", "family": "cpu", "profile": "steady", "load_percent": 70,
                "arrivals_per_second": 2, "pilot_manifest_sha256": "d" * 64,
            }]
            fake_generator = "\n".join([
                "#!/usr/bin/env python3",
                "import pathlib, sys",
                "args = dict(zip(sys.argv[1::2], sys.argv[2::2]))",
                "output = pathlib.Path(args['--emit-oracle-only'])",
                "workload, profile = args['--workload'], args['--profile']",
                "rate, arrivals = int(args['--rate']), int(args['--arrivals'])",
                "source_sha, binary_sha = args['--source-sha256'], args['--binary-sha256']",
                "config = {'cpu':'rounds=50000','memory':'initial_bytes=4096;grown_bytes=8192;seed=0x243f6a8885a308d3','http':'body_bytes=4096','disk':'bytes=786432;seed=0x13198a2e03707344'}[workload]",
                "pulse = rate * 4 if profile == 'burst' else rate",
                "duration = ((arrivals + rate - 1) // rate) * 1000000000 if profile == 'burst' else arrivals * 1000000000 // rate",
                "lines = [f'schema\\tallocatbelt-app-oracle-v2', f'source_sha256\\t{source_sha}', f'binary_sha256\\t{binary_sha}', f'profile\\t{profile}', f'workload\\t{workload}', 'mode\\topen_loop', f'average_rate_per_second\\t{rate}', f'pulse_rate_per_second\\t{pulse}', f'arrivals\\t{arrivals}', f'trace_duration_ns\\t{duration}', f'kernel_config\\t{config}', 'id\\tscheduled_ns\\tworkload\\texpected_checksum']",
                "families = ('cpu','memory','http','disk')",
                "for job_id in range(arrivals):",
                " scheduled = job_id * 1000000000 // rate if profile != 'burst' else (job_id // rate) * 1000000000 + (job_id % rate) * 250000000 // rate",
                " family = workload if workload != 'mixed' else families[job_id % 4]",
                " lines.append(f'{job_id}\\t{scheduled}\\t{family}\\t{job_id + 7}')",
                "output.write_text('\\n'.join(lines) + '\\n', encoding='utf-8')",
                "",
            ])
            for host_id, source in sources.items():
                for artifact in source["artifacts"].values():
                    binary = source_root / artifact["path"]
                    binary.parent.mkdir(parents=True, exist_ok=True)
                    binary.write_text(fake_generator, encoding="utf-8")
                    binary.chmod(0o700)
                (manifests_root / f"{host_id}.json").write_bytes(campaign.canonical_bytes(source))
            spec["source_manifests"] = [
                {"host_id": host_id, "relative_path": f"source-manifests/{host_id}.json", "sha256": source["manifest_sha256"]}
                for host_id, source in sources.items()
            ]
            spec_path = root / "spec" / "campaign.json"
            spec_path.write_bytes(campaign.canonical_bytes(spec))
            original_validate, original_verify = campaign.validate_spec, campaign.verify_source_manifest
            campaign.validate_spec = lambda *_args, **_kwargs: {"rates_frozen": True}
            campaign.verify_source_manifest = lambda *_args, **_kwargs: None
            output_root = root / "oracles"
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    exit_code = campaign.main([
                        "prepare-oracles", "--spec", str(spec_path), "--source-root", str(source_root),
                        "--host-id", "host-1", "--output-root", str(output_root),
                    ])
            finally:
                campaign.validate_spec, campaign.verify_source_manifest = original_validate, original_verify
            self.assertEqual(exit_code, 0)
            manifest = campaign.read_json(output_root / "oracle-manifest.json")
            self.assertEqual(len(manifest["oracles"]), len(campaign.ALLOCATORS))
            self.assertTrue(all((output_root / item["relative_path"]).is_file() for item in manifest["oracles"]))

    def test_aa_run_cli_refuses_fake_runner_before_any_process_launch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="application-aa-cli-") as temporary:
            root = Path(temporary)
            source_root = root / "source"
            source_root.mkdir()
            manifests_root = root / "spec" / "source-manifests"
            manifests_root.mkdir(parents=True)
            spec, sources = spec_fixture()
            spec["source_manifests"] = [
                {"host_id": host_id, "relative_path": f"source-manifests/{host_id}.json", "sha256": source["manifest_sha256"]}
                for host_id, source in sources.items()
            ]
            for host_id, source in sources.items():
                (manifests_root / f"{host_id}.json").write_bytes(campaign.canonical_bytes(source))
            spec_path = root / "spec" / "campaign.json"
            spec_path.write_bytes(campaign.canonical_bytes(spec))
            original_validate, original_verify = campaign.validate_spec, campaign.verify_source_manifest
            campaign.validate_spec = lambda *_args, **_kwargs: {
                "host_ids": ["host-1", "host-2", "host-3"], "cell_count": len(spec["cells"]),
                "execution_ready": False, "full_gate_ready": False,
                "full_gate_gaps": ["runtime readback unavailable"],
            }
            campaign.verify_source_manifest = lambda *_args, **_kwargs: None
            plan_path = root / "plan.json"
            pair_runner = root / "fake-pair-runner.sh"
            marker = root / "launched"
            pair_runner.write_text(f"#!/usr/bin/env bash\ntouch {marker}\n", encoding="utf-8")
            pair_runner.chmod(0o700)
            try:
                plan_path.write_bytes(campaign.canonical_bytes(campaign.freeze_plan(spec, sources)))
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    exit_code = campaign.main([
                        "run", "--plan", str(plan_path), "--spec", str(spec_path),
                        "--source-root", str(source_root), "--host-id", "host-1",
                        "--observed-host-contract", str(root / "missing-host.json"),
                        "--phase", "aa", "--pair-runner", str(pair_runner),
                        "--campaign-artifacts", str(root), "--output-root", str(root / "raw"),
                    ])
            finally:
                campaign.validate_spec, campaign.verify_source_manifest = original_validate, original_verify
            self.assertEqual(exit_code, 2)
            self.assertIn("hard-disabled", stderr.getvalue())
            self.assertFalse(marker.exists(), "fake AA runner launched before runtime qualification binding")

    def test_a_a_controls_reject_missing_pair_and_nonmatched_executor(self) -> None:
        job = {"phase": "aa", "host_id": "host-1", "run_id": "aa-1", "control_id": "same", "ordinal": 1, "mode": "capacity"}
        good = {"state": "valid_pair", "job": job, "process_metrics": [
            {"executor": "bounded", "capacity_per_second": 100.0, "cpu_ns_per_completion": 4, "rss_after_drain_kib": 10},
            {"executor": "bounded", "capacity_per_second": 100.0, "cpu_ns_per_completion": 4, "rss_after_drain_kib": 10},
        ]}
        with self.assertRaises(campaign.CampaignError):
            campaign.validate_aa_records([], [job], "host-1", 100, 3)
        bad = {**good, "process_metrics": [good["process_metrics"][0], {**good["process_metrics"][1], "executor": "tokio"}]}
        with self.assertRaises(campaign.CampaignError):
            campaign.validate_aa_records([bad], [job], "host-1", 100, 3)

    def test_open_loop_aa_jobs_bind_oracle_without_comparison_kind(self) -> None:
        spec, _sources = spec_fixture()
        add_frozen_rates(spec, include_oracles=True)
        spec["aa_controls"].append({
            "control_id": "aa-bounded-cpu-open", "allocator": "allocatbelt", "family": "cpu",
            "profile": "steady", "mode": "open_loop", "load_percent": 70,
            "executor": "bounded", "pairs": 6, "purpose": "open-loop A/A control",
        })
        jobs = campaign.build_jobs(spec, "aa", "host-1")
        open_jobs = [job for job in jobs if job["control_id"] == "aa-bounded-cpu-open"]
        self.assertEqual(len(open_jobs), 6)
        for job in open_jobs:
            self.assertNotIn("comparison_kind", job)
            oracle_map = campaign.oracle_map_for_job(job)
            self.assertEqual(set(oracle_map), {"allocatbelt"})
            self.assertEqual(oracle_map["allocatbelt"], job["oracle"])

    def test_pressure_predecessor_requires_successful_fixed_readback_receipt(self) -> None:
        spec, _sources = spec_fixture()
        fixed_job = {
            "run_id": "fixed-01", "host_id": "host-1", "family": "cpu", "profile": "steady",
            "mode": "capacity", "load_percent": None, "comparison_kind": "allocator",
            "baseline_allocator": "mimalloc-secure", "allocator": "allocatbelt",
            "pair_kind": "allocator-match", "ordinal": 1, "comparison_family": "fixed_policy",
        }
        pressure_job = {**fixed_job, "run_id": "pressure-01", "phase": "pressure", "comparison_family": "external_pressure", "pair_kind": "pressure-allocator-match"}
        missing = {"state": "valid_pair", "job": fixed_job, "process_metrics": [{}, {}]}
        with self.assertRaisesRegex(campaign.CampaignError, "runtime readback"):
            campaign.fixed_pressure_predecessor_receipt(pressure_job, missing, spec)
        runtime_readback = {
            "schema": "allocatbelt.application-runtime-readback.v1",
            "comparison_family": "fixed_policy", "resource_domain": "owning_global_tenant",
            "feedback_policy_sha256": spec["runtime_binding"]["feedback_policy_sha256"],
            "resource_ceiling_sha256": next(cell["resource_ceiling_sha256"] for cell in spec["cells"] if cell["family"] == "cpu" and cell["profile"] == "steady"),
            "live_usage_sha256": "1" * 64, "readback_sha256": "2" * 64, "receipt_sha256": "3" * 64,
        }
        good = {**missing, "process_metrics": [{"runtime_readback": runtime_readback.copy()}, {"runtime_readback": runtime_readback.copy()}]}
        receipt = campaign.fixed_pressure_predecessor_receipt(pressure_job, good, spec)
        self.assertEqual(receipt["run_id"], "fixed-01")
        self.assertEqual(receipt["readback_receipt_sha256s"], ["3" * 64, "3" * 64])
        self.assertTrue(campaign.is_sha256(receipt["receipt_sha256"]))
        pressure_job["predecessor_run_ids"] = ["fixed-01"]
        pressure_record = {"state": "valid_pair", "job": pressure_job, "predecessor_receipts": [receipt]}
        campaign.validate_pressure_predecessor_receipts([pressure_record], [good], spec)
        tampered = {**pressure_record, "predecessor_receipts": [{**receipt, "record_sha256": "f" * 64}]}
        with self.assertRaises(campaign.CampaignError):
            campaign.validate_pressure_predecessor_receipts([tampered], [good], spec)

    def test_pair_failures_are_retained_but_refusals_and_interruptions_halt(self) -> None:
        self.assertEqual(campaign.pair_exit_disposition(0), ("valid_pair", False))
        self.assertEqual(campaign.pair_exit_disposition(1), ("failed_or_invalid_pair", False))
        self.assertEqual(campaign.pair_exit_disposition(2), ("halt_preflight_refusal", True))
        self.assertEqual(campaign.pair_exit_disposition(-15), ("halt_integrity_or_interruption", True))

    def test_process_group_watchdog_kills_a_term_ignoring_child(self) -> None:
        with tempfile.TemporaryDirectory(prefix="application-controller-ready-") as temporary:
            ready_path = Path(temporary) / "ready"
            code = (
                "import signal,sys,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "open(sys.argv[1], 'w').write('ready'); time.sleep(30)"
            )
            child = subprocess.Popen([sys.executable, "-c", code, str(ready_path)], start_new_session=True)
            try:
                for _ in range(200):
                    if ready_path.exists():
                        break
                    time.sleep(0.01)
                self.assertTrue(ready_path.exists(), "TERM-ignoring child did not install its handler")
                campaign.terminate_process_group(child, 1)
                self.assertEqual(child.returncode, -9)
            finally:
                campaign.terminate_process_group(child, 1)

    def test_process_group_watchdog_escalates_after_shell_leader_exits(self) -> None:
        with tempfile.TemporaryDirectory(prefix="application-controller-child-") as temporary:
            pid_path = Path(temporary) / "grandchild.pid"
            # Keep the child program as a separate argument to avoid quoting
            # through a shell; it ignores TERM while its parent exits cleanly.
            child_code = (
                "import os, signal, sys, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "open(sys.argv[1], 'w').write(str(os.getpid())); time.sleep(30)"
            )
            parent_code = (
                "import signal, subprocess, sys, time; "
                "signal.signal(signal.SIGTERM, lambda *_: sys.exit(0)); "
                "subprocess.Popen([sys.executable, '-c', sys.argv[2], sys.argv[1]]); time.sleep(30)"
            )
            parent = subprocess.Popen(
                [sys.executable, "-c", parent_code, str(pid_path), child_code],
                start_new_session=True,
            )
            child_pid = None
            try:
                for _ in range(200):
                    if pid_path.exists():
                        break
                    time.sleep(0.01)
                self.assertTrue(pid_path.exists(), "TERM-ignoring grandchild did not install its handler")
                child_pid = int(pid_path.read_text(encoding="ascii"))
                campaign.terminate_process_group(parent, 1)
                self.assertEqual(parent.returncode, 0)
                for _ in range(100):
                    try:
                        state = Path(f"/proc/{child_pid}/stat").read_text(encoding="ascii").split()[2]
                    except FileNotFoundError:
                        break
                    if state == "Z":
                        break
                    time.sleep(0.01)
                else:
                    self.fail("TERM-ignoring grandchild survived process-group escalation")
            finally:
                campaign.terminate_process_group(parent, 1)

    def test_phase_ledger_hash_chain_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory(prefix="application-campaign-ledger-") as temporary:
            path = Path(temporary) / "controller-ledger.jsonl"
            first = {"previous_sha256": "0" * 64, "record": {"state": "valid_pair", "ordinal": 1}}
            first_hash = campaign.hashlib.sha256(campaign.canonical_bytes(first)).hexdigest()
            second = {"previous_sha256": first_hash, "record": {"state": "failed_or_invalid_pair", "ordinal": 2}}
            second_hash = campaign.hashlib.sha256(campaign.canonical_bytes(second)).hexdigest()
            path.write_bytes(
                campaign.canonical_bytes({**first, "record_sha256": first_hash})
                + campaign.canonical_bytes({**second, "record_sha256": second_hash})
            )
            self.assertEqual(len(campaign.read_ledger(path)), 2)
            tampered = path.read_text(encoding="utf-8").replace("failed_or_invalid_pair", "valid_pair")
            path.write_text(tampered, encoding="utf-8")
            with self.assertRaises(campaign.CampaignError):
                campaign.read_ledger(path)


if __name__ == "__main__":
    unittest.main()
