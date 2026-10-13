#!/usr/bin/env python3
"""Native tests for the prospective fixed-policy soak recipe builder."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


SCRIPTS = Path(__file__).resolve().parent
BUILDER_PATH = SCRIPTS / "application-soak-recipe.py"


def load_exact(path: Path, name: str) -> types.ModuleType:
    raw = path.read_bytes()
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ""
    exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    return module


builder = load_exact(BUILDER_PATH, "application_soak_recipe_tests")
campaign = load_exact(SCRIPTS / "application-campaign.py", "campaign_for_soak_recipe_tests")
soak_reader = load_exact(SCRIPTS / "application-soak-readback.py", "soak_reader_for_recipe_tests")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_file(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class SourceV4Fixture:
    """A real Git inventory and artifact tree with a canonical V4 manifest."""

    def __init__(self, temporary_root: Path):
        self.root = temporary_root / "source"
        self.root.mkdir(mode=0o700)
        self.input = temporary_root / "frozen-input"
        (self.input / "source").mkdir(mode=0o700, parents=True)
        self.oracle_root = temporary_root / "oracle"
        self.oracle_root.mkdir(mode=0o700)
        (self.root / ".gitignore").write_text("target/\n", encoding="ascii")
        (self.root / "Cargo.lock").write_text("# frozen SourceSchemaV4 fixture lock\n", encoding="ascii")
        (self.root / "LICENSE").write_text("fixture license\n", encoding="ascii")
        (self.root / "docs").mkdir()
        (self.root / "docs/LICENSE").symlink_to("../LICENSE")
        (self.root / "src").mkdir()
        (self.root / "src/lib.rs").write_text("pub fn fixture() {}\n", encoding="ascii")
        scripts = self.root / "scripts"
        scripts.mkdir()
        source_files = (
            "application-soak-recipe.py",
            "application-soak-readback.py",
            "application-runtime-readback.py",
            "application-source-inventory.py",
            "application-campaign.py",
            "run-application-soak.sh",
        )
        for name in source_files:
            source = SCRIPTS / name
            target = scripts / name
            shutil.copyfile(source, target)
            target.chmod(0o755 if name.endswith(".sh") else 0o644)

        self._git(["git", "init", "-q", str(self.root)])
        self._git(["git", "-C", str(self.root), "config", "user.email", "fixture@example.invalid"])
        self._git(["git", "-C", str(self.root), "config", "user.name", "Recipe Fixture"])
        self._git(["git", "-C", str(self.root), "add", "."])
        self._git(
            ["git", "-C", str(self.root), "commit", "-q", "-m", "SourceSchemaV4 recipe fixture"],
            env={**os.environ, "GIT_AUTHOR_DATE": "2001-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2001-01-01T00:00:00Z"},
        )
        self.git_commit = self._git(["git", "-C", str(self.root), "rev-parse", "HEAD"], text=True).stdout.strip()

        target = self.root / "target/fixture"
        target.mkdir(mode=0o700, parents=True)
        self.app_artifacts: dict[str, dict[str, str]] = {}
        for index, allocator in enumerate(builder.ALLOCATORS):
            artifact = target / f"application-{allocator}"
            write_file(artifact, f"fixed application producer {allocator}\n".encode(), 0o700)
            artifact.chmod(0o700)
            self.app_artifacts[allocator] = {"path": artifact.relative_to(self.root).as_posix(), "sha256": self._hash(artifact)}

        soak_binary = target / "application-soak-allocatbelt"
        write_file(soak_binary, b"candidate bounded soak artifact\n", 0o700)
        soak_binary.chmod(0o700)
        self.candidate_soak_pin = {"path": soak_binary.relative_to(self.root).as_posix(), "sha256": self._hash(soak_binary)}
        analysis_binary = target / "application-analyzer"
        write_file(analysis_binary, b"analysis artifact\n", 0o700)
        analysis_binary.chmod(0o700)
        self.analysis_pin = {"path": analysis_binary.relative_to(self.root).as_posix(), "sha256": self._hash(analysis_binary)}
        calibration_binary = target / "resource-domain-calibration"
        write_file(calibration_binary, b"independent calibration binary\n", 0o700)
        calibration_binary.chmod(0o700)

        self.runtime_validator_path = self.root / "scripts/application-runtime-readback.py"
        runtime_validator_sha = self._hash(self.runtime_validator_path)
        self.source_inventory = load_exact(self.root / builder.SOURCE_INVENTORY_PATH, "fixture_source_inventory")
        self.typed_inventory = self.source_inventory.inventory(self.root)
        self.source_files = self.typed_inventory["entries"]
        self.source_tree_sha256 = self.source_inventory.digest_inventory(self.typed_inventory)
        self.cargo_lock_sha256 = self._hash(self.root / "Cargo.lock")

        self.build_base = {
            "rustc_release": "1.99.0",
            "rustc_verbose": ["rustc 1.99.0 fixture", "host: x86_64-unknown-linux-gnu"],
            "cargo_version": "cargo 1.99.0 fixture",
            "target_triple": "x86_64-unknown-linux-gnu",
            "target_cpu": "x86-64-v3",
            "profile": "release",
            "features_sha256": "1" * 64,
            "build_inputs_sha256": "2" * 64,
        }
        self.policy = campaign.fixed_runtime_policy_artifact(runtime_validator_sha)
        self.baseline = 4096
        self.calibration_record = {
            "schema": campaign.CALIBRATION_SCHEMA,
            "architecture": "x86_64",
            "max_tenants": 1,
            "max_waiters": 256,
            "control_ceiling": 67_108_864,
            "fixed_global_control_baseline": self.baseline,
            "tenant_owner_control_bytes": 4096,
            "final_live_tenants": 0,
            "final_global_control_bytes": self.baseline,
        }
        self.calibration_output_path = target / "resource-domain-calibration.json"
        write_file(self.calibration_output_path, campaign.canonical_bytes(self.calibration_record))

        self.manifests: dict[str, dict] = {}
        self.manifest_paths: dict[str, Path] = {}
        self.manifest_shas: dict[str, str] = {}
        self.manifest_file_shas: dict[str, str] = {}
        for host_id in ("host-1", "host-2", "host-3"):
            build = {"host_id": host_id, **self.build_base}
            build_sha = campaign.digest_object(build)
            source = {
                "git_commit": self.git_commit,
                "source_tree_sha256": self.source_tree_sha256,
                "cargo_lock_sha256": self.cargo_lock_sha256,
                "files": self.source_files,
            }
            calibration = {
                "binary": {"path": calibration_binary.relative_to(self.root).as_posix(), "sha256": self._hash(calibration_binary)},
                "output": {"path": self.calibration_output_path.relative_to(self.root).as_posix(), "sha256": self._hash(self.calibration_output_path)},
                "record": self.calibration_record,
                "source": {key: source[key] for key in ("git_commit", "source_tree_sha256", "cargo_lock_sha256")},
                "build": build,
                "build_sha256": build_sha,
            }
            manifest = {
                "schema": builder.SOURCE_SCHEMA,
                "source": source,
                "build": build,
                "artifacts": self.app_artifacts,
                "soak_artifacts": {"allocatbelt": self.candidate_soak_pin},
                "analysis_artifact": self.analysis_pin,
                "fixed_runtime_policy": self.policy,
                "runtime_readback_validator": {"path": builder.RUNTIME_READBACK_PATH, "sha256": runtime_validator_sha},
                "resource_domain_calibration": calibration,
            }
            manifest["manifest_sha256"] = campaign.digest_object(manifest)
            manifest_path = self.input / "source" / f"{host_id}.json"
            write_file(manifest_path, campaign.canonical_bytes(manifest))
            self.manifests[host_id] = manifest
            self.manifest_paths[host_id] = manifest_path
            self.manifest_shas[host_id] = manifest["manifest_sha256"]
            self.manifest_file_shas[host_id] = self._hash(manifest_path)

        self.profile = "mixed"
        self.host_id = "host-1"
        self.campaign_id = "campaign-soak-recipe-v1"
        self.fixed_limits = campaign.fixed_resource_limits_for_cell("mixed", self.profile, runtime_validator_sha)
        self.ceiling_sha = digest(campaign.canonical_bytes(self.fixed_limits))
        candidate_oracle_path = self.oracle_root / "campaign-candidate-oracle.tsv"
        baseline_oracle_path = self.oracle_root / "campaign-baseline-oracle.tsv"
        write_file(candidate_oracle_path, b"frozen campaign candidate oracle fixture\n")
        write_file(baseline_oracle_path, b"frozen campaign baseline oracle fixture\n")
        self.candidate_oracle = {
            "host_id": self.host_id,
            "allocator": "allocatbelt",
            "family": "mixed",
            "profile": self.profile,
            "load_percent": 70,
            "relative_path": candidate_oracle_path.relative_to(self.oracle_root).as_posix(),
            "sha256": self._hash(candidate_oracle_path),
        }
        self.baseline_oracle = {
            "host_id": self.host_id,
            "allocator": "mimalloc-secure",
            "family": "mixed",
            "profile": self.profile,
            "load_percent": 70,
            "relative_path": baseline_oracle_path.relative_to(self.oracle_root).as_posix(),
            "sha256": self._hash(baseline_oracle_path),
        }
        self.spec = self._make_spec(runtime_validator_sha)
        self.spec_path = self.input / "campaign-spec.json"
        write_file(self.spec_path, campaign.canonical_bytes(self.spec))
        self.spec_sha256 = self._hash(self.spec_path)
        self.job = self._make_job()
        self.plan = self._make_plan()
        self.plan_path = self.input / "campaign-plan.json"
        write_file(self.plan_path, campaign.canonical_bytes(self.plan))
        self.plan_sha256 = self.plan["plan_sha256"]
        self.plan_file_sha256 = self._hash(self.plan_path)

        self.ring_path = self.oracle_root / "soak-reference.tsv"
        self.ring_raw = self._ring_bytes()
        write_file(self.ring_path, self.ring_raw)
        self.ring_sha256 = self._hash(self.ring_path)

    @staticmethod
    def _git(args: list[str], *, text: bool = False, env: dict[str, str] | None = None):
        return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=text, env=env, timeout=15)

    @staticmethod
    def _hash(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _make_spec(self, runtime_validator_sha: str) -> dict:
        hosts = []
        for index, venue in enumerate(("bare_metal", "kvm_guest", "kvm_guest"), start=1):
            controls = {
                "cpu_model": "AMD EPYC SourceSchemaV4 fixture",
                "microcode_sha256": "8" * 64,
                "kernel_release": "7.0.0 fixture",
                "governor": "performance",
                "frequency_policy": "fixed",
                "boost_policy": "enabled",
                "cpu_set": "0-7",
                "numa_policy": "node0",
                "cgroup_policy_sha256": "9" * 64,
                "background_load_policy_sha256": "a" * 64,
                "x86_64_v3_capability_sha256": "b" * 64,
                "target_triple": "x86_64-unknown-linux-gnu",
                "target_cpu": "x86-64-v3",
            }
            hosts.append({
                "host_id": f"host-{index}",
                "venue": venue,
                "host_fingerprint_sha256": digest(campaign.canonical_bytes(controls)),
                "controls": controls,
            })
        source_refs = [
            {"host_id": host_id, "relative_path": f"source/{host_id}.json", "sha256": self.manifest_shas[host_id]}
            for host_id in ("host-1", "host-2", "host-3")
        ]
        cell = {
            "family": "mixed",
            "workload": "mixed",
            "profile": self.profile,
            "arrivals": 400_000,
            "async_workers": 4,
            "resource_limits": self.fixed_limits,
            "resource_ceiling_sha256": self.ceiling_sha,
            "capacity_horizon_seconds": 30,
        }
        rate = {
            "host_id": self.host_id,
            "family": "mixed",
            "profile": self.profile,
            "load_percent": 70,
            "arrivals_per_second": 4,
            "pilot_manifest_sha256": "5" * 64,
        }
        return {
            "schema": campaign.SPEC_SCHEMA,
            "campaign_id": self.campaign_id,
            "source_manifests": source_refs,
            "runner_sha256": "6" * 64,
            "hosts": hosts,
            "cells": [cell],
            "rates": [rate],
            "oracles": [self.candidate_oracle, self.baseline_oracle],
            "protocol": {"soak_seconds": 10_800, "soak_rss_growth_percent": 5},
            "runtime_binding": {
                "resource_domain": "owning_global_tenant",
                "resource_policy_sha256": self.policy["policy_sha256"],
                "feedback_policy_sha256": "7" * 64,
                "feedback_match": "fixed_same_policy",
                "source_state": "complete",
            },
            "phase_adapters": {
                "same_executor_aa_sha256": None,
                "three_hour_soak_sha256": None,
                "simultaneous_analysis_sha256": None,
            },
            "aa_controls": [],
            "soak": {
                "workload": "mixed",
                "profile": self.profile,
                "allocator": "allocatbelt",
                "executor": "bounded",
                "driver_relative_path": builder.SOAK_RUNNER_PATH,
                "driver_sha256": self._hash(self.root / builder.SOAK_RUNNER_PATH),
                "interval_ms": 100,
            },
            "deadlines": {},
        }

    def _make_job(self) -> dict:
        run_id = f"{self.campaign_id}-{self.host_id}-mixed-mixed-fixed-open_loop-70-allocatbelt-vs-mimalloc-secure-bounded-01"
        return {
            "host_id": self.host_id,
            "phase": "confirmation",
            "family": "mixed",
            "workload": "mixed",
            "profile": self.profile,
            "mode": "open_loop",
            "load_percent": 70,
            "rate_per_second": 4,
            "arrivals": 400_000,
            "ordinal": 1,
            "comparison_family": "fixed_policy",
            "predecessor_run_ids": [],
            "allocator": "allocatbelt",
            "baseline_allocator": "mimalloc-secure",
            "comparison_kind": "allocator",
            "executor": "bounded",
            "pair_kind": "allocator-match",
            "resource_limits": self.fixed_limits,
            "resource_ceiling_sha256": self.ceiling_sha,
            "oracles": {"allocatbelt": self.candidate_oracle, "mimalloc-secure": self.baseline_oracle},
            "run_id": run_id,
        }

    def _make_plan(self) -> dict:
        jobs = []
        for index, host_id in enumerate(("host-1", "host-2", "host-3"), start=1):
            jobs.append({
                "host_id": host_id,
                "phase": "soak",
                "comparison_family": "external_pressure",
                "predecessor_run_ids": [],
                "family": "mixed",
                "workload": "mixed",
                "profile": self.profile,
                "allocator": "allocatbelt",
                "executor": "bounded",
                "run_id": f"{self.campaign_id}-{host_id}-mixed-{self.profile}-soak-allocatbelt-01",
            })
        plan = {
            "schema": campaign.PLAN_SCHEMA,
            "campaign_id": self.campaign_id,
            "spec_sha256": self.spec_sha256,
            "source_manifests": self.manifest_shas,
            "protocol": self.spec["protocol"],
            "runtime_binding": self.spec["runtime_binding"],
            "execution_ready": False,
            "full_gate_ready": False,
            "full_gate_gaps": ["functional fixture; no campaign gate is enabled"],
            "host_ids": ["host-1", "host-2", "host-3"],
            "cell_count": 1,
            "jobs": {"exploration": [], "aa": [], "confirmation": [self.job], "pressure": [], "soak": jobs},
            "runtime_process_bindings": {},
        }
        plan["plan_sha256"] = campaign.digest_object(plan, "plan_sha256")
        return plan

    def _ring_bytes(self) -> bytes:
        manifest = self.manifests[self.host_id]
        binary_sha = manifest["soak_artifacts"]["allocatbelt"]["sha256"]
        rows = [
            f"schema\t{soak_reader.RING_SCHEMA}",
            f"source_sha256\t{manifest['source']['source_tree_sha256']}",
            f"binary_sha256\t{binary_sha}",
            f"profile\t{self.profile}",
            "workload\tmixed",
            "mode\topen_loop",
            "average_rate_per_second\t4",
            "pulse_rate_per_second\t4",
            "arrivals\t8",
            "trace_duration_ns\t2000000000",
            "kernel_config\tinterleave=cpu,memory,http,disk",
            "id\tscheduled_ns\tworkload\texpected_checksum",
        ]
        families = ("cpu", "memory", "http", "disk")
        for index in range(8):
            rows.append(f"{index}\t{index * 250000000}\t{families[index % 4]}\t{1000 + index}")
        return ("\n".join(rows) + "\n").encode("ascii")

    def reseal_plan(self) -> None:
        self.plan["spec_sha256"] = digest(campaign.canonical_bytes(self.spec))
        self.plan["plan_sha256"] = campaign.digest_object(self.plan, "plan_sha256")
        self.plan_sha256 = self.plan["plan_sha256"]

    def write_inputs(self) -> None:
        self.spec_sha256 = digest(campaign.canonical_bytes(self.spec))
        self.plan["spec_sha256"] = self.spec_sha256
        self.plan["plan_sha256"] = campaign.digest_object(self.plan, "plan_sha256")
        self.plan_sha256 = self.plan["plan_sha256"]
        self.spec_path.unlink()
        write_file(self.spec_path, campaign.canonical_bytes(self.spec))
        self.plan_path.unlink()
        write_file(self.plan_path, campaign.canonical_bytes(self.plan))
        self.plan_file_sha256 = self._hash(self.plan_path)

    def build(self, *, mode: str = "functional", duration: int = 2, terminal_budget: int = 2 * 1024 * 1024, sample_budget: int = 2 * 1024 * 1024) -> dict:
        return builder.build_recipe(
            self.spec,
            self.plan,
            self.job,
            spec_sha256=self.spec_sha256,
            plan_sha256=self.plan_sha256,
            spec_path=self.spec_path,
            source_root=self.root,
            oracle_root=self.oracle_root,
            ring_relative_path=self.ring_path.relative_to(self.oracle_root).as_posix(),
            ring_sha256=self.ring_sha256,
            mode=mode,
            duration_seconds=duration,
            terminal_budget_bytes=terminal_budget,
            sample_budget_bytes=sample_budget,
        )


class SoakRecipeTests(unittest.TestCase):
    def test_stable_recipe_reads_do_not_block_on_regular_to_fifo_swap(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-recipe-fifo-") as temporary:
            root = Path(temporary)
            for name, reader in (("read", builder.read_stable), ("hash", builder.hash_file)):
                with self.subTest(helper=name):
                    path = root / f"{name}.input"
                    path.write_bytes(b"regular before open")
                    original_open = os.open
                    swapped = False

                    def swap_before_open(target, flags, *args, **kwargs):
                        nonlocal swapped
                        if Path(target) == path and not swapped:
                            path.unlink()
                            os.mkfifo(path)
                            swapped = True
                        return original_open(target, flags, *args, **kwargs)

                    with mock.patch.object(builder.os, "open", side_effect=swap_before_open):
                        with self.assertRaisesRegex(builder.RecipeBuildError, "regular"):
                            reader(path, f"{name} FIFO race fixture", 1024)
                    self.assertTrue(swapped)

    def test_real_source_v4_functional_recipe_is_deterministic_and_separate_from_pressure_job(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-recipe-") as temporary:
            fixture = SourceV4Fixture(Path(temporary))
            first = fixture.build()
            second = fixture.build()
            self.assertEqual(first["recipe_bytes"], second["recipe_bytes"])
            recipe = first["recipe"]
            self.assertEqual(recipe["schema"], "allocatbelt.application-soak-parent-recipe.v1")
            self.assertEqual(recipe["identity"]["comparison_family"], "fixed_policy")
            self.assertEqual(recipe["identity"]["run_id"], first["soak_run_id"])
            self.assertNotEqual(first["soak_run_id"], first["context_job_run_id"])
            self.assertNotEqual(first["soak_run_id"], first["planned_pressure_soak_run_id"])
            self.assertEqual(recipe["runtime"]["fixed_global_control_baseline"], fixture.baseline)
            self.assertEqual(recipe["source"]["manifest_sha256"], fixture.manifest_file_shas[fixture.host_id])
            self.assertEqual(first["source_manifest_semantic_sha256"], fixture.manifest_shas[fixture.host_id])
            self.assertEqual(first["source_manifest_file_sha256"], fixture.manifest_file_shas[fixture.host_id])
            self.assertNotEqual(recipe["source"]["manifest_sha256"], fixture.manifest_shas[fixture.host_id])
            self.assertEqual(recipe["identity"]["binary_sha256"], fixture.candidate_soak_pin["sha256"])
            self.assertEqual(recipe["oracle"]["producer_sha256"], fixture.app_artifacts["allocatbelt"]["sha256"])
            self.assertEqual(recipe["oracle"]["ring_sha256"], fixture.ring_sha256)
            self.assertFalse(first["execution_started"])
            self.assertFalse(first["qualification_enabled"])

            recipe_path = fixture.input / "built-parent-recipe.json"
            write_file(recipe_path, first["recipe_bytes"])
            reader = load_exact(fixture.root / builder.SOAK_READER_PATH, "generated_recipe_reader")
            identity_fields = (
                "campaign_id", "host_id", "run_id", "allocator", "executor", "profile",
                "source_sha256", "binary_sha256", "resource_ceiling_sha256",
            )
            audit = reader._audit_inputs(
                recipe_path,
                first["recipe_sha256"],
                {name: recipe["identity"][name] for name in identity_fields},
                fixture.root / fixture.candidate_soak_pin["path"],
                "functional",
                2,
                fixture.root / builder.SOAK_RUNNER_PATH,
                require_executing_reader_path=True,
            )
            self.assertEqual(audit["source"]["source_manifest_sha256"], fixture.manifest_file_shas[fixture.host_id])

    def test_qualified_recipe_is_only_prospective_and_keeps_10800_second_gate(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-recipe-qualified-") as temporary:
            fixture = SourceV4Fixture(Path(temporary))
            result = fixture.build(mode="qualified", duration=10_800, terminal_budget=16 * 1024**3, sample_budget=80 * 1024**2)
            self.assertEqual(result["recipe"]["runtime"]["duration_seconds"], 10_800)
            self.assertEqual(result["recipe"]["runtime"]["mode"], "qualified")
            self.assertFalse(result["execution_started"])
            self.assertFalse(result["qualification_enabled"])
            with self.assertRaisesRegex(builder.RecipeBuildError, "mode and duration"):
                fixture.build(mode="qualified", duration=2)

    def test_stale_source_manifest_pin_and_external_ring_pin_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-recipe-raw-semantic-") as temporary:
            fixture = SourceV4Fixture(Path(temporary))
            fixture.spec["source_manifests"][0]["sha256"] = fixture.manifest_file_shas[fixture.host_id]
            fixture.plan["source_manifests"][fixture.host_id] = fixture.manifest_file_shas[fixture.host_id]
            fixture.write_inputs()
            with self.assertRaisesRegex(builder.RecipeBuildError, "semantic digest differs"):
                fixture.build()

        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-recipe-stale-") as temporary:
            fixture = SourceV4Fixture(Path(temporary))
            original_plan_map = dict(fixture.plan["source_manifests"])
            fixture.plan["source_manifests"] = dict(original_plan_map)
            fixture.plan["source_manifests"][fixture.host_id] = "0" * 64
            fixture.reseal_plan()
            with self.assertRaisesRegex(builder.RecipeBuildError, "source pins differ"):
                fixture.build()
            fixture.plan["source_manifests"] = original_plan_map
            fixture.reseal_plan()
            with self.assertRaisesRegex(builder.RecipeBuildError, "independent frozen pin"):
                builder.build_recipe(
                    fixture.spec, fixture.plan, fixture.job,
                    spec_sha256=fixture.spec_sha256,
                    plan_sha256=fixture.plan_sha256,
                    spec_path=fixture.spec_path,
                    source_root=fixture.root,
                    oracle_root=fixture.oracle_root,
                    ring_relative_path=fixture.ring_path.relative_to(fixture.oracle_root).as_posix(),
                    ring_sha256="f" * 64,
                    mode="functional",
                    duration_seconds=2,
                    terminal_budget_bytes=2 * 1024 * 1024,
                    sample_budget_bytes=2 * 1024 * 1024,
                )

    def test_numeric_job_limits_and_explicit_artifact_budgets_are_checked(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-recipe-limits-") as temporary:
            fixture = SourceV4Fixture(Path(temporary))
            fixture.job["resource_limits"] = dict(fixture.fixed_limits)
            fixture.job["resource_limits"]["tasks"] -= 1
            fixture.plan["jobs"]["confirmation"][0] = fixture.job
            fixture.reseal_plan()
            with self.assertRaisesRegex(builder.RecipeBuildError, "job limits differ"):
                fixture.build()

        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-recipe-cell-limits-") as temporary:
            fixture = SourceV4Fixture(Path(temporary))
            fixture.spec["cells"][0]["resource_limits"]["tasks"] -= 1
            fixture.write_inputs()
            with self.assertRaisesRegex(builder.RecipeBuildError, "numeric fixed policy"):
                fixture.build()

        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-recipe-budget-") as temporary:
            fixture = SourceV4Fixture(Path(temporary))
            with self.assertRaisesRegex(builder.RecipeBuildError, "sample artifact budget cannot hold"):
                fixture.build(sample_budget=128)

    def test_all_application_and_declared_soak_binaries_must_be_executable(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-recipe-normal-mode-") as temporary:
            fixture = SourceV4Fixture(Path(temporary))
            normal_path = fixture.root / fixture.app_artifacts["system"]["path"]
            normal_path.chmod(0o600)
            with self.assertRaisesRegex(builder.RecipeBuildError, "application producer system is not executable"):
                fixture.build()

        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-recipe-soak-mode-") as temporary:
            fixture = SourceV4Fixture(Path(temporary))
            soak_path = fixture.root / fixture.candidate_soak_pin["path"]
            soak_path.chmod(0o600)
            with self.assertRaisesRegex(builder.RecipeBuildError, "soak artifact allocatbelt is not executable"):
                fixture.build()

    def test_non_open_loop_and_external_pressure_jobs_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-recipe-mode-") as temporary:
            fixture = SourceV4Fixture(Path(temporary))
            fixture.job["mode"] = "capacity"
            fixture.plan["jobs"]["confirmation"][0] = fixture.job
            fixture.reseal_plan()
            with self.assertRaisesRegex(builder.RecipeBuildError, "must be a frozen 70/90 open-loop"):
                fixture.build()

        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-recipe-pressure-") as temporary:
            fixture = SourceV4Fixture(Path(temporary))
            pressure_job = fixture.plan["jobs"]["soak"][0]
            with self.assertRaisesRegex(builder.RecipeBuildError, "external-pressure jobs are unsupported"):
                builder.build_recipe(
                    fixture.spec, fixture.plan, pressure_job,
                    spec_sha256=fixture.spec_sha256,
                    plan_sha256=fixture.plan_sha256,
                    spec_path=fixture.spec_path,
                    source_root=fixture.root,
                    oracle_root=fixture.oracle_root,
                    ring_relative_path=fixture.ring_path.relative_to(fixture.oracle_root).as_posix(),
                    ring_sha256=fixture.ring_sha256,
                    mode="functional",
                    duration_seconds=2,
                    terminal_budget_bytes=2 * 1024 * 1024,
                    sample_budget_bytes=2 * 1024 * 1024,
                )

    def test_cli_writes_canonical_exclusive_mode_0600_recipe_and_sha_receipt(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-recipe-cli-") as temporary:
            fixture = SourceV4Fixture(Path(temporary))
            output = Path(temporary) / "output" / "recipe.json"
            output.parent.mkdir(mode=0o700)
            command = [
                sys.executable, "-B", str(BUILDER_PATH), "build",
                "--spec", str(fixture.spec_path), "--spec-sha256", fixture.spec_sha256,
                "--plan", str(fixture.plan_path), "--plan-sha256", fixture.plan_sha256,
                "--plan-file-sha256", fixture.plan_file_sha256,
                "--job-run-id", fixture.job["run_id"],
                "--source-root", str(fixture.root), "--oracle-root", str(fixture.oracle_root),
                "--ring-relative-path", fixture.ring_path.relative_to(fixture.oracle_root).as_posix(),
                "--ring-sha256", fixture.ring_sha256,
                "--mode", "functional", "--duration-seconds", "2",
                "--terminal-budget-bytes", str(2 * 1024 * 1024),
                "--sample-budget-bytes", str(2 * 1024 * 1024),
                "--output", str(output),
            ]
            completed = subprocess.run(command, check=False, capture_output=True, timeout=30)
            self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))
            receipt = json.loads(completed.stdout)
            raw = output.read_bytes()
            recipe = json.loads(raw)
            self.assertEqual(raw, builder.canonical_bytes(recipe))
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(receipt["recipe_sha256"], digest(raw))
            self.assertEqual(receipt["source_manifest_file_sha256"], fixture.manifest_file_shas[fixture.host_id])
            self.assertEqual(receipt["source_manifest_semantic_sha256"], fixture.manifest_shas[fixture.host_id])
            self.assertNotEqual(receipt["source_manifest_file_sha256"], receipt["source_manifest_semantic_sha256"])
            self.assertFalse(receipt["execution_started"])
            self.assertFalse(receipt["qualification_enabled"])
            rerun = subprocess.run(command, check=False, capture_output=True, timeout=30)
            self.assertEqual(rerun.returncode, 2)
            self.assertEqual(output.read_bytes(), raw)

            output_inside_source = fixture.root / "target/fixture/recipe-inside-source.json"
            inside_command = list(command)
            inside_command[-1] = str(output_inside_source)
            refused = subprocess.run(inside_command, check=False, capture_output=True, timeout=30)
            self.assertEqual(refused.returncode, 2)
            self.assertIn("outside the captured source root", refused.stderr.decode(errors="replace"))
            self.assertFalse(output_inside_source.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
