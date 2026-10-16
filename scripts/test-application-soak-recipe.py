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
campaign_inputs = load_exact(SCRIPTS / "application-campaign-inputs.py", "campaign_inputs_for_soak_recipe_tests")
feedback_reader = load_exact(SCRIPTS / "application-feedback-readback.py", "feedback_reader_for_soak_recipe_tests")
campaign_test_fixtures = load_exact(SCRIPTS / "test-application-campaign.py", "campaign_test_fixtures_for_soak_recipe_tests")


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


class SourceV5CliFixture:
    """Small, fully pinned SourceV5 input set for real build/preflight CLIs.

    Its binaries and numeric collector charge are synthetic fixture values.
    Missing capacity evidence keeps both campaign readiness and launch false.
    """

    @staticmethod
    def synthetic_a48_controls() -> list[dict[str, Any]]:
        """Return a fixture-only eight-control cardinality witness (no measurements)."""
        return [{
            "control_id": f"fixture-aa-{allocator}-{executor}",
            "allocator": allocator, "executor": executor,
            "family": "mixed", "profile": "mixed",
            "mode": "capacity", "load_percent": None, "pairs": 6,
            "purpose": "synthetic A/A plan cardinality witness",
        } for allocator in builder.ALLOCATORS
          for executor in ("bounded", "tokio")]

    def __init__(
        self, temporary_root: Path, *,
        aa_controls_override: list[dict[str, Any]] | None = None,
    ):
        self.root = temporary_root / "source-v5"
        self.root.mkdir(mode=0o700)
        self.input_root = temporary_root / "input-v5"
        (self.input_root / "source").mkdir(mode=0o700, parents=True)
        self.oracle_root = temporary_root / "oracle-v5"
        self.oracle_root.mkdir(mode=0o700)
        self.output = temporary_root / "output-v5"
        self.output.mkdir(mode=0o700)
        (self.root / ".gitignore").write_text("target/\n", encoding="ascii")
        (self.root / "Cargo.lock").write_text("# bounded SourceV5 CLI fixture lock\n", encoding="ascii")

        source_paths = set(feedback_reader.CONSTRUCTION_PROBE_SOURCE_REFERENCES.values())
        source_paths.update(campaign_inputs.HARNESS_PATHS.values())
        source_paths.update({
            "Cargo.lock", "scripts/application-campaign-inputs.py",
            "scripts/application-source-inventory.py", "scripts/application-runtime-readback.py",
            campaign_inputs.FEEDBACK_RUNTIME_PATH, campaign_inputs.FEEDBACK_POLICY_PATH,
            campaign_inputs.FEEDBACK_SENSOR_PATH,
            "scripts/application-campaign.py",
            "scripts/application-byte-capacity.py",
            "scripts/application-campaign-chronology.py",
            "scripts/application-capacity-stage.py",
            "scripts/run-application-pair.sh",
            "scripts/application-fixed-pair.py",
            "scripts/application-pressure-pair.py",
            "scripts/application-source5-campaign.py",
            "scripts/application-source5-soak.py",
            "scripts/application-soak-readback.py",
            "scripts/application-source5-offline-dispatch.py",
            "scripts/application-source5-evidence-transport-v3.py",
            "scripts/application-source5-evidence-budget.py",
            "scripts/application-source5-evidence-catalogue.py",
            "scripts/application-feedback-composition.py",
            "scripts/application-feedback-readback.py",
            "scripts/application-pressure-readback.py",
        })
        for relative in sorted(source_paths, key=lambda item: item.encode("utf-8")):
            if relative == "Cargo.lock":
                continue
            source = SCRIPTS.parent / relative
            target = self.root / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            target.chmod(stat.S_IMODE(source.stat().st_mode))

        self._git(["git", "init", "-q", str(self.root)])
        self._git(["git", "-C", str(self.root), "config", "user.email", "fixture@example.invalid"])
        self._git(["git", "-C", str(self.root), "config", "user.name", "SourceV5 CLI Fixture"])
        self._git(["git", "-C", str(self.root), "add", "."])
        self._git(
            ["git", "-C", str(self.root), "commit", "-q", "-m", "bounded SourceV5 CLI fixture"],
            env={**os.environ, "GIT_AUTHOR_DATE": "2002-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2002-01-01T00:00:00Z"},
        )
        self.git_commit = self._git(["git", "-C", str(self.root), "rev-parse", "HEAD"], text=True).stdout.strip()
        self.source_tree_sha256, self.source_files = campaign.source_inventory(self.root)
        self.cargo_lock_sha256 = self._hash(self.root / "Cargo.lock")
        self.runtime_validator_sha256 = self._hash(self.root / "scripts/application-runtime-readback.py")
        self.host_ids = ("host-1", "host-2", "host-3")

        target = self.root / "target/fixture"
        target.mkdir(mode=0o700, parents=True)
        self.calibration_record = {
            "schema": campaign.CALIBRATION_SCHEMA,
            "architecture": "x86_64",
            "max_tenants": campaign.RUNTIME_FIXED_CONTROL_MAX_TENANTS,
            "max_waiters": campaign.RUNTIME_FIXED_CONTROL_MAX_WAITERS,
            "control_ceiling": campaign.RUNTIME_APPLICATION_CONTROL_CEILING,
            "fixed_global_control_baseline": 8192,
            "tenant_owner_control_bytes": 0,
            "final_live_tenants": 0,
            "final_global_control_bytes": 8192,
        }
        calibration_binary = target / "resource-domain-calibration"
        calibration_output = target / "resource-domain-calibration.json"
        write_file(calibration_binary, b"synthetic fixture calibration executable\n", 0o700)
        write_file(calibration_output, campaign.canonical_bytes(self.calibration_record))
        calibration_binary.chmod(0o700)

        harness = {
            name: {"path": relative, "sha256": self._hash(self.root / relative)}
            for name, relative in campaign_inputs.HARNESS_PATHS.items()
        }
        fixed_policy = campaign.fixed_runtime_policy_artifact(self.runtime_validator_sha256)
        feedback_policy = campaign_inputs.build_feedback_policy_artifact(self.root, self.source_files, harness)
        self.feedback_policy = feedback_policy
        probe = self._construction_probe(fixed_policy, feedback_policy)
        probe_raw = feedback_reader.canonical_bytes(probe)
        self.construction_probe_path = self.input_root / "feedback-policy-probe.json"
        write_file(self.construction_probe_path, probe_raw)
        self.construction_probe_sha256 = digest(probe_raw)

        self.artifacts: dict[str, dict[str, str]] = {}
        for allocator in builder.ALLOCATORS:
            binary_path = target / f"application-{allocator}"
            if allocator == "allocatbelt":
                code = (
                    "#!/usr/bin/env python3\nimport sys\n"
                    "expected = ['--emit-feedback-policy-only', '--workload', 'mixed', '--profile', 'mixed']\n"
                    "if sys.argv[1:] != expected: raise SystemExit(91)\n"
                    f"sys.stdout.buffer.write({probe_raw!r})\n"
                ).encode("ascii")
                write_file(binary_path, code, 0o700)
            else:
                write_file(binary_path, b"#!/bin/sh\nexit 0\n", 0o700)
            binary_path.chmod(0o700)
            self.artifacts[allocator] = {
                "path": binary_path.relative_to(self.root).as_posix(), "sha256": self._hash(binary_path),
            }
        self.soak_binary = target / "application-soak-allocatbelt"
        write_file(self.soak_binary, b"#!/bin/sh\nexit 0\n", 0o700)
        self.soak_binary.chmod(0o700)
        self.analysis_binary = target / "application-analyze"
        write_file(self.analysis_binary, b"synthetic fixture analyzer\n", 0o700)
        self.analysis_binary.chmod(0o700)

        rustc_verbose = subprocess.check_output(["rustc", "-Vv"], cwd=self.root, text=True).splitlines()
        cargo_version = subprocess.check_output(["cargo", "-V"], cwd=self.root, text=True).strip()
        rustc_release = rustc_verbose[0].split()[1]
        self.manifests: dict[str, dict[str, Any]] = {}
        self.manifest_paths: dict[str, Path] = {}
        self.manifest_raw_shas: dict[str, str] = {}
        for host_id in self.host_ids:
            build = {
                "host_id": host_id, "rustc_release": rustc_release,
                "rustc_verbose": rustc_verbose, "cargo_version": cargo_version,
                "target_triple": "x86_64-unknown-linux-gnu", "target_cpu": "x86-64-v3",
                "profile": "release", "features_sha256": "1" * 64,
                "build_inputs_sha256": "2" * 64,
            }
            calibration = {
                "binary": {"path": calibration_binary.relative_to(self.root).as_posix(), "sha256": self._hash(calibration_binary)},
                "output": {"path": calibration_output.relative_to(self.root).as_posix(), "sha256": self._hash(calibration_output)},
                "record": self.calibration_record,
                "source": {
                    "git_commit": self.git_commit, "source_tree_sha256": self.source_tree_sha256,
                    "cargo_lock_sha256": self.cargo_lock_sha256,
                },
                "build": build,
                "build_sha256": campaign.digest_object(build),
            }
            manifest = {
                "schema": campaign.SOURCE_SCHEMA_V5,
                "source": {
                    "git_commit": self.git_commit,
                    "source_tree_sha256": self.source_tree_sha256,
                    "cargo_lock_sha256": self.cargo_lock_sha256,
                    "files": self.source_files,
                },
                "build": build,
                "artifacts": self.artifacts,
                "soak_artifacts": {"allocatbelt": {
                    "path": self.soak_binary.relative_to(self.root).as_posix(),
                    "sha256": self._hash(self.soak_binary),
                }},
                "analysis_artifact": {
                    "path": self.analysis_binary.relative_to(self.root).as_posix(),
                    "sha256": self._hash(self.analysis_binary),
                },
                "fixed_runtime_policy": fixed_policy,
                "runtime_readback_validator": {
                    "path": "scripts/application-runtime-readback.py",
                    "sha256": self.runtime_validator_sha256,
                },
                "resource_domain_calibration": calibration,
                "qualification_harness": harness,
                "feedback_policy": feedback_policy,
            }
            manifest["manifest_sha256"] = campaign.digest_object(manifest)
            self.manifests[host_id] = manifest
            manifest_path = self.input_root / "source" / f"{host_id}.json"
            write_file(manifest_path, campaign.canonical_bytes(manifest))
            self.manifest_paths[host_id] = manifest_path
            self.manifest_raw_shas[host_id] = self._hash(manifest_path)

        self.spec, _old_sources = campaign_test_fixtures.spec_fixture()
        self.spec["schema"] = campaign.SPEC_SCHEMA_V3
        self.spec["campaign_id"] = "campaign-source-v5-cli-fixture"
        self.spec["runner_sha256"] = harness["soak_runner"]["sha256"]
        if aa_controls_override is not None:
            self.spec["aa_controls"] = [dict(row)
                                        for row in aa_controls_override]
        for host in self.spec["hosts"]:
            host["controls"]["cpu_set"] = str(min(os.sched_getaffinity(0)))
            host["host_fingerprint_sha256"] = digest(campaign.canonical_bytes(host["controls"]))
        self.spec["source_manifests"] = [
            {"host_id": host_id, "relative_path": f"source/{host_id}.json", "sha256": self.manifests[host_id]["manifest_sha256"]}
            for host_id in self.host_ids
        ]
        self.spec["runtime_binding"] = {
            "resource_domain": "owning_global_tenant",
            "resource_policy_sha256": fixed_policy["policy_sha256"],
            "feedback_policy_sha256": feedback_policy["policy_sha256"],
            "feedback_match": "external_same_policy",
            "source_state": "complete",
        }
        self.spec["soak"]["driver_sha256"] = harness["soak_runner"]["sha256"]
        self.spec["qualification_inputs"] = self._qualification_inputs()
        campaign_test_fixtures.add_frozen_rates(self.spec, include_oracles=True)
        self.spec_path = self.input_root / "campaign-spec.json"
        self._write_json(self.spec_path, self.spec)
        self.spec_sha256 = self._hash(self.spec_path)

        sources = dict(self.manifests)
        self.plan = campaign.freeze_plan(self.spec, sources, input_root=self.input_root)
        self.plan_path = self.input_root / "campaign-plan.json"
        self._write_json(self.plan_path, self.plan)
        self.plan_file_sha256 = self._hash(self.plan_path)
        self.plan_sha256 = self.plan["plan_sha256"]
        self.job = next(
            item for item in self.plan["jobs"]["soak"]
            if item["host_id"] == "host-1" and item["workload"] == "mixed" and item["profile"] == "mixed"
        )

        self.ring_path = self.oracle_root / "soak-reference.tsv"
        self.ring_path.write_bytes(self._ring_bytes())
        self.ring_sha256 = self._hash(self.ring_path)

    @staticmethod
    def _git(args: list[str], *, text: bool = False, env: dict[str, str] | None = None):
        return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=text, env=env, timeout=30)

    @staticmethod
    def _hash(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def _write_json(path: Path, value: dict[str, Any]) -> None:
        write_file(path, campaign.canonical_bytes(value))

    def _construction_probe(self, fixed_policy: dict[str, Any], feedback: dict[str, Any]) -> dict[str, Any]:
        context = feedback["policy"]["contexts"]["mixed/mixed"]
        workload = fixed_policy["policy"]["workloads"]["mixed"]
        global_ceilings = dict(workload["domain_ceiling"])
        global_ceilings["cpu"] = context["workers"]
        rate_buckets = {
            direction: {
                "ceiling_bytes_per_second": item["ceiling_bytes_per_second"],
                "ceiling_burst_bytes": item["ceiling_burst_bytes"],
                "max_reservations": item["max_reservations"],
            }
            for direction, item in fixed_policy["policy"]["byte_buckets"].items()
        }
        meter_model = {
            **feedback_reader.CONSTRUCTION_PROBE_METER_SOURCE_MODEL,
            "http_client_window": 8,
            "http_handler_window": 8,
        }
        return {
            "schema": feedback_reader.CONSTRUCTION_PROBE_SCHEMA,
            "context": {"workload": "mixed", "profile": "mixed", "workers": context["workers"]},
            "reader_context": {
                "version": feedback["policy"]["version"],
                **feedback["policy"]["reader_contract"],
            },
            "rust_control_context": {
                "algorithm": feedback["policy"]["algorithm"],
                "controls": context["controls"],
                "global_ceilings": global_ceilings,
                "tenant_ceilings": global_ceilings,
                "scope_limits": {
                    "managed_memory": workload["scope_limits"]["managed_memory_limit"],
                    "disk_operations": workload["scope_limits"]["disk_operation_limit"],
                    "network_operations": workload["scope_limits"]["network_operation_limit"],
                },
                "rate_buckets": rate_buckets,
                "required_byte_sources": {"disk": True, "download": True},
            },
            # Test-only synthetic composition values. The pinned campaign
            # controller deliberately keeps runtime composition unready.
            "collector": {"control_charge_bytes": 4096, "task_lease_count": 1},
            "baseline": {"expected_global_control_baseline": self.calibration_record["fixed_global_control_baseline"]},
            "meter_source_bounds": feedback_reader.meter_source_bounds_for_workload("mixed"),
            "meter_source_model": meter_model,
            "source_references": feedback_reader.CONSTRUCTION_PROBE_SOURCE_REFERENCES,
        }

    def _pin_file(self, relative: str, raw: bytes) -> dict[str, str]:
        path = self.input_root / relative
        write_file(path, raw)
        return {"relative_path": relative, "raw_sha256": digest(raw)}

    def _qualification_inputs(self) -> dict[str, Any]:
        capacities: list[dict[str, Any]] = []
        conditions: list[dict[str, Any]] = []
        templates_root = self.input_root / "qualification"
        for host_id in self.host_ids:
            for cell in self.spec["cells"]:
                workload = cell["workload"]
                profile = cell["profile"]
                suffix = f"{host_id}-{workload}-{profile}"
                calibration_id = f"capacity-{suffix}"
                request_pin = self._pin_file(
                    f"qualification/capacity/{suffix}-request.json",
                    campaign.canonical_bytes({"schema": "fixture.capacity-request.v1", "workload": workload, "profile": profile}),
                )
                context_pin = self._pin_file(
                    f"qualification/capacity/{suffix}-context.json",
                    campaign.canonical_bytes({"schema": "fixture.capacity-context.v1", "workload": workload, "profile": profile}),
                )
                capacities.append({
                    "host_id": host_id, "workload": workload, "profile": profile,
                    "calibration_id": calibration_id,
                    "calibrator": {"allocator": "allocatbelt", "executor": "bounded"},
                    "request_template": request_pin, "context_template": context_pin,
                    "evidence": None,
                })
                condition_id = f"condition-{suffix}"
                condition_schedule = {"duration_seconds": 30, "sample_interval_ms": 100, "seed": 17}
                raw_schedule = {
                    "seed": 17, "duration_seconds": 30, "sample_interval_ms": 100,
                    "startup_deadline_seconds": 10, "total_deadline_seconds": 85,
                    "term_deadline_seconds": 30, "kill_deadline_seconds": 15,
                    "minimum_overlap_seconds": 30, "startup_ready_windows": 2,
                    "cpu_duty_basis_points": 7000, "pressure_cpu_affinity": [2],
                    "application_cpu_affinity": [min(os.sched_getaffinity(0))],
                    "disk_bytes_per_second": 65_536, "scratch_file_bytes": 65_536,
                    "network_requests_per_second": 10, "network_payload_bytes": 64,
                }
                request_value = {
                    "schema": "allocatbelt.application-pressure-request.v1",
                    "identity": {
                        "host_id": host_id, "run_id": f"template-{suffix}",
                        "pair_id": f"pair-{suffix}", "condition_id": condition_id,
                        "member": "template", "nonce": "a" * 32,
                        "allocator": "allocatbelt", "executor": "allocatbelt",
                    },
                    "files": {
                        "source_manifest": {"path": "/template/source-manifest.json", "sha256": "b" * 64},
                        "application_binary": {"path": "/template/application", "sha256": "c" * 64},
                        "policy": {"path": "/template/policy.json", "sha256": "d" * 64},
                        "application_capacity_calibration": {"path": "/template/capacity.tsv", "sha256": "e" * 64},
                    },
                    "process": {"executable_path": "/template/application", "application_tmpdir_path": "/template/tmp"},
                    "storage": {
                        "application_io_paths": ["/template/work", "/template/tmp"],
                        "pressure_scratch_path": "/template/tmp", "output_minimum_free_bytes": 67_108_864,
                    },
                    "schedule": raw_schedule,
                }
                condition_pin = self._pin_file(
                    f"qualification/pressure/{suffix}-request.json", campaign.canonical_bytes(request_value),
                )
                pressure_calibration = {
                    "calibration_id": f"pressure-calibration-{suffix}",
                    "artifact": self._pin_file(
                        f"qualification/pressure/{suffix}-calibration.json",
                        campaign.canonical_bytes({"schema": "fixture.pressure-calibration.v1", "condition_id": condition_id}),
                    ),
                    "receipt": self._pin_file(
                        f"qualification/pressure/{suffix}-calibration-receipt.json",
                        campaign.canonical_bytes({"schema": "fixture.pressure-calibration-receipt.v1", "condition_id": condition_id}),
                    ),
                    "validator_sha256": self.manifests[host_id]["qualification_harness"]["pressure_validator"]["sha256"],
                }
                conditions.append({
                    "host_id": host_id, "condition_id": condition_id,
                    "condition_sha256": condition_pin["raw_sha256"],
                    "capacity_key": {
                        "host_id": host_id, "workload": workload,
                        "profile": profile, "calibration_id": calibration_id,
                    },
                    "condition": condition_pin,
                    "pressure_calibration": pressure_calibration,
                    "readiness_thresholds": {
                        "minimum_overlap_seconds": 30,
                        "minimum_ready_samples": 300,
                        "maximum_sample_gap_ms": 200,
                    },
                    "schedule": condition_schedule,
                })
        return {"capacity_templates": capacities, "pressure_conditions": conditions}

    def _ring_bytes(self) -> bytes:
        rate = 2000
        arrivals = rate * 2
        rows = [
            f"schema\t{soak_reader.RING_SCHEMA}",
            f"source_sha256\t{self.source_tree_sha256}",
            f"binary_sha256\t{self.manifests['host-1']['soak_artifacts']['allocatbelt']['sha256']}",
            "profile\tmixed", "workload\tmixed", "mode\topen_loop",
            f"average_rate_per_second\t{rate}", f"pulse_rate_per_second\t{rate}",
            f"arrivals\t{arrivals}", "trace_duration_ns\t2000000000",
            "kernel_config\tinterleave=cpu,memory,http,disk",
            "id\tscheduled_ns\tworkload\texpected_checksum",
        ]
        families = ("cpu", "memory", "http", "disk")
        rows.extend(
            f"{index}\t{index * 1_000_000_000 // rate}\t{families[index % 4]}\t{1000 + index}"
            for index in range(arrivals)
        )
        return ("\n".join(rows) + "\n").encode("ascii")


class SoakRecipeTests(unittest.TestCase):
    def test_source_v5_builder_and_parent_preflight_clis_use_full_launch_disabled_plan(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-v5-cli-") as temporary:
            fixture = SourceV5CliFixture(Path(temporary))
            recipe_path = fixture.output / "parent-recipe.json"
            build = subprocess.run(
                [
                    sys.executable, str(BUILDER_PATH), "build",
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
                    "--construction-probe", str(fixture.construction_probe_path),
                    "--construction-probe-sha256", fixture.construction_probe_sha256,
                    "--output", str(recipe_path),
                ],
                cwd="/", stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=180, check=False,
            )
            self.assertEqual(build.returncode, 0, build.stderr.decode("utf-8", errors="replace"))
            receipt = json.loads(build.stdout.decode("utf-8"))
            self.assertFalse(receipt["launch_enabled"])
            self.assertFalse(receipt["capacity_evidence_ready"])
            self.assertFalse(receipt["feedback_runtime_composition_ready"])
            recipe = json.loads(recipe_path.read_text(encoding="utf-8"))
            self.assertEqual(recipe["schema"], soak_reader.RECIPE_SCHEMA_V2)
            self.assertIsNone(recipe["pressure"]["recipe"])
            self.assertFalse(recipe["qualification"]["launch_enabled"])

            host = fixture.spec["hosts"][0]
            source = fixture.manifests[fixture.job["host_id"]]
            cell = next(
                item for item in fixture.spec["cells"]
                if item["workload"] == "mixed" and item["profile"] == "mixed"
            )
            preflight = subprocess.run(
                [
                    sys.executable, str(fixture.root / "scripts/application-soak-readback.py"), "preflight",
                    "--recipe", str(recipe_path), "--recipe-sha256", receipt["recipe_sha256"],
                    "--binary", str(fixture.soak_binary), "--output-dir", str(fixture.output),
                    "--runner-path", str(fixture.root / builder.SOAK_RUNNER_PATH),
                    "--cpu-set", host["controls"]["cpu_set"],
                    "--campaign-id", fixture.spec["campaign_id"], "--host-id", fixture.job["host_id"],
                    "--run-id", fixture.job["run_id"], "--allocator", "allocatbelt", "--executor", "bounded",
                    "--profile", "mixed", "--source-sha256", source["source"]["source_tree_sha256"],
                    "--binary-sha256", source["soak_artifacts"]["allocatbelt"]["sha256"],
                    "--resource-ceiling-sha256", cell["resource_ceiling_sha256"],
                    "--mode", "functional", "--duration-seconds", "2",
                ],
                cwd="/", stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=180, check=False,
            )
            self.assertEqual(preflight.returncode, 0, preflight.stderr.decode("utf-8", errors="replace"))
            preflight_value = json.loads(preflight.stdout.decode("utf-8"))
            self.assertFalse(preflight_value["launch_enabled"])
            self.assertTrue((fixture.output / "soak-preflight.json").is_file())

    def test_source_v5_builder_derives_same_pressure_enclosing_horizon(self):
        base_schedule = {
            "seed": 17, "duration_seconds": 30, "sample_interval_ms": 100,
            "startup_deadline_seconds": 10, "total_deadline_seconds": 85,
            "term_deadline_seconds": 30, "kill_deadline_seconds": 15,
            "minimum_overlap_seconds": 10, "startup_ready_windows": 2,
            "cpu_duty_basis_points": 8000, "pressure_cpu_affinity": [1, 3],
            "application_cpu_affinity": [0, 2], "disk_bytes_per_second": 81_920,
            "scratch_file_bytes": 4096, "network_requests_per_second": 10,
            "network_payload_bytes": 64,
        }
        request = {"schema": "allocatbelt.application-pressure-request.v1", "schedule": base_schedule}
        condition_schedule = {"duration_seconds": 30, "sample_interval_ms": 100, "seed": 17}
        result = builder._derive_v5_pressure_schedule(10_800, request, condition_schedule)
        self.assertEqual(result["application_wall_timeout_seconds"], 11_050)
        self.assertEqual(result["pressure_duration_seconds"], 11_061)
        self.assertEqual(result["pressure_schedule"]["total_deadline_seconds"], 11_116)
        reader_result = soak_reader._derive_v5_pressure_schedule(10_800, request, condition_schedule)
        self.assertEqual(result, reader_result)

    def test_source_v5_nonce_instantiation_is_bound_to_job_member_and_ordinal(self):
        template_nonce = "a" * 32
        first = builder.process_nonce(template_nonce, "campaign-1", "campaign-host-mixed-soak", "soak", 1)
        self.assertEqual(len(first), 32)
        self.assertEqual(first, builder.process_nonce(template_nonce, "campaign-1", "campaign-host-mixed-soak", "soak", 1))
        self.assertNotEqual(first, builder.process_nonce(template_nonce, "campaign-1", "campaign-host-mixed-soak-2", "soak", 1))
        self.assertNotEqual(first, builder.process_nonce(template_nonce, "campaign-1", "campaign-host-mixed-soak", "candidate", 1))
        self.assertNotEqual(first, builder.process_nonce(template_nonce, "campaign-1", "campaign-host-mixed-soak", "soak", 2))

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
