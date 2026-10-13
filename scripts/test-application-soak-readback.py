#!/usr/bin/env python3
"""Native tests for the independent application-soak parent readback."""
from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from typing import Any


SCRIPT = Path(__file__).with_name("application-soak-readback.py").resolve()
HEARTBEAT_WRITER = (
    "import pathlib,sys,time; p=pathlib.Path(sys.argv[1]); n=0\n"
    "while True:\n"
    " p.write_text(str(n)); n+=1; time.sleep(0.02)\n"
)
loader = importlib.machinery.SourceFileLoader("soak_readback", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
module = importlib.util.module_from_spec(spec)
loader.exec_module(module)


def canon(value):
    return module.canonical_bytes(value)


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_private(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class Fixture:
    def __init__(self, root: Path, profile: str = "mixed", mode: str = "functional", duration: int = 2):
        self.root = root / "source"
        self.root.mkdir(mode=0o700)
        self.output = root / "output"
        self.output.mkdir(mode=0o700)
        (self.root / ".gitignore").write_text("target/\n", encoding="utf-8")
        (self.root / "Cargo.lock").write_text("# fixture lock\n", encoding="utf-8")
        (self.root / "LICENSE").write_text("fixture license\n", encoding="utf-8")
        (self.root / "docs").mkdir()
        (self.root / "docs/LICENSE").symlink_to("../LICENSE")
        (self.root / "src").mkdir()
        (self.root / "src/lib.rs").write_text("pub fn fixture() {}\n", encoding="utf-8")
        (self.root / "scripts").mkdir()
        (self.root / "scripts/application-soak-readback.py").write_bytes(SCRIPT.read_bytes())
        inventory_source, inventory_sha = module.read_stable_bytes(
            Path(__file__).with_name("application-source-inventory.py"),
            "fixture shared source inventory module",
            module.MAX_SOURCE_FILE_BYTES,
        )
        self.inventory_path = self.root / "scripts/application-source-inventory.py"
        write_private(self.inventory_path, inventory_source)
        self.assert_inventory_module_pin(inventory_sha)
        (self.root / "scripts/run-application-soak.sh").write_bytes(
            Path(__file__).with_name("run-application-soak.sh").read_bytes()
        )
        (self.root / "scripts/application-runtime-readback.py").write_text(
            "# fixture validator\n", encoding="utf-8"
        )
        self.reader_path = self.root / "scripts/application-soak-readback.py"
        self.runner_path = self.root / "scripts/run-application-soak.sh"

        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.email", "fixture@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.root), "config", "user.name", "Fixture"], check=True)
        subprocess.run(["git", "-C", str(self.root), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-q", "-m", "fixture"],
            check=True,
            env={**os.environ, "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z"},
        )
        commit = subprocess.check_output(["git", "-C", str(self.root), "rev-parse", "HEAD"], text=True).strip()

        target = self.root / "target/fixture"
        target.mkdir(mode=0o700, parents=True)
        artifacts = {}
        soak_artifacts = {}
        for allocator in module.ALLOCATORS:
            app_path = target / f"app-{allocator}"
            soak_path = target / f"soak-{allocator}"
            write_private(app_path, f"app binary {allocator}".encode(), 0o700)
            write_private(soak_path, b"#!/bin/sh\nexit 0\n", 0o700)
            os.chmod(app_path, 0o700)
            os.chmod(soak_path, 0o700)
            artifacts[allocator] = {"path": app_path.relative_to(self.root).as_posix(), "sha256": hash_file(app_path)}
            soak_artifacts[allocator] = {"path": soak_path.relative_to(self.root).as_posix(), "sha256": hash_file(soak_path)}
        self.binary = self.root / soak_artifacts["allocatbelt"]["path"]
        self.producer = self.root / artifacts["allocatbelt"]["path"]

        calibration_binary = target / "control-calibration"
        calibration_output = target / "control-calibration.json"
        write_private(calibration_binary, b"calibration binary", 0o700)
        os.chmod(calibration_binary, 0o700)

        workers = 2 if profile == "oversubscribed" else 4
        limits = {
            "managed_bytes": 1_638_536,
            "disk_ops": 8,
            "network_ops": 16,
            "tasks": module.TASK_CEILING,
            "cpu_charges": workers,
        }
        domain = {
            "cpu": workers,
            "memory": limits["managed_bytes"],
            "disk": limits["disk_ops"],
            "network": limits["network_ops"],
            "tasks": limits["tasks"],
            "control": module.CONTROL_CEILING,
        }
        scope = {
            "managed_memory_limit": limits["managed_bytes"],
            "disk_operation_limit": limits["disk_ops"],
            "network_operation_limit": limits["network_ops"],
        }
        bucket = {
            "bytes_per_second": module.RATE_BYTES_PER_SECOND,
            "ceiling_bytes_per_second": module.RATE_BYTES_PER_SECOND,
            "burst_bytes": module.RATE_BURST_BYTES,
            "ceiling_burst_bytes": module.RATE_BURST_BYTES,
            "max_reservations": module.RATE_RESERVATIONS,
        }
        buckets = {direction: dict(bucket) for direction in module.DIRECTIONS}
        policy = {
            "schema": module.POLICY_SCHEMA,
            "comparison_family": "fixed_policy",
            "resource_policy": "fixed_primary_v1",
            "logical_window": module.LOGICAL_WINDOW,
            "task_ceiling": module.TASK_CEILING,
            "workers_by_profile": {"ordinary": 4, "oversubscribed": 2},
            "workloads": {"mixed": {"domain_ceiling": domain, "scope_limits": scope}},
            "byte_buckets": buckets,
        }
        fixed_runtime_policy = {
            "schema": module.POLICY_SCHEMA,
            "policy": policy,
            "policy_sha256": digest_bytes(canon(policy)),
        }
        baseline = 4096
        calibration_record = {
            "schema": module.CALIBRATION_SCHEMA,
            "architecture": "x86_64",
            "max_tenants": module.CONTROL_MAX_TENANTS,
            "max_waiters": module.CONTROL_MAX_WAITERS,
            "control_ceiling": module.CONTROL_CEILING,
            "fixed_global_control_baseline": baseline,
            "tenant_owner_control_bytes": 4096,
            "final_live_tenants": 0,
            "final_global_control_bytes": baseline,
        }
        write_private(calibration_output, canon(calibration_record))
        analysis_binary = target / "analyzer"
        write_private(analysis_binary, b"analysis binary", 0o700)

        inventory_module = module.source_inventory_module(inventory_sha)
        typed_inventory = inventory_module.inventory(self.root)
        source_files = typed_inventory["entries"]
        self.source_files = source_files
        source_tree = inventory_module.digest_inventory(typed_inventory)
        cargo_lock_sha = hash_file(self.root / "Cargo.lock")
        build = {
            "host_id": "host-fixture",
            "rustc_release": "1.99.0",
            "rustc_verbose": ["release: 1.99.0"],
            "cargo_version": "cargo 1.99.0 fixture",
            "target_triple": "x86_64-unknown-linux-gnu",
            "target_cpu": "x86-64-v3",
            "profile": "release",
            "features_sha256": "1" * 64,
            "build_inputs_sha256": "2" * 64,
        }
        source = {
            "git_commit": commit,
            "source_tree_sha256": source_tree,
            "cargo_lock_sha256": cargo_lock_sha,
            "files": source_files,
        }
        self.source_sha = source_tree
        self.build_sha = digest_bytes(canon(build))
        self.resource_limits = limits
        self.resource_ceiling_sha = digest_bytes(canon(limits))
        self.baseline = baseline
        self.run_id = "fixture-run-01"
        self.campaign_id = "fixture-campaign"
        self.host_id = "host-fixture"
        self.profile = profile
        self.duration = duration
        self.mode = mode

        manifest = {
            "schema": module.SOURCE_SCHEMA,
            "source": source,
            "build": build,
            "artifacts": artifacts,
            "soak_artifacts": soak_artifacts,
            "analysis_artifact": {
                "path": analysis_binary.relative_to(self.root).as_posix(),
                "sha256": hash_file(analysis_binary),
            },
            "fixed_runtime_policy": fixed_runtime_policy,
            "runtime_readback_validator": {
                "path": "scripts/application-runtime-readback.py",
                "sha256": hash_file(self.root / "scripts/application-runtime-readback.py"),
            },
            "resource_domain_calibration": {
                "binary": {"path": calibration_binary.relative_to(self.root).as_posix(), "sha256": hash_file(calibration_binary)},
                "output": {"path": calibration_output.relative_to(self.root).as_posix(), "sha256": hash_file(calibration_output)},
                "record": calibration_record,
                "source": {key: source[key] for key in ("git_commit", "source_tree_sha256", "cargo_lock_sha256")},
                "build": build,
                "build_sha256": self.build_sha,
            },
        }
        manifest["manifest_sha256"] = digest_bytes(canon(manifest))
        self.manifest_path = root / "source-manifest.json"
        write_private(self.manifest_path, canon(manifest))
        self.manifest_sha = hash_file(self.manifest_path)

        self.ring_path = root / "reference.tsv"
        self.expected = list(range(10_000, 10_008))
        rate = 4
        if profile == "burst":
            pulse = rate * 4
            trace_ns = 2_000_000_000
        else:
            pulse = rate
            trace_ns = 2_000_000_000
        ring_lines = [
            f"schema\t{module.RING_SCHEMA}",
            f"source_sha256\t{self.source_sha}",
            f"binary_sha256\t{soak_artifacts['allocatbelt']['sha256']}",
            f"profile\t{profile}",
            "workload\tmixed",
            "mode\topen_loop",
            f"average_rate_per_second\t{rate}",
            f"pulse_rate_per_second\t{pulse}",
            f"arrivals\t{len(self.expected)}",
            f"trace_duration_ns\t{trace_ns}",
            "kernel_config\tinterleave=cpu,memory,http,disk",
            "id\tscheduled_ns\tworkload\texpected_checksum",
        ]
        for row_id, checksum in enumerate(self.expected):
            if profile == "burst":
                cycle, slot = divmod(row_id, rate)
                scheduled = cycle * 1_000_000_000 + slot * 250_000_000 // rate
            else:
                scheduled = row_id * 1_000_000_000 // rate
            ring_lines.append(f"{row_id}\t{scheduled}\t{module.FAMILIES[row_id % 4]}\t{checksum}")
        self.ring_bytes = ("\n".join(ring_lines) + "\n").encode("ascii")
        write_private(self.ring_path, self.ring_bytes)
        self.ring_sha = digest_bytes(self.ring_bytes)

        self.recipe = {
            "schema": module.RECIPE_SCHEMA,
            "identity": {
                "campaign_id": self.campaign_id,
                "host_id": self.host_id,
                "run_id": self.run_id,
                "nonce": "a" * 32,
                "allocator": "allocatbelt",
                "executor": "bounded",
                "workload": "mixed",
                "profile": profile,
                "comparison_family": "fixed_policy",
                "source_sha256": self.source_sha,
                "build_sha256": self.build_sha,
                "binary_sha256": soak_artifacts["allocatbelt"]["sha256"],
                "resource_ceiling_sha256": self.resource_ceiling_sha,
            },
            "source": {
                "root": str(self.root),
                "manifest_path": str(self.manifest_path),
                "manifest_sha256": self.manifest_sha,
            },
            "oracle": {
                "producer_path": str(self.producer),
                "producer_sha256": artifacts["allocatbelt"]["sha256"],
                "ring_path": str(self.ring_path),
                "ring_sha256": self.ring_sha,
            },
            "runtime": {
                "mode": mode,
                "duration_seconds": duration,
                "sample_interval_ms": module.SAMPLE_INTERVAL_MS,
                "resource_limits": limits,
                "fixed_global_control_baseline": baseline,
                "terminal_budget_bytes": 2 * 1024 * 1024,
                "sample_budget_bytes": 2 * 1024 * 1024,
            },
            "validator": {
                "path": "scripts/application-soak-readback.py",
                "sha256": hash_file(self.root / "scripts/application-soak-readback.py"),
            },
            "runner": {
                "path": "scripts/run-application-soak.sh",
                "sha256": hash_file(self.root / "scripts/run-application-soak.sh"),
            },
        }
        self.recipe_path = root / "parent-recipe.json"
        write_private(self.recipe_path, canon(self.recipe))
        self.recipe_sha = hash_file(self.recipe_path)

    @staticmethod
    def assert_inventory_module_pin(checksum: str) -> None:
        if checksum != module.SOURCE_INVENTORY_MODULE_SHA256:
            raise AssertionError("fixture inventory module hash differs from the frozen shared source helper")

    def cli_args(self) -> list[str]:
        return [
            *self.audit_cli_args(),
            "--campaign-id", self.campaign_id,
            "--host-id", self.host_id,
            "--run-id", self.run_id,
            "--allocator", "allocatbelt",
            "--executor", "bounded",
            "--profile", self.profile,
            "--source-sha256", self.source_sha,
            "--binary-sha256", self.recipe["identity"]["binary_sha256"],
            "--resource-ceiling-sha256", self.resource_ceiling_sha,
            "--mode", self.mode,
            "--duration-seconds", str(self.duration),
        ]

    def audit_cli_args(self) -> list[str]:
        return [
            "--recipe", str(self.recipe_path),
            "--recipe-sha256", self.recipe_sha,
            "--binary", str(self.binary),
            "--output-dir", str(self.output),
            "--runner-path", str(self.runner_path),
            "--cpu-set", str(min(os.sched_getaffinity(0))),
        ]

    def reseal_manifest(self, manifest: dict[str, Any]) -> None:
        manifest.pop("manifest_sha256", None)
        manifest["manifest_sha256"] = digest_bytes(canon(manifest))
        self.manifest_path.unlink()
        write_private(self.manifest_path, canon(manifest))
        self.manifest_sha = hash_file(self.manifest_path)
        self.recipe["source"]["manifest_sha256"] = self.manifest_sha
        self.recipe_path.unlink()
        write_private(self.recipe_path, canon(self.recipe))
        self.recipe_sha = hash_file(self.recipe_path)

    def audit(self):
        return module._audit_inputs(
            self.recipe_path,
            self.recipe_sha,
            {
                "campaign_id": self.campaign_id,
                "host_id": self.host_id,
                "run_id": self.run_id,
                "allocator": "allocatbelt",
                "executor": "bounded",
                "profile": self.profile,
                "source_sha256": self.source_sha,
                "binary_sha256": self.recipe["identity"]["binary_sha256"],
                "resource_ceiling_sha256": self.resource_ceiling_sha,
            },
            self.binary,
            self.mode,
            self.duration,
            self.runner_path,
        )

    def write_receipt_and_streams(self, *, child_qualified=False):
        audit = self.audit()
        ring = audit["ring"]
        source = audit["source"]
        duration_ns = self.duration * 1_000_000_000
        started = 1_000_000_000_000
        trace = started + duration_ns
        drain = trace + 20_000_000
        shutdown = drain + 1_000_000_000
        postprocess = shutdown + 40_000_000

        terminal_lines = [
            f"schema\t{module.TERMINAL_SCHEMA}",
            f"reference_ring_sha256\t{ring['sha256']}",
            f"reference_ring_rows\t{ring['rows']}",
            "\t".join(module.TERMINAL_HEADER),
        ]
        terminal_count = 12
        for global_id in range(terminal_count):
            reference_id = global_id % ring["rows"]
            checksum = ring["expected_checksums"][reference_id]
            family = module.FAMILIES[reference_id % 4]
            terminal_lines.append(
                f"{global_id}\t{reference_id}\t{family}\tcompleted\t{checksum}\t{checksum}"
            )
        terminal_bytes = ("\n".join(terminal_lines) + "\n").encode("ascii")
        write_private(self.output / "terminal-records.tsv", terminal_bytes)

        sample_lines = ["\t".join(module.SAMPLE_HEADER)]
        domain = source["domain_ceilings"]
        scope = source["scope_limits"]
        for index in range(duration_ns // module.SAMPLE_INTERVAL_NS + 1):
            row = {name: 0 for name in module.SAMPLE_HEADER}
            row["monotonic_ns"] = started + index * module.SAMPLE_INTERVAL_NS
            row["rss_kib"] = 1024
            for owner in module.OWNERS:
                for dim in module.DOMAINS:
                    row[f"{owner}_{dim}_ceiling"] = domain[dim]
                    row[f"{owner}_{dim}_limit"] = domain[dim]
                    if owner == "global" and dim == "control":
                        row[f"{owner}_{dim}_used"] = self.baseline
            row.update(
                {
                    "scope_memory_limit": scope["managed_memory_limit"],
                    "scope_disk_limit": scope["disk_operation_limit"],
                    "scope_network_limit": scope["network_operation_limit"],
                }
            )
            for direction, bucket in source["byte_buckets"].items():
                row[f"{direction}_rate_limit_bps"] = bucket["bytes_per_second"]
                row[f"{direction}_rate_burst_bytes"] = bucket["burst_bytes"]
                row[f"{direction}_rate_ceiling_bps"] = bucket["ceiling_bytes_per_second"]
                row[f"{direction}_rate_ceiling_burst_bytes"] = bucket["ceiling_burst_bytes"]
                row[f"{direction}_rate_max_reservations"] = bucket["max_reservations"]
                row[f"{direction}_rate_available_bytes"] = bucket["burst_bytes"]
            sample_lines.append("\t".join(str(row[name]) for name in module.SAMPLE_HEADER))
        sample_bytes = ("\n".join(sample_lines) + "\n").encode("ascii")
        write_private(self.output / "resource-samples.tsv", sample_bytes)

        identity = audit["identity"]
        receipt = {
            "schema": module.RUNTIME_SOAK_SCHEMA,
            "campaign_id": identity["campaign_id"],
            "host_id": identity["host_id"],
            "run_id": identity["run_id"],
            "nonce": identity["nonce"],
            "allocator": identity["allocator"],
            "executor": identity["executor"],
            "workload": "mixed",
            "profile": self.profile,
            "comparison_family": "fixed_policy",
            "source_sha256": identity["source_sha256"],
            "binary_sha256": identity["binary_sha256"],
            "resource_ceiling_sha256": identity["resource_ceiling_sha256"],
            "reference_ring_sha256": ring["sha256"],
            "reference_ring_rows": ring["rows"],
            "reference_average_rate_per_second": ring["average_rate_per_second"],
            "duration_seconds": self.duration,
            "sample_interval_ms": module.SAMPLE_INTERVAL_MS,
            "warmup_seconds": module.WARMUP_SECONDS,
            "logical_window": module.LOGICAL_WINDOW,
            "attempted": terminal_count,
            "completed": terminal_count,
            "errors": 0,
            "lost": 0,
            "terminal_records": terminal_count,
            "terminal_stream_sha256": digest_bytes(terminal_bytes),
            "terminal_stream_relative_path": "terminal-records.tsv",
            "resource_samples_count": duration_ns // module.SAMPLE_INTERVAL_NS + 1,
            "resource_samples_sha256": digest_bytes(sample_bytes),
            "resource_samples_relative_path": "resource-samples.tsv",
            "first_post_warmup_hour_rss_median_kib": None,
            "final_hour_rss_median_kib": None,
            "qualified_horizon": child_qualified,
            "started_monotonic_ns": started,
            "trace_ended_monotonic_ns": trace,
            "drain_ended_monotonic_ns": drain,
            "shutdown_ended_monotonic_ns": shutdown,
            "postprocess_ended_monotonic_ns": postprocess,
            "ended_monotonic_ns": postprocess,
            "actual_trace_duration_ns": duration_ns,
            "drain_duration_ns": drain - trace,
            "shutdown_duration_ns": shutdown - drain,
            "postprocess_after_shutdown_ns": postprocess - shutdown,
            "production_cpu_started_ns": 5_000_000,
            "production_cpu_ended_ns": 9_000_000,
            "production_cpu_ns": 4_000_000,
            "final_global_live_tenants": 0,
            "final_global_cpu_used": 0,
            "final_global_memory_used": 0,
            "final_global_disk_used": 0,
            "final_global_network_used": 0,
            "final_global_tasks_used": 0,
            "final_global_control_used": self.baseline,
            "fixed_global_control_baseline": self.baseline,
            "final_tenant_cpu_used": 0,
            "final_tenant_memory_used": 0,
            "final_tenant_disk_used": 0,
            "final_tenant_network_used": 0,
            "final_tenant_tasks_used": 0,
            "final_tenant_control_used": 0,
            "final_scope_memory_used": 0,
            "final_scope_disk_used": 0,
            "final_scope_network_used": 0,
        }
        write_private(self.output / "soak-receipt.json", json.dumps(receipt, separators=(",", ":")).encode("ascii"))
        return receipt, terminal_bytes, sample_bytes


class SoakReadbackTests(unittest.TestCase):
    def test_run_checked_bounds_capture_and_reaps_timeout_and_orphan_groups(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-checked-") as temp:
            root = Path(temp)
            with self.assertRaisesRegex(module.SoakReadbackError, "stdout exceeded its 128-byte capture bound"):
                module._run_checked(
                    [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 4096)"],
                    root,
                    "bounded capture fixture",
                    timeout=3,
                    stdout_limit=128,
                )

            timed_heartbeat = root / "timed.heartbeat"
            timeout_code = (
                "import pathlib,signal,subprocess,sys,time; "
                "subprocess.Popen([sys.executable,'-c',sys.argv[2],sys.argv[1]]); "
                "signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)"
            )
            with self.assertRaisesRegex(module.SoakReadbackError, "deadline"):
                module._run_checked(
                    [sys.executable, "-c", timeout_code, str(timed_heartbeat), HEARTBEAT_WRITER],
                    root,
                    "timed group fixture",
                    timeout=0.35,
                )
            self.assertTrue(self._wait_heartbeat_stopped(timed_heartbeat))

            orphan_heartbeat = root / "orphan.heartbeat"
            leader_exit_code = (
                "import pathlib,subprocess,sys,time; "
                "subprocess.Popen([sys.executable,'-c',sys.argv[2],sys.argv[1]]); "
                "p=pathlib.Path(sys.argv[1]); deadline=time.monotonic()+2; "
                "exec('while not p.exists() and time.monotonic()<deadline: time.sleep(0.01)')"
            )
            self.assertEqual(
                module._run_checked(
                    [sys.executable, "-c", leader_exit_code, str(orphan_heartbeat), HEARTBEAT_WRITER],
                    root,
                    "leader-exit group fixture",
                    timeout=3,
                ),
                b"",
            )
            self.assertTrue(self._wait_heartbeat_stopped(orphan_heartbeat))

    def test_run_checked_reaps_its_group_when_interrupted(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-checked-signal-") as temp:
            root = Path(temp)
            heartbeat = root / "signal.heartbeat"
            child_code = (
                "import subprocess,sys,time; "
                "subprocess.Popen([sys.executable,'-c',sys.argv[2],sys.argv[1]]); "
                "time.sleep(60)"
            )
            wrapper = root / "checked-signal-wrapper.py"
            wrapper.write_text(
                "import importlib.machinery,importlib.util,sys\n"
                "loader=importlib.machinery.SourceFileLoader('signal_checked',sys.argv[1])\n"
                "spec=importlib.util.spec_from_loader(loader.name,loader)\n"
                "module=importlib.util.module_from_spec(spec); loader.exec_module(module)\n"
                "try:\n"
                f" module._run_checked([sys.executable,'-c',{child_code!r},sys.argv[2],{HEARTBEAT_WRITER!r}],"
                " __import__('pathlib').Path(sys.argv[4]),'signal checked fixture',timeout=30)\n"
                "except module.SoakReadbackError:\n"
                " raise SystemExit(42)\n",
                encoding="utf-8",
            )
            process = subprocess.Popen(
                [sys.executable, "-B", str(wrapper), str(SCRIPT), str(heartbeat), HEARTBEAT_WRITER, str(root)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            deadline = time.monotonic() + 3
            while not heartbeat.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(heartbeat.exists(), "checked helper child did not start before its watchdog")
            process.send_signal(signal.SIGTERM)
            _stdout, stderr = process.communicate(timeout=3)
            self.assertEqual(process.returncode, 42, stderr.decode(errors="replace"))
            self.assertTrue(self._wait_heartbeat_stopped(heartbeat))

    def test_run_checked_bounds_capture_drain_for_escaped_pipe_holder(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-escaped-pipe-") as temp:
            root = Path(temp)
            pid_path = root / "escaped.pid"
            escaped_code = (
                "import os,pathlib,signal,sys,time; os.setsid(); "
                "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); "
                "signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)"
            )
            leader_code = (
                "import pathlib,subprocess,sys,time; "
                "subprocess.Popen([sys.executable,'-c',sys.argv[2],sys.argv[1]]); "
                "deadline=time.monotonic()+2; p=pathlib.Path(sys.argv[1]); "
                "exec('while not p.exists() and time.monotonic()<deadline: time.sleep(0.01)')"
            )
            started = time.monotonic()
            try:
                with self.assertRaisesRegex(module.SoakReadbackError, "capture pipe.*remained open.*output is incomplete"):
                    module._run_checked(
                        [sys.executable, "-c", leader_code, str(pid_path), escaped_code],
                        root,
                        "escaped pipe holder fixture",
                        timeout=3,
                    )
                self.assertLess(
                    time.monotonic() - started,
                    2.0,
                    "captured-pipe drain exceeded the bounded cleanup deadline",
                )
                escaped_pid = int(pid_path.read_text(encoding="ascii"))
                os.kill(escaped_pid, signal.SIGKILL)
                self.assertTrue(self._wait_process_stopped(escaped_pid))
            finally:
                if pid_path.exists():
                    try:
                        os.kill(int(pid_path.read_text(encoding="ascii")), signal.SIGKILL)
                    except (ProcessLookupError, ValueError):
                        pass

    def test_stable_input_closes_descriptor_when_post_open_validation_fails(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-stable-input-") as temp:
            path = Path(temp) / "oversized"
            path.write_bytes(b"one byte")
            source = module.StableInput(path, "oversized fixture", maximum=1)
            with self.assertRaisesRegex(module.SoakReadbackError, "finite byte bound"):
                source.__enter__()
            self.assertIsNone(source.fd)
            self.assertIsNone(source.stream)

    def test_stable_input_never_blocks_on_regular_to_fifo_swap(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-stable-fifo-") as temp:
            path = Path(temp) / "swapped-input"
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

            source = module.StableInput(path, "FIFO swap fixture", maximum=1024)
            with mock.patch.object(module.os, "open", side_effect=swap_before_open):
                with self.assertRaisesRegex(module.SoakReadbackError, "descriptor is not a regular file"):
                    source.__enter__()
            self.assertTrue(swapped)
            self.assertIsNone(source.fd)
            self.assertIsNone(source.stream)

    def test_functional_recipe_preflights_and_never_promotes_child_flag(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-readback-") as temp:
            fixture = Fixture(Path(temp))
            command = [sys.executable, "-B", str(fixture.reader_path), "preflight", *fixture.cli_args()]
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            preflight_json = json.loads(result.stdout)
            self.assertEqual(preflight_json["mode"], "functional")
            self.assertEqual(preflight_json["duration_seconds"], 2)

            audit = fixture.audit()
            symlink_record = next(
                entry for entry in fixture.source_files
                if entry["path"] == "docs/LICENSE"
            )
            self.assertEqual(
                symlink_record,
                {
                    "path": "docs/LICENSE",
                    "kind": "symlink",
                    "mode": "120000",
                    "target": "../LICENSE",
                    "sha256": digest_bytes(b"../LICENSE"),
                    "size": len(b"../LICENSE"),
                },
            )
            descriptor = module._make_launch_descriptor(
                audit, fixture.output, str(min(os.sched_getaffinity(0)))
            )
            altered_argv = [*descriptor["argv"], "--unfrozen-argument"]
            rejected_argv = subprocess.run(
                [
                    sys.executable, "-B", str(fixture.reader_path), "launch",
                    *fixture.audit_cli_args(),
                    "--preflight", str(fixture.output / "soak-preflight.json"),
                    "--timeout-seconds", "5",
                    "--term-grace-seconds", "0.25",
                    "--terminal-path", str(fixture.output / "terminal-records.tsv"),
                    "--samples-path", str(fixture.output / "resource-samples.tsv"),
                    "--", *altered_argv,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(rejected_argv.returncode, 0)
            self.assertIn("actual candidate command/argv differs", rejected_argv.stderr)
            self.assertFalse((fixture.output / "stdout.log").exists())

            launch = subprocess.run(
                [
                    sys.executable, "-B", str(fixture.reader_path), "launch",
                    *fixture.audit_cli_args(),
                    "--preflight", str(fixture.output / "soak-preflight.json"),
                    "--timeout-seconds", "5",
                    "--term-grace-seconds", "0.25",
                    "--terminal-path", str(fixture.output / "terminal-records.tsv"),
                    "--samples-path", str(fixture.output / "resource-samples.tsv"),
                    "--", *descriptor["argv"],
                ],
                capture_output=True,
                text=True,
                check=False,
                env={**os.environ, "ALLOCATBELT_SOAK_PROFILE": "untrusted-child-override"},
            )
            self.assertEqual(launch.returncode, 0, launch.stderr)
            launch_summary = json.loads(launch.stdout)
            self.assertEqual(launch_summary["exit_code"], 0)
            launch_receipt = json.loads((fixture.output / "soak-launch.json").read_text(encoding="utf-8"))
            self.assertEqual(launch_receipt["requested_argv"], descriptor["argv"])
            self.assertEqual(launch_receipt["environment"], descriptor["environment"])
            self.assertEqual(launch_receipt["environment"]["ALLOCATBELT_SOAK_PROFILE"], "mixed")
            self.assertEqual(launch_receipt["executed_argv"], descriptor["argv"])
            self.assertTrue(launch_receipt["executed_file_descriptor"].startswith("/proc/self/fd/"))

            receipt, _, _ = fixture.write_receipt_and_streams(child_qualified=True)
            self.assertTrue(receipt["qualified_horizon"])
            verify = subprocess.run(
                [
                    sys.executable, "-B", str(fixture.reader_path), "verify-inputs",
                    *fixture.audit_cli_args(),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(verify.returncode, 0, verify.stderr)
            validated = subprocess.run(
                [
                    sys.executable, "-B", str(fixture.reader_path), "validate",
                    *fixture.audit_cli_args(),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(validated.returncode, 0, validated.stderr)
            result_doc = json.loads((fixture.output / "soak-readback.json").read_text(encoding="utf-8"))
            self.assertTrue(result_doc["validated"])
            self.assertFalse(result_doc["qualification_eligible"])
            self.assertTrue(result_doc["child_qualified_horizon"])

            (fixture.output / "soak-launch.json").unlink()
            missing_launch = subprocess.run(
                [sys.executable, "-B", str(fixture.reader_path), "validate", *fixture.audit_cli_args()],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(missing_launch.returncode, 0)
            self.assertIn("parent launch receipt is missing", missing_launch.stderr)

    def test_terminal_expected_values_are_checked_against_external_ring(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-ring-") as temp:
            fixture = Fixture(Path(temp))
            audit = fixture.audit()
            receipt, terminal_bytes, _ = fixture.write_receipt_and_streams()
            lines = terminal_bytes.decode("ascii").splitlines()
            fields = lines[4].split("\t")
            fields[5] = str(int(fields[5]) + 1)
            fields[4] = fields[5]
            lines[4] = "\t".join(fields)
            bad_terminals = ("\n".join(lines) + "\n").encode("ascii")
            terminal_path = fixture.output / "terminal-records.tsv"
            terminal_path.unlink()
            write_private(terminal_path, bad_terminals)
            receipt["terminal_stream_sha256"] = digest_bytes(bad_terminals)
            receipt_path = fixture.output / "soak-receipt.json"
            receipt_path.unlink()
            write_private(receipt_path, json.dumps(receipt, separators=(",", ":")).encode("ascii"))
            with self.assertRaisesRegex(module.SoakReadbackError, "pinned external ring"):
                module._parse_terminal_stream(terminal_path, receipt, audit["ring"], fixture.recipe["runtime"]["terminal_budget_bytes"])

    def test_resource_limits_and_credit_conservation_are_checked(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-sample-") as temp:
            fixture = Fixture(Path(temp))
            audit = fixture.audit()
            receipt, _, sample_bytes = fixture.write_receipt_and_streams()
            rows = sample_bytes.decode("ascii").splitlines()
            fields = rows[1].split("\t")
            header = rows[0].split("\t")
            available = header.index("disk_rate_available_bytes")
            fields[available] = str(module.RATE_BURST_BYTES)
            reserved = header.index("disk_rate_reserved_bytes")
            fields[reserved] = "1"
            rows[1] = "\t".join(fields)
            bad_samples = ("\n".join(rows) + "\n").encode("ascii")
            sample_path = fixture.output / "resource-samples.tsv"
            sample_path.unlink()
            write_private(sample_path, bad_samples)
            receipt["resource_samples_sha256"] = digest_bytes(bad_samples)
            with self.assertRaisesRegex(module.SoakReadbackError, "credit is not conserved"):
                module._parse_samples(sample_path, receipt, audit, fixture.recipe["runtime"]["sample_budget_bytes"])

    def test_qualified_recipe_cannot_use_a_short_horizon_and_rss_windows_are_exact(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-qualified-") as temp:
            fixture = Fixture(Path(temp), mode="qualified", duration=2)
            recipe = fixture.recipe
            with self.assertRaisesRegex(module.SoakReadbackError, "exactly 10,800"):
                module._validate_recipe(recipe, fixture.recipe_sha)
        first = final = 0
        for index in range(QUALIFIED_COUNT := 108_001):
            window = module.rss_window_for_index(index)
            first += window == "first_post_warmup_hour"
            final += window == "final_hour"
        self.assertEqual(QUALIFIED_COUNT, 108_001)
        self.assertEqual(first, 36_000)
        self.assertEqual(final, 36_000)
        self.assertEqual(module.rss_window_for_index(2999), None)
        self.assertEqual(module.rss_window_for_index(3000), "first_post_warmup_hour")
        self.assertEqual(module.rss_window_for_index(38_999), "first_post_warmup_hour")
        self.assertEqual(module.rss_window_for_index(39_000), None)
        self.assertEqual(module.rss_window_for_index(72_000), "final_hour")
        self.assertEqual(module.rss_window_for_index(108_000), None)
        self.assertEqual(module.rss_window_for_index(108_001), None)

    def test_final_rss_endpoint_cannot_mask_growth_past_five_percent(self):
        first_values = []
        final_values = []
        for index in range(108_001):
            window = module.rss_window_for_index(index)
            if window == "first_post_warmup_hour":
                first_values.append(100)
            elif window == "final_hour":
                final_values.append(105 if len(final_values) < 18_000 else 106)
        endpoint_value = 105
        self.assertIsNone(module.rss_window_for_index(108_000))
        self.assertEqual(len(first_values), 36_000)
        self.assertEqual(len(final_values), 36_000)
        self.assertEqual(module._upper_median(first_values), 100)
        self.assertEqual(module._upper_median(final_values + [endpoint_value]), 105)
        self.assertEqual(module._upper_median(final_values), 106)
        self.assertFalse(module._upper_median(final_values) * 100 <= 100 * 105)

    def test_terminal_storage_budget_is_frozen_and_growth_stops_before_completion(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-budget-") as temp:
            fixture = Fixture(Path(temp))
            recipe = dict(fixture.recipe)
            recipe["runtime"] = dict(fixture.recipe["runtime"])
            recipe["runtime"]["terminal_budget_bytes"] = module.MAX_TERMINAL_BYTES + 1
            with self.assertRaisesRegex(module.SoakReadbackError, "global parser ceiling"):
                module._validate_recipe(recipe, fixture.recipe_sha)

            output = Path(temp) / "launch-output"
            output.mkdir(mode=0o700)
            terminal = output / "terminal-records.tsv"
            writer = (
                "import pathlib,sys,time; p=pathlib.Path(sys.argv[1]); "
                "f=p.open('ab',buffering=0); "
                "exec('while True:\\n f.write(b\\\"x\\\"*64)\\n time.sleep(0.005)')"
            )
            status = module.launch_process(
                [sys.executable, "-c", writer, str(terminal)],
                str(min(os.sched_getaffinity(0))),
                output / "stdout.log",
                output / "stderr.log",
                output / "time.txt",
                timeout_seconds=5,
                term_grace_seconds=0.2,
                monitored_files=((terminal, 128),),
            )
            self.assertEqual(status, 125)
            self.assertGreater(terminal.stat().st_size, 128)
            self.assertTrue((output / "stdout.log").exists())
            self.assertTrue((output / "stderr.log").exists())

    def test_parent_recipe_source_manifest_and_ring_pins_are_not_self_echoes(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-parent-pins-") as temp:
            fixture = Fixture(Path(temp))
            audit = fixture.audit()
            self.assertEqual(set(audit["source"]["normal_application_artifacts"]), set(module.ALLOCATORS))
            self.assertEqual(set(audit["source"]["declared_soak_artifacts"]), set(module.ALLOCATORS))
            self.assertNotEqual(
                audit["source"]["candidate_binary_sha256"],
                audit["source"]["oracle_producer_binary_sha256"],
            )
            self.assertEqual(audit["ring"]["sha256"], fixture.recipe["oracle"]["ring_sha256"])
            changed = bytearray(fixture.ring_bytes)
            changed[-3] ^= 1
            fixture.ring_path.write_bytes(changed)
            with self.assertRaisesRegex(module.SoakReadbackError, "pre-run SHA pin"):
                fixture.audit()

    def test_soak_source_map_requires_candidate_and_validates_each_optional_pin(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-map-") as temp:
            fixture = Fixture(Path(temp))
            manifest = json.loads(fixture.manifest_path.read_text(encoding="utf-8"))
            manifest["soak_artifacts"] = {"allocatbelt": manifest["soak_artifacts"]["allocatbelt"]}
            fixture.reseal_manifest(manifest)
            audit = fixture.audit()
            self.assertEqual(set(audit["source"]["declared_soak_artifacts"]), {"allocatbelt"})

            manifest = json.loads(fixture.manifest_path.read_text(encoding="utf-8"))
            optional_system_path = fixture.root / "target/fixture/soak-system"
            manifest["soak_artifacts"] = {
                "allocatbelt": manifest["soak_artifacts"]["allocatbelt"],
                "system": {
                    "path": optional_system_path.relative_to(fixture.root).as_posix(),
                    "sha256": hash_file(optional_system_path),
                },
            }
            fixture.reseal_manifest(manifest)
            audit = fixture.audit()
            self.assertEqual(set(audit["source"]["declared_soak_artifacts"]), {"allocatbelt", "system"})
            optional_system_path.write_bytes(b"changed optional soak binary")
            with self.assertRaisesRegex(module.SoakReadbackError, "system soak binary"):
                fixture.audit()

            manifest["soak_artifacts"] = {"system": manifest["soak_artifacts"]["system"]}
            fixture.reseal_manifest(manifest)
            with self.assertRaisesRegex(module.SoakReadbackError, "require allocatbelt"):
                fixture.audit()

    def test_all_four_application_binary_pins_are_verified(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-app-map-") as temp:
            fixture = Fixture(Path(temp))
            source = json.loads(fixture.manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(set(source["artifacts"]), set(module.ALLOCATORS))
            path = fixture.root / source["artifacts"]["mimalloc-standard"]["path"]
            path.write_bytes(b"changed pinned application artifact")
            with self.assertRaisesRegex(module.SoakReadbackError, "mimalloc-standard application binary differs"):
                fixture.audit()

    def test_calibration_output_bytes_must_equal_the_canonical_manifest_record(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-calibration-") as temp:
            fixture = Fixture(Path(temp))
            manifest = json.loads(fixture.manifest_path.read_text(encoding="utf-8"))
            output_path = fixture.root / manifest["resource_domain_calibration"]["output"]["path"]
            altered = dict(manifest["resource_domain_calibration"]["record"])
            altered["fixed_global_control_baseline"] += 1
            altered["final_global_control_bytes"] = altered["fixed_global_control_baseline"]
            output_path.write_bytes(canon(altered))
            manifest["resource_domain_calibration"]["output"]["sha256"] = hash_file(output_path)
            fixture.reseal_manifest(manifest)
            with self.assertRaisesRegex(module.SoakReadbackError, "output record differs"):
                fixture.audit()

    def test_shell_runner_refuses_missing_parent_recipe_before_creating_output(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-shell-") as temp:
            output = Path(temp) / "not-created"
            env = dict(os.environ)
            env.pop("ALLOCATBELT_SOAK_PARENT_RECIPE", None)
            env.pop("ALLOCATBELT_SOAK_PARENT_RECIPE_SHA256", None)
            command = [
                "bash",
                str(Path(__file__).with_name("run-application-soak.sh")),
                "/bin/true",
                "allocatbelt",
                "bounded",
                "mixed",
                str(min(os.sched_getaffinity(0))),
                "campaign-test",
                "host-test",
                "run-test-01",
                str(output),
                "1" * 64,
                "2" * 64,
                "3" * 64,
            ]
            result = subprocess.run(command, capture_output=True, text=True, env=env, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertIn("missing SHA-pinned parent soak recipe", result.stderr)
            self.assertFalse(output.exists())

    @staticmethod
    def _wait_heartbeat_stopped(path: Path, timeout: float = 3.0) -> bool:
        """Confirm a descendant's observable work stops, independent of PID reuse."""
        deadline = time.monotonic() + timeout
        previous: str | None = None
        unchanged_since: float | None = None
        while time.monotonic() < deadline:
            try:
                current = path.read_text(encoding="ascii")
            except (FileNotFoundError, UnicodeError):
                current = None
            now = time.monotonic()
            if current is not None and current == previous:
                if unchanged_since is not None and now - unchanged_since >= 0.2:
                    return True
            else:
                previous = current
                unchanged_since = now
            time.sleep(0.02)
        return False

    @staticmethod
    def _wait_process_stopped(pid: int, timeout: float = 2.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                stat_line = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
            except FileNotFoundError:
                return True
            state = stat_line.rsplit(")", 1)[-1].strip().split(" ", 1)[0]
            if state == "Z":
                return True
            time.sleep(0.02)
        return False

    def test_timeout_escalates_and_kills_descendants_in_the_launch_group(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-timeout-") as temp:
            root = Path(temp)
            output = root / "out"
            output.mkdir(mode=0o700)
            pid_file = root / "grandchild.pid"
            heartbeat = root / "grandchild.heartbeat"
            child_code = (
                "import pathlib,signal,subprocess,sys,time; "
                "p=subprocess.Popen([sys.executable,'-c',sys.argv[3],sys.argv[2]]); "
                "pathlib.Path(sys.argv[1]).write_text(str(p.pid)); "
                "signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)"
            )
            status = module.launch_process(
                [sys.executable, "-c", child_code, str(pid_file), str(heartbeat), HEARTBEAT_WRITER],
                str(min(os.sched_getaffinity(0))),
                output / "stdout.log",
                output / "stderr.log",
                output / "time.txt",
                timeout_seconds=0.3,
                term_grace_seconds=0.2,
            )
            self.assertEqual(status, 124)
            self.assertTrue(pid_file.exists())
            self.assertTrue(heartbeat.exists())
            self.assertTrue(self._wait_heartbeat_stopped(heartbeat))

    def test_early_signal_uses_its_own_escalation_clock(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-signal-") as temp:
            root = Path(temp)
            output = root / "out"
            output.mkdir(mode=0o700)
            pid_file = root / "grandchild.pid"
            heartbeat = root / "grandchild.heartbeat"
            child_code = (
                "import pathlib,signal,subprocess,sys,time; "
                "p=subprocess.Popen([sys.executable,'-c',sys.argv[3],sys.argv[2]]); "
                "pathlib.Path(sys.argv[1]).write_text(str(p.pid)); "
                "signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)"
            )
            wrapper_script = root / "signal-wrapper.py"
            wrapper_script.write_text(
                "import importlib.machinery,importlib.util,sys\n"
                "from pathlib import Path\n"
                "loader=importlib.machinery.SourceFileLoader('signal_readback',sys.argv[1])\n"
                "spec=importlib.util.spec_from_loader(loader.name,loader)\n"
                "module=importlib.util.module_from_spec(spec)\n"
                "loader.exec_module(module)\n"
                "output=Path(sys.argv[2]); cpu_set=sys.argv[3]\n"
                f"child_code={child_code!r}\n"
                "status=module.launch_process([sys.executable,'-c',child_code,sys.argv[4],sys.argv[5],sys.argv[6]],"
                "cpu_set,output/'stdout.log',output/'stderr.log',output/'time.txt',"
                "timeout_seconds=30,term_grace_seconds=0.25)\n"
                "raise SystemExit(status)\n",
                encoding="utf-8",
            )
            command = [
                sys.executable, "-B", str(wrapper_script), str(SCRIPT), str(output),
                str(min(os.sched_getaffinity(0))), str(pid_file), str(heartbeat), HEARTBEAT_WRITER,
            ]
            wrapper = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            deadline = time.monotonic() + 3.0
            while not (pid_file.exists() and heartbeat.exists()) and time.monotonic() < deadline:
                time.sleep(0.02)
            if not (pid_file.exists() and heartbeat.exists()):
                wrapper.send_signal(signal.SIGTERM)
                _wrapper_stdout, wrapper_stderr = wrapper.communicate(timeout=3.0)
                detail = (output / "stderr.log").read_text(encoding="utf-8", errors="replace") if (output / "stderr.log").exists() else ""
                self.fail(f"child did not launch before the test watchdog: {detail}; launcher={wrapper_stderr.decode(errors='replace')}")
            started = time.monotonic()
            wrapper.send_signal(signal.SIGTERM)
            stdout, stderr = wrapper.communicate(timeout=3.0)
            self.assertEqual(wrapper.returncode, 128 + signal.SIGTERM, stderr.decode(errors="replace"))
            self.assertLess(time.monotonic() - started, 2.0, "early signal waited for the original 30-second launch deadline")
            self.assertTrue(self._wait_heartbeat_stopped(heartbeat))
            self.assertTrue((output / "stdout.log").exists())
            self.assertTrue((output / "stderr.log").exists())
            self.assertTrue((output / "time.txt").exists())

    def test_leader_exit_still_cleans_a_surviving_descendant(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-orphan-") as temp:
            root = Path(temp)
            output = root / "out"
            output.mkdir(mode=0o700)
            pid_file = root / "grandchild.pid"
            heartbeat = root / "grandchild.heartbeat"
            child_code = (
                "import pathlib,subprocess,sys,time; "
                "p=subprocess.Popen([sys.executable,'-c',sys.argv[3],sys.argv[2]]); "
                "pathlib.Path(sys.argv[1]).write_text(str(p.pid)); "
                "deadline=time.monotonic()+2; heartbeat=pathlib.Path(sys.argv[2]); "
                "exec('while not heartbeat.exists() and time.monotonic()<deadline: time.sleep(0.01)')"
            )
            status = module.launch_process(
                [sys.executable, "-c", child_code, str(pid_file), str(heartbeat), HEARTBEAT_WRITER],
                str(min(os.sched_getaffinity(0))),
                output / "stdout.log",
                output / "stderr.log",
                output / "time.txt",
                timeout_seconds=5.0,
                term_grace_seconds=0.2,
            )
            self.assertEqual(status, 0)
            self.assertTrue(pid_file.exists())
            self.assertTrue(heartbeat.exists())
            self.assertTrue(self._wait_heartbeat_stopped(heartbeat))


if __name__ == "__main__":
    unittest.main(verbosity=2)
