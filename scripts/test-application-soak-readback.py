#!/usr/bin/env python3
"""Native tests for the independent application-soak parent readback."""
from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
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
campaign_loader = importlib.machinery.SourceFileLoader(
    "campaign_for_soak_readback_tests",
    str(SCRIPT.with_name("application-campaign.py")),
)
campaign_spec = importlib.util.spec_from_loader(campaign_loader.name, campaign_loader)
campaign = importlib.util.module_from_spec(campaign_spec)
campaign_loader.exec_module(campaign)
pressure_loader = importlib.machinery.SourceFileLoader(
    "pressure_readback_for_soak_tests",
    str(SCRIPT.with_name("application-pressure-readback.py")),
)
pressure_spec = importlib.util.spec_from_loader(pressure_loader.name, pressure_loader)
pressure_reader = importlib.util.module_from_spec(pressure_spec)
pressure_loader.exec_module(pressure_reader)


class FakeOwnedProcessGroup(module._OwnedProcessGroup):
    """Valid owner fixture for tests that replace the process launcher."""

    def __init__(self, process):
        self.process = process

    def observe(self):
        return None


def fake_owned_app_process(pid: int):
    process = SimpleNamespace(pid=pid)
    process._allocatbelt_owned_group = FakeOwnedProcessGroup(process)
    return process


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


def source_v5_pressure_fixture(
    root: Path, output: Path, binary: Path, driver: Path, cpu_set: str,
    timeout_seconds: int, run_id: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Build a closed SourceV5 parent/pressure audit for the shared supervisor."""
    if type(timeout_seconds) is not int:
        raise AssertionError("SourceV5 fixture timeout must match its frozen unsigned integer field")
    cpu_ids = sorted(module._parse_cpu_set(cpu_set))
    root = root.resolve(strict=True)
    output = output.resolve(strict=True)
    tmpdir = root / "application-tmp"
    tmpdir.mkdir(mode=0o700)
    app_sha = hash_file(binary)
    driver_sha = hash_file(driver)
    nonce = hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:32]
    condition_id = "condition-v2-fixture"

    def pinned_file(name: str, content: bytes) -> dict[str, Any]:
        path = root / name
        write_private(path, content)
        return {"path": str(path), "raw_sha256": hash_file(path)}

    manifest = pinned_file("source-manifest.json", b"SourceV5 fixture manifest\n")
    policy = pinned_file("pressure-policy.json", b"shared numeric policy fixture\n")
    capacity = pinned_file("capacity-calibration.json", b"capacity fixture\n")
    calibration = pinned_file("pressure-calibration.json", b"pressure calibration fixture\n")
    backing_chain = [{
        "device": "259:2", "name": "nvme0n1p2", "sysfs_path": "/sys/devices/example",
    }]
    mount = {
        "mount_id": 1, "parent_mount_id": 1, "device": "259:2", "root": "/",
        "mountpoint": str(root), "mount_options": ["rw"], "filesystem": "ext4",
        "source": "/dev/nvme0n1p2", "super_options": ["rw"],
    }

    def storage_record(path: Path) -> dict[str, Any]:
        return {
            "path": str(path), "device": "259:2", "mount": mount,
            "backing_chain": backing_chain, "filesystem_type": "ext4", "tmpfs": False,
        }

    network = {
        "address_family": "AF_INET", "destination": "127.0.0.1", "source": "127.0.0.1",
        "interface": "lo", "ifindex": 1,
        "route": {"dst": "127.0.0.1", "dev": "lo", "source": "127.0.0.1"},
        "network_namespace_inode": 1, "shared_kernel": True,
        "physical_nic_claimed": False, "claim": "ipv4_loopback_shared_kernel_only",
    }
    schedule = {
        "seed": 7, "duration_seconds": 2, "sample_interval_ms": 100,
        "startup_deadline_seconds": 1, "total_deadline_seconds": 5,
        "term_deadline_seconds": 1, "kill_deadline_seconds": 1,
        "minimum_overlap_seconds": 1, "startup_ready_windows": 1,
        "cpu_duty_basis_points": 1000, "pressure_cpu_affinity": cpu_ids,
        "application_cpu_affinity": cpu_ids, "disk_bytes_per_second": 40960,
        "scratch_file_bytes": 65536, "network_requests_per_second": 10,
        "network_payload_bytes": 16,
    }
    thresholds = {
        "cpu_busy_min_basis_points": 1,
        "disk_write_min_bytes_per_second": 1,
        "disk_queue_or_stall_min_microseconds": 1,
        "loopback_requests_min_per_second": 1,
        "loopback_latency_p99_max_nanoseconds": 1_000_000_000,
        "loopback_tx_min_bytes_per_second": 1,
        "loopback_rx_min_bytes_per_second": 1,
    }
    host = {
        "kernel_release": os.uname().release,
        "boot_id_sha256": hashlib.sha256(Path("/proc/sys/kernel/random/boot_id").read_bytes().strip()).hexdigest(),
        "allowed_cpu_affinity": cpu_ids, "pressure_cpu_affinity": cpu_ids,
        "application_cpu_affinity": cpu_ids,
        "network": network,
        "application_storage": [storage_record(root), storage_record(tmpdir)],
        "pressure_scratch": storage_record(root / "pressure-scratch"),
    }
    (root / "pressure-scratch").mkdir(mode=0o700)
    storage = {
        "application_io_paths": [str(root), str(tmpdir)],
        "pressure_scratch_path": str(root / "pressure-scratch"),
        "output_minimum_free_bytes": 1,
        "application_device": "259:2", "application_mount_id": 1,
        "backing_chain": backing_chain, "non_tmpfs": True,
    }
    files = {
        "source_manifest": manifest,
        "application_binary": {
            "path": str(binary), "raw_sha256": app_sha,
            "mode": stat.S_IMODE(binary.stat().st_mode), "size": binary.stat().st_size,
        },
        "policy": policy,
        "application_capacity_calibration": capacity,
    }
    body: dict[str, Any] = {
        "schema": pressure_reader.RECIPE_SCHEMA,
        "identity": {
            "host_id": "host-v2-fixture", "run_id": run_id, "pair_id": run_id,
            "condition_id": condition_id, "member": "bounded", "nonce": nonce,
            "allocator": "allocatbelt", "executor": "allocatbelt", "phase": "external_pressure",
        },
        "files": files,
        "process": {"executable_path": str(binary), "application_tmpdir_path": str(tmpdir)},
        "host": host,
        "storage": storage,
        "network": network,
        "schedule": schedule,
        "artifact_budget": pressure_reader._artifact_budget(schedule, backing_chain),
        "pressure_calibration": calibration,
        "readiness_thresholds": thresholds,
        "script_hashes": {
            "driver_sha256": driver_sha,
            "reader_sha256": hash_file(Path(__file__).with_name("application-pressure-readback.py")),
        },
    }
    condition_material = {
        "host_id": body["identity"]["host_id"],
        "condition_id": condition_id,
        "source_manifest_sha256": manifest["raw_sha256"],
        "policy_sha256": policy["raw_sha256"],
        "application_capacity_calibration_sha256": capacity["raw_sha256"],
        "host": {
            key: host[key] for key in (
                "kernel_release", "boot_id_sha256", "allowed_cpu_affinity",
                "pressure_cpu_affinity", "application_cpu_affinity",
            )
        },
        "storage": {
            "device": storage["application_device"],
            "mount_id": storage["application_mount_id"],
            "backing_chain": backing_chain,
        },
        "network": network, "schedule": schedule,
        "pressure_calibration_sha256": calibration["raw_sha256"],
        "readiness_thresholds": thresholds,
    }
    body["condition_sha256"] = pressure_reader.digest_object(condition_material)
    semantic_sha = pressure_reader.digest_object(body)
    pressure_recipe = {**body, "recipe_sha256": semantic_sha}
    pressure_reader._validate_recipe(pressure_recipe, semantic_sha)
    recipe_path = root / "pressure-recipe.json"
    recipe_raw = canon(pressure_recipe)
    write_private(recipe_path, recipe_raw)
    raw_sha = digest_bytes(recipe_raw)
    pressure_info = {
        "value": pressure_recipe, "reader": pressure_reader,
        "recipe_sha256": semantic_sha, "raw_sha256": raw_sha,
        "condition_sha256": pressure_recipe["condition_sha256"],
        "recipe_path": str(recipe_path),
        "driver_path": str(driver), "driver_sha256": driver_sha,
        "output_dir": str(output / "pressure"),
        "launch_record_path": str(output / "pressure" / "launch-record.json"),
        "ready_path": str(output / "pressure" / "pressure-ready.json"),
        "source_root": str(root), "readiness_thresholds": thresholds,
        "driver_readiness_thresholds": thresholds,
    }
    parent_recipe = {
        "schema": module.RECIPE_SCHEMA_V2,
        "pressure": {
            "recipe": {
                "path": str(recipe_path), "raw_sha256": raw_sha,
                "semantic_sha256": semantic_sha,
            },
            "driver": {"path": driver.relative_to(root).as_posix(), "sha256": driver_sha},
        },
        "qualification": {"pressure_condition": {"readiness_thresholds": thresholds}},
    }
    parent_recipe_path = root / "soak-v2-parent-recipe.json"
    parent_raw = canon(parent_recipe)
    write_private(parent_recipe_path, parent_raw)
    reference_ring = root / "reference-ring.tsv"
    write_private(reference_ring, b"fixture reference ring\n")
    runner_path = root / "run-application-soak.sh"
    write_private(runner_path, b"#!/bin/sh\nexit 0\n", 0o700)
    identity = {
        "campaign_id": "campaign-v2-fixture", "host_id": "host-v2-fixture",
        "run_id": run_id, "nonce": nonce, "allocator": "allocatbelt",
        "executor": "bounded", "profile": "mixed", "source_sha256": "1" * 64,
        "binary_sha256": app_sha, "resource_ceiling_sha256": "2" * 64,
    }
    audit: dict[str, Any] = {
        "launch_enabled": True, "recipe_sha256": digest_bytes(parent_raw),
        "identity": identity, "ring": {"path": str(reference_ring), "sha256": hash_file(reference_ring)},
        "source": {
            "candidate_binary_path": str(binary), "candidate_binary_sha256": app_sha,
            "source_root": str(root),
            "application_supervision": {
                "application_wall_timeout_seconds": timeout_seconds,
                "pressure_duration_seconds": schedule["duration_seconds"],
            },
            "pressure_recipe": pressure_info,
        },
        "recipe": parent_recipe,
        "execution": {
            "reader_path": str(SCRIPT), "reader_sha256": hash_file(SCRIPT),
            "runner_path": str(runner_path), "runner_sha256": hash_file(runner_path),
        },
        "source_root": str(root), "mode": "functional",
        "duration_seconds": 2, "sample_interval_ms": 100,
    }
    descriptor = module._make_launch_descriptor_v2(audit, output, cpu_set, None, None)
    audit["launch_descriptor"] = descriptor
    return audit, descriptor, pressure_recipe


def write_fixture_pressure_prefix(pressure_dir: Path, pressure_recipe: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Publish a self-consistent SourceV5 ownership/ACK/start prefix for V2 tests."""
    schedule = pressure_recipe["schedule"]
    nonce = pressure_recipe["identity"]["nonce"]
    recipe_sha = pressure_recipe["recipe_sha256"]
    cpus = schedule["pressure_cpu_affinity"]
    workers = [
        {"role": "cpu", "cpu": cpu, "pid": 501 + index, "start_ticks": 501 + index,
         "pgid": 501 + index, "session_id": 501 + index, "nonce": nonce}
        for index, cpu in enumerate(cpus)
    ]
    workers.extend([
        {"role": role, "cpu": None, "pid": pid, "start_ticks": pid,
         "pgid": pid, "session_id": pid, "nonce": nonce}
        for role, pid in (("disk", 502), ("loopback", 503))
    ])
    owner_body = {
        "schema": pressure_reader.EVENT_SCHEMA, "kind": "worker_ownership",
        "recipe_sha256": recipe_sha, "nonce": nonce, "monotonic_ns": 10,
        "workers": workers,
    }
    ownership_sha = digest_bytes(canon(owner_body))
    owner_event = {**owner_body, "ownership_sha256": ownership_sha}
    authorized_body = {
        "schema": pressure_reader.EVENT_SCHEMA, "kind": "workers_authorized",
        "recipe_sha256": recipe_sha, "nonce": nonce, "ownership_sha256": ownership_sha,
        "monotonic_ns": 11, "workers": workers,
    }
    authorization_sha = digest_bytes(canon(authorized_body))
    authorized_event = {**authorized_body, "authorization_sha256": authorization_sha}
    start_event = {
        "schema": pressure_reader.EVENT_SCHEMA, "kind": "pressure_start", "sequence": -1,
        "recipe_sha256": recipe_sha, "nonce": nonce, "monotonic_ns": 12,
        "ownership_sha256": ownership_sha, "authorization_sha256": authorization_sha,
        "workers": workers,
    }
    write_private(pressure_dir / "events.jsonl", b"".join(canon(item) for item in (owner_event, authorized_event, start_event)))
    thresholds = pressure_recipe["readiness_thresholds"]
    ready_body = {
        "schema": "allocatbelt.application-pressure-ready.v1",
        "recipe_sha256": recipe_sha,
        "condition_sha256": pressure_recipe["condition_sha256"],
        "nonce": nonce,
        "ownership_protocol": module.SOURCE_V5_PRESSURE_OWNERSHIP_PROTOCOL,
        "worker_ownership_sha256": ownership_sha,
        "worker_authorization_sha256": authorization_sha,
        "pressure_ready_monotonic_ns": time.monotonic_ns(),
        "readiness": {
            "cpu_ready": True, "disk_ready": True, "loopback_ready": True, "all_ready": True,
            "cpu_busy_basis_points": max(1, thresholds["cpu_busy_min_basis_points"]),
            "disk_write_bytes_per_second": max(1, thresholds["disk_write_min_bytes_per_second"]),
            "disk_queue_or_stall_microseconds": max(1, thresholds["disk_queue_or_stall_min_microseconds"]),
            "loopback_requests_per_second": max(1, thresholds["loopback_requests_min_per_second"]),
            "loopback_latency_p99_upper_nanoseconds": min(1000, thresholds["loopback_latency_p99_max_nanoseconds"]),
            "loopback_tx_bytes_per_second": max(1, thresholds["loopback_tx_min_bytes_per_second"]),
            "loopback_rx_bytes_per_second": max(1, thresholds["loopback_rx_min_bytes_per_second"]),
        },
    }
    ready = {**ready_body, "ready_sha256": digest_bytes(canon(ready_body))}
    write_private(pressure_dir / "pressure-ready.json", canon(ready))
    return ready, digest_bytes(canon(ready))


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
            "workloads": {"mixed": {"domain_ceiling": {**domain, "cpu": 4}, "scope_limits": scope}},
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
    def test_false_legacy_descriptor_and_enabled_overlay_use_separate_environments(self):
        """Keep the disabled baseline empty while rebuilding the launched overlay."""
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-overlay-env-") as temporary:
            root = Path(temporary).resolve()
            source_root = root / "source"
            output = root / "output"
            source_root.mkdir(mode=0o700)
            output.mkdir(mode=0o700)
            binary = source_root / "application"
            driver = source_root / "application-pressure-driver.py"
            write_private(binary, b"pinned normal APP fixture\n", 0o700)
            write_private(driver, b"pinned pressure driver fixture\n")
            audit, _enabled_descriptor, _pressure_recipe = source_v5_pressure_fixture(
                source_root, output, binary, driver, "0", 5,
                "campaign-host-v2-soak-allocatbelt-01",
            )

            base_audit = dict(audit, launch_enabled=False)
            base_descriptor = module._make_launch_descriptor_v2(
                base_audit, output, "0", None, None,
                path_value="/origin/bin:/usr/bin:/bin",
            )
            self.assertFalse(base_descriptor["launch_enabled"])
            self.assertEqual(base_descriptor["environment"], {})

            overlay_audit = dict(base_audit, launch_enabled=True)
            with mock.patch.dict(os.environ, {"PATH": "/coordinator-only"}):
                overlay_descriptor = module._make_launch_descriptor_v2(
                    overlay_audit, output, "0", None, None,
                    path_value="/origin/bin:/usr/bin:/bin",
                )
            self.assertTrue(overlay_descriptor["launch_enabled"])
            self.assertEqual(
                overlay_descriptor["environment"]["PATH"],
                "/origin/bin:/usr/bin:/bin",
            )
            self.assertFalse(base_audit["launch_enabled"])
            self.assertEqual(base_descriptor["environment"], {})

    def test_full_v2_pressure_recipe_uses_real_validator_without_losing_input(self):
        """Exercise the actual pressure validator with a complete V2 recipe shape.

        This is a structural reader regression, not a host or qualification witness.
        """
        with tempfile.TemporaryDirectory(prefix="allocatbelt-full-v2-pressure-recipe-") as temporary:
            root = Path(temporary).resolve()
            source_root = root / "source"
            output = root / "output"
            source_root.mkdir(mode=0o700)
            output.mkdir(mode=0o700)
            binary = source_root / "application"
            driver = source_root / "application-pressure-driver.py"
            write_private(binary, b"pinned normal APP fixture\n", 0o700)
            write_private(driver, b"pinned pressure driver fixture\n")
            _audit, _descriptor, original_recipe = source_v5_pressure_fixture(
                source_root, output, binary, driver, "0", 5,
                "campaign-host-v2-validator-allocatbelt-01",
            )

            def raw_pin(path: Path) -> dict[str, str]:
                return {"path": str(path), "raw_sha256": hash_file(path)}

            policy_bundle_path = source_root / "per-job-context-policy.json"
            members = []
            for index in range(2):
                member_request = source_root / f"member-{index}-request.json"
                resolved_policy = source_root / f"member-{index}-resolved.json"
                composition_receipt = source_root / f"member-{index}-composition.json"
                write_private(member_request, canon({"fixture_member": index, "kind": "request"}))
                write_private(resolved_policy, canon({"fixture_member": index, "kind": "resolved"}))
                write_private(composition_receipt, canon({"fixture_member": index, "kind": "receipt"}))
                members.append({
                    "descriptor": {
                        "pair": f"fixture-pair-{index}", "executor": "bounded",
                        "allocator": "allocatbelt",
                    },
                    "request": raw_pin(member_request),
                    "construction_probe": {
                        **raw_pin(binary), "allocator": "allocatbelt",
                        "binary_sha256": hash_file(binary),
                    },
                    "resolved_policy": raw_pin(resolved_policy),
                    "composition_receipt": raw_pin(composition_receipt),
                })
            write_private(policy_bundle_path, canon({
                "schema": pressure_reader.CONTEXT_POLICY_BUNDLE_SCHEMA_V2,
                "artifact": original_recipe["files"]["policy"],
                "members": members,
            }))

            condition_path = source_root / "prospective-pressure-condition.json"
            observed_host_path = source_root / "observed-host.json"
            scope_receipt_path = source_root / "calibration-scope-receipt.json"
            write_private(condition_path, canon({"fixture": "condition"}))
            write_private(observed_host_path, canon({"fixture": "observed host"}))
            write_private(scope_receipt_path, canon({"fixture": "scope receipt"}))
            capacity_request_path = source_root / "capacity-request.json"
            capacity_receipt_path = source_root / "capacity-receipt.json"
            write_private(capacity_request_path, canon({"fixture": "capacity request"}))
            write_private(capacity_receipt_path, canon({"fixture": "capacity receipt"}))

            recipe_body = {
                key: value for key, value in original_recipe.items()
                if key != "recipe_sha256"
            }
            recipe_body["schema"] = pressure_reader.RECIPE_SCHEMA_V2
            recipe_body["calibration_scope_v2"] = {
                "schema": pressure_reader.CALIBRATION_BINDING_SCHEMA_V2,
                "scope_receipt": {
                    **raw_pin(scope_receipt_path), "scope_sha256": "a" * 64,
                },
                "validator_sha256": recipe_body["script_hashes"]["reader_sha256"],
                "condition": raw_pin(condition_path),
                "context_policy": raw_pin(policy_bundle_path),
                "capacity_bundle_pins": {
                    "schema": pressure_reader.CAPACITY_BUNDLE_PIN_SCHEMA_V2,
                    "capacity_key": {
                        "host_id": "host-v2-fixture", "workload": "mixed",
                        "profile": "mixed", "calibration_id": "capacity-fixture",
                    },
                    "source_manifest": recipe_body["files"]["source_manifest"],
                    "request": raw_pin(capacity_request_path),
                    "artifact": recipe_body["files"]["application_capacity_calibration"],
                    "receipt": raw_pin(capacity_receipt_path),
                },
                "observed_host": raw_pin(observed_host_path),
                "context_policy_sha256": "b" * 64,
            }
            semantic_sha = pressure_reader.digest_object(recipe_body)
            full_recipe = {**recipe_body, "recipe_sha256": semantic_sha}
            summary = pressure_reader._validate_recipe(full_recipe, semantic_sha)

            self.assertEqual(full_recipe["schema"], pressure_reader.RECIPE_SCHEMA_V2)
            self.assertIn("host", full_recipe)
            self.assertIn("process", full_recipe)
            self.assertEqual(summary["identity"], full_recipe["identity"])
            self.assertEqual(summary["condition_sha256"], full_recipe["condition_sha256"])
            self.assertNotIn("schema", summary)
            self.assertNotIn("host", summary)
            self.assertNotIn("process", summary)

    def test_source5_offline_audit_requires_origin_environment_before_reads(self):
        context = {
            "schema": module.SOURCE5_SOAK_OFFLINE_CONTEXT_SCHEMA,
            "evidence_path_map": {
                "schema": "allocatbelt.application-pressure-evidence-path-map.v1",
                "entries": [{"origin": "/origin", "local": "/origin"}],
            },
            "construction_probe_capture": {},
            "host_verification_pin": {},
        }
        args = SimpleNamespace(recipe=Path("/origin/recipe.json"),
                               recipe_sha256="a" * 64)
        with mock.patch.object(
            module, "read_json",
            side_effect=AssertionError("offline audit read before its closed context"),
        ) as read_json, mock.patch.object(
            module.subprocess, "Popen",
            side_effect=AssertionError("offline audit attempted a process launch"),
        ) as popen:
            with self.assertRaisesRegex(
                module.SoakReadbackError, "keys differ from the frozen contract",
            ):
                module._current_audit_offline(args, context)
            read_json.assert_not_called()
            popen.assert_not_called()

    def test_owned_worker_adoption_transition_survives_worker_exit_between_polls(self):
        pid, start_ticks, driver_pid = 501, 9001, 600
        sessions = {("cpu", 2): {
            "pid": pid, "start_ticks": start_ticks, "pgid": pid, "session_id": pid,
            "parent_pid": driver_pid, "adopted_by_subreaper": False, "reaped": False,
            "role": "cpu", "cpu": 2,
        }}
        with mock.patch.object(module, "_PRESSURE_SUBREAPER_ACTIVE", True), \
             mock.patch.object(module, "_proc_process_identity", return_value={
                 "pid": pid, "start_ticks": start_ticks, "pgid": pid, "session_id": pid,
                 "parent_pid": os.getpid(), "state": "Z",
             }), \
             mock.patch.object(module, "_proc_child_pids", return_value=[]):
            module._capture_pressure_worker_sessions(
                driver_pid, 7001, Path("/pinned/driver.py"), "a" * 64,
                {"pressure_cpu_affinity": [2]}, sessions, "b" * 32,
            )
        self.assertEqual(sessions[("cpu", 2)]["parent_pid"], os.getpid())
        self.assertTrue(sessions[("cpu", 2)]["adopted_by_subreaper"])

    def test_source_v5_cleanup_does_not_treat_empty_post_exit_inventory_as_clean(self):
        class ExitedDriver:
            pid = 600

            def poll(self):
                return -signal.SIGKILL

        schedule = {
            "pressure_cpu_affinity": [2], "term_deadline_seconds": 1,
            "kill_deadline_seconds": 1,
        }
        with mock.patch.object(module, "_PRESSURE_SUBREAPER_ACTIVE", True), \
             mock.patch.object(module, "_capture_pressure_worker_sessions"), \
             mock.patch.object(module, "_cleanup_owned_pressure_workers", return_value=True):
            with self.assertRaisesRegex(module.SoakReadbackError, "complete worker inventory"):
                module._stop_pressure_session(
                    ExitedDriver(), 7001, Path("/pinned/driver.py"), "a" * 64,
                    schedule, {}, "b" * 32,
                )

    def test_pressure_worker_capture_requires_exact_spawn_arguments_and_parent_identity(self):
        schedule = {
            "sample_interval_ms": 100, "duration_seconds": 30, "seed": 17,
            "pressure_cpu_affinity": [2], "cpu_duty_basis_points": 8000,
            "scratch_file_bytes": 4096, "disk_bytes_per_second": 65536,
            "network_requests_per_second": 10, "network_payload_bytes": 64,
        }
        base = [
            sys.executable.encode(), b"/pinned/driver.py", b"_worker",
            b"--recipe-sha256", b"a" * 64,
            b"--owner-nonce", b"b" * 32,
            b"--driver-pid", b"600", b"--driver-start-ticks", b"7001",
            b"--interval-ms", b"100", b"--duration-seconds", b"30", b"--seed", b"17",
            b"--kind", b"cpu", b"--cpu", b"2", b"--duty-basis-points", b"8000",
        ]
        command = b"\0".join(base) + b"\0"
        self.assertEqual(
            module._parse_pressure_worker_argv(
                command, Path("/pinned/driver.py"), "a" * 64, schedule,
                "b" * 32, 600, 7001,
            ),
            ("cpu", 2),
        )
        with self.assertRaisesRegex(module.SoakReadbackError, "options differ"):
            module._parse_pressure_worker_argv(
                b"\0".join(base + [b"--surprise", b"true"]) + b"\0",
                Path("/pinned/driver.py"), "a" * 64, schedule, "b" * 32, 600, 7001,
            )
        with self.assertRaisesRegex(module.SoakReadbackError, "start ticks differ"):
            module._parse_pressure_worker_argv(
                command, Path("/pinned/driver.py"), "a" * 64, schedule,
                "b" * 32, 600, 7002,
            )

    def test_pressure_readback_rejects_supervisor_logs_inside_exact_artifact_dir(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-pressure-artifact-directory-") as temporary:
            root = Path(temporary)
            recipe_path = root / "pressure-recipe.json"
            write_private(recipe_path, canon({"schema": "test.pressure.v1"}))
            artifact_dir = root / "pressure"
            artifact_dir.mkdir(mode=0o700)
            for name in ("events.jsonl", "process-binding.json", "launch-record.json", "run.json", "pressure-ready.json"):
                write_private(artifact_dir / name, b"{}\n")
            write_private(artifact_dir / "pressure-driver.stderr.log", b"captured supervisor diagnostics\n")
            with mock.patch.object(pressure_reader, "_validate_recipe", return_value={}), \
                 mock.patch.object(pressure_reader, "_verify_script_hashes"), \
                 mock.patch.object(pressure_reader, "_verify_raw_inputs"), \
                 mock.patch.object(pressure_reader, "_validate_calibration"):
                with self.assertRaisesRegex(pressure_reader.ReadbackError, "missing or unexpected files"):
                    pressure_reader.verify_pressure(recipe_path, "a" * 64, artifact_dir, {})

    def test_source_v5_manifest_raw_and_semantic_hash_roles_are_distinct(self):
        manifest = {"schema": module.SOURCE_SCHEMA_V5, "source": {"host_id": "host-1"}}
        manifest["manifest_sha256"] = digest_bytes(canon(manifest))
        raw = canon(manifest)
        raw_sha = digest_bytes(raw)
        self.assertNotEqual(raw_sha, manifest["manifest_sha256"])
        self.assertEqual(
            module._validate_v5_manifest_digest_roles(manifest, raw, manifest["manifest_sha256"], raw_sha),
            raw_sha,
        )
        with self.assertRaisesRegex(module.SoakReadbackError, "semantic digest"):
            module._validate_v5_manifest_digest_roles(manifest, raw, raw_sha)
        with self.assertRaisesRegex(module.SoakReadbackError, "raw manifest bytes"):
            module._validate_v5_manifest_digest_roles(manifest, raw, manifest["manifest_sha256"], manifest["manifest_sha256"])

    def test_foreign_source_manifest_runs_captured_full_calibration_verifier(self):
        controller_pin = {"path": "scripts/application-campaign.py", "sha256": "a" * 64}
        valid_calibration = {
            "schema": campaign.CALIBRATION_SCHEMA,
            "architecture": "x86_64",
            "max_tenants": 1,
            "max_waiters": 256,
            "control_ceiling": 67_108_864,
            "fixed_global_control_baseline": 2048,
            "tenant_owner_control_bytes": 0,
            "final_live_tenants": 0,
            "final_global_control_bytes": 2048,
        }

        def source_manifest(host_id, calibration):
            value = {
                "host_id": host_id,
                "qualification_harness": {"campaign_controller": controller_pin},
                "resource_domain_calibration": {"record": calibration},
            }
            value["manifest_sha256"] = digest_bytes(canon(value))
            raw = canon(value)
            module._validate_v5_manifest_digest_roles(value, raw, value["manifest_sha256"])
            return value

        selected = source_manifest("host-1", dict(valid_calibration))
        malformed_foreign_calibration = dict(valid_calibration)
        malformed_foreign_calibration["max_waiters"] = 257
        foreign = source_manifest("host-2", malformed_foreign_calibration)

        class CapturedController:
            CampaignError = campaign.CampaignError

            def __init__(self):
                self.verified_hosts = []

            def verify_source_manifest(self, manifest, verify_artifacts=False):
                self.assert_no_artifacts(verify_artifacts)
                self.verified_hosts.append(manifest["host_id"])
                campaign.validate_calibration_record(manifest["resource_domain_calibration"]["record"])

            @staticmethod
            def assert_no_artifacts(value):
                if value is not False:
                    raise ValueError("foreign V5 manifests must receive full structure validation without host artifact access")

        captured = CapturedController()
        with self.assertRaisesRegex(module.SoakReadbackError, "full verifier"):
            module._verify_v5_manifest_set(captured, {"host-1": selected, "host-2": foreign}, controller_pin)
        self.assertEqual(captured.verified_hosts, ["host-1", "host-2"])

    def test_source_v5_pressure_schedule_encloses_full_soak_and_bounded_phases(self):
        base_schedule = {
            "seed": 17,
            "duration_seconds": 30,
            "sample_interval_ms": 100,
            "startup_deadline_seconds": 10,
            "total_deadline_seconds": 85,
            "term_deadline_seconds": 30,
            "kill_deadline_seconds": 15,
            "minimum_overlap_seconds": 10,
            "startup_ready_windows": 2,
            "cpu_duty_basis_points": 8000,
            "pressure_cpu_affinity": [1, 3],
            "application_cpu_affinity": [0, 2],
            "disk_bytes_per_second": 81_920,
            "scratch_file_bytes": 4096,
            "network_requests_per_second": 10,
            "network_payload_bytes": 64,
        }
        request = {"schema": "allocatbelt.application-pressure-request.v1", "schedule": base_schedule}
        request_before = canon(request)
        result = module._derive_v5_pressure_schedule(
            10_800, request,
            {"duration_seconds": 30, "sample_interval_ms": 100, "seed": 17},
        )
        self.assertEqual(result["application_wall_timeout_seconds"], 11_050)
        self.assertEqual(result["pressure_duration_seconds"], 11_061)
        self.assertEqual(result["pressure_schedule"]["duration_seconds"], 11_061)
        self.assertEqual(result["pressure_schedule"]["total_deadline_seconds"], 11_116)
        expected = dict(base_schedule)
        expected["duration_seconds"] = 11_061
        expected["total_deadline_seconds"] = 11_116
        self.assertEqual(result["pressure_schedule"], expected)
        self.assertEqual(canon(request), request_before)
        with self.assertRaisesRegex(module.SoakReadbackError, "sample interval"):
            bad_schedule = dict(base_schedule, sample_interval_ms=333)
            module._derive_v5_pressure_schedule(
                10_800,
                {"schema": request["schema"], "schedule": bad_schedule},
                {"duration_seconds": 30, "sample_interval_ms": 333, "seed": 17},
            )

    def test_source_v5_validate_cli_serializes_exact_fifteen_field_composite(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-v2-cli-composite-") as temporary:
            output = Path(temporary) / "output"
            output.mkdir(mode=0o700)
            audit = {"recipe": {"schema": module.RECIPE_SCHEMA_V2}}
            preflight = {"preflight_sha256": "a" * 64}
            launch_sha = "b" * 64
            postflight = {
                "schema": module.POSTFLIGHT_SCHEMA,
                "preflight_sha256": preflight["preflight_sha256"],
                "recipe_sha256": "c" * 64,
                "source_manifest_sha256": "d" * 64,
                "source_tree_sha256": "e" * 64,
                "build_sha256": "f" * 64,
                "candidate_binary_sha256": "1" * 64,
                "oracle_producer_binary_sha256": "2" * 64,
                "reference_ring_sha256": "3" * 64,
                "launch_receipt_sha256": launch_sha,
                "inputs_unchanged": True,
            }
            postflight["postflight_sha256"] = digest_bytes(canon(postflight))
            write_private(output / "soak-postflight.json", canon(postflight))
            composite = {
                "schema": module.RESULT_SCHEMA_V2,
                "validated": True,
                "passed": True,
                "qualification_eligible": False,
                "mode": "functional",
                "identity": {"run_id": "run-v2"},
                "source_manifest_sha256": "4" * 64,
                "source_tree_sha256": "5" * 64,
                "build_sha256": "6" * 64,
                "candidate_binary_sha256": "7" * 64,
                "resource_ceiling_sha256": "8" * 64,
                "fixed_global_control_baseline": 2048,
                "receipt_sha256": "9" * 64,
                "validator_sha256": "a" * 64,
                "monotonic_endpoints": {"started": [1, 2], "trace_ended": [3, 4], "drain_ended": [5, 6], "shutdown_ended": [7, 8], "postprocess_ended": [9, 10]},
            }
            args = SimpleNamespace(output_dir=output)
            stdout = io.StringIO()
            with mock.patch.object(module, "_current_audit", return_value=(audit, preflight)), \
                 mock.patch.object(module, "_verify_launch_receipt", return_value=({"schema": "launch.v1"}, launch_sha)), \
                 mock.patch.object(module, "_validate_artifacts", return_value=composite), \
                 contextlib.redirect_stdout(stdout):
                self.assertEqual(module.command_validate(args), 0)
            saved = module._readback_json(output / "soak-readback.json", "saved SourceV5 composite")
            self.assertEqual(saved, composite)
            self.assertEqual(len(saved), 15)
            self.assertNotIn("postflight_sha256", saved)
            self.assertEqual(json.loads(stdout.getvalue())["validated"], True)

    def test_pressure_readiness_marker_is_measured_pinned_and_published_atomically(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-pressure-ready-marker-") as temporary:
            root = Path(temporary)
            recipe = {
                "identity": {"nonce": "a" * 32},
                "readiness_thresholds": {
                    "cpu_busy_min_basis_points": 7000,
                    "disk_write_min_bytes_per_second": 1024,
                    "disk_queue_or_stall_min_microseconds": 100,
                    "loopback_requests_min_per_second": 10,
                    "loopback_latency_p99_max_nanoseconds": 1_000_000,
                    "loopback_tx_min_bytes_per_second": 2048,
                    "loopback_rx_min_bytes_per_second": 2048,
                },
            }
            body = {
                "schema": "allocatbelt.application-pressure-ready.v1",
                "recipe_sha256": "b" * 64,
                "condition_sha256": "c" * 64,
                "nonce": "a" * 32,
                "ownership_protocol": module.SOURCE_V5_PRESSURE_OWNERSHIP_PROTOCOL,
                "worker_ownership_sha256": "d" * 64,
                "worker_authorization_sha256": "e" * 64,
                "pressure_ready_monotonic_ns": time.monotonic_ns(),
                "readiness": {
                    "cpu_ready": True, "disk_ready": True, "loopback_ready": True, "all_ready": True,
                    "cpu_busy_basis_points": 8000, "disk_write_bytes_per_second": 2048,
                    "disk_queue_or_stall_microseconds": 200, "loopback_requests_per_second": 20,
                    "loopback_latency_p99_upper_nanoseconds": 500_000,
                    "loopback_tx_bytes_per_second": 4096, "loopback_rx_bytes_per_second": 4096,
                },
            }
            marker = {**body, "ready_sha256": digest_bytes(canon(body))}
            marker_path = root / "pressure-ready.json"
            write_private(marker_path, canon(marker))
            checked, raw_sha = module._read_pressure_ready(marker_path, recipe, "b" * 64, "c" * 64)
            self.assertEqual(checked, marker)
            self.assertEqual(raw_sha, digest_bytes(canon(marker)))

            launch_path = root / "launch-record.json"
            published_sha = module._atomic_json_publish(launch_path, {"schema": "test.v1", "pid": 123})
            self.assertEqual(published_sha, digest_bytes(launch_path.read_bytes()))
            with self.assertRaisesRegex(module.SoakReadbackError, "refusing to replace"):
                module._atomic_json_publish(launch_path, {"schema": "test.v1", "pid": 124})

    def test_soak_v2_callback_api_rejects_invalid_callbacks_before_adapting_or_launching(self):
        with mock.patch.object(module, "_adapt_soak_v2_launch") as adapt, \
             mock.patch.object(module, "supervise_pressure_application") as supervise:
            for started, cleanup in ((None, lambda _value: None), (lambda _value: None, None)):
                with self.assertRaisesRegex(module.SoakReadbackError, "callbacks must be callable"):
                    module.launch_soak_v2_application(None, {}, {}, Path("/unused"), started, cleanup)
            adapt.assert_not_called()
            supervise.assert_not_called()

    def test_external_launch_waits_for_pressure_readiness_before_app_popen(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-pressure-first-launch-") as temporary:
            root = Path(temporary)
            output = root / "output"
            output.mkdir(mode=0o700)
            driver = root / "pressure-driver.py"
            driver.write_text("# pinned test driver\n", encoding="ascii")
            app_binary = root / "soak-binary"
            write_private(app_binary, b"soak binary", 0o700)
            app_binary.chmod(0o700)
            pressure_dir = output / "pressure"
            audit, descriptor, pressure_recipe = source_v5_pressure_fixture(
                root, output, app_binary, driver, "2", 11_050, "waits-for-readiness",
            )
            pressure_recipe_path = Path(audit["recipe"]["pressure"]["recipe"]["path"])
            events = []
            pressure_process = SimpleNamespace(pid=600, returncode=None)

            def wait_pressure(timeout=None):
                events.append("pressure_exit")
                pressure_process.returncode = 0
                return 0

            pressure_process.wait = wait_pressure
            pressure_process.poll = lambda: pressure_process.returncode

            def fake_popen(command, **kwargs):
                self.assertEqual(command[1:3], [str(driver), "run"])
                self.assertNotEqual(pressure_dir, output)
                events.append("pressure_start")
                return pressure_process

            def fake_launch(command, cpu_set, stdout_path, stderr_path, timing_path, timeout, grace, monitored_files, *, environment, cwd, expected_executable_sha256, return_details, on_started, monitor, on_signal, on_cleanup, timeout_from_before_popen, timeout_includes_cleanup):
                self.assertEqual(events, ["pressure_start", "ready"])
                self.assertEqual(timeout, 11_050)
                self.assertTrue(timeout_from_before_popen)
                self.assertTrue(timeout_includes_cleanup)
                app_process = fake_owned_app_process(700)
                on_started(app_process, Path(command[0]), expected_executable_sha256, Path(command[0]).stat(), {2}, cwd, environment)
                events.append("app_popen")
                monitor(app_process)
                on_cleanup({
                    "schema": "allocatbelt.application-soak-process-cleanup.v1",
                    "status": "verified", "pid": app_process.pid, "return_code": 0,
                    "received_signal": None, "cleanup_error": None,
                })
                return {
                    "status": 0, "child_return_code": 0, "timed_out": False,
                    "artifact_budget_exceeded": False, "received_signal": None,
                    "started_monotonic_ns": 1, "ended_monotonic_ns": 2,
                    "binary_path": command[0], "binary_sha256": expected_executable_sha256,
                    "binary_device": 1, "binary_inode": 2, "binary_size": 3,
                    "requested_argv": command, "requested_argv_sha256": "f" * 64,
                    "executed_argv": command, "executed_file_descriptor": "/proc/self/fd/200",
                    "environment": environment, "environment_sha256": "a" * 64,
                    "cwd": str(cwd), "cpu_set": cpu_set,
                }

            def capture_workers(_pid, _start_ticks, _path, _recipe_sha, _schedule, sessions, _expected_nonce, **_kwargs):
                for role, pid in (("cpu", 501), ("disk", 502), ("loopback", 503)):
                    key = (role, 2) if role == "cpu" else (role, None)
                    sessions[key] = {
                        "pid": pid, "start_ticks": pid, "pgid": pid, "session_id": pid,
                        "parent_pid": 600, "role": role, "cpu": 2 if role == "cpu" else None,
                    }

            def ready(*_args, **kwargs):
                kwargs["capture_workers"]()
                events.append("ready")
                return write_fixture_pressure_prefix(pressure_dir, pressure_recipe)

            args = SimpleNamespace(
                command=["--", *descriptor["argv"]], cpu_set="2", output_dir=output,
                timeout_seconds=11_050, term_grace_seconds=1.5,
            )
            with mock.patch.object(module.subprocess, "Popen", side_effect=fake_popen), \
                 mock.patch.object(module, "_wait_pressure_ready", side_effect=ready), \
                 mock.patch.object(module, "_proc_start_ticks", return_value=123), \
                 mock.patch.object(module, "_proc_process_identity", return_value={
                     "pid": 700, "start_ticks": 701, "state": "S", "parent_pid": os.getpid(),
                     "pgid": 700, "session_id": 700,
                 }), \
                 mock.patch.object(module, "_capture_pressure_worker_sessions", side_effect=capture_workers), \
                 mock.patch.object(module, "_wait_pressure_workers_gone", return_value=True), \
                 mock.patch.object(module, "_make_pressure_launch_binding", side_effect=lambda *_args: {"schema": "binding.v1"}), \
                 mock.patch.object(module, "_make_application_launch_attestation", return_value={"schema": "attestation.fixture.v1"}), \
                 mock.patch.object(module, "launch_process", side_effect=fake_launch), \
                 mock.patch.object(module, "_launch_receipt_value", return_value={"schema": "launch.v1"}), \
                 mock.patch.object(module, "_validate_pressure_proof", side_effect=lambda *_args: (events.append("pressure_proof") or {"raw_sha256": "2" * 64})):
                callbacks = []
                receipt = module.launch_soak_v2_application(
                    args,
                    audit,
                    {"terminal_budget_bytes": 1024, "sample_budget_bytes": 1024},
                    output,
                    on_started=lambda value: callbacks.append(("started", value)),
                    on_cleanup=lambda value: callbacks.append(("cleanup", value)),
                )
            self.assertEqual(receipt["status"], 0)
            self.assertFalse(receipt["interrupted"])
            self.assertEqual([kind for kind, _value in callbacks], ["started", "cleanup"])
            self.assertEqual(callbacks[0][1], {"schema": "attestation.fixture.v1"})
            self.assertEqual(callbacks[1][1]["pid"], 700)
            self.assertEqual(callbacks[1][1], receipt["application_cleanup"])
            self.assertEqual(events, ["pressure_start", "ready", "app_popen", "pressure_exit", "pressure_proof"])

    def test_pressure_supervisor_rejects_environment_over_frozen_byte_bound_before_popen(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-pressure-environment-bound-") as temporary:
            root = Path(temporary)
            output = root / "output"
            output.mkdir(mode=0o700)
            driver = root / "pressure-driver.py"
            driver.write_text("# pinned test driver\n", encoding="ascii")
            binary = root / "soak-binary"
            write_private(binary, b"soak binary", 0o700)
            audit, descriptor, _pressure_recipe = source_v5_pressure_fixture(
                root, output, binary, driver, "2", 5, "oversized-environment",
            )
            args = SimpleNamespace(
                command=["--", *descriptor["argv"]], cpu_set=descriptor["cpu_set"],
                timeout_seconds=5.0, term_grace_seconds=1.5,
            )
            pressure_info, app_descriptor = module._adapt_soak_v2_launch(
                args, audit, {"terminal_budget_bytes": 1024, "sample_budget_bytes": 1024},
            )
            self.assertIs(type(app_descriptor["application_wall_timeout_seconds"]), int)
            app_descriptor["environment"] = {"ALLOCATBELT_TEST": "x" * module.MAX_ENVIRONMENT_BYTES}
            with mock.patch.object(module.subprocess, "Popen") as popen:
                with self.assertRaisesRegex(module.SoakReadbackError, "environment exceeds its finite bound"):
                    module.supervise_pressure_application(
                        app_descriptor, pressure_info, output,
                        lambda _value: None, lambda _value: None,
                    )
                popen.assert_not_called()

    def test_source_v5_pressure_proof_requires_durable_marker_and_matching_event_prefix(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-v5-pressure-prefix-") as temporary:
            root = Path(temporary)
            pressure_dir = root / "pressure"
            pressure_dir.mkdir(mode=0o700)
            nonce = "a" * 32
            condition_sha = "c" * 64
            pressure_body = {
                "schema": pressure_reader.RECIPE_SCHEMA,
                "identity": {"nonce": nonce},
                "condition_sha256": condition_sha,
            }
            recipe_sha = pressure_reader.digest_object(pressure_body)
            pressure_recipe = {**pressure_body, "recipe_sha256": recipe_sha}
            recipe_raw = canon(pressure_recipe)
            recipe_path = root / "recipe.json"
            write_private(recipe_path, recipe_raw)
            raw_sha = digest_bytes(recipe_raw)
            worker = {
                "role": "cpu", "cpu": 2, "pid": 101, "start_ticks": 501,
                "pgid": 101, "session_id": 101, "nonce": nonce,
            }
            owner_body = {
                "schema": "allocatbelt.application-pressure-event.v1",
                "kind": "worker_ownership", "recipe_sha256": recipe_sha,
                "nonce": nonce, "monotonic_ns": 10, "workers": [worker],
            }
            owner_sha = digest_bytes(canon(owner_body))
            owner_event = {**owner_body, "ownership_sha256": owner_sha}
            authorization_body = {
                "schema": "allocatbelt.application-pressure-event.v1",
                "kind": "workers_authorized", "recipe_sha256": recipe_sha,
                "nonce": nonce, "ownership_sha256": owner_sha,
                "monotonic_ns": 11, "workers": [worker],
            }
            authorization_sha = digest_bytes(canon(authorization_body))
            authorization_event = {**authorization_body, "authorization_sha256": authorization_sha}
            start_event = {
                "schema": "allocatbelt.application-pressure-event.v1",
                "kind": "pressure_start", "sequence": -1,
                "recipe_sha256": recipe_sha, "nonce": nonce,
                "monotonic_ns": 12, "ownership_sha256": owner_sha,
                "authorization_sha256": authorization_sha, "workers": [worker],
            }
            events_raw = b"".join(canon(item) for item in (owner_event, authorization_event, start_event))
            write_private(pressure_dir / "events.jsonl", events_raw)
            pressure_info = {
                "value": pressure_recipe,
                "recipe_sha256": recipe_sha,
                "raw_sha256": raw_sha,
                "condition_sha256": condition_sha,
            }
            marker = {
                "ownership_protocol": module.SOURCE_V5_PRESSURE_OWNERSHIP_PROTOCOL,
                "worker_ownership_sha256": owner_sha,
                "worker_authorization_sha256": authorization_sha,
            }
            ready_sha = "d" * 64
            with mock.patch.object(module, "_read_pressure_ready", return_value=(marker, ready_sha)):
                checked, captured_sha = module._require_source_v5_pressure_prefix(
                    pressure_dir, pressure_info, ready_sha,
                )
            self.assertEqual(checked, marker)
            self.assertEqual(captured_sha, ready_sha)

            with mock.patch.object(module, "_read_pressure_ready", return_value=(
                {**marker, "worker_authorization_sha256": "e" * 64}, ready_sha,
            )):
                with self.assertRaisesRegex(module.SoakReadbackError, "does not bind the durable ownership"):
                    module._require_source_v5_pressure_prefix(pressure_dir, pressure_info, ready_sha)

            pressure_info["reader"] = SimpleNamespace(verify_pressure=mock.Mock())
            audit = {
                "source": {"pressure_recipe": pressure_info},
                "recipe": {
                    "pressure": {"recipe": {
                        "path": str(recipe_path), "raw_sha256": raw_sha,
                        "semantic_sha256": recipe_sha,
                    }},
                    "qualification": {"pressure_condition": {"readiness_thresholds": {
                        "minimum_ready_samples": 1, "minimum_overlap_seconds": 1,
                    }}},
                },
            }
            legacy_marker = {"schema": "allocatbelt.application-pressure-ready.v1"}
            with mock.patch.object(module, "_pressure_output_hashes", return_value={
                "run": "1" * 64, "events": "2" * 64, "launch": "3" * 64,
                "process_binding": "4" * 64, "ready": ready_sha,
            }), mock.patch.object(module, "_read_pressure_ready", return_value=(legacy_marker, ready_sha)):
                with self.assertRaisesRegex(module.SoakReadbackError, "requires the durable worker ownership protocol"):
                    module._validate_pressure_proof(root, audit)
            pressure_info["reader"].verify_pressure.assert_not_called()

    def test_external_v2_term_hup_cover_pressure_first_lifecycle_and_restore_handlers(self):
        sentinel_handlers = {
            signal.SIGTERM: lambda _signum, _frame: None,
            signal.SIGHUP: lambda _signum, _frame: None,
        }
        original_handlers = {signum: signal.getsignal(signum) for signum in sentinel_handlers}
        for signum, handler in sentinel_handlers.items():
            signal.signal(signum, handler)
        try:
            stages = (
                ("pressure_popen", signal.SIGTERM, False),
                ("readiness", signal.SIGHUP, False),
                ("app_popen", signal.SIGTERM, False),
                ("final_driver_wait", signal.SIGHUP, False),
                ("cleanup", signal.SIGTERM, False),
                ("app_cleanup_failure", signal.SIGTERM, True),
            )
            for stage, signum, app_cleanup_failure in stages:
                with self.subTest(stage=stage, signum=signum), tempfile.TemporaryDirectory(
                    prefix=f"allocatbelt-soak-v2-signal-{stage}-"
                ) as temporary:
                    root = Path(temporary)
                    output = root / "output"
                    output.mkdir(mode=0o700)
                    driver = root / "pressure-driver.py"
                    driver.write_text("# pinned test driver\n", encoding="ascii")
                    binary = root / "soak-binary"
                    write_private(binary, b"soak binary", 0o700)

                    class FakePressure:
                        pid = 600

                        def __init__(self):
                            self.returncode = None

                        def poll(self):
                            return self.returncode

                        def wait(self, timeout=None):
                            if stage == "final_driver_wait" and self.returncode is None:
                                os.kill(os.getpid(), signum)
                            self.returncode = 0
                            return 0

                    pressure_process = FakePressure()
                    audit, descriptor, pressure_recipe = source_v5_pressure_fixture(
                        root, output, binary, driver, "2", 11_050, f"run-{stage}",
                    )
                    pressure_dir = output / "pressure"
                    args = SimpleNamespace(
                        command=["--", *descriptor["argv"]], cpu_set="2",
                        output_dir=output, timeout_seconds=11_050, term_grace_seconds=1.5,
                    )
                    events: list[str] = []
                    sessions: dict[tuple[str, int | None], dict[str, Any]] = {}

                    def fake_popen(_command, **_kwargs):
                        events.append("pressure_popen")
                        if stage == "pressure_popen":
                            os.kill(os.getpid(), signum)
                        return pressure_process

                    def ready(*_args, **kwargs):
                        kwargs["capture_workers"]()
                        events.append("ready")
                        marker = write_fixture_pressure_prefix(pressure_dir, pressure_recipe)
                        if stage == "readiness":
                            os.kill(os.getpid(), signum)
                        return marker

                    def capture_workers(_pid, _start, _path, _recipe_sha, _schedule, target, _nonce, **_kwargs):
                        for role, pid in (("cpu", 501), ("disk", 502), ("loopback", 503)):
                            key = (role, 2) if role == "cpu" else (role, None)
                            target[key] = {
                                "pid": pid, "start_ticks": pid, "pgid": pid,
                                "session_id": pid, "parent_pid": 600,
                                "role": role, "cpu": 2 if role == "cpu" else None,
                            }

                    def fake_launch(
                        command, _cpu_set, _stdout, _stderr, _timing, _timeout, _grace,
                        _monitored, *, environment, cwd, expected_executable_sha256,
                        return_details, on_started, monitor, on_signal, on_cleanup,
                        timeout_from_before_popen, timeout_includes_cleanup,
                    ):
                        self.assertTrue(return_details)
                        self.assertTrue(timeout_from_before_popen)
                        self.assertTrue(timeout_includes_cleanup)
                        self.assertTrue(callable(on_signal))
                        app = fake_owned_app_process(700)
                        on_started(app, Path(command[0]), expected_executable_sha256,
                                   Path(command[0]).stat(), {2}, cwd, environment)
                        events.append("app_popen")
                        monitor(app)
                        if stage in ("app_popen", "app_cleanup_failure"):
                            os.kill(os.getpid(), signum)
                        if stage == "app_cleanup_failure":
                            raise module.SoakReadbackError("injected application reap failure")
                        on_cleanup({
                            "schema": "allocatbelt.application-soak-process-cleanup.v1",
                            "status": "verified", "pid": app.pid,
                            "return_code": 1 if stage == "cleanup" else 0,
                            "received_signal": None, "cleanup_error": None,
                        })
                        return {
                            "status": 1 if stage == "cleanup" else 0,
                            "child_return_code": 1 if stage == "cleanup" else 0,
                            "timed_out": False, "artifact_budget_exceeded": False,
                            "received_signal": None, "started_monotonic_ns": 1,
                            "ended_monotonic_ns": 2, "binary_path": command[0],
                            "binary_sha256": expected_executable_sha256,
                            "binary_device": 1, "binary_inode": 2, "binary_size": 3,
                            "requested_argv": command, "requested_argv_sha256": "a" * 64,
                            "executed_argv": command, "executed_file_descriptor": "/proc/self/fd/200",
                            "environment": environment, "environment_sha256": "b" * 64,
                            "cwd": str(cwd), "cpu_set": "2",
                        }

                    def stop_pressure(*_args, **_kwargs):
                        events.append("pressure_cleanup")
                        if stage == "cleanup":
                            os.kill(os.getpid(), signum)
                        pressure_process.returncode = 143

                    with mock.patch.object(module.subprocess, "Popen", side_effect=fake_popen), \
                         mock.patch.object(module, "_wait_pressure_ready", side_effect=ready), \
                         mock.patch.object(module, "_proc_start_ticks", return_value=123), \
                         mock.patch.object(module, "_proc_process_identity", return_value={
                             "pid": 700, "start_ticks": 701, "state": "S",
                             "parent_pid": os.getpid(), "pgid": 700, "session_id": 700,
                         }), \
                         mock.patch.object(module, "_capture_pressure_worker_sessions", side_effect=capture_workers), \
                         mock.patch.object(module, "_stop_pressure_session", side_effect=stop_pressure), \
                         mock.patch.object(module, "_wait_pressure_workers_gone", return_value=True), \
                         mock.patch.object(module, "_make_pressure_launch_binding", return_value={"schema": "binding.v1"}), \
                         mock.patch.object(module, "_make_application_launch_attestation", return_value={"schema": "attestation.fixture.v1"}), \
                         mock.patch.object(module, "launch_process", side_effect=fake_launch), \
                         mock.patch.object(module, "_launch_receipt_value", return_value={"schema": "launch.v1"}), \
                         mock.patch.object(module, "_validate_pressure_proof") as validate_proof:
                        if app_cleanup_failure:
                            with self.assertRaisesRegex(module.SoakReadbackError, "application_cleanup='unverified'"):
                                module.command_launch_v2(
                                    args, audit,
                                    {"terminal_budget_bytes": 1024, "sample_budget_bytes": 1024},
                                    output,
                                )
                        else:
                            status = module.command_launch_v2(
                                args, audit,
                                {"terminal_budget_bytes": 1024, "sample_budget_bytes": 1024},
                                output,
                            )
                    if not app_cleanup_failure:
                        self.assertEqual(status, 128 + signum)
                    self.assertIn("pressure_cleanup", events)
                    self.assertIsNotNone(pressure_process.returncode, "interrupted pressure child was not cleaned up")
                    validate_proof.assert_not_called()
                    receipt = json.loads((output / "soak-supervisor-interruption.json").read_text(encoding="utf-8"))
                    self.assertEqual(receipt["schema"], "allocatbelt.application-soak-supervisor-interruption.v2")
                    self.assertEqual(receipt["signal"], signum)
                    self.assertEqual(receipt["exit_code"], 128 + signum)
                    expected_app_state = "unverified" if app_cleanup_failure else "not_started" if stage in ("pressure_popen", "readiness") else "verified"
                    self.assertEqual(receipt["application_cleanup"], expected_app_state)
                    self.assertEqual(receipt["pressure_cleanup"], "verified")
                    self.assertEqual(receipt["cleanup"], "unverified" if app_cleanup_failure else "verified")
                    for restored_signal, expected_handler in sentinel_handlers.items():
                        self.assertIs(signal.getsignal(restored_signal), expected_handler)
        finally:
            for signum, handler in original_handlers.items():
                signal.signal(signum, handler)

    def test_external_v2_real_app_term_and_hup_report_completed_cleanup(self):
        available_cpu = min(os.sched_getaffinity(0))
        original_handlers = {
            signal.SIGTERM: signal.getsignal(signal.SIGTERM),
            signal.SIGHUP: signal.getsignal(signal.SIGHUP),
        }
        original_popen = subprocess.Popen
        for signum, fail_reap in ((signal.SIGTERM, False), (signal.SIGHUP, False), (signal.SIGTERM, True)):
            with self.subTest(signum=signum), tempfile.TemporaryDirectory(
                prefix=f"allocatbelt-soak-v2-real-signal-{signum}-"
            ) as temporary:
                root = Path(temporary)
                output = root / "output"
                output.mkdir(mode=0o700)
                driver = root / "pressure-driver.py"
                driver.write_text("# pinned test driver\n", encoding="ascii")
                binary = root / "signal-soak.py"
                code = (
                    "#!/usr/bin/python3\nimport os,pathlib,signal,sys,time\n"
                    + ("signal.signal(signal.SIGTERM, signal.SIG_IGN)\n" if fail_reap else "")
                    + "args=sys.argv; out=pathlib.Path(args[args.index('--output-dir')+1])\n"
                    "pathlib.Path(out/'app-started').write_text(str(os.getpid()))\n"
                    "time.sleep(0.3)\n"
                    f"os.kill(os.getppid(), {int(signum)})\n"
                    "time.sleep(60)\n"
                )
                write_private(binary, code.encode("ascii"), 0o700)
                binary.chmod(0o700)
                audit, descriptor, pressure_recipe = source_v5_pressure_fixture(
                    root, output, binary, driver, str(available_cpu), 5,
                    f"real-signal-{int(signum)}",
                )
                started = output / "app-started"
                pressure_dir = output / "pressure"
                pressure_process = SimpleNamespace(pid=600, returncode=None)
                pressure_process.poll = lambda: pressure_process.returncode
                args = SimpleNamespace(
                    command=["--", *descriptor["argv"]], cpu_set=str(available_cpu), output_dir=output,
                    timeout_seconds=5.0, term_grace_seconds=1.5,
                )
                self.assertIs(type(args.timeout_seconds), float)
                self.assertEqual(args.timeout_seconds, descriptor["application_wall_timeout_seconds"])
                app_identity: dict[str, int] = {}

                def fake_popen(command, **kwargs):
                    if len(command) >= 3 and command[1:3] == [str(driver), "run"]:
                        return pressure_process
                    return original_popen(command, **kwargs)

                def capture_workers(_pid, _start, _path, _recipe_sha, _schedule, sessions, nonce, **_kwargs):
                    for role, pid in (("cpu", 501), ("disk", 502), ("loopback", 503)):
                        key = (role, available_cpu) if role == "cpu" else (role, None)
                        sessions[key] = {
                            "pid": pid, "start_ticks": pid, "pgid": pid,
                            "session_id": pid, "parent_pid": 600,
                            "role": role, "cpu": available_cpu if role == "cpu" else None,
                            "nonce": nonce,
                        }

                def ready(*_args, **kwargs):
                    kwargs["capture_workers"]()
                    return write_fixture_pressure_prefix(pressure_dir, pressure_recipe)

                def stop_pressure(*_args, **_kwargs):
                    pressure_process.returncode = 0

                def make_binding(process, *_args):
                    observed = module._proc_process_identity(process.pid)
                    self.assertIsNotNone(observed)
                    app_identity.update(pid=process.pid, start_ticks=observed["start_ticks"])
                    return {"schema": "binding.v1"}

                original_owned_reap = module._OwnedProcessGroup.reap_if_ready
                injected_app_reaps = []

                def fail_owned_app_reap(owner, *reap_args, **reap_kwargs):
                    if owner.pid == app_identity.get("pid"):
                        injected_app_reaps.append(owner.pid)
                        raise module.SoakReadbackError("injected app reap failure")
                    return original_owned_reap(owner, *reap_args, **reap_kwargs)

                cleanup_patch = (
                    mock.patch.object(module._OwnedProcessGroup, "reap_if_ready", autospec=True, side_effect=fail_owned_app_reap)
                    if fail_reap else contextlib.nullcontext()
                )
                try:
                    with mock.patch.object(module.subprocess, "Popen", side_effect=fake_popen), \
                         mock.patch.object(module, "_wait_pressure_ready", side_effect=ready), \
                         mock.patch.object(module, "_proc_start_ticks", return_value=123), \
                         mock.patch.object(module, "_capture_pressure_worker_sessions", side_effect=capture_workers), \
                         mock.patch.object(module, "_stop_pressure_session", side_effect=stop_pressure), \
                         mock.patch.object(module, "_make_pressure_launch_binding", side_effect=make_binding), \
                         mock.patch.object(module, "_make_application_launch_attestation", return_value={"schema": "attestation.fixture.v1"}), \
                         mock.patch.object(module, "_launch_receipt_value", return_value={"schema": "launch.v1"}), \
                         mock.patch.object(module, "_validate_pressure_proof") as validate_proof, \
                         cleanup_patch as app_reap_probe:
                        if fail_reap:
                            with self.assertRaisesRegex(module.SoakReadbackError, "application_cleanup='failed'"):
                                module.command_launch_v2(
                                    args, audit,
                                    {"terminal_budget_bytes": 1024, "sample_budget_bytes": 1024},
                                    output,
                                )
                        else:
                            callback_records = []
                            supervisor_receipt = module.launch_soak_v2_application(
                                args, audit,
                                {"terminal_budget_bytes": 1024, "sample_budget_bytes": 1024},
                                output,
                                on_started=lambda value: callback_records.append(("started", value)),
                                on_cleanup=lambda value: callback_records.append(("cleanup", value)),
                            )
                            status = supervisor_receipt["status"]
                    if not fail_reap:
                        self.assertEqual(status, 128 + signum)
                        self.assertTrue(supervisor_receipt["interrupted"])
                        self.assertEqual(supervisor_receipt["received_signal"], signum)
                        self.assertEqual([kind for kind, _value in callback_records], ["started", "cleanup"])
                        self.assertEqual(callback_records[1][1], supervisor_receipt["application_cleanup"])
                        self.assertEqual(callback_records[1][1]["pid"], app_identity["pid"])
                        self.assertEqual(callback_records[1][1]["status"], "verified")
                    else:
                        app_reap_probe.assert_called()
                        self.assertTrue(injected_app_reaps, "reap failure must target the actual APP child")
                    validate_proof.assert_not_called()
                finally:
                    if fail_reap and app_identity:
                        observed = module._proc_process_identity(app_identity["pid"])
                        if observed is not None and observed["start_ticks"] == app_identity["start_ticks"]:
                            self.assertEqual(observed["pgid"], app_identity["pid"])
                            self.assertEqual(observed["session_id"], app_identity["pid"])
                            if observed["state"] not in ("Z", "X"):
                                os.killpg(app_identity["pid"], signal.SIGKILL)
                            try:
                                os.waitpid(app_identity["pid"], 0)
                            except ChildProcessError:
                                pass
                self.assertTrue(started.is_file(), "real app process did not reach its signal point")
                self.assertIsNotNone(pressure_process.returncode)
                validate_proof.assert_not_called()
                receipt = json.loads((output / "soak-supervisor-interruption.json").read_text(encoding="utf-8"))
                self.assertEqual(receipt["signal"], signum)
                self.assertEqual(receipt["application_cleanup"], "failed" if fail_reap else "verified")
                self.assertEqual(receipt["pressure_cleanup"], "verified")
                self.assertEqual(receipt["cleanup"], "failed" if fail_reap else "verified")
                for restored_signal, handler in original_handlers.items():
                    self.assertIs(signal.getsignal(restored_signal), handler)

    def test_external_v2_preserves_internal_timeout_and_artifact_limit_status(self):
        available_cpu = min(os.sched_getaffinity(0))
        original_handlers = {
            signal.SIGTERM: signal.getsignal(signal.SIGTERM),
            signal.SIGHUP: signal.getsignal(signal.SIGHUP),
        }
        original_popen = subprocess.Popen
        for failure_mode, expected_status in (("timeout", 124), ("artifact_limit", 125)):
            with self.subTest(failure_mode=failure_mode), tempfile.TemporaryDirectory(
                prefix=f"allocatbelt-soak-v2-internal-{failure_mode}-"
            ) as temporary:
                root = Path(temporary)
                output = root / "output"
                output.mkdir(mode=0o700)
                driver = root / "pressure-driver.py"
                driver.write_text("# pinned test driver\n", encoding="ascii")
                binary = root / "bounded-soak.py"
                if failure_mode == "timeout":
                    body = "#!/usr/bin/python3\nimport signal,time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(5)\n"
                else:
                    body = (
                        "#!/usr/bin/python3\nimport os,pathlib,signal,time\n"
                        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                        "pathlib.Path(os.environ['ALLOCATBELT_SOAK_TERMINALS']).write_bytes(b'x'*4096)\n"
                        "time.sleep(5)\n"
                    )
                write_private(binary, body.encode("ascii"), 0o700)
                binary.chmod(0o700)
                terminal_path = output / "terminal-records.tsv"
                audit, descriptor, pressure_recipe = source_v5_pressure_fixture(
                    root, output, binary, driver, str(available_cpu), 3,
                    f"internal-{failure_mode}",
                )
                pressure_dir = output / "pressure"
                argv = descriptor["argv"]
                pressure_process = SimpleNamespace(pid=600, returncode=None)
                pressure_process.poll = lambda: pressure_process.returncode
                args = SimpleNamespace(
                    command=["--", *argv], cpu_set=str(available_cpu), output_dir=output,
                    timeout_seconds=3.0, term_grace_seconds=1.5,
                )

                def fake_popen(command, **kwargs):
                    if len(command) >= 3 and command[1:3] == [str(driver), "run"]:
                        return pressure_process
                    return original_popen(command, **kwargs)

                def capture_workers(_pid, _start, _path, _recipe_sha, _schedule, sessions, nonce, **_kwargs):
                    for role, pid in (("cpu", 501), ("disk", 502), ("loopback", 503)):
                        key = (role, available_cpu) if role == "cpu" else (role, None)
                        sessions[key] = {
                            "pid": pid, "start_ticks": pid, "pgid": pid,
                            "session_id": pid, "parent_pid": 600,
                            "role": role, "cpu": available_cpu if role == "cpu" else None,
                            "nonce": nonce,
                        }

                def ready(*_args, **kwargs):
                    kwargs["capture_workers"]()
                    return write_fixture_pressure_prefix(pressure_dir, pressure_recipe)

                def stop_pressure(*_args, **_kwargs):
                    pressure_process.returncode = 0

                with mock.patch.object(module.subprocess, "Popen", side_effect=fake_popen), \
                     mock.patch.object(module, "_wait_pressure_ready", side_effect=ready), \
                     mock.patch.object(module, "_proc_start_ticks", return_value=123), \
                     mock.patch.object(module, "_capture_pressure_worker_sessions", side_effect=capture_workers), \
                     mock.patch.object(module, "_stop_pressure_session", side_effect=stop_pressure), \
                     mock.patch.object(module, "_make_pressure_launch_binding", return_value={"schema": "binding.v1"}), \
                     mock.patch.object(module, "_make_application_launch_attestation", return_value={"schema": "attestation.fixture.v1"}), \
                     mock.patch.object(module, "_launch_receipt_value", return_value={"schema": "launch.v1"}), \
                     mock.patch.object(module, "_validate_pressure_proof") as validate_proof:
                    status = module.command_launch_v2(
                        args, audit,
                        {"terminal_budget_bytes": 128, "sample_budget_bytes": 1024},
                        output,
                    )
                self.assertEqual(status, expected_status)
                self.assertIsNotNone(pressure_process.returncode)
                self.assertFalse((output / "soak-supervisor-interruption.json").exists())
                validate_proof.assert_not_called()
                for signum, handler in original_handlers.items():
                    self.assertIs(signal.getsignal(signum), handler)

    def test_external_launch_is_refused_while_source_v5_readiness_is_false(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-v2-disabled-") as temporary:
            output = Path(temporary) / "output"
            output.mkdir(mode=0o700)
            preflight_path = output / "soak-preflight.json"
            write_private(preflight_path, b"{}\n")
            descriptor = {"launch_enabled": False, "argv": []}
            audit = {
                "recipe": {"schema": module.RECIPE_SCHEMA_V2},
                "launch_enabled": False,
                "launch_descriptor": descriptor,
            }
            args = SimpleNamespace(
                command=["--", "should-not-run"], output_dir=output,
                recipe=Path(temporary) / "recipe.json", recipe_sha256="1" * 64,
                preflight=preflight_path, binary=Path(temporary) / "binary",
            )
            with mock.patch.object(module, "_current_audit", return_value=(audit, {"schema": "preflight"})), \
                 mock.patch.object(module.subprocess, "Popen") as popen:
                with self.assertRaisesRegex(module.SoakReadbackError, "remains launch-disabled"):
                    module.command_launch(args)
                popen.assert_not_called()

    def test_external_pressure_samples_allow_policy_bounded_adaptive_controls(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-external-samples-") as temporary:
            fixture = Fixture(Path(temporary), profile="mixed", duration=2)
            audit = fixture.audit()
            audit["recipe"]["schema"] = module.RECIPE_SCHEMA_V2
            audit["source"]["feedback_context"] = {
                "controls": {
                    "cpu": {"floor": 1, "ceiling": 4},
                    "disk": {"floor": 64 * 1024**2, "ceiling": module.RATE_BYTES_PER_SECOND},
                    "download": {"floor": 64 * 1024**2, "ceiling": module.RATE_BYTES_PER_SECOND},
                },
            }
            _, _, sample_bytes = fixture.write_receipt_and_streams()
            fields = sample_bytes.splitlines()[1].decode("ascii").split("\t")
            row = {name: int(value) for name, value in zip(module.SAMPLE_HEADER, fields, strict=True)}
            row["global_cpu_limit"] = 3
            row["tenant_cpu_limit"] = 2
            row["disk_rate_limit_bps"] = 128 * 1024**2
            row["download_rate_limit_bps"] = 96 * 1024**2
            module._check_numeric_sample(row, audit, 0)

            row["tenant_cpu_limit"] = 5
            with self.assertRaisesRegex(module.SoakReadbackError, "CPU limit is outside"):
                module._check_numeric_sample(row, audit, 0)

    def test_runtime_soak_v2_requires_exact_clock_brackets_and_nonselfeligibility(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-v2-receipt-") as temporary:
            fixture = Fixture(Path(temporary), profile="mixed", mode="functional", duration=2)
            receipt, _terminal, _samples = fixture.write_receipt_and_streams()
            audit = fixture.audit()
            audit["recipe"]["schema"] = module.RECIPE_SCHEMA_V2
            audit["identity"]["comparison_family"] = "external_pressure"
            receipt["schema"] = module.RUNTIME_SOAK_SCHEMA_V2
            receipt["comparison_family"] = "external_pressure"
            receipt["mode"] = "soak"
            receipt["qualification_eligible"] = False
            receipt["feedback_started"] = True
            receipt["feedback_worker_joined"] = True
            receipt["feedback_worker_failure"] = None
            receipt["feedback_trace_worker_joined"] = True
            for phase, scalar_name in (
                ("started", "started_monotonic_ns"),
                ("trace_ended", "trace_ended_monotonic_ns"),
                ("drain_ended", "drain_ended_monotonic_ns"),
                ("shutdown_ended", "shutdown_ended_monotonic_ns"),
                ("postprocess_ended", "postprocess_ended_monotonic_ns"),
            ):
                scalar = receipt[scalar_name]
                receipt[f"{phase}_monotonic_lower_ns"] = scalar
                receipt[f"{phase}_monotonic_upper_ns"] = scalar
            receipt_path = fixture.output / "soak-receipt-v2.json"
            write_private(receipt_path, canon(receipt))
            checked, checked_sha, _ = module._validate_receipt_json(receipt_path, fixture.output, audit)
            self.assertEqual(checked["schema"], module.RUNTIME_SOAK_SCHEMA_V2)
            self.assertEqual(checked_sha, digest_bytes(canon(receipt)))
            audit["source"]["feedback_context"] = {
                "controls": {
                    "cpu": {"floor": 1, "ceiling": 4},
                    "disk": {"floor": 64 * 1024**2, "ceiling": module.RATE_BYTES_PER_SECOND},
                    "download": {"floor": 64 * 1024**2, "ceiling": module.RATE_BYTES_PER_SECOND},
                },
            }
            samples = module._parse_samples(fixture.output / "resource-samples.tsv", checked, audit, module.MAX_SAMPLE_BYTES)
            phases = module._validate_phase_and_receipt(checked, audit, 12, samples)
            self.assertFalse(phases["qualification_eligible"])
            self.assertEqual(phases["monotonic_endpoints"]["started"], [receipt["started_monotonic_ns"]] * 2)

            receipt["started_monotonic_ns"] += 1
            broken_path = fixture.output / "soak-receipt-v2-broken.json"
            write_private(broken_path, canon(receipt))
            with self.assertRaisesRegex(module.SoakReadbackError, "scalar is not the lower"):
                module._validate_receipt_json(broken_path, fixture.output, audit)

            receipt["started_monotonic_ns"] -= 1
            receipt["qualification_eligible"] = True
            dishonest_path = fixture.output / "soak-receipt-v2-dishonest.json"
            write_private(dishonest_path, canon(receipt))
            with self.assertRaisesRegex(module.SoakReadbackError, "cannot author its own"):
                module._validate_receipt_json(dishonest_path, fixture.output, audit)

    def test_oversubscribed_derives_two_slots_from_canonical_ordinary_policy(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-oversubscribed-") as temp:
            fixture = Fixture(Path(temp), profile="oversubscribed")
            frozen_manifest = fixture.manifest_path.read_bytes()
            audit = fixture.audit()
            self.assertEqual(audit["source"]["domain_ceilings"]["cpu"], 2)
            self.assertEqual(audit["recipe"]["runtime"]["resource_limits"]["cpu_charges"], 2)
            self.assertEqual(fixture.manifest_path.read_bytes(), frozen_manifest)
            policy = json.loads(frozen_manifest)["fixed_runtime_policy"]["policy"]
            self.assertEqual(policy["workloads"]["mixed"]["domain_ceiling"]["cpu"], 4)
            for profile in ("mixed", "burst", "oversubscribed"):
                self.assertEqual(module._expected_mixed_limits(profile, policy)[0]["cpu_charges"], 2 if profile == "oversubscribed" else 4)
            self.assertEqual(policy["workloads"]["mixed"]["domain_ceiling"]["cpu"], 4)

    def test_oversubscribed_rejects_rewritten_artifact_or_worker_map(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-policy-rewrite-") as temp:
            fixture = Fixture(Path(temp), profile="oversubscribed")
            original = json.loads(fixture.manifest_path.read_bytes())["fixed_runtime_policy"]["policy"]
            rewritten = json.loads(json.dumps(original))
            rewritten["workloads"]["mixed"]["domain_ceiling"]["cpu"] = 2
            with self.assertRaisesRegex(module.SoakReadbackError, "domain ceiling"):
                module._expected_mixed_limits("oversubscribed", rewritten)
            for section, name in (("domain_ceiling", "cpu"), ("domain_ceiling", "memory"), ("scope_limits", "disk_operation_limit")):
                rewritten = json.loads(json.dumps(original))
                rewritten["workloads"]["mixed"][section][name] = float(rewritten["workloads"]["mixed"][section][name])
                with self.assertRaisesRegex(module.SoakReadbackError, "integer"):
                    module._expected_mixed_limits("oversubscribed", rewritten)
            for ordinary, oversubscribed in ((2, 2), (4, 4), (True, 2), (4.0, 2), (4, 2.0)):
                rewritten = json.loads(json.dumps(original))
                rewritten["workers_by_profile"] = {"ordinary": ordinary, "oversubscribed": oversubscribed}
                with self.assertRaisesRegex(module.SoakReadbackError, "worker map"):
                    module._expected_mixed_limits("oversubscribed", rewritten)

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

    def test_native_child_wait_and_group_signals_precede_the_only_reap(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-owned-order-") as temporary:
            root = Path(temporary)
            child_pid_path = root / "descendant.pid"
            descendant = (
                "import pathlib,signal,sys,time; "
                "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                "pathlib.Path(sys.argv[1]).write_text(str(__import__('os').getpid())); time.sleep(60)"
            )
            leader = (
                "import pathlib,subprocess,sys,time; "
                "subprocess.Popen([sys.executable,'-c',sys.argv[2],sys.argv[1]],"
                "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
                "p=pathlib.Path(sys.argv[1]); deadline=time.monotonic()+2; "
                "exec('while not p.exists() and time.monotonic()<deadline: time.sleep(0.005)'); "
                "print('owned child complete')"
            )

            checked_output, checked_events, checked_pid = self._run_with_owned_wait_trace(
                lambda: module._run_checked(
                    [sys.executable, "-c", leader, str(child_pid_path), descendant],
                    root,
                    "owned ordering fixture",
                    timeout=3,
                )
            )
            self.assertEqual(checked_output, b"owned child complete\n")
            self._assert_owned_reap_is_last(checked_events, checked_pid)
            self.assertIn(("killpg", signal.SIGTERM), checked_events)
            self.assertIn(("killpg", signal.SIGKILL), checked_events)
            self.assertTrue(self._wait_process_stopped(int(child_pid_path.read_text(encoding="ascii"))))

            child_pid_path.unlink()
            output = root / "launch-output"
            output.mkdir(mode=0o700)
            launch_status, launch_events, launch_pid = self._run_with_owned_wait_trace(
                lambda: module.launch_process(
                    [sys.executable, "-c", leader, str(child_pid_path), descendant],
                    str(min(os.sched_getaffinity(0))),
                    output / "stdout.log", output / "stderr.log", output / "time.txt",
                    timeout_seconds=3,
                    term_grace_seconds=0.2,
                )
            )
            self.assertEqual(launch_status, 0)
            self._assert_owned_reap_is_last(launch_events, launch_pid)
            self.assertIn(("killpg", signal.SIGTERM), launch_events)
            self.assertIn(("killpg", signal.SIGKILL), launch_events)
            self.assertTrue(self._wait_process_stopped(int(child_pid_path.read_text(encoding="ascii"))))

    def test_late_hup_during_post_exit_binary_hash_never_reuses_the_reaped_pgid(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-late-hup-") as temporary:
            root = Path(temporary)
            output = root / "launch-output"
            output.mkdir(mode=0o700)
            hash_calls = 0
            original_hash = module._hash_open_executable
            callback_signals = []

            def signal_during_final_hash(*args, **kwargs):
                nonlocal hash_calls
                hash_calls += 1
                if hash_calls == 2:
                    os.kill(os.getpid(), signal.SIGHUP)
                return original_hash(*args, **kwargs)

            details, events, pid = self._run_with_owned_wait_trace(
                lambda: module.launch_process(
                    [sys.executable, "-c", "pass"],
                    str(min(os.sched_getaffinity(0))),
                    output / "stdout.log", output / "stderr.log", output / "time.txt",
                    timeout_seconds=3,
                    return_details=True,
                    on_signal=callback_signals.append,
                ),
                hash_wrapper=signal_during_final_hash,
            )
            self.assertEqual(details["status"], 128 + signal.SIGHUP)
            self.assertEqual(details["received_signal"], signal.SIGHUP)
            self.assertEqual(callback_signals, [signal.SIGHUP])
            self._assert_owned_reap_is_last(events, pid)

    def test_late_term_and_hup_during_cleanup_receipt_write_update_final_details(self):
        for signum in (signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signum=signum), tempfile.TemporaryDirectory(prefix=f"allocatbelt-soak-late-cleanup-{signum}-") as temporary:
                root = Path(temporary)
                output = root / "launch-output"
                output.mkdir(mode=0o700)
                cleanup_receipt_path = output / "cleanup-record.json"
                callback_signals = []
                original_writer = module._write_exclusive_json
                original_handlers = {
                    handled: signal.getsignal(handled)
                    for handled in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
                }

                def signal_during_cleanup_receipt(path, value):
                    if Path(path) == cleanup_receipt_path:
                        os.kill(os.getpid(), signum)
                    return original_writer(path, value)

                def persist_cleanup_receipt(value):
                    module._write_exclusive_json(cleanup_receipt_path, value)

                details, events, pid = self._run_with_owned_wait_trace(
                    lambda: module.launch_process(
                        [sys.executable, "-c", "pass"],
                        str(min(os.sched_getaffinity(0))),
                        output / "stdout.log", output / "stderr.log", output / "time.txt",
                        timeout_seconds=3,
                        return_details=True,
                        on_signal=callback_signals.append,
                        on_cleanup=persist_cleanup_receipt,
                    ),
                    write_wrapper=signal_during_cleanup_receipt,
                )
                cleanup_receipt = module._readback_json(cleanup_receipt_path, "late-signal cleanup receipt")
                self.assertEqual(details["status"], 128 + signum)
                self.assertEqual(details["received_signal"], signum)
                self.assertEqual(callback_signals, [signum])
                self.assertEqual(cleanup_receipt["received_signal"], signum)
                self.assertEqual(cleanup_receipt["status"], "verified")
                self.assertEqual(
                    {handled: signal.getsignal(handled) for handled in original_handlers},
                    original_handlers,
                )
                self._assert_owned_reap_is_last(events, pid)

    def test_group_scan_failure_uses_only_the_held_default_owner_for_fallback_signals(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-group-scan-fault-") as temporary:
            root = Path(temporary)
            output = root / "launch-output"
            output.mkdir(mode=0o700)
            original_scandir = os.scandir
            original_killpg = os.killpg
            scanner_calls = 0
            group_signals = []
            cleanup_results = []

            def fail_one_proc_scan(path):
                nonlocal scanner_calls
                if os.fspath(path) == "/proc" and scanner_calls == 0:
                    scanner_calls += 1
                    raise PermissionError(13, "injected process-table scan fault", "/proc")
                return original_scandir(path)

            def record_group_signal(pgid, signum):
                group_signals.append(signum)
                return original_killpg(pgid, signum)

            with mock.patch.object(module.os, "scandir", side_effect=fail_one_proc_scan), \
                 mock.patch.object(module.os, "killpg", side_effect=record_group_signal):
                with self.assertRaisesRegex(module.SoakReadbackError, "could not verify its process group"):
                    module.launch_process(
                        [sys.executable, "-c", "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)"],
                        str(min(os.sched_getaffinity(0))),
                        output / "stdout.log", output / "stderr.log", output / "time.txt",
                        timeout_seconds=0.25,
                        term_grace_seconds=0.1,
                        on_cleanup=cleanup_results.append,
                    )
            self.assertEqual(scanner_calls, 1)
            self.assertIn(signal.SIGTERM, group_signals, "scan-fault fallback did not signal while direct ownership was held")
            self.assertIn(signal.SIGKILL, group_signals)
            self.assertEqual(cleanup_results[0]["status"], "failed")
            self.assertIsInstance(cleanup_results[0]["return_code"], int)

    def test_sigchld_change_during_scan_blocks_group_signal_and_final_wait(self):
        for stage, child_code in (
            ("signal", "import time; time.sleep(30)"),
            ("final-wait", "pass"),
        ):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory(prefix=f"allocatbelt-soak-sigchld-{stage}-") as temporary:
                root = Path(temporary)
                pid_path = root / "app.pid"
                result_path = root / "result.json"
                wrapper = root / "sigchld-wrapper.py"
                wrapper.write_text(
                    "import importlib.machinery,importlib.util,json,os,signal,sys\n"
                    "from pathlib import Path\n"
                    "loader=importlib.machinery.SourceFileLoader('sigchld_readback',sys.argv[1])\n"
                    "spec=importlib.util.spec_from_loader(loader.name,loader)\n"
                    "module=importlib.util.module_from_spec(spec); loader.exec_module(module)\n"
                    "pid_path=Path(sys.argv[2]); result_path=Path(sys.argv[3]); cpu_set=sys.argv[4]\n"
                    "stage=sys.argv[5]; child_code=sys.argv[6]\n"
                    "group_signals=[]; waits=[]; watched_pid=None; changed=False\n"
                    "original_killpg=os.killpg; original_waitpid=os.waitpid\n"
                    "def record_killpg(pgid,signum):\n"
                    " global watched_pid\n"
                    " if pgid==watched_pid: group_signals.append(signum)\n"
                    " return original_killpg(pgid,signum)\n"
                    "def record_waitpid(pid,options):\n"
                    " global watched_pid\n"
                    " if pid==watched_pid: waits.append(pid)\n"
                    " return original_waitpid(pid,options)\n"
                    "os.killpg=record_killpg; os.waitpid=record_waitpid\n"
                    "original_scan=module._OwnedProcessGroup._scan_group_unlocked\n"
                    "def change_after_scan(owner):\n"
                    " global changed\n"
                    " result=original_scan(owner)\n"
                    " if not changed:\n"
                    "  signal.signal(signal.SIGCHLD,signal.SIG_IGN); changed=True\n"
                    " return result\n"
                    "module._OwnedProcessGroup._scan_group_unlocked=change_after_scan\n"
                    "def started(process,*_args):\n"
                    " global watched_pid\n"
                    " watched_pid=process.pid; pid_path.write_text(str(process.pid))\n"
                    "try:\n"
                    " module.launch_process([sys.executable,'-c',child_code],cpu_set,"
                    "result_path.parent/'stdout.log',result_path.parent/'stderr.log',result_path.parent/'time.txt',"
                    "timeout_seconds=0.2,term_grace_seconds=0.1,on_started=started)\n"
                    "except module.SoakReadbackError as error:\n"
                    " result_path.write_text(json.dumps({'error':str(error),'killpg':group_signals,'waitpid':waits,'stage':stage}))\n"
                    " raise SystemExit(42)\n"
                    "raise SystemExit(43)\n",
                    encoding="utf-8",
                )
                process = subprocess.Popen(
                    [sys.executable, "-B", str(wrapper), str(SCRIPT), str(pid_path), str(result_path),
                     str(min(os.sched_getaffinity(0))), stage, child_code],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                )
                stdout, stderr = process.communicate(timeout=3)
                self.assertEqual(process.returncode, 42, stderr.decode(errors="replace"))
                result = json.loads(result_path.read_text(encoding="utf-8"))
                self.assertIn("SIGCHLD", result["error"])
                self.assertEqual(result["killpg"], [], "ownership loss must prevent every numeric process-group signal")
                self.assertEqual(result["waitpid"], [], "unsupported wait semantics must not produce a child status")
                if stage == "signal":
                    child_pid = int(pid_path.read_text(encoding="ascii"))
                    try:
                        os.kill(child_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    self.assertTrue(self._wait_process_stopped(child_pid))

    def test_same_session_new_pgid_descendants_are_unverified_and_never_group_signaled(self):
        escaped_child = (
            "import json,os,pathlib,signal,sys,time; os.setpgid(0,0); "
            "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
            "raw=pathlib.Path(f'/proc/{os.getpid()}/stat').read_bytes(); tail=raw[raw.rfind(b')')+1:].split(); "
            "record={'pid':os.getpid(),'start_ticks':int(tail[19]),'pgid':os.getpgrp(),'session_id':os.getsid(0)}; "
            "pathlib.Path(sys.argv[1]).write_text(json.dumps(record,sort_keys=True)); time.sleep(60)"
        )
        ready_leader = (
            "import pathlib,subprocess,sys,time; "
            "subprocess.Popen([sys.executable,'-c',sys.argv[2],sys.argv[1]]); "
            "p=pathlib.Path(sys.argv[1]); deadline=time.monotonic()+2; "
            "exec('while not p.exists() and time.monotonic()<deadline: time.sleep(0.005)'); "
            "print('leader exited after escaped member was ready')"
        )
        capture_leader = (
            "import pathlib,subprocess,sys,time; "
            "subprocess.Popen([sys.executable,'-c',sys.argv[2],sys.argv[1]],"
            "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
            "p=pathlib.Path(sys.argv[1]); deadline=time.monotonic()+2; "
            "exec('while not p.exists() and time.monotonic()<deadline: time.sleep(0.005)'); "
            "print('capture leader exited after escaped member was ready')"
        )

        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-same-session-escape-") as temporary:
            root = Path(temporary)
            ready = root / "escaped.json"
            output = root / "launch-output"
            output.mkdir(mode=0o700)
            cleanup_results = []
            try:
                launch_result, launch_events, leader_pid = self._run_with_owned_wait_trace(
                    lambda: self._capture_launch_cleanup_failure(
                        [sys.executable, "-c", ready_leader, str(ready), escaped_child],
                        output, cleanup_results,
                    )
                )
                self.assertIn("same-session processes outside its owned process group", launch_result["error"])
                self.assertEqual(cleanup_results[0]["status"], "failed")
                self.assertEqual(cleanup_results[0]["return_code"], 0)
                escaped = json.loads(ready.read_text(encoding="utf-8"))
                self.assertNotEqual(escaped["pgid"], leader_pid)
                self.assertEqual(escaped["session_id"], leader_pid)
                self._assert_live_test_identity(escaped)
                self.assertEqual(os.stat(f"/proc/{escaped['pid']}/fd/1").st_ino, (output / "stdout.log").stat().st_ino)
                self.assertFalse(any(event[0] == "killpg" for event in launch_events), "escaped PGID must not be signaled through the leader's numeric PGID")
            finally:
                if ready.exists():
                    self._kill_retained_test_identity(json.loads(ready.read_text(encoding="utf-8")))

        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-capture-session-escape-") as temporary:
            root = Path(temporary)
            ready = root / "escaped.json"
            events = []
            original_killpg = os.killpg

            def trace_killpg(pgid, signum):
                events.append((pgid, signum))
                return original_killpg(pgid, signum)

            try:
                with mock.patch.object(module.os, "killpg", side_effect=trace_killpg):
                    with self.assertRaisesRegex(module.SoakReadbackError, "same-session processes outside its owned process group"):
                        module._run_checked(
                            [sys.executable, "-c", capture_leader, str(ready), escaped_child],
                            root,
                            "same-session capture escape fixture",
                            timeout=3,
                        )
                escaped = json.loads(ready.read_text(encoding="utf-8"))
                self.assertNotEqual(escaped["pgid"], escaped["session_id"])
                self._assert_live_test_identity(escaped)
                self.assertEqual(events, [], "capture cleanup must leave the escaped PGID untouched")
            finally:
                if ready.exists():
                    self._kill_retained_test_identity(json.loads(ready.read_text(encoding="utf-8")))

    @staticmethod
    def _capture_launch_cleanup_failure(command, output, cleanup_results):
        try:
            return module.launch_process(
                command,
                str(min(os.sched_getaffinity(0))),
                output / "stdout.log", output / "stderr.log", output / "time.txt",
                timeout_seconds=3,
                term_grace_seconds=0.2,
                on_cleanup=cleanup_results.append,
            )
        except module.SoakReadbackError as error:
            return {"error": str(error)}

    def _assert_live_test_identity(self, record):
        identity = module._parse_proc_stat(
            record["pid"], Path(f"/proc/{record['pid']}/stat").read_bytes(), "test-owned escaped descendant",
        )
        self.assertEqual(identity["start_ticks"], record["start_ticks"])
        self.assertEqual(identity["pgid"], record["pgid"])
        self.assertEqual(identity["session_id"], record["session_id"])
        self.assertNotIn(identity["state"], ("Z", "X"))

    def _kill_retained_test_identity(self, record):
        try:
            identity = module._parse_proc_stat(
                record["pid"], Path(f"/proc/{record['pid']}/stat").read_bytes(), "test-owned escaped descendant cleanup",
            )
        except FileNotFoundError:
            return
        if (identity["start_ticks"], identity["pgid"], identity["session_id"]) != (
            record["start_ticks"], record["pgid"], record["session_id"],
        ):
            raise AssertionError("escaped descendant PID no longer has the test's retained identity")
        os.kill(record["pid"], signal.SIGKILL)
        self.assertTrue(self._wait_process_stopped(record["pid"]))

    def test_proc_stat_zero_group_and_session_record_is_ignored_as_foreign(self):
        def stat_record(pid, parent_pid, pgid, sid, start_ticks):
            tail = ["S", str(parent_pid), str(pgid), str(sid), *(["0"] * 15), str(start_ticks)]
            return f"{pid} (kernel worker fixture) {' '.join(tail)}\n".encode("ascii")

        leader_pid = 4242
        foreign_pid = 900042
        leader_raw = stat_record(leader_pid, 42, leader_pid, leader_pid, 123456)
        foreign_raw = stat_record(foreign_pid, 2, 0, 0, 999999)

        class FakeProcEntry:
            def __init__(self, pid):
                self.name = str(pid)
                self.path = f"/proc/{pid}"

        class FakeProcEntries:
            def __enter__(self):
                return iter((FakeProcEntry(leader_pid), FakeProcEntry(foreign_pid)))

            def __exit__(self, *_args):
                return False

        owner = SimpleNamespace(
            pid=leader_pid,
            label="zero stat fixture",
            identity={"start_ticks": 123456, "parent_pid": 42},
        )
        original_read_bytes = Path.read_bytes

        def fake_read_bytes(path):
            if path == Path(f"/proc/{leader_pid}/stat"):
                return leader_raw
            if path == Path(f"/proc/{foreign_pid}/stat"):
                return foreign_raw
            return original_read_bytes(path)

        parsed_foreign = module._parse_proc_stat(foreign_pid, foreign_raw, "zero stat fixture")
        self.assertEqual((parsed_foreign["pgid"], parsed_foreign["session_id"]), (0, 0))
        with mock.patch.object(module.os, "scandir", return_value=FakeProcEntries()), \
             mock.patch.object(Path, "read_bytes", new=fake_read_bytes):
            members, escaped, scan_error = module._OwnedProcessGroup._scan_group_unlocked(owner)
        self.assertIsNone(scan_error)
        self.assertEqual([member["pid"] for member in members], [leader_pid])
        self.assertEqual(escaped, [])

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
            with self.assertRaisesRegex(module.SoakReadbackError, "retained credits exceed owner bounds"):
                module._parse_samples(sample_path, receipt, audit, fixture.recipe["runtime"]["sample_budget_bytes"])

    def test_soak_samples_accept_refill_while_two_original_owners_remain(self):
        for version in (module.RECIPE_SCHEMA, module.RECIPE_SCHEMA_V2):
            with self.subTest(version=version), tempfile.TemporaryDirectory(
                    prefix="soak-refilled-owners-") as temp:
                fixture = Fixture(Path(temp), profile="mixed", mode="functional", duration=2)
                audit = fixture.audit()
                receipt, _, raw = fixture.write_receipt_and_streams()
                if version == module.RECIPE_SCHEMA_V2:
                    audit["recipe"]["schema"] = version
                    audit["source"]["feedback_context"] = {"controls": {
                        "cpu": {"floor": 1, "ceiling": 4},
                        "disk": {"floor": 64 * 1024**2, "ceiling": module.RATE_BYTES_PER_SECOND},
                        "download": {"floor": 64 * 1024**2, "ceiling": module.RATE_BYTES_PER_SECOND},
                    }}
                lines = raw.decode("ascii").splitlines()
                header = lines[0].split("\t")
                values = lines[1].split("\t")
                burst = audit["source"]["byte_buckets"]["disk"]["ceiling_burst_bytes"]
                values[header.index("disk_rate_available_bytes")] = str(burst)
                values[header.index("disk_rate_reserved_bytes")] = str(2 * burst)
                values[header.index("disk_rate_reservations")] = "2"
                lines[1] = "\t".join(values)
                changed = ("\n".join(lines) + "\n").encode("ascii")
                path = fixture.output / "resource-samples.tsv"
                path.unlink()
                write_private(path, changed)
                receipt["resource_samples_sha256"] = digest_bytes(changed)
                module._parse_samples(
                    path, receipt, audit,
                    fixture.recipe["runtime"]["sample_budget_bytes"],
                )

    def test_soak_samples_reject_owner_and_token_overcommit_in_both_versions(self):
        with tempfile.TemporaryDirectory(prefix="soak-invalid-balances-") as temp:
            fixture = Fixture(Path(temp), profile="mixed", mode="functional", duration=2)
            audit = fixture.audit()
            _, _, raw = fixture.write_receipt_and_streams()
            header, values = (line.split("\t") for line in raw.decode("ascii").splitlines()[:2])
            row = dict(zip(header, map(int, values), strict=True))
            for version in (module.RECIPE_SCHEMA, module.RECIPE_SCHEMA_V2):
                audit["recipe"]["schema"] = version
                audit["source"]["feedback_context"] = {"controls": {
                    "cpu": {"floor": 1, "ceiling": 4},
                    "disk": {"floor": 64 * 1024**2, "ceiling": module.RATE_BYTES_PER_SECOND},
                    "download": {"floor": 64 * 1024**2, "ceiling": module.RATE_BYTES_PER_SECOND},
                }}
                burst = audit["source"]["byte_buckets"]["disk"]["ceiling_burst_bytes"]
                for available, reserved, owners in (
                    (burst + 1, 0, 0), (0, burst + 1, 1),
                    (0, 1, 0), (0, 1, 2), (0, 65, 65),
                ):
                    bad = dict(row, disk_rate_available_bytes=available,
                               disk_rate_reserved_bytes=reserved,
                               disk_rate_reservations=owners)
                    with self.subTest(version=version,
                                      balances=(available, reserved, owners)), \
                            self.assertRaises(module.SoakReadbackError):
                        module._check_numeric_sample(bad, audit, 0)

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

    @staticmethod
    def _run_with_owned_wait_trace(run, *, hash_wrapper=None, write_wrapper=None):
        events = []
        child_pids = []
        original_popen = module.subprocess.Popen
        original_waitid = os.waitid
        original_waitpid = os.waitpid
        original_killpg = os.killpg

        def capture_popen(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            child_pids.append(process.pid)
            return process

        def trace_waitid(idtype, pid, options):
            result = original_waitid(idtype, pid, options)
            if child_pids and idtype == os.P_PID and pid == child_pids[0]:
                events.append(("waitid", options))
            return result

        def trace_waitpid(pid, options):
            result = original_waitpid(pid, options)
            if child_pids and pid == child_pids[0]:
                events.append(("waitpid", options))
            return result

        def trace_killpg(pgid, signum):
            if child_pids and pgid == child_pids[0]:
                events.append(("killpg", signum))
            return original_killpg(pgid, signum)

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(module.subprocess, "Popen", side_effect=capture_popen))
            stack.enter_context(mock.patch.object(module.os, "waitid", side_effect=trace_waitid))
            stack.enter_context(mock.patch.object(module.os, "waitpid", side_effect=trace_waitpid))
            stack.enter_context(mock.patch.object(module.os, "killpg", side_effect=trace_killpg))
            if hash_wrapper is not None:
                stack.enter_context(mock.patch.object(module, "_hash_open_executable", side_effect=hash_wrapper))
            if write_wrapper is not None:
                stack.enter_context(mock.patch.object(module, "_write_exclusive_json", side_effect=write_wrapper))
            result = run()
        if len(child_pids) != 1:
            raise AssertionError(f"expected one traced native child, captured {child_pids}")
        return result, events, child_pids[0]

    def _assert_owned_reap_is_last(self, events, child_pid):
        self.assertTrue(events, "native supervision made no observable wait calls")
        waitpid_indexes = [index for index, event in enumerate(events) if event[0] == "waitpid"]
        self.assertEqual(len(waitpid_indexes), 1, f"owned child must have one final waitpid: {events}")
        final_waitpid = waitpid_indexes[0]
        self.assertEqual(events[final_waitpid][1], os.WNOHANG)
        self.assertTrue(any(event[0] == "waitid" for event in events[:final_waitpid]))
        for index, event in enumerate(events):
            if event[0] == "waitid":
                self.assertTrue(event[1] & os.WNOWAIT, f"waitid reaped or failed to preserve child {child_pid}: {events}")
            if event[0] == "killpg":
                self.assertLess(index, final_waitpid, f"killpg followed the owned child's final reap: {events}")
                self.assertGreater(index, 0)
                self.assertEqual(events[index - 1][0], "waitid", f"killpg lacked an immediate post-scan ownership guard: {events}")
        self.assertFalse(
            any(event[0] in ("waitid", "killpg") for event in events[final_waitpid + 1:]),
            f"numeric process operations followed final waitpid for child {child_pid}: {events}",
        )

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

    def test_source_v5_wall_timeout_includes_popen_callback_time(self):
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-v2-pre-popen-timeout-") as temporary:
            root = Path(temporary)
            output = root / "output"
            output.mkdir(mode=0o700)
            before = time.monotonic()
            details = module.launch_process(
                [sys.executable, "-c", "import time; time.sleep(5)"],
                str(min(os.sched_getaffinity(0))),
                output / "stdout.log", output / "stderr.log", output / "time.txt",
                timeout_seconds=1.1, term_grace_seconds=0.2, return_details=True,
                on_started=lambda *_args: time.sleep(0.25),
                timeout_from_before_popen=True, timeout_includes_cleanup=True,
            )
            self.assertTrue(details["timed_out"])
            self.assertEqual(details["status"], 124)
            self.assertIsNone(details["received_signal"], "internal timeout TERM is not an external signal")
            self.assertLess(time.monotonic() - before, 1.1)

    def test_pressure_cleanup_waits_past_generic_grace_for_frozen_driver_term(self):
        signals = []

        class DelayedDriver:
            pid = 600

            def __init__(self):
                self.returncode = None
                self.exit_at = time.monotonic() + 1.7

            def poll(self):
                if self.returncode is None and time.monotonic() >= self.exit_at:
                    self.returncode = 2
                return self.returncode

            def send_signal(self, signum):
                signals.append(signum)

            def wait(self, timeout=None):
                if self.poll() is not None:
                    return self.returncode
                remaining = max(0.0, self.exit_at - time.monotonic())
                if timeout is not None and timeout < remaining:
                    time.sleep(timeout)
                    raise subprocess.TimeoutExpired("pressure-driver", timeout)
                time.sleep(remaining)
                self.returncode = 2
                return self.returncode

        driver = DelayedDriver()
        started = time.monotonic()
        module._stop_pressure_session(
            driver, None, Path("/captured/application-pressure-driver.py"), "b" * 64,
            {"term_deadline_seconds": 2, "kill_deadline_seconds": 1}, {},
        )
        self.assertGreaterEqual(time.monotonic() - started, 1.5)
        self.assertEqual(signals, [signal.SIGTERM])

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
