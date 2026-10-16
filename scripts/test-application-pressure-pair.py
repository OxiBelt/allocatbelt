#!/usr/bin/env python3
"""Native contract tests for SourceV5 normal-APP pressure pairs.

Run this suite on the designated native qualification host. Its subprocess
case verifies the actual fd-based direct-Popen attestation; it does not start
an allocator benchmark or produce campaign evidence.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import inspect
import importlib.util
import contextlib
import io
import os
import signal
import shutil
import stat
import tempfile
import types
from pathlib import Path
import unittest
from unittest.mock import patch


SCRIPT_DIR = Path(__file__).resolve().parent
SOURCE_ROOT = SCRIPT_DIR.parent
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
import sys
sys.dont_write_bytecode = True


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pair = load_module("pressure_pair_contract_tests", SCRIPT_DIR / "application-pressure-pair.py")
fixed_pair = load_module("pressure_pair_fixed_environment_tests", SCRIPT_DIR / "application-fixed-pair.py")
soak = load_module("pressure_pair_shared_supervisor_tests", SCRIPT_DIR / "application-soak-readback.py")
pressure_driver = load_module("pressure_pair_pressure_driver_api_tests", SCRIPT_DIR / "application-pressure-driver.py")
pressure_reader = load_module("pressure_pair_pressure_reader_api_tests", SCRIPT_DIR / "application-pressure-readback.py")
feedback_reader = load_module("pressure_pair_feedback_reader_contract_tests", SCRIPT_DIR / "application-feedback-readback.py")
feedback_composition = load_module("pressure_pair_feedback_composition_contract_tests", SCRIPT_DIR / "application-feedback-composition.py")


def sha_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifact_pin(path: Path) -> dict[str, str]:
    return {"path": str(path), "raw_sha256": "a" * 64}


def valid_member(index: int, root: Path) -> dict:
    pair_name = "bounded" if index == 0 else "tokio"
    executor = pair.EXECUTOR_LABELS["bounded" if index == 0 else "tokio"]
    allocator = "allocatbelt"
    output = root / f"0{index}-{pair_name}-{allocator}"
    trace = output / "feedback-trace"
    probe = root / f"probe-{index}.json"
    return {
        "ordinal": index,
        "descriptor": {"pair": pair_name, "executor": "bounded" if index == 0 else "tokio", "allocator": allocator},
        "feedback_template": {"value": {}, "template_sha256": "b" * 64},
        "identity": {
            "host_id": "host", "run_id": "run", "report_nonce": "c" * 32,
            "allocator": allocator, "executor": executor, "workload": "mixed", "profile": "mixed",
            "mode": "open_loop", "rate_per_second": 10, "arrivals": 100,
            "source_sha256": "d" * 64, "binary_sha256": "e" * 64,
            "resource_ceiling_sha256": "f" * 64, "policy_sha256": "1" * 64,
            "pressure_nonce": "2" * 32,
        },
        "application_binary": artifact_pin(root / "app"),
        "construction_probe": {"path": str(probe), "raw_sha256": "3" * 64, "allocator": allocator, "binary_sha256": "e" * 64},
        "composition": {name: artifact_pin(root / f"member-{index}-{name}.json") for name in ("request", "policy", "receipt")},
        "argv": [str(root / "app"), "--executor", "bounded" if index == 0 else "tokio"],
        "environment": {"PATH": "/usr/bin:/bin"},
        "cwd": str(root), "tmpdir_path": str(root), "cpu_set": "0", "cpu_affinity": [0],
        "network_namespace_inode": 1,
        "oracle": {"entry": {}, "artifact": artifact_pin(root / "oracle.tsv")},
        "outputs": {
            "root": str(output), "stdout": str(output / "app.stdout.tsv"), "stderr": str(output / "app.stderr"),
            "timing": str(output / "app.time.json"), "ids": str(output / "app.ids.tsv"),
            "shutdown": str(output / "app.shutdown.tsv"), "capacity_families": str(output / "app.capacity-families.tsv"),
            "runtime_binding": str(output / "app.runtime.tsv"), "trace_directory": str(trace),
            "feedback_manifest": str(trace / "feedback-trace-manifest.tsv"),
            "feedback_events": str(trace / "feedback-events.jsonl"),
            "feedback_samples": str(trace / "resource-samples.tsv"),
            "feedback_validation": str(output / "feedback-validation.json"),
            "pressure_readback": str(output / "pressure-readback.json"),
            "app_launch_attestation": str(output / "app-launch.json"),
            "supervision_receipt": str(output / "supervision.json"),
            "cleanup_receipt": str(output / "cleanup.json"),
            "runtime_expectation": str(output / "runtime-expectation.json"),
            "finalization_request": str(output / "finalization-request.json"),
            "finalization_receipt": str(output / "finalization-receipt.json"),
        },
        "pressure_recipe": {"artifact": artifact_pin(root / f"pressure-{index}.json"), "semantic_sha256": "4" * 64, "condition_sha256": "5" * 64},
    }


def valid_recipe(root: Path) -> dict:
    pin = lambda name: artifact_pin(root / name)
    members = [valid_member(index, root) for index in range(2)]
    return {
        "schema": pair.RECIPE_SCHEMA,
        "spec": {"artifact": pin("spec.json"), "semantic_sha256": "6" * 64},
        "plan": {"artifact": pin("plan.json"), "semantic_sha256": "7" * 64},
        "source_manifest": {"artifact": pin("source.json"), "semantic_sha256": "8" * 64, "source_root": str(root)},
        "job": {"value": {"host_id": "host", "run_id": "run"}, "semantic_sha256": "9" * 64},
        "execution_overlay": {"artifact": pin("overlay.json")},
        "capacity_completion": {"artifact": pin("completion.json"), "schedule_sha256": "a" * 64, "registration_head": "b" * 64},
        "capacity_bundle": {name: pin(f"capacity-{name}.json") for name in ("request", "artifact", "receipt")},
        "fixed_predecessor": {"record": pin("fixed-predecessor.json")},
        "shared_policy": {"artifact": pin("shared-policy.json")},
        "pressure_condition": {
            "condition": pin("condition.json"), "condition_id": "condition", "condition_sha256": "a" * 64,
            "pressure_calibration": {"artifact": pin("pressure-calibration.json"), "receipt": pin("pressure-calibration-receipt.json"), "validator_sha256": "b" * 64, "calibration_id": "pressure-cal"},
            "readiness_thresholds": {"minimum_overlap_seconds": 30, "minimum_ready_samples": 300, "maximum_sample_gap_ms": 200},
            "schedule": {"duration_seconds": 60, "sample_interval_ms": 100, "seed": 42},
        },
        "members": members,
        "deadlines": {
            "trace_seconds": 30, "drain_seconds": 10, "shutdown_seconds": 10, "process_seconds": 300,
            "outer_seconds": 600, "application_wall_timeout_seconds": 300,
            "application_term_grace_seconds": 1.5, "pressure_exit_observation_seconds": 1,
            "pressure_duration_seconds": 311, "pressure_total_seconds": 320,
        },
        "artifact_budgets": {
            "stdout_bytes": 1024, "ids_bytes": 4096, "shutdown_bytes": 1024,
            "runtime_binding_bytes": 4096, "feedback_manifest_bytes": 4096,
            "feedback_events_bytes": 4096, "feedback_samples_bytes": 4096,
            "feedback_validation_bytes": 4096, "pressure_proof_bytes": 4096,
            "supervision_bytes": 4096, "member_sidecar_bytes": 4096, "pair_sidecar_bytes": 8192,
        },
        "validators": {
            "campaign_controller": {"path": "scripts/application-campaign.py", "sha256": "c" * 64},
            "campaign_chronology": {"path": "scripts/application-campaign-chronology.py", "sha256": "d" * 64},
            "feedback_composition": {"path": "scripts/application-feedback-composition.py", "sha256": "e" * 64},
            "feedback_validator": {"path": "scripts/application-feedback-readback.py", "sha256": "f" * 64},
            "pressure_validator": {"path": "scripts/application-pressure-readback.py", "sha256": "1" * 64},
            "soak_supervisor": {"path": "scripts/application-soak-readback.py", "sha256": "2" * 64},
            "capacity_producer": {"path": "scripts/application-byte-capacity.py", "sha256": "3" * 64},
        },
    }


def soak_v2_adapter_inputs(root: Path):
    binary = root / "bench-application"
    recipe_path = root / "pressure-recipe.json"
    argv = [str(binary), "--workload", "mixed", "--profile", "mixed"]
    pressure_info = {
        "value": {"schema": "allocatbelt.application-pressure-recipe.v1"},
        "reader": pressure_reader,
        "recipe_sha256": "a" * 64,
        "raw_sha256": "b" * 64,
        "condition_sha256": "c" * 64,
    }
    descriptor = {
        "argv": argv,
        "cpu_set": "0",
        "cwd": str(root),
        "environment": {"PATH": "/usr/bin:/bin"},
        "binary_path": str(binary),
        "binary_sha256": "d" * 64,
        "application_wall_timeout_seconds": 11050,
        "pressure_recipe_path": str(recipe_path),
        "pressure_driver_path": str(SCRIPT_DIR / "application-pressure-driver.py"),
        "pressure_driver_sha256": "e" * 64,
        "pressure_output_dir": str(root / "pressure"),
        "pressure_launch_path": str(root / "pressure" / "launch-record.json"),
        "pressure_ready_path": str(root / "pressure" / "pressure-ready.json"),
        "stdout_path": str(root / "stdout.log"),
        "stderr_path": str(root / "stderr.log"),
        "timing_path": str(root / "time.txt"),
        "terminal_path": str(root / "terminal-records.tsv"),
        "samples_path": str(root / "resource-samples.tsv"),
    }
    recipe = {
        "schema": soak.RECIPE_SCHEMA_V2,
        "pressure": {"recipe": {
            "path": str(recipe_path), "raw_sha256": "b" * 64, "semantic_sha256": "a" * 64,
        }},
        "qualification": {"pressure_condition": {"readiness_thresholds": {
            "minimum_overlap_seconds": 30, "minimum_ready_samples": 300, "maximum_sample_gap_ms": 200,
        }}},
    }
    audit = {
        "launch_descriptor": descriptor,
        "source": {
            "pressure_recipe": pressure_info,
            "application_supervision": {"application_wall_timeout_seconds": 11050},
        },
        "source_root": str(root),
        "recipe": recipe,
        "recipe_sha256": "f" * 64,
        "identity": {
            "campaign_id": "campaign", "host_id": "host", "run_id": "run", "nonce": "1" * 32,
        },
    }
    args = argparse.Namespace(
        command=["--", *argv], cpu_set="0", timeout_seconds=11050.0,
        term_grace_seconds=1.5,
    )
    preflight = {"terminal_budget_bytes": 4096, "sample_budget_bytes": 8192}
    return args, audit, preflight


def full_pressure_recipe_api_fixture(root: Path) -> tuple[dict[str, object], dict[str, object]]:
    """Build a full-recipe fixture for the captured reader/driver API boundary."""
    cpu = min(os.sched_getaffinity(0))
    file_pins: dict[str, dict[str, object]] = {}
    for name, raw in (
        ("source_manifest", b"source-manifest-fixture\n"),
        ("application_binary", b"application-binary-fixture\n"),
        ("policy", b"policy-fixture\n"),
        ("application_capacity_calibration", b"capacity-fixture\n"),
    ):
        path = root / name
        path.write_bytes(raw)
        file_pins[name] = {"path": str(path), "raw_sha256": hashlib.sha256(raw).hexdigest()}

    app_path = root / "app-io"
    scratch_path = root / "pressure-scratch"
    app_path.mkdir(mode=0o700)
    scratch_path.mkdir(mode=0o700)
    binary_path = Path(file_pins["application_binary"]["path"])
    os.chmod(binary_path, 0o755)
    file_pins["application_binary"].update({
        "mode": stat.S_IMODE(binary_path.stat().st_mode),
        "size": binary_path.stat().st_size,
    })
    device = "259:2"
    backing_chain = [{"device": device, "name": "nvme0n1p2", "sysfs_path": "/sys/devices/example"}]
    mount = {
        "mount_id": 1, "parent_mount_id": 1, "device": device, "root": "/",
        "mountpoint": str(root.resolve(strict=True)), "mount_options": ["rw"],
        "filesystem": "ext4", "source": "/dev/nvme0n1p2", "super_options": ["rw"],
    }

    def storage_record(path: Path) -> dict[str, object]:
        return {
            "path": str(path), "device": device, "mount": mount,
            "backing_chain": backing_chain, "filesystem_type": "ext4", "tmpfs": False,
        }

    app_storage = storage_record(app_path)
    scratch_storage = storage_record(scratch_path)
    network = {
        "address_family": "AF_INET", "destination": "127.0.0.1", "source": "127.0.0.1",
        "interface": "lo", "ifindex": 1, "route": {"dst": "127.0.0.1", "dev": "lo", "source": "127.0.0.1"},
        "network_namespace_inode": 99, "shared_kernel": True, "physical_nic_claimed": False,
        "claim": "ipv4_loopback_shared_kernel_only",
    }
    host = {
        "kernel_release": os.uname().release,
        "boot_id_sha256": pressure_driver.digest_bytes(Path("/proc/sys/kernel/random/boot_id").read_bytes().strip()),
        "allowed_cpu_affinity": [cpu], "pressure_cpu_affinity": [cpu],
        "application_cpu_affinity": [cpu], "network": network,
        "application_storage": [app_storage], "pressure_scratch": scratch_storage,
    }
    schedule = {
        "seed": 7, "duration_seconds": 3, "sample_interval_ms": 100,
        "startup_deadline_seconds": 1, "total_deadline_seconds": 8,
        "term_deadline_seconds": 2, "kill_deadline_seconds": 2,
        "minimum_overlap_seconds": 1, "startup_ready_windows": 1,
        "cpu_duty_basis_points": 1000, "pressure_cpu_affinity": [cpu],
        "application_cpu_affinity": [cpu], "disk_bytes_per_second": 40960,
        "scratch_file_bytes": 65536, "network_requests_per_second": 10,
        "network_payload_bytes": 16,
    }
    selected = {
        "cpu_busy_min_basis_points": 100,
        "disk_write_min_bytes_per_second": 4096,
        "disk_queue_or_stall_min_microseconds": 1,
        "loopback_requests_min_per_second": 1,
        "loopback_latency_p99_max_nanoseconds": 1_000_000_000,
        "loopback_tx_min_bytes_per_second": 1,
        "loopback_rx_min_bytes_per_second": 1,
    }
    driver_sha = hashlib.sha256((SCRIPT_DIR / "application-pressure-driver.py").read_bytes()).hexdigest()
    reader_sha = hashlib.sha256((SCRIPT_DIR / "application-pressure-readback.py").read_bytes()).hexdigest()
    pressure_recipe: dict[str, object] = {
        "schema": "allocatbelt.application-pressure-recipe.v1",
        "identity": {
            "host_id": "host", "run_id": "run", "pair_id": "run", "condition_id": "condition",
            "member": "bounded", "nonce": "a" * 32, "allocator": "allocatbelt",
            "executor": "allocatbelt", "phase": "external_pressure",
        },
        "files": file_pins,
        "process": {"executable_path": str(binary_path), "application_tmpdir_path": str(app_path)},
        "storage": {
            "application_io_paths": [str(app_path)],
            "pressure_scratch_path": str(scratch_path),
            "output_minimum_free_bytes": 64 * 1024 * 1024,
            "application_device": device, "application_mount_id": 1,
            "backing_chain": backing_chain, "non_tmpfs": True,
        },
        "network": network,
        "schedule": schedule,
        "artifact_budget": pressure_reader._artifact_budget(schedule, backing_chain),
        "pressure_calibration": {"path": str(root / "pressure-calibration.json"), "raw_sha256": "0" * 64},
        "readiness_thresholds": selected,
        "script_hashes": {"driver_sha256": driver_sha, "reader_sha256": reader_sha},
        "host": host,
        "condition_sha256": "0" * 64,
        "recipe_sha256": "0" * 64,
    }
    profile_keys = (
        "seed", "sample_interval_ms", "startup_deadline_seconds", "term_deadline_seconds",
        "kill_deadline_seconds", "cpu_duty_basis_points", "pressure_cpu_affinity",
        "application_cpu_affinity", "disk_bytes_per_second", "scratch_file_bytes",
        "network_requests_per_second", "network_payload_bytes",
    )
    workers = [
        {"role": "cpu", "cpu": cpu, "pid": 2200, "start_ticks": 101, "pgid": 2200, "session_id": 2200},
        {"role": "disk", "cpu": None, "pid": 2201, "start_ticks": 102, "pgid": 2201, "session_id": 2201},
        {"role": "loopback", "cpu": None, "pid": 2202, "start_ticks": 103, "pgid": 2202, "session_id": 2202},
    ]
    cleanup = []
    for index, worker in enumerate(workers):
        started = 10_000_000_000 + index * 10
        cleanup.append({
            **worker, "exit_code": 0, "cleanup_started_monotonic_ns": started,
            "term_deadline_monotonic_ns": started + 2_000_000_000,
            "kill_deadline_monotonic_ns": started + 4_000_000_000,
            "term_error": None, "kill_error": None, "reap_error": None,
            "alive_after_cleanup": False, "term_sent_monotonic_ns": None,
            "kill_sent_monotonic_ns": None, "reaped_monotonic_ns": started + 1,
            "stderr_output": "", "stderr_raw_base64": "", "stderr_raw_sha256": hashlib.sha256(b"").hexdigest(),
            "stderr_raw_bytes": 0, "stderr_raw_truncated": False, "stderr_read_error": None,
        })
    calibration: dict[str, object] = {
        "schema": "allocatbelt.application-pressure-contention-calibration.v1",
        "identity": {"host_id": "host", "pair_id": "run", "condition_id": "condition", "phase": "calibration"},
        "schedule_sha256": pressure_reader.digest_object({key: schedule[key] for key in profile_keys}),
        "raw_inputs": {
            "source_manifest_sha256": file_pins["source_manifest"]["raw_sha256"],
            "policy_sha256": file_pins["policy"]["raw_sha256"],
            "application_capacity_calibration_sha256": file_pins["application_capacity_calibration"]["raw_sha256"],
        },
        "driver_sha256": driver_sha, "host": host,
        "storage": {"application_device": device, "mount_id": 1, "backing_chain": backing_chain},
        "network": network, "worker_sessions": workers, "samples": [{} for _ in range(30)],
        "summary": {}, "suggested_readiness_thresholds": selected,
        "worker_cleanup": cleanup, "scratch_file_removed": True,
        "start_monotonic_ns": 1_000_000_000, "finish_monotonic_ns": 4_000_000_000,
        "deadlines": {"startup_seconds": 1, "total_seconds": 10, "term_seconds": 2, "kill_seconds": 2},
    }
    calibration["calibration_sha256"] = pressure_reader.digest_object(calibration)
    calibration_raw = pair.canonical_bytes(calibration)
    calibration_path = root / "pressure-calibration.json"
    calibration_path.write_bytes(calibration_raw)
    pressure_recipe["pressure_calibration"] = {"path": str(calibration_path), "raw_sha256": hashlib.sha256(calibration_raw).hexdigest()}
    identity = pressure_recipe["identity"]
    storage = pressure_recipe["storage"]
    assert isinstance(identity, dict) and isinstance(storage, dict)
    pressure_recipe["condition_sha256"] = pressure_reader.digest_object({
        "host_id": identity["host_id"],
        "condition_id": identity["condition_id"],
        "source_manifest_sha256": file_pins["source_manifest"]["raw_sha256"],
        "policy_sha256": file_pins["policy"]["raw_sha256"],
        "application_capacity_calibration_sha256": file_pins["application_capacity_calibration"]["raw_sha256"],
        "host": {
            "kernel_release": host["kernel_release"],
            "boot_id_sha256": host["boot_id_sha256"],
            "allowed_cpu_affinity": host["allowed_cpu_affinity"],
            "pressure_cpu_affinity": host["pressure_cpu_affinity"],
            "application_cpu_affinity": host["application_cpu_affinity"],
        },
        "storage": {
            "device": storage["application_device"],
            "mount_id": storage["application_mount_id"],
            "backing_chain": backing_chain,
        },
        "network": network,
        "schedule": schedule,
        "pressure_calibration_sha256": pressure_recipe["pressure_calibration"]["raw_sha256"],
        "readiness_thresholds": selected,
    })
    pressure_recipe.pop("recipe_sha256")
    pressure_recipe["recipe_sha256"] = pressure_reader.digest_object(pressure_recipe)
    pressure_summary = {"files": file_pins, "script_hashes": pressure_recipe["script_hashes"]}
    return pressure_summary, pressure_recipe


class PressurePairContractTests(unittest.TestCase):
    def _floor_policy_fixture(self, root: Path, selected: bool):
        policy_id = feedback_reader.CAPACITY_FLOOR_POLICY_ID
        descriptor = {
            "capacity_divisor": feedback_reader.CAPACITY_FLOOR_DIVISOR,
            "minimum_floor_bytes_per_second": feedback_reader.CAPACITY_FLOOR_MINIMUM_BYTES_PER_SECOND,
            "policy_id": policy_id,
            "probe_activation": feedback_reader.CAPACITY_FLOOR_PROBE_ACTIVATION,
            "rule": feedback_reader.CAPACITY_FLOOR_RULE,
            "rule_version": feedback_reader.CAPACITY_RESOLUTION_VERSION,
            "runtime_activation": feedback_reader.CAPACITY_FLOOR_RUNTIME_ACTIVATION,
            "static_floor_bytes_per_second": feedback_reader.CAPACITY_RATE_FLOOR,
            "static_rate_roof_bytes_per_second": feedback_reader.CAPACITY_RATE_ROOF,
        }

        member = valid_member(0, root)
        capacity_bundle = {
            name: {"path": str(root / f"capacity-{name}.json"), "raw_sha256": key * 64}
            for name, key in (("request", "a"), ("artifact", "b"), ("receipt", "c"))
        }
        shared = {
            "schema": pair.POLICY_SCHEMA,
            "context": ({"capacity_floor_policy_id": policy_id} if selected else {}),
            "capacity_bundle": capacity_bundle,
            "member_resolutions": [{
                "pair": member["descriptor"]["pair"],
                "executor": member["descriptor"]["executor"],
                "allocator": member["descriptor"]["allocator"],
                "resolved_policy_sha256": member["identity"]["policy_sha256"],
            }],
            "numeric_policy": {},
        }
        shared["policy_sha256"] = pair._shared_policy_semantic_sha(shared)
        spec = {"capacity_floor_policy_id": policy_id} if selected else {}
        inputs = {
            "spec": spec,
            "source": {
                "source": {"source_tree_sha256": member["identity"]["source_sha256"]},
                "feedback_policy": {"policy": ({"capacity_floor_policy": descriptor} if selected else {})},
            },
            "job": {
                "run_id": member["identity"]["run_id"],
                "workload": member["identity"]["workload"],
                "profile": member["identity"]["profile"],
            },
            "host_id": member["identity"]["host_id"],
            "recipe": {"capacity_bundle": capacity_bundle},
        }
        modules = {
            "feedback_composition": feedback_composition,
            "feedback_validator": feedback_reader,
        }
        return inputs, member, shared, modules, descriptor, policy_id

    def test_pressure_launch_environment_carries_only_the_fully_bound_floor_selector(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-pair-floor-env-") as directory:
            root = Path(directory)
            inputs, member, shared, modules, _descriptor, policy_id = self._floor_policy_fixture(root, True)
            environment = pair._expected_member_environment(inputs, member, shared, modules)
            self.assertEqual(environment["ALLOCATBELT_APP_PRESSURE_QUALIFICATION"], "true")
            self.assertEqual(environment["ALLOCATBELT_APP_CAPACITY_FLOOR_POLICY_ID"], policy_id)
            self.assertEqual(environment["ALLOCATBELT_APP_CAPACITY_CALIBRATION_FILE"],
                             inputs["recipe"]["capacity_bundle"]["artifact"]["path"])
            self.assertEqual(environment["ALLOCATBELT_APP_CAPACITY_CALIBRATION_SHA256"],
                             inputs["recipe"]["capacity_bundle"]["artifact"]["raw_sha256"])

            for allocator in pair.ALLOCATORS:
                for executor in ("bounded", "tokio"):
                    descriptor = {"pair": executor, "executor": executor, "allocator": allocator}
                    identity = {
                        **member["identity"], "allocator": allocator,
                        "executor": pair.EXECUTOR_LABELS[executor],
                    }
                    matrix_member = {**member, "descriptor": descriptor, "identity": identity}
                    matrix_policy = {
                        **shared,
                        "member_resolutions": [{
                            "pair": executor, "executor": executor,
                            "allocator": allocator,
                            "resolved_policy_sha256": identity["policy_sha256"],
                        }],
                    }
                    matrix_policy["policy_sha256"] = pair._shared_policy_semantic_sha(matrix_policy)
                    matrix_environment = pair._expected_member_environment(
                        inputs, matrix_member, matrix_policy, modules,
                    )
                    self.assertEqual(
                        matrix_environment["ALLOCATBELT_APP_CAPACITY_FLOOR_POLICY_ID"],
                        policy_id,
                        f"selected floor policy was dropped for {executor}/{allocator}",
                    )

            static_inputs, static_member, static_policy, static_modules, *_ = self._floor_policy_fixture(root, False)
            static_environment = pair._expected_member_environment(
                static_inputs, static_member, static_policy, static_modules,
            )
            self.assertNotIn("ALLOCATBELT_APP_CAPACITY_FLOOR_POLICY_ID", static_environment)

    def test_real_source5_replay_reconstructs_and_checks_the_complete_selected_environment(self) -> None:
        tree = ast.parse(
            (SCRIPT_DIR / "application-pressure-pair.py").read_bytes(),
            filename="application-pressure-pair.py",
        )
        functions = {
            node.name: node for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        self.assertIn("_verify_policy_resolutions", functions)
        self.assertIn("_verify_members", functions)
        resolution = ast.unparse(functions["_verify_policy_resolutions"])
        self.assertIn("inputs['spec'].get('capacity_floor_policy_id')", resolution)
        self.assertIn("composer.REQUEST_SCHEMA_V2", resolution)
        self.assertIn("expected_request['capacity_floor_policy_id']", resolution)
        self.assertIn("resolved.get('capacity_floor_policy_id')", resolution)
        self.assertIn("receipt.get('capacity_floor_policy_id')", resolution)
        member_replay = ast.unparse(functions["_verify_members"])
        self.assertIn(
            "_expected_member_environment(inputs, member, shared['value'], modules)",
            member_replay,
        )
        self.assertIn("member['environment'] == expected_environment", member_replay)

    def test_pressure_launch_selector_rejects_unbound_source_policy_capacity_and_resolution(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-pair-floor-negative-") as directory:
            root = Path(directory)
            inputs, member, shared, modules, descriptor, policy_id = self._floor_policy_fixture(root, True)

            unknown = dict(inputs)
            unknown["spec"] = {"capacity_floor_policy_id": "unknown_floor_policy"}
            with self.assertRaisesRegex(pair.PressurePairError, "unknown capacity-floor"):
                pair._expected_member_environment(unknown, member, shared, modules)

            missing_selector = {**inputs, "spec": {}}
            missing_selector["source"] = {
                **inputs["source"],
                "feedback_policy": {"policy": {"capacity_floor_policy": descriptor}},
            }
            with self.assertRaisesRegex(pair.PressurePairError, "uncalibrated pressure launch"):
                pair._expected_member_environment(missing_selector, member, shared, modules)

            bad_source = {**inputs, "source": {
                **inputs["source"],
                "feedback_policy": {"policy": {"capacity_floor_policy": {**descriptor, "rule": "other"}}},
            }}
            with self.assertRaisesRegex(pair.PressurePairError, "feedback reader rejected"):
                pair._expected_member_environment(bad_source, member, shared, modules)

            bad_context = {**shared, "context": {"capacity_floor_policy_id": "unknown_floor_policy"}}
            bad_context["policy_sha256"] = pair._shared_policy_semantic_sha(bad_context)
            with self.assertRaisesRegex(pair.PressurePairError, "resolved policy context"):
                pair._expected_member_environment(inputs, member, bad_context, modules)

            bad_capacity = {**shared, "capacity_bundle": {
                **shared["capacity_bundle"],
                "artifact": {**shared["capacity_bundle"]["artifact"], "raw_sha256": "d" * 64},
            }}
            bad_capacity["policy_sha256"] = pair._shared_policy_semantic_sha(bad_capacity)
            with self.assertRaisesRegex(pair.PressurePairError, "capacity pins"):
                pair._expected_member_environment(inputs, member, bad_capacity, modules)

            bad_resolution = {**shared, "member_resolutions": [{
                **shared["member_resolutions"][0], "resolved_policy_sha256": "e" * 64,
            }]}
            bad_resolution["policy_sha256"] = pair._shared_policy_semantic_sha(bad_resolution)
            with self.assertRaisesRegex(pair.PressurePairError, "unique matching SourceV5 member"):
                pair._expected_member_environment(inputs, member, bad_resolution, modules)

            self.assertEqual(policy_id, descriptor["policy_id"])

    def test_fixed_policy_launch_environment_omits_the_pressure_floor_selector(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fixed-pair-floor-env-") as directory:
            root = Path(directory)
            environment = fixed_pair._derive_expected_environment(
                {"run_id": "run", "workload": "mixed", "profile": "mixed", "mode": "capacity",
                 "rate_per_second": None, "arrivals": None},
                {"executor": "bounded", "allocator": "allocatbelt"},
                {"resource_ceiling_sha256": "a" * 64, "policy_sha256": "b" * 64,
                 "report_nonce": "c" * 32},
                {"source": {"source_tree_sha256": "d" * 64},
                 "artifacts": {"allocatbelt": {"sha256": "e" * 64}}},
                root,
                {"shutdown": str(root / "shutdown"), "ids": str(root / "ids"),
                 "capacity_families": str(root / "families"), "runtime_readback": str(root / "runtime")},
                None, None,
            )
            self.assertEqual(environment["ALLOCATBELT_APP_COMPARISON_FAMILY"], "fixed_policy")
            self.assertNotIn("ALLOCATBELT_APP_CAPACITY_FLOOR_POLICY_ID", environment)

    def test_pressure_descriptors_cover_all_original_allocator_labels_and_both_executors(self) -> None:
        for allocator in pair.ALLOCATORS:
            job = {"phase": "pressure", "comparison_family": "external_pressure", "comparison_kind": "executor", "allocator": allocator}
            self.assertEqual(
                pair.pressure_process_descriptors(job),
                [
                    {"pair": "bounded", "executor": "bounded", "allocator": allocator},
                    {"pair": "tokio", "executor": "tokio", "allocator": allocator},
                ],
            )
        allocator_job = {
            "phase": "pressure", "comparison_family": "external_pressure", "comparison_kind": "allocator",
            "allocator": "allocatbelt", "baseline_allocator": "system",
        }
        self.assertEqual(pair.pressure_process_descriptors(allocator_job), [
            {"pair": "candidate", "executor": "bounded", "allocator": "allocatbelt"},
            {"pair": "baseline", "executor": "bounded", "allocator": "system"},
        ])

    def test_feedback_nonce_binds_original_member_and_ordinal(self) -> None:
        template = "a" * 32
        first = pair.instantiate_feedback_nonce(template, "campaign", "run", "bounded", 3)
        self.assertEqual(first, pair.instantiate_feedback_nonce(template, "campaign", "run", "bounded", 3))
        self.assertNotEqual(first, pair.instantiate_feedback_nonce(template, "campaign", "run", "tokio", 3))
        self.assertNotEqual(first, pair.instantiate_feedback_nonce(template, "campaign", "run", "bounded", 4))
        with self.assertRaises(pair.PressurePairError):
            pair.instantiate_feedback_nonce("a" * 64, "campaign", "run", "bounded", 3)

    def test_private_recipe_is_exact_and_has_two_ordered_original_members(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-pair-recipe-") as directory:
            root = Path(directory)
            recipe = valid_recipe(root)
            checked = pair._validate_recipe_shape(recipe)
            self.assertEqual(len(checked["members"]), 2)
            forged = dict(recipe)
            forged["execution_overlay"] = {**recipe["execution_overlay"], "supported": True}
            with self.assertRaisesRegex(pair.PressurePairError, "field set"):
                pair._validate_recipe_shape(forged)
            incomplete = dict(recipe)
            incomplete["members"] = recipe["members"][:1]
            with self.assertRaisesRegex(pair.PressurePairError, "exactly two"):
                pair._validate_recipe_shape(incomplete)
            extra_gate = dict(recipe, qualification_eligible=True)
            with self.assertRaisesRegex(pair.PressurePairError, "field set"):
                pair._validate_recipe_shape(extra_gate)

    def test_fixed_descriptors_remain_rejected_by_pressure_adapter(self) -> None:
        with self.assertRaises(pair.PressurePairError):
            pair.pressure_process_descriptors({"phase": "confirmation", "comparison_family": "fixed_policy"})

    def test_soak_v2_postflight_translates_the_parent_recipe_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-pair-soak-postflight-") as directory:
            root = Path(directory).resolve(strict=True)
            args, audit, _preflight = soak_v2_adapter_inputs(root)
            del args
            pressure_dir = root / "pressure"
            pressure_dir.mkdir(mode=0o700)
            artifact_hashes = {
                "run": "1" * 64, "events": "2" * 64, "launch": "3" * 64,
                "process_binding": "4" * 64, "ready": "5" * 64,
            }
            observed: dict[str, object] = {}
            proof = {"sample_count": 300, "application_overlap_nanoseconds": 30_000_000_000}
            audit["source"]["pressure_recipe"]["reader"] = types.SimpleNamespace(
                verify_pressure=lambda recipe_path, _recipe_sha, actual_dir, _pins: (
                    observed.update({"recipe_path": recipe_path, "pressure_dir": actual_dir}) or proof
                ),
            )

            with patch.object(soak, "_pressure_output_hashes", return_value=artifact_hashes), \
                 patch.object(soak, "_require_source_v5_pressure_prefix", return_value=({}, "5" * 64)):
                result = soak._validate_pressure_proof(root, audit)

            self.assertEqual(result["raw_sha256"], hashlib.sha256(pair.canonical_bytes(proof)).hexdigest())
            self.assertEqual(observed["recipe_path"], root / "pressure-recipe.json")
            self.assertEqual(observed["pressure_dir"], pressure_dir)
            self.assertEqual(soak.read_json(root / "pressure-readback.json", "legacy proof", 1024)[0], proof)

    def test_soak_v2_cli_bounds_are_revalidated_and_integerized(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-pair-soak-adapter-") as directory:
            root = Path(directory).resolve(strict=True)
            args, audit, preflight = soak_v2_adapter_inputs(root)
            pressure_info, descriptor = soak._adapt_soak_v2_launch(args, audit, preflight)
            self.assertEqual(descriptor["argv"], audit["launch_descriptor"]["argv"])
            self.assertIs(type(descriptor["application_wall_timeout_seconds"]), int)
            self.assertEqual(descriptor["application_wall_timeout_seconds"], 11050)
            self.assertEqual(descriptor["term_grace_seconds"], 1.5)
            self.assertEqual(pressure_info["recipe_path"], str(root / "pressure-recipe.json"))

            for field, changed in (
                ("command", ["--", *audit["launch_descriptor"]["argv"], "--extra"]),
                ("timeout_seconds", 11049.0),
                ("term_grace_seconds", 2.0),
            ):
                altered = argparse.Namespace(**vars(args))
                setattr(altered, field, changed)
                with self.subTest(field=field), self.assertRaises(soak.SoakReadbackError):
                    soak._adapt_soak_v2_launch(altered, audit, preflight)

    def test_soak_v2_adapter_preserves_success_timeout_and_interrupt_results(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-pair-soak-results-") as directory:
            root = Path(directory).resolve(strict=True)
            args, audit, preflight = soak_v2_adapter_inputs(root)
            details = {"status": 0}
            proof = {"raw_sha256": "7" * 64}
            captured: dict[str, object] = {}

            def supervisor(app_descriptor, pressure_info, output_root, on_started, on_cleanup):
                captured["descriptor"] = app_descriptor
                interrupted = bool(captured.get("interrupt"))
                status = details["status"]
                if interrupted:
                    status = app_descriptor["on_interrupted"]({
                        "signal": signal.SIGHUP, "pressure_pid": 10,
                        "pressure_start_ticks": 20, "pressure_return_code": 0,
                        "application_cleanup": "verified", "pressure_cleanup": "verified",
                        "workers": [],
                    })
                return {
                    "schema": "allocatbelt.application-pressure-supervision.v1",
                    "execution_kind": "timed_soak", "status": status,
                    "interrupted": interrupted,
                    "pressure_proof": proof if details["status"] == 0 else None,
                    "pressure_ready_sha256": "8" * 64,
                    "details": None if interrupted else details,
                }

            with patch.object(soak, "supervise_pressure_application", side_effect=supervisor), \
                 patch.object(soak, "_launch_receipt_value", return_value={"schema": "legacy-launch"}), \
                 patch.object(soak, "_write_exclusive_json", return_value="9" * 64) as write_json, \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(soak.command_launch_v2(args, audit, preflight, root), 0)
                descriptor = captured["descriptor"]
                self.assertEqual(descriptor["argv"], audit["launch_descriptor"]["argv"])
                self.assertIs(type(descriptor["application_wall_timeout_seconds"]), int)
                self.assertEqual(descriptor["term_grace_seconds"], 1.5)

                details["status"] = 124
                self.assertEqual(soak.command_launch_v2(args, audit, preflight, root), 124)

                captured["interrupt"] = True
                self.assertEqual(soak.command_launch_v2(args, audit, preflight, root), 129)

            interruption_receipts = [
                call.args[1] for call in write_json.call_args_list
                if Path(call.args[0]).name == "soak-supervisor-interruption.json"
            ]
            self.assertEqual(len(interruption_receipts), 1)
            self.assertEqual(interruption_receipts[0]["schema"], "allocatbelt.application-soak-supervisor-interruption.v2")
            self.assertEqual(feedback_reader.SOAK_READBACK_SCHEMA_V2, "allocatbelt.application-soak-readback.v2")
            self.assertEqual(len(feedback_reader.SOAK_READBACK_FIELDS_V2), 15)

    def test_chronology_pin_translation_matches_the_real_public_pin_reader(self) -> None:
        chronology_path = SCRIPT_DIR / "application-campaign-chronology.py"
        if not chronology_path.is_file():
            self.skipTest("requires the separately reviewed and SourceV5-pinned Campaign Chronology R12 dependency")
        with tempfile.TemporaryDirectory(prefix="pressure-pair-chronology-pin-") as directory:
            root = Path(directory).resolve(strict=True)
            source_root = root / "source"
            chronology_copy = source_root / "scripts" / chronology_path.name
            chronology_copy.parent.mkdir(mode=0o700, parents=True)
            chronology_raw = chronology_path.read_bytes()
            chronology_copy.write_bytes(chronology_raw)
            os.chmod(chronology_copy, 0o644)
            source = {"source": {"files": [{
                "path": "scripts/application-campaign-chronology.py", "kind": "file",
                "mode": "100644", "sha256": hashlib.sha256(chronology_raw).hexdigest(),
                "size": len(chronology_raw),
            }]}}
            pinned_api, _pin = pair._pinned_source_module(
                source, source_root, "scripts/application-campaign-chronology.py",
                "campaign chronology API regression", 4 * 1024 * 1024,
            )
            for label, payload in (
                ("observed-host", {"schema": "source-v5-pin-fixture", "host": "host"}),
                ("capacity-completion", {"schema": "capacity-stage-completion-fixture", "count": 15}),
            ):
                path = root / f"{label}.json"
                raw = pair.canonical_bytes(payload)
                path.write_bytes(raw)
                private_pin = {"path": str(path), "raw_sha256": hashlib.sha256(raw).hexdigest()}
                chronology_pin = pair._chronology_api_pin(private_pin, label)
                value, actual_path, returned_raw, returned_sha = pinned_api._read_pin(
                    chronology_pin, f"{label} regression", 4096,
                )
                self.assertEqual(value, payload)
                self.assertEqual(actual_path, path)
                self.assertEqual(returned_raw, raw)
                self.assertEqual(returned_sha, private_pin["raw_sha256"])
                with self.subTest(pin=label), self.assertRaises(pinned_api.ChronologyError):
                    pinned_api._read_pin(private_pin, f"untranslated {label} pin", 4096)

    def test_pressure_calibration_and_live_host_apis_receive_the_full_recipe(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-pair-full-recipe-") as directory:
            root = Path(directory).resolve(strict=True)
            summary, full_recipe = full_pressure_recipe_api_fixture(root)
            host = full_recipe["host"]
            storage_by_path = {
                item["path"]: item
                for item in [*host["application_storage"], host["pressure_scratch"]]
            }

            def storage_record(path: Path, _label: str):
                return storage_by_path[str(path)]

            with patch.object(pressure_reader, "_validate_calibration_samples", return_value=None), \
                 patch.object(pressure_reader, "_validate_worker_stderr_capture", return_value=b""), \
                 patch.object(pressure_reader, "_worker_exit_status_valid", return_value=True), \
                 patch.object(pressure_reader, "_require_pid_reaped", return_value=None), \
                 patch.object(pressure_reader, "_measurement_summary", return_value={}), \
                 patch.object(pressure_reader, "_propose", return_value=full_recipe["readiness_thresholds"]), \
                 patch.object(pressure_driver, "_affinity", return_value=host["allowed_cpu_affinity"]), \
                 patch.object(pressure_driver, "_loopback_route", return_value=host["network"]), \
                 patch.object(pressure_driver, "_storage_record", side_effect=storage_record):
                pair._verify_pressure_recipe_host_inputs(
                    pressure_reader, pressure_driver, summary, full_recipe,
                )

            with self.assertRaises(KeyError):
                pressure_reader._validate_calibration(summary)

    def test_offline_pressure_host_inputs_use_the_verified_pair_source_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-pair-offline-source-root-") as directory:
            root = Path(directory).resolve(strict=True)
            summary, pressure_recipe = full_pressure_recipe_api_fixture(root)
            self.assertNotIn("source_manifest", pressure_recipe)
            host = pressure_recipe["host"]
            facts = {
                "boot_id_sha256": host["boot_id_sha256"],
                "kernel_release": host["kernel_release"],
                "cpu_affinity": host["allowed_cpu_affinity"],
                "network_namespace_inode": pressure_recipe["network"][
                    "network_namespace_inode"],
            }
            offline_origin = {
                "schema": "allocatbelt.application-source5-origin-journal-receipt.v1",
                "host_id": pressure_recipe["identity"]["host_id"],
                "observed_host_raw_sha256": "a" * 64,
                "before": facts, "after": facts,
                "storage_sha256": "b" * 64,
                "origin_facts_sha256": "c" * 64,
            }
            path_map = {
                "schema": "allocatbelt.application-pressure-evidence-path-map.v1",
                "entries": [],
            }
            offline_context = {
                "schema": pair.OFFLINE_CALIBRATION_CONTEXT_SCHEMA,
                "source_root": str(root), "evidence_path_map": path_map,
            }
            with patch.object(pressure_reader, "_validate_calibration",
                              return_value=None) as calibration, \
                 patch.object(pressure_driver, "_verify_live_environment",
                              side_effect=AssertionError("offline replay probed current host")):
                pair._verify_pressure_recipe_host_inputs(
                    pressure_reader, pressure_driver, summary, pressure_recipe,
                    offline_origin=offline_origin, offline_context=offline_context,
                    source_root=root,
                )
            calibration.assert_called_once_with(pressure_recipe, offline_context={
                "source_root": str(root), "evidence_path_map": path_map,
            })

            with patch.object(pressure_reader, "_validate_calibration",
                              return_value=None) as calibration:
                with self.assertRaisesRegex(
                    pair.PressurePairError,
                    "offline pressure calibration context changed",
                ):
                    pair._verify_pressure_recipe_host_inputs(
                        pressure_reader, pressure_driver, summary, pressure_recipe,
                        offline_origin=offline_origin, offline_context=offline_context,
                        source_root=root / "relocated",
                    )
                calibration.assert_not_called()

    def test_validated_pressure_info_crosses_real_shared_supervisor_preflight(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-pair-supervisor-preflight-") as directory:
            root = Path(directory).resolve(strict=True)
            source_root = root / "source"
            source_root.mkdir(mode=0o700)
            _summary, pressure_recipe = full_pressure_recipe_api_fixture(source_root)
            driver_dir = source_root / "scripts"
            driver_dir.mkdir(mode=0o700)
            driver_path = driver_dir / "application-pressure-driver.py"
            shutil.copyfile(SCRIPT_DIR / "application-pressure-driver.py", driver_path)
            os.chmod(driver_path, 0o644)
            driver_sha = sha_file(driver_path)

            binary = Path(pressure_recipe["files"]["application_binary"]["path"])
            binary_sha = sha_file(binary)
            cpu = pressure_recipe["schedule"]["application_cpu_affinity"][0]
            app_io = Path(pressure_recipe["process"]["application_tmpdir_path"])
            pressure_recipe["identity"]["nonce"] = "2" * 32
            pressure_recipe.pop("recipe_sha256")
            pressure_recipe["recipe_sha256"] = pressure_reader.digest_object(pressure_recipe)
            recipe_sha = pressure_recipe["recipe_sha256"]
            recipe_path = source_root / "pressure-recipe.json"
            recipe_raw = pair.canonical_bytes(pressure_recipe)
            recipe_path.write_bytes(recipe_raw)
            os.chmod(recipe_path, 0o600)
            self.assertNotIn("recipe_sha256", pressure_reader._validate_recipe(pressure_recipe, recipe_sha))

            output_root = root / "member-output"
            output_root.mkdir(mode=0o700)
            os.chmod(output_root, 0o700)
            outputs = {
                "root": str(output_root), "trace_directory": str(output_root / "feedback-trace"),
                "stdout": str(output_root / "app.stdout.tsv"), "stderr": str(output_root / "app.stderr"),
                "timing": str(output_root / "app.time.json"), "ids": str(output_root / "app.ids.tsv"),
                "shutdown": str(output_root / "app.shutdown.tsv"),
                "capacity_families": str(output_root / "app.capacity-families.tsv"),
                "runtime_binding": str(output_root / "app.runtime.tsv"),
                "feedback_manifest": str(output_root / "feedback-trace" / "feedback-trace-manifest.tsv"),
                "feedback_events": str(output_root / "feedback-trace" / "feedback-events.jsonl"),
                "feedback_samples": str(output_root / "feedback-trace" / "resource-samples.tsv"),
            }
            member = valid_member(0, root)
            member["descriptor"] = {"pair": "bounded", "executor": "bounded", "allocator": "allocatbelt"}
            member["identity"].update({
                "binary_sha256": binary_sha, "pressure_nonce": "2" * 32,
                "executor": "allocatbelt", "mode": "open_loop", "workload": "mixed",
            })
            member["application_binary"] = {"path": str(binary), "raw_sha256": binary_sha}
            member["pressure_recipe"] = {
                "artifact": {"path": str(recipe_path), "raw_sha256": hashlib.sha256(recipe_raw).hexdigest()},
                "semantic_sha256": recipe_sha, "condition_sha256": pressure_recipe["condition_sha256"],
            }
            member["network_namespace_inode"] = pressure_recipe["network"]["network_namespace_inode"]
            member["tmpdir_path"] = str(app_io)
            member["cpu_affinity"] = [cpu]
            member["cpu_set"] = str(cpu)
            member["cwd"] = str(app_io)
            member["argv"] = [str(binary), "--workload", "mixed"]
            member["environment"] = {
                "PATH": "/usr/bin:/bin", "TMPDIR": str(app_io),
                "ALLOCATBELT_APP_PRESSURE_NONCE": "2" * 32,
            }
            member["outputs"] = outputs

            condition_schedule = {
                **pressure_recipe["schedule"], "duration_seconds": 1, "total_deadline_seconds": 4,
            }
            recipe = {
                "pressure_condition": {
                    "condition_id": "condition",
                    "pressure_calibration": {"artifact": pressure_recipe["pressure_calibration"]},
                    "readiness_thresholds": {
                        "minimum_overlap_seconds": 1, "minimum_ready_samples": 10,
                        "maximum_sample_gap_ms": 200,
                    },
                },
                "shared_policy": {"artifact": pressure_recipe["files"]["policy"]},
                "deadlines": {
                    "application_wall_timeout_seconds": 1,
                    "application_term_grace_seconds": 1.5,
                    "pressure_exit_observation_seconds": 1,
                    "pressure_duration_seconds": 3,
                    "pressure_total_seconds": 8,
                },
                "artifact_budgets": {
                    "stdout_bytes": 1024, "ids_bytes": 1024, "shutdown_bytes": 1024,
                    "runtime_binding_bytes": 1024, "feedback_manifest_bytes": 1024,
                    "feedback_events_bytes": 1024, "feedback_samples_bytes": 1024,
                },
            }
            manifest_pin = pressure_recipe["files"]["source_manifest"]
            capacity_pin = pressure_recipe["files"]["application_capacity_calibration"]
            inputs = {
                "host_id": "host", "job": {"run_id": "run"},
                "source_root": source_root, "manifest_raw_sha256": manifest_pin["raw_sha256"],
                "source": {
                    "artifacts": {"allocatbelt": {"path": binary.name, "sha256": binary_sha}},
                    "qualification_harness": {"pressure_driver": {
                        "path": "scripts/application-pressure-driver.py", "sha256": driver_sha,
                    }},
                },
            }
            self.assertIsInstance(inputs["source_root"], Path)
            condition = {
                "driver_readiness_thresholds": pressure_recipe["readiness_thresholds"],
                "request": {"schedule": condition_schedule},
                "effective_calibration": pressure_recipe["pressure_calibration"],
                "calibration_scope_v2": None,
            }
            capacity = {"artifact": {"raw_sha256": capacity_pin["raw_sha256"]}}
            modules = {"pressure_validator": pressure_reader, "pressure_driver": pressure_driver}
            args = (member, recipe, inputs, {}, modules, condition, capacity, recipe["deadlines"])

            with patch.object(pair, "_verify_pressure_recipe_host_inputs", return_value=None):
                bad_raw = {**member, "pressure_recipe": {
                    **member["pressure_recipe"],
                    "artifact": {"path": str(recipe_path), "raw_sha256": "0" * 64},
                }}
                with self.assertRaises(pair.PressurePairError):
                    pair._verify_pressure_recipe(bad_raw, *args[1:])
                bad_semantic = {**member, "pressure_recipe": {
                    **member["pressure_recipe"], "semantic_sha256": "0" * 64,
                }}
                with self.assertRaises(pressure_reader.ReadbackError):
                    pair._verify_pressure_recipe(bad_semantic, *args[1:])
                bad_condition = {**member, "pressure_recipe": {
                    **member["pressure_recipe"], "condition_sha256": "0" * 64,
                }}
                with self.assertRaises(pair.PressurePairError):
                    pair._verify_pressure_recipe(bad_condition, *args[1:])
                pressure_info = pair._verify_pressure_recipe(*args)

            self.assertEqual(pressure_info["recipe_sha256"], recipe_sha)
            self.assertEqual(pressure_info["semantic_sha256"], recipe_sha)
            app_descriptor = pair._member_supervision_descriptor(
                {"member": member, "binary_path": binary}, recipe,
            )
            observed: dict[str, object] = {}

            def stop_before_launch(args, audit, preflight, actual_output_root):
                observed.update({
                    "descriptor": audit["launch_descriptor"],
                    "pressure_info": audit["source"]["pressure_recipe"],
                    "preflight": preflight,
                    "output_root": actual_output_root,
                })
                self.assertEqual(audit["source"]["pressure_recipe"]["recipe_sha256"], recipe_sha)
                self.assertEqual(audit["launch_descriptor"]["execution_kind"], "normal_app")
                self.assertIs(audit["launch_descriptor"]["launch_enabled"], True)
                self.assertEqual(args.command, member["argv"])
                return 0

            with patch.object(soak, "_run_pressure_supervisor_impl", side_effect=stop_before_launch):
                receipt = soak.supervise_pressure_application(
                    app_descriptor, pressure_info, output_root,
                    lambda _value: None, lambda _value: None,
                )

            self.assertEqual(receipt["execution_kind"], "normal_app")
            self.assertEqual(receipt["status"], 0)
            self.assertEqual(observed["pressure_info"]["recipe_sha256"], recipe_sha)
            self.assertEqual(observed["preflight"]["terminal_budget_bytes"], 1024)

    def test_controller_metrics_keep_pressure_measurements_and_closed_qualification(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-pair-metrics-") as directory:
            root = Path(directory).resolve(strict=True)
            member = {
                "descriptor": {"pair": "bounded", "executor": "bounded", "allocator": "allocatbelt"},
                "identity": {
                    "mode": "open_loop", "report_nonce": "a" * 32,
                    "resource_ceiling_sha256": "b" * 64, "policy_sha256": "c" * 64,
                },
            }
            checked = {
                "pair_output_root": str(root),
                "app_result": {
                    "stdout": {
                        "completed_on_time": "9", "completed_late": "1",
                        "capacity_publications_per_second": "",
                        "successful_throughput_through_drain_per_second": "2.5",
                        "response_p50_ns": "10", "response_p95_ns": "20", "response_p99_ns": "30",
                        "rss_after_drain_kib": "400", "retained_managed_bytes": "50",
                        "max_observed_managed_bytes": "70", "managed_limit_bytes": "100",
                    },
                    "row_metrics": {
                        "capacity_throughput_by_family": {},
                        "family_successes": {"cpu": 10},
                        "latency_p99_by_family_ns": {"cpu": 30},
                        "cpu_ns_per_completion": 40,
                        "production_cpu_started_ns": 100,
                        "production_cpu_ended_ns": 500,
                        "production_cpu_ns": 400,
                    },
                    "raw_artifacts": {
                        "ids": {"path": str(root / "member" / "app.ids.tsv"), "raw_sha256": "d" * 64},
                        "shutdown": {"path": str(root / "member" / "shutdown.tsv"), "raw_sha256": "e" * 64},
                    },
                },
                "pressure_proof": {"sample_count": 300, "application_overlap_nanoseconds": 30_000_000_000},
                "runtime_numeric_snapshot": {"schema": "allocatbelt.application-runtime-numeric-snapshot.v2"},
                "runtime_binding_sha256": "f" * 64,
                "source_manifest_raw_sha256": "1" * 64,
                "fixed_global_control_baseline": 1234,
            }
            metrics = pair.controller_pressure_metrics_adapter(member, checked)
            self.assertEqual(metrics["cpu_ns_per_completion"], 40)
            self.assertEqual(metrics["ids_path"], "member/app.ids.tsv")
            self.assertEqual(metrics["ids_sha256"], "d" * 64)
            self.assertEqual(metrics["pressure_sample_count"], 300)
            self.assertEqual(metrics["runtime_readback"]["comparison_family"], "external_pressure")
            self.assertEqual(metrics["p99_qualification"], "not_applicable")
            self.assertIs(metrics["qualification_eligible"], False)

    def test_normal_app_pair_runner_builds_both_original_supervision_descriptors(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-pair-two-members-") as directory:
            output_root = Path(directory).resolve(strict=True)
            os.chmod(output_root, 0o700)
            recipe = valid_recipe(output_root)
            recipe_path = output_root / "pressure-pair-recipe.json"
            recipe_raw = pair.canonical_bytes(recipe)
            recipe_path.write_bytes(recipe_raw)
            os.chmod(recipe_path, 0o600)
            expected_recipe_sha = hashlib.sha256(recipe_raw).hexdigest()
            prepared_members = [
                {"member": member, "binary_path": Path(member["application_binary"]["path"])}
                for member in recipe["members"]
            ]
            prepared = {
                "recipe": recipe, "output_root": output_root, "members": prepared_members,
                "inputs": {"job": recipe["job"]["value"]},
                "modules": {"campaign_controller": types.SimpleNamespace()},
            }
            calls: list[dict[str, object]] = []

            def fake_run_one(member_context, _prepared, on_app_started, on_app_terminal):
                self.assertIsNone(on_app_started)
                self.assertIsNone(on_app_terminal)
                descriptor = pair._member_supervision_descriptor(member_context, recipe)
                calls.append({
                    "execution_kind": descriptor["execution_kind"],
                    "argv": descriptor["argv"],
                    "environment": descriptor["environment"],
                    "pair": member_context["member"]["descriptor"]["pair"],
                    "allocator": member_context["member"]["descriptor"]["allocator"],
                })
                return {"receipt": {"status": 0}}

            with patch.object(pair, "_prepare_prerequisites", return_value=prepared), \
                 patch.object(pair, "_prepare_member_directories"), \
                 patch.object(pair, "_run_one_member", side_effect=fake_run_one), \
                 patch.object(pair, "_validate_app_outputs", return_value={"stdout": {}, "raw_artifacts": {}, "row_metrics": {}}), \
                 patch.object(pair, "_finalize_feedback", return_value={}), \
                 patch.object(pair, "_process_row", side_effect=lambda ctx, *_args: {"pair": ctx["member"]["descriptor"]["pair"]}), \
                 patch.object(pair, "_member_evidence", side_effect=lambda ctx, *_args: {"pair": ctx["member"]["descriptor"]["pair"]}), \
                 patch.object(pair, "_write_process_ledger", return_value="1" * 64), \
                 patch.object(pair, "_pair_readback_body", return_value={"schema": pair.READBACK_SCHEMA}), \
                 patch.object(pair, "validate_pressure_pair_artifacts", return_value={
                     "validated": True, "pressure_metrics": [{"pair": "bounded"}, {"pair": "tokio"}],
                 }):
                result = pair.run_pressure_pair(recipe_path, expected_recipe_sha, output_root)

            self.assertEqual([call["pair"] for call in calls], ["bounded", "tokio"])
            self.assertTrue(all(call["execution_kind"] == "normal_app" for call in calls))
            self.assertTrue(all(call["argv"] and call["environment"] for call in calls))
            self.assertEqual(result["member_count"], 2)
            self.assertFalse(result["qualification_eligible"])

    def test_direct_popen_attestation_captures_actual_pid_argv_environment_and_fd(self) -> None:
        executable_text = shutil.which("sleep")
        self.assertIsNotNone(executable_text)
        executable = Path(executable_text).resolve(strict=True)
        executable_sha = sha_file(executable)
        allowed = sorted(os.sched_getaffinity(0))
        cpu = allowed[0]
        cpu_set = str(cpu)
        with tempfile.TemporaryDirectory(prefix="pressure-pair-popen-") as directory:
            root = Path(directory).resolve(strict=True)
            environment = {
                "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                "TMPDIR": str(root), "ALLOCATBELT_APP_PRESSURE_NONCE": "a" * 32,
                "PAIR_ATTESTATION_TEST": "native-direct-popen",
            }
            argv = [str(executable), "0.05"]
            outputs = [root / "stdout", root / "stderr", root / "time.json"]
            binding: dict[str, object] = {}

            def started(process, actual_executable, actual_sha, _info, cpu_ids, cwd, actual_environment):
                process_stat = soak._proc_process_identity(process.pid)
                self.assertIsNotNone(process_stat)
                launch_binding = {
                    "process": {
                        "pid": process.pid,
                        "start_ticks": process_stat["start_ticks"],
                        "executable_path": str(actual_executable),
                        "executable_sha256": actual_sha,
                        "cwd": str(cwd),
                        "tmpdir_path": actual_environment["TMPDIR"],
                        "cpu_affinity": sorted(cpu_ids),
                        "network_namespace_inode": os.stat(f"/proc/{process.pid}/ns/net").st_ino,
                    },
                }
                binding["attestation"] = soak._make_application_launch_attestation(
                    process, argv, environment, "normal_app", launch_binding,
                )
                binding["pid"] = process.pid

            details = soak.launch_process(
                argv, cpu_set, outputs[0], outputs[1], outputs[2], 5.0, 1.5,
                environment=environment, cwd=root, expected_executable_sha256=executable_sha,
                return_details=True, on_started=started,
                timeout_from_before_popen=True, timeout_includes_cleanup=True,
            )
            self.assertEqual(details["status"], 0)
            attestation = binding["attestation"]
            self.assertEqual(attestation["execution_kind"], "normal_app")
            self.assertEqual(attestation["process"]["pid"], binding["pid"])
            self.assertEqual(attestation["process"]["argv"], argv)
            self.assertEqual(attestation["process"]["environment_sha256"], hashlib.sha256(pair.canonical_bytes(environment)).hexdigest())
            self.assertEqual(attestation["process"]["executable_sha256"], executable_sha)
            self.assertEqual(attestation["process"]["executable_fd_reference"], details["executed_file_descriptor"])


class PressureReaderReturnBoundaryTests(unittest.TestCase):
    """Use the real reader return shape while retaining each full raw recipe."""

    def _pair_fixture(self, root: Path) -> tuple[dict, dict[str, str]]:
        pair_recipe = valid_recipe(root)
        for index, member in enumerate(pair_recipe["members"]):
            member_root = root / f"pressure-member-{index}"
            member_root.mkdir(mode=0o700)
            _unused_summary, full_recipe = full_pressure_recipe_api_fixture(member_root)
            identity = member["identity"]
            if index == 1:
                identity["pressure_nonce"] = "3" * 32
            full_recipe["identity"].update({
                "host_id": "host", "run_id": "run", "pair_id": "run",
                "condition_id": "condition", "member": member["descriptor"]["pair"],
                "nonce": identity["pressure_nonce"],
                "allocator": member["descriptor"]["allocator"],
                "executor": identity["executor"],
            })
            body = {key: value for key, value in full_recipe.items()
                    if key != "recipe_sha256"}
            full_recipe["recipe_sha256"] = pressure_reader.digest_object(body)
            raw = pair.canonical_bytes(full_recipe)
            path = member_root / "pressure-recipe.json"
            path.write_bytes(raw)
            os.chmod(path, 0o600)
            reference = {
                "artifact": {"path": str(path),
                             "raw_sha256": hashlib.sha256(raw).hexdigest()},
                "semantic_sha256": full_recipe["recipe_sha256"],
                "condition_sha256": full_recipe["condition_sha256"],
            }
            member["pressure_recipe"] = reference
        inputs = {"host_id": "host", "job": {"run_id": "run"}}
        return pair_recipe, inputs

    def test_actual_reader_summary_does_not_replace_full_member_recipe(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-reader-return-") as directory:
            root = Path(directory).resolve(strict=True)
            recipe, inputs = self._pair_fixture(root)
            full_rows, summaries = pair._read_pressure_pair_member_recipes(
                recipe, inputs, pressure_reader,
            )
            self.assertEqual(len(full_rows), 2)
            self.assertEqual(len(summaries), 2)
            for index, (full, summary) in enumerate(zip(full_rows, summaries)):
                self.assertIn("host", full)
                self.assertIn("process", full)
                self.assertIn("recipe_sha256", full)
                self.assertNotIn("host", summary)
                self.assertNotIn("process", summary)
                self.assertNotIn("schema", summary)
                self.assertNotIn("recipe_sha256", summary)
                self.assertEqual(summary["condition_sha256"],
                                 recipe["members"][index]["pressure_recipe"]["condition_sha256"])

    def test_condition_member_and_raw_pin_changes_fail_at_the_reader_boundary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-reader-return-negative-") as directory:
            root = Path(directory).resolve(strict=True)
            recipe, inputs = self._pair_fixture(root)
            original_condition = recipe["members"][0]["pressure_recipe"]["condition_sha256"]
            recipe["members"][0]["pressure_recipe"]["condition_sha256"] = "0" * 64
            with self.assertRaisesRegex(pair.PressurePairError,
                                        "reader summary differs from its full recipe pins"):
                pair._read_pressure_pair_member_recipes(recipe, inputs, pressure_reader)
            recipe["members"][0]["pressure_recipe"]["condition_sha256"] = original_condition

            original_pair = recipe["members"][1]["descriptor"]["pair"]
            recipe["members"][1]["descriptor"]["pair"] = "changed-member"
            with self.assertRaisesRegex(pair.PressurePairError,
                                        "full recipe identity differs from its original pair member"):
                pair._read_pressure_pair_member_recipes(recipe, inputs, pressure_reader)
            recipe["members"][1]["descriptor"]["pair"] = original_pair

            original_raw = recipe["members"][0]["pressure_recipe"]["artifact"]["raw_sha256"]
            recipe["members"][0]["pressure_recipe"]["artifact"]["raw_sha256"] = "f" * 64
            with self.assertRaisesRegex(pair.PressurePairError,
                                        "raw bytes differ from their pin"):
                pair._read_pressure_pair_member_recipes(recipe, inputs, pressure_reader)
            recipe["members"][0]["pressure_recipe"]["artifact"]["raw_sha256"] = original_raw


class ProbeCaptureBudgetVersionTests(unittest.TestCase):
    """Synthetic schema/envelope checks; not ProbeV2 capture qualification."""

    @staticmethod
    def _budget() -> dict[str, object]:
        return {
            "capture_timeout_ns": 30_000_000_000,
            "storage_budget": {
                "tmpdir_bytes": 1024 * 1024 * 1024,
                "tmpdir_inodes": 4096,
                "stdout_bytes": 512 * 1024,
                "stderr_bytes": 64 * 1024,
                "owner_result_bytes": 16 * 1024 * 1024,
                "inventory_bytes": 16 * 1024 * 1024,
                "failure_bytes": 64 * 1024,
                "receipt_bytes": 16 * 1024 * 1024,
                "output_inodes": 4096,
            },
        }

    def test_pair_recipe_v1_remains_closed_and_v2_requires_prospective_budget(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-pair-budget-v2-") as directory:
            root = Path(directory).resolve(strict=True)
            version_one = valid_recipe(root)
            self.assertEqual(pair._validate_recipe_shape(version_one)["schema"], pair.RECIPE_SCHEMA)

            extended_v1 = {**version_one, "probe_capture": self._budget()}
            with self.assertRaisesRegex(pair.PressurePairError, "unexpected field set"):
                pair._validate_recipe_shape(extended_v1)

            version_two = {**version_one, "schema": pair.RECIPE_SCHEMA_V2,
                           "probe_capture": self._budget()}
            self.assertEqual(
                pair._validate_recipe_shape(version_two)["probe_capture"],
                self._budget(),
            )
            without_budget = {key: value for key, value in version_two.items()
                              if key != "probe_capture"}
            with self.assertRaisesRegex(pair.PressurePairError, "unexpected field set"):
                pair._validate_recipe_shape(without_budget)

            extra_budget = {**version_two, "probe_capture": {
                **self._budget(), "later_fill": 1,
            }}
            with self.assertRaisesRegex(pair.PressurePairError, "unexpected field set"):
                pair._validate_recipe_shape(extra_budget)

    def test_source5_preflight_closes_index_and_role_metadata_before_nested_streams(self) -> None:
        def make_capture(root: Path, *, role_swap: bool):
            small_path = root / "a-small-journal.jsonl"
            large_path = root / "b-large-journal.jsonl"
            nested_path = root / "a-typed-source.py"
            index_path = root / "c-evidence-index.json"
            origin_path = root / "d-origin-receipt.json"
            source_root = root / "source"
            input_root = root / "input"
            output_root = root / "output"
            small_raw = b"x"
            origin_raw = b"origin"
            nested_raw = b"source"
            index_entries = []
            captured_rows = []
            if role_swap:
                indexed_nested = {
                    "role": "typed_source_file", "host_id": "host-a",
                    "origin_path": str(nested_path), "local_path": str(nested_path),
                    "raw_sha256": hashlib.sha256(nested_raw).hexdigest(),
                    "semantic_sha256": None, "byte_count": len(nested_raw),
                }
                index_entries.append(indexed_nested)
                captured_rows.append({
                    **indexed_nested, "role": "normal_app_output",
                    "raw_bytes": nested_raw,
                })
            else:
                captured_rows.extend([
                    {
                        "role": "journal", "host_id": "host-a",
                        "origin_path": str(small_path), "local_path": str(small_path),
                        "raw_sha256": hashlib.sha256(small_raw).hexdigest(),
                        "semantic_sha256": None, "byte_count": len(small_raw),
                        "raw_bytes": small_raw,
                    },
                    {
                        "role": "journal", "host_id": "host-a",
                        "origin_path": str(large_path), "local_path": str(large_path),
                        "raw_sha256": hashlib.sha256(b"").hexdigest(),
                        "semantic_sha256": None,
                        "byte_count": pair.MAX_SOURCE5_CAPTURE_BYTES,
                        "raw_bytes": b"",
                    },
                ])
            index = {
                "schema": pair.SOURCE5_EVIDENCE_INDEX_SCHEMA,
                "campaign_id": "campaign", "host_id": "host-a",
                "source_root": str(source_root), "input_root": str(input_root),
                "output_root": str(output_root), "entries": index_entries,
            }
            index["index_sha256"] = pair.digest_object(index)
            index_raw = pair.canonical_bytes(index)
            index_sha = hashlib.sha256(index_raw).hexdigest()
            origin_sha = hashlib.sha256(origin_raw).hexdigest()
            captured_rows.extend([
                {
                    "role": "evidence_index", "host_id": "host-a",
                    "origin_path": str(index_path), "local_path": str(index_path),
                    "raw_sha256": index_sha,
                    "semantic_sha256": index["index_sha256"],
                    "byte_count": len(index_raw), "raw_bytes": index_raw,
                },
                {
                    "role": "origin_receipt", "host_id": "host-a",
                    "origin_path": str(origin_path), "local_path": str(origin_path),
                    "raw_sha256": origin_sha, "semantic_sha256": "c" * 64,
                    "byte_count": len(origin_raw), "raw_bytes": origin_raw,
                },
            ])
            captured_rows.sort(key=lambda row: row["origin_path"])
            request = {
                "schema": pair.SOURCE5_HOST_JOURNAL_REQUEST_SCHEMA,
                "scope": "prospective_exploration", "campaign_id": "campaign",
                "host_id": "host-a", "source_root": str(source_root),
                "input_root": str(input_root), "output_root": str(output_root),
                "execution_manifest": {
                    "path": str(root / "execution-manifest.json"),
                    "raw_sha256": "d" * 64, "semantic_sha256": "e" * 64,
                },
                "provenance": {}, "journal": {},
                "origin_receipt": {
                    "path": str(origin_path), "raw_sha256": origin_sha,
                    "semantic_sha256": "c" * 64,
                },
                "evidence_index": {
                    "path": str(index_path), "raw_sha256": index_sha,
                    "semantic_sha256": index["index_sha256"],
                },
            }
            context = {
                "schema": "allocatbelt.application-source5-pressure-journal-context.v1",
                "request": request,
                "captured_evidence": {
                    "schema": pair.SOURCE5_CAPTURED_SCHEMA,
                    "entries": captured_rows,
                },
                "job_record_pin": {},
            }
            return context

        for role_swap in (False, True):
            with self.subTest(role_swap=role_swap), \
                 tempfile.TemporaryDirectory(prefix="pressure-source5-stream-closure-") as directory:
                context = make_capture(Path(directory).resolve(strict=True),
                                       role_swap=role_swap)
                nested_reads = []
                original_chunks = pair._source5_capture_chunks

                def tracked_chunks(value, count, label):
                    if "evidence index" not in label:
                        nested_reads.append(label)
                    yield from original_chunks(value, count, label)

                expected = ("captured Source5 store is not the exact index/receipt closure"
                            if not role_swap else
                            "captured Source5 row differs from its index metadata")
                with patch.object(pair, "_source5_capture_chunks",
                                  side_effect=tracked_chunks):
                    with self.assertRaisesRegex(pair.PressurePairError, expected):
                        pair._source5_preflight_capture_context(context, None)
                self.assertEqual(nested_reads, [])

        over_role_cap = {
            "role": "journal", "origin_path": "/capture/journal",
            "byte_count": pair.MAX_SOURCE5_CAPTURE_BYTES + 1,
            "raw_sha256": hashlib.sha256(b"").hexdigest(), "raw_bytes": b"",
        }
        with self.assertRaisesRegex(pair.PressurePairError, "exact role cap"):
            pair._source5_capture_digest(over_role_cap)

    def test_locked_capture_envelope_must_match_both_prospective_values(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-capture-budget-pin-") as directory:
            root = Path(directory).resolve(strict=True)
            expected = self._budget()
            capture = {name: None for name in feedback_reader.PROBE_CAPTURE_RECEIPT_FIELDS}
            capture.update({
                "schema": feedback_reader.PROBE_CAPTURE_RECEIPT_SCHEMA,
                "capture_timeout_ns": expected["capture_timeout_ns"],
                "storage_budget": expected["storage_budget"],
                "qualification_eligible": False,
                "execution_ready": False,
                "controller_chronology_proven": False,
            })
            body = {key: value for key, value in capture.items()
                    if key != "receipt_sha256"}
            capture["receipt_sha256"] = feedback_reader.digest_object(body)
            raw = feedback_reader.canonical_bytes(capture)
            path = root / "capture-receipt.json"
            path.write_bytes(raw)
            os.chmod(path, 0o600)
            pin = {
                "path": str(path), "raw_sha256": hashlib.sha256(raw).hexdigest(),
                "receipt_sha256": capture["receipt_sha256"],
            }
            checked = pair._verify_probe_capture_budget_receipt(
                feedback_reader, pin, expected, 0,
            )
            self.assertEqual(checked["capture_timeout_ns"], expected["capture_timeout_ns"])
            self.assertEqual(checked["storage_budget"], expected["storage_budget"])

            changed = {
                "capture_timeout_ns": expected["capture_timeout_ns"] - 1,
                "storage_budget": dict(expected["storage_budget"]),
            }
            with self.assertRaisesRegex(pair.PressurePairError,
                                        "differs from its prospective recipe budget"):
                pair._verify_probe_capture_budget_receipt(
                    feedback_reader, pin, changed, 0,
                )
            changed_storage = {
                "capture_timeout_ns": expected["capture_timeout_ns"],
                "storage_budget": dict(expected["storage_budget"]),
            }
            changed_storage["storage_budget"]["stdout_bytes"] -= 1
            with self.assertRaisesRegex(pair.PressurePairError,
                                        "differs from its prospective recipe budget"):
                pair._verify_probe_capture_budget_receipt(
                    feedback_reader, pin, changed_storage, 0,
                )

    def test_strict_source5_capture_rejects_archived_v1_recipe_before_dependency_reads(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-v1-origin-gate-") as directory:
            root = Path(directory).resolve(strict=True)
            recipe = valid_recipe(root)
            recipe_path = root / "legacy-v1-recipe.json"
            recipe_raw = pair.canonical_bytes(recipe)
            recipe_path.write_bytes(recipe_raw)
            os.chmod(recipe_path, 0o600)
            receipt_path = root.parent / "legacy-v1-host-receipt.json"
            with self.assertRaisesRegex(
                pair.PressurePairError,
                "strict Source5 host capture requires pressure-pair recipe v2",
            ):
                pair.verify_pressure_pair_with_host_receipt(
                    {"path": str(recipe_path),
                     "raw_sha256": hashlib.sha256(recipe_raw).hexdigest()},
                    root,
                    {"path": str(root / pair.PAIR_READBACK_FILE),
                     "raw_sha256": "a" * 64},
                    receipt_path,
                    chronology_module=types.SimpleNamespace(), lock=object(),
                    authorization_context={},
                )
            self.assertFalse(receipt_path.exists())


class CompleteMappedFilePreflightTests(unittest.TestCase):
    """Reach the full SourceV5 role closure before exercising component binds."""

    def _full_capture(self, root: Path) -> dict[str, object]:
        root = root.resolve(strict=True)
        source_root = root / "source"
        input_root = root / "inputs"
        output_root = root / "outputs"
        for directory in (source_root, input_root, output_root):
            directory.mkdir(mode=0o700)

        indexed_rows: list[dict[str, object]] = []
        captured_rows: list[dict[str, object]] = []
        written: dict[str, tuple[str, bytes]] = {}

        def add_file(path: Path, role: str, host_id: str | None, raw: bytes,
                     *, semantic_sha256: str | None = None,
                     mode: int = 0o600) -> dict[str, object]:
            path = path.resolve(strict=False)
            name = str(path)
            raw_sha256 = hashlib.sha256(raw).hexdigest()
            previous = written.get(name)
            if previous is not None:
                if previous != (role, raw):
                    raise AssertionError(f"fixture reuses {name} under another role or payload")
                return next(row for row in captured_rows if row["origin_path"] == name)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes(raw)
            os.chmod(path, mode)
            row = {
                "role": role, "host_id": host_id, "origin_path": name,
                "local_path": name, "raw_sha256": raw_sha256,
                "semantic_sha256": semantic_sha256, "byte_count": len(raw),
            }
            indexed_rows.append(dict(row))
            captured_rows.append({**row, "raw_bytes": raw})
            written[name] = (role, raw)
            return captured_rows[-1]

        source_path = source_root / "scripts" / "fixture-module.py"
        source_raw = b"# typed fixture module\n"
        source_sha = hashlib.sha256(source_raw).hexdigest()
        source_record = {
            "path": "scripts/fixture-module.py", "kind": "file",
            "mode": "100644", "sha256": source_sha, "size": len(source_raw),
        }
        source_tree_sha = pair.digest_object({
            "schema": "allocatbelt.application-source-inventory.v1",
            "entries": [source_record],
        })
        add_file(source_path, "typed_source_file", "host-a", source_raw, mode=0o644)

        assets: dict[str, dict[str, str]] = {}
        asset_roles = {
            **{name: "normal_app_output" for name in pair.ALLOCATORS},
            "soak": "source5_soak_artifact", "analyzer": "analysis_artifact",
            "capacity-binary": "capacity_artifact", "capacity-output": "capacity_artifact",
        }
        for label, role in asset_roles.items():
            relative = f"artifacts/{label}.bin"
            asset_path = source_root / relative
            asset_raw = f"fixture {label}\n".encode("ascii")
            raw_sha256 = hashlib.sha256(asset_raw).hexdigest()
            add_file(asset_path, role, "host-a", asset_raw)
            assets[label] = {"path": relative, "sha256": raw_sha256}

        for host_id in ("host-a", "host-b", "host-c"):
            body: dict[str, object] = {
                "schema": pair.V5_SOURCE_SCHEMA,
                "build": {"host_id": host_id},
                "source": {
                    "git_commit": "a" * 40,
                    "source_tree_sha256": source_tree_sha,
                    "cargo_lock_sha256": "b" * 64,
                    "files": [source_record],
                },
                "artifacts": {
                    allocator: assets[allocator] for allocator in pair.ALLOCATORS
                },
                "soak_artifacts": {"allocatbelt": assets["soak"]},
                "analysis_artifact": assets["analyzer"],
                "resource_domain_calibration": {
                    "binary": assets["capacity-binary"],
                    "output": assets["capacity-output"],
                    "record": {}, "source": {}, "build": {},
                    "build_sha256": "c" * 64,
                },
                "runtime_readback_validator": {
                    "path": source_record["path"], "sha256": source_sha,
                },
            }
            body["manifest_sha256"] = pair.digest_object(body)
            raw = pair.canonical_bytes(body)
            manifest_path = input_root / f"source-{host_id}.json"
            add_file(manifest_path, "source_manifest", host_id, raw,
                     semantic_sha256=body["manifest_sha256"])

        recipe_root = root
        recipe = valid_recipe(recipe_root)
        recipe_raw = pair.canonical_bytes(recipe)
        recipe_path = output_root / "pressure-recipe.json"
        add_file(recipe_path, "pressure_pair_artifact", "host-a", recipe_raw)
        readback_path = output_root / pair.PAIR_READBACK_FILE
        add_file(readback_path, "pressure_pair_artifact", "host-a", b"readback fixture\n")
        host_receipt_path = output_root / "host-verification-receipt.json"
        add_file(host_receipt_path, "component_receipt", "host-a", b"host receipt fixture\n")
        add_file(input_root / "spec-v3.json", "spec_v3", "host-a", b"spec fixture\n")
        add_file(input_root / "plan-v3.json", "plan_v3", "host-a", b"plan fixture\n")
        add_file(output_root / "journal.jsonl", "journal", "host-a", b"event\n")

        execution_body: dict[str, object] = {
            "modules": {"host-a": {
                "scripts/fixture-module.py": {
                    "path": "scripts/fixture-module.py", "sha256": source_sha,
                },
            }},
        }
        execution_body["manifest_sha256"] = pair.digest_object(execution_body)
        execution_raw = pair.canonical_bytes(execution_body)
        execution_path = output_root / "execution-manifest.json"
        add_file(execution_path, "execution_manifest", "host-a", execution_raw,
                 semantic_sha256=execution_body["manifest_sha256"])

        index_path = output_root / "evidence-index.json"
        origin_path = output_root / "origin-receipt.json"
        indexed_rows.sort(key=lambda row: row["origin_path"])
        index_body: dict[str, object] = {
            "schema": pair.SOURCE5_EVIDENCE_INDEX_SCHEMA,
            "campaign_id": "campaign", "host_id": "host-a",
            "source_root": str(source_root), "input_root": str(input_root),
            "output_root": str(output_root), "entries": indexed_rows,
        }
        index_body["index_sha256"] = pair.digest_object(index_body)
        index_raw = pair.canonical_bytes(index_body)
        index_sha = hashlib.sha256(index_raw).hexdigest()
        index_capture = {
            "role": "evidence_index", "host_id": "host-a",
            "origin_path": str(index_path), "local_path": str(index_path),
            "raw_sha256": index_sha,
            "semantic_sha256": index_body["index_sha256"],
            "byte_count": len(index_raw), "raw_bytes": index_raw,
        }
        index_path.write_bytes(index_raw)
        os.chmod(index_path, 0o600)
        captured_rows.append(index_capture)
        origin_raw = b"origin receipt fixture\n"
        origin_sha = hashlib.sha256(origin_raw).hexdigest()
        origin_path.write_bytes(origin_raw)
        os.chmod(origin_path, 0o600)
        captured_rows.append({
            "role": "origin_receipt", "host_id": "host-a",
            "origin_path": str(origin_path), "local_path": str(origin_path),
            "raw_sha256": origin_sha, "semantic_sha256": "d" * 64,
            "byte_count": len(origin_raw), "raw_bytes": origin_raw,
        })
        captured_rows.sort(key=lambda row: row["origin_path"])

        request = {
            "schema": pair.SOURCE5_HOST_JOURNAL_REQUEST_SCHEMA,
            "scope": "prospective_exploration", "campaign_id": "campaign",
            "host_id": "host-a", "source_root": str(source_root),
            "input_root": str(input_root), "output_root": str(output_root),
            "execution_manifest": {
                "path": str(execution_path),
                "raw_sha256": hashlib.sha256(execution_raw).hexdigest(),
                "semantic_sha256": execution_body["manifest_sha256"],
            },
            "provenance": {}, "journal": {},
            "origin_receipt": {
                "path": str(origin_path), "raw_sha256": origin_sha,
                "semantic_sha256": "d" * 64,
            },
            "evidence_index": {
                "path": str(index_path), "raw_sha256": index_sha,
                "semantic_sha256": index_body["index_sha256"],
            },
        }
        context = {
            "schema": "allocatbelt.application-source5-pressure-journal-context.v1",
            "request": request,
            "captured_evidence": {
                "schema": pair.SOURCE5_CAPTURED_SCHEMA,
                "entries": captured_rows,
            },
            "job_record_pin": {},
        }
        path_entries = [{"origin": str(path), "local": str(path)}
                        for path in (source_root, input_root, output_root)]
        path_entries.extend({"origin": row["origin_path"],
                             "local": row["local_path"]}
                            for row in captured_rows)
        path_entries.sort(key=lambda row: row["origin"])
        return {
            "context": context,
            "path_map": {
                "schema": "allocatbelt.application-pressure-evidence-path-map.v1",
                "entries": path_entries,
            },
            "recipe": recipe,
            "recipe_path": recipe_path,
            "recipe_raw": recipe_raw,
            "output_root": output_root,
            "readback_path": readback_path,
            "host_receipt_path": host_receipt_path,
            "execution_path": execution_path,
            "index_path": index_path,
        }

    def _call_public_reader(self, fixture: dict[str, object], recipe_sha: str):
        return pair.validate_pressure_pair_artifacts_offline(
            {"path": str(fixture["recipe_path"]), "raw_sha256": recipe_sha},
            str(fixture["output_root"]),
            {"path": str(fixture["readback_path"]), "raw_sha256": "e" * 64},
            {"path": str(fixture["host_receipt_path"]),
             "raw_sha256": "f" * 64, "receipt_sha256": "1" * 64},
            fixture["path_map"], source5_journal_context=fixture["context"],
        )

    def test_full_closure_accepts_unchanged_rows_and_rejects_mutated_recipe_before_parse(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-source5-complete-map-") as directory:
            root = Path(directory).resolve(strict=True)
            fixture = self._full_capture(root)
            recipe_path = fixture["recipe_path"]
            original_sha = hashlib.sha256(fixture["recipe_raw"]).hexdigest()
            capture_rows = fixture["context"]["captured_evidence"]["entries"]
            recipe_capture = next(row for row in capture_rows
                                  if row["origin_path"] == str(recipe_path))
            self.assertEqual(recipe_capture["raw_sha256"], original_sha)
            self.assertEqual(recipe_capture["raw_bytes"], fixture["recipe_raw"])

            closed = pair._source5_preflight_capture_context(
                fixture["context"], fixture["path_map"],
            )
            self.assertIn(str(recipe_path), closed["mapped"])
            self.assertEqual(closed["capture_rows"][str(recipe_path)]["raw_sha256"], original_sha)

            original_json_loads = pair.json.loads
            parsed_recipe_payloads: list[str] = []

            def track_recipe_json(payload, *args, **kwargs):
                if payload == fixture["recipe_raw"].decode("utf-8"):
                    parsed_recipe_payloads.append(payload)
                return original_json_loads(payload, *args, **kwargs)

            with patch.object(pair, "read_stable", wraps=pair.read_stable) as stable_reads, \
                 patch.object(pair, "_load_module", wraps=pair._load_module) as module_loads, \
                 patch.object(pair.json, "loads", side_effect=track_recipe_json):
                with self.assertRaisesRegex(pair.PressurePairError,
                                            "requires pressure-pair recipe v2"):
                    self._call_public_reader(fixture, original_sha)
                recipe_reads = [call for call in stable_reads.call_args_list
                                if len(call.args) >= 2 and
                                call.args[1] == "offline pressure-pair recipe"]
                self.assertEqual(len(recipe_reads), 1)
                self.assertEqual(parsed_recipe_payloads,
                                 [fixture["recipe_raw"].decode("utf-8")])
                module_loads.assert_not_called()

            mutations = []
            same_size = dict(fixture["recipe"])
            same_size["deadlines"] = {
                **fixture["recipe"]["deadlines"], "outer_seconds": 601,
            }
            mutations.append(("raw-digest", same_size, True))
            larger = dict(fixture["recipe"])
            larger["job"] = {
                **fixture["recipe"]["job"],
                "value": {**fixture["recipe"]["job"]["value"],
                          "run_id": "run-with-a-longer-local-caller-value"},
            }
            mutations.append(("byte-count", larger, False))
            for label, mutated, same_byte_count in mutations:
                with self.subTest(mutation=label):
                    pair._validate_recipe_shape(mutated)
                    mutated_raw = pair.canonical_bytes(mutated)
                    mutated_sha = hashlib.sha256(mutated_raw).hexdigest()
                    self.assertNotEqual(mutated_sha, original_sha)
                    self.assertEqual(len(mutated_raw) == len(fixture["recipe_raw"]),
                                     same_byte_count)
                    recipe_path.write_bytes(mutated_raw)
                    os.chmod(recipe_path, 0o600)
                    parsed_mutant_payloads: list[str] = []

                    def track_mutant_json(payload, *args, **kwargs):
                        if payload == mutated_raw.decode("utf-8"):
                            parsed_mutant_payloads.append(payload)
                        return original_json_loads(payload, *args, **kwargs)

                    with patch.object(pair, "read_stable", wraps=pair.read_stable) as stable_reads, \
                         patch.object(pair, "_load_module", wraps=pair._load_module) as module_loads, \
                         patch.object(pair.json, "loads", side_effect=track_mutant_json):
                        with self.assertRaisesRegex(pair.PressurePairError,
                                                    "mapped local/captured bytes differ"):
                            self._call_public_reader(fixture, mutated_sha)
                        recipe_reads = [call for call in stable_reads.call_args_list
                                        if len(call.args) >= 2 and
                                        call.args[1] == "offline pressure-pair recipe"]
                        self.assertEqual(recipe_reads, [])
                        self.assertEqual(parsed_mutant_payloads, [])
                        module_loads.assert_not_called()
            self.assertEqual(recipe_capture["raw_sha256"], original_sha)


class StrictObservedHostBindingTests(unittest.TestCase):
    """Boundary regressions for distinct Source5 and pressure host schemas."""

    def _observed_context(self, path: Path, host_id: str = "host") -> tuple[dict[str, str], dict[str, object]]:
        controls = {
            "cpu_model": "fixture-cpu-model", "microcode_sha256": "a" * 64,
            "kernel_release": "fixture-kernel", "governor": "performance",
            "frequency_policy": "fixed", "boost_policy": "disabled",
            "cpu_set": "0-3", "numa_policy": "local",
            "cgroup_policy_sha256": "b" * 64,
            "background_load_policy_sha256": "c" * 64,
            "x86_64_v3_capability_sha256": "d" * 64,
            "target_triple": "x86_64-unknown-linux-gnu", "target_cpu": "x86-64-v3",
        }
        observed = {
            "schema": "allocatbelt.application-capacity-host-context.v1",
            "host_id": host_id, "boot_id_sha256": "e" * 64,
            "controls_sha256": hashlib.sha256(pair.canonical_bytes(controls)).hexdigest(),
            "controls": controls, "kernel_release": controls["kernel_release"],
            "cpu_model": controls["cpu_model"], "cpu_affinity": [0, 1, 2, 3],
            "network_namespace_inode": 98765,
        }
        raw = pair.canonical_bytes(observed)
        path.write_bytes(raw)
        os.chmod(path, 0o600)
        return {"path": str(path), "raw_sha256": hashlib.sha256(raw).hexdigest()}, observed

    def _recipes_for(self, pin: dict[str, str], observed: dict[str, object]) -> list[dict[str, object]]:
        rows = []
        for index in range(2):
            rows.append({
                "identity": {"host_id": observed["host_id"], "member": index},
                "host": {
                    "boot_id_sha256": observed["boot_id_sha256"],
                    "kernel_release": observed["kernel_release"],
                    "allowed_cpu_affinity": observed["cpu_affinity"],
                },
                "network": {"network_namespace_inode": observed["network_namespace_inode"]},
                "calibration_scope_v2": {
                    "schema": "allocatbelt.application-pressure-calibration-binding.v2",
                    "scope_receipt": {"path": "/evidence/scope.json", "raw_sha256": "1" * 64,
                                       "scope_sha256": "2" * 64},
                    "validator_sha256": "3" * 64,
                    "condition": {"path": "/evidence/condition.json", "raw_sha256": "4" * 64},
                    "context_policy": {"path": "/evidence/context.json", "raw_sha256": "5" * 64},
                    "capacity_bundle_pins": {}, "observed_host": dict(pin),
                    "context_policy_sha256": "6" * 64,
                },
            })
        return rows

    def test_pressure_recipe_host_namespace_is_rejected_before_live_checks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-host-shape-") as directory:
            _summary, pressure_recipe = full_pressure_recipe_api_fixture(Path(directory))
            live_checks: list[object] = []
            with patch.object(
                pressure_driver, "_verify_live_environment",
                side_effect=lambda value: live_checks.append(value),
            ):
                with self.assertRaisesRegex(
                    pair.PressurePairError,
                    "strict Source5 observed-host context has an unexpected field set",
                ):
                    pair._capture_pair_origin_facts(
                        "host", pressure_recipe["host"],
                        [pressure_recipe, pressure_recipe], pressure_driver,
                    )
            self.assertEqual(live_checks, [])

    def test_modified_observed_host_bytes_fail_the_original_raw_pin(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-host-raw-pin-") as directory:
            root = Path(directory)
            pin, observed = self._observed_context(root / "observed-host.json")
            recipes = self._recipes_for(pin, observed)
            checked_pin, checked = pair._verify_pair_observed_host_pin(
                pin, "host", recipes, pressure_reader,
            )
            self.assertEqual(checked_pin, pin)
            self.assertEqual(checked, observed)

            modified = dict(observed)
            modified["network_namespace_inode"] = 98766
            (root / "observed-host.json").write_bytes(pair.canonical_bytes(modified))
            with self.assertRaisesRegex(pair.PressurePairError, "bytes differ from their raw pin"):
                pair._verify_pair_observed_host_pin(pin, "host", recipes, pressure_reader)

    def test_repinned_observed_host_cannot_rebind_original_pressure_recipes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-host-generation-") as directory:
            root = Path(directory)
            original_pin, observed = self._observed_context(root / "observed-host.json")
            recipes = self._recipes_for(original_pin, observed)
            changed = dict(observed)
            changed_controls = dict(observed["controls"])
            changed_controls["governor"] = "another-frozen-policy"
            changed["controls"] = changed_controls
            changed["controls_sha256"] = hashlib.sha256(
                pair.canonical_bytes(changed_controls),
            ).hexdigest()
            changed_path = root / "changed-observed-host.json"
            changed_raw = pair.canonical_bytes(changed)
            changed_path.write_bytes(changed_raw)
            os.chmod(changed_path, 0o600)
            changed_pin = {"path": str(changed_path),
                           "raw_sha256": hashlib.sha256(changed_raw).hexdigest()}
            with self.assertRaisesRegex(pair.PressurePairError,
                                        "changed the exact observed-host raw pin"):
                pair._verify_pair_observed_host_pin(
                    changed_pin, "host", recipes, pressure_reader,
                )

    def test_pair_path_closure_rejects_unmapped_host_input_before_read(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-host-map-order-") as directory:
            root = Path(directory).resolve(strict=True)
            parent, nested = root / "overlay.json", root / "observed-host.json"
            document = {"chronology": {"observed_host": {
                "path": str(nested), "raw_sha256": "a" * 64,
            }}}
            reads: list[str] = []
            with patch.object(
                pair, "read_json",
                side_effect=lambda path, *args, **kwargs: reads.append(str(path)),
            ):
                with self.assertRaisesRegex(pair.PressurePairError,
                                            "omits (?:an )?exact nested original dependency"):
                    pair._preflight_pair_json_path_closure(
                        [document], {str(root), str(parent)}, {str(root)},
                    )
            self.assertEqual(reads, [])

    def test_json_suffix_does_not_authorize_nested_payload_reads(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-opaque-json-map-") as directory:
            root = Path(directory).resolve(strict=True)
            opaque = root / "application-payload.json"
            document = {"typed_payload": {"path": str(opaque),
                                           "raw_sha256": "b" * 64}}
            reads: list[str] = []
            with patch.object(
                pair, "read_json",
                side_effect=lambda path, *args, **kwargs: reads.append(str(path)),
            ):
                pair._preflight_pair_json_path_closure(
                    [document], {str(root), str(opaque)}, {str(root)},
                )
            self.assertEqual(reads, [])

    def test_sourcev5_module_globals_come_from_captured_bytes_and_origin_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-captured-globals-") as directory:
            root = Path(directory).resolve(strict=True)
            source_path = root / "scripts" / "pinned-helper.py"
            source_path.parent.mkdir()
            captured = b'CAPTURED_VALUE = "verified-bytes"\nCAPTURED_FILE = __file__\n'
            replacement = b'CAPTURED_VALUE = "changed-path-bytes"\nCAPTURED_FILE = __file__\n'
            source_path.write_bytes(captured)
            os.chmod(source_path, 0o644)
            cache = source_path.parent / "__pycache__" / "pinned-helper.cpython-999.pyc"
            cache.parent.mkdir()
            cache.write_bytes(b"ignored stale bytecode")
            record = {
                "path": "scripts/pinned-helper.py", "kind": "file", "mode": "100644",
                "sha256": hashlib.sha256(captured).hexdigest(), "size": len(captured),
            }
            source = {"source": {"files": [record]}}
            real_read = pair.read_stable

            def swap_after_capture(path: Path, label: str, maximum: int):
                result = real_read(path, label, maximum)
                if path == source_path:
                    source_path.write_bytes(replacement)
                return result

            with patch.object(pair, "read_stable", side_effect=swap_after_capture):
                module, pin = pair._pinned_source_module(
                    source, root, record["path"], "captured helper regression", 4096,
                )
            self.assertEqual(pin["sha256"], record["sha256"])
            self.assertEqual(module.CAPTURED_VALUE, "verified-bytes")
            self.assertEqual(module.CAPTURED_FILE, str(source_path))
            self.assertEqual(source_path.read_bytes(), replacement)


class CapturedFixedPredecessorContextTests(unittest.TestCase):
    """Shape-only checks for the additive live predecessor-context boundary."""

    def _projection_fixture(self, root: Path):
        job = {
            "host_id": "host-a", "phase": "pressure",
            "run_id": "pressure-run-01",
            "predecessor_run_ids": ["fixed-run-01"],
        }
        job_record = {"path": str(root / "fixed-job-record.json"),
                      "raw_sha256": "a" * 64}
        receipt_value = {"schema": "allocatbelt.fixed-pressure-predecessor.v1",
                         "component_sha256": "b" * 64}
        receipt_pin = {"path": str(root / "preflight" /
                                    "fixed-pressure-predecessor.json"),
                       "raw_sha256": "c" * 64}
        auth = {
            "job": job, "job_index": 12,
            "helper_input": {"path": str(root / "helper.json"),
                             "sha256": "d" * 64},
            "authorization_id": "pressure-auth-01",
            "capacity_registration_head": "e" * 64,
        }
        overlay = {"chronology": {
            "journal_head": "f" * 64, "journal_record_count": 17,
            "registration_head": "e" * 64,
        }}
        recipe = {"fixed_predecessor": {"record": job_record}}
        inputs = {"job": job, "job_index": 12}
        projection = {
            "schema": pair.SOURCE5_PRESSURE_PREREQUISITES_SCHEMA,
            "job": job, "job_index": 12,
            "helper_input": auth["helper_input"],
            "authorization_id": auth["authorization_id"],
            "authorization_head": "1" * 64,
            "authorization_record_count": 4,
            "registration_head": "e" * 64,
            "historical_head": "f" * 64,
            "historical_record_count": 17,
            "fixed_predecessor": {
                "run_id": "fixed-run-01", "job_record": job_record,
                "receipt": receipt_pin, "receipt_value": receipt_value,
                "component_sha256": "2" * 64,
                "process_metrics_sha256": "3" * 64,
                "state": "valid_pair",
            },
            "component_replayed": True,
            "qualification_eligible": False,
        }
        return projection, recipe, inputs, auth, overlay

    def test_json_context_is_not_a_chronology_issued_capability(self) -> None:
        with self.assertRaisesRegex(
                pair.PressurePairError, "non-JSON chronology-issued context"):
            pair._verify_captured_source5_pressure_predecessor_context(
                {}, {}, Path("/private/pressure-output"), None,
                {}, {}, {}, {}, {},
            )

    def test_validator_receives_original_lock_authorization_and_recipe_pins(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-captured-issuer-") as tmp:
            root = Path(tmp)
            source_root = root / "source"
            chronology_path = source_root / "scripts" / \
                "application-campaign-chronology.py"
            chronology_path.parent.mkdir(parents=True)
            chronology_path.write_text("# pinned chronology source\n",
                                      encoding="utf-8")
            namespace: dict[str, object] = {}
            projection = {"captured": True}
            validator_source = (
                "def validate(context, *, lock, authorization_context, "
                "recipe_pin, output_root):\n"
                "    calls.append((context, lock, authorization_context, "
                "recipe_pin, output_root))\n"
                "    return projection\n"
            )
            calls: list[tuple] = []
            namespace["calls"] = calls
            namespace["projection"] = projection
            exec(compile(validator_source, str(chronology_path), "exec"),
                 namespace)
            chronology = types.SimpleNamespace(
                __file__=str(chronology_path),
                validate_source5_pressure_predecessor_context=
                    namespace["validate"],
            )

            context = object()
            lock = object()
            authorization = {"authorization_id": "auth-01"}
            recipe_pin = {"path": str(root / "recipe.json"),
                          "raw_sha256": "a" * 64}
            output_root = root / "output"
            with patch.object(
                    pair,
                    "_validate_captured_source5_pressure_prerequisites",
                    return_value={"validated": True}) as close_projection:
                result = pair._verify_captured_source5_pressure_predecessor_context(
                    context, recipe_pin, output_root, lock, {},
                    {"source_root": source_root},
                    {"campaign_chronology": chronology}, authorization, {},
                )

            self.assertEqual(result, {"validated": True})
            self.assertEqual(len(calls), 1)
            self.assertIs(calls[0][0], context)
            self.assertIs(calls[0][1], lock)
            self.assertIs(calls[0][2], authorization)
            self.assertEqual(calls[0][3], recipe_pin)
            self.assertEqual(calls[0][4], output_root)
            self.assertEqual(close_projection.call_args.args[0], projection)
            self.assertIs(close_projection.call_args.args[0], projection)

    def test_validator_loader_keeps_supplied_chronology_module_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-chronology-instance-") as tmp:
            root = Path(tmp)
            source_root = root / "source"
            chronology_path = source_root / "scripts" / \
                "application-campaign-chronology.py"
            chronology_path.parent.mkdir(parents=True)
            chronology_path.write_text("# chronology loaded by caller\n",
                                      encoding="utf-8")
            chronology_path.chmod(0o644)
            chronology_raw = chronology_path.read_bytes()
            chronology_sha = hashlib.sha256(chronology_raw).hexdigest()
            chronology_record = {
                "path": "scripts/application-campaign-chronology.py",
                "kind": "file", "mode": "100644",
                "sha256": chronology_sha, "size": len(chronology_raw),
            }
            source_paths = {
                "campaign_controller": "scripts/application-campaign.py",
                "campaign_chronology":
                    "scripts/application-campaign-chronology.py",
                "feedback_composition":
                    "scripts/application-feedback-composition.py",
                "feedback_validator":
                    "scripts/application-feedback-readback.py",
                "pressure_validator":
                    "scripts/application-pressure-readback.py",
                "soak_supervisor": "scripts/application-soak-readback.py",
                "capacity_producer": "scripts/application-byte-capacity.py",
                "pressure_driver": "scripts/application-pressure-driver.py",
                "fixed_pair": "scripts/application-fixed-pair.py",
                "soak_recipe_builder": "scripts/application-soak-recipe.py",
                "soak_runner": "scripts/application-soak-runner.py",
            }
            source_hashes = {
                name: (chronology_sha if name == "campaign_chronology"
                       else hashlib.sha256(name.encode()).hexdigest())
                for name in source_paths
            }
            harness = {
                "campaign_controller": {
                    "path": source_paths["campaign_controller"],
                    "sha256": source_hashes["campaign_controller"],
                },
                "feedback_validator": {
                    "path": source_paths["feedback_validator"],
                    "sha256": source_hashes["feedback_validator"],
                },
                "byte_capacity_producer": {
                    "path": source_paths["capacity_producer"],
                    "sha256": source_hashes["capacity_producer"],
                },
                "pressure_driver": {
                    "path": source_paths["pressure_driver"],
                    "sha256": source_hashes["pressure_driver"],
                },
                "pressure_validator": {
                    "path": source_paths["pressure_validator"],
                    "sha256": source_hashes["pressure_validator"],
                },
                "soak_recipe_builder": {
                    "path": source_paths["soak_recipe_builder"],
                    "sha256": source_hashes["soak_recipe_builder"],
                },
                "soak_validator": {
                    "path": source_paths["soak_supervisor"],
                    "sha256": source_hashes["soak_supervisor"],
                },
                "soak_runner": {
                    "path": source_paths["soak_runner"],
                    "sha256": source_hashes["soak_runner"],
                },
            }
            source = {
                "source": {"files": [chronology_record]},
                "qualification_harness": harness,
            }
            recipe = {
                "validators": {
                    name: {"path": source_paths[name],
                           "sha256": source_hashes[name]}
                    for name in (
                        "campaign_controller", "campaign_chronology",
                        "feedback_composition", "feedback_validator",
                        "pressure_validator", "soak_supervisor",
                        "capacity_producer",
                    )
                },
            }
            supplied = types.ModuleType("already_loaded_chronology")
            supplied.__file__ = str(chronology_path)
            loaded_elsewhere = types.ModuleType("ordinary_validator")

            def fake_module_loader(source_value, source_root_value, relative,
                                   label, maximum):
                return loaded_elsewhere, {
                    "path": relative, "sha256": source_hashes.get(
                        next((key for key, path in source_paths.items()
                              if path == relative), ""),
                    ),
                }

            with patch.object(pair, "_pinned_source_module",
                              side_effect=fake_module_loader) as loader:
                modules = pair._load_validators(
                    recipe, {"source": source,
                             "source_root": source_root}, supplied,
                )

            self.assertIs(modules["campaign_chronology"], supplied)
            self.assertFalse(any(call.args[2] ==
                                 "scripts/application-campaign-chronology.py"
                                 for call in loader.call_args_list))

    def test_live_apis_add_context_without_a_journal_map_parameter(self) -> None:
        for function in (pair._prepare_prerequisites,
                         pair.validate_pressure_pair_artifacts,
                         pair._run_pressure_pair_component,
                         pair.run_pressure_pair_locked,
                         pair.verify_pressure_pair_with_host_receipt):
            with self.subTest(function=function.__name__):
                signature = inspect.signature(function)
                parameter = signature.parameters.get(
                    "pressure_predecessor_context",
                )
                self.assertIsNotNone(parameter)
                self.assertEqual(parameter.default, None)
                self.assertNotIn("evidence_path_map", signature.parameters)

    def test_projection_closes_active_authorization_and_original_predecessor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-captured-context-") as tmp:
            root = Path(tmp)
            projection, recipe, inputs, auth, overlay = self._projection_fixture(root)
            checked = pair._validate_captured_source5_pressure_prerequisites(
                projection, recipe, inputs, auth, overlay, root,
            )
            self.assertEqual(checked, projection)

            wrong_predecessor = {
                **projection,
                "fixed_predecessor": {
                    **projection["fixed_predecessor"],
                    "run_id": "unrelated-fixed-run",
                },
            }
            with self.assertRaisesRegex(pair.PressurePairError,
                                        "original pressure-plan edge"):
                pair._validate_captured_source5_pressure_prerequisites(
                    wrong_predecessor, recipe, inputs, auth, overlay, root,
                )

            wrong_head = {**projection, "historical_head": "4" * 64}
            with self.assertRaisesRegex(pair.PressurePairError,
                                        "active pressure authorization/overlay"):
                pair._validate_captured_source5_pressure_prerequisites(
                    wrong_head, recipe, inputs, auth, overlay, root,
                )


class FixedPredecessorReceiptPersistenceTests(unittest.TestCase):
    def test_live_preflight_persists_and_rechecks_exact_reconstructed_receipt(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-fixed-receipt-live-") as temporary:
            root = Path(temporary).resolve()
            preflight = root / "preflight"
            preflight.mkdir(mode=0o700)
            path = preflight / "fixed-pressure-predecessor.json"
            receipt = {"schema": "allocatbelt.fixed-pressure-predecessor.v1",
                       "state": "valid_pair", "metrics": [1, 2]}
            raw = pair.canonical_bytes(receipt)
            expected_sha = hashlib.sha256(raw).hexdigest()

            actual_sha = pair._close_reconstructed_fixed_predecessor_receipt(
                path, receipt, raw, captured_receipt_pin=None,
                captured_replay=False,
            )
            self.assertEqual(actual_sha, expected_sha)
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

            repeated_sha = pair._close_reconstructed_fixed_predecessor_receipt(
                path, receipt, raw, captured_receipt_pin=None,
                captured_replay=False,
            )
            self.assertEqual(repeated_sha, expected_sha)

            changed = {**receipt, "metrics": [1, 3]}
            with self.assertRaisesRegex(
                    pair.PressurePairError,
                    "stored fixed-pressure predecessor receipt differs"):
                pair._close_reconstructed_fixed_predecessor_receipt(
                    path, changed, pair.canonical_bytes(changed),
                    captured_receipt_pin=None, captured_replay=False,
                )

    def test_archived_replay_closes_captured_pin_without_origin_io(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-fixed-receipt-replay-") as temporary:
            root = Path(temporary).resolve()
            absent_origin = root / "reclaimed" / "preflight" / \
                "fixed-pressure-predecessor.json"
            receipt = {"schema": "allocatbelt.fixed-pressure-predecessor.v1",
                       "state": "valid_pair", "metrics": [7, 8]}
            raw = pair.canonical_bytes(receipt)
            raw_sha = hashlib.sha256(raw).hexdigest()
            with patch.object(
                    pair, "read_json",
                    side_effect=AssertionError("captured replay read an origin receipt")), \
                 patch.object(
                    pair, "write_new",
                    side_effect=AssertionError("captured replay wrote an origin receipt")):
                actual_sha = pair._close_reconstructed_fixed_predecessor_receipt(
                    absent_origin, receipt, raw,
                    captured_receipt_pin={"path": str(absent_origin),
                                          "raw_sha256": raw_sha},
                    captured_replay=True,
                )
            self.assertEqual(actual_sha, raw_sha)
            self.assertFalse(absent_origin.exists())

            with self.assertRaisesRegex(
                    pair.PressurePairError,
                    "differs from fresh source/job/metrics reconstruction"):
                pair._close_reconstructed_fixed_predecessor_receipt(
                    absent_origin, receipt, raw,
                    captured_receipt_pin={"path": str(absent_origin),
                                          "raw_sha256": "0" * 64},
                    captured_replay=True,
                )


class PressureApplicationTmpdirOwnerProofTests(unittest.TestCase):
    def _proofs(self):
        path = "/reserved/source5/pressure/member-0/application-tmp"
        mount = {
            "mount_id": 17, "major_minor": "8:1", "mount_root": "/",
            "mount_point": "/reserved", "filesystem_type": "ext4",
            "mount_source": "/dev/sda1", "device": 8,
        }
        initial = {
            "path": path, "device": 8, "inode": 1001, "mode": 0o700,
            "mount": mount, "available_bytes": 1 << 20,
            "available_inodes": 4096, "bytes_limit": 65536,
            "inode_limit": 128,
        }
        final = {
            "path": path, "device": 8, "inode": 1001, "mode": 0o700,
            "mount": mount, "bytes_used": 0, "file_count": 0,
            "directory_count": 0, "bytes_limit": 65536,
            "inode_limit": 128, "available_bytes": 1 << 20,
            "available_inodes": 4096,
        }
        return initial, final

    def test_owner_return_proof_preserves_exact_identity_and_empty_counts(self) -> None:
        initial, final = self._proofs()
        checked_initial, checked_final = pair._validate_pressure_tmpdir_owner_proof(
            initial, final, initial["path"],
            {"bytes_limit": 65536, "inode_limit": 128},
            "pressure member zero",
        )
        self.assertEqual(checked_initial, initial)
        self.assertEqual(checked_final, final)

    def test_owner_return_proof_rejects_nonempty_or_replaced_root(self) -> None:
        initial, final = self._proofs()
        nonempty = dict(final, file_count=1)
        with self.assertRaisesRegex(pair.PressurePairError,
                                    "exact empty original owner-return inventory"):
            pair._validate_pressure_tmpdir_owner_proof(
                initial, nonempty, initial["path"],
                {"bytes_limit": 65536, "inode_limit": 128},
                "pressure member zero",
            )
        replaced = dict(final, inode=1002)
        with self.assertRaisesRegex(pair.PressurePairError,
                                    "exact empty original owner-return inventory"):
            pair._validate_pressure_tmpdir_owner_proof(
                initial, replaced, initial["path"],
                {"bytes_limit": 65536, "inode_limit": 128},
                "pressure member zero",
            )


class CapturedPressureArtifactViewTests(unittest.TestCase):
    def test_hview_stream_reads_exact_stage_object_without_origin_stat(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-captured-stage-") as temporary:
            root = Path(temporary).resolve()
            stage_root = root / "stage"
            stage_root.mkdir(mode=0o700)
            origin = str(root / "reclaimed" / "pressure-output.jsonl")
            local = stage_root / "object-00.bin"
            raw = b"captured pressure stream\n"
            local.write_bytes(raw)
            local.chmod(0o400)
            raw_sha = hashlib.sha256(raw).hexdigest()
            view = pair.CapturedPressureArtifactView(str(stage_root), {
                origin: {
                    "origin_path": origin, "path": str(local),
                    "role": "pressure_pair_artifact", "host_id": "host-a",
                    "raw_sha256": raw_sha, "semantic_sha256": None,
                    "byte_count": len(raw), "maximum_bytes": len(raw),
                },
            })
            self.assertTrue(view.has_file(origin))
            self.assertFalse(Path(origin).exists())

            inspected: list[str] = []
            original_lstat = Path.lstat

            def track_lstat(path: Path, *args, **kwargs):
                inspected.append(str(path))
                if str(path) == origin:
                    raise AssertionError("captured replay lstat-ed an original origin")
                return original_lstat(path, *args, **kwargs)

            io_context = {
                "artifact_view": view,
                "captured_origin_paths": frozenset({origin}),
                "output_root": root / "reclaimed",
                "retained_output_paths": frozenset(),
                "optional_output_paths": frozenset(),
            }
            token_value = pair._PRESSURE_CAPTURED_REPLAY.set(io_context)
            try:
                with patch.object(Path, "lstat", track_lstat):
                    actual, checksum, actual_info = pair.read_stable(
                        Path(origin), "captured pressure stream", len(raw),
                    )
                self.assertEqual(actual, raw)
                self.assertEqual(checksum, raw_sha)
                self.assertIsNone(actual_info)
                self.assertNotIn(origin, inspected)
                with self.assertRaisesRegex(
                        pair.PressurePairError,
                        "missing from the exact archive view"):
                    pair.read_stable(
                        root / "reclaimed" / "unlisted.bin",
                        "unlisted pressure output", 128,
                    )
            finally:
                pair._PRESSURE_CAPTURED_REPLAY.reset(token_value)

    def test_stage_map_rejects_aliasing_and_mutated_objects(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-captured-tamper-") as temporary:
            root = Path(temporary).resolve()
            stage_root = root / "stage"
            stage_root.mkdir(mode=0o700)
            local = stage_root / "object-00.bin"
            raw = b"expected\n"
            local.write_bytes(raw)
            local.chmod(0o400)
            origin = str(root / "reclaimed" / "pressure-output.json")
            reference = {
                "origin_path": origin, "path": str(local),
                "role": "pressure_pair_artifact", "host_id": "host-a",
                "raw_sha256": hashlib.sha256(raw).hexdigest(),
                "semantic_sha256": None, "byte_count": len(raw),
                "maximum_bytes": len(raw),
            }
            view = pair.CapturedPressureArtifactView(str(stage_root), {origin: reference})
            local.chmod(0o600)
            with self.assertRaisesRegex(pair.PressurePairError,
                                        "private mode-0400 staged regular object"):
                view.read(origin, "mutated pressure object", 128)
            with self.assertRaisesRegex(pair.PressurePairError, "aliased"):
                pair.CapturedPressureArtifactView(str(stage_root), {
                    origin: reference,
                    str(root / "reclaimed" / "pressure-second.json"): {
                        **reference,
                        "origin_path": str(root / "reclaimed" / "pressure-second.json"),
                    },
                })

    def test_stage_map_rejects_truncated_symlink_and_missing_objects(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-captured-truncated-") as temporary:
            root = Path(temporary).resolve()
            stage_root = root / "stage"
            stage_root.mkdir(mode=0o700)
            origin = str(root / "reclaimed" / "pressure-output.json")
            expected = b"complete captured bytes\n"
            local = stage_root / "object-00.bin"
            local.write_bytes(expected[:-1])
            local.chmod(0o400)
            reference = {
                "origin_path": origin, "path": str(local),
                "role": "pressure_pair_artifact", "host_id": "host-a",
                "raw_sha256": hashlib.sha256(expected).hexdigest(),
                "semantic_sha256": None, "byte_count": len(expected),
                "maximum_bytes": len(expected),
            }
            truncated = pair.CapturedPressureArtifactView(str(stage_root), {
                origin: reference,
            })
            with self.assertRaisesRegex(pair.PressurePairError,
                                        "exact private mode-0400 staged regular object"):
                truncated.read(origin, "truncated pressure object", 128)

            local.chmod(0o600)
            local.write_bytes(expected)
            local.chmod(0o400)
            symlink = stage_root / "object-01.bin"
            symlink.symlink_to(local.name)
            linked = pair.CapturedPressureArtifactView(str(stage_root), {
                origin: {**reference, "path": str(symlink)},
            })
            with self.assertRaisesRegex(pair.PressurePairError,
                                        "cannot safely open or verify captured pressure symlink pressure object"):
                linked.read(origin, "symlink pressure object", 128)

            regular = pair.CapturedPressureArtifactView(str(stage_root), {
                origin: reference,
            })
            with self.assertRaisesRegex(pair.PressurePairError,
                                        "absent from the exact captured pressure object set"):
                regular.read(str(root / "reclaimed" / "missing.json"),
                             "missing pressure object", 128)

    def test_stage_map_uses_dirfd_and_rejects_linked_objects_or_replaced_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pressure-captured-dirfd-") as temporary:
            root = Path(temporary).resolve()
            stage_root = root / "stage"
            stage_root.mkdir(mode=0o700)
            local = stage_root / "object-00.bin"
            raw = b"captured pressure identity\n"
            local.write_bytes(raw)
            local.chmod(0o400)
            origin = str(root / "reclaimed" / "pressure-output.json")
            reference = {
                "origin_path": origin, "path": str(local),
                "role": "pressure_pair_artifact", "host_id": "host-a",
                "raw_sha256": hashlib.sha256(raw).hexdigest(),
                "semantic_sha256": None, "byte_count": len(raw),
                "maximum_bytes": len(raw),
            }
            view = pair.CapturedPressureArtifactView(
                str(stage_root), {origin: reference},
            )
            hardlink = root / "outside-hardlink.bin"
            os.link(local, hardlink)
            with self.assertRaisesRegex(pair.PressurePairError,
                                        "mode-0400 staged regular object"):
                view.read(origin, "linked pressure object", len(raw))
            hardlink.unlink()

            moved_root = root / "stage-renamed"
            stage_root.rename(moved_root)
            stage_root.symlink_to(moved_root.name, target_is_directory=True)
            with self.assertRaisesRegex(
                    pair.PressurePairError,
                    "cannot safely open or verify captured pressure replaced pressure stage",
            ):
                view.read(origin, "replaced pressure stage", len(raw))


def run_pressure_pair_offline_fixture(
    request_path: Path, expected_request_raw_sha256: str,
    source5_journal_context: object,
) -> dict:
    """Public-entrypoint harness for genuine copied Source5 pair evidence.

    The context must come from the exact captured host request/store/job record;
    this helper does not manufacture a success flag or a module handle.
    """
    value, raw, actual = pair.read_json(
        request_path, "pressure-pair offline fixture request", 2 * 1024 * 1024,
        expected_request_raw_sha256,
    )
    pair.exact(value, {
        "schema", "recipe", "output_root", "readback", "host_verification",
        "evidence_path_map",
    }, "pressure-pair offline fixture request")
    if value["schema"] != "allocatbelt.application-pressure-pair-offline-fixture.v1":
        raise pair.PressurePairError("unsupported pressure-pair offline fixture request schema")
    replay = pair.validate_pressure_pair_artifacts_offline(
        value["recipe"], value["output_root"], value["readback"],
        value["host_verification"], value["evidence_path_map"],
        source5_journal_context=source5_journal_context,
    )
    if replay.get("validated") is not True or replay.get("qualification_eligible") is not False or replay.get("execution_ready") is not False:
        raise pair.PressurePairError("offline pressure-pair fixture returned a partial or eligible result")
    return {"request_raw_sha256": actual, "raw_request": raw, "replay": replay}


def capture_pressure_pair_origin_fixture(
    recipe_pin: dict, output_root: Path, readback_pin: dict, host_receipt_path: Path,
    *, chronology_module, lock, authorization_context: dict,
    pressure_predecessor_context=None,
) -> dict:
    """Run the real strict origin API for caller-supplied completed evidence.

    The caller must supply the active Source5 lock/auth context and genuine
    completed pair artifacts. This wrapper creates no evidence itself; the
    production API replays the original pair and ProbeV2 capture before it
    writes a separate host receipt.
    """
    return pair.verify_pressure_pair_with_host_receipt(
        recipe_pin, output_root, readback_pin, host_receipt_path,
        chronology_module=chronology_module, lock=lock,
        authorization_context=authorization_context,
        pressure_predecessor_context=pressure_predecessor_context,
    )



if __name__ == "__main__":
    unittest.main()
