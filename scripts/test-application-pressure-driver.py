#!/usr/bin/env python3
"""Focused correctness tests for the bounded application pressure lane.

Run this suite only on the designated native SSH-MCP host. It performs a
three-second pressure-contention calibration, a short synthetic sleeper
overlap to exercise launch/readback wiring, and an injected event-cap failure
to check post-cleanup receipt preservation. It is not a real application,
performance, or qualification run.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import patch


SCRIPT_DIR = Path(__file__).resolve().parent
DRIVER_PATH = SCRIPT_DIR / "application-pressure-driver.py"
READER_PATH = SCRIPT_DIR / "application-pressure-readback.py"
SOAK_READBACK_PATH = SCRIPT_DIR / "application-soak-readback.py"


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


driver = _load_module("pressure_driver_test_target", DRIVER_PATH)
readback = _load_module("pressure_readback_test_target", READER_PATH)
soak_supervisor = _load_module("pressure_subreaper_test_target", SOAK_READBACK_PATH)


class PressureDriverTests(unittest.TestCase):
    def test_json_parser_rejects_duplicate_keys_nonfinite_values_and_booleans(self) -> None:
        with self.assertRaises(driver.PressureError):
            driver.parse_object(b'{"x":1,"x":2}\n', "duplicate", 128)
        with self.assertRaises(driver.PressureError):
            driver.parse_object(b'{"x":NaN}\n', "nonfinite", 128)
        with self.assertRaises(driver.PressureError):
            driver.uint(True, "boolean-as-integer")

    def test_schedule_rejects_excessive_cumulative_io_and_unknown_fields(self) -> None:
        schedule = {
            "seed": 7,
            "duration_seconds": 3,
            "sample_interval_ms": 250,
            "startup_deadline_seconds": 10,
            "total_deadline_seconds": 20,
            "term_deadline_seconds": 2,
            "kill_deadline_seconds": 2,
            "minimum_overlap_seconds": 1,
            "startup_ready_windows": 1,
            "cpu_duty_basis_points": 7000,
            "pressure_cpu_affinity": [0],
            "application_cpu_affinity": [0],
            "disk_bytes_per_second": 1024 * 1024,
            "scratch_file_bytes": 65536,
            "network_requests_per_second": 100,
            "network_payload_bytes": 256,
        }
        normalized = driver._schedule(schedule)
        self.assertEqual(normalized["duration_seconds"], 3)
        oversize = dict(schedule, network_requests_per_second=100000, network_payload_bytes=65536)
        with self.assertRaises(driver.PressureError):
            driver._schedule(oversize)
        with self.assertRaises(driver.PressureError):
            driver._schedule(dict(schedule, shell_command="never accepted"))

    def test_frozen_event_budget_covers_two_and_four_cpu_soak_and_rejects_wide_schedules(self) -> None:
        backing_chain = [{"device": "259:2", "name": "nvme0n1p2", "sysfs_path": "/sys/devices/example"}]

        def budget_for(cpu_count: int, duration: int) -> dict[str, int]:
            schedule = {
                "seed": 17,
                "duration_seconds": duration,
                "sample_interval_ms": 100,
                "startup_deadline_seconds": 10,
                "total_deadline_seconds": 12000 if duration > 10800 else 14400,
                "term_deadline_seconds": 2,
                "kill_deadline_seconds": 2,
                "minimum_overlap_seconds": duration,
                "startup_ready_windows": 1,
                "cpu_duty_basis_points": 7000,
                "pressure_cpu_affinity": list(range(cpu_count)),
                "application_cpu_affinity": [0],
                "disk_bytes_per_second": 1024 * 1024,
                "scratch_file_bytes": 65536,
                "network_requests_per_second": 100,
                "network_payload_bytes": 256,
            }
            return driver._artifact_budget(driver._schedule(schedule), backing_chain)

        for cpu_count in (2, 4):
            budget = budget_for(cpu_count, 10800)
            self.assertEqual(budget["sample_count"], 108000)
            self.assertLessEqual(budget["maximum_event_bytes"], driver.MAX_ARTIFACT_BYTES)
        for cpu_count in (16, 64):
            with self.assertRaises(driver.PressureError):
                budget_for(cpu_count, 12000)

    def test_rounded_block_writes_reject_the_64_gib_boundary_profile(self) -> None:
        schedule = {
            "seed": 19,
            "duration_seconds": 12000,
            "sample_interval_ms": 100,
            "startup_deadline_seconds": 10,
            "total_deadline_seconds": 14400,
            "term_deadline_seconds": 2,
            "kill_deadline_seconds": 2,
            "minimum_overlap_seconds": 12000,
            "startup_ready_windows": 1,
            "cpu_duty_basis_points": 7000,
            "pressure_cpu_affinity": [0],
            "application_cpu_affinity": [0],
            "disk_bytes_per_second": 5726623,
            "scratch_file_bytes": 65536,
            "network_requests_per_second": 100,
            "network_payload_bytes": 256,
        }
        actual_window_bytes = ((schedule["disk_bytes_per_second"] * 100 // 1000 + 4095) // 4096) * 4096
        self.assertEqual(actual_window_bytes * 120000, 68_812_800_000)
        with self.assertRaises(driver.PressureError):
            driver._schedule(schedule)

    def test_monotonic_wait_clamps_deadline_and_never_computes_negative_sleep(self) -> None:
        requested: list[float] = []
        with patch.object(driver.time, "monotonic_ns", side_effect=[100, 151]), patch.object(driver.time, "sleep", side_effect=requested.append):
            driver._sleep_until(150, deadline_ns=200, maximum_sleep_ns=100, label="race fixture")
        self.assertEqual(requested, [50 / 1_000_000_000])

        requested.clear()
        with patch.object(driver.time, "monotonic_ns", side_effect=[100, 120, 151]), patch.object(driver.time, "sleep", side_effect=requested.append):
            with self.assertRaises(driver.PressureError):
                driver._sleep_until(150, deadline_ns=150, maximum_sleep_ns=10, label="deadline fixture")
        self.assertEqual(requested, [10 / 1_000_000_000, 10 / 1_000_000_000])

    def test_cleanup_reaping_checks_first_live_and_last_dead_pid_start_pair(self) -> None:
        def exact_pid_is_live(pid: int, start_ticks: int) -> bool:
            return (pid, start_ticks) == (101, 1001)

        with patch.object(readback, "_pid_same", side_effect=exact_pid_is_live):
            with self.assertRaises(readback.ReadbackError):
                readback._require_pid_reaped(101, 1001, "first-worker regression")
            readback._require_pid_reaped(202, 2002, "last-worker regression")

    def test_streamed_overlap_rejects_inactive_holes_revival_and_unready_live_windows(self) -> None:
        live_seen = False
        inactive_seen = False
        for startup_active, startup_ready in ((False, False), (False, True)):
            live_seen, inactive_seen = readback._advance_app_sample_continuity(
                app_started=False, live_seen=live_seen, terminal_inactive_seen=inactive_seen,
                app_active=startup_active, readiness_ok=startup_ready, complete_overlap_window=False,
            )
        self.assertFalse(live_seen)
        self.assertFalse(inactive_seen)

        live_seen, inactive_seen = readback._advance_app_sample_continuity(
            app_started=True, live_seen=live_seen, terminal_inactive_seen=inactive_seen,
            app_active=True, readiness_ok=False, complete_overlap_window=False,
        )
        self.assertTrue(live_seen)
        self.assertFalse(inactive_seen)
        live_seen, inactive_seen = readback._advance_app_sample_continuity(
            app_started=True, live_seen=live_seen, terminal_inactive_seen=inactive_seen,
            app_active=True, readiness_ok=True, complete_overlap_window=True,
        )
        self.assertFalse(inactive_seen)

        with self.assertRaises(readback.ReadbackError):
            readback._advance_app_sample_continuity(
                app_started=True, live_seen=live_seen, terminal_inactive_seen=inactive_seen,
                app_active=True, readiness_ok=False, complete_overlap_window=True,
            )

        dead_live, trailing_death = readback._advance_app_sample_continuity(
            app_started=True, live_seen=live_seen, terminal_inactive_seen=inactive_seen,
            app_active=False, readiness_ok=False, complete_overlap_window=True,
        )
        self.assertTrue(dead_live)
        self.assertTrue(trailing_death)
        with self.assertRaises(readback.ReadbackError):
            readback._advance_app_sample_continuity(
                app_started=True, live_seen=dead_live, terminal_inactive_seen=trailing_death,
                app_active=True, readiness_ok=True, complete_overlap_window=True,
            )

    def test_ready_bounds_use_measured_windows_across_between_sample_app_observations(self) -> None:
        base = 10_000_000_000
        ready_snapshot = {"all_ready": True}
        pid, start_ticks = 101, 1001
        binding = {
            "pressure_ready_monotonic_ns": base + 100_000_000,
            "readiness_snapshot": ready_snapshot,
            "observed_monotonic_ns": base + 150_000_000,
            "launch_record_sha256": "a" * 64,
        }
        process = {"pid": pid, "start_ticks": start_ticks}
        recipe = {"schedule": {
            "sample_interval_ms": 100, "startup_ready_windows": 1, "minimum_overlap_seconds": 0,
        }}
        run = {
            "sample_count": 3, "application_overlap_nanoseconds": 50_000_000,
            "finish_monotonic_ns": base + 500_000_000, "worker_cleanup": [],
        }

        def validate_sample(event: dict[str, Any], _recipe: dict[str, Any], _sequence: int) -> dict[str, Any]:
            return {
                "start": event["start_monotonic_ns"], "end": event["end_monotonic_ns"],
                "app_active": event["app_active"], "readiness": {"all_ready": event["all_ready"]},
            }

        def timeline(trailing_ready: bool) -> dict[str, dict[str, int]]:
            events = [
                {"schema": readback.EVENT_SCHEMA, "kind": "sample", "start_monotonic_ns": base,
                 "end_monotonic_ns": base + 100_000_000, "app_active": False, "all_ready": True},
                {"schema": readback.EVENT_SCHEMA, "kind": "application_start", "sequence": 0,
                 "monotonic_ns": base + 150_000_000, "pid": pid, "start_ticks": start_ticks,
                 "launch_record_sha256": binding["launch_record_sha256"]},
                {"schema": readback.EVENT_SCHEMA, "kind": "sample", "start_monotonic_ns": base + 100_000_000,
                 "end_monotonic_ns": base + 200_000_000, "app_active": True, "all_ready": True},
                {"schema": readback.EVENT_SCHEMA, "kind": "sample", "start_monotonic_ns": base + 200_000_000,
                 "end_monotonic_ns": base + 300_000_000, "app_active": False, "all_ready": trailing_ready},
                {"schema": readback.EVENT_SCHEMA, "kind": "application_exit", "sequence": 1,
                 "monotonic_ns": base + 200_000_000, "pid": pid, "start_ticks": start_ticks,
                 "exit_observed": True},
                {"schema": readback.EVENT_SCHEMA, "kind": "pressure_cleanup",
                 "monotonic_ns": base + 400_000_000, "workers": [],
                 "scratch_file_removed": True, "cleanup_ok": True},
            ]
            start_event = {"monotonic_ns": base - 100_000_000}
            with patch.object(readback, "_validate_sample", side_effect=validate_sample), \
                 patch.object(readback, "_require_pid_reaped"):
                return readback._validate_event_timeline(
                    iter(events), start_event, recipe, process, binding, run, {},
                )

        measured = timeline(trailing_ready=True)
        self.assertEqual(measured["application_window"], {
            "observed_start_monotonic_ns": base + 150_000_000,
            "observed_exit_monotonic_ns": base + 200_000_000,
        })
        self.assertEqual(measured["continuous_ready_window"], {
            "start_monotonic_ns": base + 100_000_000,
            "end_monotonic_ns": base + 300_000_000,
        })

        unready_boundary = timeline(trailing_ready=False)
        self.assertEqual(unready_boundary["continuous_ready_window"], {
            "start_monotonic_ns": base + 100_000_000,
            "end_monotonic_ns": base + 200_000_000,
        })

    def test_readiness_proposal_is_derived_from_numeric_measurements(self) -> None:
        summary = {
            "sample_count": 4,
            "cpu_busy_basis_points_median": 8000,
            "disk_write_bytes_per_second_median": 1_000_000,
            "disk_queue_or_stall_microseconds_median": 12,
            "loopback_requests_per_second_median": 100,
            "loopback_latency_p99_upper_nanoseconds_median": 50_000,
            "loopback_tx_bytes_per_second_median": 32_000,
            "loopback_rx_bytes_per_second_median": 32_000,
        }
        proposal = driver._suggest_thresholds(summary)
        self.assertEqual(proposal["cpu_busy_min_basis_points"], 6400)
        self.assertEqual(proposal["disk_write_min_bytes_per_second"], 800_000)
        self.assertEqual(proposal["disk_queue_or_stall_min_microseconds"], 6)
        self.assertEqual(proposal["loopback_latency_p99_max_nanoseconds"], 100_000)

    def test_calibration_host_does_not_claim_physical_network_pressure(self) -> None:
        route = driver._loopback_route()
        self.assertEqual(route["destination"], "127.0.0.1")
        self.assertEqual(route["interface"], "lo")
        self.assertFalse(route["physical_nic_claimed"])
        self.assertEqual(route["claim"], "ipv4_loopback_shared_kernel_only")

    def test_finite_calibration_freeze_run_and_independent_readback(self) -> None:
        if not sys.platform.startswith("linux"):
            self.skipTest("the pressure lane is Linux-only")
        if shutil.which("ip") is None:
            self.fail("native target is missing iproute2 `ip` required by the loopback route pin")
        root = Path(tempfile.mkdtemp(prefix=f"allocatbelt-pressure-test-{os.getpid()}-", dir="/var/tmp")).resolve()
        succeeded = False
        driver_process: subprocess.Popen[bytes] | None = None
        app_process: subprocess.Popen[bytes] | None = None
        try:
            tmpdir = root / "app-tmp"
            workdir = root / "app-work"
            tmpdir.mkdir(mode=0o700)
            workdir.mkdir(mode=0o700)
            source_path = root / "source-manifest.json"
            policy_path = root / "policy.json"
            capacity_path = root / "app-byte-capacity-calibration.json"
            source_path.write_bytes(b'{"schema":"synthetic-pressure-source.v1"}\n')
            policy_path.write_bytes(b'{"schema":"synthetic-pressure-policy.v1"}\n')
            capacity_path.write_bytes(b'{"schema":"synthetic-app-byte-capacity.v1"}\n')
            executable = Path(sys.executable).resolve(strict=True)
            binary_raw = executable.read_bytes()
            cpu = min(os.sched_getaffinity(0))
            nonce = uuid.uuid4().hex
            pair_id = f"pressure-pair-{nonce[:12]}"
            condition_id = f"pressure-condition-{nonce[:12]}"
            common_identity = {
                "host_id": "native-pressure-test-host",
                "run_id": f"pressure-run-{nonce[:12]}",
                "pair_id": pair_id,
                "condition_id": condition_id,
                "member": "test-member",
                "nonce": nonce,
                "allocator": "system",
                "executor": "synthetic",
            }
            schedule = {
                "seed": 731,
                "duration_seconds": 3,
                "sample_interval_ms": 250,
                "startup_deadline_seconds": 10,
                "total_deadline_seconds": 20,
                "term_deadline_seconds": 2,
                "kill_deadline_seconds": 2,
                "minimum_overlap_seconds": 1,
                "startup_ready_windows": 1,
                "cpu_duty_basis_points": 7000,
                "pressure_cpu_affinity": [cpu],
                "application_cpu_affinity": [cpu],
                "disk_bytes_per_second": 1024 * 1024,
                "scratch_file_bytes": 65536,
                "network_requests_per_second": 100,
                "network_payload_bytes": 256,
            }
            io_paths = [str(workdir), str(tmpdir)]
            common = {
                "schema": driver.REQUEST_SCHEMA,
                "identity": common_identity,
                "files": {
                    "source_manifest": {"path": str(source_path), "sha256": driver.digest_bytes(source_path.read_bytes())},
                    "application_binary": {"path": str(executable), "sha256": driver.digest_bytes(binary_raw)},
                    "policy": {"path": str(policy_path), "sha256": driver.digest_bytes(policy_path.read_bytes())},
                    "application_capacity_calibration": {"path": str(capacity_path), "sha256": driver.digest_bytes(capacity_path.read_bytes())},
                },
                "process": {"executable_path": str(executable), "application_tmpdir_path": str(tmpdir)},
                "storage": {
                    "application_io_paths": io_paths,
                    "pressure_scratch_path": str(tmpdir),
                    "output_minimum_free_bytes": 64 * 1024 * 1024,
                },
                "schedule": schedule,
            }
            calibration_request = root / "calibration-request.json"
            calibration_path = root / "pressure-contention-calibration.json"
            calibration_request.write_bytes(driver.canonical_bytes(common))
            calibration_result = subprocess.run(
                [sys.executable, str(DRIVER_PATH), "calibrate", "--request", str(calibration_request), "--output", str(calibration_path)],
                cwd="/", stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=50, check=False, start_new_session=True,
            )
            self.assertEqual(calibration_result.returncode, 0, calibration_result.stderr.decode("utf-8", errors="replace"))
            calibration_receipt = json.loads(calibration_result.stdout.decode("utf-8"))
            calibration = json.loads(calibration_path.read_text(encoding="utf-8"))
            self.assertEqual(calibration_receipt["calibration_raw_sha256"], driver.digest_bytes(calibration_path.read_bytes()))
            suggested = calibration["suggested_readiness_thresholds"]
            selected = {
                "cpu_busy_min_basis_points": max(1, suggested["cpu_busy_min_basis_points"] // 2),
                "disk_write_min_bytes_per_second": max(1, suggested["disk_write_min_bytes_per_second"] // 2),
                "disk_queue_or_stall_min_microseconds": suggested["disk_queue_or_stall_min_microseconds"],
                "loopback_requests_min_per_second": max(1, suggested["loopback_requests_min_per_second"] // 2),
                "loopback_latency_p99_max_nanoseconds": suggested["loopback_latency_p99_max_nanoseconds"] * 8,
                "loopback_tx_min_bytes_per_second": max(1, suggested["loopback_tx_min_bytes_per_second"] // 2),
                "loopback_rx_min_bytes_per_second": max(1, suggested["loopback_rx_min_bytes_per_second"] // 2),
            }
            run_identity = dict(common_identity, nonce=uuid.uuid4().hex)
            pressure_request_value = dict(common)
            pressure_request_value["identity"] = run_identity
            pressure_request_value["pressure_calibration"] = {"path": str(calibration_path), "sha256": calibration_receipt["calibration_raw_sha256"]}
            pressure_request_value["readiness_thresholds"] = selected
            pressure_request = root / "pressure-request.json"
            recipe_path = root / "frozen-pressure-recipe.json"
            pressure_request.write_bytes(driver.canonical_bytes(pressure_request_value))
            freeze_result = subprocess.run(
                [sys.executable, str(DRIVER_PATH), "freeze", "--request", str(pressure_request), "--output", str(recipe_path)],
                cwd="/", stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=20, check=False,
            )
            self.assertEqual(freeze_result.returncode, 0, freeze_result.stderr.decode("utf-8", errors="replace"))
            frozen = json.loads(freeze_result.stdout.decode("utf-8"))
            recipe = json.loads(recipe_path.read_text(encoding="utf-8"))
            self.assertEqual(recipe["condition_sha256"], frozen["condition_sha256"])
            self.assertEqual(driver._validate_recipe(recipe, frozen["recipe_sha256"])["condition_sha256"], recipe["condition_sha256"])
            with self.assertRaises(driver.PressureError):
                driver._validate_recipe(recipe, "0" * 64)

            artifacts = root / "pressure-run-artifacts"
            ready_path = artifacts / "pressure-ready.json"
            launch_path = artifacts / "launch-record.json"
            environment = os.environ.copy()
            driver_process = subprocess.Popen(
                [sys.executable, str(DRIVER_PATH), "run", "--recipe", str(recipe_path),
                 "--expected-recipe-sha256", frozen["recipe_sha256"],
                 "--launch-record", str(launch_path), "--output-dir", str(artifacts),
                 "--ready-file", str(ready_path)],
                cwd="/", stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True, env=environment,
            )
            ready_deadline = time.monotonic() + 12
            while time.monotonic() < ready_deadline and not ready_path.is_file():
                if driver_process.poll() is not None:
                    stdout, stderr = driver_process.communicate()
                    self.fail(f"pressure driver exited before readiness: {stderr.decode(errors='replace')} {stdout.decode(errors='replace')}")
                time.sleep(0.02)
            self.assertTrue(ready_path.is_file(), "pressure ready barrier missed its finite deadline")
            app_environment = os.environ.copy()
            app_environment["ALLOCATBELT_APP_PRESSURE_NONCE"] = run_identity["nonce"]
            app_environment["TMPDIR"] = str(tmpdir)
            app_process = subprocess.Popen(
                [str(executable), "-c", "import time; time.sleep(2.0)"],
                cwd=workdir, env=app_environment, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, start_new_session=True,
            )
            os.sched_setaffinity(app_process.pid, {cpu})
            app_stat = driver._proc_stat(app_process.pid)
            process_binding_body = {
                "schema": driver.LAUNCH_SCHEMA,
                "recipe_sha256": frozen["recipe_sha256"],
                "nonce": run_identity["nonce"],
                "process": {
                    "pid": app_process.pid,
                    "start_ticks": app_stat["start_ticks"],
                    "executable_path": str(executable),
                    "executable_sha256": driver.digest_bytes(binary_raw),
                    "cwd": str(workdir),
                    "tmpdir_path": str(tmpdir),
                    "cpu_affinity": [cpu],
                    "network_namespace_inode": os.stat(f"/proc/{app_process.pid}/ns/net").st_ino,
                },
            }
            launch_record = {**process_binding_body, "launch_binding_sha256": driver.digest_object(process_binding_body)}
            descriptor = os.open(launch_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                launch_raw = driver.canonical_bytes(launch_record)
                self.assertEqual(os.write(descriptor, launch_raw), len(launch_raw))
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            _, app_stderr = app_process.communicate(timeout=8)
            self.assertEqual(app_process.returncode, 0, app_stderr.decode("utf-8", errors="replace"))
            driver_stdout, driver_stderr = driver_process.communicate(timeout=20)
            self.assertEqual(driver_process.returncode, 0, driver_stderr.decode("utf-8", errors="replace"))
            run_artifacts = json.loads(driver_stdout.decode("utf-8"))
            self.assertEqual(run_artifacts["status"], "complete")
            verify = subprocess.run(
                [sys.executable, str(READER_PATH), "verify",
                 "--recipe", str(recipe_path), "--expected-recipe-sha256", frozen["recipe_sha256"],
                 "--artifacts", str(artifacts),
                 "--expected-run-sha256", run_artifacts["run_sha256"],
                 "--expected-events-sha256", run_artifacts["events_sha256"],
                 "--expected-launch-sha256", run_artifacts["launch_record_sha256"],
                 "--expected-process-binding-sha256", run_artifacts["process_binding_sha256"],
                 "--expected-ready-sha256", run_artifacts["readiness_marker_sha256"]],
                cwd="/", stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=20, check=False,
            )
            self.assertEqual(verify.returncode, 0, verify.stderr.decode("utf-8", errors="replace"))
            readback_value = json.loads(verify.stdout.decode("utf-8"))
            self.assertEqual(readback_value["status"], "valid")
            self.assertFalse(readback_value["physical_nic_claimed"])
            self.assertEqual(readback_value["recipe_raw_sha256"], driver.digest_bytes(recipe_path.read_bytes()))
            self.assertEqual(readback_value["validator_sha256"], driver.digest_bytes(READER_PATH.read_bytes()))
            self.assertEqual(readback_value["identity"]["host_id"], run_identity["host_id"])
            self.assertEqual(readback_value["identity"]["run_id"], run_identity["run_id"])
            self.assertEqual(readback_value["identity"]["nonce"], run_identity["nonce"])
            self.assertEqual(readback_value["application_process"]["pid"], app_process.pid)
            self.assertEqual(readback_value["application_process"]["start_ticks"], app_stat["start_ticks"])
            self.assertEqual(readback_value["application_process"]["nonce"], run_identity["nonce"])
            self.assertEqual(readback_value["application_process"]["executable_sha256"], driver.digest_bytes(binary_raw))
            application_window = readback_value["application_window"]
            continuous_ready = readback_value["continuous_ready_window"]
            self.assertEqual(
                set(application_window),
                {"observed_start_monotonic_ns", "observed_exit_monotonic_ns"},
            )
            self.assertEqual(set(continuous_ready), {"start_monotonic_ns", "end_monotonic_ns"})
            self.assertGreaterEqual(
                continuous_ready["end_monotonic_ns"],
                application_window["observed_exit_monotonic_ns"],
            )
            self.assertGreater(
                continuous_ready["end_monotonic_ns"], continuous_ready["start_monotonic_ns"]
            )
            process_binding = json.loads((artifacts / "process-binding.json").read_text(encoding="utf-8"))
            self.assertGreaterEqual(
                continuous_ready["start_monotonic_ns"],
                process_binding["pressure_ready_monotonic_ns"],
            )
            pressure_events = [
                json.loads(line) for line in (artifacts / "events.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(
                [event["kind"] for event in pressure_events[:3]],
                ["worker_ownership", "workers_authorized", "pressure_start"],
            )
            ownership_event, authorized_event, pressure_start_event = pressure_events[:3]
            self.assertEqual(ownership_event["nonce"], run_identity["nonce"])
            self.assertEqual(authorized_event["ownership_sha256"], ownership_event["ownership_sha256"])
            self.assertEqual(pressure_start_event["authorization_sha256"], authorized_event["authorization_sha256"])
            self.assertEqual(pressure_start_event["ownership_sha256"], ownership_event["ownership_sha256"])
            self.assertEqual(len(authorized_event["workers"]), len(ownership_event["workers"]))
            sample_events = [event for event in pressure_events if event.get("kind") == "sample"]
            start_samples = [
                sample for sample in sample_events
                if sample["interval_start_monotonic_ns"] == continuous_ready["start_monotonic_ns"]
            ]
            end_samples = [
                sample for sample in sample_events
                if sample["interval_end_monotonic_ns"] == continuous_ready["end_monotonic_ns"]
            ]
            self.assertEqual(len(start_samples), 1)
            self.assertEqual(len(end_samples), 1)
            self.assertTrue(start_samples[0]["readiness"]["all_ready"])
            self.assertTrue(end_samples[0]["readiness"]["all_ready"])
            proof_body = {key: value for key, value in readback_value.items() if key != "readback_sha256"}
            self.assertEqual(readback_value["readback_sha256"], driver.digest_object(proof_body))

            duplicate_pid = root / "duplicate-worker-pid-artifacts"
            shutil.copytree(artifacts, duplicate_pid)
            duplicate_events = []
            for event in pressure_events:
                if event["kind"] == "worker_ownership":
                    event = json.loads(driver.canonical_bytes(event))
                    event["workers"][1]["pid"] = event["workers"][0]["pid"]
                    event["workers"][1]["pgid"] = event["workers"][0]["pid"]
                    event["workers"][1]["session_id"] = event["workers"][0]["pid"]
                    owner_body = {key: value for key, value in event.items() if key != "ownership_sha256"}
                    event["ownership_sha256"] = driver.digest_object(owner_body)
                duplicate_events.append(driver.canonical_bytes(event) + b"\n")
            duplicate_events_raw = b"".join(duplicate_events)
            (duplicate_pid / "events.jsonl").write_bytes(duplicate_events_raw)
            duplicate_run = json.loads((duplicate_pid / "run.json").read_text(encoding="utf-8"))
            duplicate_run["events_sha256"] = driver.digest_bytes(duplicate_events_raw)
            duplicate_run["events_bytes"] = len(duplicate_events_raw)
            duplicate_run_body = {key: value for key, value in duplicate_run.items() if key != "run_sha256"}
            duplicate_run["run_sha256"] = driver.digest_object(duplicate_run_body)
            duplicate_run_raw = driver.canonical_bytes(duplicate_run)
            (duplicate_pid / "run.json").write_bytes(duplicate_run_raw)
            duplicate_rejected = subprocess.run(
                [sys.executable, str(READER_PATH), "verify",
                 "--recipe", str(recipe_path), "--expected-recipe-sha256", frozen["recipe_sha256"],
                 "--artifacts", str(duplicate_pid),
                 "--expected-run-sha256", driver.digest_bytes(duplicate_run_raw),
                 "--expected-events-sha256", driver.digest_bytes(duplicate_events_raw),
                 "--expected-launch-sha256", run_artifacts["launch_record_sha256"],
                 "--expected-process-binding-sha256", run_artifacts["process_binding_sha256"],
                 "--expected-ready-sha256", run_artifacts["readiness_marker_sha256"]],
                cwd="/", stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=20, check=False,
            )
            self.assertNotEqual(duplicate_rejected.returncode, 0, "independent reader accepted a self-resealed duplicate worker PID")
            self.assertIn("duplicates a worker PID", duplicate_rejected.stderr.decode("utf-8", errors="replace"))

            tampered = root / "tampered-artifacts"
            shutil.copytree(artifacts, tampered)
            with (tampered / "events.jsonl").open("ab") as stream:
                stream.write(b" ")
            rejected = subprocess.run(
                [sys.executable, str(READER_PATH), "verify",
                 "--recipe", str(recipe_path), "--expected-recipe-sha256", frozen["recipe_sha256"],
                 "--artifacts", str(tampered),
                 "--expected-run-sha256", run_artifacts["run_sha256"],
                 "--expected-events-sha256", run_artifacts["events_sha256"],
                 "--expected-launch-sha256", run_artifacts["launch_record_sha256"],
                 "--expected-process-binding-sha256", run_artifacts["process_binding_sha256"],
                 "--expected-ready-sha256", run_artifacts["readiness_marker_sha256"]],
                cwd="/", stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=20, check=False,
            )
            self.assertNotEqual(rejected.returncode, 0, "independent reader accepted a changed event stream")

            cap_identity = dict(
                common_identity,
                nonce=uuid.uuid4().hex,
                run_id=f"pressure-run-cap-{uuid.uuid4().hex[:12]}",
            )
            cap_request_value = dict(pressure_request_value, identity=cap_identity)
            cap_request = root / "event-cap-pressure-request.json"
            cap_recipe_path = root / "event-cap-frozen-pressure-recipe.json"
            cap_request.write_bytes(driver.canonical_bytes(cap_request_value))
            cap_freeze = subprocess.run(
                [sys.executable, str(DRIVER_PATH), "freeze", "--request", str(cap_request), "--output", str(cap_recipe_path)],
                cwd="/", stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=20, check=False,
            )
            self.assertEqual(cap_freeze.returncode, 0, cap_freeze.stderr.decode("utf-8", errors="replace"))
            cap_recipe = json.loads(cap_freeze.stdout.decode("utf-8"))
            cap_artifacts = root / "event-cap-run-artifacts"
            cap_wrapper = root / "run-with-injected-sample-cap.py"
            cap_wrapper.write_text(
                """import importlib.util, json, sys
from pathlib import Path
driver_path, recipe_path, recipe_sha, output_path = sys.argv[1:5]
root = Path(output_path)
spec = importlib.util.spec_from_file_location('pressure_cap_driver', driver_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
original = module._write_event_raw
def stop_at_sample(stream, raw, *, maximum_bytes=module.MAX_ARTIFACT_BYTES):
    event = json.loads(raw.decode('ascii'))
    if event.get('kind') == 'sample':
        raise module.PressureError('fixture injected sample event capacity exhaustion')
    return original(stream, raw, maximum_bytes=maximum_bytes)
module._write_event_raw = stop_at_sample
try:
    module.run_pressure(Path(recipe_path), recipe_sha, root / 'launch-record.json', root, root / 'pressure-ready.json')
except module.PressureError as error:
    receipt = json.loads((root / 'run.json').read_text(encoding='utf-8'))
    assert 'fixture injected sample event capacity exhaustion' in str(error)
    assert receipt['status'] == 'failed' and 'fixture injected sample event capacity exhaustion' in receipt['failure']
    assert receipt['cleanup_ok'] is True and receipt['scratch_file_removed'] is True
    assert all(row['alive_after_cleanup'] is False for row in receipt['worker_cleanup'])
    kinds = [json.loads(line)['kind'] for line in (root / 'events.jsonl').read_text(encoding='utf-8').splitlines()]
    assert kinds == ['worker_ownership', 'workers_authorized', 'pressure_start', 'pressure_failure', 'pressure_cleanup']
    print(json.dumps({'status': receipt['status'], 'cleanup_ok': receipt['cleanup_ok'], 'events': kinds}, sort_keys=True))
else:
    raise AssertionError('injected event cap unexpectedly allowed a pressure sample')
""",
                encoding="utf-8",
            )
            cap_run = subprocess.run(
                [sys.executable, str(cap_wrapper), str(DRIVER_PATH), str(cap_recipe_path), cap_recipe["recipe_sha256"], str(cap_artifacts)],
                cwd="/", stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=50, check=False, start_new_session=True,
            )
            self.assertEqual(cap_run.returncode, 0, cap_run.stderr.decode("utf-8", errors="replace"))
            cap_receipt = json.loads((cap_artifacts / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(cap_receipt["status"], "failed")
            self.assertTrue(cap_receipt["cleanup_ok"])
            self.assertTrue(cap_receipt["scratch_file_removed"])
            self.assertTrue((cap_artifacts / "events.jsonl").is_file())

            fault_expectations = {
                "before_owner_journal": [],
                "after_owner_journal": ["worker_ownership"],
                "zero_pre_capture_after_owner_journal": ["worker_ownership"],
                "captured_then_zombie_after_owner_journal": ["worker_ownership"],
                "captured_then_zombie_before_owner_journal": [],
                "after_ack_before_start": ["worker_ownership", "workers_authorized", "pressure_start"],
                "during_work": ["worker_ownership", "workers_authorized", "pressure_start"],
            }
            fault_wrapper = root / "run-pressure-ownership-fault.py"
            fault_wrapper.write_text(
                """import importlib.util, json, os, subprocess, sys, time
from pathlib import Path
driver_path, recipe_path, recipe_sha, launch_path, output_path, ready_path, checkpoint_path, stage = sys.argv[1:9]
spec = importlib.util.spec_from_file_location('pressure_ownership_fault_driver', driver_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
OriginalWorkerSet = module.WorkerSet
def pause(checkpoint):
    value = {'schema': 'allocatbelt.pressure-worker-fault-checkpoint.test.v1', 'stage': stage, 'checkpoint': checkpoint}
    raw = module.canonical_bytes(value)
    descriptor = os.open(checkpoint_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        assert os.write(descriptor, raw) == len(raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    while True:
        time.sleep(0.05)
class FaultWorkerSet(OriginalWorkerSet):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.unrelated_after_driver = None
    def ownership_rows(self):
        if stage in ('before_owner_journal', 'captured_then_zombie_before_owner_journal'):
            pause('workers_ready_before_ownership_fsync')
        return super().ownership_rows()
    def grant_ownership(self, ownership_sha256):
        if stage == 'zero_pre_capture_after_owner_journal':
            # A later isolated zombie is intentionally outside the durable
            # ownership roster. The parent may reap it, but must retain an
            # unknown-inventory failure rather than treating it as a worker.
            self.unrelated_after_driver = subprocess.Popen(
                [sys.executable, '-c', 'pass'], stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        if stage in ('after_owner_journal', 'zero_pre_capture_after_owner_journal', 'captured_then_zombie_after_owner_journal'):
            pause('ownership_fsynced_before_worker_grant')
        return super().grant_ownership(ownership_sha256)
    def begin(self, start_ns, ownership_sha256, authorization_sha256):
        if stage == 'after_ack_before_start':
            pause('all_worker_acks_fsynced_before_work_start_grant')
        super().begin(start_ns, ownership_sha256, authorization_sha256)
        if stage == 'during_work':
            pause('work_start_granted')
module.WorkerSet = FaultWorkerSet
module.run_pressure(Path(recipe_path), recipe_sha, Path(launch_path), Path(output_path), Path(ready_path))
""",
                encoding="utf-8",
            )
            parent_subreaper_previous = soak_supervisor._set_child_subreaper(True)
            try:
                for fault_index, (fault_stage, expected_kinds) in enumerate(fault_expectations.items(), start=1):
                    fault_identity = dict(
                        common_identity,
                        nonce=uuid.uuid4().hex,
                        run_id=f"pressure-run-fault-{fault_index}-{uuid.uuid4().hex[:8]}",
                    )
                    fault_request_value = dict(pressure_request_value, identity=fault_identity)
                    fault_request = root / f"{fault_stage}-pressure-request.json"
                    fault_recipe_path = root / f"{fault_stage}-pressure-recipe.json"
                    fault_request.write_bytes(driver.canonical_bytes(fault_request_value))
                    fault_freeze = subprocess.run(
                        [sys.executable, str(DRIVER_PATH), "freeze", "--request", str(fault_request), "--output", str(fault_recipe_path)],
                        cwd="/", stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        timeout=20, check=False,
                    )
                    self.assertEqual(fault_freeze.returncode, 0, fault_freeze.stderr.decode("utf-8", errors="replace"))
                    fault_recipe_info = json.loads(fault_freeze.stdout.decode("utf-8"))
                    fault_recipe = json.loads(fault_recipe_path.read_text(encoding="utf-8"))
                    fault_artifacts = root / f"{fault_stage}-pressure-artifacts"
                    fault_checkpoint = root / f"{fault_stage}-checkpoint.json"
                    zero_pre_capture = fault_stage == "zero_pre_capture_after_owner_journal"
                    captured_then_zombie = fault_stage == "captured_then_zombie_after_owner_journal"
                    captured_before_journal = fault_stage == "captured_then_zombie_before_owner_journal"
                    unrelated = None
                    if zero_pre_capture:
                        unrelated = subprocess.Popen(
                            [sys.executable, "-c", "import time; time.sleep(10)"],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            start_new_session=True,
                        )
                    fault_process = subprocess.Popen(
                        [
                            sys.executable, str(fault_wrapper), str(DRIVER_PATH), str(fault_recipe_path),
                            fault_recipe_info["recipe_sha256"], str(fault_artifacts / "launch-record.json"),
                            str(fault_artifacts), str(fault_artifacts / "pressure-ready.json"),
                            str(fault_checkpoint), fault_stage,
                        ],
                        cwd="/", stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        start_new_session=True,
                    )
                    fault_start_ticks = soak_supervisor._proc_start_ticks(fault_process.pid)
                    captured: dict[tuple[str, int | None], dict[str, Any]] = {}
                    worker_keys = soak_supervisor._expected_pressure_worker_keys(fault_recipe["schedule"])
                    try:
                        deadline = time.monotonic() + 15
                        while time.monotonic() < deadline and not fault_checkpoint.is_file():
                            if fault_process.poll() is not None:
                                stdout, stderr = fault_process.communicate()
                                self.fail(
                                    f"pressure ownership fault {fault_stage} exited before its checkpoint: "
                                    f"{stderr.decode('utf-8', errors='replace')} {stdout.decode('utf-8', errors='replace')}"
                                )
                            if not zero_pre_capture:
                                soak_supervisor._capture_pressure_worker_sessions(
                                    fault_process.pid, fault_start_ticks, DRIVER_PATH,
                                    fault_recipe_info["recipe_sha256"], fault_recipe["schedule"], captured,
                                    fault_identity["nonce"], ownership_event_path=fault_artifacts / "events.jsonl",
                                )
                            time.sleep(0.02)
                        self.assertTrue(fault_checkpoint.is_file(), f"pressure fault {fault_stage} missed its bounded checkpoint")
                        if zero_pre_capture:
                            self.assertEqual(captured, {}, "zero-pre-capture case recorded a worker before driver death")
                        else:
                            for _ in range(20):
                                soak_supervisor._capture_pressure_worker_sessions(
                                    fault_process.pid, fault_start_ticks, DRIVER_PATH,
                                    fault_recipe_info["recipe_sha256"], fault_recipe["schedule"], captured,
                                    fault_identity["nonce"], ownership_event_path=fault_artifacts / "events.jsonl",
                                )
                                if set(captured) == worker_keys:
                                    break
                                time.sleep(0.02)
                            self.assertEqual(set(captured), worker_keys, f"fault {fault_stage} did not capture every exact spawned worker")
                        checkpoint = json.loads(fault_checkpoint.read_text(encoding="utf-8"))
                        self.assertEqual(checkpoint["stage"], fault_stage)
                        if fault_stage == "during_work":
                            time.sleep(0.8)
                        fault_events_path = fault_artifacts / "events.jsonl"
                        event_kinds = (
                            [json.loads(line)["kind"] for line in fault_events_path.read_text(encoding="utf-8").splitlines()]
                            if fault_events_path.exists() else []
                        )
                        self.assertEqual(event_kinds, expected_kinds)
                        fault_process.kill()
                        fault_process.wait(timeout=5)
                        if zero_pre_capture or captured_then_zombie or captured_before_journal:
                            zombie_deadline = time.monotonic() + 3
                            expected_zombie_count = len(worker_keys) + (1 if zero_pre_capture else 0)
                            while time.monotonic() < zombie_deadline:
                                candidates = [
                                    soak_supervisor._proc_process_identity(pid)
                                    for pid in soak_supervisor._proc_child_pids(os.getpid(), "zero-pre-capture fixture")
                                    if unrelated is None or pid != unrelated.pid
                                ]
                                candidates = [item for item in candidates if item is not None]
                                if len(candidates) == expected_zombie_count and all(item["state"] == "Z" for item in candidates):
                                    break
                                time.sleep(0.02)
                            self.assertEqual(len(candidates), expected_zombie_count)
                            self.assertTrue(all(item["state"] == "Z" for item in candidates), "zero-pre-capture workers did not reach the adopted-zombie state")
                        if captured_before_journal:
                            self.assertEqual(fault_events_path.read_bytes(), b"", "the pre-journal fault unexpectedly emitted an ownership record")
                        soak_supervisor._capture_pressure_worker_sessions(
                            fault_process.pid, fault_start_ticks, DRIVER_PATH,
                            fault_recipe_info["recipe_sha256"], fault_recipe["schedule"], captured,
                            fault_identity["nonce"], ownership_event_path=fault_artifacts / "events.jsonl",
                        )
                        if zero_pre_capture or captured_then_zombie or captured_before_journal:
                            soak_supervisor._capture_pressure_worker_sessions(
                                fault_process.pid, fault_start_ticks, DRIVER_PATH,
                                fault_recipe_info["recipe_sha256"], fault_recipe["schedule"], captured,
                                fault_identity["nonce"], ownership_event_path=fault_artifacts / "events.jsonl",
                            )
                        self.assertTrue(
                            soak_supervisor._cleanup_owned_pressure_workers(
                                captured,
                                fault_recipe["schedule"]["term_deadline_seconds"],
                                fault_recipe["schedule"]["kill_deadline_seconds"],
                            ),
                            f"subreaper could not clean authenticated workers after {fault_stage}",
                        )
                        self.assertTrue(all(record["adopted_by_subreaper"] for record in captured.values()))
                        self.assertTrue(all(record["reaped"] for record in captured.values()))
                        if zero_pre_capture:
                            self.assertEqual(
                                {key for key in captured if key in worker_keys}, worker_keys,
                                "durable ownership roster did not authenticate every orphaned pressure worker",
                            )
                            unknown = [record for record in captured.values() if record.get("unknown_adopted_zombie")]
                            self.assertEqual(len(unknown), 1, "unrelated post-driver zombie was treated as an authenticated worker")
                            self.assertFalse(
                                soak_supervisor._pressure_worker_inventory_complete(captured, fault_recipe["schedule"]),
                                "weakly identified adopted zombie made the worker inventory eligible",
                            )
                            self.assertIsNotNone(unrelated)
                            self.assertIsNone(unrelated.poll(), "zombie fallback signalled an unrelated live child")
                        elif captured_then_zombie:
                            self.assertEqual(set(captured), worker_keys)
                            self.assertFalse(any(record.get("unknown_adopted_zombie") for record in captured.values()))
                            self.assertTrue(
                                soak_supervisor._pressure_worker_inventory_complete(captured, fault_recipe["schedule"]),
                                "exact owner journal identities were lost during live-to-zombie adoption",
                            )
                        elif captured_before_journal:
                            self.assertEqual(set(captured), worker_keys)
                            self.assertFalse(any(record.get("unknown_adopted_zombie") for record in captured.values()))
                            self.assertTrue(
                                soak_supervisor._pressure_worker_inventory_complete(captured, fault_recipe["schedule"]),
                                "prior exact live capture was lost when the ownership journal never appeared",
                            )
                    finally:
                        if fault_process.poll() is None:
                            fault_process.kill()
                            fault_process.wait(timeout=5)
                        try:
                            soak_supervisor._capture_pressure_worker_sessions(
                                fault_process.pid, fault_start_ticks, DRIVER_PATH,
                                fault_recipe_info["recipe_sha256"], fault_recipe["schedule"], captured,
                                fault_identity["nonce"], ownership_event_path=fault_artifacts / "events.jsonl",
                            )
                            if captured:
                                soak_supervisor._cleanup_owned_pressure_workers(
                                    captured,
                                    fault_recipe["schedule"]["term_deadline_seconds"],
                                    fault_recipe["schedule"]["kill_deadline_seconds"],
                                )
                        finally:
                            scratch_path = Path(fault_recipe["storage"]["pressure_scratch_path"]) / f".allocatbelt-pressure-{fault_identity['nonce']}.bin"
                            try:
                                scratch_path.unlink()
                            except FileNotFoundError:
                                pass
                            if unrelated is not None and unrelated.poll() is None:
                                unrelated.send_signal(signal.SIGTERM)
                                unrelated.wait(timeout=3)
                            for pipe in (fault_process.stdout, fault_process.stderr):
                                if pipe is not None and not pipe.closed:
                                    pipe.close()
                print(json.dumps({
                    "status": "pressure-worker-parent-death-fault-tests-passed",
                    "faults": list(fault_expectations),
                    "parent_owned_reaping": True,
                }, sort_keys=True))
            finally:
                soak_supervisor._set_child_subreaper(parent_subreaper_previous)

            evidence_dir = os.environ.get("ALLOCATBELT_PRESSURE_TEST_EVIDENCE_DIR")
            if evidence_dir:
                evidence_path = Path(evidence_dir)
                self.assertTrue(evidence_path.is_absolute(), "evidence destination must be absolute")
                self.assertTrue(evidence_path.parent.is_dir(), "evidence destination parent must exist")
                self.assertFalse(evidence_path.exists() or evidence_path.is_symlink(), "evidence destination already exists")
                shutil.copytree(root, evidence_path)
            else:
                evidence_path = None
            succeeded = True
            print(json.dumps({
                "status": "pressure-driver-readback-tests-passed",
                "recipe_sha256": frozen["recipe_sha256"],
                "calibration_raw_sha256": calibration_receipt["calibration_raw_sha256"],
                "events_sha256": run_artifacts["events_sha256"],
                "readback_sha256": readback_value["readback_sha256"],
                "bounded_synthetic_overlap_seconds": round(readback_value["application_overlap_nanoseconds"] / 1_000_000_000, 3),
                "raw_evidence_path": str(evidence_path) if evidence_path else None,
            }, sort_keys=True))
        finally:
            if app_process is not None and app_process.poll() is None:
                app_process.send_signal(signal.SIGTERM)
                try:
                    app_process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    app_process.kill()
                    app_process.wait(timeout=3)
            if app_process is not None and app_process.stderr is not None and not app_process.stderr.closed:
                app_process.stderr.close()
            if driver_process is not None and driver_process.poll() is None:
                driver_process.send_signal(signal.SIGTERM)
                try:
                    driver_process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    driver_process.kill()
                    driver_process.wait(timeout=4)
            if succeeded:
                shutil.rmtree(root)
            else:
                print(f"pressure test fixture preserved at {root}", file=sys.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
