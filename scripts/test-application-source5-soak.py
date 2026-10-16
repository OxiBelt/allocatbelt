#!/usr/bin/env python3
"""Regression tests for the Source5 one-APP Soak adapter contracts."""
from __future__ import annotations

import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import stat
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SOAK_PATH = ROOT / "scripts/application-source5-soak.py"
CONTROLLER_PATH = ROOT / "scripts/application-source5-campaign.py"
CHRONOLOGY_PATH = ROOT / "scripts/application-campaign-chronology.py"
SOAK_RECIPE_PATH = ROOT / "scripts/application-soak-recipe.py"
SOAK_RECIPE_TEST_PATH = ROOT / "scripts/test-application-soak-recipe.py"


def load_source(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class Source5SoakPublicApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.soak = load_source("source5_soak_adapter_test", SOAK_PATH)
        cls.chronology = load_source(
            "source5_soak_chronology_test", CHRONOLOGY_PATH,
        )
        cls.controller = load_source(
            "source5_soak_controller_test", CONTROLLER_PATH,
        )
        cls.recipe_fixtures = load_source(
            "source5_soak_recipe_fixture_test", SOAK_RECIPE_TEST_PATH,
        )
        cls.readback = load_source(
            "source5_soak_readback_binding_test",
            ROOT / "scripts/application-soak-readback.py",
        )

    def test_original_soak_job_has_one_non_pair_role(self) -> None:
        job = {
            "phase": "soak", "run_id": "campaign-host-mixed-soak-allocatbelt-01",
            "allocator": "allocatbelt", "executor": "bounded",
        }
        self.assertEqual(self.soak.soak_descriptor(job), {
            "role": "original_soak_app",
            "allocator": "allocatbelt",
            "executor": "bounded",
        })

    def test_pressure_predecessor_read_precedes_its_pressure_owner_read(self) -> None:
        host_id = "host-a"
        jobs = {
            "exploration": [{
                "phase": "exploration", "run_id": "explore-0",
                "host_id": host_id, "mode": "closed_loop",
            }],
            "aa": [{
                "phase": "aa", "run_id": "aa-0",
                "host_id": host_id, "mode": "closed_loop",
            }],
            "confirmation": [{
                "phase": "confirmation", "run_id": "confirm-0",
                "host_id": host_id, "mode": "closed_loop",
            }],
            "pressure": [{
                "phase": "pressure", "run_id": f"pressure-{index}",
                "host_id": host_id, "mode": "closed_loop",
                "predecessor_run_ids": ["confirm-0"],
            } for index in range(2)],
            "soak": [{
                "phase": "soak", "run_id": "soak-0",
                "host_id": host_id, "mode": "closed_loop",
            }],
        }
        context = types.SimpleNamespace(
            host_id=host_id, plan={"jobs": jobs},
            manifest={"campaign_id": "campaign"},
        )
        caps = {
            (phase, job["run_id"]): {
                "maximum_request_bytes": 128,
                "maximum_response_bytes": 128,
                "object_count": 1,
                "bundle_bytes": 1024,
            }
            for phase, phase_jobs in jobs.items()
            for job in phase_jobs
        }

        schedule = self.controller._source5_archive_read_schedule(
            context, caps,
        )
        pressure_reads = [
            row for row in schedule
            if row["analysis_phase"] == "pressure_analysis" and
            row["use"] in {"pressure_predecessor", "phase_analysis"}
        ]
        self.assertEqual(len(pressure_reads), 4)
        for index, pressure_job in enumerate(jobs["pressure"]):
            predecessor, owner = pressure_reads[index * 2:index * 2 + 2]
            self.assertEqual(predecessor["use"], "pressure_predecessor")
            self.assertEqual(predecessor["owner_phase"], "confirmation")
            self.assertEqual(
                predecessor["job"]["run_id"],
                pressure_job["predecessor_run_ids"][0],
            )
            self.assertEqual(owner["use"], "phase_analysis")
            self.assertEqual(owner["owner_phase"], "pressure")
            self.assertEqual(owner["job"]["run_id"], pressure_job["run_id"])

    def test_prospective_resource_budget_is_additive_to_exact_material_v1(self) -> None:
        job = {
            "phase": "soak", "run_id": "campaign-host-mixed-soak-allocatbelt-01",
            "campaign_id": "campaign", "host_id": "host",
            "allocator": "allocatbelt", "executor": "bounded",
        }
        pin = lambda path: {
            "path": path, "raw_sha256": "1" * 64,
        }
        module = lambda path: {
            "path": path, "raw_sha256": "2" * 64,
            "mode": "100644", "size": 1024,
        }
        body = {
            "schema": self.soak.SOAK_RESOURCE_BUDGET_SCHEMA,
            "binding": {
                "campaign_id": "campaign", "host_id": "host",
                "job_sha256": self.soak.sha256(self.soak.canonical_bytes(job)),
                "source_manifest": {
                    **pin("/origin/source/source-manifest.json"),
                    "semantic_sha256": "3" * 64,
                },
                "source_tree_sha256": "4" * 64,
                "parent_recipe": pin("/origin/input/recipe.json"),
                "build_receipt": pin("/origin/input/build-receipt.json"),
                "prepared_host_binding_sha256": "5" * 64,
                "observed_host": pin("/origin/input/host-context.json"),
                "monitor_owner": module("scripts/application-fixed-pair.py"),
                "soak_adapter": module("scripts/application-source5-soak.py"),
                "soak_reader": module("scripts/application-soak-readback.py"),
            },
            "layout": {
                "output_root": "/origin/output/run",
                "application_tmpdir": "/origin/tmp/application",
                "pressure_scratch": "/origin/tmp/pressure",
                "probe_capture_root": "/origin/probe/0123456789abcdef0123456789abcdef",
                "probe_tmpdir": "/origin/probe/0123456789abcdef0123456789abcdef/tmp",
                "host_receipt_path": "/origin/receipt/host.json",
            },
            "schedule": {
                "production_seconds": 10_800,
                "application_sample_interval_ms": 100,
                "application_sample_tolerance_ns": 10_000_000,
                "application_sample_count": 108_001,
                "application_wall_timeout_seconds": 11_050,
                "pressure_total_deadline_seconds": 12_000,
                "authorization_effective_timeout_seconds": 13_000,
                "probe_timeout_seconds": 30,
                "resource_monitor_interval_ms": 100,
                "resource_monitor_tolerance_ns": 100_000_000,
            },
            "ceilings": {
                "maximum_output_bytes": 8 * 1024 * 1024 * 1024,
                "maximum_output_inodes": 100_000,
                "maximum_application_tmpdir_bytes": 512 * 1024 * 1024,
                "maximum_application_tmpdir_inodes": 4096,
                "maximum_pressure_scratch_bytes": 512 * 1024 * 1024,
                "maximum_pressure_scratch_inodes": 4096,
                "maximum_probe_output_bytes": 64 * 1024 * 1024,
                "maximum_probe_output_inodes": 16,
                "maximum_probe_tmpdir_bytes": 64 * 1024 * 1024,
                "maximum_probe_tmpdir_inodes": 256,
                "minimum_free_bytes": 1024 * 1024 * 1024,
                "minimum_free_inodes": 1024,
                "durable_receipt_reserve_bytes": 8 * 1024 * 1024,
                "durable_receipt_reserve_inodes": 16,
                "maximum_monitor_stream_bytes": 1024 * 1024 * 1024,
                "maximum_monitor_rows": 1_000_000,
                "maximum_monitor_row_bytes": 2 * 1024 * 1024,
            },
            "artifact_limits": {
                name: 8 * 1024 * 1024
                for name in self.soak.RESOURCE_BUDGET_ARTIFACT_LIMIT_FIELDS
            },
        }
        body["artifact_limits"].update({
            "terminal_stream_bytes": 32 * 1024 * 1024 * 1024,
            "resource_samples_bytes": 96 * 1024 * 1024,
            "pressure_events_bytes": 512 * 1024 * 1024,
            "probe_stdout_bytes": 512 * 1024,
            "probe_stderr_bytes": 64 * 1024,
            "probe_owner_receipt_bytes": 16 * 1024 * 1024,
            "probe_inventory_bytes": 16 * 1024 * 1024,
            "probe_failure_bytes": 64 * 1024,
            "probe_capture_receipt_bytes": 16 * 1024 * 1024,
            "resource_monitor_stream_bytes": 512 * 1024 * 1024,
            "owner_return_receipt_bytes": 2 * 1024 * 1024,
        })
        budget = self.soak.make_resource_budget_document(body)
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-budget-pin-") as temporary:
            budget_path = Path(temporary) / "resource-budget.json"
            budget_raw = self.soak.canonical_bytes(budget)
            budget_path.write_bytes(budget_raw)
            budget_path.chmod(0o600)
            budget_pin = {
                "path": str(budget_path),
                "raw_sha256": self.soak.sha256(budget_raw),
                "semantic_sha256": budget["resource_budget_sha256"],
            }
            common = {
                "campaign_id": "campaign", "host_id": "host", "job": job,
                "parent_recipe_pin": pin("/origin/input/recipe.json"),
                "build_receipt_pin": pin("/origin/input/build-receipt.json"),
                "prepared_host_binding_sha256": "5" * 64,
            }
            legacy = self.soak.make_material_index(**common)
            bounded = self.soak.make_material_index(
                **common, resource_budget_pin=budget_pin,
            )
            self.assertEqual(legacy["schema"], self.soak.MATERIALS_INDEX_SCHEMA)
            self.assertEqual(set(legacy), {
                "schema", "campaign_id", "host_id", "job", "job_sha256",
                "parent_recipe", "build_receipt",
                "prepared_host_binding_sha256", "materials_sha256",
            })
            self.assertEqual(bounded["schema"], self.soak.MATERIALS_INDEX_SCHEMA_V2)
            self.assertEqual(bounded["resource_budget"], budget_pin)
            self.assertEqual(
                self.soak.validate_material_index(
                    legacy, "campaign", "host", job, "5" * 64,
                ), legacy,
            )
            self.assertEqual(
                self.soak.validate_material_index(
                    bounded, "campaign", "host", job, "5" * 64,
                ), bounded,
            )
            with self.assertRaises(self.soak.Source5SoakError):
                self.soak.validate_material_index(
                    {**bounded, "resource_budget": {
                        **budget_pin, "semantic_sha256": "f" * 64,
                    }}, "campaign", "host", job, "5" * 64,
                )
        bad_schedule = dict(body["schedule"], application_sample_count=108_000)
        with self.assertRaises(self.soak.Source5SoakError):
            self.soak.make_resource_budget_document({**body, "schedule": bad_schedule})

    def test_probe_capture_phase_advances_from_preflight_before_owner(self) -> None:
        class OrderedMonitor:
            def __init__(self) -> None:
                self.order = self_test.soak.RESOURCE_MONITOR_PHASES
                self.phases: list[str] = []
                self.failure = None

            def sample(self, phase: str, *, force: bool = False) -> bool:
                if self.phases:
                    self_test.assertGreaterEqual(
                        self.order.index(phase),
                        self.order.index(self.phases[-1]),
                    )
                self.phases.append(phase)
                return False

        self_test = self
        monitor = OrderedMonitor()
        budget = {
            "schedule": {"resource_monitor_interval_ms": 60_000},
            "layout": {"probe_capture_root": "/tmp/probe/capture"},
        }

        def fake_probe_capture(*args, **kwargs):
            owner_monitor = kwargs["resource_monitor"]
            self.assertFalse(owner_monitor())
            self.assertFalse(owner_monitor())
            return ({"capture": True}, {"path": "/tmp/probe/capture/receipt.json",
                                        "raw_sha256": "a" * 64}, {})

        with mock.patch.object(
            self.soak, "_capture_source5_soak_probe", side_effect=fake_probe_capture,
        ):
            self.soak._capture_source5_soak_probe_monitored(
                {}, {}, {}, {}, object(), budget, monitor,
            )
        monitor.sample("preflight_audit", force=True)
        self.assertEqual(monitor.phases, [
            "preflight", "probe_capture", "probe_capture", "probe_capture",
            "preflight_audit",
        ])

    def test_prepare_source5_soak_reaches_sentinel_preflight_without_unbound_local(self) -> None:
        class SentinelBoundaryReached(Exception):
            pass

        with tempfile.TemporaryDirectory(prefix="source5-prepare-sentinel-") as temp:
            output = Path(temp) / "output"
            output.mkdir(mode=0o700)
            job = {
                "phase": "soak", "run_id": "sentinel-run",
                "campaign_id": "campaign", "host_id": "host",
                "allocator": "allocatbelt", "executor": "bounded",
            }
            binding = {"binding_sha256": "b" * 64}
            recipe_pin = {
                "path": str(Path(temp) / "recipe.json"),
                "raw_sha256": "c" * 64,
            }
            build_pin = {
                "path": str(Path(temp) / "build-receipt.json"),
                "raw_sha256": "d" * 64,
            }
            material_index = {
                "schema": self.soak.MATERIALS_INDEX_SCHEMA,
                "job": job, "parent_recipe": recipe_pin,
                "build_receipt": build_pin,
            }
            identities = {
                "prepared_host_binding_sha256": binding["binding_sha256"],
                "recipe_sha256": recipe_pin["raw_sha256"],
            }
            recipe = {"runtime": {"mode": "functional", "duration_seconds": 1}}
            audit = {
                "recipe": {"schema": self.soak.RECIPE_SCHEMA},
                "identity": {"run_id": job["run_id"]},
                "launch_enabled": False,
                "mode": "functional", "duration_seconds": 1,
            }
            sentinel_preflight = {"sentinel": "captured-reader-preflight"}
            report = {"schema": "sentinel-preflight-report"}

            class ReadbackBoundary:
                def __init__(self) -> None:
                    self.command_preflight = mock.Mock()
                    self._current_audit = mock.Mock(
                        return_value=(audit, sentinel_preflight),
                    )
                    self._preflight_report = mock.Mock(return_value=report)

            readback = ReadbackBoundary()

            def write_sentinel_preflight(_args) -> int:
                (output / "soak-preflight.json").write_bytes(
                    self.soak.canonical_bytes(report),
                )
                return 0

            readback.command_preflight.side_effect = write_sentinel_preflight
            helper_input = {
                "payload": {
                    "materials_index": {
                        "path": str(Path(temp) / "materials-index.json"),
                        "raw_sha256": "a" * 64,
                    },
                    "output_root": str(output),
                    "prepared_host_binding_sha256": binding["binding_sha256"],
                },
            }
            prepared = {
                "source5_prepared_input_completion": {"sentinel": True},
                "host_id": "host",
            }
            details = {
                "job": job,
                "members": [self.soak.soak_descriptor(job)],
                "output_root": str(output),
            }
            args = types.SimpleNamespace(recipe_sha256=recipe_pin["raw_sha256"])
            with mock.patch.object(
                self.soak, "read_json",
                return_value=(material_index, b"{}", "a" * 64),
            ), mock.patch.object(
                self.soak, "_selected_prepared_host_binding",
                return_value=binding,
            ), mock.patch.object(
                self.soak, "_verify_build_receipt",
                return_value=(material_index, recipe, identities),
            ), mock.patch.object(
                self.soak, "_readback_args", return_value=args,
            ), mock.patch.object(
                self.soak, "build_source5_launch_overlay",
                side_effect=SentinelBoundaryReached("sentinel overlay stop"),
            ) as overlay_boundary:
                with self.assertRaisesRegex(
                    SentinelBoundaryReached, "sentinel overlay stop",
                ):
                    self.soak.prepare_source5_soak(
                        helper_input, prepared, details, readback,
                    )

            self.assertTrue((output / "soak-preflight.json").is_file())
            readback.command_preflight.assert_called_once()
            readback._current_audit.assert_called_once()
            overlay_boundary.assert_called_once()
            self.assertIs(overlay_boundary.call_args.args[9], sentinel_preflight)
            self.assertFalse((output / "source5-soak-launch-authorization.json").exists())

    def test_bounded_run_retains_and_finalizes_preflight_monitor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-run-monitor-") as temp:
            output = Path(temp) / "output"
            output.mkdir(mode=0o700)
            budget_pin = {
                "path": str(Path(temp) / "budget.json"),
                "raw_sha256": "a" * 64, "semantic_sha256": "b" * 64,
            }
            stream_pin = {
                "path": str(output / "source5-soak-resource-monitor.jsonl"),
                "raw_sha256": "c" * 64,
            }

            class HeldMonitor:
                def __init__(self) -> None:
                    self.fd = 41
                    self.budget_pin = budget_pin
                    self.last_usage = {"domains": {}, "devices": {}}
                    self.final_summary = None
                    self.phases: list[str] = []
                    self.finish_calls = 0

                def sample(self, phase: str, *, force: bool = False) -> bool:
                    self.phases.append(phase)
                    return False

                def finish(self, usage):
                    self.finish_calls += 1
                    self.fd = None
                    self.final_summary = {
                        "schema": "allocatbelt.application-source5-soak-resource-monitor-summary.v1",
                        "budget": budget_pin, "stream": stream_pin,
                        "row_count": 4, "high_water": {}, "final_usage": {},
                        "failure": None, "prefix_sha256": "d" * 64,
                    }
                    return self.final_summary

            monitor = HeldMonitor()
            job = {
                "phase": "soak", "run_id": "run", "campaign_id": "campaign",
                "host_id": "host", "allocator": "allocatbelt",
                "executor": "bounded",
            }
            argv = ["/pinned/app"]
            environment_sha = "e" * 64
            binary_sha = "f" * 64
            process = {
                "pid": 321, "start_ticks": 654,
                "executable_path": "/pinned/app",
                "executable_sha256": binary_sha,
                "executable_device": 1, "executable_inode": 2,
                "executable_size": 3, "executable_fd_reference": 4,
                "cwd": "/pinned", "argv": argv,
                "argv_sha256": "1" * 64, "cmdline_raw_sha256": "2" * 64,
                "environment_sha256": environment_sha,
                "environment_raw_sha256": "3" * 64,
            }
            attestation_body = {
                "schema": "allocatbelt.application-pressure-app-launch-attestation.v1",
                "process": process,
            }
            attestation = {
                **attestation_body,
                "attestation_sha256": self.soak.sha256(
                    self.soak.canonical_bytes(attestation_body),
                ),
            }
            cleanup = {
                "schema": "allocatbelt.application-soak-process-cleanup.v1",
                "status": "verified", "pid": process["pid"],
                "return_code": 1, "received_signal": None,
                "cleanup_error": None,
            }
            details = {
                "status": 1, "timed_out": False,
                "artifact_budget_exceeded": False,
            }
            launch_calls = []

            class FakeReadback:
                def launch_soak_v2_application(
                    _self, _args, _audit, _preflight, _output,
                    on_started, on_cleanup, **kwargs,
                ):
                    launch_calls.append(kwargs)
                    on_started(attestation)
                    on_cleanup(cleanup)
                    return {
                        "schema": "allocatbelt.application-pressure-supervision.v1",
                        "execution_kind": "timed_soak", "status": 1,
                        "interrupted": False, "received_signal": None,
                        "application_cleanup": cleanup,
                        "application_binding": {},
                        "application_binding_sha256": "4" * 64,
                        "application_attestation": attestation,
                        "pressure_ready_sha256": "5" * 64,
                        "pressure_proof": {}, "pressure_cleanup": "verified",
                        "pressure_driver": {}, "pressure_worker_sessions": [],
                        "details": details,
                    }

            descriptor = {
                "argv": argv, "environment_sha256": environment_sha,
            }
            preflight = {
                "schema": "allocatbelt.application-source5-soak-preflight.v2",
                "materials_index": {"job": job},
                "materials_index_pin": {"path": "/input/index", "raw_sha256": "6" * 64},
                "helper_input": {},
                "parent_recipe": {
                    "identity": {
                        "campaign_id": "campaign", "host_id": "host",
                        "run_id": "run", "binary_sha256": binary_sha,
                    },
                },
                "parent_recipe_pin": {"path": "/input/recipe", "raw_sha256": "7" * 64},
                "build_receipt_pin": {"path": "/input/build", "raw_sha256": "8" * 64},
                "identities": {"prepared_host_binding_sha256": "9" * 64},
                "audit": {"launch_descriptor": descriptor},
                "preflight": {},
                "preflight_pin": {"path": "/output/preflight", "raw_sha256": "a" * 64},
                "launch_overlay": {},
                "launch_overlay_pin": {"path": "/output/overlay", "raw_sha256": "b" * 64},
                "base_audit": {}, "base_audit_sha256": "c" * 64,
                "args": object(), "output_dir": output,
                "readback_module": FakeReadback(), "prepared": {}, "details": {},
                "resource_budget": {
                    "artifact_limits": {"source5_supervisor_bytes": 1024 * 1024},
                },
                "resource_budget_pin": budget_pin,
                "probe_capture": {},
                "probe_capture_pin": {"path": "/probe/receipt", "raw_sha256": "d" * 64},
                "probe_capture_context": {}, "initial_resource_usage": {},
                "resource_monitor": monitor,
            }
            events = []
            component = self.soak.run_source5_soak(
                preflight, events.append, events.append,
            )
            self.assertEqual(len(launch_calls), 1)
            self.assertIs(launch_calls[0]["resource_monitor_context"], monitor)
            self.assertEqual(monitor.finish_calls, 1)
            self.assertIsNone(monitor.fd)
            self.assertEqual(component["schema"], self.soak.COMPONENT_SCHEMA_V2)
            self.assertIs(component["resource_monitor"], monitor.final_summary)
            self.assertEqual(component["pins"]["resource_monitor"], stream_pin)
            self.assertFalse(component["validated"])
            self.assertFalse(component["passed"])

    def test_offline_path_map_is_closed_sorted_and_identity_only(self) -> None:
        valid = {
            "schema": self.soak.EVIDENCE_PATH_MAP_SCHEMA,
            "entries": [
                {"origin": "/origin", "local": "/origin"},
                {"origin": "/origin/input", "local": "/origin/input"},
            ],
        }
        self.assertEqual(self.soak._validate_evidence_path_map(valid), {
            "/origin": "/origin", "/origin/input": "/origin/input",
        })
        bad_maps = (
            {**valid, "entries": list(reversed(valid["entries"]))},
            {**valid, "entries": [
                {"origin": "/origin/input", "local": "/copy/input"},
            ]},
            {**valid, "entries": valid["entries"] + [valid["entries"][0]]},
        )
        for mapping in bad_maps:
            with self.subTest(mapping=mapping), self.assertRaises(self.soak.Source5SoakError):
                self.soak._validate_evidence_path_map(mapping)

    def test_captured_evidence_inventory_reads_archived_output_without_origin_stat(self) -> None:
        class CapturedView:
            def __init__(self, raw_by_origin: dict[str, bytes]):
                self.raw_by_origin = raw_by_origin

            def has_file(self, path: str | Path) -> bool:
                return str(path) in self.raw_by_origin

            def read(self, path: str | Path, _label: str, maximum: int):
                raw = self.raw_by_origin[str(path)]
                if len(raw) > maximum:
                    raise ValueError("test capture exceeded parser cap")
                return raw, hashlib.sha256(raw).hexdigest()

            def open_snapshot(self, path: str | Path, _label: str, maximum: int):
                raw = self.raw_by_origin[str(path)]
                if len(raw) > maximum:
                    raise ValueError("test capture exceeded parser cap")

                @contextlib.contextmanager
                def snapshot():
                    yield io.BytesIO(raw), hashlib.sha256(raw).hexdigest(), len(raw)

                return snapshot()

        with tempfile.TemporaryDirectory(prefix="allocatbelt-captured-inventory-") as directory:
            base = Path(directory).resolve()
            source_root = base / "resident-source"
            input_root = base / "resident-input"
            source_root.mkdir(mode=0o700)
            input_root.mkdir(mode=0o700)
            output_root = base / "reclaimed-output"
            probe_root = base / "reclaimed-probe"
            captured_output = output_root / "soak-launch.json"
            owner_receipt = base / "reclaimed-host-receipt.json"
            output_raw = b"archived Soak launch receipt\n"
            mode = lambda path: f"{stat.S_IMODE(path.stat().st_mode):04o}"
            entries = [
                {"path": str(source_root), "kind": "directory", "mode": mode(source_root)},
                {"path": str(input_root), "kind": "directory", "mode": mode(input_root)},
                {"path": str(output_root), "kind": "directory", "mode": "0700"},
                {"path": str(probe_root), "kind": "directory", "mode": "0700"},
                {"path": str(captured_output), "kind": "file", "mode": "0600",
                 "size": len(output_raw), "raw_sha256": self.soak.sha256(output_raw)},
            ]
            entries.sort(key=lambda entry: entry["path"])
            receipt = {
                "schema": self.soak.HOST_VERIFICATION_SCHEMA,
                "tree_roots": {
                    "source": str(source_root), "input": str(input_root),
                    "output": str(output_root), "probe_capture": str(probe_root),
                },
                "evidence_inventory": entries,
                "evidence_bases": sorted([str(source_root), str(input_root)]),
                "construction_probe": {"schema": self.soak.PROBE_CAPTURE_SCHEMA},
            }
            captured = CapturedView({
                str(captured_output): output_raw,
                str(owner_receipt): b"host receipt is separately verified by the caller\n",
            })
            self.soak._verify_evidence_inventory(
                receipt, None, artifact_view=captured,
                tree_inventories=[],
                captured_origin_paths=sorted(captured.raw_by_origin),
                evidence_file_paths=[str(captured_output)],
                evidence_directory_paths=sorted({
                    str(source_root), str(input_root), str(output_root), str(probe_root),
                }),
                source_root=source_root, input_root=input_root,
                output_root=output_root, probe_capture_root=probe_root,
                host_receipt_path=str(owner_receipt),
                readback=self.readback,
            )
            self.assertFalse(output_root.exists())
            self.assertFalse(probe_root.exists())

    def test_soak_origin_json_preserves_live_and_captured_raw_pin_contract(self) -> None:
        value = {"schema": "allocatbelt.test-soak-origin-json.v1", "count": 3}
        raw = self.soak.canonical_bytes(value)
        raw_sha = self.soak.sha256(raw)
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-origin-json-") as temporary:
            path = Path(temporary) / "resident.json"
            path.write_bytes(raw)
            os.chmod(path, 0o600)
            live = self.soak._read_soak_origin_json(
                path, raw_sha, "resident Soak fixture", 1024,
                self.readback, None, frozenset(),
            )
            self.assertEqual(live, (value, raw, raw_sha))
            with self.assertRaisesRegex(
                self.soak.Source5SoakError,
                "resident Soak fixture differs from its raw pin",
            ):
                self.soak._read_soak_origin_json(
                    path, "f" * 64, "resident Soak fixture", 1024,
                    self.readback, None, frozenset(),
                )

            archived_path = Path(temporary) / "reclaimed.json"
            stage_root = Path(temporary) / "stage"
            stage_root.mkdir(mode=0o700)
            staged_file = stage_root / "object-00.bin"
            staged_file.write_bytes(raw)
            os.chmod(staged_file, 0o400)
            archived = self.readback.CapturedSoakArtifactView(
                stage_root,
                {str(archived_path): {
                    "origin_path": str(archived_path),
                    "path": str(staged_file),
                    "role": "source5_soak_artifact",
                    "host_id": "host-a",
                    "raw_sha256": raw_sha,
                    "semantic_sha256": None,
                    "byte_count": len(raw),
                    "maximum_bytes": len(raw),
                }},
            )
            inspected: list[str] = []
            original_lstat = Path.lstat

            def track_lstat(path: Path, *args, **kwargs):
                inspected.append(str(path))
                if str(path) == str(archived_path):
                    raise AssertionError("captured Soak readback stat-ed its reclaimed origin")
                return original_lstat(path, *args, **kwargs)

            with mock.patch.object(Path, "lstat", track_lstat):
                replay = self.soak._read_soak_origin_json(
                    archived_path, raw_sha, "captured Soak fixture", 1024,
                    self.readback, archived, frozenset({str(archived_path)}),
                    required_capture=True,
                )
            self.assertEqual(replay, (value, raw, raw_sha))
            self.assertNotIn(str(archived_path), inspected)
            self.assertFalse(archived_path.exists())

    def test_captured_soak_view_requires_0400_dirfd_stage_and_rejects_root_replacement(self) -> None:
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-captured-dirfd-") as temporary:
            root = Path(temporary).resolve()
            stage_root = root / "stage"
            stage_root.mkdir(mode=0o700)
            origin = root / "reclaimed-soak-output.json"
            raw = self.soak.canonical_bytes({"schema": "fixture", "value": 4})
            local = stage_root / "object-00.bin"
            local.write_bytes(raw)
            os.chmod(local, 0o400)
            reference = {
                "origin_path": str(origin), "path": str(local),
                "role": "source5_soak_artifact", "host_id": "host-a",
                "raw_sha256": self.soak.sha256(raw), "semantic_sha256": None,
                "byte_count": len(raw), "maximum_bytes": len(raw),
            }
            view = self.readback.CapturedSoakArtifactView(
                stage_root, {str(origin): reference},
            )
            with view.open_snapshot(origin, "Soak staged output", len(raw)) as (
                    stream, actual_sha, byte_count):
                self.assertEqual(stream.read(), raw)
                self.assertEqual(actual_sha, reference["raw_sha256"])
                self.assertEqual(byte_count, len(raw))

            hardlink = root / "outside-hardlink.bin"
            os.link(local, hardlink)
            with self.assertRaisesRegex(
                    self.readback.SoakReadbackError,
                    "mode-0400 regular file",
            ):
                view.read(origin, "Soak hardlinked output", len(raw))
            hardlink.unlink()

            moved_root = root / "stage-renamed"
            stage_root.rename(moved_root)
            stage_root.symlink_to(moved_root.name, target_is_directory=True)
            with self.assertRaisesRegex(
                    self.readback.SoakReadbackError,
                    "cannot safely open or verify captured Soak staged output",
            ):
                view.read(origin, "Soak staged output", len(raw))

    def test_captured_soak_view_rejects_a_symlink_stage_member(self) -> None:
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-captured-symlink-") as temporary:
            root = Path(temporary).resolve()
            stage_root = root / "stage"
            stage_root.mkdir(mode=0o700)
            origin = root / "reclaimed-soak-output.json"
            raw = self.soak.canonical_bytes({"schema": "fixture", "value": 5})
            target = stage_root / "object-real.bin"
            target.write_bytes(raw)
            os.chmod(target, 0o400)
            symlink = stage_root / "object-00.bin"
            symlink.symlink_to(target.name)
            view = self.readback.CapturedSoakArtifactView(
                stage_root, {str(origin): {
                    "origin_path": str(origin), "path": str(symlink),
                    "role": "source5_soak_artifact", "host_id": "host-a",
                    "raw_sha256": self.soak.sha256(raw),
                    "semantic_sha256": None, "byte_count": len(raw),
                    "maximum_bytes": len(raw),
                }},
            )
            with self.assertRaisesRegex(
                    self.readback.SoakReadbackError,
                    "cannot safely open or verify captured Soak symlink member",
            ):
                view.read(origin, "Soak symlink member", len(raw))

    def test_typed_source_inventory_closes_declared_parent_directories_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="allocatbelt-soak-source-map-") as temporary:
            root = Path(temporary).resolve()
            declared = root / "scripts" / "captured.py"
            declared.parent.mkdir()
            declared.write_bytes(b"captured source bytes\n")
            unrelated = root / ".git" / "config.json"
            unrelated.parent.mkdir()
            unrelated.write_text("not part of the declared source inventory\n")
            source_bytes = declared.read_bytes()
            manifest = {
                "source": {
                    "files": [{
                        "path": "scripts/captured.py", "kind": "file",
                        "mode": "100644",
                        "sha256": self.soak.sha256(source_bytes),
                        "size": len(source_bytes),
                    }],
                },
            }

            entries = self.soak._typed_source_inventory(root, manifest)
            paths = {entry["path"] for entry in entries}
            self.assertEqual(paths, {
                str(root), str(root / "scripts"), str(declared),
            })
            self.assertNotIn(str(unrelated), paths)

    def test_public_offline_replay_rejects_missing_receipt_path_before_reads(self) -> None:
        prepared = {
            "source_root": "/origin/source",
            "prepared": {"spec_path": Path("/origin/input/spec.json")},
        }
        component = {
            "pins": {"supervisor": {"path": "/origin/output/source5-soak-supervisor.json"}},
        }
        mapping = {
            "schema": self.soak.EVIDENCE_PATH_MAP_SCHEMA,
            "entries": [
                {"origin": "/origin", "local": "/origin"},
                {"origin": "/origin/input", "local": "/origin/input"},
                {"origin": "/origin/output", "local": "/origin/output"},
                {"origin": "/origin/source", "local": "/origin/source"},
            ],
        }
        with mock.patch.object(
            self.soak, "read_stable",
            side_effect=AssertionError("offline boundary read before path-map closure"),
        ) as read_stable:
            with self.assertRaisesRegex(
                self.soak.Source5SoakError, "omits top-level Source5 Soak replay path",
            ):
                self.soak.verify_source5_soak_component_offline(
                    component, prepared, {}, {},
                    {"path": "/origin/receipt/host.json", "raw_sha256": "a" * 64,
                     "receipt_sha256": "b" * 64},
                    replay_context={
                        "schema": self.soak.SOAK_OFFLINE_CONTEXT_SCHEMA,
                        "evidence_path_map": mapping,
                    },
                )
            read_stable.assert_not_called()

    def test_material_index_binds_raw_recipe_receipt_and_prepared_host(self) -> None:
        job = {
            "phase": "soak", "run_id": "campaign-host-mixed-soak-allocatbelt-01",
            "allocator": "allocatbelt", "executor": "bounded",
            "workload": "mixed", "profile": "mixed", "ordinal": 1,
            "comparison_family": "external_pressure",
        }
        binding_sha = "a" * 64
        value = self.soak.make_material_index(
            "campaign", "host", job,
            {"path": "/private/recipe.json", "raw_sha256": "b" * 64},
            {"path": "/private/build-receipt.json", "raw_sha256": "c" * 64},
            binding_sha,
        )
        self.assertEqual(self.soak.validate_material_index(
            value, "campaign", "host", job, binding_sha,
        ), value)
        changed = {**value, "host_id": "other"}
        with self.assertRaises(self.soak.Source5SoakError):
            self.soak.validate_material_index(
                changed, "campaign", "host", job, binding_sha,
            )
        extra = {**value, "launch_enabled": True}
        with self.assertRaises(self.soak.Source5SoakError):
            self.soak.validate_material_index(
                extra, "campaign", "host", job, binding_sha,
            )

    def test_pressure_binding_uses_pressure_semantic_not_either_raw_digest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="allocatbelt-pressure-hash-roles-") as temporary:
            root = Path(temporary)
            parent_path = root / "parent-soak-recipe.json"
            pressure_path = root / "pressure-recipe.json"
            parent_path.write_bytes(self.soak.canonical_bytes({"parent": "soak"}))
            pressure_body = {"schema": "pressure-hash-role-fixture.v1"}
            pressure_semantic_sha256 = self.soak.sha256(
                self.soak.canonical_bytes(pressure_body),
            )
            pressure_value = {
                **pressure_body, "recipe_sha256": pressure_semantic_sha256,
            }
            pressure_path.write_bytes(self.soak.canonical_bytes(pressure_value))
            parent_raw_sha256 = self.soak.sha256(parent_path.read_bytes())
            pressure_raw_sha256 = self.soak.sha256(pressure_path.read_bytes())
            self.assertEqual(
                len({parent_raw_sha256, pressure_raw_sha256,
                     pressure_semantic_sha256}),
                3,
            )
            parent_pin = {
                "path": str(parent_path), "raw_sha256": parent_raw_sha256,
            }
            pressure_pin = {
                "path": str(pressure_path),
                "raw_sha256": pressure_raw_sha256,
                "semantic_sha256": pressure_semantic_sha256,
            }
            pressure_validator_result = {
                "raw_sha256": pressure_raw_sha256,
                "recipe_sha256": pressure_semantic_sha256,
            }
            nonce = "0123456789abcdef0123456789abcdef"
            app_environment = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "TMPDIR": str(root),
                "ALLOCATBELT_APP_PRESSURE_NONCE": nonce,
            }
            child = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(10)"],
                cwd=root, env=app_environment, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            try:
                pid = child.pid
                executable_path = Path(f"/proc/{pid}/exe").resolve(strict=True)
                executable_sha256 = self.soak.read_stable(
                    executable_path, "test APP executable", self.soak.MAX_ARTIFACT_BYTES,
                )[1]
                cwd = Path(f"/proc/{pid}/cwd").resolve(strict=True)
                cpu_affinity = sorted(os.sched_getaffinity(pid))
                network_namespace_inode = os.stat(f"/proc/{pid}/ns/net").st_ino
                pressure_recipe = {
                    "recipe_sha256": pressure_semantic_sha256,
                    "identity": {"nonce": nonce},
                    "files": {"application_binary": {
                        "raw_sha256": executable_sha256,
                    }},
                    "storage": {"application_io_paths": [str(cwd)]},
                    "schedule": {"application_cpu_affinity": cpu_affinity},
                    "process": {"application_tmpdir_path": str(root)},
                    "network": {
                        "network_namespace_inode": network_namespace_inode,
                    },
                }
                binding = self.readback._make_pressure_launch_binding(
                    child, executable_path, executable_sha256,
                    set(cpu_affinity), cwd, app_environment, pressure_recipe,
                )
            finally:
                child.terminate()
                child.wait(timeout=5)

            # The accepted constructor places the pressure recipe semantic
            # digest in `recipe_sha256`; the Source5 reader independently
            # checks both raw files and the parent-recipe raw identity.
            roles = self.soak._validate_pressure_binding_recipe_roles(
                binding["recipe_sha256"], parent_pin, parent_raw_sha256,
                pressure_pin, pressure_validator_result,
            )
            self.assertEqual(roles, {
                "parent_recipe_raw_sha256": parent_raw_sha256,
                "pressure_recipe_raw_sha256": pressure_raw_sha256,
                "pressure_recipe_semantic_sha256": pressure_semantic_sha256,
            })

            for wrong_binding_sha256 in (
                parent_raw_sha256, pressure_raw_sha256,
            ):
                with self.subTest(binding_sha256=wrong_binding_sha256):
                    wrong_binding = {
                        **binding, "recipe_sha256": wrong_binding_sha256,
                    }
                    with self.assertRaises(self.soak.Source5SoakError):
                        self.soak._validate_pressure_binding_recipe_roles(
                            wrong_binding["recipe_sha256"], parent_pin,
                            parent_raw_sha256, pressure_pin,
                            pressure_validator_result,
                        )

            with self.assertRaises(self.soak.Source5SoakError):
                self.soak._validate_pressure_binding_recipe_roles(
                    binding["recipe_sha256"], parent_pin,
                    pressure_raw_sha256, pressure_pin,
                    pressure_validator_result,
                )
            wrong_pressure_raw_pin = {
                **pressure_pin, "raw_sha256": parent_raw_sha256,
            }
            with self.assertRaises(self.soak.Source5SoakError):
                self.soak._validate_pressure_binding_recipe_roles(
                    binding["recipe_sha256"], parent_pin,
                    parent_raw_sha256, wrong_pressure_raw_pin,
                    pressure_validator_result,
                )
            for substituted_semantic in (parent_raw_sha256,
                                         pressure_raw_sha256):
                with self.subTest(semantic_sha256=substituted_semantic):
                    wrong_pressure_pin = {
                        **pressure_pin,
                        "semantic_sha256": substituted_semantic,
                    }
                    with self.assertRaises(self.soak.Source5SoakError):
                        self.soak._validate_pressure_binding_recipe_roles(
                            binding["recipe_sha256"], parent_pin,
                            parent_raw_sha256, wrong_pressure_pin,
                            pressure_validator_result,
                        )

    def test_signal_cleanup_keeps_negative_raw_code_and_normalizes_status(self) -> None:
        cleanup = {
            "schema": "allocatbelt.application-soak-process-cleanup.v1",
            "status": "verified", "pid": 321, "return_code": -15,
            "received_signal": None, "cleanup_error": None,
        }
        status, signal_number = self.soak.normalize_cleanup_status(cleanup)
        self.assertEqual(status, 143)
        self.assertEqual(signal_number, 15)
        self.assertEqual(cleanup["return_code"], -15)

    def test_missing_child_status_is_a_normalized_launch_failure(self) -> None:
        cleanup = {
            "schema": "allocatbelt.application-soak-process-cleanup.v1",
            "status": "failed", "pid": 322, "return_code": None,
            "received_signal": None, "cleanup_error": "wait status unavailable",
        }
        self.assertEqual(self.soak.normalize_cleanup_status(cleanup), (125, None))

    def test_chronology_accepts_one_clean_original_soak_lifecycle(self) -> None:
        chronology = self.chronology
        descriptor = {
            "role": "original_soak_app", "allocator": "allocatbelt",
            "executor": "bounded",
        }
        authorization_id = "source5-original-soak"
        state = chronology._empty_journal({})
        state["source5_authorized"][authorization_id] = {
            "details": {
                "phase": "soak",
                "job": {"run_id": "campaign-host-mixed-soak-allocatbelt-01"},
                "members": [descriptor],
            },
            "authorization_head": "a" * 64,
            "starts": [{
                "descriptor": descriptor, "pid": 456, "start_ticks": 789,
                "event_head": "b" * 64,
            }],
            "terminals": [{
                "status": 0,
                "cleanup": {
                    "status": "verified",
                    "application_cleanup": {"status": "verified"},
                },
                "event_head": "c" * 64,
            }],
        }
        state["source5_pending"] = authorization_id
        terminal = {
            "authorization_id": authorization_id,
            "state": "valid_soak", "blocked_reason": None,
            "component_sha256": "d" * 64,
            "process_metrics_sha256": "e" * 64,
            "started_count": 1, "terminal_count": 1,
            "qualification_eligible": False,
        }
        chronology._check_event_semantics(
            state, "source5_job_terminal", terminal, "f" * 64, {},
            replay=True, apply=True,
        )
        self.assertEqual(
            state["source5_finished"][(
                "soak", "campaign-host-mixed-soak-allocatbelt-01",
            )]["state"],
            "valid_soak",
        )

    def test_incomplete_soak_terminal_consumes_and_blocks_original_ordinal(self) -> None:
        chronology = self.chronology
        descriptor = {
            "role": "original_soak_app", "allocator": "allocatbelt",
            "executor": "bounded",
        }
        authorization_id = "source5-incomplete-soak"
        state = chronology._empty_journal({})
        state["source5_authorized"][authorization_id] = {
            "details": {
                "phase": "soak",
                "job": {"run_id": "campaign-host-mixed-soak-allocatbelt-01"},
                "members": [descriptor],
            },
            "authorization_head": "a" * 64,
            "starts": [], "terminals": [],
        }
        state["source5_pending"] = authorization_id
        terminal = {
            "authorization_id": authorization_id,
            "state": "blocked", "blocked_reason": "incomplete_app_lifecycle",
            "component_sha256": "b" * 64,
            "process_metrics_sha256": "c" * 64,
            "started_count": 0, "terminal_count": 0,
            "qualification_eligible": False,
        }
        chronology._check_event_semantics(
            state, "source5_job_terminal", terminal, "d" * 64, {},
            replay=True, apply=True,
        )
        self.assertIsNone(state["source5_pending"])
        self.assertTrue(state["source5_cleanup_blocked"])
        self.assertEqual(
            state["source5_finished"][(
                "soak", "campaign-host-mixed-soak-allocatbelt-01",
            )]["state"],
            "blocked",
        )

    def test_final_host_decision_never_sets_campaign_eligibility(self) -> None:
        phases = ["exploration", "aa", "fixed_analysis", "pressure_analysis", "soak"]
        phase_results = [{
            "phase": phase, "numeric_gates_passed": True,
            "analysis_sha256": f"{index + 1:064x}",
            "event_head": f"{index + 6:064x}",
            "records_sha256": f"{index + 11:064x}",
        } for index, phase in enumerate(phases)]
        context = type("Context", (), {
            "manifest": {
                "campaign_id": "campaign",
                "prepared_input_generation": {
                    "completion": {
                        "path": "/private/completion.json",
                        "raw_sha256": "a" * 64,
                        "semantic_sha256": "b" * 64,
                    },
                },
            },
            "host_id": "host",
            "spec_pin": {"path": "/private/spec.json", "raw_sha256": "c" * 64},
            "plan_pin": {"path": "/private/plan.json", "raw_sha256": "d" * 64},
            "spec_semantic_sha256": "e" * 64,
            "plan_semantic_sha256": "f" * 64,
            "prepared_input_completion": {
                "schema": "allocatbelt.application-source5-preparation-completion.v1",
                "completion_sha256": "b" * 64,
                "pilots": [{
                    "host_id": "host",
                    "prepared_host_binding": {"binding_sha256": "1" * 64},
                }],
            },
            "source_manifest_pins": {
                "host": {"path": "/private/source.json", "raw_sha256": "2" * 64},
            },
            "source": {
                "manifest_sha256": "3" * 64,
                "source": {"source_tree_sha256": "4" * 64},
                "build": {"build_sha256": "5" * 64},
            },
        })()
        decision = self.controller._source5_final_decision_value(
            context, phase_results,
        )
        self.assertTrue(decision["numeric_gates_passed"])
        self.assertFalse(decision["campaign_qualification_eligible"])
        self.assertEqual(decision["cohort_status"], "not_verified")
        self.assertIn("accepted_pressure_offline_replay_api_unavailable",
                      decision["cohort_blockers"])

    def test_controller_routes_soak_to_one_locked_helper_and_final_replay(self) -> None:
        controller = ast.parse(CONTROLLER_PATH.read_bytes(), filename=str(CONTROLLER_PATH))
        chronology = ast.parse(CHRONOLOGY_PATH.read_bytes(), filename=str(CHRONOLOGY_PATH))
        controller_names = {
            item.name for item in controller.body if isinstance(item, ast.FunctionDef)
        }
        chronology_names = {
            item.name for item in chronology.body if isinstance(item, ast.FunctionDef)
        }
        self.assertIn("run_soak_phase", controller_names)
        self.assertIn("_fresh_source5_final_phase_results", controller_names)
        self.assertIn("_source5_soak_phase_records", chronology_names)
        self.assertIn("verify_source5_completed_soak_job_locked", chronology_names)
        run_authorized = next(
            item for item in chronology.body
            if isinstance(item, ast.FunctionDef) and
            item.name == "run_authorized_source5_job_locked"
        )
        calls = {item.func.attr for item in ast.walk(run_authorized)
                 if isinstance(item, ast.Call) and isinstance(item.func, ast.Attribute)}
        self.assertIn("run_source5_soak", calls)

    def test_public_material_builder_and_preflight_replay_real_source_pins(self) -> None:
        """Use real recipe, material-index and readback APIs on the bounded V5 fixture.

        The host-binding rows are shape-only fixture values so this exercises
        raw source/recipe integration, not prepared-cohort authorization or
        qualification. No APP or pressure process is launched.
        """
        with tempfile.TemporaryDirectory(prefix="allocatbelt-source5-soak-api-") as temporary:
            temp_root = Path(temporary)
            fixture = self.recipe_fixtures.SourceV5CliFixture(
                temp_root,
                aa_controls_override=(
                    self.recipe_fixtures.SourceV5CliFixture.
                    synthetic_a48_controls()
                ),
            )
            host_id = fixture.job["host_id"]
            recipe_path = fixture.output / "source5-parent-recipe.json"
            receipt_path = fixture.output / "source5-build-receipt.json"
            build = subprocess.run(
                [
                    sys.executable, str(SOAK_RECIPE_PATH), "build",
                    "--spec", str(fixture.spec_path),
                    "--spec-sha256", fixture.spec_sha256,
                    "--plan", str(fixture.plan_path),
                    "--plan-sha256", fixture.plan_sha256,
                    "--plan-file-sha256", fixture.plan_file_sha256,
                    "--job-run-id", fixture.job["run_id"],
                    "--source-root", str(fixture.root),
                    "--oracle-root", str(fixture.oracle_root),
                    "--ring-relative-path",
                    fixture.ring_path.relative_to(fixture.oracle_root).as_posix(),
                    "--ring-sha256", fixture.ring_sha256,
                    "--mode", "functional", "--duration-seconds", "2",
                    "--terminal-budget-bytes", str(2 * 1024 * 1024),
                    "--sample-budget-bytes", str(2 * 1024 * 1024),
                    "--construction-probe", str(fixture.construction_probe_path),
                    "--construction-probe-sha256",
                    fixture.construction_probe_sha256,
                    "--output", str(recipe_path),
                ],
                cwd="/", stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=180, check=False,
            )
            self.assertEqual(build.returncode, 0,
                             build.stderr.decode("utf-8", errors="replace"))
            receipt = json.loads(build.stdout.decode("utf-8"))
            receipt_path.write_bytes(build.stdout)
            self.assertFalse(receipt["launch_enabled"])
            self.assertFalse(receipt["capacity_evidence_ready"])
            self.assertFalse(receipt["feedback_runtime_composition_ready"])

            def binding_for(selected_host: str) -> dict[str, object]:
                body = {
                    "schema": "allocatbelt.application-source5-fixed-pair-host-binding.v1",
                    "host_id": selected_host,
                    "fixed_spec_host_pin": {
                        "path": str(fixture.spec_path),
                        "raw_sha256": fixture.spec_sha256,
                    },
                    "prepared_host_context_pin": {
                        "path": str(fixture.input_root / "host-context.json"),
                        "raw_sha256": "a" * 64,
                    },
                    "spec_host_semantic_sha256": "b" * 64,
                    "boot_id_sha256": "c" * 64,
                    "kernel_release": "synthetic-unit-fixture",
                    "controls_sha256": "d" * 64,
                    "process_affinity": [0],
                    "network_namespace_inode": 1,
                }
                return {
                    **body,
                    "binding_sha256": self.soak.sha256(
                        self.soak.canonical_bytes(body),
                    ),
                }

            completion = {
                "schema": "allocatbelt.application-source5-preparation-completion.v1",
                "pilots": [{
                    "host_id": selected_host,
                    "prepared_host_binding": binding_for(selected_host),
                } for selected_host in fixture.host_ids],
            }
            source_pins = {
                selected_host: {
                    "path": str(fixture.manifest_paths[selected_host]),
                    "raw_sha256": fixture.manifest_raw_shas[selected_host],
                }
                for selected_host in fixture.host_ids
            }
            artifact_root = temp_root / "source5-artifacts"
            artifact_root.mkdir(mode=0o700)
            source = fixture.manifests[host_id]
            readback_prepared = {
                "source_root": fixture.root,
                "source": source,
                "host_id": host_id,
                "campaign_id": fixture.spec["campaign_id"],
            }
            readback = self.soak._load_readback_module(readback_prepared)
            context = types.SimpleNamespace(
                scope="final_frozen",
                prepared_input_completion=completion,
                host_id=host_id,
                plan=fixture.plan,
                manifest={
                    "schema": self.controller.EXECUTION_SCHEMA_V2,
                    "campaign_id": fixture.spec["campaign_id"],
                },
                modules={
                    "scripts/application-source5-soak.py": self.soak,
                    "scripts/application-soak-readback.py": readback,
                },
                spec_pin={"path": str(fixture.spec_path),
                          "raw_sha256": fixture.spec_sha256},
                plan_pin={"path": str(fixture.plan_path),
                          "raw_sha256": fixture.plan_file_sha256},
                spec_semantic_sha256=fixture.spec_sha256,
                plan_semantic_sha256=fixture.plan_sha256,
                source_manifest_pins=source_pins,
                sources=fixture.manifests,
                source=source,
                source_root=fixture.root,
                input_root=fixture.input_root,
                artifact_root=artifact_root,
            )
            material_path = artifact_root / "soak" / "materials-index.json"
            material_pin = self.controller.create_soak_material_index(
                context, recipe_path, receipt_path, material_path,
            )
            material_index, _index_raw, _index_sha = self.soak.read_json(
                material_path, material_pin["raw_sha256"],
                "Source5 Soak materials index",
            )
            self.assertEqual(
                material_pin["materials_sha256"],
                material_index["materials_sha256"],
            )
            materials_payload_pin = {
                "path": material_pin["path"],
                "raw_sha256": material_pin["raw_sha256"],
            }
            binding = self.soak._selected_prepared_host_binding(
                completion, host_id,
            )
            source_refs = {
                selected_host: {
                    "host_id": selected_host,
                    **source_pins[selected_host],
                    "semantic_sha256": fixture.manifests[selected_host][
                        "manifest_sha256"],
                    "source_tree_sha256": fixture.manifests[selected_host][
                        "source"]["source_tree_sha256"],
                }
                for selected_host in fixture.host_ids
            }
            receipt_context = {
                "campaign_id": fixture.spec["campaign_id"],
                "host_id": host_id,
                "source_root": fixture.root,
                "prepared": {
                    "spec_path": fixture.spec_path,
                    "spec_raw_sha256": fixture.spec_sha256,
                    "spec_semantic_sha256": fixture.spec_sha256,
                    "plan_path": fixture.plan_path,
                    "plan_raw_sha256": fixture.plan_file_sha256,
                    "plan_semantic_sha256": fixture.plan_sha256,
                },
                "source_manifest_raw_refs": source_refs,
                "source": source,
            }
            checked_index, recipe, identities = self.soak._verify_build_receipt(
                material_index, receipt_context, fixture.job, binding, readback,
            )
            self.assertEqual(checked_index, material_index)
            self.assertEqual(recipe["runtime"]["mode"], "functional")

            wrong_source_context = {
                **receipt_context,
                "source_manifest_raw_refs": {
                    **source_refs,
                    host_id: {**source_refs[host_id], "raw_sha256": "f" * 64},
                },
            }
            with self.assertRaises(self.soak.Source5SoakError):
                self.soak._verify_build_receipt(
                    material_index, wrong_source_context, fixture.job,
                    binding, readback,
                )

            host = next(item for item in fixture.spec["hosts"]
                        if item["host_id"] == host_id)
            cell = next(item for item in fixture.spec["cells"]
                        if item["workload"] == "mixed" and
                        item["profile"] == fixture.job["profile"])
            args = types.SimpleNamespace(
                recipe=recipe_path, recipe_sha256=receipt["recipe_sha256"],
                campaign_id=fixture.spec["campaign_id"], host_id=host_id,
                run_id=fixture.job["run_id"], allocator="allocatbelt",
                executor="bounded", profile=fixture.job["profile"],
                source_sha256=source["source"]["source_tree_sha256"],
                binary_sha256=source["soak_artifacts"]["allocatbelt"]["sha256"],
                resource_ceiling_sha256=cell["resource_ceiling_sha256"],
                binary=fixture.root / source["soak_artifacts"]["allocatbelt"]["path"],
                mode="functional", duration_seconds=2,
                runner_path=fixture.root /
                    self.recipe_fixtures.builder.SOAK_RUNNER_PATH,
                output_dir=fixture.output, cpu_set=host["controls"]["cpu_set"],
            )
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(readback.command_preflight(args), 0)
            base_audit, base_preflight = readback._current_audit(args)
            self.assertFalse(base_audit["launch_enabled"])
            self.assertFalse(base_preflight["launch_enabled"])
            self.assertFalse(recipe["qualification"]["execution_ready"])
            controller_handle = base_audit["source"]["controller"]
            self.assertIsInstance(controller_handle, types.ModuleType)
            base_audit_sha = self.soak._base_readback_audit_sha256(base_audit)
            overlay_copy = self.soak._copy_readback_audit_for_overlay(
                base_audit, base_preflight,
            )
            self.assertIs(overlay_copy["source"]["controller"],
                          controller_handle)
            self.assertFalse(overlay_copy["launch_enabled"])
            self.assertEqual(
                self.soak._base_readback_audit_sha256(base_audit),
                base_audit_sha,
            )

            bad_controller_audit = {
                **base_audit,
                "source": {
                    **base_audit["source"], "controller_sha256": "f" * 64,
                },
            }
            with self.assertRaises(self.soak.Source5SoakError):
                self.soak._base_readback_audit_sha256(bad_controller_audit)

            pressure_validator_pin = source["qualification_harness"][
                "pressure_validator"]
            pressure_validator_path = fixture.root / pressure_validator_pin["path"]
            pressure_raw, pressure_sha, _pressure_file_info = \
                self.soak.read_stable(
                    pressure_validator_path,
                    "fixture captured SourceV5 pressure validator",
                    self.soak.MAX_SCRIPT_BYTES,
                )
            self.assertEqual(pressure_sha, pressure_validator_pin["sha256"])
            pressure_handle = types.ModuleType(
                f"soak_pressure_reader_{pressure_sha}",
            )
            pressure_handle.__file__ = str(pressure_validator_path)
            pressure_handle.__package__ = ""
            exec(compile(pressure_raw, str(pressure_validator_path), "exec",
                         dont_inherit=True), pressure_handle.__dict__)
            pressure_projection = self.soak._captured_module_projection(
                pressure_handle, fixture.root, source["source"]["files"],
                pressure_validator_pin, f"soak_pressure_reader_{pressure_sha}",
                "SourceV5 pressure validator",
            )
            self.assertEqual(pressure_projection["raw_sha256"], pressure_sha)
            with self.assertRaises(self.soak.Source5SoakError):
                self.soak._captured_module_projection(
                    pressure_handle, fixture.root, source["source"]["files"],
                    {**pressure_validator_pin, "sha256": "f" * 64},
                    f"soak_pressure_reader_{pressure_sha}",
                    "SourceV5 pressure validator",
                )

            helper_input = {
                "schema": "allocatbelt.application-source5-helper-input.v1",
                "scope": "final_frozen", "phase": "soak",
                "campaign_id": fixture.spec["campaign_id"],
                "host_id": host_id,
                "job_index": 0,
                "job": fixture.job,
                "job_sha256": self.soak.sha256(
                    self.soak.canonical_bytes(fixture.job),
                ),
                "members": [self.soak.soak_descriptor(fixture.job)],
                "prerequisites": [],
                "input_snapshot_sha256": "e" * 64,
                "outer_deadline_seconds": 300,
                "effective_timeout_seconds": 300,
                "qualification_eligible": False,
                "payload": {
                    "materials_index": materials_payload_pin,
                    "output_root": str(fixture.output),
                    "prepared_host_binding_sha256": binding["binding_sha256"],
                },
            }
            details = {
                "campaign_id": fixture.spec["campaign_id"],
                "host_id": host_id, "phase": "soak", "job_index": 0,
                "job": fixture.job,
                "job_sha256": helper_input["job_sha256"],
                "members": [self.soak.soak_descriptor(fixture.job)],
                "prerequisites": [],
                "input_snapshot_sha256": helper_input["input_snapshot_sha256"],
                "outer_deadline_seconds": 300,
                "effective_timeout_seconds": 300,
                "output_root": str(fixture.output),
            }
            with self.assertRaisesRegex(
                    self.soak.Source5SoakError,
                    "lacks genuine capacity, composition, or pressure prerequisites"):
                self.soak.build_source5_launch_overlay(
                    helper_input,
                    {"campaign_id": fixture.spec["campaign_id"],
                     "host_id": host_id},
                    details, material_index, binding, recipe, identities,
                    args, base_audit, base_preflight, readback,
                )
            self.assertEqual(
                self.soak._base_readback_audit_sha256(base_audit),
                base_audit_sha,
            )
            self.assertIs(base_audit["source"]["controller"], controller_handle)
            self.assertFalse(base_audit["launch_enabled"])
            self.assertEqual(
                self.soak._base_readback_audit_sha256(base_audit),
                base_audit_sha,
            )
            self.assertFalse(base_audit["launch_enabled"])

            prepare_output = temp_root / "budgetless-prepare-entrypoint"
            prepare_output.mkdir(mode=0o700)
            prepare_helper_input = {
                **helper_input,
                "payload": {
                    **helper_input["payload"],
                    "output_root": str(prepare_output),
                },
            }
            prepare_details = {
                **details, "output_root": str(prepare_output),
            }
            prepare_context = {
                **receipt_context,
                "source5_prepared_input_completion": completion,
                "source_manifest_raw_refs": source_refs,
            }
            with self.assertRaisesRegex(
                self.soak.Source5SoakError,
                "qualified Soak recipe has no original pressure recipe",
            ), mock.patch.object(
                self.soak, "_capture_source5_soak_probe_monitored",
                side_effect=AssertionError("preflight reached a probe owner"),
            ), mock.patch.object(
                self.soak, "_verify_build_receipt",
                wraps=self.soak._verify_build_receipt,
            ) as live_builder:
                self.soak.prepare_source5_soak(
                    prepare_helper_input, prepare_context, prepare_details,
                    readback,
                )
            self.assertEqual(live_builder.call_count, 1)
            self.assertIsNone(live_builder.call_args.kwargs.get("artifact_view"))
            self.assertFalse((prepare_output / "soak-preflight.json").exists())
            for owner_artifact in (
                "soak-launch.json", "source5-soak-supervisor.json",
                "source5-soak-component.json",
                "source5-soak-application-owner-return.json",
                "source5-soak-pressure-owner-return.json",
            ):
                self.assertFalse((prepare_output / owner_artifact).exists())

            self._build_and_replay_full_width_contract_fixture(
                fixture, context, completion, source, source_pins, binding,
                material_index, recipe_path, receipt_path, artifact_root,
                host_id,
            )

    def _build_and_replay_full_width_contract_fixture(
        self, fixture, context, completion, source, source_pins, binding,
        material_index, recipe_path, receipt_path, artifact_root, host_id,
    ) -> None:
        """Exercise the unmocked full Plan-width builder on synthetic SourceV5 bytes."""
        controller = self.controller
        module_paths = {
            "scripts/application-campaign.py",
            "scripts/application-campaign-inputs.py",
            "scripts/application-byte-capacity.py",
            "scripts/application-campaign-chronology.py",
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
        }
        source_rows = source["source"]["files"]
        typed_by_path = {row["path"]: row for row in source_rows}
        modules = {}
        for relative in sorted(module_paths):
            record = typed_by_path[relative]
            path = fixture.root / relative
            raw, actual, _info = self.soak.read_stable(
                path, f"fixture pinned width module {relative}",
                self.soak.MAX_SCRIPT_BYTES,
            )
            self.assertEqual(actual, record["sha256"])
            self.assertEqual(len(raw), record["size"])
            modules[relative] = controller._load_module(
                raw, path, relative.replace("/", "_").replace(".", "_"),
            )

        context.modules = modules
        context.campaign = modules["scripts/application-campaign.py"]
        context.chronology = modules["scripts/application-campaign-chronology.py"]
        context.fixed_pair = modules["scripts/application-fixed-pair.py"]
        context.pressure_pair = modules["scripts/application-pressure-pair.py"]
        context.spec = fixture.spec
        context.plan_raw = fixture.plan_path.read_bytes()
        context.output_root = artifact_root
        context.scope = "final_frozen"
        context.host_evidence_budget_pin = None
        context.host_evidence_budget_raw = None
        context.journal_width_budget_pin = None
        context.journal_width_jobs = None
        context.journal_width_soak_materials = None
        context.journal_width_tmpdir_budget = None
        context.journal_width_original_pins = None
        context.journal_width_observed_host = None
        context.journal_width_cleanup_source_bytes = None
        context.journal_width_contract = None
        context.journal_width_contract_pin = None

        catalogue = modules[controller.EVIDENCE_CATALOGUE_SOURCE_PATH]
        catalogue_pins = {}
        for role, relative in catalogue.OWNER_PATHS.items():
            row = typed_by_path[relative]
            catalogue_pins[role] = {
                "path": relative, "raw_sha256": row["sha256"],
                "byte_count": row["size"],
            }
        context.owner_evidence_contract = {
            "owner_source_pins": catalogue_pins,
        }

        all_module_pins = {}
        for selected_host, selected_source in fixture.manifests.items():
            all_module_pins[selected_host] = {
                row["path"]: {"path": row["path"], "sha256": row["sha256"]}
                for row in selected_source["source"]["files"]
                if row["kind"] == "file"
            }
        host_dir = artifact_root / fixture.spec["campaign_id"] / "source5" / host_id
        capacity_dir = host_dir / "capacity-registration"
        capacity_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        registration = {
            "host_completion": {
                "path": str(capacity_dir / "host-completion.json"),
                "raw_sha256": "1" * 64, "semantic_sha256": "2" * 64,
            },
            "host_verification": {
                "path": str(capacity_dir / "host-verification.json"),
                "raw_sha256": "3" * 64,
            },
            "ledger": {
                "path": str(capacity_dir / "ledger.jsonl"),
                "raw_sha256": "4" * 64, "terminal_head": "5" * 64,
            },
            "capacity_schedule_sha256": fixture.plan[
                "capacity_process_templates_sha256"],
            "registration_head": "6" * 64,
        }
        preparation_test = load_source(
            "source5_width_preparation_fixture",
            ROOT / "scripts/test-application-source5-input-preparation.py",
        )
        prep_fixture, _prep_spec = preparation_test.preparation_fixture()
        prep_fixture["core"]["campaign_id"] = fixture.spec["campaign_id"]
        inputs_module = modules["scripts/application-campaign-inputs.py"]
        preparation_path = fixture.input_root / "width-preparation-intent.json"
        preparation_pin = inputs_module.build_preparation_intent(
            prep_fixture["core"], prep_fixture["source_pins"],
            prep_fixture["observed_hosts"], prep_fixture["capacity_templates"],
            prep_fixture["condition_intensities"], preparation_path,
        )
        preparation_pin = {
            key: preparation_pin[key]
            for key in ("path", "raw_sha256", "semantic_sha256")
        }
        ceilings = {
            "maximum_job_output_bytes": 1_073_741_824,
            "maximum_job_output_inodes": 1024,
            "maximum_generation_bytes": 2_147_483_648,
            "maximum_generation_inodes": 8192,
            "maximum_tmpdir_bytes": 1_073_741_824,
            "maximum_tmpdir_inodes": 4096,
            "maximum_trace_file_bytes": 536_870_912,
            "durable_receipt_reserve_bytes": 1_048_576,
            "durable_receipt_reserve_inodes": 8,
            "minimum_free_bytes": 2_147_483_648,
            "minimum_free_inodes": 10_000,
            "monitor_sample_interval_milliseconds": 100,
            "process_deadline_seconds": fixture.spec["deadlines"][
                "process_seconds"],
        }
        prepared_budget = inputs_module.build_preparation_resource_budget(
            inputs_module.json.loads(preparation_path.read_bytes()),
            preparation_pin, host_id, ceilings,
        )
        prepared_budget_path = fixture.input_root / "width-resource-budget.json"
        prepared_budget_raw = inputs_module._canonical(prepared_budget)
        prepared_budget_path.write_bytes(prepared_budget_raw)
        prepared_budget_path.chmod(0o600)
        prepared_budget_pin = {
            "path": str(prepared_budget_path),
            "raw_sha256": inputs_module._sha256(prepared_budget_raw),
            "semantic_sha256": prepared_budget["resource_budget_sha256"],
        }

        capacity_entries = [
            row for row in fixture.plan["capacity_process_templates"]
            if row["capacity_key"]["host_id"] == host_id
        ]
        self.assertEqual(len(capacity_entries), 15)
        width_completion = {
            **completion,
            "capacity_preparations": [{
                "host_id": host_id, "entries": capacity_entries,
            }],
            "resource_budgets": {host_id: prepared_budget_pin},
        }
        context.prepared_input_completion = width_completion
        context.manifest = {
            "schema": controller.EXECUTION_SCHEMA_V4,
            "campaign_id": fixture.spec["campaign_id"],
            "hosts": list(fixture.host_ids),
            "modules": all_module_pins,
            "original_inputs": {
                "campaign_artifacts_root": str(fixture.oracle_root),
            },
            "prepared_capacity_registration": registration,
            "prepared_input_generation": {
                "completion": preparation_pin,
                "provenance": {
                    "schema": "allocatbelt.application-source5-preparation-provenance.v1",
                    "preparation_pin": preparation_pin,
                    "final_spec_pin": {
                        "path": str(fixture.spec_path),
                        "raw_sha256": fixture.spec_sha256,
                        "semantic_sha256": fixture.spec_sha256,
                    },
                    "final_plan_pin": {
                        "path": str(fixture.plan_path),
                        "raw_sha256": fixture.plan_file_sha256,
                        "semantic_sha256": fixture.plan_sha256,
                    },
                },
            },
        }
        manifest_raw = controller.canonical_bytes(context.manifest)
        context.manifest_pin = {
            "path": str(fixture.input_root / "width-execution-manifest.json"),
            "raw_sha256": controller.sha256(manifest_raw),
        }
        context.capacity_completion = {
            "artifact": {
                "path": str(capacity_dir / "capacity-completion.json"),
                "sha256": "7" * 64,
            },
            "ledger_raw_sha256": "4" * 64,
            "terminal_head": "5" * 64,
            "schedule_sha256": registration["capacity_schedule_sha256"],
            "registration_head": registration["registration_head"],
        }

        observed_controls = next(
            row["controls"] for row in fixture.spec["hosts"]
            if row["host_id"] == host_id
        )
        cpu_set = observed_controls["cpu_set"]
        cpu_values = []
        for component in cpu_set.split(","):
            bounds = [int(value) for value in component.split("-")]
            cpu_values.extend(range(bounds[0], bounds[-1] + 1))
        observed = {
            "boot_id_sha256": "8" * 64,
            "controls_sha256": controller.sha256(
                controller.canonical_bytes(observed_controls),
            ),
            "controls": observed_controls,
            "cpu_affinity": sorted(set(cpu_values)),
            "network_namespace_inode": 1,
        }
        observed_path = fixture.input_root / "width-observed-host.json"
        observed_raw = controller.canonical_bytes(observed)
        observed_path.write_bytes(observed_raw)
        observed_path.chmod(0o600)
        context.observed_host_pin = {
            "path": str(observed_path),
            "raw_sha256": controller.sha256(observed_raw),
        }

        budget_directory = (artifact_root / fixture.spec["campaign_id"] /
                            "source5" / host_id / "evidence-budget")
        budget_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        host_budget_path = budget_directory / "host-evidence-budget-v2.json"
        host_budget_fixture = {"schema": "fixture.width-budget-pin.v1"}
        host_budget_raw = controller.canonical_bytes(host_budget_fixture)
        host_budget_pin = {
            "path": str(host_budget_path),
            "raw_sha256": controller.sha256(host_budget_raw),
            "semantic_sha256": controller.sha256(host_budget_raw),
        }
        context.host_evidence_budget_pin = host_budget_pin
        context.journal_width_budget_pin = host_budget_pin

        pressure_jobs = [
            row for row in fixture.plan["jobs"]["pressure"]
            if row["host_id"] == host_id
        ]
        pressure_directory = artifact_root / "pressure-materials"
        pressure_directory.mkdir(mode=0o700)
        pressure_body = {
            "schema": controller.PRESSURE_MATERIAL_INDEX_SCHEMA_V2,
            "campaign_id": fixture.spec["campaign_id"],
            "host_id": host_id,
            "jobs": {
                row["run_id"]: {
                    "path": str(pressure_directory / f"{row['run_id']}.json"),
                    "raw_sha256": "9" * 64,
                } for row in pressure_jobs
            },
        }
        pressure_index = {
            **pressure_body,
            "manifest_sha256": controller.sha256(
                controller.canonical_bytes(pressure_body),
            ),
        }
        pressure_index_path = pressure_directory / "materials-index.json"
        pressure_index_raw = controller.canonical_bytes(pressure_index)
        pressure_index_path.write_bytes(pressure_index_raw)
        pressure_index_path.chmod(0o600)

        soak_budget_module = modules["scripts/application-source5-soak.py"]
        source_ref = source_pins[host_id]
        parent_pin = material_index["parent_recipe"]
        build_pin = material_index["build_receipt"]
        module_prepared = {"source": source, "source_root": fixture.root}
        resource_budget_body = {
            "schema": soak_budget_module.SOAK_RESOURCE_BUDGET_SCHEMA,
            "binding": {
                "campaign_id": fixture.spec["campaign_id"],
                "host_id": host_id,
                "job_sha256": soak_budget_module.sha256(
                    soak_budget_module.canonical_bytes(fixture.job),
                ),
                "source_manifest": {
                    "path": source_ref["path"],
                    "raw_sha256": source_ref["raw_sha256"],
                    "semantic_sha256": source["manifest_sha256"],
                },
                "source_tree_sha256": source["source"]["source_tree_sha256"],
                "parent_recipe": parent_pin,
                "build_receipt": build_pin,
                "prepared_host_binding_sha256": binding["binding_sha256"],
                "observed_host": binding["prepared_host_context_pin"],
                "monitor_owner": soak_budget_module._resource_budget_module_pin(
                    module_prepared, "scripts/application-fixed-pair.py",
                    "monitor owner",
                ),
                "soak_adapter": soak_budget_module._resource_budget_module_pin(
                    module_prepared, "scripts/application-source5-soak.py",
                    "Soak adapter",
                ),
                "soak_reader": soak_budget_module._resource_budget_module_pin(
                    module_prepared, "scripts/application-soak-readback.py",
                    "Soak reader",
                ),
            },
            "layout": {
                "output_root": str(fixture.output),
                "application_tmpdir": str(artifact_root / "tmp" / "application"),
                "pressure_scratch": str(artifact_root / "tmp" / "pressure"),
                "probe_capture_root": str(artifact_root / "probe" /
                                           ("a" * 32)),
                "probe_tmpdir": str(artifact_root / "probe" /
                                     ("a" * 32) / "tmp"),
                "host_receipt_path": str(artifact_root / "host-receipt.json"),
            },
            "schedule": {
                "production_seconds": 10_800,
                "application_sample_interval_ms": 100,
                "application_sample_tolerance_ns": 10_000_000,
                "application_sample_count": 108_001,
                "application_wall_timeout_seconds": 11_050,
                "pressure_total_deadline_seconds": 12_000,
                "authorization_effective_timeout_seconds": 13_000,
                "probe_timeout_seconds": 30,
                "resource_monitor_interval_ms": 100,
                "resource_monitor_tolerance_ns": 100_000_000,
            },
            "ceilings": {
                "maximum_output_bytes": 8 * 1024 * 1024 * 1024,
                "maximum_output_inodes": 100_000,
                "maximum_application_tmpdir_bytes": 512 * 1024 * 1024,
                "maximum_application_tmpdir_inodes": 4096,
                "maximum_pressure_scratch_bytes": 512 * 1024 * 1024,
                "maximum_pressure_scratch_inodes": 4096,
                "maximum_probe_output_bytes": 64 * 1024 * 1024,
                "maximum_probe_output_inodes": 16,
                "maximum_probe_tmpdir_bytes": 64 * 1024 * 1024,
                "maximum_probe_tmpdir_inodes": 256,
                "minimum_free_bytes": 1024 * 1024 * 1024,
                "minimum_free_inodes": 1024,
                "durable_receipt_reserve_bytes": 8 * 1024 * 1024,
                "durable_receipt_reserve_inodes": 16,
                "maximum_monitor_stream_bytes": 1024 * 1024 * 1024,
                "maximum_monitor_rows": 1_000_000,
                "maximum_monitor_row_bytes": 2 * 1024 * 1024,
            },
            "artifact_limits": {
                name: 8 * 1024 * 1024
                for name in soak_budget_module.RESOURCE_BUDGET_ARTIFACT_LIMIT_FIELDS
            },
        }
        resource_budget_body["artifact_limits"].update({
            "terminal_stream_bytes": 32 * 1024 * 1024 * 1024,
            "resource_samples_bytes": 96 * 1024 * 1024,
            "pressure_events_bytes": 512 * 1024 * 1024,
            "probe_stdout_bytes": 512 * 1024,
            "probe_stderr_bytes": 64 * 1024,
            "probe_owner_receipt_bytes": 16 * 1024 * 1024,
            "probe_inventory_bytes": 16 * 1024 * 1024,
            "probe_failure_bytes": 64 * 1024,
            "probe_capture_receipt_bytes": 16 * 1024 * 1024,
            "resource_monitor_stream_bytes": 512 * 1024 * 1024,
            "owner_return_receipt_bytes": 2 * 1024 * 1024,
        })
        soak_budget = soak_budget_module.make_resource_budget_document(
            resource_budget_body,
        )
        soak_budget_directory = artifact_root / "soak"
        soak_budget_directory.mkdir(mode=0o700, exist_ok=True)
        soak_budget_path = soak_budget_directory / "width-resource-budget.json"
        soak_budget_raw = soak_budget_module.canonical_bytes(soak_budget)
        soak_budget_path.write_bytes(soak_budget_raw)
        soak_budget_path.chmod(0o600)
        width_soak_index_path = soak_budget_directory / "width-materials-index.json"
        controller.create_soak_material_index(
            context, recipe_path, receipt_path, width_soak_index_path,
            soak_budget_path,
        )

        projected = controller.build_source5_journal_width_contract(
            context, pressure_index_path, width_soak_index_path,
            host_budget_path, None,
        )
        contract = projected["contract"]
        expected_counts = {
            "exploration": 360, "aa": 48, "confirmation": 8100,
            "pressure": 8100, "soak": 1,
        }
        observed_counts = {
            phase: sum(row["host_id"] == host_id
                       for row in fixture.plan["jobs"][phase])
            for phase in expected_counts
        }
        self.assertEqual(observed_counts, expected_counts)
        self.assertEqual(sum(observed_counts.values()), 16_609)
        self.assertEqual(len(contract["job_rows"]), 16_609)
        self.assertEqual(len(contract["owner_pins"]), 11)
        self.assertEqual(contract["total_event_count"], 99_659)
        self.assertFalse(fixture.plan["execution_ready"])
        self.assertFalse(fixture.plan["full_gate_ready"])

        context.journal_width_contract = contract
        context.journal_width_contract_pin = {
            "path": str(host_dir / "journal-width-contract.json"),
            "raw_sha256": projected["raw_sha256"],
            "semantic_sha256": projected["semantic_sha256"],
        }
        controller._require_source5_journal_width_projection(context, projected)

        analyzer_rows = []
        for phase in ("confirmation", "pressure"):
            for job in controller._host_jobs(context, phase):
                if job.get("mode") != "open_loop":
                    continue
                descriptors = (
                    context.fixed_pair._member_descriptors(
                        job, context.campaign,
                    ) if phase == "confirmation" else
                    context.pressure_pair.pressure_process_descriptors(job)
                )
                for member_index, descriptor in enumerate(descriptors):
                    if phase == "confirmation":
                        role = "normal_app_output"
                        owner = "fixed_pair"
                        maximum = context.fixed_pair.MAX_ID_BYTES
                        trace_path = (
                            artifact_root / fixture.spec["campaign_id"] /
                            "source5" / host_id / "job-artifacts" /
                            phase / job["run_id"] /
                            f"{descriptor['pair']}-{descriptor['executor']}.ids.tsv"
                        )
                    else:
                        role = "opaque_trace"
                        owner = "pressure_pair"
                        maximum = context.pressure_pair.MAX_TRACE_BYTES
                        member_root = (
                            artifact_root / fixture.spec["campaign_id"] /
                            "source5" / host_id / "job-artifacts" /
                            "pressure" / job["run_id"] /
                            f"{member_index:02d}-{descriptor['pair']}-"
                            f"{descriptor['executor']}-{descriptor['allocator']}"
                        )
                        trace_path = Path(
                            controller._pressure_member_outputs(member_root)["ids"]
                        )
                    analyzer_rows.append({
                        "path": str(trace_path),
                        "kind": "file", "role": role, "owner": owner,
                        "host_id": host_id,
                        "storage_root": str(artifact_root),
                        "phase": phase, "run_id": job["run_id"],
                        "member_index": member_index,
                        "max_bytes": maximum,
                        "max_file_bytes": maximum,
                    })
        self.assertTrue(any(
            row["phase"] == "pressure" and
            Path(row["path"]).name == "ids.tsv"
            for row in analyzer_rows
        ))
        analyzer_projection = controller._source5_analyzer_scratch_projection(
            context, analyzer_rows,
        )
        self.assertEqual(
            analyzer_projection["maximum_trace_file_bytes"],
            context.pressure_pair.MAX_TRACE_BYTES,
        )
        self.assertEqual(analyzer_projection["maximum_trace_families"], 4)
        with self.assertRaisesRegex(
                controller.Source5CampaignError, "do not close"):
            controller._source5_analyzer_scratch_projection(
                context, analyzer_rows[:-1],
            )
        swapped_trace_rows = [dict(row) for row in analyzer_rows]
        swapped_trace_rows[0]["path"] += ".other"
        with self.assertRaisesRegex(
                controller.Source5CampaignError, "exact owner role"):
            controller._source5_analyzer_scratch_projection(
                context, swapped_trace_rows,
            )

        mutant = json.loads(controller.canonical_bytes(contract))
        for row in mutant["job_rows"]:
            row["maximum_event_bytes_by_kind"] = {
                kind: 1 for kind in row["event_counts"]
            }
            row["failed_event_bytes_by_kind"] = {
                kind: 1 for kind in row["event_counts"]
            }
            job_events = sum(row["event_counts"].values())
            row["success_job_bytes"] = job_events
            row["failed_window_bytes"] = job_events
            row["byte_uplift"] = 0
        for total in mutant["phase_totals"]:
            total["success_event_bytes"] = sum(
                row["success_job_bytes"] for row in mutant["job_rows"]
                if row["phase"] == total["phase"]
            )
        for fixed in mutant["fixed_event_widths"]:
            fixed["maximum_line_bytes"] = 1
        mutant["total_event_bytes"] = (
            sum(row["count"] for row in mutant["fixed_event_widths"]) +
            sum(row["success_job_bytes"] for row in mutant["job_rows"])
        )
        first = mutant["job_rows"][0]
        mutant["failed_owner_window"] = {
            key: first[key] for key in (
                "phase", "job_index", "ordinal", "run_id", "job_sha256",
                "failed_event_count", "failed_event_count_uplift",
                "failed_window_bytes", "success_job_bytes", "byte_uplift",
            )
        }
        mutant_body = {key: value for key, value in mutant.items()
                       if key != "contract_sha256"}
        mutant["contract_sha256"] = controller.sha256(
            controller.canonical_bytes(mutant_body),
        )
        mutant_raw = controller.canonical_bytes(mutant)
        context.journal_width_contract = mutant
        context.journal_width_contract_pin = {
            "path": str(host_dir / "journal-width-contract.json"),
            "raw_sha256": controller.sha256(mutant_raw),
            "semantic_sha256": mutant["contract_sha256"],
        }
        with self.assertRaisesRegex(
                controller.Source5CampaignError,
                "deterministic source-side preflight recomputation"):
            controller._require_source5_journal_width_projection(
                context, projected,
            )


if __name__ == "__main__":
    unittest.main()
