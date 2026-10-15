#!/usr/bin/env python3
"""Regression tests for the Source5 one-APP Soak adapter contracts."""
from __future__ import annotations

import ast
import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
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
            fixture = self.recipe_fixtures.SourceV5CliFixture(temp_root)
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
                manifest={"campaign_id": fixture.spec["campaign_id"]},
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
            ):
                self.soak.prepare_source5_soak(
                    prepare_helper_input, prepare_context, prepare_details,
                    readback,
                )
            self.assertFalse((prepare_output / "soak-preflight.json").exists())
            for owner_artifact in (
                "soak-launch.json", "source5-soak-supervisor.json",
                "source5-soak-component.json",
                "source5-soak-application-owner-return.json",
                "source5-soak-pressure-owner-return.json",
            ):
                self.assertFalse((prepare_output / owner_artifact).exists())


if __name__ == "__main__":
    unittest.main()
