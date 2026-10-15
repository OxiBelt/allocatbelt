#!/usr/bin/env python3
"""Focused regression for the bounded Source5 host-v3 pressure receiver."""
from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("application-pressure-readback.py").resolve()
loader = importlib.machinery.SourceFileLoader("pressure_readback_v3_tests", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
reader = importlib.util.module_from_spec(spec)
loader.exec_module(reader)


def raw_pin(path: Path, letter: str) -> dict[str, str]:
    return {"path": str(path), "raw_sha256": letter * 64}


def write_canonical(path: Path, value: dict) -> tuple[bytes, str]:
    raw = reader.canonical_bytes(value)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, raw)
    finally:
        os.close(descriptor)
    return raw, hashlib.sha256(raw).hexdigest()


class Source5HostV3PressureReceiverTests(unittest.TestCase):
    def test_valid_host_v3_pin_passes_the_single_app_receiver(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-host-v3-pin-") as temporary:
            root = Path(temporary)
            output = root / "output"
            probe_root = root / "probe" / ("a" * 32)
            host_path = root / "host-verification.json"
            budget_path = root / "resource-budget.json"
            stream_path = output / "source5-soak-resource-monitor.jsonl"
            job = {
                "campaign_id": "campaign", "host_id": "host",
                "run_id": "soak-run", "phase": "soak",
            }
            source = {
                "path": str(root / "source-manifest.json"),
                "raw_sha256": "1" * 64,
                "semantic_sha256": "2" * 64,
                "source_tree_sha256": "3" * 64,
            }
            parent_recipe = raw_pin(root / "parent-recipe.json", "4")
            build_receipt = raw_pin(root / "build-receipt.json", "5")
            prepared_host = raw_pin(root / "observed-host.json", "6")
            prepared_binding_sha = "7" * 64
            component_pins = {
                "materials_index": raw_pin(root / "materials-index.json", "8"),
                "parent_recipe": parent_recipe,
                "build_receipt": build_receipt,
                "preflight": raw_pin(output / "soak-preflight.json", "9"),
                "launch_authorization": raw_pin(output / "launch-authorization.json", "a"),
                "supervisor": raw_pin(output / "source5-soak-supervisor.json", "b"),
                "launch": raw_pin(output / "soak-launch.json", "c"),
                "postflight": raw_pin(output / "source5-soak-postflight.json", "d"),
                "readback": raw_pin(output / "soak-readback.json", "e"),
                "probe_capture": raw_pin(probe_root / "capture-receipt.json", "f"),
                "resource_monitor": raw_pin(stream_path, "1"),
                "application_owner": raw_pin(output / "app-owner.json", "2"),
                "pressure_owner": raw_pin(output / "pressure-owner.json", "3"),
            }
            layout = {
                "output_root": str(output),
                "application_tmpdir": str(root / "application-tmp"),
                "pressure_scratch": str(root / "pressure-scratch"),
                "probe_capture_root": str(probe_root),
                "probe_tmpdir": str(probe_root / "tmp"),
                "host_receipt_path": str(host_path),
            }
            budget_body = {
                "schema": "allocatbelt.application-source5-soak-resource-budget.v2",
                "binding": {
                    "campaign_id": "campaign", "host_id": "host",
                    "job_sha256": reader.digest_object(job),
                    "source_manifest": {
                        key: source[key]
                        for key in ("path", "raw_sha256", "semantic_sha256")
                    },
                    "source_tree_sha256": source["source_tree_sha256"],
                    "parent_recipe": parent_recipe,
                    "build_receipt": build_receipt,
                    "prepared_host_binding_sha256": prepared_binding_sha,
                    "observed_host": prepared_host,
                    "monitor_owner": {}, "soak_adapter": {}, "soak_reader": {},
                },
                "layout": layout,
            }
            budget = {
                **budget_body,
                "resource_budget_sha256": reader.digest_object(budget_body),
            }
            budget_raw, budget_raw_sha = write_canonical(budget_path, budget)
            budget_pin = {
                "path": str(budget_path), "raw_sha256": budget_raw_sha,
                "semantic_sha256": budget["resource_budget_sha256"],
            }
            roles = {
                "output", "application_tmpdir", "pressure_scratch",
                "probe_capture", "probe_tmpdir",
            }
            final_usage = {
                "domains": {
                    role: {"bytes_used": 0, "inode_count": 0}
                    for role in roles
                },
                "high_water": {
                    role: {"bytes": 0, "inodes": 0}
                    for role in roles
                },
            }
            resource_monitor = {
                "schema": "allocatbelt.application-source5-soak-resource-monitor-summary.v1",
                "budget": budget_pin,
                "stream": raw_pin(stream_path, "1"),
                "row_count": 1,
                "high_water": final_usage["high_water"],
                "final_usage": final_usage["domains"],
                "failure": None, "prefix_sha256": "4" * 64,
            }
            origin_body = {
                "schema": "allocatbelt.application-source5-soak-origin-host.v1",
                "host_id": "host",
                "observed_host_raw_sha256": prepared_host["raw_sha256"],
                "boot_id_sha256": "5" * 64,
                "kernel_release": "fixture-kernel",
                "allowed_cpu_affinity": [0],
                "network_namespace_inode": 1,
                "controls_sha256": "6" * 64,
            }
            origin = {
                **origin_body,
                "host_identity_sha256": reader.digest_object(origin_body),
            }
            receipt_body = {
                "schema": reader.SOURCE5_SOAK_HOST_VERIFICATION_SCHEMA_V3,
                "campaign_id": "campaign", "host_id": "host", "run_id": "soak-run",
                "component_sha256": "7" * 64,
                "component_pins": {
                    **component_pins, "resource_budget": budget_pin,
                },
                "generation": {
                    "campaign_id": "campaign", "host_id": "host", "job": job,
                    "source_manifest": source,
                },
                "prepared_host_context_pin": prepared_host,
                "fixed_spec_host_pin": raw_pin(root / "spec.json", "8"),
                "observed_host_pin": prepared_host,
                "prepared_host_binding_sha256": prepared_binding_sha,
                "helper_input_pin": raw_pin(root / "helper-input.json", "9"),
                "construction_probe": {
                    "receipt_pin": raw_pin(probe_root / "capture-receipt.json", "f"),
                },
                "pressure_origin": {
                    "schema": "allocatbelt.application-source5-soak-pressure-origin.v2",
                    "recipe_pin": raw_pin(root / "pressure-recipe.json", "a"),
                    "recipe_dependency_paths": [str(root / "pressure-recipe.json")],
                    "application_tmpdir_path": layout["application_tmpdir"],
                    "storage_before": {}, "storage_after": {},
                },
                "origin_host": origin,
                "process_absence": {}, "tree_roots": [],
                "evidence_inventory": [], "evidence_bases": [],
                "readback_sha256": "b" * 64,
                "bounded_execution_ready": True, "bounded_blockers": [],
                "qualification_eligible": False, "execution_ready": False,
                "resource_budget": budget_pin,
                "resource_monitor": resource_monitor,
                "final_usage": final_usage,
            }
            receipt = {
                **receipt_body,
                "receipt_sha256": reader.digest_object(receipt_body),
            }
            receipt_raw, receipt_raw_sha = write_canonical(host_path, receipt)
            host_pin = {
                "path": str(host_path), "raw_sha256": receipt_raw_sha,
                "receipt_sha256": receipt["receipt_sha256"],
            }

            validated, actual_raw_sha, checked_pin = \
                reader._validate_source5_soak_host_receipt_v2(
                    host_pin, allow_v3=True,
                )

            self.assertEqual(validated, receipt)
            self.assertEqual(actual_raw_sha, receipt_raw_sha)
            self.assertEqual(checked_pin, host_pin)
            self.assertEqual(budget_raw, budget_path.read_bytes())


if __name__ == "__main__":
    unittest.main()
