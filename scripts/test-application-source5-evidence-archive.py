#!/usr/bin/env python3
"""Focused invariants for the Source5 checkpoint/archive coordinator."""
from __future__ import annotations

import hashlib
import fcntl
import copy
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
ARCHIVE_PATH = SCRIPT_DIR / "application-source5-evidence-archive.py"


def load_target():
    spec = importlib.util.spec_from_file_location(
        "source5_evidence_archive_test_target", ARCHIVE_PATH,
    )
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load production target {ARCHIVE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


archive = load_target()


def canonical(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def private(path: Path) -> Path:
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)
    return path


def pinned(path: Path, raw: bytes, semantic: str | None = None) -> dict[str, str]:
    return {
        "path": str(path), "raw_sha256": sha(raw),
        "semantic_sha256": sha(raw) if semantic is None else semantic,
    }


def source5_fixture(root: Path, *, state: str = "failed_or_invalid"):
    job = {
        "host_id": "host-a", "phase": "aa", "ordinal": 1,
        "run_id": "campaign-host-a-aa-01", "predecessor_run_ids": [],
    }
    plan_body = {
        "schema": "allocatbelt.application-campaign-plan.v3",
        "campaign_id": "campaign-a", "jobs": {"aa": [job]},
    }
    plan = {**plan_body, "plan_sha256": sha(canonical(plan_body))}
    plan_raw = canonical(plan)
    plan_path = root / "inputs" / "plan-v3.json"
    record_path = root / "source5" / "host-a" / "aa" / "job-records" / f"{job['run_id']}.json"
    metrics = []
    chronology = {
        "authorization_id": "source5-auth-01",
        "authorization_head": "a" * 64,
        "app_started_heads": [], "app_terminal_heads": [],
        "job_terminal_head": "b" * 64,
        "component_sha256": "c" * 64,
        "process_metrics_sha256": sha(canonical(metrics)),
        "app_start_events": [], "app_terminal_events": [],
        "member_processes": [],
    }
    record_body = {
        "schema": "allocatbelt.application-source5-job-record.v1",
        "state": state, "job": job, "pair_directory": str(root / "pair"),
        "process_metrics": metrics, "evidence": {},
        "chronology": chronology, "qualification_eligible": False,
    }
    record = {**record_body, "record_sha256": sha(canonical(record_body))}
    record_raw = canonical(record)
    return {
        "job": job, "plan": plan, "plan_raw": plan_raw,
        "plan_pin": {
            "path": str(plan_path), "raw_sha256": sha(plan_raw),
            "semantic_sha256": plan["plan_sha256"],
        },
        "record": record, "record_raw": record_raw,
        "job_record_pin": {
            "path": str(record_path), "raw_sha256": sha(record_raw),
        },
    }


def context_for(root: Path, fixture: dict) -> dict:
    return {
        "schema": archive.CONTEXT_SCHEMA_V1,
        "campaign_id": "campaign-a", "host_id": "host-a", "phase": "aa",
        "job_index": 0,
        "source_manifest_pin": pinned(root / "source.json", b"source"),
        "execution_manifest_pin": pinned(root / "execution.json", b"execution"),
        "plan_pin": fixture["plan_pin"],
        "resource_budget_pin": pinned(root / "host-budget.json", b"budget"),
        "predecessor_ack_pin": None,
        "authorized_signer_fingerprint": "A" * 40,
    }


def selected_budget_source_fixture() -> tuple[bytes, dict, bytes]:
    relative = archive.SOURCE5_BUDGET_VALIDATOR_PATH
    module_path = SCRIPT_DIR.parent / relative
    module_raw = module_path.read_bytes()
    info = module_path.stat(follow_symlinks=False)
    mode = f"{stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode):06o}"
    module_sha = sha(module_raw)
    files = [{
        "path": relative, "kind": "file", "mode": mode,
        "sha256": module_sha, "size": len(module_raw),
    }]
    source_body = {
        "git_commit": "1" * 40,
        "source_tree_sha256": sha(canonical({
            "schema": archive.SOURCE_INVENTORY_SCHEMA_V1,
            "entries": files,
        })),
        "files": files,
    }
    source = {
        "schema": archive.SOURCE_MANIFEST_SCHEMA_V5,
        "source": source_body,
        "build": {
            "host_id": "host-a", "rustc_release": "1.99.0",
            "rustc_verbose": ["rustc 1.99.0"], "cargo_version": "cargo 1.99.0",
            "target_triple": "x86_64-unknown-linux-gnu",
            "target_cpu": "x86-64-v3", "profile": "release",
            "features_sha256": "2" * 64, "build_inputs_sha256": "3" * 64,
        },
    }
    source["manifest_sha256"] = sha(canonical(source))
    source_raw = canonical(source)
    source_pin = {
        "path": "/inputs/source-manifest.json",
        "raw_sha256": sha(source_raw),
        "semantic_sha256": source["manifest_sha256"],
    }
    execution_body = {
        "schema": archive.EXECUTION_SCHEMA_V4,
        "campaign_id": "campaign-a", "hosts": ["host-a"],
        "original_inputs": {"source_manifests": {
            "host-a": {
                "artifact": {
                    "path": source_pin["path"],
                    "raw_sha256": source_pin["raw_sha256"],
                },
                "semantic_sha256": source_pin["semantic_sha256"],
            },
        }},
        "execution_sources": {"host-a": {
            "source_root": "/not-opened/source",
            "git_commit": source_body["git_commit"],
            "source_tree_sha256": source_body["source_tree_sha256"],
            "build_sha256": sha(canonical(source["build"])),
        }},
        "modules": {"host-a": {relative: {
            "path": relative, "sha256": module_sha,
        }}},
    }
    execution = {
        **execution_body,
        "manifest_sha256": sha(canonical(execution_body)),
    }
    execution_raw = canonical(execution)
    context = {
        "campaign_id": "campaign-a", "host_id": "host-a",
        "source_manifest_pin": source_pin,
        "execution_manifest_pin": {
            "path": "/inputs/execution-manifest.json",
            "raw_sha256": sha(execution_raw),
            "semantic_sha256": execution["manifest_sha256"],
        },
    }
    return source_raw, context, execution_raw


def fixed_host_receipt_fixture(
    root: Path, *, state: str = "invalid_pair",
) -> dict:
    """Build structural H14 closure metadata; this is not APP execution evidence."""
    fixture = source5_fixture(root, state=state)
    job = fixture["job"]
    overlay_path = str(root / "pair" / "fixed-pair-execution-overlay.json")
    execution_path = str(root / "pair" / "fixed-pair-execution-receipt.json")
    host_receipt_path = str(root / "fixed-host-receipts" / "job.json")
    observed_path = str(root / "inputs" / "observed-host.json")
    source_manifest_path = str(root / "source.json")
    source_manifest_raw = b"source"
    source_manifest_pin = {
        "path": source_manifest_path,
        "raw_sha256": sha(source_manifest_raw),
        "semantic_sha256": sha(source_manifest_raw),
    }
    static_mount = {
        "mount_id": 41, "major_minor": "8:1", "mount_root": "/",
        "mount_point": "/tmp", "filesystem_type": "ext4",
        "mount_source": "/dev/test", "device": 8,
    }
    output_mount = {
        **static_mount, "available_bytes": 8192, "available_inodes": 128,
    }
    observed_sha = "d" * 64
    overlay_body = {
        "schema": "allocatbelt.application-fixed-pair-execution-overlay.v1",
        "campaign_id": "campaign-a", "host_id": "host-a",
        "spec": {"pin": {"path": str(root / "inputs/spec.json"),
                           "sha256": "e" * 64}, "semantic_sha256": "f" * 64},
        "plan": {"pin": {"path": fixture["plan_pin"]["path"],
                           "sha256": fixture["plan_pin"]["raw_sha256"]},
                 "semantic_sha256": fixture["plan_pin"]["semantic_sha256"]},
        "sources": {
            "manifests": {"host-a": {
                "pin": {"path": source_manifest_path,
                        "sha256": source_manifest_pin["raw_sha256"]},
                "manifest_sha256": source_manifest_pin["semantic_sha256"],
            }},
            "selected": {
                "host_id": "host-a", "root": str(root / "source"),
                "git_commit": "a" * 40, "source_tree_sha256": "b" * 64,
                "build_sha256": "c" * 64,
            },
            "campaign_artifacts_root": str(root / "artifacts"),
            "observed_host": {
                "pin": {"path": observed_path, "sha256": observed_sha},
                "host_fingerprint_sha256": "1" * 64,
                "controls_sha256": "2" * 64,
                "process_affinity": [0, 1],
                "network_namespace_inode": 9876,
            },
            "historical_runner_sha256": "3" * 64,
            "output_mount": static_mount,
        },
        "execution_source": {}, "modules": {},
        "job": {"value": job, "sha256": sha(canonical(job))},
        "runtime_bindings": {
            "pin": {"path": str(root / "inputs/runtime.json"),
                    "sha256": "4" * 64},
            "manifest_sha256": "5" * 64,
            "plan_entry_sha256": "6" * 64, "value": {},
        },
        "members": [{}, {}], "deadlines": {}, "artifact_budgets": {},
        "output_root": str(root / "pair"),
    }
    overlay = {
        **overlay_body, "overlay_sha256": sha(canonical(overlay_body)),
    }
    overlay_raw = canonical(overlay)

    status = "valid_pair" if state == "valid_pair" else "failed_or_invalid"
    execution_body = {
        "schema": "allocatbelt.application-fixed-pair-execution-receipt.v1",
        "campaign_id": "campaign-a", "host_id": "host-a",
        "run_id": job["run_id"], "status": status,
        "overlay_sha256": overlay["overlay_sha256"],
    }
    if state == "valid_pair":
        execution_body["member_attempts"] = [
            {"ordinal": ordinal, "tmpdir_final": {
                "path": str(root / f"member-{ordinal}-tmp"),
                "device": 8, "inode": 100 + ordinal, "mode": 0o700,
                "mount": static_mount, "bytes_used": 0,
                "file_count": 0, "directory_count": 0,
                "bytes_limit": 1024, "inode_limit": 64,
                "available_bytes": 4096, "available_inodes": 128,
            }}
            for ordinal in range(2)
        ]
        execution_body["construction_probes"] = [
            {"member_ordinal": ordinal, "tmpdir_final": {
                "path": str(root / f"probe-{ordinal}-tmp"),
                "device": 8, "inode": 200 + ordinal, "mode": 0o700,
                "mount": static_mount, "bytes_used": 0,
                "file_count": 0, "directory_count": 0,
                "bytes_limit": 1024, "inode_limit": 64,
                "available_bytes": 4096, "available_inodes": 128,
            }}
            for ordinal in range(2)
        ]
    execution_receipt = {
        **execution_body,
        "receipt_sha256": sha(canonical(execution_body)),
    }
    execution_raw = canonical(execution_receipt)

    host_identity_body = {
        "schema": "allocatbelt.application-fixed-pair-host-verification-identity.v1",
        "host_id": "host-a", "observed_host_raw_sha256": observed_sha,
        "process_affinity": [0, 1], "network_namespace_inode": 9876,
        "output_mount": output_mount,
    }
    host_identity = {
        **host_identity_body,
        "host_verification_sha256": sha(canonical(host_identity_body)),
    }
    host_receipt_body = {
        "schema": "allocatbelt.application-fixed-pair-host-verification.v1",
        "strict_verified": True, "qualification_eligible": False,
        "execution_ready": False, "campaign_chronology_complete": False,
        "overlay_raw_sha256": sha(overlay_raw),
        "execution_receipt_raw_sha256": sha(execution_raw),
        "execution_receipt_sha256": execution_receipt["receipt_sha256"],
        "status": status, "run_id": job["run_id"],
        "host_verification": host_identity,
    }
    host_receipt = {
        **host_receipt_body,
        "receipt_sha256": sha(canonical(host_receipt_body)),
    }
    host_raw = canonical(host_receipt)

    host_pin = {
        "path": host_receipt_path, "raw_sha256": sha(host_raw),
        "host_verification_sha256": host_receipt["receipt_sha256"],
    }
    fixture["record"] = {
        **fixture["record"],
        "evidence": {
            "overlay": {"path": overlay_path, "raw_sha256": sha(overlay_raw)},
            "receipt": {"path": execution_path,
                        "raw_sha256": sha(execution_raw)},
            "host_receipt": host_pin,
        },
    }
    body = {key: value for key, value in fixture["record"].items()
            if key != "record_sha256"}
    fixture["record"]["record_sha256"] = sha(canonical(body))
    fixture["record_raw"] = canonical(fixture["record"])
    fixture["job_record_pin"] = {
        "path": fixture["job_record_pin"]["path"],
        "raw_sha256": sha(fixture["record_raw"]),
    }
    rows = [
        {"origin_path": overlay_path, "role": "fixed_pair_artifact",
         "byte_count": len(overlay_raw), "raw_sha256": sha(overlay_raw),
         "semantic_sha256": overlay["overlay_sha256"]},
        {"origin_path": execution_path, "role": "component_receipt",
         "byte_count": len(execution_raw), "raw_sha256": sha(execution_raw),
         "semantic_sha256": execution_receipt["receipt_sha256"]},
        {"origin_path": host_receipt_path, "role": "fixed_pair_host_receipt",
         "byte_count": len(host_raw), "raw_sha256": sha(host_raw),
         "semantic_sha256": host_receipt["receipt_sha256"]},
    ]
    rows.sort(key=lambda row: row["origin_path"])
    return {
        "fixture": fixture, "context": context_for(root, fixture),
        "rows": rows, "overlay_raw": overlay_raw,
        "owner_receipts": {
            execution_path: execution_raw, host_receipt_path: host_raw,
        },
    }


def rebind_fixed_host_fixture_plan(sample: dict, plan_pin: dict) -> None:
    """Reseal synthetic fixed bytes after adding the metadata test's successor."""
    fixture = sample["fixture"]
    overlay_row = next(row for row in sample["rows"]
                       if row["role"] == "fixed_pair_artifact")
    overlay = json.loads(sample["overlay_raw"])
    overlay["plan"] = {
        "pin": {"path": plan_pin["path"],
                "sha256": plan_pin["raw_sha256"]},
        "semantic_sha256": plan_pin["semantic_sha256"],
    }
    overlay_body = {key: value for key, value in overlay.items()
                    if key != "overlay_sha256"}
    overlay["overlay_sha256"] = sha(canonical(overlay_body))
    overlay_raw = canonical(overlay)
    sample["overlay_raw"] = overlay_raw
    overlay_row.update({
        "byte_count": len(overlay_raw), "raw_sha256": sha(overlay_raw),
        "semantic_sha256": overlay["overlay_sha256"],
    })

    fixture["record"]["evidence"]["overlay"]["raw_sha256"] = sha(overlay_raw)
    execution_row = next(row for row in sample["rows"]
                         if row["role"] == "component_receipt")
    execution_raw = sample["owner_receipts"][execution_row["origin_path"]]
    execution = json.loads(execution_raw)
    execution["overlay_sha256"] = overlay["overlay_sha256"]
    execution_body = {key: value for key, value in execution.items()
                      if key != "receipt_sha256"}
    execution["receipt_sha256"] = sha(canonical(execution_body))
    execution_raw = canonical(execution)
    sample["owner_receipts"][execution_row["origin_path"]] = execution_raw
    execution_row.update({
        "byte_count": len(execution_raw), "raw_sha256": sha(execution_raw),
        "semantic_sha256": execution["receipt_sha256"],
    })
    fixture["record"]["evidence"]["receipt"]["raw_sha256"] = sha(execution_raw)
    host_row = next(row for row in sample["rows"]
                    if row["role"] == "fixed_pair_host_receipt")
    host_raw = sample["owner_receipts"][host_row["origin_path"]]
    host = json.loads(host_raw)
    host["overlay_raw_sha256"] = sha(overlay_raw)
    host["execution_receipt_raw_sha256"] = sha(execution_raw)
    host["execution_receipt_sha256"] = execution["receipt_sha256"]
    host_body = {key: value for key, value in host.items()
                 if key != "receipt_sha256"}
    host["receipt_sha256"] = sha(canonical(host_body))
    host_raw = canonical(host)
    sample["owner_receipts"][host_row["origin_path"]] = host_raw
    host_row.update({
        "byte_count": len(host_raw), "raw_sha256": sha(host_raw),
        "semantic_sha256": host["receipt_sha256"],
    })
    fixture["record"]["evidence"]["host_receipt"].update({
        "raw_sha256": sha(host_raw),
        "host_verification_sha256": host["receipt_sha256"],
    })
    body = {key: value for key, value in fixture["record"].items()
            if key != "record_sha256"}
    fixture["record"]["record_sha256"] = sha(canonical(body))
    fixture["record_raw"] = canonical(fixture["record"])
    fixture["job_record_pin"]["raw_sha256"] = sha(fixture["record_raw"])


def probe_tree_fixture(root: Path) -> dict:
    """Build canonical owner-return bytes for one regular ProbeV2 TMP child."""
    fixture = source5_fixture(root, state="valid_pair")
    context = context_for(root, fixture)
    mount = {
        "mount_id": 41, "major_minor": "8:1", "mount_root": "/",
        "mount_point": "/tmp", "filesystem_type": "ext4",
        "mount_source": "/dev/test", "device": 8,
    }

    def final_tmp(path: str, inode: int, *, bytes_used: int = 0,
                  file_count: int = 0) -> dict:
        return {
            "path": path, "device": 8, "inode": inode, "mode": 0o700,
            "mount": mount, "bytes_used": bytes_used,
            "file_count": file_count, "directory_count": 0,
            "bytes_limit": 4096, "inode_limit": 64,
            "available_bytes": 8192, "available_inodes": 128,
        }

    fixed_path = str(root / "a-fixed-pair-receipt.json")
    fixed_body = {
        "schema": "allocatbelt.application-fixed-pair-execution-receipt.v1",
        "campaign_id": "campaign-a", "host_id": "host-a",
        "run_id": fixture["job"]["run_id"], "status": "valid_pair",
        "member_attempts": [
            {"ordinal": ordinal,
             "tmpdir_final": final_tmp(
                 str(root / f"member-{ordinal}-tmp"), 100 + ordinal,
             )}
            for ordinal in range(2)
        ],
        "construction_probes": [
            {"member_ordinal": ordinal,
             "tmpdir_final": final_tmp(
                 str(root / f"probe-{ordinal}-tmp"), 200 + ordinal,
             )}
            for ordinal in range(2)
        ],
    }
    fixed = {**fixed_body,
             "receipt_sha256": sha(canonical(fixed_body))}
    fixed_raw = canonical(fixed)

    root_path = str(root / "opaque-trace")
    trace_path = str(root / "opaque-trace" / "result.bin")
    trace_raw = b"trace"
    inventory_entry = {
        "path": trace_path, "kind": "file", "uid": os.getuid(),
        "mode": 0o600, "size": len(trace_raw),
        "raw_sha256": sha(trace_raw),
    }
    inventory_body = {
        "schema": "allocatbelt.application-feedback-probe-tmpdir-inventory.v1",
        "entries": [inventory_entry],
    }
    inventory_sha = sha(canonical(inventory_body))
    inventory = {**inventory_body, "inventory_sha256": inventory_sha}
    inventory_raw = canonical(inventory)
    inventory_path = str(root / "m-probe-inventory.json")
    inventory_pin = {
        "path": inventory_path, "raw_sha256": sha(inventory_raw),
        "semantic_sha256": inventory_sha,
    }

    capture_path = str(root / "n-probe-capture-receipt.json")
    capture_body = {
        "schema": "allocatbelt.application-feedback-probe-capture.v2",
        "output_matches_probe": True, "stderr_empty": True,
        "exit_status": 0, "qualification_eligible": False,
        "execution_ready": False, "controller_chronology_proven": False,
        "tmpdir_inventory_pin": {
            "path": inventory_path, "raw_sha256": sha(inventory_raw),
            "inventory_sha256": inventory_sha,
        },
        "tmpdir_initial": {
            "path": root_path, "device": 8, "inode": 300, "mode": 0o700,
            "mount": mount, "available_bytes": 8192,
            "available_inodes": 128, "bytes_limit": 4096,
            "inode_limit": 64,
        },
        "tmpdir_final": {
            "path": root_path, "device": 8, "inode": 300, "mode": 0o700,
            "mount": mount, "bytes_used": len(trace_raw),
            "file_count": 1, "directory_count": 0,
            "bytes_limit": 4096, "inode_limit": 64,
            "available_bytes": 8192, "available_inodes": 128,
        },
        "storage_budget": {
            "tmpdir_bytes": 4096, "tmpdir_inodes": 64,
            "stdout_bytes": 1024, "stderr_bytes": 1024,
            "owner_result_bytes": 4096, "inventory_bytes": 16384,
            "failure_bytes": 1024, "receipt_bytes": 16384,
            "output_inodes": 8,
        },
    }
    capture = {**capture_body,
               "receipt_sha256": sha(canonical(capture_body))}
    capture_raw = canonical(capture)
    capture_pin = {
        "path": capture_path, "raw_sha256": sha(capture_raw),
        "semantic_sha256": capture["receipt_sha256"],
    }
    rows = [
        {"origin_path": fixed_path, "role": "component_receipt",
         "byte_count": len(fixed_raw), "raw_sha256": sha(fixed_raw),
         "semantic_sha256": fixed["receipt_sha256"]},
        {"origin_path": inventory_path,
         "role": "probe_capture_inventory_member0",
         "byte_count": len(inventory_raw), "raw_sha256": sha(inventory_raw),
         "semantic_sha256": inventory_sha},
        {"origin_path": capture_path,
         "role": "probe_capture_receipt_member0",
         "byte_count": len(capture_raw), "raw_sha256": sha(capture_raw),
         "semantic_sha256": capture["receipt_sha256"]},
        {"origin_path": trace_path, "role": "opaque_trace",
         "byte_count": len(trace_raw), "raw_sha256": sha(trace_raw),
         "semantic_sha256": None},
    ]
    rows.sort(key=lambda row: row["origin_path"])
    tree = {
        "owner_job_sha256": sha(canonical(fixture["job"])),
        "root_path": root_path, "role": "opaque_trace",
        "owner_receipt_pin": capture_pin,
        "inventory_pin": inventory_pin,
        "inventory_sha256": inventory_sha,
        "entry_count": 1, "byte_count": len(trace_raw),
        "entries": [inventory_entry],
    }
    return {
        "fixture": fixture, "context": context, "rows": rows,
        "fixed_path": fixed_path, "fixed_raw": fixed_raw,
        "capture_path": capture_path, "capture_raw": capture_raw,
        "inventory_path": inventory_path, "inventory_raw": inventory_raw,
        "trace_path": trace_path, "tree": tree,
        "owner_receipts": {fixed_path: fixed_raw,
                           capture_path: capture_raw},
        "owner_pins": {
            "component_receipt": {
                "path": fixed_path, "raw_sha256": sha(fixed_raw),
                "semantic_sha256": fixed["receipt_sha256"],
            },
            "probe_capture_receipt_member0": capture_pin,
        },
    }


class ArchiveCliTests(unittest.TestCase):
    def test_caught_input_failure_reaches_the_process_exit(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-cli-exit-") as tmp:
            missing = str(Path(tmp) / "absent")
            options = (
                "request", "request-pin", "job-record", "catalogue-chunk-map",
                "catalogue-cache-root", "dependency-local-map",
                "dependency-cache-root", "staging-root", "archive-root",
                "stage-map-path", "gpg-executable", "gpg-homedir",
            )
            argv = [sys.executable, "-B", str(ARCHIVE_PATH)]
            for option in options:
                argv.extend(["--" + option, missing])
            argv.extend(["--signer-fingerprint", "A" * 40])
            result = subprocess.run(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, check=False, timeout=10,
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, b"")
            self.assertIn(b"Source5 evidence archive failed:", result.stderr)

    def test_plan_ceiling_does_not_expand_general_metadata(self) -> None:
        raw = canonical({"value": "x" * 1024})
        with self.assertRaises(archive.EvidenceArchiveError):
            archive._parse_canonical(raw, "small metadata", maximum_bytes=512)
        self.assertEqual(
            archive._parse_canonical(raw, "PlanV3", maximum_bytes=2048),
            {"value": "x" * 1024},
        )
        self.assertEqual(archive.MAX_PLAN_BYTES, 256 * 1024 * 1024)
        self.assertEqual(archive.MAX_JSON_BYTES, 32 * 1024 * 1024)


class CheckpointRequestTests(unittest.TestCase):
    def test_root_catalogue_scan_closes_every_exact_tree_declaration(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-root-tree-catalogue-") as tmp:
            root = Path(tmp)
            origin_chunk = str(root / "catalogue.jsonl")
            tree_path = str(root / "opaque-trace")
            row = {
                "path": tree_path, "kind": "tree", "role": "opaque_trace",
                "host_id": "host-a", "max_bytes": 4096,
                "max_file_bytes": 2048, "max_inodes": 33,
                "storage_root": str(root), "owner": "probe_capture",
                "phase": "soak", "run_id": "run-a", "member_index": 0,
                "aggregate_id": None, "aggregate_max_bytes": None,
                "origin_pin": None,
            }
            raw = canonical(row)
            path = root / "catalogue.jsonl"
            path.write_bytes(raw)
            os.chmod(path, 0o600)
            descriptor = (tree_path, tree_path, origin_chunk, sha(raw),
                          len(raw), 1)
            paths = archive._opaque_tree_catalogue_paths_for_job(
                sha(b"tree-closure-budget"), [descriptor],
                {origin_chunk: str(path)}, "host-a", "soak", "run-a",
            )
            self.assertEqual(paths, {tree_path})
            self.assertEqual(
                archive._opaque_tree_catalogue_paths_for_job(
                    sha(b"tree-closure-budget"), [descriptor],
                    {origin_chunk: str(path)}, "host-a", "soak", "run-b",
                ),
                set(),
            )

    def test_request_binds_raw_plan_record_original_index_and_rows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-request-test-") as tmp:
            root = Path(tmp)
            output = private(root / "output")
            fixture = source5_fixture(root)
            context = context_for(root, fixture)
            row = {
                "origin_path": str(root / "source5" / "host-a" / "aa" /
                                    "outputs" / "result.bin"),
                "role": "normal_app_output", "byte_count": 4,
                "raw_sha256": sha(b"data"), "semantic_sha256": None,
            }
            request, request_pin = archive.build_checkpoint_request(
                context, fixture["job_record_pin"], fixture["record_raw"],
                fixture["plan_raw"], [row], {}, output / "checkpoint-request.json",
            )
            self.assertEqual(request["entries"], [row])
            self.assertNotIn(fixture["job_record_pin"]["path"],
                             [entry["origin_path"] for entry in request["entries"]])
            self.assertEqual(request["request_sha256"],
                             sha(canonical({key: value for key, value in request.items()
                                            if key != "request_sha256"})))
            self.assertEqual(request_pin["raw_sha256"],
                             sha((output / "checkpoint-request.json").read_bytes()))
            self.assertEqual(request_pin["semantic_sha256"],
                             request["request_sha256"])

    def test_filtered_plan_index_mismatch_fails_before_request_write(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-index-mismatch-") as tmp:
            root = Path(tmp)
            output = private(root / "output")
            fixture = source5_fixture(root)
            context = context_for(root, fixture)
            context["job_index"] = 1
            row = {
                "origin_path": str(root / "source5" / "host-a" / "aa" /
                                    "outputs" / "result.bin"),
                "role": "normal_app_output", "byte_count": 4,
                "raw_sha256": sha(b"data"), "semantic_sha256": None,
            }
            with self.assertRaises(archive.EvidenceArchiveError):
                archive.build_checkpoint_request(
                    context, fixture["job_record_pin"], fixture["record_raw"],
                    fixture["plan_raw"], [row], {},
                    output / "should-not-exist.json",
                )
            self.assertFalse((output / "should-not-exist.json").exists())

    def test_v2_request_closes_probe_inventory_and_fixed_probe_tmp_proofs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-probe-tree-v2-") as tmp:
            root = Path(tmp)
            output = private(root / "output")
            sample = probe_tree_fixture(root)
            fixture = sample["fixture"]
            request, request_pin = archive.build_checkpoint_request(
                sample["context"], fixture["job_record_pin"],
                fixture["record_raw"], fixture["plan_raw"], sample["rows"],
                sample["owner_receipts"], output / "request.json",
                tree_inventories=[sample["tree"]],
            )
            self.assertEqual(request["schema"], archive.REQUEST_SCHEMA_V2)
            self.assertEqual(request["tree_inventories"], [sample["tree"]])
            self.assertEqual(request_pin["semantic_sha256"],
                             request["request_sha256"])
            probe_proofs = [
                proof for proof in request["empty_tmp_proofs"]
                if proof.get("domain") == "probe_tmpdir"
            ]
            self.assertEqual([proof["member_ordinal"] for proof in probe_proofs],
                             [0, 1])
            self.assertEqual(
                {proof["owner_receipt_pin"]["path"] for proof in probe_proofs},
                {sample["fixed_path"]},
            )
            self.assertEqual(
                archive._validate_checkpoint_request(request), request,
            )

            outside = dict(sample["tree"])
            outside["entries"] = [dict(sample["tree"]["entries"][0],
                                        path=str(root / "outside.bin"))]
            with self.assertRaisesRegex(archive.EvidenceArchiveError,
                                        "outside their exact root"):
                archive._validate_tree_inventories(
                    [outside], sample["rows"], sample["owner_pins"],
                    expected_job_sha256=sample["tree"]["owner_job_sha256"],
                )

            nested = dict(sample["tree"],
                          root_path=sample["tree"]["root_path"] + "/nested")
            with self.assertRaisesRegex(archive.EvidenceArchiveError,
                                        "disjoint opaque-trace"):
                archive._validate_tree_inventories(
                    [sample["tree"], nested], sample["rows"],
                    sample["owner_pins"],
                    expected_job_sha256=sample["tree"]["owner_job_sha256"],
                )

    def test_v2_tree_file_must_have_one_exact_regular_object_row(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-probe-tree-closure-") as tmp:
            sample = probe_tree_fixture(Path(tmp))
            entries = [row for row in sample["rows"]
                       if row["origin_path"] != sample["trace_path"]]
            with self.assertRaisesRegex(archive.EvidenceArchiveError,
                                        "exact reclaimable request object"):
                archive._validate_tree_inventories(
                    [sample["tree"]], entries, sample["owner_pins"],
                    expected_job_sha256=sample["tree"]["owner_job_sha256"],
                )

    def test_empty_inventory_keeps_its_exact_v2_tree_root(self) -> None:
        tree_root = "/private/job/opaque-trace"
        inventory_path = "/private/job/probe-inventory.json"
        receipt_path = "/private/job/probe-receipt.json"
        inventory_body = {
            "schema": "allocatbelt.application-feedback-probe-tmpdir-inventory.v1",
            "entries": [],
        }
        inventory_sha = sha(canonical(inventory_body))
        inventory_raw = canonical({**inventory_body,
                                   "inventory_sha256": inventory_sha})
        inventory_pin = {
            "path": inventory_path, "raw_sha256": sha(inventory_raw),
            "semantic_sha256": inventory_sha,
        }
        receipt_pin = {
            "path": receipt_path, "raw_sha256": "a" * 64,
            "semantic_sha256": "b" * 64,
        }
        rows = [
            {"origin_path": inventory_path,
             "role": "probe_capture_inventory_member0",
             "byte_count": len(inventory_raw), "raw_sha256": sha(inventory_raw),
             "semantic_sha256": inventory_sha},
            {"origin_path": receipt_path,
             "role": "probe_capture_receipt_member0", "byte_count": 1,
             "raw_sha256": receipt_pin["raw_sha256"],
             "semantic_sha256": receipt_pin["semantic_sha256"]},
        ]
        tree = {
            "owner_job_sha256": "c" * 64, "root_path": tree_root,
            "role": "opaque_trace", "owner_receipt_pin": receipt_pin,
            "inventory_pin": inventory_pin,
            "inventory_sha256": inventory_sha,
            "entry_count": 0, "byte_count": 0, "entries": [],
        }
        checked = archive._validate_tree_inventories(
            [tree], rows, {"probe_capture_receipt_member0": receipt_pin},
            expected_job_sha256="c" * 64,
        )
        self.assertEqual(checked, [tree])

    def test_job_record_cannot_enter_reclaimable_request_rows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-local-job-record-") as tmp:
            root = Path(tmp)
            output = private(root / "output")
            fixture = source5_fixture(root)
            row = {
                "origin_path": fixture["job_record_pin"]["path"],
                "role": "source5_job_record",
                "byte_count": len(fixture["record_raw"]),
                "raw_sha256": sha(fixture["record_raw"]),
                "semantic_sha256": fixture["record"]["record_sha256"],
            }
            with self.assertRaises(archive.EvidenceArchiveError):
                archive.build_checkpoint_request(
                    context_for(root, fixture), fixture["job_record_pin"],
                    fixture["record_raw"], fixture["plan_raw"], [row], {},
                    output / "must-not-exist.json",
                )
            self.assertFalse((output / "must-not-exist.json").exists())

    def test_job_disposition_is_also_nonexportable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-local-disposition-") as tmp:
            root = Path(tmp)
            output = private(root / "output")
            fixture = source5_fixture(root)
            disposition_path = str(
                root / "source5" / "host-a" / "aa" / "job-records" /
                f"{fixture['job']['run_id']}.disposition.json"
            )
            raw = b"failure disposition remains local"
            row = {
                "origin_path": disposition_path,
                "role": "source5_job_disposition",
                "byte_count": len(raw), "raw_sha256": sha(raw),
                "semantic_sha256": None,
            }
            with self.assertRaises(archive.EvidenceArchiveError):
                archive.build_checkpoint_request(
                    context_for(root, fixture), fixture["job_record_pin"],
                    fixture["record_raw"], fixture["plan_raw"], [row], {},
                    output / "must-not-exist.json",
                )
            self.assertFalse((output / "must-not-exist.json").exists())

    def test_fixed_host_receipt_request_binds_job_record_and_owner_row(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-fixed-host-receipt-") as tmp:
            root = Path(tmp)
            output = private(root / "output")
            sample = fixed_host_receipt_fixture(root)
            fixture = sample["fixture"]
            request, _request_pin = archive.build_checkpoint_request(
                sample["context"], fixture["job_record_pin"],
                fixture["record_raw"], fixture["plan_raw"], sample["rows"],
                sample["owner_receipts"], output / "request.json",
            )
            host_row = next(row for row in sample["rows"]
                            if row["role"] == "fixed_pair_host_receipt")
            self.assertEqual(
                request["owner_receipt_pins"]["fixed_pair_host_receipt"],
                {"path": host_row["origin_path"],
                 "raw_sha256": host_row["raw_sha256"],
                 "semantic_sha256": host_row["semantic_sha256"]},
            )

            with self.assertRaisesRegex(archive.EvidenceArchiveError,
                                        "exact overlay/execution receipt rows"):
                archive.build_checkpoint_request(
                    sample["context"], fixture["job_record_pin"],
                    fixture["record_raw"], fixture["plan_raw"],
                    [row for row in sample["rows"]
                     if row["role"] != "fixed_pair_artifact"],
                    sample["owner_receipts"], output / "missing-overlay.json",
                )
            self.assertFalse((output / "missing-overlay.json").exists())

    def test_fixed_host_receipt_rechecks_observed_overlay_facts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-fixed-host-overlay-") as tmp:
            root = Path(tmp)
            sample = fixed_host_receipt_fixture(root)
            fixture = sample["fixture"]
            entries = [dict(row) for row in sample["rows"]]
            owner_receipts = dict(sample["owner_receipts"])
            host_row = next(row for row in entries
                            if row["role"] == "fixed_pair_host_receipt")
            host = json.loads(owner_receipts[host_row["origin_path"]])
            host_identity = dict(host["host_verification"])
            identity_body = {
                key: value for key, value in host_identity.items()
                if key != "host_verification_sha256"
            }
            identity_body["process_affinity"] = [2, 3]
            host["host_verification"] = {
                **identity_body,
                "host_verification_sha256": sha(canonical(identity_body)),
            }
            host_body = {key: value for key, value in host.items()
                         if key != "receipt_sha256"}
            host = {**host_body,
                    "receipt_sha256": sha(canonical(host_body))}
            host_raw = canonical(host)
            owner_receipts[host_row["origin_path"]] = host_raw
            host_row.update({
                "byte_count": len(host_raw), "raw_sha256": sha(host_raw),
                "semantic_sha256": host["receipt_sha256"],
            })
            fixture["record"]["evidence"]["host_receipt"].update({
                "raw_sha256": sha(host_raw),
                "host_verification_sha256": host["receipt_sha256"],
            })
            record_body = {key: value for key, value in fixture["record"].items()
                           if key != "record_sha256"}
            fixture["record"]["record_sha256"] = sha(canonical(record_body))
            fixture["record_raw"] = canonical(fixture["record"])
            fixture["job_record_pin"]["raw_sha256"] = sha(fixture["record_raw"])
            owner_pins = {
                row["role"]: {
                    "path": row["origin_path"],
                    "raw_sha256": row["raw_sha256"],
                    "semantic_sha256": row["semantic_sha256"],
                }
                for row in entries if archive._is_owner_receipt_role(row["role"])
            }
            with self.assertRaisesRegex(
                    archive.EvidenceArchiveError,
                    "host identity facts differ from its captured overlay"):
                archive._validate_fixed_pair_host_receipt_bindings(
                    sample["context"], fixture["record"], entries,
                    owner_pins, owner_receipt_bytes=owner_receipts,
                    overlay_raw=sample["overlay_raw"],
                )

    def test_success_request_requires_both_raw_owner_zero_usage_facts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-tmp-proof-") as tmp:
            root = Path(tmp)
            output = private(root / "output")
            fixture = source5_fixture(root, state="valid_pair")
            context = context_for(root, fixture)
            receipt_path = str(root / "fixed-pair-execution-receipt.json")
            mount = {
                "mount_id": 41, "major_minor": "8:1", "mount_root": "/",
                "mount_point": "/tmp", "filesystem_type": "ext4",
                "mount_source": "/dev/test", "device": 8,
            }

            def final_tmp(ordinal: int) -> dict:
                return {
                    "path": str(root / f"member-{ordinal}-tmp"), "device": 8,
                    "inode": 100 + ordinal, "mode": 0o700,
                    "mount": mount, "bytes_used": 0, "file_count": 0,
                    "directory_count": 0, "bytes_limit": 1024,
                    "inode_limit": 64, "available_bytes": 4096,
                    "available_inodes": 128,
                }

            receipt_body = {
                "schema": "allocatbelt.application-fixed-pair-execution-receipt.v1",
                "campaign_id": "campaign-a", "host_id": "host-a",
                "run_id": fixture["job"]["run_id"], "status": "valid_pair",
                "member_attempts": [
                    {"ordinal": 0, "tmpdir_final": final_tmp(0)},
                    {"ordinal": 1, "tmpdir_final": final_tmp(1)},
                ],
            }
            receipt = {
                **receipt_body, "receipt_sha256": sha(canonical(receipt_body)),
            }
            receipt_raw = canonical(receipt)
            receipt_pin = {
                "path": receipt_path, "raw_sha256": sha(receipt_raw),
                "semantic_sha256": receipt["receipt_sha256"],
            }
            rows = [{
                "origin_path": receipt_path, "role": "component_receipt",
                "byte_count": len(receipt_raw), "raw_sha256": sha(receipt_raw),
                "semantic_sha256": receipt["receipt_sha256"],
            }]
            request, _pin = archive.build_checkpoint_request(
                context, fixture["job_record_pin"], fixture["record_raw"],
                fixture["plan_raw"], rows, {receipt_path: receipt_raw},
                output / "checkpoint-request.json",
            )
            empty_v2_input, _empty_pin = archive.build_checkpoint_request(
                context, fixture["job_record_pin"], fixture["record_raw"],
                fixture["plan_raw"], rows, {receipt_path: receipt_raw},
                output / "checkpoint-request-empty-trees.json",
                tree_inventories=[],
            )
            self.assertEqual(request["schema"], archive.REQUEST_SCHEMA_V1)
            self.assertEqual(empty_v2_input, request)
            self.assertEqual(
                [proof["member_ordinal"] for proof in request["empty_tmp_proofs"]],
                [0, 1],
            )
            self.assertFalse(any(proof.get("domain") == "probe_tmpdir"
                                 for proof in request["empty_tmp_proofs"]))
            self.assertTrue(all(proof["owner_receipt_pin"] == receipt_pin
                                for proof in request["empty_tmp_proofs"]))

            bad_receipt = dict(receipt_body)
            bad_receipt["member_attempts"] = [
                {"ordinal": 0, "tmpdir_final": final_tmp(0)},
                {"ordinal": 1, "tmpdir_final": {
                    **final_tmp(1), "bytes_used": 1,
                }},
            ]
            bad_receipt["receipt_sha256"] = sha(canonical(bad_receipt))
            bad_raw = canonical(bad_receipt)
            bad_rows = [dict(rows[0], byte_count=len(bad_raw),
                             raw_sha256=sha(bad_raw),
                             semantic_sha256=bad_receipt["receipt_sha256"])]
            with self.assertRaises(archive.EvidenceArchiveError):
                archive.build_checkpoint_request(
                    context, fixture["job_record_pin"], fixture["record_raw"],
                    fixture["plan_raw"], bad_rows, {receipt_path: bad_raw},
                    output / "bad-request.json",
                )
            self.assertFalse((output / "bad-request.json").exists())


class FixedCheckpointRequestV3Tests(unittest.TestCase):
    """Structural archive fixture; it does not claim native APP execution."""

    def _request(self, root: Path):
        output = private(root / "output")
        sample = fixed_host_receipt_fixture(root, state="valid_pair")
        fixture = sample["fixture"]
        request, request_pin = archive.build_fixed_checkpoint_request_v3(
            sample["context"], fixture["job_record_pin"],
            fixture["record_raw"], fixture["plan_raw"], sample["rows"],
            sample["owner_receipts"], output / "fixed-request.json",
        )
        return output, sample, request, request_pin

    def test_fixed_v3_request_and_checkpoint_round_trip_four_receipt_proofs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-fixed-checkpoint-v3-") as tmp:
            root = Path(tmp)
            output, sample, request, request_pin = self._request(root)
            fixture = sample["fixture"]
            self.assertEqual(request["schema"], archive.REQUEST_SCHEMA_V3)
            self.assertEqual(set(request), {
                "schema", "context", "job_record_pin", "authorization",
                "predecessor_ack_pin", "owner_receipt_pins", "empty_tmp_proofs",
                "entries", "request_sha256",
            })
            self.assertNotIn("tree_inventories", request)
            self.assertEqual(len(request["empty_tmp_proofs"]), 4)
            self.assertEqual(
                [(proof["member_ordinal"], proof.get("domain"))
                 for proof in request["empty_tmp_proofs"]],
                [(0, None), (0, "probe_tmpdir"),
                 (1, None), (1, "probe_tmpdir")],
            )
            component_pin = request["owner_receipt_pins"]["component_receipt"]
            component_receipt = json.loads(
                sample["owner_receipts"][component_pin["path"]],
            )
            derived = archive._zero_fixed_tmp_proofs(
                component_receipt, component_pin, "component_receipt",
                include_probe_tmp_proofs=True,
            )
            derived.sort(key=lambda item: (
                item["role"], item["member_ordinal"], item.get("domain", ""),
            ))
            self.assertEqual(request["empty_tmp_proofs"], derived)
            self.assertEqual(archive._validate_checkpoint_request(request), request)
            self.assertEqual(archive._checkpoint_metadata_limit(request),
                             archive.MAX_JSON_BYTES)

            request_raw = (output / "fixed-request.json").read_bytes()
            manifest_pin = {
                "path": str(root / "archive" / "objects" / "manifest.json"),
                "raw_sha256": "a" * 64, "semantic_sha256": "b" * 64,
            }
            checkpoint, checkpoint_pin = archive.build_job_checkpoint(
                request_pin, request_raw, sample["context"],
                fixture["job_record_pin"], fixture["record_raw"],
                fixture["plan_raw"], sample["rows"],
                sample["owner_receipts"], manifest_pin,
                output / "fixed-checkpoint.json",
            )
            self.assertEqual(checkpoint["schema"], archive.CHECKPOINT_SCHEMA_V3)
            self.assertEqual(set(checkpoint), {
                "schema", "request_pin", "context", "job_record_pin",
                "authorization", "predecessor_ack_pin", "owner_receipt_pins",
                "empty_tmp_proofs", "object_manifest_pin", "entries",
                "checkpoint_sha256",
            })
            self.assertEqual(checkpoint["empty_tmp_proofs"], derived)
            self.assertEqual(archive._validate_checkpoint(checkpoint), checkpoint)
            self.assertEqual(checkpoint_pin["semantic_sha256"],
                             checkpoint["checkpoint_sha256"])
            self.assertEqual(archive._checkpoint_metadata_limit(checkpoint),
                             archive.MAX_JSON_BYTES)

            staging = root / "staging"
            staging.mkdir(mode=0o700)
            stage_rows = []
            owner_receipts = dict(sample["owner_receipts"])
            owner_receipts[next(
                row["origin_path"] for row in sample["rows"]
                if row["role"] == "fixed_pair_artifact"
            )] = sample["overlay_raw"]
            for index, entry in enumerate(checkpoint["entries"]):
                raw = owner_receipts[entry["origin_path"]]
                local = staging / f"{index:04d}"
                local.write_bytes(raw)
                local.chmod(0o600)
                info = local.lstat()
                local_pin = {
                    "path": str(local), "kind": "regular",
                    "device": info.st_dev, "inode": info.st_ino,
                    "mode": stat.S_IMODE(info.st_mode),
                    "byte_count": len(raw), "raw_sha256": sha(raw),
                }
                stage_rows.append({
                    "origin_path": entry["origin_path"],
                    "object_id": archive._object_identity(
                        entry["origin_path"], entry["raw_sha256"],
                    ),
                    "remote_object_pin": {},
                    "local_staged_file": local_pin,
                })
            verified_receipts = archive._verify_owner_receipt_bytes(
                checkpoint, {"rows": stage_rows}, str(staging), fixture["record"],
            )
            self.assertEqual(verified_receipts, sample["owner_receipts"])

            legacy, _legacy_pin = archive.build_checkpoint_request(
                sample["context"], fixture["job_record_pin"],
                fixture["record_raw"], fixture["plan_raw"], sample["rows"],
                sample["owner_receipts"], output / "legacy-request.json",
            )
            self.assertEqual(legacy["schema"], archive.REQUEST_SCHEMA_V1)
            self.assertEqual(len(legacy["empty_tmp_proofs"]), 2)
            self.assertNotIn("tree_inventories", legacy)

    def test_fixed_v3_rejects_reordered_duplicate_and_unjoined_proofs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-fixed-checkpoint-v3-negative-") as tmp:
            root = Path(tmp)
            _output, _sample, request, _request_pin = self._request(root)

            def rehash_request(value):
                body = {key: item for key, item in value.items()
                        if key != "request_sha256"}
                value["request_sha256"] = sha(canonical(body))
                return value

            reordered = dict(request)
            reordered["empty_tmp_proofs"] = list(
                reversed(request["empty_tmp_proofs"]),
            )
            with self.assertRaisesRegex(archive.EvidenceArchiveError,
                                        "not sorted unique"):
                archive._validate_checkpoint_request(rehash_request(reordered))

            duplicate = dict(request)
            duplicate["empty_tmp_proofs"] = [
                dict(proof) for proof in request["empty_tmp_proofs"]
            ]
            duplicate["empty_tmp_proofs"][1] = dict(
                duplicate["empty_tmp_proofs"][0],
            )
            with self.assertRaisesRegex(archive.EvidenceArchiveError,
                                        "four-proof fixed closure"):
                archive._validate_checkpoint_request(rehash_request(duplicate))

            malformed_ordinal = dict(request)
            malformed_ordinal["empty_tmp_proofs"] = [
                dict(proof) for proof in request["empty_tmp_proofs"]
            ]
            malformed_ordinal["empty_tmp_proofs"][0]["member_ordinal"] = "0"
            with self.assertRaisesRegex(archive.EvidenceArchiveError,
                                        "four-proof fixed closure"):
                archive._validate_checkpoint_request(
                    rehash_request(malformed_ordinal),
                )

            unjoined = dict(request)
            unjoined["empty_tmp_proofs"] = [
                {**proof, "owner_receipt_pin": dict(proof["owner_receipt_pin"])}
                for proof in request["empty_tmp_proofs"]
            ]
            unjoined["empty_tmp_proofs"][0]["owner_receipt_pin"]["raw_sha256"] = "f" * 64
            with self.assertRaisesRegex(archive.EvidenceArchiveError,
                                        "exact zero-usage owner receipt"):
                archive._validate_checkpoint_request(rehash_request(unjoined))

            boolean_count = dict(request)
            boolean_count["empty_tmp_proofs"] = [
                dict(proof) for proof in request["empty_tmp_proofs"]
            ]
            boolean_count["empty_tmp_proofs"][0]["bytes_used"] = False
            with self.assertRaisesRegex(archive.EvidenceArchiveError,
                                        "finite integer bound"):
                archive._validate_checkpoint_request(rehash_request(boolean_count))

            with_tree = dict(request, tree_inventories=[])
            with self.assertRaisesRegex(archive.EvidenceArchiveError,
                                        "unexpected field set"):
                archive._validate_checkpoint_request(rehash_request(with_tree))

            wrong_phase = dict(request)
            wrong_phase["context"] = dict(request["context"], phase="soak")
            with self.assertRaisesRegex(archive.EvidenceArchiveError,
                                        "four-proof fixed closure"):
                archive._validate_checkpoint_request(rehash_request(wrong_phase))

            failed_root = root / "failed-job"
            failed_root.mkdir(mode=0o700)
            failed = fixed_host_receipt_fixture(
                failed_root, state="invalid_pair",
            )
            failed_output = private(failed_root / "output")
            with self.assertRaisesRegex(
                archive.EvidenceArchiveError,
                "successful exact component and strict host receipts",
            ):
                archive.build_fixed_checkpoint_request_v3(
                    failed["context"], failed["fixture"]["job_record_pin"],
                    failed["fixture"]["record_raw"],
                    failed["fixture"]["plan_raw"], failed["rows"],
                    failed["owner_receipts"], failed_output / "must-not-exist.json",
                )
            self.assertFalse((failed_output / "must-not-exist.json").exists())


class ExecutionManifestSignerBindingTests(unittest.TestCase):
    def test_signer_context_must_match_the_execution_manifest_host_entry(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-signer-context-") as tmp:
            root = Path(tmp)
            fixture = source5_fixture(root)
            context = context_for(root, fixture)
            signer_pin = {
                "path": str(root / "private-signer-context.json"),
                "raw_sha256": "a" * 64,
                "semantic_sha256": "b" * 64,
            }
            host_contexts = {
                "host-a": {
                    "artifact": {
                        "path": signer_pin["path"],
                        "raw_sha256": signer_pin["raw_sha256"],
                    },
                    "semantic_sha256": signer_pin["semantic_sha256"],
                },
                "host-b": {
                    "artifact": {
                        "path": str(root / "host-b-signer-context.json"),
                        "raw_sha256": "c" * 64,
                    },
                    "semantic_sha256": "d" * 64,
                },
            }
            body = {
                "schema": "allocatbelt.application-source5-campaign-execution.v4",
                "campaign_id": "campaign-a", "hosts": ["host-a", "host-b"],
                "original_inputs": {}, "execution_sources": {},
                "modules": {}, "observed_hosts": {},
                "artifact_root": "/private/artifacts",
                "output_root": "/private/output", "phase_order": ["aa"],
                "protocol_sha256": "e" * 64,
                "qualification_eligible": False,
                "scope": "final_prepared_bounded",
                "prepared_input_generation": {},
                "prepared_capacity_registration": {},
                "archive_signer_contexts": host_contexts,
            }
            execution = {
                **body, "manifest_sha256": sha(canonical(body)),
            }
            execution_raw = canonical(execution)
            execution_pin = {
                "path": str(root / "execution-manifest.json"),
                "raw_sha256": sha(execution_raw),
                "semantic_sha256": execution["manifest_sha256"],
            }
            context["execution_manifest_pin"] = execution_pin
            self.assertEqual(
                archive._validate_execution_manifest_signer_context(
                    execution_raw, execution_pin, signer_pin, context,
                ),
                execution_pin,
            )
            with self.assertRaises(archive.EvidenceArchiveError):
                archive._validate_execution_manifest_signer_context(
                    execution_raw, execution_pin,
                    {**signer_pin, "raw_sha256": "f" * 64}, context,
                )


class ObjectCopyTests(unittest.TestCase):
    def test_stream_copy_reopens_content_addressed_object_and_literal_link(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-object-copy-") as tmp:
            root = Path(tmp)
            staging = private(root / "staging")
            archive_root = private(root / "archive")
            regular_path = staging / "regular.bin"
            regular_raw = b"already-fsynced source object\x00with bytes"
            regular_path.write_bytes(regular_raw)
            os.chmod(regular_path, 0o600)
            link_path = staging / "literal-link"
            os.symlink("target-that-is-not-followed", link_path)
            fd = archive._open_dir_path(str(archive_root),
                                        "test archive", private_final=True)
            try:
                regular_row = {
                    "origin_path": "/origin/regular.bin",
                    "role": "normal_app_output",
                    "byte_count": len(regular_raw),
                    "raw_sha256": sha(regular_raw),
                    "semantic_sha256": None,
                }
                object_id = archive._object_identity(
                    regular_row["origin_path"], regular_row["raw_sha256"],
                )
                first_pin, first_source = archive._copy_object(
                    fd, object_id, str(regular_path), str(staging), regular_row,
                )
                object_path = archive_root / "objects" / object_id
                self.assertEqual(object_path.read_bytes(), regular_raw)
                self.assertEqual(stat_mode(object_path), 0o600)
                self.assertEqual(os.stat(object_path).st_nlink, 1)
                again_pin, _again_source = archive._copy_object(
                    fd, object_id, str(regular_path), str(staging), regular_row,
                )
                self.assertEqual(first_pin, again_pin)
                self.assertEqual(first_source["kind"], "regular")

                link_raw = b"target-that-is-not-followed"
                link_row = {
                    "origin_path": "/origin/literal-link",
                    "role": "normal_app_output",
                    "byte_count": len(link_raw),
                    "raw_sha256": sha(link_raw),
                    "semantic_sha256": None,
                }
                link_object = archive._object_identity(
                    link_row["origin_path"], link_row["raw_sha256"],
                )
                archive._copy_object(
                    fd, link_object, str(link_path), str(staging), link_row,
                )
                self.assertEqual(
                    (archive_root / "objects" / link_object).read_bytes(),
                    link_raw,
                )
                self.assertTrue(link_path.is_symlink())
            finally:
                os.close(fd)

    def test_stage_path_escape_and_changed_inode_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-stage-identity-") as tmp:
            root = Path(tmp)
            stage = private(root / "stage")
            original = stage / "object.bin"
            original.write_bytes(b"pinned")
            os.chmod(original, 0o600)
            row = {"byte_count": 6, "raw_sha256": sha(b"pinned")}
            descriptor, _literal = archive._staged_descriptor(
                str(original), str(stage), row,
            )
            replacement = stage / "replacement.bin"
            replacement.write_bytes(b"pinned")
            os.chmod(replacement, 0o600)
            replacement.replace(original)
            with self.assertRaises(archive.EvidenceArchiveError):
                archive._unlink_stage_file(str(original), str(stage), descriptor)
            outside_root = private(root / "outside")
            outside = outside_root / "escape.bin"
            outside.write_bytes(b"pinned")
            os.chmod(outside, 0o600)
            with self.assertRaises(archive.EvidenceArchiveError):
                archive._staged_descriptor(str(outside), str(stage), row)


def stat_mode(path: Path) -> int:
    import stat
    return stat.S_IMODE(path.stat().st_mode)


class GpgIdentityTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("gpg") and shutil.which("gpgv") and
                         shutil.which("gpgconf"),
                         "GPG, GPGV and GPGConf are required for detached signature verification")
    def test_detached_ack_signature_uses_the_pinned_primary_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-test-key-") as tmp:
            with ExitStack() as cleanup:
                root = Path(tmp)
                home = private(root / "gnupg")
                cleanup.callback(lambda: subprocess.run(
                    ["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, check=False, timeout=30,
                ))
                key = subprocess.run(
                    ["gpg", "--batch", "--quiet", "--homedir", str(home),
                     "--pinentry-mode", "loopback", "--passphrase", "",
                     "--quick-generate-key",
                     "Source5 archive test <source5-archive@example.invalid>",
                     "ed25519", "sign", "0"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, check=False, timeout=60,
                )
                self.assertEqual(key.returncode, 0, key.stderr.decode(errors="replace"))
                listed = subprocess.run(
                    ["gpg", "--batch", "--with-colons", "--fingerprint",
                     "--list-secret-keys"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    check=False, timeout=30, env={
                        "GNUPGHOME": str(home), "LC_ALL": "C", "LANG": "C",
                    },
                )
                self.assertEqual(listed.returncode, 0, listed.stderr.decode(errors="replace"))
                fingerprints = [
                    line.split(":")[9] for line in listed.stdout.decode().splitlines()
                    if line.startswith("fpr:")
                ]
                self.assertEqual(len(fingerprints), 1)
                fingerprint = fingerprints[0]
                exported = subprocess.run(
                    ["gpg", "--batch", "--quiet", "--homedir", str(home),
                     "--export", fingerprint],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    check=False, timeout=30,
                )
                self.assertEqual(exported.returncode, 0)
                keyring = root / "trusted.gpg"
                keyring.write_bytes(exported.stdout)
                os.chmod(keyring, 0o600)
                gpgv = shutil.which("gpgv")
                gpgv_path = Path(gpgv).resolve(strict=True)
                gpgv_raw = gpgv_path.read_bytes()
                ack = canonical({"schema": "test", "durable": "all bytes reopened"})
                signature = archive._gpg_sign(ack, {
                    "gpg_executable": shutil.which("gpg"),
                    "gpg_homedir": str(home),
                    "primary_fingerprint": fingerprint,
                    "maximum_signature_bytes": 4096,
                })
                primary = archive._verify_detached_signature(ack, signature, {
                    "fingerprint": fingerprint,
                    "keyring_pin": {
                        "path": str(keyring), "raw_sha256": sha(keyring.read_bytes()),
                    },
                    "gpgv_pin": {
                        "path": str(gpgv_path),
                        "raw_sha256": sha(gpgv_raw),
                    },
                })
                self.assertEqual(primary, fingerprint)
                with self.assertRaises(archive.EvidenceArchiveError):
                    archive._verify_detached_signature(ack + b"forged", signature, {
                        "fingerprint": fingerprint,
                        "keyring_pin": {
                            "path": str(keyring),
                            "raw_sha256": sha(keyring.read_bytes()),
                        },
                        "gpgv_pin": {
                            "path": str(gpgv_path),
                            "raw_sha256": sha(gpgv_raw),
                        },
                    })
                with self.assertRaises(archive.EvidenceArchiveError):
                    archive._gpg_sign(ack, {
                        "gpg_executable": shutil.which("gpg"),
                        "gpg_homedir": str(home),
                        "primary_fingerprint": fingerprint,
                        "maximum_signature_bytes": 1,
                    })

                # Keep the origin identity while reading a distinct real capture.
                captured = private(root / "captured") / "public-keyring.gpg"
                captured.write_bytes(exported.stdout)
                captured.chmod(0o400)
                old_keyring_pin = {"path": str(keyring), "raw_sha256": sha(exported.stdout)}
                signer = {"fingerprint": fingerprint, "keyring_pin": old_keyring_pin,
                          "gpgv_pin": {"path": str(gpgv_path), "raw_sha256": sha(gpgv_raw)}}
                keyring.unlink()
                calls = []

                def captured_reader(pin, maximum):
                    self.assertEqual(pin, old_keyring_pin)
                    raw = captured.read_bytes()
                    self.assertLessEqual(len(raw), maximum)
                    calls.append(dict(pin))
                    return raw

                self.assertEqual(archive._verify_detached_signature(
                    ack, signature, signer, captured_keyring_reader=captured_reader,
                ), fingerprint)
                self.assertFalse(keyring.exists())
                self.assertEqual(calls, [old_keyring_pin])
                for changed_ack, changed_signature, reader in (
                    (ack + b"changed", signature, captured_reader),
                    (ack, b"invalid signature", captured_reader),
                    (ack, signature, lambda pin, maximum: b"wrong public keyring"),
                    (ack, signature, lambda pin, maximum: b""),
                    (ack, signature, lambda pin, maximum: bytearray(exported.stdout)),
                    (ack, signature, lambda pin, maximum: b"X" * (maximum + 1)),
                ):
                    with self.subTest(ack_changed=changed_ack != ack,
                                      signature_changed=changed_signature != signature):
                        with self.assertRaises(archive.EvidenceArchiveError):
                            archive._verify_detached_signature(
                                changed_ack, changed_signature, signer,
                                captured_keyring_reader=reader,
                            )
                with self.assertRaises(OSError):
                    archive._verify_detached_signature(ack, signature, signer)

                # A recorded read uses both captured signer tools. The old
                # executable origin is absent; verification executes only an
                # exact byte copy in the explicitly reserved private window.
                captured_gpgv_path = captured.parent / "gpgv-executable.bin"
                captured_gpgv_path.write_bytes(gpgv_raw)
                os.chmod(captured_gpgv_path, 0o400)
                historical_gpgv_path = root / "historical-gpgv-executable"
                shutil.copyfile(gpgv_path, historical_gpgv_path)
                historical_gpgv_path.chmod(stat_mode(gpgv_path))
                gpgv_origin_pin = {
                    "path": str(historical_gpgv_path),
                    "raw_sha256": sha(gpgv_raw),
                }
                historical_gpgv_path.unlink()

                def captured_gpgv_reader(pin, maximum):
                    self.assertEqual(pin, gpgv_origin_pin)
                    raw = captured_gpgv_path.read_bytes()
                    self.assertLessEqual(len(raw), maximum)
                    return raw

                gpg_auxiliary_root = private(root / "recorded-gpg-auxiliary")
                gpg_aux_space = os.statvfs(gpg_auxiliary_root)
                allocation_block = gpg_aux_space.f_frsize or gpg_aux_space.f_bsize
                file_maxima = (
                    len(gpgv_raw), len(exported.stdout), len(ack),
                    len(signature), 64 * 1024, 64 * 1024,
                )
                required_allocated = allocation_block + sum(
                    ((maximum + allocation_block - 1) // allocation_block) *
                    allocation_block for maximum in file_maxima
                )
                resource_body = {
                    "schema": archive.RECORDED_READ_GPG_RESOURCE_SCHEMA_V2,
                    "scratch_root": str(gpg_auxiliary_root),
                    "device": gpg_auxiliary_root.stat().st_dev,
                    "reserved_bytes": required_allocated,
                    "allocation_block_bytes": allocation_block,
                    "window_directory_allocated_bytes": allocation_block,
                    "required_file_bytes": sum(file_maxima),
                    "required_allocated_bytes": required_allocated,
                    "reserved_inodes": 7,
                    "maximum_gpgv_bytes": len(gpgv_raw),
                    "maximum_keyring_bytes": len(exported.stdout),
                    "maximum_ack_bytes": len(ack),
                    "maximum_signature_bytes": len(signature),
                    "maximum_stdout_bytes": 64 * 1024,
                    "maximum_stderr_bytes": 64 * 1024,
                    "maximum_window_seconds": 30,
                }
                recorded_resource = {
                    **resource_body,
                    "resource_sha256": sha(canonical(resource_body)),
                }

                sentinel = gpg_auxiliary_root / "retained-prior-window"
                sentinel.write_bytes(b"must be removed by the test operator")
                sentinel.chmod(0o600)
                descriptor_count = len(os.listdir("/proc/self/fd"))
                for attempt in range(2):
                    failed_start = time.monotonic_ns()
                    with self.assertRaises(archive.EvidenceArchiveError):
                        archive._verify_detached_signature_recorded(
                            ack, signature,
                            {"fingerprint": fingerprint,
                             "keyring_pin": old_keyring_pin,
                             "gpgv_pin": gpgv_origin_pin},
                            captured_keyring_reader=captured_reader,
                            captured_gpgv_reader=captured_gpgv_reader,
                            root_auxiliary_resource_declaration=recorded_resource,
                            operation_started_ns=failed_start,
                            window_deadline_ns=failed_start + 30_000_000_000,
                        )
                    self.assertEqual(len(os.listdir("/proc/self/fd")),
                                     descriptor_count)
                    self.assertEqual(list(gpg_auxiliary_root.iterdir()),
                                     [sentinel])
                sentinel.unlink()

                original_popen = archive.subprocess.Popen
                observed_modes = []

                def inspect_executable_mode(command, *args, **kwargs):
                    executable_info = Path(command[0]).stat()
                    modes = []
                    for descriptor_text in os.listdir("/proc/self/fd"):
                        descriptor = int(descriptor_text)
                        try:
                            info = os.fstat(descriptor)
                            if (info.st_dev, info.st_ino) == (
                                    executable_info.st_dev,
                                    executable_info.st_ino):
                                modes.append(
                                    fcntl.fcntl(descriptor, fcntl.F_GETFL) &
                                    os.O_ACCMODE,
                                )
                        except OSError:
                            continue
                    observed_modes.extend(modes)
                    self.assertTrue(modes)
                    self.assertEqual(set(modes), {os.O_RDONLY})
                    return original_popen(command, *args, **kwargs)

                started_ns = time.monotonic_ns()
                with mock.patch.object(
                        archive.subprocess, "Popen",
                        side_effect=inspect_executable_mode):
                    self.assertEqual(
                        archive._verify_detached_signature_recorded(
                            ack, signature,
                            {"fingerprint": fingerprint,
                             "keyring_pin": old_keyring_pin,
                             "gpgv_pin": gpgv_origin_pin},
                            captured_keyring_reader=captured_reader,
                            captured_gpgv_reader=captured_gpgv_reader,
                            root_auxiliary_resource_declaration=recorded_resource,
                            operation_started_ns=started_ns,
                            window_deadline_ns=started_ns + 30_000_000_000,
                        ),
                        fingerprint,
                    )
                self.assertEqual(observed_modes, [os.O_RDONLY])
                self.assertFalse(historical_gpgv_path.exists())
                self.assertEqual(list(gpg_auxiliary_root.iterdir()), [])

                unequal_body = dict(resource_body)
                unequal_body["maximum_stdout_bytes"] = 32 * 1024
                unequal_file_maxima = (
                    len(gpgv_raw), len(exported.stdout), len(ack),
                    len(signature), 32 * 1024, 64 * 1024,
                )
                unequal_required = allocation_block + sum(
                    ((maximum + allocation_block - 1) // allocation_block) *
                    allocation_block for maximum in unequal_file_maxima
                )
                unequal_body["reserved_bytes"] = unequal_required
                unequal_body["required_file_bytes"] = sum(unequal_file_maxima)
                unequal_body["required_allocated_bytes"] = unequal_required
                unequal_resource = {
                    **unequal_body,
                    "resource_sha256": sha(canonical(unequal_body)),
                }
                unequal_started = time.monotonic_ns()
                with self.assertRaises(archive.EvidenceArchiveError):
                    archive._verify_detached_signature_recorded(
                        ack, signature,
                        {"fingerprint": fingerprint,
                         "keyring_pin": old_keyring_pin,
                         "gpgv_pin": gpgv_origin_pin},
                        captured_keyring_reader=captured_reader,
                        captured_gpgv_reader=captured_gpgv_reader,
                        root_auxiliary_resource_declaration=unequal_resource,
                        operation_started_ns=unequal_started,
                        window_deadline_ns=unequal_started + 30_000_000_000,
                    )
                self.assertEqual(list(gpg_auxiliary_root.iterdir()), [])
                failed_started_ns = time.monotonic_ns()
                with self.assertRaises(archive.EvidenceArchiveError):
                    archive._verify_detached_signature_recorded(
                        ack + b"changed", signature,
                        {"fingerprint": fingerprint,
                         "keyring_pin": old_keyring_pin,
                         "gpgv_pin": gpgv_origin_pin},
                        captured_keyring_reader=captured_reader,
                        captured_gpgv_reader=captured_gpgv_reader,
                        root_auxiliary_resource_declaration=recorded_resource,
                        operation_started_ns=failed_started_ns,
                        window_deadline_ns=failed_started_ns + 30_000_000_000,
                    )
                self.assertEqual(list(gpg_auxiliary_root.iterdir()), [])


class RecordedReadPlanProjectionJoinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        plan_test_path = SCRIPT_DIR / "test-application-source5-recorded-preparation-read.py"
        spec = importlib.util.spec_from_file_location(
            "recorded_read_projection_actual_h6_fixture", plan_test_path,
        )
        if spec is None or spec.loader is None:
            raise AssertionError("cannot load the actual H6 read-plan fixture")
        cls.plan_tests_module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.plan_tests_module
        spec.loader.exec_module(cls.plan_tests_module)
        cls.plan_test_class = cls.plan_tests_module.ActualH6RecordedReadPlanTests
        cls.plan_test_class.setUpClass()
        cls.plan_test_instance = cls.plan_test_class(
            "test_actual_h5_schedule_joins_recomputed_caps_and_builds_720_windows",
        )

        source_h_path = SCRIPT_DIR / "application-source5-campaign.py"
        source_h_spec = importlib.util.spec_from_file_location(
            "recorded_read_projection_source_h", source_h_path,
        )
        if source_h_spec is None or source_h_spec.loader is None:
            raise AssertionError("cannot load the SourceH recorded-read projection")
        cls.source_h = importlib.util.module_from_spec(source_h_spec)
        sys.modules[source_h_spec.name] = cls.source_h
        source_h_spec.loader.exec_module(cls.source_h)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.plan_test_class.tearDownClass()

    def _append_synthetic_released_prefix(
        self, fixture, plan_module, context, ledger_fd, target_ordinal: int,
        deadline_ns: int,
    ) -> str:
        """Create only a test-scoped already-released plan-bound ledger prefix."""
        previous = "0" * 64
        lines = []

        def append(event) -> None:
            nonlocal previous
            body = {"previous_sha256": previous, "record": event}
            record_sha = sha(canonical(body))
            line = canonical({**body, "record_sha256": record_sha})
            self.assertLessEqual(
                len(line), context["maximum_control_line_bytes"],
            )
            lines.append(line)
            previous = record_sha

        basis, basis_pin = fixture.basis, fixture.basis_pin
        plan, plan_pin = fixture.plan, fixture.plan_pin
        for ordinal in range(target_ordinal):
            self.assertLess(time.monotonic_ns(), deadline_ns)
            chunk = fixture.window_chunk_for(ordinal)
            row = fixture.window_row_for(ordinal)
            request, request_raw, request_pin = \
                plan_module.build_recorded_preparation_read_request_v2(
                    basis, basis_pin, plan, plan_pin, ordinal, chunk,
                )
            request_pin3 = {key: request_pin[key] for key in (
                "path", "raw_sha256", "semantic_sha256",
            )}
            accepted = archive._recorded_root_control_event(
                basis, basis_pin, plan, plan_pin, row, 2 * ordinal + 1,
                "request_accepted", request_pin3, context["paths"],
            )
            append(accepted)
            # Earlier outputs are represented only as released fixture history.
            # These deterministic pins are never used as Root/H authority.
            prefix_tar_sha = sha(canonical({
                "schema": "recorded-read-test-released-prefix.v1",
                "read_ordinal": ordinal,
                "planned_tar_bytes": row["resource_bounds"]["tar_bytes"],
            }))
            legacy_response = plan_module._legacy_response(
                request["legacy_request"], prefix_tar_sha,
                row["resource_bounds"]["tar_bytes"],
            )
            legacy_response_raw = canonical(legacy_response)
            response, response_raw, _source_response_pin = \
                plan_module.build_recorded_preparation_read_response_v2(
                    request_raw, legacy_response, legacy_response_raw,
                    basis, basis_pin, plan, plan_pin, chunk,
                )
            response_pin = {
                "path": context["paths"]["response"],
                "raw_sha256": sha(response_raw),
                "semantic_sha256": response["response_sha256"],
            }
            bundle_pin = {
                "path": context["paths"]["bundle"],
                "raw_sha256": prefix_tar_sha,
                "byte_count": row["resource_bounds"]["tar_bytes"],
            }
            published = archive._recorded_root_control_event(
                basis, basis_pin, plan, plan_pin, row, 2 * ordinal + 2,
                "response_published", request_pin3, context["paths"],
                response_pin, bundle_pin,
            )
            append(published)
        prefix_raw = b"".join(lines)
        self.assertLessEqual(
            len(prefix_raw), context["maximum_control_ledger_bytes"],
        )
        if prefix_raw:
            self.assertLess(time.monotonic_ns(), deadline_ns)
            os.lseek(ledger_fd, 0, os.SEEK_SET)
            view = memoryview(prefix_raw)
            while view:
                written = os.write(ledger_fd, view)
                self.assertGreater(written, 0)
                view = view[written:]
            os.fsync(ledger_fd)
        cursor, pending, checked_previous = archive._recorded_root_control_state(
            ledger_fd, context, basis, basis_pin, plan, plan_pin, plan_module,
            deadline_ns=deadline_ns,
        )
        self.assertEqual(cursor, target_ordinal)
        self.assertIsNone(pending)
        self.assertEqual(checked_previous, previous)
        return previous

    def test_actual_h6_manifest_and_typed_cap_projection_joins(self) -> None:
        fixture = self.plan_test_instance
        plan_module = self.plan_tests_module.read_plan
        for ordinal in (0, plan_module.READ_JOB_COUNT_PER_HOST):
            with self.subTest(ordinal=ordinal):
                row = fixture.window_row_for(ordinal)
                owner = row["owner_host_id"]
                run_id = row["job"]["run_id"]
                typed_caps = fixture.readback_caps[owner][run_id]
                projected_caps = archive._recorded_read_source_cap_projection(
                    typed_caps,
                )
                self.assertEqual(projected_caps,
                                 row["recomputed_source_caps"])
                self.assertEqual(
                    archive._recorded_read_manifest_projection(row),
                    self.source_h._source5_recorded_read_manifest_projection(
                        plan_module, fixture.plan, row,
                    ),
                )
                manifest = archive._recorded_read_manifest_projection(row)
                self.assertEqual(manifest["objects"], row["objects"])
                self.assertEqual(
                    manifest["manifest_sha256"],
                    row["original_pins"]["object_manifest"]["semantic_sha256"],
                )
                cap_fields = {
                    "maximum_request_bytes": "request_bytes",
                    "maximum_response_bytes": "response_bytes",
                    "bundle_bytes": "bundle_bytes",
                    "stage_bytes": "stage_bytes",
                    "stage_inodes": "stage_inodes",
                    "object_count": "object_count",
                    "maximum_object_bytes": "maximum_object_bytes",
                    "live_window_bytes": "live_window_bytes",
                    "live_window_inodes": "live_window_inodes",
                }
                for plan_name, source_name in cap_fields.items():
                    changed = dict(typed_caps)
                    changed[source_name] += 1
                    changed_projection = archive._recorded_read_source_cap_projection(
                        changed,
                    )
                    self.assertNotEqual(changed_projection[plan_name],
                                        row["recomputed_source_caps"][plan_name])

                changed_row = copy.deepcopy(row)
                changed_row["manifest_summary"]["payload_bytes"] += 1
                with self.assertRaises(archive.EvidenceArchiveError):
                    archive._recorded_read_manifest_projection(changed_row)
                changed_row = copy.deepcopy(row)
                changed_row["objects"][0]["object_pin"]["raw_sha256"] = "f" * 64
                with self.assertRaises(archive.EvidenceArchiveError):
                    archive._recorded_read_manifest_projection(changed_row)

                source_manifest_pin = row["original_pins"]["object_manifest"]
                source_h_manifest = self.source_h._source5_recorded_read_manifest_projection(
                    plan_module, fixture.plan, row,
                )
                source_manifest_raw = \
                    self.source_h._source5_recorded_read_manifest_raw_pin_join(
                        source_h_manifest, source_manifest_pin,
                    )
                self.assertEqual(source_manifest_raw, canonical(source_h_manifest))
                crossed_source_manifest_pin = dict(source_manifest_pin)
                crossed_source_manifest_pin["raw_sha256"] = "0" * 64
                with self.assertRaises(self.source_h.Source5CampaignError):
                    self.source_h._source5_recorded_read_manifest_raw_pin_join(
                        source_h_manifest, crossed_source_manifest_pin,
                    )

        # Exercise the same wait helper after SourceH's real session creator
        # has made the eight planned directories, including slot/stage.
        basis, basis_pin = fixture.basis, fixture.basis_pin
        plan, plan_pin = fixture.plan, fixture.plan_pin
        scratch_root = Path(plan["scratch_declaration"]["root"])
        if not scratch_root.exists():
            private(scratch_root)
        started = time.monotonic_ns()
        setup_deadline = started + 120_000_000_000
        session = self.source_h._source5_recorded_read_session_documents(
            basis, basis_pin, plan, plan_pin, plan_module,
            create_missing=True, window_chunk_values=fixture.window_chunks,
            deadline_ns=setup_deadline,
        )
        session_stage = Path(plan["session_paths"]["stage"])
        self.assertTrue(session_stage.is_dir())
        self.assertEqual(list(session_stage.iterdir()), [])
        session_chunk = fixture.window_chunk_for(0)
        session_row = fixture.window_row_for(0)
        session_request, session_request_raw, session_request_pin = \
            plan_module.build_recorded_preparation_read_request_v2(
                basis, basis_pin, plan, plan_pin, 0, session_chunk,
            )
        self.source_h._source5_recorded_read_chunk_file(
            Path(session_request_pin["path"]), session_request_raw,
            "recorded-read actual-session wait request",
            allocation_block_bytes=plan["scratch_declaration"][
                "allocation_block_bytes"],
            deadline_ns=setup_deadline, sync_parent=True,
        )
        slot_root = Path(plan["session_paths"]["slot"])
        request_path = Path(session_request_pin["path"])
        response_incoming = Path(plan["session_paths"]["response_incoming"])
        response_path = Path(plan["session_paths"]["response"])
        bundle_incoming = Path(plan["session_paths"]["bundle_incoming"])
        bundle_path = Path(plan["session_paths"]["bundle"])
        for first, second in (("response", "bundle"), ("bundle", "response")):
            first_incoming = (response_incoming if first == "response"
                              else bundle_incoming)
            first_final = response_path if first == "response" else bundle_path
            second_incoming = (response_incoming if second == "response"
                               else bundle_incoming)
            second_final = response_path if second == "response" else bundle_path
            first_incoming.write_bytes((first + "-incoming").encode())
            first_incoming.chmod(0o600)
            waiter_errors = []
            waiter_done = threading.Event()

            def wait_for_actual_session_pair() -> None:
                try:
                    self.source_h._source5_wait_for_recorded_read_publication(
                        slot_root, request_path.name,
                        response_incoming.name, response_path.name,
                        bundle_incoming.name, bundle_path.name,
                        stage_name=session_stage.name,
                        request_maximum_bytes=session_row["resource_bounds"][
                            "outer_request_bytes"],
                        response_maximum_bytes=session_row["resource_bounds"][
                            "outer_response_bytes"],
                        bundle_maximum_bytes=session_row["resource_bounds"][
                            "tar_bytes"],
                        device_id=plan["scratch_declaration"]["device_id"],
                        allocation_block_bytes=plan["scratch_declaration"][
                            "allocation_block_bytes"],
                        deadline_ns=time.monotonic_ns() + 5_000_000_000,
                    )
                except BaseException as error:
                    waiter_errors.append(error)
                finally:
                    waiter_done.set()

            waiter = threading.Thread(target=wait_for_actual_session_pair)
            waiter.start()
            time.sleep(0.06)
            self.assertFalse(waiter_done.is_set())
            first_incoming.rename(first_final)
            time.sleep(0.06)
            self.assertFalse(waiter_done.is_set())
            second_incoming.write_bytes((second + "-incoming").encode())
            second_incoming.chmod(0o600)
            time.sleep(0.06)
            self.assertFalse(waiter_done.is_set())
            second_incoming.rename(second_final)
            waiter.join(timeout=2)
            self.assertFalse(waiter.is_alive())
            self.assertEqual(waiter_errors, [])
            self.assertTrue(waiter_done.is_set())
            first_final.unlink()
            second_final.unlink()
            slot_fd = os.open(slot_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(slot_fd)
            finally:
                os.close(slot_fd)
        request_path.unlink()
        request_parent_fd = os.open(
            request_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(request_parent_fd)
        finally:
            os.close(request_parent_fd)

    def test_root_output_release_rejects_foreign_pin_and_unlinks_exact_pair(self) -> None:
        fixture = self.plan_test_instance
        plan_module = self.plan_tests_module.read_plan
        basis, basis_pin = fixture.basis, fixture.basis_pin
        plan, plan_pin = fixture.plan, fixture.plan_pin
        minimum_tar_row = min(
            (row for chunk_value in fixture.window_chunks
             for row in chunk_value["rows"]),
            key=lambda value: (value["resource_bounds"]["tar_bytes"],
                               value["read_ordinal"]),
        )
        ordinal = minimum_tar_row["read_ordinal"]
        chunk = fixture.window_chunk_for(ordinal)
        row = fixture.window_row_for(ordinal)
        source_root = Path(plan["scratch_declaration"]["root"])
        if not source_root.exists():
            private(source_root)
        started = time.monotonic_ns()
        deadline = started + plan["timeout_declaration"][
            "maximum_io_window_seconds"] * 1_000_000_000
        self.source_h._source5_recorded_read_session_documents(
            basis, basis_pin, plan, plan_pin, plan_module,
            create_missing=True, window_chunk_values=fixture.window_chunks,
            deadline_ns=deadline,
        )
        request, request_raw, request_pin = \
            plan_module.build_recorded_preparation_read_request_v2(
                basis, basis_pin, plan, plan_pin, ordinal, chunk,
            )
        self.source_h._source5_recorded_read_chunk_file(
            Path(request_pin["path"]), request_raw,
            "recorded-read root-release test request",
            allocation_block_bytes=plan["scratch_declaration"][
                "allocation_block_bytes"],
            sync_parent=True,
        )

        with tempfile.TemporaryDirectory(
                prefix="source5-recorded-root-release-") as temporary:
            root = private(Path(temporary) / "root-output")
            space = os.statvfs(root)
            block = space.f_frsize or space.f_bsize
            self.assertEqual(block,
                             plan["scratch_declaration"]["allocation_block_bytes"])
            response_cap = row["resource_bounds"]["outer_response_bytes"]
            bundle_cap = row["resource_bounds"]["tar_bytes"]
            failure_cap = 64 * 1024
            line_cap = (plan["resource_projection"][
                "control_ledger_maximum_line_bytes"] + 4096)
            ledger_cap = 2 * plan_module.READ_WINDOW_COUNT * line_cap
            file_caps = (response_cap, bundle_cap, ledger_cap, failure_cap)
            file_bytes = sum(file_caps)
            file_allocated = sum(
                ((cap + block - 1) // block) * block for cap in file_caps
            )
            directory_count = 6
            directory_allocated = directory_count * block
            resource_body = {
                "schema": archive.RECORDED_READ_ROOT_OUTPUT_SCHEMA_V2,
                "root": str(root), "device": root.stat().st_dev,
                "reserved_bytes": directory_allocated + file_allocated,
                "reserved_inodes": 10,
                "allocation_block_bytes": block,
                "directory_metadata_bytes": block,
                "directory_allocated_bytes": directory_allocated,
                "required_file_bytes": file_bytes,
                "required_file_allocated_bytes": file_allocated,
                "required_allocated_bytes": directory_allocated + file_allocated,
                "maximum_response_bytes": response_cap,
                "maximum_bundle_bytes": bundle_cap,
                "maximum_control_ledger_bytes": ledger_cap,
                "maximum_control_line_bytes": line_cap,
                "failure_receipt_bytes": failure_cap,
                "maximum_window_seconds": plan["timeout_declaration"][
                    "maximum_io_window_seconds"],
            }
            resource = {
                **resource_body,
                "resource_sha256": sha(canonical(resource_body)),
            }
            context = archive._recorded_read_root_output_context(
                resource, basis, basis_pin, plan, plan_pin,
                ordinal, chunk, plan_module,
            )
            archive._prepare_recorded_read_root_output_dirs(context)
            same_device_aux = private(
                Path(temporary) / "gpg-aux-same-device",
            )
            aux_space = os.statvfs(same_device_aux)
            aux_block = aux_space.f_frsize or aux_space.f_bsize
            same_device_gpg_resource = {
                "scratch_root": str(same_device_aux),
                "device": same_device_aux.stat().st_dev,
                "allocation_block_bytes": aux_block,
                "reserved_bytes": aux_block,
                "reserved_inodes": 1,
            }
            self.assertEqual(same_device_gpg_resource["device"],
                             context["device"])
            archive._check_recorded_read_root_resource_pair(
                context, same_device_gpg_resource, deadline_ns=deadline,
            )
            original_open_dir_path = archive._open_dir_path
            acquired_gpg_fds = []

            def reject_output_root_after_gpg_open(
                    path_value, label, *, private_final):
                if label == "Root recorded-read output root":
                    raise archive.EvidenceArchiveError(
                        "injected Root output-root acquisition failure",
                    )
                descriptor = original_open_dir_path(
                    path_value, label, private_final=private_final,
                )
                if label == "Root recorded-read GPG auxiliary root":
                    acquired_gpg_fds.append(descriptor)
                return descriptor

            descriptor_count = len(os.listdir("/proc/self/fd"))
            for attempt in range(2):
                with mock.patch.object(
                        archive, "_open_dir_path",
                        side_effect=reject_output_root_after_gpg_open):
                    with self.assertRaises(archive.EvidenceArchiveError):
                        archive._check_recorded_read_root_resource_pair(
                            context, same_device_gpg_resource,
                            deadline_ns=deadline,
                        )
                self.assertEqual(len(acquired_gpg_fds), attempt + 1)
                self.assertEqual(len(os.listdir("/proc/self/fd")),
                                 descriptor_count)
                with self.assertRaises(OSError):
                    os.fstat(acquired_gpg_fds[-1])

            overcommitted_gpg_resource = dict(same_device_gpg_resource)
            overcommitted_gpg_resource["reserved_bytes"] = (
                aux_space.f_bavail * aux_block
            )
            with self.assertRaises(archive.EvidenceArchiveError):
                archive._check_recorded_read_root_resource_pair(
                    context, overcommitted_gpg_resource,
                    deadline_ns=deadline,
                )
            shared_memory_root = Path("/dev/shm")
            if shared_memory_root.is_dir():
                with tempfile.TemporaryDirectory(
                        prefix="source5-root-output-separate-device-",
                        dir=shared_memory_root) as separate_temp:
                    separate_aux = private(Path(separate_temp) / "gpg-aux")
                    separate_space = os.statvfs(separate_aux)
                    separate_block = (separate_space.f_frsize or
                                      separate_space.f_bsize)
                    if separate_aux.stat().st_dev != context["device"]:
                        archive._check_recorded_read_root_resource_pair(
                            context,
                            {"scratch_root": str(separate_aux),
                             "device": separate_aux.stat().st_dev,
                             "allocation_block_bytes": separate_block,
                             "reserved_bytes": separate_block,
                             "reserved_inodes": 1},
                            deadline_ns=deadline,
                        )
            root_ledger_fd = archive._open_recorded_read_root_ledger(context)
            try:
                previous = self._append_synthetic_released_prefix(
                    fixture, plan_module, context, root_ledger_fd, ordinal,
                    deadline,
                )
                request_pin3 = {key: request_pin[key] for key in (
                    "path", "raw_sha256", "semantic_sha256",
                )}
                first_event = archive._recorded_root_control_event(
                    basis, basis_pin, plan, plan_pin, row, 2 * ordinal + 1,
                    "request_accepted", request_pin3, context["paths"],
                )
                previous = archive._append_recorded_root_control_event(
                    root_ledger_fd, first_event, previous, context,
                    deadline_ns=deadline,
                )

                zero_block = bytes(1024 * 1024)
                tar_hasher = hashlib.sha256()
                tar_remaining = bundle_cap
                while tar_remaining:
                    amount = min(len(zero_block), tar_remaining)
                    tar_hasher.update(zero_block[:amount])
                    tar_remaining -= amount
                tar_sha256 = tar_hasher.hexdigest()
                legacy_response = plan_module._legacy_response(
                    request["legacy_request"], tar_sha256, bundle_cap,
                )
                legacy_response_raw = canonical(legacy_response)
                response, response_raw, _response_slot_pin = \
                    plan_module.build_recorded_preparation_read_response_v2(
                        request_raw, legacy_response, legacy_response_raw,
                        basis, basis_pin, plan, plan_pin, chunk,
                    )
                output_fd = archive._open_dir_path(
                    context["paths"]["slot"],
                    "Root output release test slot", private_final=True,
                )
                try:
                    response_slot = archive._write_recorded_read_output_bytes(
                        output_fd, Path(context["paths"]["response"]).name,
                        response_raw, response_cap,
                        "Root output release test response",
                        allocation_block_bytes=block, deadline_ns=deadline,
                    )
                    bundle_fd = os.open(
                        Path(context["paths"]["bundle"]).name,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                        getattr(os, "O_NOFOLLOW", 0),
                        0o600, dir_fd=output_fd,
                    )
                    try:
                        os.fchmod(bundle_fd, 0o600)
                        os.ftruncate(bundle_fd, bundle_cap)
                        os.fsync(bundle_fd)
                        bundle_info = os.fstat(bundle_fd)
                        self.assertEqual(bundle_info.st_size, bundle_cap)
                        self.assertLessEqual(
                            bundle_info.st_blocks * 512,
                            ((bundle_cap + block - 1) // block) * block,
                        )
                        os.fsync(output_fd)
                        bundle_slot = {
                            "raw_sha256": tar_sha256,
                            "byte_count": bundle_cap,
                        }
                    finally:
                        os.close(bundle_fd)
                finally:
                    os.close(output_fd)
                response_pin = {
                    "path": context["paths"]["response"],
                    "raw_sha256": response_slot["raw_sha256"],
                    "semantic_sha256": response["response_sha256"],
                }
                bundle_pin = {
                    "path": context["paths"]["bundle"],
                    "raw_sha256": bundle_slot["raw_sha256"],
                    "byte_count": bundle_slot["byte_count"],
                }
                second_event = archive._recorded_root_control_event(
                    basis, basis_pin, plan, plan_pin, row, 2 * ordinal + 2,
                    "response_published", request_pin3, context["paths"],
                    response_pin, bundle_pin,
                )
                archive._append_recorded_root_control_event(
                    root_ledger_fd, second_event, previous, context,
                    deadline_ns=deadline,
                )
            finally:
                os.close(root_ledger_fd)
            archive._verify_recorded_read_root_output_directory_growth(context)

            source_manifest_pin = basis["source_manifest_pins"][
                basis["consumer_host_id"]
            ]
            selected_source_raw = fixture.source_fixture_class.raw_reader(
                {key: source_manifest_pin[key] for key in (
                    "path", "raw_sha256",
                )},
                archive.MAX_SOURCE_MANIFEST_BYTES,
            )
            source_root_text = basis["current_roots"]["source_root"]
            foreign_response_pin = dict(response_pin)
            foreign_response_pin["raw_sha256"] = "0" * 64
            with self.assertRaises(archive.EvidenceArchiveError):
                archive.release_recorded_preparation_read_root_output_v1(
                    canonical(basis), canonical(plan), canonical(
                        plan_module.build_recorded_preparation_read_session_descriptor_v2(
                            plan, plan_pin,
                        )[0],
                    ), source_root_text, selected_source_raw, resource,
                    ordinal, foreign_response_pin, bundle_pin,
                )
            self.assertTrue(Path(response_pin["path"]).is_file())
            self.assertTrue(Path(bundle_pin["path"]).is_file())

            descriptor, descriptor_raw, _descriptor_pin = \
                plan_module.build_recorded_preparation_read_session_descriptor_v2(
                    plan, plan_pin,
                )
            released = archive.release_recorded_preparation_read_root_output_v1(
                canonical(basis), canonical(plan), descriptor_raw,
                source_root_text, selected_source_raw, resource,
                ordinal, response_pin, bundle_pin,
            )
            self.assertEqual(released["response_pin"], response_pin)
            self.assertEqual(released["bundle_pin"], bundle_pin)
            self.assertFalse(Path(response_pin["path"]).exists())
            self.assertFalse(Path(bundle_pin["path"]).exists())
            request_path = Path(request_pin["path"])
            request_path.unlink()
            request_parent_fd = os.open(
                request_path.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(request_parent_fd)
            finally:
                os.close(request_parent_fd)
class HostBudgetR6SchemaTests(unittest.TestCase):
    def _fixture(self, *, width_bound: bool):
        campaign = "campaign-a"
        host = "host-a"
        plan_pin = pinned(Path("/private/inputs/plan.json"), b"plan")
        source_pin = pinned(Path("/private/inputs/source.json"), b"source")
        signer_contexts = {
            item: {
                "artifact": {
                    "path": f"/private/inputs/{item}-signer.json",
                    "raw_sha256": sha(item.encode()),
                },
                "semantic_sha256": sha((item + "-semantic").encode()),
            } for item in ("host-a", "host-b", "host-c")
        }
        width_body = {
            "schema": "allocatbelt.application-source5-journal-width-contract.v1",
            "campaign_id": campaign, "host_id": host,
            "original_pins_sha256": "1" * 64,
            "plan_pin": plan_pin, "source_manifest_pin": source_pin,
            "owner_pins": {}, "job_rows": [], "phase_totals": [],
            "fixed_event_widths": [], "total_event_count": 1,
            "total_event_bytes": 1,
            "failed_owner_window": {"phase": "exploration"},
        }
        width_contract = {
            **width_body, "contract_sha256": sha(canonical(width_body)),
        }
        width_raw = canonical(width_contract)
        width_pin = {
            "path": "/private/artifacts/campaign-a/source5/host-a/"
                    "prepared-input/journal-width-contract.json",
            "raw_sha256": sha(width_raw),
            "semantic_sha256": width_contract["contract_sha256"],
        }
        hosts = ["host-a", "host-b", "host-c"]
        execution_body = {
            "schema": archive.EXECUTION_SCHEMA_V4,
            "campaign_id": campaign, "hosts": hosts,
            "original_inputs": {}, "execution_sources": {},
            "modules": {}, "observed_hosts": {},
            "artifact_root": "/private/artifacts",
            "output_root": "/private/output", "phase_order": [],
            "protocol_sha256": "2" * 64,
            "qualification_eligible": False,
            "scope": "final_prepared_bounded",
            "prepared_input_generation": {"completion": {}, "provenance": {}},
            "prepared_capacity_registration": {},
            "archive_signer_contexts": signer_contexts,
            "journal_width_contracts": {
                item: ({"artifact": {"path": width_pin["path"],
                                      "raw_sha256": width_pin["raw_sha256"]},
                        "semantic_sha256": width_pin["semantic_sha256"]}
                       if item == host else {
                           "artifact": {
                               "path": f"/private/inputs/{item}-width.json",
                               "raw_sha256": sha((item + "-width").encode()),
                           },
                           "semantic_sha256": sha((item + "-width-sem").encode()),
                       }) for item in hosts
            },
        }
        if not width_bound:
            del execution_body["journal_width_contracts"]
        execution = {
            **execution_body,
            "manifest_sha256": sha(canonical(execution_body)),
        }
        execution_raw = canonical(execution)
        execution_pin = {
            "path": "/private/inputs/execution.json",
            "raw_sha256": sha(execution_raw),
            "semantic_sha256": execution["manifest_sha256"],
        }
        context = {
            "campaign_id": campaign, "host_id": host,
            "plan_pin": plan_pin, "source_manifest_pin": source_pin,
            "execution_manifest_pin": execution_pin,
            "resource_budget_pin": pinned(
                Path("/private/inputs/host-budget.json"), b"budget",
            ),
        }
        original = {
            "spec": pinned(Path("/private/inputs/spec.json"), b"spec"),
            "plan": plan_pin, "execution_manifest": execution_pin,
            "source_manifests": {host: source_pin},
            "source_tree_sha256": "3" * 64,
        }
        legacy_body = {
            "schema": "allocatbelt.application-source5-host-evidence-budget.v2",
            "campaign_id": campaign, "host_id": host,
            "original_pins": original, "schedule": {}, "owner_contract": {},
            "path_catalogue": {"retention_policy": {
                "maximum_signature_bytes": 4096,
                "always_local_roles": sorted(
                    archive.ALWAYS_LOCAL_EVIDENCE_ROLES_LEGACY |
                    ({"journal_width_contract"} if width_bound else set()),
                ),
            }},
            "storage_reservation": {}, "role_byte_reservations": {},
            "transport": {},
            "execution_blockers": [
                "verified_between_pair_archive_ack_reclaim_not_integrated",
            ] if width_bound else [
                "source_derived_journal_width_not_bound",
                "verified_between_pair_archive_ack_reclaim_not_integrated",
            ],
            "readiness": {
                "budget_complete": False, "execution_ready": False,
                "component_gate_ready": False, "qualification_eligible": False,
            },
        }
        body = dict(legacy_body)
        if width_bound:
            body["execution_manifest_schema"] = archive.EXECUTION_SCHEMA_V4
            body["journal_width_contract_pin"] = width_pin
        budget = {**body, "budget_sha256": sha(canonical(body))}
        return context, budget, execution_raw, width_raw, width_pin

    def test_legacy_budget_keeps_the_exact_old_field_set_and_nonready_state(self) -> None:
        context, budget, execution_raw, _width_raw, _width_pin = self._fixture(
            width_bound=False,
        )
        self.assertEqual(set(budget), archive.HOST_BUDGET_FIELDS_LEGACY)
        parsed, is_r6 = archive._parse_host_budget_value(
            canonical(budget), "legacy host budget",
        )
        self.assertFalse(is_r6)
        self.assertFalse(parsed["readiness"]["execution_ready"])
        self.assertFalse(archive._validate_host_budget_revision(
            parsed, context, execution_manifest_raw=execution_raw,
            require_v4_manifest=False,
        ))
        extended = {**budget, "journal_width_contract_pin": None}
        extended["budget_sha256"] = sha(canonical({
            key: value for key, value in extended.items()
            if key != "budget_sha256"
        }))
        with self.assertRaises(archive.EvidenceArchiveError):
            archive._parse_host_budget_value(
                canonical(extended), "unknown hybrid budget",
            )

    def test_r6_v4_width_pin_must_match_manifest_and_raw_contract(self) -> None:
        context, budget, execution_raw, width_raw, width_pin = self._fixture(
            width_bound=True,
        )
        parsed, is_r6 = archive._parse_host_budget_value(
            canonical(budget), "R6 host budget",
        )
        self.assertTrue(is_r6)
        self.assertTrue(archive._validate_host_budget_revision(
            parsed, context, execution_manifest_raw=execution_raw,
            journal_width_contract_raw=width_raw, require_v4_manifest=True,
        ))
        changed = {**parsed,
                   "journal_width_contract_pin": {
                       **width_pin, "raw_sha256": "f" * 64,
                   }}
        with self.assertRaisesRegex(archive.EvidenceArchiveError,
                                    "width pin differs"):
            archive._validate_host_budget_revision(
                changed, context, execution_manifest_raw=execution_raw,
                journal_width_contract_raw=width_raw,
                require_v4_manifest=True,
            )
        with self.assertRaises(archive.EvidenceArchiveError):
            archive._validate_host_budget_revision(
                parsed, context, execution_manifest_raw=execution_raw,
                require_v4_manifest=True,
            )

    def test_r6_width_fields_are_rejected_for_a_legacy_manifest_marker(self) -> None:
        context, budget, _execution_raw, _width_raw, _pin = self._fixture(
            width_bound=True,
        )
        wrong = {**budget,
                 "execution_manifest_schema": archive.EXECUTION_SCHEMA_V3}
        with self.assertRaisesRegex(archive.EvidenceArchiveError,
                                    "reserved for execution manifest v4"):
            archive._validate_host_budget_revision(wrong, context)

    def test_dependency_maps_keep_legacy_three_and_v4_five_row_closures(self) -> None:
        context, _budget, _execution_raw, _width_raw, width_pin = self._fixture(
            width_bound=True,
        )
        common = [context["source_manifest_pin"], context["plan_pin"],
                  context["resource_budget_pin"]]
        legacy_pins = sorted(common, key=lambda item: item["path"])

        def local_map(pins):
            body = {
                "schema": archive.DEPENDENCY_LOCAL_MAP_SCHEMA_V1,
                "campaign_id": context["campaign_id"],
                "host_id": context["host_id"],
                "entries": [{
                    "origin_pin": item,
                    "local_path": f"/private/cache/dependency-{index}.json",
                } for index, item in enumerate(pins)],
            }
            return canonical({**body, "map_sha256": sha(canonical(body))})

        old_paths, old_pins = archive._parse_dependency_local_map_details(
            local_map(legacy_pins), context,
        )
        self.assertEqual(set(old_paths), {item["path"] for item in common})
        self.assertEqual(set(old_pins), set(old_paths))
        v4_pins = [*common, context["execution_manifest_pin"], width_pin]
        v4_paths, v4_map_pins = archive._parse_dependency_local_map_details(
            local_map(v4_pins), context,
        )
        self.assertEqual(list(v4_map_pins), [item["path"] for item in v4_pins])
        self.assertEqual(set(v4_paths), {item["path"] for item in v4_pins})
        with self.assertRaises(archive.EvidenceArchiveError):
            archive._parse_dependency_local_map_details(
                local_map(v4_pins[:4]), context,
            )


class PredecessorAckMetadataTests(unittest.TestCase):
    def test_signed_ack_is_plan_predecessor_without_payload_reopen(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-predecessor-ack-") as tmp:
            root = Path(tmp)
            host_output = private(root / "host-output")
            request_dir = private(host_output / "requests")
            sample = fixed_host_receipt_fixture(root, state="valid_pair")
            fixture = sample["fixture"]
            job = fixture["job"]
            successor_id = "campaign-host-a-aa-02"
            successor = {
                "host_id": "host-a", "phase": "aa", "ordinal": 2,
                "run_id": successor_id,
                "predecessor_run_ids": [job["run_id"]],
            }
            plan_body = {
                "schema": "allocatbelt.application-campaign-plan.v3",
                "campaign_id": "campaign-a",
                "jobs": {"aa": [job, successor]},
            }
            plan = {
                **plan_body, "plan_sha256": sha(canonical(plan_body)),
            }
            plan_raw = canonical(plan)
            plan_pin = {
                "path": str(root / "inputs" / "plan-v3.json"),
                "raw_sha256": sha(plan_raw),
                "semantic_sha256": plan["plan_sha256"],
            }
            rebind_fixed_host_fixture_plan(sample, plan_pin)
            fixture["plan"] = plan
            fixture["plan_raw"] = plan_raw
            fixture["plan_pin"] = plan_pin
            context = sample["context"]
            context["plan_pin"] = plan_pin
            context["authorized_signer_fingerprint"] = "A" * 40

            source_pin = context["source_manifest_pin"]
            width_body = {
                "schema": "allocatbelt.application-source5-journal-width-contract.v1",
                "campaign_id": "campaign-a", "host_id": "host-a",
                "original_pins_sha256": "1" * 64,
                "plan_pin": plan_pin, "source_manifest_pin": source_pin,
                "owner_pins": {}, "job_rows": [], "phase_totals": [],
                "fixed_event_widths": [], "total_event_count": 1,
                "total_event_bytes": 1,
                "failed_owner_window": {"phase": "aa"},
            }
            width_contract = {
                **width_body, "contract_sha256": sha(canonical(width_body)),
            }
            width_raw = canonical(width_contract)
            width_pin = {
                "path": str(root / "artifacts" / "journal-width.json"),
                "raw_sha256": sha(width_raw),
                "semantic_sha256": width_contract["contract_sha256"],
            }

            keyring_path = str(root / "inputs" / "public-keyring.gpg")
            gpgv_path = str(root / "inputs" / "gpgv")
            signer_body = {
                "schema": archive.SIGNER_CONTEXT_SCHEMA_V1,
                "campaign_id": "campaign-a", "host_id": "host-a",
                "authorized_primary_fingerprint": "A" * 40,
                "maximum_signature_bytes": 4096,
                "keyring_pin": {"path": keyring_path,
                                "raw_sha256": sha(b"test keyring")},
                "gpgv_pin": {"path": gpgv_path,
                             "raw_sha256": sha(b"test gpgv")},
                "signature_format": "binary_detached_primary_sha256_v1",
            }
            signer_context = {
                **signer_body,
                "signer_context_sha256": sha(canonical(signer_body)),
            }
            signer_context_raw = canonical(signer_context)
            signer_context_pin = {
                "path": str(root / "inputs" / "signer-context.json"),
                "raw_sha256": sha(signer_context_raw),
                "semantic_sha256": signer_context["signer_context_sha256"],
            }
            # This legacy V4 metadata fixture uses the original three-host
            # cohort. Only host-a is selected for this single-job read.
            peer_signer_wrappers = {}
            peer_width_wrappers = {}
            for peer in ("host-b", "host-c"):
                peer_body = {**signer_body, "host_id": peer}
                peer_value = {**peer_body,
                              "signer_context_sha256": sha(canonical(peer_body))}
                peer_raw = canonical(peer_value)
                peer_signer_wrappers[peer] = {
                    "artifact": {"path": str(root / "inputs" / (peer + "-signer.json")),
                                 "raw_sha256": sha(peer_raw)},
                    "semantic_sha256": peer_value["signer_context_sha256"],
                }
                peer_width_body = {**width_body, "host_id": peer,
                                   "source_manifest_pin": pinned(
                                       root / "inputs" / (peer + "-source.json"),
                                       (peer + "-source").encode())}
                peer_width_value = {**peer_width_body,
                                    "contract_sha256": sha(canonical(peer_width_body))}
                peer_width_raw = canonical(peer_width_value)
                peer_width_wrappers[peer] = {
                    "artifact": {"path": str(root / "artifacts" / (peer + "-width.json")),
                                 "raw_sha256": sha(peer_width_raw)},
                    "semantic_sha256": peer_width_value["contract_sha256"],
                }
            execution_body = {
                "schema": archive.EXECUTION_SCHEMA_V4,
                "campaign_id": "campaign-a", "hosts": ["host-a", "host-b", "host-c"],
                "original_inputs": {}, "execution_sources": {},
                "modules": {}, "observed_hosts": {},
                "artifact_root": str(root / "artifacts"),
                "output_root": str(host_output), "phase_order": ["aa"],
                "protocol_sha256": "2" * 64,
                "qualification_eligible": False,
                "scope": "final_prepared_bounded",
                "prepared_input_generation": {},
                "prepared_capacity_registration": {},
                "archive_signer_contexts": {
                    **peer_signer_wrappers,
                    "host-a": {
                        "artifact": {
                            "path": signer_context_pin["path"],
                            "raw_sha256": signer_context_pin["raw_sha256"],
                        },
                        "semantic_sha256":
                            signer_context_pin["semantic_sha256"],
                    },
                },
                "journal_width_contracts": {
                    **peer_width_wrappers,
                    "host-a": {
                        "artifact": {"path": width_pin["path"],
                                     "raw_sha256": width_pin["raw_sha256"]},
                        "semantic_sha256": width_pin["semantic_sha256"],
                    },
                },
            }
            execution = {
                **execution_body,
                "manifest_sha256": sha(canonical(execution_body)),
            }
            execution_raw = canonical(execution)
            execution_pin = {
                "path": str(root / "inputs" / "execution-manifest.json"),
                "raw_sha256": sha(execution_raw),
                "semantic_sha256": execution["manifest_sha256"],
            }
            context["execution_manifest_pin"] = execution_pin

            original_pins = {
                "spec": pinned(root / "inputs" / "spec.json", b"spec"),
                "plan": plan_pin,
                "execution_manifest": execution_pin,
                "source_manifests": {
                    "host-a": source_pin,
                    **{peer: pinned(root / "inputs" / (peer + "-source.json"),
                                    (peer + "-source").encode())
                       for peer in ("host-b", "host-c")},
                },
                "source_tree_sha256": "3" * 64,
            }
            catalogue_body = {
                "schema": "allocatbelt.application-source5-host-path-catalogue.v2",
                "retention_policy": {
                    "maximum_signature_bytes": 4096,
                    "always_local_roles": sorted(
                        archive.ALWAYS_LOCAL_EVIDENCE_ROLES_LEGACY |
                        {"journal_width_contract"},
                    ),
                },
            }
            catalogue = {
                **catalogue_body,
                "semantic_sha256": sha(canonical(catalogue_body)),
            }
            budget_body = {
                "schema": "allocatbelt.application-source5-host-evidence-budget.v2",
                "campaign_id": "campaign-a", "host_id": "host-a",
                "original_pins": original_pins, "schedule": {},
                "owner_contract": {}, "path_catalogue": catalogue,
                "storage_reservation": {}, "role_byte_reservations": {},
                "transport": {},
                "execution_blockers": [
                    "verified_between_pair_archive_ack_reclaim_not_integrated",
                ],
                "readiness": {
                    "budget_complete": False, "execution_ready": False,
                    "component_gate_ready": False,
                    "qualification_eligible": False,
                },
                "execution_manifest_schema": archive.EXECUTION_SCHEMA_V4,
                "journal_width_contract_pin": width_pin,
            }
            budget = {
                **budget_body, "budget_sha256": sha(canonical(budget_body)),
            }
            budget_raw = canonical(budget)
            context["resource_budget_pin"] = {
                "path": str(root / "inputs" / "host-budget.json"),
                "raw_sha256": sha(budget_raw),
                "semantic_sha256": budget["budget_sha256"],
            }

            rows = sample["rows"]
            owner_receipts = sample["owner_receipts"]
            receipt_row = next(row for row in rows
                               if row["role"] == "component_receipt")
            receipt_path = receipt_row["origin_path"]
            receipt_raw = owner_receipts[receipt_path]
            receipt = json.loads(receipt_raw)
            request, request_pin = archive.build_checkpoint_request(
                context, fixture["job_record_pin"], fixture["record_raw"],
                plan_raw, rows, owner_receipts,
                request_dir / "request.json",
            )
            self.assertIn("fixed_pair_host_receipt",
                          request["owner_receipt_pins"])
            request_raw = canonical(request)

            archive_root = root / "private-archive"
            source5_root = archive_root / "campaign-a" / "host-a" / "source5"
            private(archive_root)
            private(archive_root / "campaign-a")
            private(archive_root / "campaign-a" / "host-a")
            private(source5_root)
            job_sha = sha(canonical(job))
            leaf = f"{job['ordinal']:06d}-{job_sha}.json"
            payload_by_origin = {
                **owner_receipts,
                next(row["origin_path"] for row in rows
                     if row["role"] == "fixed_pair_artifact"):
                    sample["overlay_raw"],
            }
            object_rows = []
            object_projection = []
            payload_bytes = 0
            for row in rows:
                origin = row["origin_path"]
                raw = payload_by_origin[origin]
                raw_sha = sha(raw)
                object_id = archive._object_identity(origin, raw_sha)
                object_rows.append({
                    "origin_path": origin, "role": row["role"],
                    "object_id": object_id, "byte_count": len(raw),
                    "raw_sha256": raw_sha,
                    "semantic_sha256": row["semantic_sha256"],
                    "object_pin": {
                        "path": str(source5_root / "objects" / object_id),
                        "raw_sha256": raw_sha, "semantic_sha256": raw_sha,
                        "byte_count": len(raw),
                    },
                })
                object_projection.append({
                    "object_id": object_id,
                    "path": str(source5_root / "objects" / object_id),
                    "raw_sha256": raw_sha, "byte_count": len(raw),
                })
                payload_bytes += len(raw)
            object_manifest_body = {
                "schema": archive.OBJECT_MANIFEST_SCHEMA_V1,
                "campaign_id": "campaign-a", "host_id": "host-a",
                "phase": "aa", "job_index": 0,
                "job_ordinal": job["ordinal"], "job_sha256": job_sha,
                "run_id": job["run_id"],
                "job_record_raw_sha256": fixture["job_record_pin"]["raw_sha256"],
                "predecessor_ack_pin": None,
                "objects": object_rows,
                "object_count": len(object_rows), "payload_bytes": payload_bytes,
            }
            object_manifest = {
                **object_manifest_body,
                "manifest_sha256": sha(canonical(object_manifest_body)),
            }
            manifest_raw = canonical(object_manifest)
            manifest_pin = {
                "path": str(source5_root / "objects" / "manifests" / "aa" / leaf),
                "raw_sha256": sha(manifest_raw),
                "semantic_sha256": object_manifest["manifest_sha256"],
            }
            checkpoint_dir = private(source5_root / "checkpoints")
            checkpoint_phase_dir = private(checkpoint_dir / "aa")
            checkpoint, checkpoint_pin = archive.build_job_checkpoint(
                request_pin, request_raw, context,
                fixture["job_record_pin"], fixture["record_raw"], plan_raw,
                rows, owner_receipts, manifest_pin,
                checkpoint_phase_dir / leaf,
            )
            checkpoint_raw = canonical(checkpoint)
            checkpoint_pin["raw_sha256"] = sha(checkpoint_raw)

            ack_pin_path = str(source5_root / "acks" / "aa" / leaf)
            signature_path = str(source5_root / "acks" / "signatures" /
                                 "aa" / f"{leaf[:-5]}.sig")
            validation_pin = {
                "path": str(source5_root / "validation" / "job-records" /
                            "aa" / leaf),
                "origin_path": fixture["job_record_pin"]["path"],
                "raw_sha256": fixture["job_record_pin"]["raw_sha256"],
                "semantic_sha256": fixture["record"]["record_sha256"],
                "byte_count": len(fixture["record_raw"]),
            }
            object_reopen_sha = sha(canonical(object_projection))
            archive_directory = {
                "path": str(source5_root), "device": 1, "inode": 2,
                "mode": 0o700,
            }
            durable_base = {
                "archive_source5_directory": archive_directory,
                "job_record_validation": validation_pin,
                "checkpoint_pin": checkpoint_pin,
                "object_manifest_pin": manifest_pin,
                "object_reopen_sha256": object_reopen_sha,
                "object_count": len(object_rows), "payload_bytes": payload_bytes,
            }
            durable = {
                **durable_base,
                "commit_id": sha(canonical({
                    "checkpoint_pin": checkpoint_pin,
                    "object_manifest_pin": manifest_pin,
                    "object_reopen_sha256": object_reopen_sha,
                    "job_record_validation": validation_pin,
                })),
            }
            ack_body = {
                "schema": archive.ACK_SCHEMA_V1,
                "checkpoint_pin": checkpoint_pin,
                "object_manifest_pin": manifest_pin,
                "predecessor_ack_pin": None,
                "signer_fingerprint": "A" * 40,
                "durable_commit": durable,
            }
            ack = {**ack_body, "ack_sha256": sha(canonical(ack_body))}
            ack_raw = canonical(ack)
            ack_pin = {
                "path": ack_pin_path, "raw_sha256": sha(ack_raw),
                "semantic_sha256": ack["ack_sha256"],
            }
            signature_raw = b"synthetic detached signature for metadata-flow test"
            signature_pin = {
                "path": signature_path, "raw_sha256": sha(signature_raw),
                "signer_fingerprint": "A" * 40,
            }

            protected = (
                "_validate_host_stage_closure", "_verify_owner_receipt_bytes",
                "_staged_descriptor", "_read_staged_raw",
                "_read_absolute_private_file", "_read_object_pin",
                "_open_dir_path",
            )
            originals = {name: getattr(archive, name) for name in protected}
            old_verify = archive._verify_detached_signature
            old_fixed_host_check = archive._validate_fixed_pair_host_receipt_bindings
            calls = []
            metadata_host_checks = []

            def forbidden_payload_read(*_args, **_kwargs):
                raise AssertionError("predecessor verifier opened object payload data")

            def accepted_signature(raw_ack, raw_signature, signer):
                calls.append((raw_ack, raw_signature, signer))
                return "A" * 40

            def metadata_only_host_check(*args, **kwargs):
                self.assertIsNone(kwargs.get("owner_receipt_bytes"))
                self.assertIsNone(kwargs.get("overlay_raw"))
                self.assertIsInstance(kwargs.get("manifest_objects"), list)
                self.assertTrue(any(
                    row.get("role") == "fixed_pair_host_receipt"
                    for row in kwargs["manifest_objects"]
                ))
                metadata_host_checks.append(kwargs["manifest_objects"])
                return old_fixed_host_check(*args, **kwargs)

            for name in protected:
                setattr(archive, name, forbidden_payload_read)
            archive._verify_detached_signature = accepted_signature
            archive._validate_fixed_pair_host_receipt_bindings = \
                metadata_only_host_check
            try:
                result = archive.verify_signed_ack_for_predecessor(
                    checkpoint_pin, checkpoint, checkpoint_raw,
                    request_raw, budget_raw,
                    fixture["job_record_pin"], fixture["record_raw"], plan_raw,
                    manifest_pin, object_manifest, manifest_raw,
                    ack_pin, ack, ack_raw, signature_pin, signature_raw,
                    signer_context_pin, signer_context_raw,
                    execution_pin, execution_raw,
                    expected_ack_pin=ack_pin,
                    expected_run_id=job["run_id"],
                    successor_run_id=successor_id,
                    journal_width_contract_raw=width_raw,
                )
                self.assertEqual(result["schema"],
                                 archive.VERIFIED_PREDECESSOR_ACK_SCHEMA_V1)
                self.assertIs(result["may_reclaim"], False)
                self.assertNotIn("stage_map_pin", result)
                self.assertEqual(result["plan_predecessor"]["run_id"],
                                 job["run_id"])
                self.assertEqual(result["plan_predecessor"]["successor"]["run_id"],
                                 successor_id)
                self.assertEqual(len(calls), 1)
                self.assertEqual(len(metadata_host_checks), 1)
                read_result = archive.verify_signed_ack_for_read(
                    checkpoint_pin, checkpoint, checkpoint_raw,
                    request_raw, budget_raw,
                    fixture["job_record_pin"], fixture["record_raw"], plan_raw,
                    manifest_pin, object_manifest, manifest_raw,
                    ack_pin, ack, ack_raw, signature_pin, signature_raw,
                    signer_context_pin, signer_context_raw,
                    execution_pin, execution_raw,
                    expected_ack_pin=ack_pin,
                    expected_run_id=job["run_id"],
                    journal_width_contract_raw=width_raw,
                )
                self.assertEqual(read_result["schema"],
                                 archive.VERIFIED_READ_ACK_SCHEMA_V1)
                self.assertIs(read_result["may_read"], True)
                self.assertIs(read_result["may_reclaim"], False)
                self.assertNotIn("plan_predecessor", read_result)
                self.assertNotIn("stage_map_pin", read_result)
                self.assertEqual(read_result["job_identity"]["run_id"],
                                 job["run_id"])
                self.assertEqual(read_result["object_manifest_pin"],
                                 manifest_pin)
                self.assertEqual(len(calls), 2)
                self.assertEqual(len(metadata_host_checks), 2)
                with self.assertRaisesRegex(archive.EvidenceArchiveError,
                                            "exact original PlanV3 read job"):
                    archive.verify_signed_ack_for_read(
                        checkpoint_pin, checkpoint, checkpoint_raw,
                        request_raw, budget_raw,
                        fixture["job_record_pin"], fixture["record_raw"], plan_raw,
                        manifest_pin, object_manifest, manifest_raw,
                        ack_pin, ack, ack_raw, signature_pin, signature_raw,
                        signer_context_pin, signer_context_raw,
                        execution_pin, execution_raw,
                        expected_ack_pin=ack_pin,
                        expected_run_id="campaign-host-a-aa-99",
                        journal_width_contract_raw=width_raw,
                    )
                with self.assertRaisesRegex(archive.EvidenceArchiveError,
                                            "exact original PlanV3 predecessor"):
                    archive.verify_signed_ack_for_predecessor(
                        checkpoint_pin, checkpoint, checkpoint_raw,
                        request_raw, budget_raw,
                        fixture["job_record_pin"], fixture["record_raw"], plan_raw,
                        manifest_pin, object_manifest, manifest_raw,
                        ack_pin, ack, ack_raw, signature_pin, signature_raw,
                        signer_context_pin, signer_context_raw,
                        execution_pin, execution_raw,
                        expected_ack_pin=ack_pin,
                        expected_run_id="campaign-host-a-aa-99",
                        successor_run_id=successor_id,
                        journal_width_contract_raw=width_raw,
                    )
                wrong_ack_pin = dict(ack_pin, raw_sha256="f" * 64)
                with self.assertRaisesRegex(archive.EvidenceArchiveError,
                                            "expected predecessor ACK pin"):
                    archive.verify_signed_ack_for_predecessor(
                        checkpoint_pin, checkpoint, checkpoint_raw,
                        request_raw, budget_raw,
                        fixture["job_record_pin"], fixture["record_raw"], plan_raw,
                        manifest_pin, object_manifest, manifest_raw,
                        ack_pin, ack, ack_raw, signature_pin, signature_raw,
                        signer_context_pin, signer_context_raw,
                        execution_pin, execution_raw,
                        expected_ack_pin=wrong_ack_pin,
                        expected_run_id=job["run_id"],
                        successor_run_id=successor_id,
                        journal_width_contract_raw=width_raw,
                    )
            finally:
                for name, original in originals.items():
                    setattr(archive, name, original)
                archive._verify_detached_signature = old_verify
                archive._validate_fixed_pair_host_receipt_bindings = \
                    old_fixed_host_check


class TypedTreeCleanupTests(unittest.TestCase):
    def _tree(self, staging: Path):
        root = staging / "probe-tmp"
        nested = root / "nested"
        nested.mkdir(mode=0o700, parents=True)
        os.chmod(root, 0o700)
        os.chmod(nested, 0o700)
        payload = b"typed probe trace"
        trace = nested / "trace.bin"
        trace.write_bytes(payload)
        os.chmod(trace, 0o640)
        root_info = root.lstat()
        directory_info = nested.lstat()
        file_info = trace.lstat()
        entries = [
            {"path": str(nested), "kind": "directory",
             "uid": directory_info.st_uid,
             "mode": stat.S_IMODE(directory_info.st_mode),
             "size": None, "raw_sha256": None},
            {"path": str(trace), "kind": "file", "uid": file_info.st_uid,
             "mode": stat.S_IMODE(file_info.st_mode),
             "size": len(payload), "raw_sha256": sha(payload)},
        ]
        tree = {"root_path": str(root), "entries": entries}
        receipt = {"tmpdir_final": {
            "path": str(root), "device": root_info.st_dev,
            "inode": root_info.st_ino,
            "mode": stat.S_IMODE(root_info.st_mode),
            "mount": {}, "bytes_used": len(payload), "file_count": 1,
            "directory_count": 1, "bytes_limit": 4096,
            "inode_limit": 64, "available_bytes": 8192,
            "available_inodes": 128,
        }}
        return root, nested, trace, payload, tree, receipt

    def test_exact_tree_replay_allows_owner_mode_then_removes_only_listed_dirs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-tree-cleanup-") as tmp:
            staging = private(Path(tmp) / "stage")
            root, nested, trace, payload, tree, receipt = self._tree(staging)
            directories = archive._verify_typed_tree_on_disk(
                tree, receipt, str(staging),
            )
            descriptor, literal = archive._staged_descriptor(
                str(trace), str(staging), {
                    "byte_count": len(payload), "raw_sha256": sha(payload),
                }, expected_regular_mode=tree["entries"][1]["mode"],
            )
            self.assertIsNone(literal)
            self.assertEqual(descriptor["kind"], "regular")
            archive._unlink_stage_file(str(trace), str(staging), descriptor)
            for directory in sorted(
                    directories,
                    key=lambda item: (len(Path(item["path"]).parts),
                                      item["path"]),
                    reverse=True):
                archive._rmdir_typed_tree_directory(
                    directory["path"], str(staging), directory,
                )
            self.assertFalse(root.exists())
            self.assertFalse(nested.exists())

    def test_unlisted_tree_file_blocks_cleanup_preflight(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-tree-extra-") as tmp:
            staging = private(Path(tmp) / "stage")
            _root, _nested, trace, _payload, tree, receipt = self._tree(staging)
            extra = trace.parent / "unexpected.bin"
            extra.write_bytes(b"unlisted")
            os.chmod(extra, 0o600)
            with self.assertRaisesRegex(archive.EvidenceArchiveError,
                                        "unexpected or duplicate descendant"):
                archive._verify_typed_tree_on_disk(
                    tree, receipt, str(staging),
                )
            self.assertTrue(trace.is_file())
            self.assertTrue(extra.is_file())

    def test_missing_directory_parent_closes_staging_root_descriptor(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-tree-rootfd-closure-") as tmp:
            staging = private(Path(tmp) / "stage")
            opened: dict[str, int] = {}
            original_open = archive._open_dir_path

            def track_open(path, label, *, private_final):
                descriptor = original_open(
                    path, label, private_final=private_final,
                )
                if label == "private staging root":
                    opened["root_fd"] = descriptor
                return descriptor

            expected = {
                "path": str(staging / "missing"), "device": 1,
                "inode": 2, "uid": os.getuid(), "mode": 0o700,
            }
            with mock.patch.object(archive, "_open_dir_path", track_open), \
                    mock.patch.object(
                        archive, "_open_parent",
                        side_effect=OSError("injected parent-open failure"),
                    ):
                with self.assertRaisesRegex(OSError, "parent-open failure"):
                    archive._rmdir_typed_tree_directory(
                        expected["path"], str(staging), expected,
                    )
            with self.assertRaises(OSError):
                os.fstat(opened["root_fd"])


class BudgetV3SourceSelectionTests(unittest.TestCase):
    def test_validator_is_loaded_from_selected_typed_source_bytes(self) -> None:
        source_raw, context, execution_raw = selected_budget_source_fixture()
        namespace = archive._read_source_budget_module(
            source_raw, context, execution_raw,
        )
        self.assertTrue(callable(
            namespace["validate_host_evidence_budget_v3"],
        ))
        self.assertEqual(
            namespace["HOST_BUDGET_SCHEMA_V3"],
            "allocatbelt.application-source5-host-evidence-budget.v3",
        )
        self.assertEqual(
            namespace["__file__"],
            str(SCRIPT_DIR.parent / archive.SOURCE5_BUDGET_VALIDATOR_PATH),
        )

    def test_execution_manifest_module_pin_must_match_source_inventory(self) -> None:
        source_raw, context, execution_raw = selected_budget_source_fixture()
        execution = json.loads(execution_raw)
        execution["modules"]["host-a"][
            archive.SOURCE5_BUDGET_VALIDATOR_PATH
        ]["sha256"] = "f" * 64
        execution.pop("manifest_sha256")
        execution["manifest_sha256"] = sha(canonical(execution))
        execution_raw = canonical(execution)
        context["execution_manifest_pin"] = {
            "path": "/inputs/execution-manifest.json",
            "raw_sha256": sha(execution_raw),
            "semantic_sha256": execution["manifest_sha256"],
        }
        with self.assertRaisesRegex(
                archive.EvidenceArchiveError,
                "budget-validator module differs from the execution-manifest"):
            archive._read_source_budget_module(
                source_raw, context, execution_raw,
            )

    def test_root_catalogue_reader_uses_the_disjoint_captured_path(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-budget-row-io-") as tmp:
            root = Path(tmp)
            cache = private(root / "cache")
            local_parent = private(cache / "captured")
            local = local_parent / "chunk.jsonl"
            raw = b'{"kind":"file"}\n'
            local.write_bytes(raw)
            os.chmod(local, 0o600)
            origin_parent = private(root / "host-origin")
            origin = origin_parent / "chunk.jsonl"
            origin.write_bytes(b"wrong origin bytes")
            os.chmod(origin, 0o600)
            digest = sha(raw)
            budget = {"path_catalogue": {"chunks": [{
                "path": str(origin), "raw_sha256": digest,
                "semantic_sha256": digest, "byte_count": len(raw),
                "row_count": 1, "first_path": "/x", "last_path": "/x",
            }]}}
            reader = archive._source_budget_catalogue_reader(
                budget, {str(origin): str(local)}, str(cache), root_local=True,
            )
            self.assertEqual(reader(str(origin), len(raw)), raw)



class BudgetSchemaFieldsetCorrelationTests(unittest.TestCase):
    @staticmethod
    def _reseal(budget):
        body = {key: value for key, value in budget.items()
                if key != "budget_sha256"}
        return {**body, "budget_sha256": sha(canonical(body))}

    @classmethod
    def _ready_v3(cls, budget):
        body = {key: value for key, value in budget.items()
                if key != "budget_sha256"}
        body.update({
            "schema": archive.HOST_BUDGET_SCHEMA_V3,
            "admission_profile": archive.HOST_BUDGET_V3_ADMISSION_PROFILE,
            "execution_blockers": [],
            "readiness": {
                "budget_complete": True, "execution_ready": True,
                "component_gate_ready": False,
                "qualification_eligible": False,
            },
        })
        return cls._reseal(body)

    def _signature_limit(self, budget, context):
        raw = canonical(budget)
        context = dict(context)
        context["resource_budget_pin"] = pinned(
            Path("/private/inputs/host-budget.json"), raw,
            budget["budget_sha256"],
        )
        return archive._campaign_signature_limit(
            raw, context["resource_budget_pin"], context,
        )

    def test_campaign_signature_limit_rejects_crossed_schema_fieldsets(self) -> None:
        fixture = HostBudgetR6SchemaTests.__new__(HostBudgetR6SchemaTests)
        legacy_context, legacy, *_ = fixture._fixture(width_bound=False)
        width_context, width, *_ = fixture._fixture(width_bound=True)
        v3 = self._ready_v3(width)
        crossed = [
            ("legacy fields with v3 schema", {
                **legacy, "schema": archive.HOST_BUDGET_SCHEMA_V3,
            }, legacy_context),
            ("width-v2 fields with v3 schema", {
                **width, "schema": archive.HOST_BUDGET_SCHEMA_V3,
            }, width_context),
            ("v3 fields with v2 schema", {
                **v3, "schema": archive.HOST_BUDGET_SCHEMA_V2,
            }, width_context),
            ("v3 fields with wrong profile", {
                **v3, "admission_profile": "other_profile",
            }, width_context),
        ]
        for label, candidate, context in crossed:
            with self.subTest(label=label):
                with self.assertRaisesRegex(
                        archive.EvidenceArchiveError, "schema|profile"):
                    self._signature_limit(self._reseal(candidate), context)

    def test_v3_signature_limit_requires_selected_source_inputs(self) -> None:
        fixture = HostBudgetR6SchemaTests.__new__(HostBudgetR6SchemaTests)
        context, width, *_ = fixture._fixture(width_bound=True)
        v3 = self._ready_v3(width)
        with self.assertRaisesRegex(archive.EvidenceArchiveError, "requires"):
            self._signature_limit(v3, context)
        with self.assertRaisesRegex(
                archive.EvidenceArchiveError, "selected Source validator"):
            archive._validate_host_budget_revision(
                v3, context, validate_source_module=False,
            )

class ObjectRowV3SourceValidationTests(unittest.TestCase):
    """Check Source-selected v3 validation at the object-row boundary.

    The synthetic ready-shaped document intentionally has no complete SourceH
    path catalogue, so the selected validator must be invoked and reject at
    that numeric/input boundary. This is not a ready-budget or campaign claim.
    """

    @staticmethod
    def _sealed(body, digest_field):
        return {**body, digest_field: sha(canonical(body))}

    def test_object_rows_invoke_the_selected_source_v3_validator(self) -> None:
        fixture = HostBudgetR6SchemaTests.__new__(HostBudgetR6SchemaTests)
        (context, width_budget, _old_execution_raw, width_raw,
         width_pin) = fixture._fixture(width_bound=True)
        source_raw, source_context, _ = selected_budget_source_fixture()
        source = json.loads(source_raw)
        source_pin = source_context["source_manifest_pin"]
        module_row = source["source"]["files"][0]

        width = json.loads(width_raw)
        width_body = {key: value for key, value in width.items()
                      if key != "contract_sha256"}
        width_body["plan_pin"] = context["plan_pin"]
        width_body["source_manifest_pin"] = source_pin
        width = self._sealed(width_body, "contract_sha256")
        width_raw = canonical(width)
        width_pin = {
            "path": width_pin["path"], "raw_sha256": sha(width_raw),
            "semantic_sha256": width["contract_sha256"],
        }

        artifact_root = "/private/artifacts"
        budget_path = (
            f"{artifact_root}/campaign-a/source5/host-a/evidence-budget/"
            "host-evidence-budget-v3.json"
        )
        signer_raw = b"synthetic public signer context pin"
        signer_wrapper = {
            "artifact": {
                "path": "/private/inputs/host-a-signer-context.json",
                "raw_sha256": sha(signer_raw),
            },
            "semantic_sha256": sha(b"synthetic signer context semantic"),
        }
        execution_body = {
            "schema": archive.EXECUTION_SCHEMA_V4,
            "campaign_id": "campaign-a", "hosts": ["host-a"],
            "original_inputs": {"source_manifests": {
                "host-a": {
                    "artifact": {"path": source_pin["path"],
                                 "raw_sha256": source_pin["raw_sha256"]},
                    "semantic_sha256": source_pin["semantic_sha256"],
                },
            }},
            "execution_sources": {"host-a": {
                "source_root": "/not-opened/source",
                "git_commit": source["source"]["git_commit"],
                "source_tree_sha256": source["source"]["source_tree_sha256"],
                "build_sha256": sha(canonical(source["build"])),
            }},
            "modules": {"host-a": {module_row["path"]: {
                "path": module_row["path"],
                "sha256": module_row["sha256"],
            }}},
            "observed_hosts": {}, "artifact_root": artifact_root,
            "output_root": "/private/output", "phase_order": [],
            "protocol_sha256": "e" * 64,
            "qualification_eligible": False,
            "scope": "final_prepared_bounded",
            "prepared_input_generation": {"completion": {}, "provenance": {}},
            "prepared_capacity_registration": {},
            "archive_signer_contexts": {"host-a": signer_wrapper},
            "journal_width_contracts": {"host-a": {
                "artifact": {"path": width_pin["path"],
                             "raw_sha256": width_pin["raw_sha256"]},
                "semantic_sha256": width_pin["semantic_sha256"],
            }},
        }
        execution = self._sealed(execution_body, "manifest_sha256")
        execution_raw = canonical(execution)
        execution_pin = {
            "path": "/private/inputs/execution-manifest.json",
            "raw_sha256": sha(execution_raw),
            "semantic_sha256": execution["manifest_sha256"],
        }
        context = dict(context)
        context["source_manifest_pin"] = source_pin
        context["execution_manifest_pin"] = execution_pin

        budget_body = {key: value for key, value in width_budget.items()
                       if key != "budget_sha256"}
        original_pins = json.loads(canonical(budget_body["original_pins"]))
        original_pins["execution_manifest"] = execution_pin
        original_pins["source_manifests"]["host-a"] = source_pin
        budget_body["journal_width_contract_pin"] = width_pin
        budget_body.update({
            "schema": archive.HOST_BUDGET_SCHEMA_V3,
            "admission_profile": archive.HOST_BUDGET_V3_ADMISSION_PROFILE,
            "original_pins": original_pins,
            "execution_blockers": [],
            "readiness": {
                "budget_complete": True, "execution_ready": True,
                "component_gate_ready": False,
                "qualification_eligible": False,
            },
        })
        budget = self._sealed(budget_body, "budget_sha256")
        budget_raw = canonical(budget)
        context["resource_budget_pin"] = {
            "path": budget_path, "raw_sha256": sha(budget_raw),
            "semantic_sha256": budget["budget_sha256"],
        }

        selected_loader = archive._read_source_budget_module
        selected_calls = []

        def observe_selected_loader(*args):
            namespace = selected_loader(*args)
            selected_validator = namespace["validate_host_evidence_budget_v3"]

            def observe_selected_validator(value, *,
                                           journal_width_contract_raw,
                                           catalogue_row_reader):
                selected_calls.append({
                    "value": value,
                    "width_raw": journal_width_contract_raw,
                    "row_reader": catalogue_row_reader,
                })
                return selected_validator(
                    value,
                    journal_width_contract_raw=journal_width_contract_raw,
                    catalogue_row_reader=catalogue_row_reader,
                )

            namespace["validate_host_evidence_budget_v3"] =                 observe_selected_validator
            return namespace

        with mock.patch.object(
                archive, "_read_source_budget_module",
                side_effect=observe_selected_loader),              mock.patch.object(
                archive, "_source_budget_catalogue_reader",
                return_value=lambda _origin, _byte_count: b"") as row_reader:
            with self.assertRaisesRegex(
                    archive.EvidenceArchiveError,
                    "selected Source5 host-budget v3 validator rejected"):
                archive._validate_host_budget_object_rows(
                    budget_raw, context, {}, [],
                    {"path": "/private/output/job.json",
                     "raw_sha256": "a" * 64},
                    1, "b" * 64, {}, "/private/cache",
                    source_manifest_raw=source_raw,
                    execution_manifest_raw=execution_raw,
                    journal_width_contract_raw=width_raw,
                )
        self.assertEqual(len(selected_calls), 1)
        self.assertEqual(selected_calls[0]["value"], budget)
        self.assertEqual(selected_calls[0]["width_raw"], width_raw)
        self.assertIsNotNone(selected_calls[0]["row_reader"])
        row_reader.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
