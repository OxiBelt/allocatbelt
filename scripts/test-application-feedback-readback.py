#!/usr/bin/env python3
"""Focused native fixtures for the application feedback trace reader.

Run only on the designated SSH-MCP native host. Fixtures are synthetic trace
artifacts; they do not launch an application or establish performance.
"""
from __future__ import annotations

import hashlib
import contextlib
import importlib.util
import inspect
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch


SCRIPT_DIR = Path(__file__).resolve().parent
READER_PATH = SCRIPT_DIR / "application-feedback-readback.py"
PRESSURE_READER_PATH = SCRIPT_DIR / "application-pressure-readback.py"
CAMPAIGN_PATH = SCRIPT_DIR / "application-campaign.py"


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


reader = _load("application_feedback_readback_test_target", READER_PATH)
FEEDBACK_OFFLINE_FIXTURE_SCHEMA = "allocatbelt.application-feedback-offline-fixture.v1"
campaign = _load("application_campaign_feedback_fixture", CAMPAIGN_PATH)
pressure_pair = _load(
    "application_pressure_pair_feedback_capture_test_target",
    SCRIPT_DIR / "application-pressure-pair.py",
)


def _source_v5_manifest(identity: dict[str, Any]) -> dict[str, Any]:
    inputs = campaign.campaign_inputs_module()
    inventory = campaign.source_inventory_module()
    source_root = SCRIPT_DIR.parent
    relative_paths = set(reader.CONSTRUCTION_PROBE_SOURCE_REFERENCES.values())
    relative_paths.update(inputs.HARNESS_PATHS.values())
    relative_paths.update((
        "scripts/application-campaign-inputs.py",
        "scripts/application-source-inventory.py",
        "scripts/application-runtime-readback.py",
        inputs.FEEDBACK_RUNTIME_PATH,
        inputs.FEEDBACK_POLICY_PATH,
        inputs.FEEDBACK_SENSOR_PATH,
    ))
    files = []
    for relative in sorted(relative_paths, key=lambda value: value.encode("utf-8")):
        path = source_root / relative
        raw = path.read_bytes()
        info = path.stat(follow_symlinks=False)
        files.append({
            "path": relative, "kind": "file",
            "mode": "100755" if info.st_mode & 0o111 else "100644",
            "sha256": _sha(raw), "size": len(raw),
        })
    source_tree = inventory.digest_records(files)
    source = {
        "git_commit": "synthetic-source-v5",
        "source_tree_sha256": source_tree,
        "cargo_lock_sha256": "d" * 64,
        "files": files,
    }
    build = {
        "host_id": identity["host_id"], "rustc_release": "1.99.0", "rustc_verbose": [],
        "cargo_version": "cargo 1.99.0", "target_triple": "x86_64-unknown-linux-gnu",
        "target_cpu": "x86-64-v3", "profile": "release", "features_sha256": "e" * 64,
        "build_inputs_sha256": "f" * 64,
    }
    identity["source_sha256"] = source_tree
    artifacts = {
        "allocatbelt": {"path": "target/release/liballocatbelt.so", "sha256": identity["binary_sha256"]},
        "mimalloc-secure": {"path": "target/release/libmimalloc-secure.so", "sha256": "1" * 64},
        "mimalloc-standard": {"path": "target/release/libmimalloc-standard.so", "sha256": "2" * 64},
        "system": {"path": "target/release/libsystem.so", "sha256": "3" * 64},
    }
    harness = {
        name: {"path": relative, "sha256": next(item["sha256"] for item in files if item["path"] == relative)}
        for name, relative in inputs.HARNESS_PATHS.items()
    }
    fixed_policy = campaign.fixed_runtime_policy_artifact(
        next(item["sha256"] for item in files if item["path"] == "scripts/application-runtime-readback.py")
    )
    feedback_policy = inputs.build_feedback_policy_artifact(source_root, files, harness)
    baseline = 8192
    calibration_record = {
        "schema": campaign.CALIBRATION_SCHEMA, "architecture": "x86_64",
        "max_tenants": campaign.RUNTIME_FIXED_CONTROL_MAX_TENANTS,
        "max_waiters": campaign.RUNTIME_FIXED_CONTROL_MAX_WAITERS,
        "control_ceiling": campaign.RUNTIME_APPLICATION_CONTROL_CEILING,
        "fixed_global_control_baseline": baseline, "tenant_owner_control_bytes": 4096,
        "final_live_tenants": 0, "final_global_control_bytes": baseline,
    }
    manifest = {
        "schema": reader.SOURCE_MANIFEST_SCHEMA_V5,
        "source": source,
        "build": build,
        "artifacts": artifacts,
        "soak_artifacts": {"allocatbelt": {"path": "target/soak/allocatbelt", "sha256": "4" * 64}},
        "analysis_artifact": {"path": "target/release/analyzer", "sha256": "5" * 64},
        "fixed_runtime_policy": fixed_policy,
        "runtime_readback_validator": {
            "path": "scripts/application-runtime-readback.py",
            "sha256": next(item["sha256"] for item in files if item["path"] == "scripts/application-runtime-readback.py"),
        },
        "resource_domain_calibration": {
            "binary": {"path": "target/calibration/control", "sha256": "6" * 64},
            "output": {"path": "target/calibration/control.json", "sha256": "7" * 64},
            "record": calibration_record,
            "source": {key: source[key] for key in ("git_commit", "source_tree_sha256", "cargo_lock_sha256")},
            "build": build,
            "build_sha256": campaign.digest_object(build),
        },
        "qualification_harness": harness,
        "feedback_policy": feedback_policy,
    }
    manifest["manifest_sha256"] = campaign.digest_object(manifest)
    return manifest


def _v4_policy_from_source(
    identity: dict[str, Any], source: dict[str, Any], control_charge_bytes: int = 4096,
) -> dict[str, Any]:
    feedback = source["feedback_policy"]["policy"]
    context = feedback["contexts"][f"{identity['workload']}/{identity['profile']}"]
    fixed = source["fixed_runtime_policy"]["policy"]
    fixed_workload = fixed["workloads"][identity["workload"]]
    worker_count = context["workers"]
    global_ceilings = dict(fixed_workload["domain_ceiling"])
    global_ceilings["cpu"] = worker_count
    return {
        "version": feedback["version"],
        **feedback["reader_contract"],
        "controls": context["controls"],
        "capacity_sources": {"disk": False, "download": False},
        "global_ceilings": global_ceilings,
        "tenant_ceilings": dict(global_ceilings),
        "scope_limits": {
            "managed_memory": fixed_workload["scope_limits"]["managed_memory_limit"],
            "disk_operations": fixed_workload["scope_limits"]["disk_operation_limit"],
            "network_operations": fixed_workload["scope_limits"]["network_operation_limit"],
        },
        "rate_buckets": {
            direction: {
                "ceiling_bytes_per_second": item["ceiling_bytes_per_second"],
                "ceiling_burst_bytes": item["ceiling_burst_bytes"],
                "max_reservations": item["max_reservations"],
            }
            for direction, item in fixed["byte_buckets"].items()
        },
        "meter_source_bounds": reader.meter_source_bounds_for_workload(identity["workload"]),
        "collector": {
            "task_lease_count": 1,
            "control_charge_bytes": control_charge_bytes,
            "expected_global_control_baseline": source["resource_domain_calibration"]["record"]["fixed_global_control_baseline"],
        },
    }


class Fixture:
    def __init__(
        self, root: Path, workload: str = "disk", *, profile: str | None = None,
        capacity_trace: bool = False,
    ):
        self.root = root
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.capacity_trace = capacity_trace
        self.trace = root / "feedback-trace"
        self.trace.mkdir(mode=0o700)
        self.identity = {
            "host_id": "agent-9700x",
            "run_id": "feedback-run-01",
            "report_nonce": "0123456789abcdef0123456789abcdef",
            "process_id": 42424,
            "allocator": "allocatbelt",
            "executor": "tokio-1.53.1",
            "workload": workload,
            "profile": profile or ("mixed" if workload == "mixed" else "steady"),
            "mode": "capacity",
            "source_sha256": "a" * 64,
            "binary_sha256": "b" * 64,
            "pressure_qualification": False,
        }
        self.policy = self._policy(workload)
        self.construction_probe_path = root / "feedback-policy-probe.json"
        probe_bytes = reader.canonical_bytes(self._construction_probe())
        self.construction_probe_path.write_bytes(probe_bytes)
        self.construction_probe_pin = {
            "path": str(self.construction_probe_path), "raw_sha256": _sha(probe_bytes),
            "allocator": self.identity["allocator"], "binary_sha256": self.identity["binary_sha256"],
        }
        self.source_path = root / "source-manifest.json"
        self._write_source_manifest()
        body = {
            "schema": reader.EXPECTATION_SCHEMA,
            "construction_probe": dict(self.construction_probe_pin),
            "mode": "capacity_calibration",
            "identity": dict(self.identity),
            "policy": self.policy,
            "app_capacity_artifact_sha256": None,
            "host_binding": {"path": str(self.source_path), "raw_sha256": _sha(self.source_path.read_bytes())},
            "external_pressure_proof": None,
            "final_runtime_binding": None,
            "minimum_production_seconds": 1,
            "minimum_pressure_overlap_seconds": 0,
        }
        self.expectation_bytes, self.expectation_sha = reader.build_pressure_expectation_recipe(body)
        self.expectation_path = root / "feedback-expectation.json"
        self.expectation_path.write_bytes(self.expectation_bytes)
        self._write_trace()

    def _construction_probe(self) -> dict[str, Any]:
        workload = self.identity["workload"]
        disk_sources = workload in ("disk", "mixed")
        http_sources = workload in ("http", "mixed")
        policy = self.policy
        return {
            "schema": reader.CONSTRUCTION_PROBE_SCHEMA,
            "context": {
                "workload": workload, "profile": self.identity["profile"],
                "workers": 2 if self.identity["profile"] == "oversubscribed" else 4,
            },
            "reader_context": {
                "version": policy["version"],
                "minimum_dense_observations": policy["minimum_dense_observations"],
                "sample_interval_ns": policy["sample_interval_ns"],
                "max_dense_gap_ns": policy["max_dense_gap_ns"],
                "required_breach_samples": policy["required_breach_samples"],
                "telemetry_freshness_ns": policy["telemetry_freshness_ns"],
                "actuation_cooldown_ns": policy["actuation_cooldown_ns"],
            },
            "rust_control_context": {
                "algorithm": {
                    "cpu_reduction_rule": "floor_current_limit_over_10_zero_is_quantized",
                    "cpu_recovery_increment": 1,
                    "network_sensor_source": "download_application_bytes_only",
                    "upload_controlled": False,
                },
                "controls": policy["controls"],
                "global_ceilings": policy["global_ceilings"],
                "tenant_ceilings": policy["tenant_ceilings"],
                "scope_limits": policy["scope_limits"],
                "rate_buckets": {
                    direction: {
                        "ceiling_bytes_per_second": item["ceiling_bytes_per_second"],
                        "ceiling_burst_bytes": item["ceiling_burst_bytes"],
                        "max_reservations": item["max_reservations"],
                    }
                    for direction, item in policy["rate_buckets"].items()
                },
                "required_byte_sources": {"disk": disk_sources, "download": http_sources},
            },
            "collector": {
                "control_charge_bytes": policy["collector"]["control_charge_bytes"],
                "task_lease_count": policy["collector"]["task_lease_count"],
            },
            "baseline": {
                "expected_global_control_baseline": policy["collector"]["expected_global_control_baseline"],
            },
            "meter_source_bounds": policy["meter_source_bounds"],
            "meter_source_model": {
                "disk_registration_owner": "one shared FsRateControl owner; clones retain its single registration",
                "disk_source_path": "crates/allocatbelt/src/runtime/fs_rate.rs",
                "http_client_window": 8,
                "http_handler_window": 8,
                "http_client_window_source": "bench/src/application.rs::WINDOW",
                "http_handler_window_source": "bench/src/application/http.rs::{CLIENT_TASKS,HANDLER_TASKS}",
                "http_registration_owner": "each client and accepted handler RateLimitedIo registers one read and one write meter source",
                "http_registration_source": "crates/allocatbelt/src/runtime/rate_io.rs::FeedbackMeters::new",
                "http_source_path": "bench/src/application/http.rs",
                "stream_registration_owner": "one registration for each endpoint direction while the adapter lives",
                "disk_registration_source": "crates/allocatbelt/src/runtime/fs_rate.rs::FsRateControl::new",
            },
            "source_references": reader.CONSTRUCTION_PROBE_SOURCE_REFERENCES,
        }

    @staticmethod
    def _policy(workload: str) -> dict[str, Any]:
        def control(floor: int, initial: int, ceiling: int) -> dict[str, int]:
            return {"floor": floor, "initial": initial, "ceiling": ceiling, "low_bps": 4000, "high_bps": 8000}

        global_ceilings = {"cpu": 64, "memory": 1 << 30, "disk": 1 << 30, "network": 1 << 30, "tasks": 256, "control": 1 << 30}
        tenant_ceilings = {"cpu": 32, "memory": 1 << 29, "disk": 1 << 29, "network": 1 << 29, "tasks": 128, "control": 1 << 29}
        buckets = {
            "disk": {"ceiling_bytes_per_second": 16 << 30, "ceiling_burst_bytes": 1 << 20, "max_reservations": 8},
            "upload": {"ceiling_bytes_per_second": 1 << 30, "ceiling_burst_bytes": 1 << 20, "max_reservations": 8},
            "download": {"ceiling_bytes_per_second": 16 << 30, "ceiling_burst_bytes": 1 << 20, "max_reservations": 8},
        }
        disk_sources = workload in ("disk", "mixed")
        http_sources = workload in ("http", "mixed")
        return {
            "version": "runtime-feedback-policy-v1",
            "sample_interval_ns": 100_000_000,
            "max_dense_gap_ns": 200_000_000,
            "telemetry_freshness_ns": 500_000_000,
            "required_breach_samples": 3,
            "actuation_cooldown_ns": 1_000_000_000,
            "minimum_dense_observations": 1,
            "controls": {
                "cpu": control(1, 4, 4),
                "disk": control(64 << 20, 128 << 20, 16 << 30),
                "download": control(64 << 20, 128 << 20, 16 << 30),
            },
            "capacity_sources": {"disk": False, "download": False},
            "global_ceilings": global_ceilings,
            "tenant_ceilings": tenant_ceilings,
            "scope_limits": {"managed_memory": 1 << 30, "disk_operations": 64, "network_operations": 64},
            "rate_buckets": buckets,
            "meter_source_bounds": {
                "disk": {"minimum_live": 0, "maximum_live": 1 if disk_sources else 0, "source_rule": "disk_shared_owner" if disk_sources else "not_applicable", "lifetime": "registered_endpoint_owner"},
                "upload": {"minimum_live": 0, "maximum_live": 16 if http_sources else 0, "source_rule": "http_client_and_server_window" if http_sources else "not_applicable", "lifetime": "registered_endpoint_owner"},
                "download": {"minimum_live": 0, "maximum_live": 16 if http_sources else 0, "source_rule": "http_client_and_server_window" if http_sources else "not_applicable", "lifetime": "registered_endpoint_owner"},
            },
            "collector": {"task_lease_count": 1, "control_charge_bytes": 4096, "expected_global_control_baseline": 8192},
        }

    def _write_source_manifest(self) -> None:
        source = {
            "git_commit": "c" * 40,
            "source_tree_sha256": self.identity["source_sha256"],
            "cargo_lock_sha256": "d" * 64,
            "files": [],
        }
        build = {
            "host_id": self.identity["host_id"], "rustc_release": "1.99.0", "rustc_verbose": [],
            "cargo_version": "cargo 1.99.0", "target_triple": "x86_64-unknown-linux-gnu",
            "target_cpu": "x86-64-v3", "profile": "release", "features_sha256": "e" * 64,
            "build_inputs_sha256": "f" * 64,
        }
        artifacts = {
            "allocatbelt": {"path": "target/release/liballocatbelt.so", "sha256": self.identity["binary_sha256"]},
            "mimalloc-secure": {"path": "target/release/libmimalloc-secure.so", "sha256": "1" * 64},
            "mimalloc-standard": {"path": "target/release/libmimalloc-standard.so", "sha256": "2" * 64},
            "system": {"path": "target/release/libsystem.so", "sha256": "3" * 64},
        }
        manifest = {
            "schema": reader.SOURCE_MANIFEST_SCHEMA, "source": source, "build": build,
            "artifacts": artifacts, "soak_artifacts": {},
            "analysis_artifact": {"path": "target/release/analyzer", "sha256": "4" * 64},
            "fixed_runtime_policy": {}, "runtime_readback_validator": {}, "resource_domain_calibration": {},
        }
        manifest["manifest_sha256"] = reader.digest_object(manifest)
        self.source_path.write_bytes(reader.canonical_bytes(manifest))

    @staticmethod
    def _event(sequence: int, kind: str, at: int, **fields: Any) -> dict[str, Any]:
        return {"schema": reader.EVENT_SCHEMA, "sequence": sequence, "at": _bracket(at), "kind": kind, **fields}

    def _write_trace(self) -> None:
        base = 5_000_000_000
        width = 10
        events: list[dict[str, Any]] = []
        sequence = 0
        initial = self.policy["controls"]
        for index, resource in enumerate(reader.RESOURCES):
            sequence += 1
            at = base + (index + 1) * 1_000_000
            limit = initial[resource]["initial"]
            events.append(self._event(
                sequence, "startup_readback", at, resource=resource, expected_limit=limit,
                started_at=_bracket(at - 400), completed_at=_bracket(at - 200),
                outcome="value", actual_limit=limit,
            ))
        sequence += 1
        events.append(self._event(sequence, "service_started", base + 4_000_000))
        observation_count = 303 if self.capacity_trace else 14
        sample_times = [base + 200_000_000 + index * 100_000_000 for index in range(observation_count)]
        for index, sample_at in enumerate(sample_times, 1):
            sequence += 1
            raw = {"at": _bracket(sample_at), "cpu_basis_points": 9000, "disk_basis_points": None, "download_basis_points": None}
            events.append(self._event(
                sequence, "sensor_callback", sample_at + 200, started_at=_bracket(sample_at - 200),
                completed_at=_bracket(sample_at + 100), outcome="Sampled", raw_sample=raw,
            ))
            sequence += 1
            planned_at = sample_at + 300
            events.append(self._event(
                sequence, "sample_decision", sample_at + 400, sample_at=_bracket(sample_at), sample=raw,
                accepted=True, rejection=None, planned_at=_bracket(planned_at),
            ))
            streak = min(3, index)
            cpu_no_change = (
                {"reason": "breach_samples_remaining", "observed": streak, "required": 3}
                if streak < 3 else {"reason": "reduction_quantized"}
            )
            controls = []
            for resource in reader.RESOURCES:
                config = initial[resource]
                if resource == "cpu":
                    controls.append({
                        "resource": resource, "current_limit": config["initial"],
                        "utilization_basis_points": 9000, "telemetry": "Fresh",
                        "ticket": None, "no_change": cpu_no_change,
                    })
                else:
                    controls.append({
                        "resource": resource, "current_limit": config["initial"],
                        "utilization_basis_points": None, "telemetry": "Missing",
                        "ticket": None, "no_change": {"reason": "telemetry_unavailable"},
                    })
            sequence += 1
            events.append(self._event(sequence, "plan", sample_at + 600, planned_at=_bracket(planned_at), controls=controls))
        sequence += 1
        stop_at = base + (30_410_000_000 if self.capacity_trace else 1_501_000_000)
        events.append(self._event(sequence, "stop_requested", stop_at))
        sequence += 1
        events.append(self._event(sequence, "worker_joined", stop_at + 10_000_000, panicked=False))
        self.events_path = self.trace / "feedback-events.jsonl"
        self.events_path.write_bytes(b"".join(_json_line(event) for event in events))

        row_count = 305 if self.capacity_trace else 16
        row_times = [base + 150_000_000 + index * 100_000_000 for index in range(row_count)]
        sample_lines = [
            f"schema\t{reader.SAMPLE_SCHEMA}\n".encode("ascii"),
            ("\t".join(reader.SAMPLE_HEADER) + "\n").encode("ascii"),
        ]
        for index, row_time in enumerate(row_times, 1):
            final = index == len(row_times)
            disk_enabled = self.identity["workload"] in ("disk", "mixed")
            http_enabled = self.identity["workload"] in ("http", "mixed")
            attached_sources = {
                "disk": int(disk_enabled and index % 2 == 0),
                "upload": 16 if http_enabled and index % 2 == 0 else 0,
                "download": 16 if http_enabled and index % 2 == 1 else 0,
            }
            sample_lines.append(_sample_row(
                self.policy, index, row_time,
                observation_count if final else min(observation_count, max(0, index - 1)), final,
                attached_sources=attached_sources,
                capacity_progress_directions=(
                    ({"disk"} if disk_enabled else set()) | ({"download"} if http_enabled else set())
                    if self.capacity_trace else None
                ),
            ))
        self.samples_path = self.trace / "resource-samples.tsv"
        self.samples_path.write_bytes(b"".join(sample_lines))

        event_sha = _sha(self.events_path.read_bytes())
        sample_sha = _sha(self.samples_path.read_bytes())
        phases = (
            {
                "production_start": (base + 200_000_000, None),
                "production_end": (base + 30_200_000_010, None),
                "drain_end": (base + 30_300_000_000, None),
                "rss_before": (base + 190_000_000, (100, 120)),
                "rss_after_drain": (base + 30_310_000_000, (102, 125)),
                "shutdown_end": (base + 30_430_000_000, None),
                "rss_after_shutdown": (base + 30_450_000_000, (101, 125)),
                "owner_release": (base + 30_600_000_000, None),
            }
            if self.capacity_trace else
            {
                "production_start": (base + 200_000_000, None),
                "production_end": (base + 1_300_000_000, None),
                "drain_end": (base + 1_400_000_000, None),
                "rss_before": (base + 190_000_000, (100, 120)),
                "rss_after_drain": (base + 1_410_000_000, (102, 125)),
                "shutdown_end": (base + 1_540_000_000, None),
                "rss_after_shutdown": (base + 1_580_000_000, (101, 125)),
                "owner_release": (base + 1_700_000_000, None),
            }
        )
        lines = [
            f"schema\t{reader.TRACE_MANIFEST_SCHEMA}\n",
            f"identity\tprocess_id\t{self.identity['process_id']}\n",
        ]
        for name in ("report_nonce", "run_id", "executor", "allocator", "workload", "profile", "mode", "source_sha256", "binary_sha256"):
            lines.append(f"identity\t{name}\t{self.identity[name]}\n")
        lines.extend([
            f"identity\tpressure_qualification\t{str(self.identity['pressure_qualification']).lower()}\n",
            "trace_directory\tdevice\t1\tmode\t700\n",
            f"artifact\tfeedback-events.jsonl\t{self.events_path.stat().st_size}\t{event_sha}\n",
            f"artifact\tresource-samples.tsv\t{self.samples_path.stat().st_size}\t{sample_sha}\n",
            f"events\t{reader.EVENT_SCHEMA}\t{len(events)}\t1\t{len(events)}\tring_wrapped\tfalse\tread_gaps\t0\n",
            f"samples\t{reader.SAMPLE_SCHEMA}\t{len(row_times)}\t1\t{len(row_times)}\n",
            f"clock_anchor\t{base}\t{base + width}\n",
            "history_capacity\t16384\n",
        ])
        budgets = {
            "max_horizon_seconds": 11400, "sample_interval_ms": 100, "max_sample_rows": 114002,
            "max_sample_cycles": 114001, "terminal_sample_headroom": 1, "max_sample_record_bytes": 8192,
            "max_sample_file_bytes": reader.MAX_SAMPLE_FILE_BYTES, "max_event_records": reader.MAX_EVENT_RECORDS,
            "max_event_record_bytes": 2048, "max_event_file_bytes": reader.MAX_EVENT_FILE_BYTES,
            "max_manifest_file_bytes": reader.MAX_MANIFEST_BYTES, "base_events_per_sample_cycle": 3,
            "control_count": 3, "actuation_cooldown_ms": 1000, "max_tickets_per_control": 11401,
            "events_per_ticket": 4, "application_reconciliation_requests": 0, "terminal_event_headroom": 100,
        }
        lines.extend(f"budget\t{name}\t{value}\n" for name, value in budgets.items())
        for name, (at, rss) in phases.items():
            rss_fields = ("none\tnone" if rss is None else f"{rss[0]}\t{rss[1]}")
            lines.append(f"phase\t{name}\t{at}\t{at + width}\t{rss_fields}\n")
        lines.extend([
            f"control\tcollector_charge_bytes\t{self.policy['collector']['control_charge_bytes']}\texpected_global_control_baseline\t{self.policy['collector']['expected_global_control_baseline']}\n",
            "task\tcollector_task_lease_count\t1\n",
            "completion\tcomplete\ttrue\n",
        ])
        self.manifest_path = self.trace / "feedback-trace-manifest.tsv"
        self.manifest_path.write_bytes("".join(lines).encode("ascii"))
        self.hashes = {
            "manifest": _sha(self.manifest_path.read_bytes()),
            "events": event_sha,
            "samples": sample_sha,
        }

    def verify(self) -> dict[str, Any]:
        return reader.verify_feedback(self.expectation_path, self.expectation_sha, self.trace, dict(self.hashes))

    def install_v4_source_v5(self) -> None:
        source = _source_v5_manifest(self.identity)
        self.source_path.write_bytes(reader.canonical_bytes(source))
        self.source = source
        self.identity["source_sha256"] = source["source"]["source_tree_sha256"]
        self.source_pin = {
            "path": str(self.source_path), "raw_sha256": _sha(self.source_path.read_bytes()),
        }
        source_app = source["artifacts"][self.identity["allocator"]]
        probe_body = _v4_policy_from_source(self.identity, source)
        self.policy = probe_body
        probe_bytes = reader.canonical_bytes(self._construction_probe())
        self.construction_probe_path.write_bytes(probe_bytes)
        self.construction_probe_pin = {
            "path": str(self.construction_probe_path), "raw_sha256": _sha(probe_bytes),
            "allocator": self.identity["allocator"], "binary_sha256": source_app["sha256"],
        }
        self.identity["binary_sha256"] = source_app["sha256"]
        self.identity["executor"] = "allocatbelt"
        body = json.loads(self.expectation_bytes)
        body["schema"] = reader.EXPECTATION_SCHEMA_V4
        body["mode"] = "capacity_calibration"
        body["identity"] = dict(self.identity)
        body["policy"] = self.policy
        body["construction_probe"] = dict(self.construction_probe_pin)
        body["host_binding"] = dict(self.source_pin)
        body["minimum_production_seconds"] = 30
        body.pop("recipe_sha256", None)
        _freeze_fixture_expectation(self, body)
        self.capacity_trace = True
        self._write_trace()
        self.source["artifacts"]["allocatbelt"]["sha256"] = self.identity["binary_sha256"]
        self.source["manifest_sha256"] = campaign.digest_object(self.source)
        self.source_path.write_bytes(reader.canonical_bytes(self.source))
        self.source_pin["raw_sha256"] = _sha(self.source_path.read_bytes())
        self.expectation["host_binding"] = dict(self.source_pin)
        body = {key: value for key, value in self.expectation.items() if key != "recipe_sha256"}
        _freeze_fixture_expectation(self, body)
        self.hashes = {
            "manifest": _sha(self.manifest_path.read_bytes()),
            "events": _sha(self.events_path.read_bytes()),
            "samples": _sha(self.samples_path.read_bytes()),
        }

    def repin_v4_source(self) -> None:
        self.source["manifest_sha256"] = campaign.digest_object(self.source)
        source_raw = reader.canonical_bytes(self.source)
        self.source_path.write_bytes(source_raw)
        self.source_pin["raw_sha256"] = _sha(source_raw)
        body = {key: value for key, value in self.expectation.items() if key != "recipe_sha256"}
        body["host_binding"] = dict(self.source_pin)
        _freeze_fixture_expectation(self, body)

    def repin(self, artifact: str, raw: bytes) -> None:
        path = {"events": self.events_path, "samples": self.samples_path}[artifact]
        path.write_bytes(raw)
        raw_sha = _sha(raw)
        self.hashes[artifact] = raw_sha
        manifest_rows = self.manifest_path.read_text(encoding="ascii").splitlines()
        filename = "feedback-events.jsonl" if artifact == "events" else "resource-samples.tsv"
        updated: list[str] = []
        for line in manifest_rows:
            fields = line.split("\t")
            if fields[0] == "artifact" and fields[1] == filename:
                line = f"artifact\t{filename}\t{len(raw)}\t{raw_sha}"
            updated.append(line)
        self.manifest_path.write_text("\n".join(updated) + "\n", encoding="ascii")
        self.hashes["manifest"] = _sha(self.manifest_path.read_bytes())

    def repin_phase(self, name: str, lower: int) -> None:
        rows = self.manifest_path.read_text(encoding="ascii").splitlines()
        updated = []
        found = False
        for line in rows:
            fields = line.split("\t")
            if fields[0] == "phase" and fields[1] == name:
                fields[2], fields[3] = str(lower), str(lower + 10)
                line = "\t".join(fields)
                found = True
            updated.append(line)
        if not found:
            raise AssertionError(f"phase is absent from the fixture: {name}")
        self.manifest_path.write_text("\n".join(updated) + "\n", encoding="ascii")
        self.hashes["manifest"] = _sha(self.manifest_path.read_bytes())


def _bracket(at: int) -> list[int]:
    return [at, at + 10]


def _json_line(value: dict[str, Any]) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _force_all_meter_sources_zero(fixture: Fixture) -> None:
    rows = fixture.samples_path.read_text(encoding="ascii").splitlines()
    header = rows[1].split("\t")
    columns = [header.index(f"{direction}_meter_attached_sources") for direction in reader.RATE_DIRECTIONS]
    for index in range(2, len(rows)):
        fields = rows[index].split("\t")
        for column in columns:
            fields[column] = "0"
        rows[index] = "\t".join(fields)
    fixture.repin("samples", ("\n".join(rows) + "\n").encode("ascii"))


def _mark_cpu_samples_missing(fixture: Fixture, ordinals: set[int]) -> None:
    events = [json.loads(line) for line in fixture.events_path.read_text(encoding="ascii").splitlines()]
    decisions = [index for index, event in enumerate(events) if event["kind"] == "sample_decision"]
    require_indices = set(range(len(decisions)))
    if not ordinals.issubset(require_indices):
        raise AssertionError("missing CPU test sample ordinal is outside the fixture")
    for ordinal, event_index in enumerate(decisions):
        decision = events[event_index]
        sample_at = decision["sample_at"]
        if ordinal in ordinals:
            decision["sample"]["cpu_basis_points"] = None
            sensor = next(
                event for event in events[:event_index]
                if event["kind"] == "sensor_callback" and event["raw_sample"]["at"] == sample_at
            )
            sensor["raw_sample"]["cpu_basis_points"] = None
        plan = events[event_index + 1]
        if plan["kind"] != "plan":
            raise AssertionError("sample decision fixture has no immediately following plan")
        cpu = next(control for control in plan["controls"] if control["resource"] == "cpu")
        if ordinal in ordinals:
            cpu["utilization_basis_points"] = None
            cpu["telemetry"] = "Missing"
            cpu["no_change"] = {"reason": "telemetry_unavailable"}
        else:
            previous_missing = max((missed for missed in ordinals if missed < ordinal), default=-1)
            streak = ordinal - previous_missing
            cpu["utilization_basis_points"] = 9000
            cpu["telemetry"] = "Fresh"
            cpu["no_change"] = (
                {"reason": "breach_samples_remaining", "observed": streak, "required": 3}
                if streak < 3 else {"reason": "reduction_quantized"}
            )
    fixture.repin("events", b"".join(_json_line(event) for event in events))

    rows = fixture.samples_path.read_text(encoding="ascii").splitlines()
    header = rows[1].split("\t")
    sample_count_column = header.index("feedback_sample_count")
    for row_index in range(2, len(rows)):
        fields = rows[row_index].split("\t")
        count = int(fields[sample_count_column])
        if count == 0:
            continue
        last_ordinal = count - 1
        if last_ordinal in ordinals:
            fields[header.index("cpu_utilization_basis_points")] = "none"
            fields[header.index("cpu_telemetry")] = "Missing"
            fields[header.index("cpu_no_change")] = "Some(TelemetryUnavailable)"
        else:
            previous_missing = max((missed for missed in ordinals if missed < last_ordinal), default=-1)
            streak = last_ordinal - previous_missing
            fields[header.index("cpu_utilization_basis_points")] = "9000"
            fields[header.index("cpu_telemetry")] = "Fresh"
            if streak < 3:
                fields[header.index("cpu_no_change")] = f"Some(BreachSamplesRemaining {{ observed: {streak}, required: 3 }})"
            else:
                fields[header.index("cpu_no_change")] = "Some(ReductionQuantized)"
        rows[row_index] = "\t".join(fields)
    fixture.repin("samples", ("\n".join(rows) + "\n").encode("ascii"))


def _freeze_fixture_expectation(fixture: Fixture, body: dict[str, Any]) -> None:
    raw, raw_sha = reader.build_pressure_expectation_recipe(body)
    fixture.expectation_bytes = raw
    fixture.expectation_sha = raw_sha
    fixture.expectation_path.write_bytes(raw)
    fixture.expectation = json.loads(raw)


def _pressure_soak_expectation_spec(fixture: Fixture) -> dict[str, Any]:
    value = json.loads(fixture.expectation_bytes)
    value.pop("recipe_sha256")
    value["schema"] = reader.EXPECTATION_SCHEMA_V3
    value["mode"] = "pressure_soak_validation"
    value["identity"] = dict(fixture.identity)
    value["identity"].update({
        "executor": "allocatbelt", "mode": "soak", "binary_sha256": "d" * 64,
        "pressure_qualification": True,
    })
    value["construction_probe"]["binary_sha256"] = "b" * 64
    value["app_capacity_artifact_sha256"] = "c" * 64
    value["external_pressure_proof"] = {
        "path": str(fixture.root / "pressure-readback.json"),
        "raw_sha256": "1" * 64, "validator_sha256": _sha(PRESSURE_READER_PATH.read_bytes()),
        "recipe_raw_sha256": "2" * 64,
    }
    value["final_runtime_binding"] = {
        "soak_receipt": {"path": str(fixture.root / "soak-receipt.json"), "raw_sha256": "3" * 64},
        "soak_readback": {"path": str(fixture.root / "soak-readback.json"), "raw_sha256": "4" * 64},
    }
    value["external_soak_identity"] = {
        "campaign_id": "campaign-v3", "host_id": fixture.identity["host_id"],
        "run_id": fixture.identity["run_id"], "nonce": fixture.identity["report_nonce"],
        "allocator": "allocatbelt", "executor": "bounded", "workload": "mixed",
        "profile": fixture.identity["profile"], "comparison_family": "external_pressure",
        "source_sha256": fixture.identity["source_sha256"], "build_sha256": "5" * 64,
        "binary_sha256": "d" * 64, "resource_ceiling_sha256": "6" * 64,
    }
    value["minimum_pressure_overlap_seconds"] = 1
    return value


def _v3_soak_binding_case(
    fixture: Fixture,
    *,
    receipt_changes: dict[str, Any] | None = None,
    endpoint_changes: dict[str, list[int]] | None = None,
    composite_receipt_sha: object | None = None,
    stale_composite_receipt: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    body = _pressure_soak_expectation_spec(fixture)
    build = {"target_triple": "x86_64-unknown-linux-gnu", "profile": "release"}
    build_sha = reader.digest_object(build)
    body["external_soak_identity"]["build_sha256"] = build_sha

    baseline = body["policy"]["collector"]["expected_global_control_baseline"]
    soak_validator_sha = "c" * 64
    pressure_validator_sha = _sha(PRESSURE_READER_PATH.read_bytes())
    source_manifest_value = {
        "schema": reader.SOURCE_MANIFEST_SCHEMA_V5,
        "manifest_sha256": "7" * 64,
        "source": {
            "git_commit": "synthetic-source-v5", "source_tree_sha256": fixture.identity["source_sha256"],
            "cargo_lock_sha256": "8" * 64, "files": [],
        },
        "build": build,
        "artifacts": {"allocatbelt": {"path": "artifacts/app", "sha256": "b" * 64}},
        "soak_artifacts": {"allocatbelt": {"path": "artifacts/soak", "sha256": "d" * 64}},
        "qualification_harness": {
            "soak_validator": {"path": "scripts/application-soak-readback.py", "sha256": soak_validator_sha},
            "pressure_validator": {"path": "scripts/application-pressure-readback.py", "sha256": pressure_validator_sha},
        },
        "resource_domain_calibration": {
            "binary": {"path": "calibration/bin", "sha256": "9" * 64},
            "output": {"path": "calibration/output", "sha256": "a" * 64},
            "record": {"fixed_global_control_baseline": baseline},
            "source": {}, "build": build, "build_sha256": build_sha,
        },
    }

    lower = {
        "started": 1_000,
        "trace_ended": 2_000,
        "drain_ended": 2_100,
        "shutdown_ended": 2_200,
        "postprocess_ended": 2_400,
    }
    receipt: dict[str, Any] = {key: 0 for key in reader.SOAK_RECEIPT_FIELDS_V2}
    receipt.update({
        "schema": reader.RUNTIME_SOAK_SCHEMA_V2,
        "campaign_id": body["external_soak_identity"]["campaign_id"],
        "host_id": body["external_soak_identity"]["host_id"],
        "run_id": body["external_soak_identity"]["run_id"],
        "nonce": body["external_soak_identity"]["nonce"],
        "allocator": "allocatbelt", "executor": "bounded", "workload": "mixed",
        "profile": body["external_soak_identity"]["profile"],
        "comparison_family": "external_pressure", "mode": "soak", "qualification_eligible": False,
        "source_sha256": body["external_soak_identity"]["source_sha256"],
        "binary_sha256": body["external_soak_identity"]["binary_sha256"],
        "resource_ceiling_sha256": body["external_soak_identity"]["resource_ceiling_sha256"],
        "reference_ring_sha256": "c" * 64, "terminal_stream_sha256": "e" * 64,
        "resource_samples_sha256": "f" * 64, "terminal_stream_relative_path": "terminals.tsv",
        "resource_samples_relative_path": "samples.tsv", "first_post_warmup_hour_rss_median_kib": None,
        "final_hour_rss_median_kib": None, "feedback_started": True,
        "feedback_worker_joined": True, "feedback_worker_failure": None,
        "feedback_trace_worker_joined": True, "qualified_horizon": False,
        "started_monotonic_ns": lower["started"],
        "trace_ended_monotonic_ns": lower["trace_ended"],
        "drain_ended_monotonic_ns": lower["drain_ended"],
        "shutdown_ended_monotonic_ns": lower["shutdown_ended"],
        "postprocess_ended_monotonic_ns": lower["postprocess_ended"],
        "ended_monotonic_ns": lower["postprocess_ended"],
        "actual_trace_duration_ns": 1_000, "drain_duration_ns": 100,
        "shutdown_duration_ns": 100, "postprocess_after_shutdown_ns": 200,
        "production_cpu_started_ns": 1, "production_cpu_ended_ns": 2, "production_cpu_ns": 1,
        "duration_seconds": 10, "sample_interval_ms": 100, "warmup_seconds": 300,
        "logical_window": 8, "resource_samples_count": 101,
        "fixed_global_control_baseline": baseline,
        "final_global_live_tenants": 0, "final_global_control_used": baseline,
    })
    for phase, scalar in lower.items():
        receipt[f"{phase}_monotonic_lower_ns"] = scalar
        receipt[f"{phase}_monotonic_upper_ns"] = scalar + 10
    original_receipt_sha = _sha(reader.canonical_bytes(receipt))
    receipt.update(receipt_changes or {})

    receipt_path = fixture.root / "soak-receipt.json"
    receipt_raw = reader.canonical_bytes(receipt)
    receipt_path.write_bytes(receipt_raw)
    receipt_sha = _sha(receipt_raw)
    endpoints = {phase: [receipt[f"{phase}_monotonic_lower_ns"], receipt[f"{phase}_monotonic_upper_ns"]] for phase in lower}
    endpoints.update(endpoint_changes or {})
    readback = {
        "schema": reader.SOAK_READBACK_SCHEMA_V2,
        "validated": True, "passed": True, "qualification_eligible": False, "mode": "functional",
        "identity": dict(body["external_soak_identity"]),
        "source_manifest_sha256": "6" * 64,
        "source_tree_sha256": body["external_soak_identity"]["source_sha256"],
        "build_sha256": build_sha,
        "candidate_binary_sha256": body["external_soak_identity"]["binary_sha256"],
        "resource_ceiling_sha256": body["external_soak_identity"]["resource_ceiling_sha256"],
        "fixed_global_control_baseline": baseline,
        "receipt_sha256": (
            composite_receipt_sha if composite_receipt_sha is not None else
            original_receipt_sha if stale_composite_receipt else receipt_sha
        ),
        "validator_sha256": soak_validator_sha,
        "monotonic_endpoints": endpoints,
    }
    readback_path = fixture.root / "soak-readback.json"
    readback_raw = reader.canonical_bytes(readback)
    readback_path.write_bytes(readback_raw)
    body["final_runtime_binding"] = {
        "soak_receipt": {"path": str(receipt_path), "raw_sha256": receipt_sha},
        "soak_readback": {"path": str(readback_path), "raw_sha256": _sha(readback_raw)},
    }
    recipe = reader._validate_expectation_body(body)
    phases = {
        "production_start": {"lower": lower["started"], "upper": lower["started"] + 10},
        "production_end": {"lower": lower["trace_ended"], "upper": lower["trace_ended"] + 10},
        "drain_end": {"lower": lower["drain_ended"], "upper": lower["drain_ended"] + 10},
        "shutdown_end": {"lower": lower["shutdown_ended"], "upper": lower["shutdown_ended"] + 10},
        "owner_release": {"lower": 2_300, "upper": 2_310},
    }
    manifest = {"clock_anchor": (100, 110), "phases": phases}
    return recipe, {"raw_sha256": "6" * 64, "value": source_manifest_value}, manifest


def _sample_row(
    policy: dict[str, Any], sequence: int, lower: int, feedback_count: int, final: bool,
    *, attached_sources: dict[str, int] | None = None,
    capacity_progress_directions: set[str] | None = None,
) -> bytes:
    row: dict[str, Any] = {
        "sample_sequence": sequence, "window_lower_ns": lower, "window_upper_ns": lower + 1000,
        "rss_kib": 100, "hwm_kib": 125, "collector_task_lease_count": 1,
    }
    for owner in ("global", "tenant"):
        ceilings = policy[f"{owner}_ceilings"]
        for resource in reader.DOMAIN:
            ceiling = ceilings[resource]
            row[f"{owner}_ceiling_{resource}"] = ceiling
            row[f"{owner}_limit_{resource}"] = ceiling
            row[f"{owner}_used_{resource}"] = 1
    row.update({
        "scope_managed_memory_limit": policy["scope_limits"]["managed_memory"],
        "scope_disk_operation_limit": policy["scope_limits"]["disk_operations"],
        "scope_network_operation_limit": policy["scope_limits"]["network_operations"],
        "scope_managed_memory_used": 1, "scope_disk_operations_used": 1, "scope_network_operations_used": 1,
    })
    for direction in reader.RATE_DIRECTIONS:
        config = policy["rate_buckets"][direction]
        current = policy["controls"][direction]["initial"] if direction in ("disk", "download") else config["ceiling_bytes_per_second"]
        burst = config["ceiling_burst_bytes"]
        for field, value in {
            "bytes_per_second": current, "burst_bytes": burst,
            "ceiling_bytes_per_second": config["ceiling_bytes_per_second"],
            "ceiling_burst_bytes": burst, "max_reservations": config["max_reservations"],
            "available_bytes": burst, "reserved_bytes": 0, "reservations": 0,
        }.items():
            row[f"{direction}_rate_{field}"] = value
        progress = capacity_progress_directions is not None and direction in capacity_progress_directions
        committed = sequence * (1000 if direction == "disk" else 2000) if progress else 0
        completions = sequence if progress else 0
        for field, value in {
            "measured_lower_ns": lower + 100, "measured_upper_ns": lower + 110,
            "committed_bytes": committed, "completions": completions,
            "attached_sources": (attached_sources or {}).get(direction, 0), "generation": 0,
            "counter_overflow": False, "invalid_io": False,
            "source_count_overflow": False, "generation_overflow": False,
        }.items():
            row[f"{direction}_meter_{field}"] = value
    row.update({
        "feedback_sample_count": feedback_count,
        "feedback_stop_requested": final,
        "feedback_shutdown_complete": final,
        "feedback_worker_failure": "none",
    })
    for resource in reader.RESOURCES:
        config = policy["controls"][resource]
        if resource == "cpu":
            utilization, telemetry, no_change = 9000, "Fresh", "Some(ReductionQuantized)"
        else:
            utilization, telemetry, no_change = "none", "Missing", "Some(TelemetryUnavailable)"
        row[f"{resource}_current_limit"] = config["initial"]
        row[f"{resource}_utilization_basis_points"] = utilization
        row[f"{resource}_telemetry"] = telemetry
        row[f"{resource}_policy_faulted"] = False
        row[f"{resource}_pending_generation"] = "none"
        row[f"{resource}_no_change"] = no_change
    output: list[str] = []
    for field in reader.SAMPLE_HEADER:
        value = row[field]
        if value == "none":
            output.append("none")
        elif type(value) is bool:
            output.append("true" if value else "false")
        else:
            output.append(str(value))
    return ("\t".join(output) + "\n").encode("ascii")


class CapturedTraceReplayTests(unittest.TestCase):
    def _captured_fixture(self, root: Path):
        fixture = Fixture(root / "origin", workload="mixed")
        fixture.install_v4_source_v5()
        expected = fixture.verify()
        origin_bytes = {
            str(fixture.expectation_path): fixture.expectation_path.read_bytes(),
            str(fixture.manifest_path): fixture.manifest_path.read_bytes(),
            str(fixture.events_path): fixture.events_path.read_bytes(),
            str(fixture.samples_path): fixture.samples_path.read_bytes(),
        }
        stage_root = root / "stage"
        stage_root.mkdir(mode=0o700)
        references = {}
        for index, (origin, raw) in enumerate(sorted(origin_bytes.items())):
            local = stage_root / f"object-{index:02d}.bin"
            local.write_bytes(raw)
            local.chmod(0o400)
            references[origin] = {
                "origin_path": origin, "path": str(local),
                "role": "pressure_pair_artifact", "host_id": fixture.identity["host_id"],
                "raw_sha256": _sha(raw), "semantic_sha256": None,
                "byte_count": len(raw), "maximum_bytes": len(raw),
            }
        view = pressure_pair.CapturedPressureArtifactView(
            str(stage_root), references,
        )
        captured = sorted(origin_bytes)
        resident = sorted({
            *captured, str(fixture.source_path),
            str(fixture.construction_probe_path),
        })
        trace_root = str(fixture.trace)
        context = {
            "schema": pressure_pair.CAPTURED_PRESSURE_REPLAY_CONTEXT_SCHEMA,
            "artifact_view": view,
            "captured_origin_paths": captured,
            "evidence_file_paths": resident,
            "evidence_directory_paths": [trace_root],
            "source_symlink_paths": [], "tree_inventories": [],
            "probe_capture_pin": {
                "path": str(root / "probe-capture.json"),
                "raw_sha256": "a" * 64, "receipt_sha256": "b" * 64,
            },
            "capacity_bundle": {
                "request": {"path": str(root / "capacity-request.json"),
                            "raw_sha256": "c" * 64},
                "artifact": {"path": str(root / "capacity.tsv"),
                             "raw_sha256": "d" * 64},
                "receipt": {"path": str(root / "capacity-receipt.json"),
                            "raw_sha256": "e" * 64},
            },
        }
        for path in (fixture.expectation_path, fixture.manifest_path,
                     fixture.events_path, fixture.samples_path):
            path.unlink()
        return fixture, expected, context, set(origin_bytes)

    def test_captured_pressure_context_streams_expectation_and_trace_without_origin_io(self) -> None:
        with tempfile.TemporaryDirectory(prefix="feedback-captured-trace-") as temporary:
            root = Path(temporary).resolve()
            fixture, expected, context, origins = self._captured_fixture(root)
            inspected: list[str] = []
            original_lstat = Path.lstat
            original_open = os.open

            def guarded_lstat(path: Path, *args: Any, **kwargs: Any):
                rendered = str(path)
                if rendered in origins or rendered == str(fixture.trace):
                    inspected.append(rendered)
                    raise AssertionError("captured feedback replay touched a reclaimed origin")
                return original_lstat(path, *args, **kwargs)

            def guarded_open(path: Any, *args: Any, **kwargs: Any):
                if isinstance(path, (str, bytes, os.PathLike)):
                    rendered = os.fsdecode(path)
                    if rendered in origins or rendered == str(fixture.trace):
                        inspected.append(rendered)
                        raise AssertionError("captured feedback replay opened a reclaimed origin")
                return original_open(path, *args, **kwargs)

            with patch.object(Path, "lstat", guarded_lstat), \
                 patch.object(os, "open", guarded_open):
                actual = reader._verify_feedback_replay(
                    fixture.expectation_path, fixture.expectation_sha,
                    fixture.trace, dict(fixture.hashes),
                    offline_replay_context=context,
                )
            self.assertEqual(actual, expected)
            self.assertEqual(inspected, [])
            self.assertFalse(fixture.expectation_path.exists())
            self.assertFalse(fixture.events_path.exists())

    def test_captured_pressure_trace_rejects_tampered_staged_stream(self) -> None:
        with tempfile.TemporaryDirectory(prefix="feedback-captured-tamper-") as temporary:
            root = Path(temporary).resolve()
            fixture, _expected, context, _origins = self._captured_fixture(root)
            event_origin = str(fixture.events_path)
            reference = context["artifact_view"].objects[event_origin]
            staged = Path(reference["path"])
            staged.chmod(0o600)
            staged.write_bytes(b"x" * reference["byte_count"])
            staged.chmod(0o400)
            with self.assertRaisesRegex(
                    pressure_pair.PressurePairError,
                    "differs from its exact raw pin"):
                reader._verify_feedback_replay(
                    fixture.expectation_path, fixture.expectation_sha,
                    fixture.trace, dict(fixture.hashes),
                    offline_replay_context=context,
                )

    def test_captured_pressure_trace_rejects_missing_symlink_and_truncated_objects(self) -> None:
        for mutation in ("missing", "symlink", "truncated"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(
                    prefix=f"feedback-captured-{mutation}-") as temporary:
                root = Path(temporary).resolve()
                fixture, _expected, context, _origins = self._captured_fixture(root)
                event_origin = str(fixture.events_path)
                reference = context["artifact_view"].objects[event_origin]
                staged = Path(reference["path"])
                if mutation == "missing":
                    staged.unlink()
                elif mutation == "symlink":
                    other = next(
                        Path(row["path"])
                        for origin, row in context["artifact_view"].objects.items()
                        if origin != event_origin
                    )
                    staged.unlink()
                    staged.symlink_to(other.name)
                else:
                    staged.chmod(0o600)
                    staged.write_bytes(b"x" * max(0, reference["byte_count"] - 1))
                    staged.chmod(0o400)
                with self.assertRaises(pressure_pair.PressurePairError):
                    reader._verify_feedback_replay(
                        fixture.expectation_path, fixture.expectation_sha,
                        fixture.trace, dict(fixture.hashes),
                        offline_replay_context=context,
                    )

    def test_captured_pressure_mode_routes_proof_and_runtime_binding_through_view(self) -> None:
        with tempfile.TemporaryDirectory(prefix="feedback-captured-pressure-mode-") as temporary:
            root = Path(temporary).resolve()
            fixture = Fixture(root / "origin", workload="mixed")
            # This component case exercises the v2 pressure-proof and v1
            # runtime readers. The v4 expectation permits calibration only.
            self.assertEqual(json.loads(fixture.expectation_bytes)["schema"], reader.EXPECTATION_SCHEMA_V2)
            fixture.capacity_trace = False
            fixture.identity["pressure_qualification"] = True
            fixture._write_trace()

            helper = FeedbackReadbackTests()
            helper.fixture = fixture
            runtime_capture: dict[str, Any] = {}
            original_runtime_check = reader._verify_runtime_binding

            def capture_valid_runtime_binding(
                recipe: dict[str, Any], final_policy: dict[str, Any],
                accepted_sample_count: int, *, artifact_view: Any = None,
            ):
                result = original_runtime_check(
                    recipe, final_policy, accepted_sample_count,
                    artifact_view=artifact_view,
                )
                if "raw" not in runtime_capture and result[0] and not result[2]:
                    pin = recipe["final_runtime_binding"]
                    runtime_capture["path"] = pin["path"]
                    runtime_capture["raw"] = Path(pin["path"]).read_bytes()
                    runtime_capture["schema_header"] = runtime_capture["raw"].splitlines()[0]
                    runtime_capture["final_policy"] = dict(final_policy)
                    runtime_capture["accepted_sample_count"] = accepted_sample_count
                return result

            with patch.object(reader, "_verify_runtime_binding",
                              side_effect=capture_valid_runtime_binding):
                helper.test_runtime_binding_v2_requires_final_zero_snapshot_and_v1_never_qualifies()
            self.assertIn("raw", runtime_capture)
            self.assertEqual(
                runtime_capture["schema_header"],
                f"schema\t{reader.RUNTIME_BINDING_SCHEMA_V1}".encode("ascii"),
            )

            pressure = helper._pressure_spec()
            pressure["identity"]["pressure_qualification"] = True
            proof = helper._pressure_proof(
                _sha(PRESSURE_READER_PATH.read_bytes()),
            )
            proof["continuous_ready_window"]["start_monotonic_ns"] = 5_100_000_000
            proof_body = {key: value for key, value in proof.items()
                          if key != "readback_sha256"}
            proof["readback_sha256"] = reader.digest_object(proof_body)
            proof_path = fixture.root / "pressure-readback.json"
            proof_raw = reader.canonical_bytes(proof)
            proof_path.write_bytes(proof_raw)
            pressure["external_pressure_proof"]["raw_sha256"] = _sha(proof_raw)
            runtime_path = Path(runtime_capture["path"])
            runtime_raw = runtime_capture["raw"]
            runtime_path.write_bytes(runtime_raw)
            pressure["final_runtime_binding"] = {
                "path": str(runtime_path), "raw_sha256": _sha(runtime_raw),
            }
            _freeze_fixture_expectation(fixture, pressure)
            fixture._write_trace()

            origin_bytes = {
                str(fixture.expectation_path): fixture.expectation_path.read_bytes(),
                str(fixture.manifest_path): fixture.manifest_path.read_bytes(),
                str(fixture.events_path): fixture.events_path.read_bytes(),
                str(fixture.samples_path): fixture.samples_path.read_bytes(),
                str(proof_path): proof_raw,
                str(runtime_path): runtime_raw,
            }
            stage_root = root / "pressure-stage"
            stage_root.mkdir(mode=0o700)
            references = {}
            for index, (origin, raw) in enumerate(sorted(origin_bytes.items())):
                local = stage_root / f"object-{index:02d}.bin"
                local.write_bytes(raw)
                local.chmod(0o400)
                references[origin] = {
                    "origin_path": origin, "path": str(local),
                    "role": "pressure_pair_artifact",
                    "host_id": fixture.identity["host_id"],
                    "raw_sha256": _sha(raw), "semantic_sha256": None,
                    "byte_count": len(raw), "maximum_bytes": len(raw),
                }
            view = pressure_pair.CapturedPressureArtifactView(
                str(stage_root), references,
            )
            captured = sorted(origin_bytes)
            resident = sorted({
                *captured, str(fixture.source_path),
                str(fixture.construction_probe_path),
            })
            context = {
                "schema": pressure_pair.CAPTURED_PRESSURE_REPLAY_CONTEXT_SCHEMA,
                "artifact_view": view,
                "captured_origin_paths": captured,
                "evidence_file_paths": resident,
                "evidence_directory_paths": [str(fixture.trace)],
                "source_symlink_paths": [], "tree_inventories": [],
                "probe_capture_pin": {
                    "path": str(root / "probe-capture.json"),
                    "raw_sha256": "a" * 64, "receipt_sha256": "b" * 64,
                },
                "capacity_bundle": {
                    "request": {"path": str(root / "capacity-request.json"),
                                "raw_sha256": "c" * 64},
                    "artifact": {"path": str(root / "capacity.tsv"),
                                 "raw_sha256": "d" * 64},
                    "receipt": {"path": str(root / "capacity-receipt.json"),
                                "raw_sha256": "e" * 64},
                },
            }
            for path in (fixture.expectation_path, fixture.manifest_path,
                         fixture.events_path, fixture.samples_path,
                         proof_path, runtime_path):
                if path != fixture.source_path and path != fixture.construction_probe_path:
                    path.unlink()

            production = (5_200_000_000, 5_200_000_010)
            drain = (6_400_000_000, 6_400_000_010)
            inspected: list[str] = []
            original_lstat = Path.lstat
            original_open = os.open

            def guarded_lstat(path: Path, *args: Any, **kwargs: Any):
                if str(path) in captured or str(path) == str(fixture.trace):
                    inspected.append(str(path))
                    raise AssertionError("captured pressure binding replay touched an origin output")
                return original_lstat(path, *args, **kwargs)

            def guarded_open(path: Any, *args: Any, **kwargs: Any):
                if isinstance(path, (str, bytes, os.PathLike)):
                    rendered = os.fsdecode(path)
                    if rendered in captured or rendered == str(fixture.trace):
                        inspected.append(rendered)
                        raise AssertionError("captured pressure binding replay opened an origin output")
                return original_open(path, *args, **kwargs)

            with patch.object(Path, "lstat", guarded_lstat), \
                 patch.object(os, "open", guarded_open):
                proof_result = reader._verify_pressure_proof(
                    pressure, production, drain,
                    offline_replayed_proof=proof, allow_pressure_v2=True,
                    artifact_view=view,
                )
                runtime_result = reader._verify_runtime_binding(
                    pressure, runtime_capture["final_policy"],
                    runtime_capture["accepted_sample_count"],
                    artifact_view=view,
                )
            self.assertEqual(proof_result, (True, _sha(proof_raw)))
            self.assertTrue(runtime_result[0])
            self.assertFalse(runtime_result[2])
            self.assertEqual(inspected, [])

    def test_captured_pressure_mode_replays_full_stream_proof_and_runtime_without_origin_io(self) -> None:
        # This synthetic v2 exercise covers component-reader eligibility only;
        # it is not a Source5 host/campaign or performance qualification.
        with tempfile.TemporaryDirectory(prefix="feedback-captured-pressure-full-") as temporary:
            root = Path(temporary).resolve()
            fixture = Fixture(root / "origin", workload="mixed")
            fixture.identity["pressure_qualification"] = True
            fixture._write_trace()
            helper = FeedbackReadbackTests()
            helper.fixture = fixture
            runtime_capture: dict[str, Any] = {}
            original_runtime_check = reader._verify_runtime_binding

            def capture_complete_runtime_binding(
                recipe: dict[str, Any], final_policy: dict[str, Any],
                accepted_sample_count: int, *, artifact_view: Any = None,
            ):
                result = original_runtime_check(
                    recipe, final_policy, accepted_sample_count,
                    artifact_view=artifact_view,
                )
                if result[0] and result[2]:
                    pin = recipe["final_runtime_binding"]
                    runtime_capture.update({
                        "path": pin["path"],
                        "raw": Path(pin["path"]).read_bytes(),
                        "final_policy": dict(final_policy),
                        "accepted_sample_count": accepted_sample_count,
                    })
                    runtime_capture["schema_header"] = runtime_capture["raw"].splitlines()[0]
                return result

            with patch.object(reader, "_verify_runtime_binding",
                              side_effect=capture_complete_runtime_binding):
                helper.test_runtime_binding_v2_requires_final_zero_snapshot_and_v1_never_qualifies()
            self.assertIn("raw", runtime_capture)
            self.assertEqual(
                runtime_capture["schema_header"],
                f"schema\t{reader.RUNTIME_BINDING_SCHEMA_V2}".encode("ascii"),
            )

            pressure = helper._pressure_spec()
            pressure["identity"] = dict(fixture.identity)
            proof = helper._pressure_proof(_sha(PRESSURE_READER_PATH.read_bytes()))
            proof["continuous_ready_window"] = {
                "start_monotonic_ns": 5_000_000_000,
                "end_monotonic_ns": 7_000_000_000,
            }
            proof_body = {key: value for key, value in proof.items()
                          if key != "readback_sha256"}
            proof["readback_sha256"] = reader.digest_object(proof_body)
            proof_path = fixture.root / "pressure-readback.json"
            proof_raw = reader.canonical_bytes(proof)
            proof_path.write_bytes(proof_raw)
            pressure["external_pressure_proof"]["raw_sha256"] = _sha(proof_raw)
            runtime_path = Path(runtime_capture["path"])
            runtime_raw = runtime_capture["raw"]
            runtime_path.write_bytes(runtime_raw)
            pressure["final_runtime_binding"] = {
                "path": str(runtime_path), "raw_sha256": _sha(runtime_raw),
            }
            _freeze_fixture_expectation(fixture, pressure)
            fixture._write_trace()

            origin_bytes = {
                str(fixture.expectation_path): fixture.expectation_path.read_bytes(),
                str(fixture.manifest_path): fixture.manifest_path.read_bytes(),
                str(fixture.events_path): fixture.events_path.read_bytes(),
                str(fixture.samples_path): fixture.samples_path.read_bytes(),
                str(proof_path): proof_raw,
                str(runtime_path): runtime_raw,
            }
            stage_root = root / "pressure-full-stage"
            stage_root.mkdir(mode=0o700)
            references = {}
            for index, (origin, raw) in enumerate(sorted(origin_bytes.items())):
                local = stage_root / f"object-{index:02d}.bin"
                local.write_bytes(raw)
                local.chmod(0o400)
                references[origin] = {
                    "origin_path": origin, "path": str(local),
                    "role": "pressure_pair_artifact",
                    "host_id": fixture.identity["host_id"],
                    "raw_sha256": _sha(raw), "semantic_sha256": None,
                    "byte_count": len(raw), "maximum_bytes": len(raw),
                }
            view = pressure_pair.CapturedPressureArtifactView(
                str(stage_root), references,
            )
            captured = sorted(origin_bytes)
            resident = sorted({
                *captured, str(fixture.source_path),
                str(fixture.construction_probe_path),
            })
            trace_root = str(fixture.trace)
            context = {
                "schema": pressure_pair.CAPTURED_PRESSURE_REPLAY_CONTEXT_SCHEMA,
                "artifact_view": view,
                "captured_origin_paths": captured,
                "evidence_file_paths": resident,
                "evidence_directory_paths": [trace_root],
                "source_symlink_paths": [], "tree_inventories": [],
                "probe_capture_pin": {
                    "path": str(root / "probe-capture.json"),
                    "raw_sha256": "a" * 64, "receipt_sha256": "b" * 64,
                },
                "capacity_bundle": {
                    "request": {"path": str(root / "capacity-request.json"),
                                "raw_sha256": "c" * 64},
                    "artifact": {"path": str(root / "capacity.tsv"),
                                 "raw_sha256": "d" * 64},
                    "receipt": {"path": str(root / "capacity-receipt.json"),
                                "raw_sha256": "e" * 64},
                },
            }
            for path in (fixture.expectation_path, fixture.manifest_path,
                         fixture.events_path, fixture.samples_path,
                         proof_path, runtime_path):
                path.unlink()
            fixture.trace.rmdir()

            source_origin = str(fixture.source_path)
            missing_source_context = dict(context)
            missing_source_context["evidence_file_paths"] = [
                path for path in resident if path != source_origin
            ]
            source_inspected: list[str] = []
            original_lstat = Path.lstat
            original_stat = Path.stat
            original_resolve = Path.resolve
            original_open = os.open

            def guard_unlisted_source_lstat(
                path: Path, *args: Any, **kwargs: Any,
            ):
                if str(path) == source_origin:
                    source_inspected.append(str(path))
                    raise AssertionError("unlisted resident source manifest was statted")
                return original_lstat(path, *args, **kwargs)

            def guard_unlisted_source_stat(
                path: Path, *args: Any, **kwargs: Any,
            ):
                if str(path) == source_origin:
                    source_inspected.append(str(path))
                    raise AssertionError("unlisted resident source manifest was statted")
                return original_stat(path, *args, **kwargs)

            def guard_unlisted_source_resolve(
                path: Path, *args: Any, **kwargs: Any,
            ):
                if str(path) == source_origin:
                    source_inspected.append(str(path))
                    raise AssertionError("unlisted resident source manifest was resolved")
                return original_resolve(path, *args, **kwargs)

            def guard_unlisted_source_open(path: Any, *args: Any, **kwargs: Any):
                if isinstance(path, (str, bytes, os.PathLike)) and \
                        os.fsdecode(path) == source_origin:
                    source_inspected.append(source_origin)
                    raise AssertionError("unlisted resident source manifest was opened")
                return original_open(path, *args, **kwargs)

            with patch.object(Path, "lstat", guard_unlisted_source_lstat), \
                 patch.object(Path, "stat", guard_unlisted_source_stat), \
                 patch.object(Path, "resolve", guard_unlisted_source_resolve), \
                 patch.object(os, "open", guard_unlisted_source_open):
                with self.assertRaisesRegex(
                        reader.ValidationError,
                        "omits exact resident source manifest"):
                    reader._verify_feedback_replay(
                        fixture.expectation_path, fixture.expectation_sha,
                        fixture.trace, dict(fixture.hashes),
                        offline_replay_context=missing_source_context,
                        offline_replayed_proof=proof,
                    )
            self.assertEqual(source_inspected, [])

            inspected: list[str] = []
            original_lstat = Path.lstat
            original_stat = Path.stat
            original_resolve = Path.resolve
            original_open = os.open

            def guarded_lstat(path: Path, *args: Any, **kwargs: Any):
                rendered = str(path)
                if rendered in captured or rendered == trace_root:
                    inspected.append(rendered)
                    raise AssertionError("captured pressure replay touched a reclaimed output")
                return original_lstat(path, *args, **kwargs)

            def guarded_stat(path: Path, *args: Any, **kwargs: Any):
                rendered = str(path)
                if rendered in captured or rendered == trace_root:
                    inspected.append(rendered)
                    raise AssertionError("captured pressure replay statted a reclaimed output")
                return original_stat(path, *args, **kwargs)

            def guarded_resolve(
                path: Path, *args: Any, **kwargs: Any,
            ):
                rendered = str(path)
                if rendered in captured or rendered == trace_root:
                    inspected.append(rendered)
                    raise AssertionError("captured pressure replay resolved a reclaimed output")
                return original_resolve(path, *args, **kwargs)

            def guarded_open(path: Any, *args: Any, **kwargs: Any):
                if isinstance(path, (str, bytes, os.PathLike)):
                    rendered = os.fsdecode(path)
                    if rendered in captured or rendered == trace_root:
                        inspected.append(rendered)
                        raise AssertionError("captured pressure replay opened a reclaimed output")
                return original_open(path, *args, **kwargs)

            with patch.object(Path, "lstat", guarded_lstat), \
                 patch.object(Path, "stat", guarded_stat), \
                 patch.object(Path, "resolve", guarded_resolve), \
                 patch.object(os, "open", guarded_open):
                result = reader._verify_feedback_replay(
                    fixture.expectation_path, fixture.expectation_sha,
                    fixture.trace, dict(fixture.hashes),
                    offline_replay_context=context,
                    offline_replayed_proof=proof,
                )
            self.assertTrue(result["validated"])
            self.assertTrue(result["qualification_eligible"])
            self.assertTrue(result["final_runtime_binding"]["validated"])
            self.assertEqual(inspected, [])

    def test_captured_trace_rejects_any_nested_file_or_directory(self) -> None:
        for nested_kind in ("captured_file", "mapped_only_file", "directory"):
            with self.subTest(nested_kind=nested_kind), tempfile.TemporaryDirectory(
                    prefix=f"feedback-captured-nested-{nested_kind}-") as temporary:
                root = Path(temporary).resolve()
                fixture, _expected, context, _origins = self._captured_fixture(root)
                trace_root = str(fixture.trace)
                nested_dir = str(Path(trace_root) / "unexpected")
                references = {
                    origin: dict(row)
                    for origin, row in context["artifact_view"].objects.items()
                }
                if nested_kind in ("captured_file", "mapped_only_file"):
                    nested_origin = str(Path(nested_dir) / "extra.bin")
                    if nested_kind == "captured_file":
                        raw = b"unexpected nested trace member\n"
                        local = context["artifact_view"].stage_root / "nested-extra.bin"
                        local.write_bytes(raw)
                        local.chmod(0o400)
                        references[nested_origin] = {
                            "origin_path": nested_origin, "path": str(local),
                            "role": "pressure_pair_artifact",
                            "host_id": fixture.identity["host_id"],
                            "raw_sha256": _sha(raw), "semantic_sha256": None,
                            "byte_count": len(raw), "maximum_bytes": len(raw),
                        }
                        context["captured_origin_paths"] = sorted(
                            [*context["captured_origin_paths"], nested_origin],
                        )
                    context["evidence_file_paths"] = sorted(
                        [*context["evidence_file_paths"], nested_origin],
                    )
                else:
                    nested_origin = None
                context["evidence_directory_paths"] = sorted(
                    [*context["evidence_directory_paths"], nested_dir],
                )
                context["artifact_view"] = pressure_pair.CapturedPressureArtifactView(
                    str(context["artifact_view"].stage_root), references,
                )
                with self.assertRaisesRegex(
                        reader.ValidationError, "unpinned",
                ):
                    reader._verify_feedback_replay(
                        fixture.expectation_path, fixture.expectation_sha,
                        fixture.trace, dict(fixture.hashes),
                        offline_replay_context=context,
                    )


class FeedbackReadbackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="feedback-readback-test-")
        self.fixture = Fixture(Path(self.temp.name))

    def tearDown(self) -> None:
        outcome = getattr(getattr(self, "_outcome", None), "result", None)
        if outcome is not None and not outcome.wasSuccessful():
            print(f"feedback readback fixture preserved at {self.temp.name}", file=sys.stderr)
            self.temp._finalizer.detach()
        else:
            self.temp.cleanup()

    def test_complete_synthetic_capacity_calibration_is_valid_but_never_eligible(self) -> None:
        result = self.fixture.verify()
        self.assertTrue(result["validated"])
        self.assertFalse(result["qualification_eligible"])
        self.assertEqual(result["mode"], "capacity_calibration")
        self.assertEqual(result["identity"], self.fixture.identity)
        self.assertEqual(result["final_runtime_binding"], {"raw_sha256": None, "validated": False})
        self.assertEqual(result["raw_artifact_sha256"]["events"], self.fixture.hashes["events"])

    def test_v2_capacity_calibration_accepts_first_missing_cpu_priming_sample(self) -> None:
        _mark_cpu_samples_missing(self.fixture, {0})
        result = self.fixture.verify()
        self.assertTrue(result["validated"])
        self.assertFalse(result["qualification_eligible"])

    def test_v2_capacity_calibration_freezes_on_later_missing_cpu_sample(self) -> None:
        _mark_cpu_samples_missing(self.fixture, {1})
        result = self.fixture.verify()
        self.assertTrue(result["validated"])
        self.assertFalse(result["qualification_eligible"])

    def test_v2_capacity_calibration_requires_dense_cpu_overlap(self) -> None:
        _mark_cpu_samples_missing(self.fixture, set(range(14)))
        with self.assertRaisesRegex(reader.ValidationError, "capacity calibration has insufficient dense CPU observations during production/drain"):
            self.fixture.verify()

    def test_v4_source_v5_capacity_trace_is_valid_but_never_eligible(self) -> None:
        fixture = Fixture(Path(self.temp.name) / "v4-capacity", "mixed", profile="oversubscribed", capacity_trace=True)
        fixture.install_v4_source_v5()
        result = fixture.verify()
        self.assertTrue(result["validated"])
        self.assertFalse(result["qualification_eligible"])
        self.assertEqual(result["schema"], reader.READBACK_SCHEMA)
        self.assertEqual(result["mode"], "capacity_calibration")
        self.assertEqual(result["final_runtime_binding"], {"raw_sha256": None, "validated": False})
        self.assertEqual(len(result), 10)
        self.assertEqual(fixture.expectation["schema"], reader.EXPECTATION_SCHEMA_V4)
        self.assertEqual(fixture.policy["controls"]["cpu"]["initial"], 2)
        self.assertEqual(len(fixture.source["feedback_policy"]["policy"]["contexts"]), 15)

    def test_v4_rejects_non_calibration_modes_and_source_v4(self) -> None:
        body = json.loads(self.fixture.expectation_bytes)
        body.pop("recipe_sha256")
        body["schema"] = reader.EXPECTATION_SCHEMA_V4
        body["mode"] = "pressure_soak_validation"
        with self.assertRaisesRegex(reader.ValidationError, "expectation v4 requires capacity_calibration mode"):
            reader._validate_expectation_body(body)

        body["mode"] = "capacity_calibration"
        recipe = reader._validate_expectation_body(body)
        with self.assertRaisesRegex(reader.ValidationError, "feedback expectation v4 requires a SourceV5 manifest"):
            reader._verify_source_manifest(recipe)

    def test_v4_source_v5_reader_captures_controller_input_and_self_modes_and_sizes(self) -> None:
        fixture = Fixture(Path(self.temp.name) / "v4-captured-source")
        fixture.install_v4_source_v5()
        cases = (
            ("scripts/application-campaign.py", "mode"),
            ("scripts/application-campaign.py", "size", None),
            ("scripts/application-campaign.py", "sha256"),
            ("scripts/application-campaign-inputs.py", "mode"),
            ("scripts/application-campaign-inputs.py", "size", None),
            ("scripts/application-campaign-inputs.py", "sha256"),
            ("scripts/application-feedback-readback.py", "mode"),
            ("scripts/application-feedback-readback.py", "size", None),
            ("scripts/application-feedback-readback.py", "sha256"),
        )
        for case in cases:
            relative, field = case[:2]
            candidate = Fixture(Path(self.temp.name) / f"v4-pin-{Path(relative).stem}-{field}")
            candidate.install_v4_source_v5()
            record = next(item for item in candidate.source["source"]["files"] if item["path"] == relative)
            if field == "mode":
                record[field] = "100755" if record[field] == "100644" else "100644"
            elif field == "size":
                record[field] += 1
            else:
                record[field] = "0" * 64
                harness_key = {
                    "scripts/application-campaign.py": "campaign_controller",
                    "scripts/application-feedback-readback.py": "feedback_validator",
                }.get(relative)
                if harness_key is not None:
                    candidate.source["qualification_harness"][harness_key]["sha256"] = record[field]
            candidate.repin_v4_source()
            recipe = reader._validate_expectation_body({
                key: value for key, value in candidate.expectation.items() if key != "recipe_sha256"
            })
            with self.assertRaises(reader.ValidationError, msg=f"SourceV5 {relative} {field} drift was accepted"):
                reader._verify_source_manifest(recipe)

    def test_v4_recaptures_the_source_pinned_reader_before_emitting_a_receipt(self) -> None:
        for drift, message in (
            ("replacement", "SourceV5 feedback validator bytes differ from the typed inventory pin"),
            ("mode", "SourceV5 feedback validator mode or size differs from its typed inventory pin"),
        ):
            fixture = Fixture(Path(self.temp.name) / f"v4-final-reader-{drift}", "mixed", capacity_trace=True)
            fixture.install_v4_source_v5()
            with tempfile.TemporaryDirectory(prefix="v4-reader-capture-") as temporary:
                script_dir = Path(temporary)
                support_files = (
                    "application-campaign.py", "application-campaign-inputs.py",
                    "application-runtime-readback.py", "application-source-inventory.py",
                    "application-feedback-readback.py",
                )
                for name in support_files:
                    source_path = SCRIPT_DIR / name
                    target_path = script_dir / name
                    shutil.copyfile(source_path, target_path)
                    record = next(
                        item for item in fixture.source["source"]["files"]
                        if item["path"] == f"scripts/{name}"
                    )
                    os.chmod(target_path, int(record["mode"], 8) & 0o777)

                reader_path = script_dir / "application-feedback-readback.py"
                original_rows_validator = reader._validate_resource_sample_rows

                def drift_after_trace_validation(*args: Any, **kwargs: Any) -> str:
                    result = original_rows_validator(*args, **kwargs)
                    if drift == "mode":
                        os.chmod(reader_path, 0o755)
                    else:
                        replacement_path = script_dir / "reader-replacement"
                        replacement_path.write_bytes(b"x" * reader_path.stat().st_size)
                        os.chmod(replacement_path, 0o644)
                        os.replace(replacement_path, reader_path)
                    return result

                with patch.object(reader, "__file__", str(reader_path)), \
                     patch.object(reader, "_validate_resource_sample_rows", side_effect=drift_after_trace_validation):
                    with self.assertRaisesRegex(reader.ValidationError, message):
                        fixture.verify()

    def test_v4_source_v5_rejects_repinned_host_tree_and_binary_mismatches(self) -> None:
        cases = (
            ("host", "SourceV5 manifest host differs from feedback expectation"),
            ("tree", "SourceV5 source tree hash differs from feedback identity"),
            ("binary", "SourceV5 application binary hash differs from feedback identity"),
        )
        for label, message in cases:
            fixture = Fixture(Path(self.temp.name) / f"v4-identity-{label}", "mixed")
            fixture.install_v4_source_v5()
            body = {key: value for key, value in fixture.expectation.items() if key != "recipe_sha256"}
            if label == "host":
                body["identity"]["host_id"] = "repinned-other-host"
            elif label == "tree":
                body["identity"]["source_sha256"] = "0" * 64
            else:
                body["identity"]["binary_sha256"] = "0" * 64
                body["construction_probe"]["binary_sha256"] = "0" * 64
            _freeze_fixture_expectation(fixture, body)
            recipe = reader._validate_expectation_body({key: value for key, value in fixture.expectation.items() if key != "recipe_sha256"})
            with self.assertRaisesRegex(reader.ValidationError, message):
                reader._verify_source_manifest(recipe)

    def test_v4_source_v5_rejects_a_repinned_wrong_semantic_manifest_digest(self) -> None:
        fixture = Fixture(Path(self.temp.name) / "v4-semantic-digest", "mixed")
        fixture.install_v4_source_v5()
        fixture.source["manifest_sha256"] = "0" * 64
        source_raw = reader.canonical_bytes(fixture.source)
        fixture.source_path.write_bytes(source_raw)
        fixture.source_pin["raw_sha256"] = _sha(source_raw)
        body = {key: value for key, value in fixture.expectation.items() if key != "recipe_sha256"}
        body["host_binding"] = dict(fixture.source_pin)
        _freeze_fixture_expectation(fixture, body)
        recipe = reader._validate_expectation_body({key: value for key, value in fixture.expectation.items() if key != "recipe_sha256"})
        with self.assertRaisesRegex(reader.ValidationError, "SourceV5 full campaign verifier rejected the manifest: source-manifest digest mismatch"):
            reader._verify_source_manifest(recipe)

    def test_v4_projects_all_source_v5_contexts_and_zero_registration_bounds(self) -> None:
        fixture = Fixture(Path(self.temp.name) / "v4-contexts")
        fixture.install_v4_source_v5()
        source = fixture.source
        base = {key: value for key, value in fixture.expectation.items() if key != "recipe_sha256"}
        reader._verify_source_manifest_v5(source, reader._validate_expectation_body(base))
        contexts = source["feedback_policy"]["policy"]["contexts"]
        self.assertEqual(len(contexts), 15)
        for context_key in sorted(contexts):
            workload, profile = context_key.split("/", 1)
            identity = dict(fixture.identity, workload=workload, profile=profile)
            fixture.identity = identity
            fixture.policy = _v4_policy_from_source(identity, source)
            body = dict(base, identity=identity, policy=fixture.policy)
            probe_raw = reader.canonical_bytes(fixture._construction_probe())
            fixture.construction_probe_path.write_bytes(probe_raw)
            body["construction_probe"] = {
                "path": str(fixture.construction_probe_path), "raw_sha256": _sha(probe_raw),
                "allocator": identity["allocator"], "binary_sha256": identity["binary_sha256"],
            }
            recipe = reader._validate_expectation_body(body)
            reader.validate_construction_probe(recipe, source)
            self.assertEqual(recipe["policy"]["controls"]["cpu"]["initial"], 2 if profile == "oversubscribed" else 4)
            bounds = recipe["policy"]["meter_source_bounds"]
            if workload not in ("disk", "mixed"):
                self.assertEqual(bounds["disk"]["maximum_live"], 0)
            if workload not in ("http", "mixed"):
                self.assertEqual(bounds["upload"]["maximum_live"], 0)
                self.assertEqual(bounds["download"]["maximum_live"], 0)

    def test_v4_rejects_repinned_policy_and_probe_projection_tampering(self) -> None:
        policy_mutations = (
            ("control", lambda policy: policy["controls"]["disk"].__setitem__("low_bps", policy["controls"]["disk"]["low_bps"] + 1)),
            ("global_ceiling", lambda policy: policy["global_ceilings"].__setitem__("memory", policy["global_ceilings"]["memory"] + 1)),
            ("tenant_ceiling", lambda policy: policy["tenant_ceilings"].__setitem__("memory", policy["tenant_ceilings"]["memory"] + 1)),
            ("scope", lambda policy: policy["scope_limits"].__setitem__("managed_memory", policy["scope_limits"]["managed_memory"] + 1)),
            ("bucket", lambda policy: policy["rate_buckets"]["disk"].__setitem__("ceiling_burst_bytes", policy["rate_buckets"]["disk"]["ceiling_burst_bytes"] + 1)),
            ("collector_charge", lambda policy: policy["collector"].__setitem__("control_charge_bytes", policy["collector"]["control_charge_bytes"] + 1)),
            ("baseline", lambda policy: policy["collector"].__setitem__("expected_global_control_baseline", policy["collector"]["expected_global_control_baseline"] + 1)),
        )
        for label, mutate in policy_mutations:
            fixture = Fixture(Path(self.temp.name) / f"v4-policy-{label}", "mixed")
            fixture.install_v4_source_v5()
            body = {key: value for key, value in fixture.expectation.items() if key != "recipe_sha256"}
            mutate(body["policy"])
            _freeze_fixture_expectation(fixture, body)
            with self.assertRaises(reader.ValidationError, msg=f"repinned V4 {label} policy mutation was accepted"):
                recipe = reader._validate_expectation_body({key: value for key, value in fixture.expectation.items() if key != "recipe_sha256"})
                checked_source = reader._verify_source_manifest(recipe)
                reader.validate_construction_probe(recipe, checked_source["value"])

        probe_mutations = (
            ("probe_control", lambda probe: probe["rust_control_context"]["controls"]["cpu"].__setitem__("low_bps", probe["rust_control_context"]["controls"]["cpu"]["low_bps"] + 1)),
            ("probe_ceiling", lambda probe: probe["rust_control_context"]["global_ceilings"].__setitem__("memory", probe["rust_control_context"]["global_ceilings"]["memory"] + 1)),
            ("probe_scope", lambda probe: probe["rust_control_context"]["scope_limits"].__setitem__("managed_memory", probe["rust_control_context"]["scope_limits"]["managed_memory"] + 1)),
            ("probe_bucket", lambda probe: probe["rust_control_context"]["rate_buckets"]["disk"].__setitem__("max_reservations", probe["rust_control_context"]["rate_buckets"]["disk"]["max_reservations"] + 1)),
            ("probe_collector_count", lambda probe: probe["collector"].__setitem__("task_lease_count", 2)),
            ("probe_baseline", lambda probe: probe["baseline"].__setitem__("expected_global_control_baseline", probe["baseline"]["expected_global_control_baseline"] + 1)),
            ("probe_registration_count", lambda probe: probe["meter_source_bounds"]["disk"].__setitem__("maximum_live", probe["meter_source_bounds"]["disk"]["maximum_live"] + 1)),
            ("probe_source_reference", lambda probe: probe["source_references"].__setitem__("application_entrypoint", "bench/src/wrong.rs")),
        )
        for label, mutate in probe_mutations:
            fixture = Fixture(Path(self.temp.name) / f"v4-{label}", "mixed")
            fixture.install_v4_source_v5()
            probe = json.loads(fixture.construction_probe_path.read_bytes())
            mutate(probe)
            probe_raw = reader.canonical_bytes(probe)
            fixture.construction_probe_path.write_bytes(probe_raw)
            body = {key: value for key, value in fixture.expectation.items() if key != "recipe_sha256"}
            body["construction_probe"]["raw_sha256"] = _sha(probe_raw)
            _freeze_fixture_expectation(fixture, body)
            with self.assertRaises(reader.ValidationError, msg=f"repinned V4 {label} probe mutation was accepted"):
                recipe = reader._validate_expectation_body({key: value for key, value in fixture.expectation.items() if key != "recipe_sha256"})
                checked_source = reader._verify_source_manifest(recipe)
                reader.validate_construction_probe(recipe, checked_source["value"])

    def test_v4_trace_collector_charge_baseline_and_task_count_remain_bound(self) -> None:
        cases = (
            ("collector_charge_bytes", "trace collector Control charge differs from expectation"),
            ("expected_global_control_baseline", "trace Control baseline differs from expectation"),
            ("collector_task_lease_count", "trace collector Task lease differs from expectation"),
        )
        for field, message in cases:
            fixture = Fixture(Path(self.temp.name) / f"v4-trace-{field}", "mixed", capacity_trace=True)
            fixture.install_v4_source_v5()
            rows = fixture.manifest_path.read_text(encoding="ascii").splitlines()
            updated = []
            for line in rows:
                parts = line.split("\t")
                if field == "collector_charge_bytes" and parts[0] == "control":
                    parts[2] = str(int(parts[2]) + 1)
                    line = "\t".join(parts)
                elif field == "expected_global_control_baseline" and parts[0] == "control":
                    parts[4] = str(int(parts[4]) + 1)
                    line = "\t".join(parts)
                elif field == "collector_task_lease_count" and parts[0] == "task":
                    parts[2] = "2"
                    line = "\t".join(parts)
                updated.append(line)
            fixture.manifest_path.write_text("\n".join(updated) + "\n", encoding="ascii")
            fixture.hashes["manifest"] = _sha(fixture.manifest_path.read_bytes())
            with self.assertRaisesRegex(reader.ValidationError, message):
                fixture.verify()

    def test_v4_capacity_allows_first_missing_cpu_priming_sample(self) -> None:
        fixture = Fixture(Path(self.temp.name) / "v4-cpu-priming", "mixed", capacity_trace=True)
        fixture.install_v4_source_v5()
        _mark_cpu_samples_missing(fixture, {0})
        result = fixture.verify()
        self.assertTrue(result["validated"])
        self.assertFalse(result["qualification_eligible"])

    def test_v4_capacity_keeps_dense_cpu_and_full_window_guards(self) -> None:
        fixture = Fixture(Path(self.temp.name) / "v4-cpu-density", "mixed", capacity_trace=True)
        fixture.install_v4_source_v5()
        _mark_cpu_samples_missing(fixture, set(range(303)))
        with self.assertRaisesRegex(reader.ValidationError, "capacity calibration has insufficient dense CPU observations during production/drain"):
            fixture.verify()

        fixture = Fixture(Path(self.temp.name) / "v4-first-window", "mixed", capacity_trace=True)
        fixture.install_v4_source_v5()
        base = 5_000_000_000
        fixture.repin_phase("production_start", base + 199_999_999)
        with self.assertRaisesRegex(reader.ValidationError, "accepted feedback samples do not cover production through drain"):
            fixture.verify()

        fixture = Fixture(Path(self.temp.name) / "v4-last-window", "mixed", capacity_trace=True)
        fixture.install_v4_source_v5()
        fixture.repin_phase("drain_end", 5_000_000_000 + 30_401_000_000)
        fixture.repin_phase("rss_after_drain", 5_000_000_000 + 30_412_000_000)
        with self.assertRaisesRegex(reader.ValidationError, "accepted feedback samples do not cover production through drain"):
            fixture.verify()

    def test_source_v5_uses_captured_pinned_controller_full_verifier(self) -> None:
        controller_path = SCRIPT_DIR / "application-campaign.py"
        inputs_path = SCRIPT_DIR / "application-campaign-inputs.py"
        feedback_path = SCRIPT_DIR / "application-feedback-readback.py"

        def regular_record(path: Path, relative: str) -> dict[str, Any]:
            raw = path.read_bytes()
            info = path.stat(follow_symlinks=False)
            mode = f"{stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode):06o}"
            return {
                "path": relative, "kind": "file", "mode": mode,
                "sha256": _sha(raw), "size": len(raw),
            }

        controller = regular_record(controller_path, "scripts/application-campaign.py")
        inputs = regular_record(inputs_path, "scripts/application-campaign-inputs.py")
        feedback = regular_record(feedback_path, "scripts/application-feedback-readback.py")
        value = {
            "schema": reader.SOURCE_MANIFEST_SCHEMA_V5,
            "source": {
                "git_commit": "synthetic-source-v5",
                "source_tree_sha256": "a" * 64,
                "cargo_lock_sha256": "b" * 64,
                "files": [controller, inputs, feedback],
            },
            "build": {}, "artifacts": {}, "soak_artifacts": {},
            "analysis_artifact": {}, "fixed_runtime_policy": {},
            "runtime_readback_validator": {}, "resource_domain_calibration": {},
            "qualification_harness": {
                "campaign_controller": {"path": controller["path"], "sha256": controller["sha256"]},
                "feedback_validator": {"path": feedback["path"], "sha256": feedback["sha256"]},
            },
            "feedback_policy": {},
            "manifest_sha256": "0" * 64,
        }
        recipe = {"schema": reader.EXPECTATION_SCHEMA_V3, "mode": "pressure_soak_validation"}
        with self.assertRaisesRegex(reader.ValidationError, "SourceV5 full campaign verifier rejected the manifest: source-manifest digest mismatch"):
            reader._verify_source_manifest_v5(value, recipe)

        wrong_controller = dict(controller, sha256="c" * 64)
        value["source"]["files"][0] = wrong_controller
        value["qualification_harness"]["campaign_controller"]["sha256"] = "c" * 64
        with self.assertRaisesRegex(reader.ValidationError, "campaign controller bytes differ from the typed inventory pin"):
            reader._verify_source_manifest_v5(value, recipe)

    def test_v3_expectation_uses_distinct_application_probe_and_timed_soak_roles(self) -> None:
        fixture = Fixture(self.fixture.root / "pressure-soak-v3", workload="mixed")
        body = _pressure_soak_expectation_spec(fixture)
        recipe = reader._validate_expectation_body(body)
        self.assertEqual(recipe["mode"], "pressure_soak_validation")
        self.assertEqual(recipe["identity"]["binary_sha256"], recipe["external_soak_identity"]["binary_sha256"])
        self.assertNotEqual(recipe["construction_probe"]["binary_sha256"], recipe["identity"]["binary_sha256"])

        invalid_role = json.loads(json.dumps(body))
        invalid_role["identity"]["executor"] = "tokio-1.53.1"
        with self.assertRaisesRegex(reader.ValidationError, "explicit bounded-to-allocatbelt executor role mapping"):
            reader._validate_expectation_body(invalid_role)

    def test_v3_expectation_rejects_source_v4(self) -> None:
        fixture = Fixture(self.fixture.root / "source-v4-v3", workload="mixed")
        recipe = reader._validate_expectation_body(_pressure_soak_expectation_spec(fixture))
        with self.assertRaisesRegex(reader.ValidationError, "feedback expectation v3 requires a SourceV5 manifest"):
            reader._verify_source_manifest(recipe)

    def test_v3_construction_probe_maps_to_regular_source_v5_inventory_entries(self) -> None:
        fixture = Fixture(self.fixture.root / "probe-v3", workload="mixed")
        body = _pressure_soak_expectation_spec(fixture)
        recipe = reader._validate_expectation_body(body)
        source_records = [
            {"path": path, "kind": "file", "mode": "100644", "sha256": "a" * 64, "size": 1}
            for path in reader.CONSTRUCTION_PROBE_SOURCE_REFERENCES.values()
        ]
        policy_body = {
            "schema": "allocatbelt.application-feedback-policy-artifact.v1",
            "version": recipe["policy"]["version"],
            "reader_contract": {
                key: recipe["policy"][key] for key in (
                    "sample_interval_ns", "max_dense_gap_ns", "telemetry_freshness_ns",
                    "required_breach_samples", "actuation_cooldown_ns", "minimum_dense_observations",
                )
            },
            "algorithm": fixture._construction_probe()["rust_control_context"]["algorithm"],
            "contexts": {
                "mixed/mixed": {
                    "workers": 4,
                    "minimum_dense_observations": recipe["policy"]["minimum_dense_observations"],
                    "controls": recipe["policy"]["controls"],
                },
            },
            "source_pins": {
                name: {"path": f"scripts/{name}.py", "sha256": "b" * 64}
                for name in ("feedback_validator", "runtime_bindings", "runtime_policy", "runtime_sensor")
            },
        }
        source_manifest = {
            "schema": reader.SOURCE_MANIFEST_SCHEMA_V5,
            "source": {"git_commit": "synthetic-v5", "source_tree_sha256": "b" * 64, "cargo_lock_sha256": "c" * 64, "files": source_records},
            "artifacts": {"allocatbelt": {"path": "artifacts/app", "sha256": recipe["construction_probe"]["binary_sha256"]}},
            "feedback_policy": {
                "schema": "allocatbelt.application-feedback-policy-artifact.v1",
                "policy": policy_body,
                "policy_sha256": reader.digest_object(policy_body),
            },
        }
        probe_sha = reader.validate_construction_probe(recipe, source_manifest)
        self.assertEqual(probe_sha, recipe["construction_probe"]["raw_sha256"])

        selected_source = json.loads(json.dumps(source_manifest))
        selected_artifact = selected_source["feedback_policy"]
        selected_artifact["schema"] = "allocatbelt.application-feedback-policy-artifact.v2"
        selected_policy = selected_artifact["policy"]
        selected_policy["schema"] = selected_artifact["schema"]
        selected_policy["capacity_floor_policy"] = {
            "capacity_divisor": reader.CAPACITY_FLOOR_DIVISOR,
            "minimum_floor_bytes_per_second": reader.CAPACITY_FLOOR_MINIMUM_BYTES_PER_SECOND,
            "policy_id": reader.CAPACITY_FLOOR_POLICY_ID,
            "probe_activation": reader.CAPACITY_FLOOR_PROBE_ACTIVATION,
            "rule": reader.CAPACITY_FLOOR_RULE,
            "rule_version": reader.CAPACITY_RESOLUTION_VERSION,
            "runtime_activation": reader.CAPACITY_FLOOR_RUNTIME_ACTIVATION,
            "static_floor_bytes_per_second": reader.CAPACITY_RATE_FLOOR,
            "static_rate_roof_bytes_per_second": reader.CAPACITY_RATE_ROOF,
        }
        selected_artifact["policy_sha256"] = reader.digest_object(selected_policy)
        self.assertEqual(reader.validate_construction_probe(recipe, selected_source), probe_sha)

        selected_policy["capacity_floor_policy"]["capacity_divisor"] = 9
        selected_artifact["policy_sha256"] = reader.digest_object(selected_policy)
        with self.assertRaisesRegex(reader.ValidationError, "capacity_divisor differs"):
            reader.validate_construction_probe(recipe, selected_source)

        original_probe = fixture.construction_probe_path.read_bytes()
        for forbidden_field, value in (
            ("capacity_calibration", {}),
            ("capacity_floor_policy_id", reader.CAPACITY_FLOOR_POLICY_ID),
        ):
            with self.subTest(forbidden_field=forbidden_field):
                injected_probe = json.loads(original_probe)
                injected_probe[forbidden_field] = value
                injected_raw = reader.canonical_bytes(injected_probe)
                fixture.construction_probe_path.write_bytes(injected_raw)
                injected_recipe = json.loads(json.dumps(recipe))
                injected_recipe["construction_probe"]["raw_sha256"] = _sha(injected_raw)
                with self.assertRaises(reader.ValidationError):
                    reader.validate_construction_probe(injected_recipe, source_manifest)
        fixture.construction_probe_path.write_bytes(original_probe)

        missing = json.loads(json.dumps(source_manifest))
        missing["source"]["files"] = [record for record in missing["source"]["files"] if record["path"] != "crates/allocatbelt/src/runtime/resource_domain.rs"]
        with self.assertRaisesRegex(reader.ValidationError, "not a regular SourceV5 inventory entry: resource_domain"):
            reader.validate_construction_probe(recipe, missing)

    def test_v3_soak_receipt_and_composite_bind_exact_final_state_and_clock(self) -> None:
        fixture = Fixture(self.fixture.root / "soak-binding-v3", workload="mixed")
        recipe, source_manifest, trace_manifest = _v3_soak_binding_case(fixture)
        result = reader._verify_soak_final_binding_v3(recipe, source_manifest, trace_manifest)
        self.assertTrue(result["validated"])
        self.assertFalse(result["qualification_eligible"])
        self.assertEqual(result["mode"], "functional")

    def test_v3_soak_receipt_and_readback_use_captured_view_without_origin_io(self) -> None:
        fixture = Fixture(self.fixture.root / "soak-binding-captured-v3", workload="mixed")
        recipe, source_manifest, trace_manifest = _v3_soak_binding_case(fixture)
        binding = recipe["final_runtime_binding"]
        origin_bytes = {
            binding[name]["path"]: Path(binding[name]["path"]).read_bytes()
            for name in ("soak_receipt", "soak_readback")
        }
        stage_root = fixture.root / "captured-soak-stage"
        stage_root.mkdir(mode=0o700)
        references = {}
        for index, (origin, raw) in enumerate(sorted(origin_bytes.items())):
            local = stage_root / f"soak-object-{index:02d}.bin"
            local.write_bytes(raw)
            local.chmod(0o400)
            references[origin] = {
                "origin_path": origin, "path": str(local),
                "role": "pressure_pair_artifact",
                "host_id": fixture.identity["host_id"],
                "raw_sha256": _sha(raw), "semantic_sha256": None,
                "byte_count": len(raw), "maximum_bytes": len(raw),
            }
        view = pressure_pair.CapturedPressureArtifactView(
            str(stage_root), references,
        )
        for path in origin_bytes:
            Path(path).unlink()
        origins = set(origin_bytes)
        inspected: list[str] = []
        original_lstat = Path.lstat
        original_stat = Path.stat
        original_resolve = Path.resolve
        original_open = os.open

        def guarded_lstat(path: Path, *args: Any, **kwargs: Any):
            rendered = str(path)
            if rendered in origins:
                inspected.append(rendered)
                raise AssertionError("captured Soak binding lstat touched a reclaimed origin")
            return original_lstat(path, *args, **kwargs)

        def guarded_stat(path: Path, *args: Any, **kwargs: Any):
            rendered = str(path)
            if rendered in origins:
                inspected.append(rendered)
                raise AssertionError("captured Soak binding stat touched a reclaimed origin")
            return original_stat(path, *args, **kwargs)

        def guarded_resolve(path: Path, *args: Any, **kwargs: Any):
            rendered = str(path)
            if rendered in origins:
                inspected.append(rendered)
                raise AssertionError("captured Soak binding resolve touched a reclaimed origin")
            return original_resolve(path, *args, **kwargs)

        def guarded_open(path: Any, *args: Any, **kwargs: Any):
            if isinstance(path, (str, bytes, os.PathLike)):
                rendered = os.fsdecode(path)
                if rendered in origins:
                    inspected.append(rendered)
                    raise AssertionError("captured Soak binding open touched a reclaimed origin")
            return original_open(path, *args, **kwargs)

        with patch.object(Path, "lstat", guarded_lstat), \
             patch.object(Path, "stat", guarded_stat), \
             patch.object(Path, "resolve", guarded_resolve), \
             patch.object(os, "open", guarded_open):
            result = reader._verify_soak_final_binding_v3(
                recipe, source_manifest, trace_manifest, artifact_view=view,
            )
        self.assertTrue(result["validated"])
        self.assertFalse(result["qualification_eligible"])
        self.assertEqual(result["raw_sha256"], _sha(origin_bytes[binding["soak_receipt"]["path"]]))
        self.assertEqual(result["readback_raw_sha256"], _sha(origin_bytes[binding["soak_readback"]["path"]]))
        self.assertEqual(inspected, [])

    def test_v3_soak_binding_rejects_nonzero_final_usage(self) -> None:
        fixture = Fixture(self.fixture.root / "soak-binding-final-v3", workload="mixed")
        recipe, source_manifest, trace_manifest = _v3_soak_binding_case(
            fixture, receipt_changes={"final_global_tasks_used": 1},
        )
        with self.assertRaisesRegex(reader.ValidationError, "retains final application usage at final_global_tasks_used"):
            reader._verify_soak_final_binding_v3(recipe, source_manifest, trace_manifest)

    def test_v3_soak_binding_rejects_composite_clock_drift(self) -> None:
        fixture = Fixture(self.fixture.root / "soak-binding-clock-v3", workload="mixed")
        recipe, source_manifest, trace_manifest = _v3_soak_binding_case(
            fixture, endpoint_changes={"started": [1_001, 1_011]},
        )
        with self.assertRaisesRegex(reader.ValidationError, "soak composite started bracket differs from the Rust receipt"):
            reader._verify_soak_final_binding_v3(recipe, source_manifest, trace_manifest)

    def test_v3_soak_binding_rejects_changed_receipt_with_stale_composite(self) -> None:
        fixture = Fixture(self.fixture.root / "soak-binding-stale-composite-v3", workload="mixed")
        recipe, source_manifest, trace_manifest = _v3_soak_binding_case(
            fixture,
            receipt_changes={"terminal_stream_sha256": "0" * 64},
            stale_composite_receipt=True,
        )
        with self.assertRaisesRegex(reader.ValidationError, "soak composite receipt digest differs from the captured Rust receipt bytes"):
            reader._verify_soak_final_binding_v3(recipe, source_manifest, trace_manifest)

    def test_v3_soak_binding_rejects_malformed_composite_receipt_digest(self) -> None:
        fixture = Fixture(self.fixture.root / "soak-binding-malformed-receipt-digest-v3", workload="mixed")
        recipe, source_manifest, trace_manifest = _v3_soak_binding_case(
            fixture, composite_receipt_sha="not-a-sha256",
        )
        with self.assertRaisesRegex(reader.ValidationError, "soak composite receipt SHA-256 must be lowercase SHA-256"):
            reader._verify_soak_final_binding_v3(recipe, source_manifest, trace_manifest)

    def test_v3_soak_binding_rejects_pinned_well_formed_wrong_composite_receipt_digest(self) -> None:
        fixture = Fixture(self.fixture.root / "soak-binding-wrong-receipt-digest-v3", workload="mixed")
        recipe, source_manifest, trace_manifest = _v3_soak_binding_case(
            fixture, composite_receipt_sha="0" * 64,
        )
        with self.assertRaisesRegex(reader.ValidationError, "soak composite receipt digest differs from the captured Rust receipt bytes"):
            reader._verify_soak_final_binding_v3(recipe, source_manifest, trace_manifest)

    def test_v3_feedback_readback_consumes_both_external_proofs_and_stays_component_scoped(self) -> None:
        fixture = Fixture(self.fixture.root / "feedback-v3", workload="mixed")
        body = _pressure_soak_expectation_spec(fixture)
        fixture.identity = dict(body["identity"])
        fixture._write_trace()
        _freeze_fixture_expectation(fixture, body)
        feedback_raw = READER_PATH.read_bytes()
        feedback_info = READER_PATH.stat(follow_symlinks=False)
        source_value = {
            "schema": reader.SOURCE_MANIFEST_SCHEMA_V5,
            "source": {
                "files": [{
                    "path": "scripts/application-feedback-readback.py", "kind": "file",
                    "mode": f"{stat.S_IFMT(feedback_info.st_mode) | stat.S_IMODE(feedback_info.st_mode):06o}",
                    "sha256": _sha(feedback_raw), "size": len(feedback_raw),
                }],
            },
            "qualification_harness": {
                "pressure_validator": {
                    "path": "scripts/application-pressure-readback.py",
                    "sha256": body["external_pressure_proof"]["validator_sha256"],
                },
            },
        }
        soak_summary = {
            "raw_sha256": "a" * 64, "readback_raw_sha256": "b" * 64,
            "validated": True, "qualification_eligible": False, "mode": "functional",
        }
        with patch.object(reader, "_verify_source_manifest", return_value={"raw_sha256": "c" * 64, "value": source_value}), \
             patch.object(reader, "validate_construction_probe", return_value="d" * 64), \
             patch.object(reader, "_verify_pressure_proof", return_value=(True, "e" * 64)), \
             patch.object(reader, "_verify_soak_final_binding_v3", return_value=soak_summary):
            result = fixture.verify()
        self.assertTrue(result["validated"])
        self.assertEqual(result["schema"], reader.READBACK_SCHEMA_V2)
        self.assertFalse(result["qualification_eligible"])
        self.assertEqual(result["final_runtime_binding"], {
            "raw_sha256": "a" * 64, "readback_raw_sha256": "b" * 64,
            "validated": True, "qualification_eligible": False, "mode": "functional",
        })

    def test_archived_v1_pressure_receipt_validates_but_never_qualifies(self) -> None:
        self.fixture.identity["pressure_qualification"] = True
        self.fixture._write_trace()
        _force_all_meter_sources_zero(self.fixture)
        validator_sha = _sha(PRESSURE_READER_PATH.read_bytes())
        base_v2_body = json.loads(self.fixture.expectation_bytes)
        base_v2_body.pop("recipe_sha256")

        def verify_version(schema: str) -> dict[str, Any]:
            body = json.loads(json.dumps(base_v2_body))
            body["schema"] = schema
            body["mode"] = "pressure_validation"
            body["identity"] = dict(self.fixture.identity)
            if schema == reader.EXPECTATION_SCHEMA_V1:
                body.pop("construction_probe")
            body["app_capacity_artifact_sha256"] = "c" * 64
            body["external_pressure_proof"] = {
                "path": str(self.fixture.root / "pressure-readback.json"),
                "raw_sha256": "d" * 64, "validator_sha256": validator_sha,
                "recipe_raw_sha256": "e" * 64,
            }
            body["final_runtime_binding"] = {
                "path": str(self.fixture.root / "runtime-binding.tsv"), "raw_sha256": "f" * 64,
            }
            body["minimum_pressure_overlap_seconds"] = 1
            if schema == reader.EXPECTATION_SCHEMA_V1:
                body["policy"].pop("meter_source_bounds")
                body["policy"]["meter_sources"] = {"disk": 0, "upload": 0, "download": 0}
            else:
                body["policy"].pop("meter_sources", None)
            _freeze_fixture_expectation(self.fixture, body)
            with patch.object(reader, "_verify_pressure_proof", return_value=(True, "1" * 64)), \
                 patch.object(reader, "_verify_runtime_binding", return_value=(True, "2" * 64, True)):
                return self.fixture.verify()

        legacy = verify_version(reader.EXPECTATION_SCHEMA_V1)
        self.assertTrue(legacy["validated"])
        self.assertEqual(legacy["mode"], "pressure_validation")
        self.assertFalse(legacy["qualification_eligible"])

        legacy_rows = self.fixture.samples_path.read_text(encoding="ascii").splitlines()
        legacy_header = legacy_rows[1].split("\t")
        legacy_fields = legacy_rows[3].split("\t")
        legacy_fields[legacy_header.index("disk_meter_attached_sources")] = "1"
        legacy_rows[3] = "\t".join(legacy_fields)
        self.fixture.repin("samples", ("\n".join(legacy_rows) + "\n").encode("ascii"))
        with patch.object(reader, "_verify_pressure_proof", return_value=(True, "1" * 64)), \
             patch.object(reader, "_verify_runtime_binding", return_value=(True, "2" * 64, True)):
            with self.assertRaisesRegex(reader.ValidationError, "legacy disk meter source count"):
                self.fixture.verify()

        current = verify_version(reader.EXPECTATION_SCHEMA_V2)
        self.assertTrue(current["validated"])
        self.assertTrue(current["qualification_eligible"])

    def test_v2_meter_source_counts_change_with_live_owners_within_frozen_bounds(self) -> None:
        self.assertTrue(self.fixture.verify()["validated"])
        sample_rows = self.fixture.samples_path.read_text(encoding="ascii").splitlines()
        header = sample_rows[1].split("\t")
        disk_index = header.index("disk_meter_attached_sources")
        disk_counts = {int(row.split("\t")[disk_index]) for row in sample_rows[2:]}
        self.assertEqual(disk_counts, {0, 1})

        invalid_rows = list(sample_rows)
        fields = invalid_rows[3].split("\t")
        fields[disk_index] = "2"
        invalid_rows[3] = "\t".join(fields)
        self.fixture.repin("samples", ("\n".join(invalid_rows) + "\n").encode("ascii"))
        with self.assertRaisesRegex(reader.ValidationError, "outside caller-frozen bounds"):
            self.fixture.verify()

        http_fixture = Fixture(Path(self.temp.name) / "http", workload="http")
        self.assertTrue(http_fixture.verify()["validated"])
        http_rows = http_fixture.samples_path.read_text(encoding="ascii").splitlines()
        http_header = http_rows[1].split("\t")
        upload_index = http_header.index("upload_meter_attached_sources")
        download_index = http_header.index("download_meter_attached_sources")
        self.assertEqual({int(row.split("\t")[upload_index]) for row in http_rows[2:]}, {0, 16})
        self.assertEqual({int(row.split("\t")[download_index]) for row in http_rows[2:]}, {0, 16})
        invalid_rows = list(http_rows)
        fields = invalid_rows[3].split("\t")
        fields[upload_index] = "17"
        invalid_rows[3] = "\t".join(fields)
        http_fixture.repin("samples", ("\n".join(invalid_rows) + "\n").encode("ascii"))
        with self.assertRaisesRegex(reader.ValidationError, "outside caller-frozen bounds"):
            http_fixture.verify()

    def test_v2_meter_source_bounds_are_workload_frozen(self) -> None:
        expected = {
            "cpu": {
                "disk": (0, "not_applicable"), "upload": (0, "not_applicable"),
                "download": (0, "not_applicable"),
            },
            "disk": {
                "disk": (1, "disk_shared_owner"), "upload": (0, "not_applicable"),
                "download": (0, "not_applicable"),
            },
            "http": {
                "disk": (0, "not_applicable"), "upload": (16, "http_client_and_server_window"),
                "download": (16, "http_client_and_server_window"),
            },
            "mixed": {
                "disk": (1, "disk_shared_owner"), "upload": (16, "http_client_and_server_window"),
                "download": (16, "http_client_and_server_window"),
            },
        }
        base = json.loads(self.fixture.expectation_bytes)
        base.pop("recipe_sha256")
        for workload, directions in expected.items():
            with self.subTest(workload=workload):
                body = json.loads(json.dumps(base))
                body["identity"]["workload"] = workload
                body["identity"]["profile"] = "mixed" if workload == "mixed" else "steady"
                body["policy"]["meter_source_bounds"] = {
                    direction: {
                        "minimum_live": 0, "maximum_live": maximum,
                        "source_rule": rule, "lifetime": "registered_endpoint_owner",
                    }
                    for direction, (maximum, rule) in directions.items()
                }
                reader._validate_expectation_body(body)

                wrong = json.loads(json.dumps(body))
                wrong["policy"]["meter_source_bounds"]["disk"]["maximum_live"] += 1
                with self.assertRaisesRegex(reader.ValidationError, "maximum live meter sources differ"):
                    reader._validate_expectation_body(wrong)

                wrong = json.loads(json.dumps(body))
                wrong["policy"]["meter_source_bounds"]["disk"]["minimum_live"] = 1
                with self.assertRaisesRegex(reader.ValidationError, "minimum live meter sources differ"):
                    reader._validate_expectation_body(wrong)

                wrong = json.loads(json.dumps(body))
                current_rule = wrong["policy"]["meter_source_bounds"]["disk"]["source_rule"]
                wrong["policy"]["meter_source_bounds"]["disk"]["source_rule"] = (
                    "disk_shared_owner" if current_rule == "not_applicable" else "not_applicable"
                )
                with self.assertRaisesRegex(reader.ValidationError, "meter source rule differs"):
                    reader._validate_expectation_body(wrong)

                wrong = json.loads(json.dumps(body))
                wrong["policy"]["meter_source_bounds"]["upload"]["lifetime"] = "application_runtime"
                with self.assertRaisesRegex(reader.ValidationError, "lifetime is unsupported"):
                    reader._validate_expectation_body(wrong)

    def test_v2_rejects_unknown_and_unfrozen_workload_profile_pairs(self) -> None:
        body = json.loads(self.fixture.expectation_bytes)
        body.pop("recipe_sha256")
        invalid_pairs = (
            ("gpu", "steady"), ("unlisted", "unlisted"),
            ("cpu", "unlisted"), ("http", "mixed"),
            ("mixed", "steady"), ("mixed", "unlisted"),
        )
        for workload, profile in invalid_pairs:
            with self.subTest(workload=workload, profile=profile):
                candidate = json.loads(json.dumps(body))
                candidate["identity"]["workload"] = workload
                candidate["identity"]["profile"] = profile
                with self.assertRaisesRegex(reader.ValidationError, "frozen 15-context matrix"):
                    reader._validate_expectation_body(candidate)

        checked = reader._validate_expectation_body(body)
        checked["identity"]["workload"] = "gpu"
        source_manifest = json.loads(self.fixture.source_path.read_bytes())
        with self.assertRaisesRegex(reader.ValidationError, "frozen 15-context matrix"):
            reader.validate_construction_probe(checked, source_manifest)

        legacy = json.loads(json.dumps(body))
        legacy["schema"] = reader.EXPECTATION_SCHEMA_V1
        legacy.pop("construction_probe")
        legacy["identity"]["workload"] = "mixed"
        legacy["identity"]["profile"] = "steady"
        legacy["policy"].pop("meter_source_bounds")
        legacy["policy"]["meter_sources"] = {"disk": 0, "upload": 0, "download": 0}
        self.assertEqual(reader._validate_expectation_body(legacy)["schema"], reader.EXPECTATION_SCHEMA_V1)

    def test_construction_probe_must_match_each_frozen_policy_projection(self) -> None:
        base_body = json.loads(self.fixture.expectation_bytes)
        base_body.pop("recipe_sha256")
        base_probe = json.loads(self.fixture.construction_probe_path.read_bytes())
        cases = (
            ("context", lambda probe: probe["context"].update(workload="http"), "workload or profile"),
            ("timing", lambda probe: probe["reader_context"].update(sample_interval_ns=1), "timing or density"),
            ("control", lambda probe: probe["rust_control_context"]["controls"]["disk"].update(initial=1), "control differs"),
            ("ceiling", lambda probe: probe["rust_control_context"]["global_ceilings"].update(cpu=1), "global_ceilings differ"),
            ("scope", lambda probe: probe["rust_control_context"]["scope_limits"].update(network_operations=1), "scope limits differ"),
            ("bucket", lambda probe: probe["rust_control_context"]["rate_buckets"]["disk"].update(max_reservations=1), "rate bucket differs"),
            ("collector", lambda probe: probe["collector"].update(control_charge_bytes=1), "Control charge differs"),
            ("baseline", lambda probe: probe["baseline"].update(expected_global_control_baseline=1), "baseline differs"),
            ("sources", lambda probe: probe["meter_source_bounds"]["disk"].update(maximum_live=0), "maximum live meter sources differ"),
        )
        for name, mutate, message in cases:
            with self.subTest(component=name):
                probe = json.loads(json.dumps(base_probe))
                mutate(probe)
                probe_raw = reader.canonical_bytes(probe)
                self.fixture.construction_probe_path.write_bytes(probe_raw)
                body = json.loads(json.dumps(base_body))
                body["construction_probe"]["raw_sha256"] = _sha(probe_raw)
                _freeze_fixture_expectation(self.fixture, body)
                with self.assertRaisesRegex(reader.ValidationError, message):
                    self.fixture.verify()

    def test_construction_probe_binary_is_anchored_to_source_manifest(self) -> None:
        body = json.loads(self.fixture.expectation_bytes)
        body.pop("recipe_sha256")
        recipe = reader._validate_expectation_body(body)
        source_manifest = json.loads(self.fixture.source_path.read_bytes())
        source_manifest["artifacts"]["allocatbelt"]["sha256"] = "f" * 64
        with self.assertRaisesRegex(reader.ValidationError, "differs from its source-manifest artifact"):
            reader.validate_construction_probe(recipe, source_manifest)

    def test_trace_directory_scan_stops_early_and_closes_iterator(self) -> None:
        class Entry:
            def __init__(self, name: str, mode: int = stat.S_IFREG | 0o600):
                self.name = name
                self.mode = mode

            def stat(self, *, follow_symlinks: bool) -> Any:
                self.assert_no_follow = not follow_symlinks
                return type("Info", (), {"st_mode": self.mode})()

        class Scan:
            def __init__(self, names: list[str]):
                self.entries = iter(Entry(name) for name in names)
                self.calls = 0
                self.closed = False

            def __enter__(self) -> "Scan":
                return self

            def __exit__(self, *_: object) -> None:
                self.closed = True

            def __iter__(self) -> "Scan":
                return self

            def __next__(self) -> Entry:
                self.calls += 1
                return next(self.entries)

        descriptor = os.open(self.fixture.trace, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            unknown = Scan(["unexpected", "feedback-trace-manifest.tsv"])
            with patch.object(reader.os, "scandir", return_value=unknown):
                with self.assertRaisesRegex(reader.ValidationError, "unexpected entry"):
                    reader._validate_trace_directory_layout(descriptor)
            self.assertEqual(unknown.calls, 1)
            self.assertTrue(unknown.closed)

            linked = Scan(["feedback-trace-manifest.tsv"])
            linked.entries = iter([Entry("feedback-trace-manifest.tsv", stat.S_IFLNK | 0o777)])
            with patch.object(reader.os, "scandir", return_value=linked):
                with self.assertRaisesRegex(reader.ValidationError, "regular nonsymlink"):
                    reader._validate_trace_directory_layout(descriptor)
            self.assertEqual(linked.calls, 1)
            self.assertTrue(linked.closed)

            fourth = Scan([
                "feedback-trace-manifest.tsv", "feedback-events.jsonl", "resource-samples.tsv", "unexpected",
            ])
            with patch.object(reader.os, "scandir", return_value=fourth):
                with self.assertRaisesRegex(reader.ValidationError, "more than three"):
                    reader._validate_trace_directory_layout(descriptor)
            self.assertEqual(fourth.calls, 4)
            self.assertTrue(fourth.closed)
        finally:
            os.close(descriptor)

    def test_unknown_event_fields_and_sequence_gaps_fail_after_hash_repin(self) -> None:
        rows = self.fixture.events_path.read_text(encoding="ascii").splitlines()
        event = json.loads(rows[5])
        event["unknown_field"] = 1
        rows[5] = json.dumps(event, separators=(",", ":"), ensure_ascii=True)
        self.fixture.repin("events", ("\n".join(rows) + "\n").encode("ascii"))
        with self.assertRaises(reader.ValidationError):
            self.fixture.verify()

    def test_unknown_event_sequence_gap_fails_after_hash_repin(self) -> None:
        rows = self.fixture.events_path.read_text(encoding="ascii").splitlines()
        event = json.loads(rows[8])
        event["sequence"] += 1
        rows[8] = json.dumps(event, separators=(",", ":"), ensure_ascii=True)
        self.fixture.repin("events", ("\n".join(rows) + "\n").encode("ascii"))
        with self.assertRaisesRegex(reader.ValidationError, "sequence"):
            self.fixture.verify()

    def test_fabricated_pending_generation_fails_even_when_artifact_hashes_match(self) -> None:
        rows = self.fixture.samples_path.read_text(encoding="ascii").splitlines()
        header = rows[1].split("\t")
        values = rows[-1].split("\t")
        values[header.index("disk_pending_generation")] = "1"
        rows[-1] = "\t".join(values)
        self.fixture.repin("samples", ("\n".join(rows) + "\n").encode("ascii"))
        with self.assertRaisesRegex(reader.ValidationError, "generation|pending"):
            self.fixture.verify()

    def test_bucket_credit_overcommit_and_hard_ceiling_are_rejected(self) -> None:
        rows = self.fixture.samples_path.read_text(encoding="ascii").splitlines()
        header = rows[1].split("\t")
        values = rows[2].split("\t")
        values[header.index("global_used_cpu")] = str(int(values[header.index("global_ceiling_cpu")]) + 1)
        rows[2] = "\t".join(values)
        self.fixture.repin("samples", ("\n".join(rows) + "\n").encode("ascii"))
        with self.assertRaisesRegex(reader.ValidationError, "hard ceiling"):
            self.fixture.verify()

        self.fixture = Fixture(Path(self.temp.name) / "second")
        rows = self.fixture.samples_path.read_text(encoding="ascii").splitlines()
        header = rows[1].split("\t")
        values = rows[2].split("\t")
        values[header.index("disk_rate_reserved_bytes")] = "1"
        rows[2] = "\t".join(values)
        self.fixture.repin("samples", ("\n".join(rows) + "\n").encode("ascii"))
        with self.assertRaisesRegex(reader.ValidationError, "credits"):
            self.fixture.verify()

    def test_refilled_bucket_retains_multiple_original_admissions(self) -> None:
        rows = self.fixture.samples_path.read_text(encoding="ascii").splitlines()
        header = rows[1].split("\t")
        values = rows[2].split("\t")
        burst = int(values[header.index("disk_rate_ceiling_burst_bytes")])
        values[header.index("disk_rate_available_bytes")] = str(burst)
        values[header.index("disk_rate_reserved_bytes")] = str(2 * burst)
        values[header.index("disk_rate_reservations")] = "2"
        rows[2] = "\t".join(values)
        self.fixture.repin("samples", ("\n".join(rows) + "\n").encode("ascii"))
        self.assertTrue(self.fixture.verify()["validated"])

    def test_lowered_burst_preserves_original_owner_ceiling(self) -> None:
        rows = self.fixture.samples_path.read_text(encoding="ascii").splitlines()
        header = rows[1].split("\t")
        values = rows[2].split("\t")
        burst = int(values[header.index("disk_rate_ceiling_burst_bytes")])
        values[header.index("disk_rate_burst_bytes")] = str(burst // 2)
        values[header.index("disk_rate_available_bytes")] = str(burst // 2)
        values[header.index("disk_rate_reserved_bytes")] = str(burst)
        values[header.index("disk_rate_reservations")] = "1"
        rows[2] = "\t".join(values)
        self.fixture.repin("samples", ("\n".join(rows) + "\n").encode("ascii"))
        self.assertTrue(self.fixture.verify()["validated"])

    def test_impossible_available_and_retained_balances_are_rejected(self) -> None:
        mutations = (
            ("available", {"available_bytes": lambda burst: burst + 1}, "available bucket credits"),
            ("owner-cap", {"reserved_bytes": lambda burst: burst + 1, "reservations": lambda _: 1}, "owner bounds"),
            ("zero-owner", {"reserved_bytes": lambda _: 1, "reservations": lambda _: 0}, "owner bounds"),
            ("empty-owner", {"reserved_bytes": lambda _: 1, "reservations": lambda _: 2}, "owner bounds"),
        )
        for name, fields, diagnostic in mutations:
            with self.subTest(name=name):
                self.fixture = Fixture(Path(self.temp.name) / name)
                rows = self.fixture.samples_path.read_text(encoding="ascii").splitlines()
                header = rows[1].split("\t")
                values = rows[2].split("\t")
                burst = int(values[header.index("disk_rate_ceiling_burst_bytes")])
                for field, value in fields.items():
                    values[header.index("disk_rate_" + field)] = str(value(burst))
                rows[2] = "\t".join(values)
                self.fixture.repin("samples", ("\n".join(rows) + "\n").encode("ascii"))
                with self.assertRaisesRegex(reader.ValidationError, diagnostic):
                    self.fixture.verify()

    def test_expectation_rejects_unknown_fields_and_missing_pressure_proofs(self) -> None:
        body = json.loads(self.fixture.expectation_bytes)
        body.pop("recipe_sha256")
        with self.assertRaises(reader.ValidationError):
            reader.build_pressure_expectation_recipe({**body, "skip_policy_check": True})
        pressure = dict(body, mode="pressure_validation", app_capacity_artifact_sha256="c" * 64)
        pressure["identity"] = dict(self.fixture.identity, pressure_qualification=True)
        pressure["minimum_pressure_overlap_seconds"] = 10
        with self.assertRaises(reader.ValidationError):
            reader.build_pressure_expectation_recipe(pressure)

    def test_pressure_proof_must_bind_pid_nonce_binary_and_continuous_window(self) -> None:
        pressure = self._pressure_spec()
        validator_sha = _sha(PRESSURE_READER_PATH.read_bytes())
        proof_path = self.fixture.root / "pressure-readback.json"
        proof = self._pressure_proof(validator_sha)
        proof_path.write_bytes(reader.canonical_bytes(proof))
        pressure["external_pressure_proof"] = {
            "path": str(proof_path), "raw_sha256": _sha(proof_path.read_bytes()),
            "validator_sha256": validator_sha, "recipe_raw_sha256": proof["recipe_raw_sha256"],
        }
        production = (5_200_000_000, 5_200_000_010)
        drain = (6_400_000_000, 6_400_000_010)
        with self.assertRaisesRegex(reader.ValidationError, "does not cover"):
            reader._verify_pressure_proof(pressure, production, drain)
        proof["continuous_ready_window"]["start_monotonic_ns"] = 5_100_000_000
        proof["application_window"]["observed_start_monotonic_ns"] = 5_249_999_999
        proof["application_window"]["observed_exit_monotonic_ns"] = 6_650_000_001
        proof["application_overlap_nanoseconds"] = 1_400_000_002
        proof["readback_sha256"] = reader.digest_object({key: value for key, value in proof.items() if key != "readback_sha256"})
        proof_path.write_bytes(reader.canonical_bytes(proof))
        pressure["external_pressure_proof"]["raw_sha256"] = _sha(proof_path.read_bytes())
        self.assertTrue(reader._verify_pressure_proof(pressure, production, drain)[0])
        with self.assertRaisesRegex(reader.ValidationError, "does not cover"):
            reader._verify_pressure_proof(pressure, (5_099_999_999, 5_100_000_000), drain)
        proof["application_window"]["observed_exit_monotonic_ns"] = 6_249_999_998
        proof["application_overlap_nanoseconds"] = 999_999_999
        proof["readback_sha256"] = reader.digest_object({key: value for key, value in proof.items() if key != "readback_sha256"})
        proof_path.write_bytes(reader.canonical_bytes(proof))
        pressure["external_pressure_proof"]["raw_sha256"] = _sha(proof_path.read_bytes())
        with self.assertRaisesRegex(reader.ValidationError, "measured application pressure overlap"):
            reader._verify_pressure_proof(pressure, production, drain)
        proof["application_window"]["observed_exit_monotonic_ns"] = 6_650_000_001
        proof["application_overlap_nanoseconds"] = 1_400_000_002
        proof["readback_sha256"] = reader.digest_object({key: value for key, value in proof.items() if key != "readback_sha256"})
        proof_path.write_bytes(reader.canonical_bytes(proof))
        pressure["external_pressure_proof"]["raw_sha256"] = _sha(proof_path.read_bytes())
        proof["application_process"]["pid"] += 1
        proof["readback_sha256"] = reader.digest_object({key: value for key, value in proof.items() if key != "readback_sha256"})
        proof_path.write_bytes(reader.canonical_bytes(proof))
        pressure["external_pressure_proof"]["raw_sha256"] = _sha(proof_path.read_bytes())
        with self.assertRaisesRegex(reader.ValidationError, "different application PID"):
            reader._verify_pressure_proof(pressure, production, drain)

    def test_runtime_binding_v2_requires_final_zero_snapshot_and_v1_never_qualifies(self) -> None:
        pressure = self._pressure_spec()
        runtime_path = self.fixture.root / "runtime-binding.tsv"
        pressure["final_runtime_binding"] = {"path": str(runtime_path), "raw_sha256": "0" * 64}
        baseline = str(self.fixture.policy["collector"]["expected_global_control_baseline"])
        rows: dict[str, str] = {
            "identity.report_nonce": self.fixture.identity["report_nonce"],
            "identity.run_id": self.fixture.identity["run_id"],
            "identity.allocator": self.fixture.identity["allocator"],
            "identity.executor": self.fixture.identity["executor"],
            "identity.source_sha256": self.fixture.identity["source_sha256"],
            "identity.binary_sha256": self.fixture.identity["binary_sha256"],
            "identity.comparison_family": "external_pressure",
            "identity.profile": self.fixture.identity["profile"],
            "identity.workload": self.fixture.identity["workload"],
            "configuration.fixed_global_control_baseline": baseline,
            "configuration.managed_memory_limit_bytes": str(self.fixture.policy["scope_limits"]["managed_memory"]),
            "configuration.disk_operation_limit": str(self.fixture.policy["scope_limits"]["disk_operations"]),
            "configuration.network_operation_limit": str(self.fixture.policy["scope_limits"]["network_operations"]),
            "feedback.policy.version": "runtime-feedback-policy-v1",
            "feedback.sample_interval_ms": "100", "feedback.max_dense_sample_gap_ms": "200",
            "feedback.telemetry_freshness_ms": "500", "feedback.required_breach_samples": "3",
            "feedback.actuation_cooldown_ms": "1000", "feedback.minimum_dense_observations": "1",
            "feedback.pressure_qualification_requested": "true",
            "feedback.calibration.artifact_sha256": pressure["app_capacity_artifact_sha256"],
            "feedback.calibration.host_id": self.fixture.identity["host_id"],
            "feedback.calibration.profile": self.fixture.identity["profile"],
            "feedback.calibration.workload": self.fixture.identity["workload"],
            "feedback.calibration.source_sha256": self.fixture.identity["source_sha256"],
            "feedback.calibration.disk.status": "missing", "feedback.calibration.disk.bytes_per_second": "missing",
            "feedback.calibration.disk.units": "missing", "feedback.calibration.download.status": "missing",
            "feedback.calibration.download.bytes_per_second": "missing", "feedback.calibration.download.units": "missing",
            "after_shutdown.feedback.sample_count": "14", "after_shutdown.feedback.worker_failure": "none",
            "after_shutdown.feedback.stop_requested": "true", "after_shutdown.feedback.shutdown_complete": "true",
            "after_shutdown.feedback.reconciliation_pending": "none", "after_shutdown.feedback.reconciliation_in_flight": "none",
            "after_release.global.live_tenants": "0", "after_release.global.used.control": baseline,
            "after_release.expected_global_control_baseline": baseline,
            "after_release.control_matches_fixed_baseline": "true",
        }
        for resource, ceiling in self.fixture.policy["global_ceilings"].items():
            rows[f"configuration.domain_ceiling.{resource}"] = str(ceiling)
            rows[f"after_shutdown.global.ceiling.{resource}"] = str(ceiling)
            rows[f"after_shutdown.global.limit.{resource}"] = str(ceiling)
        for resource, ceiling in self.fixture.policy["tenant_ceilings"].items():
            rows[f"after_shutdown.tenant.ceiling.{resource}"] = str(ceiling)
            rows[f"after_shutdown.tenant.limit.{resource}"] = str(ceiling)
        for owner in ("global", "tenant"):
            for resource in ("cpu", "memory", "disk", "network", "tasks"):
                rows[f"after_shutdown.{owner}.used.{resource}"] = "0"
        for key in ("managed_memory_used", "disk_operations_used", "network_operations_used"):
            rows[f"after_shutdown.scope.{key}"] = "0"
        for row_key, policy_key in (("managed_memory_limit", "managed_memory"),
                                    ("disk_operation_limit", "disk_operations"),
                                    ("network_operation_limit", "network_operations")):
            rows[f"after_shutdown.scope.{row_key}"] = str(self.fixture.policy["scope_limits"][policy_key])
        for direction, bucket in self.fixture.policy["rate_buckets"].items():
            prefix = f"after_shutdown.io.{direction}_"
            rows[prefix + "ceiling_bytes_per_second"] = str(bucket["ceiling_bytes_per_second"])
            rows[prefix + "ceiling_burst_bytes"] = str(bucket["ceiling_burst_bytes"])
            rows[prefix + "max_reservations"] = str(bucket["max_reservations"])
            rows[prefix + "bytes_per_second"] = str(self.fixture.policy["controls"][direction]["initial"] if direction in ("disk", "download") else bucket["ceiling_bytes_per_second"])
            rows[prefix + "burst_bytes"] = str(bucket["ceiling_burst_bytes"])
            rows[prefix + "available_bytes"] = str(bucket["ceiling_burst_bytes"])
            rows[prefix + "reserved_bytes"] = "0"
            rows[prefix + "reservations"] = "0"
        final_policy = {}
        for resource, config in self.fixture.policy["controls"].items():
            fields = {
                "floor": "floor", "initial": "initial", "ceiling": "ceiling",
                "low_utilization_basis_points": "low_bps", "high_utilization_basis_points": "high_bps",
            }
            for output_field, config_field in fields.items():
                rows[f"feedback.policy.{resource}.{output_field}"] = str(config[config_field])
            telemetry = "Fresh" if resource == "cpu" else "Missing"
            utilization = 9000 if resource == "cpu" else None
            feedback_name = {"cpu": "cpu", "disk": "disk_rate", "download": "download_rate"}[resource]
            feedback_prefix = f"after_shutdown.feedback.{feedback_name}."
            rows[feedback_prefix + "current_limit"] = str(config["initial"])
            rows[feedback_prefix + "utilization_basis_points"] = "missing" if utilization is None else str(utilization)
            rows[feedback_prefix + "telemetry"] = telemetry.lower()
            rows[feedback_prefix + "policy_faulted"] = "false"
            rows[feedback_prefix + "pending_generation"] = "none"
            final_policy[resource] = {
                "current_limit": config["initial"], "utilization_basis_points": utilization,
                "telemetry": telemetry, "policy_faulted": False, "pending_generation": None,
            }
        self._write_runtime_binding(runtime_path, rows)
        pressure["final_runtime_binding"]["raw_sha256"] = _sha(runtime_path.read_bytes())
        valid, raw_sha, release_complete = reader._verify_runtime_binding(pressure, final_policy, 14)
        self.assertTrue(valid)
        self.assertEqual(raw_sha, pressure["final_runtime_binding"]["raw_sha256"])
        self.assertFalse(release_complete)

        for resource in ("cpu", "memory", "disk", "network", "tasks"):
            rows[f"after_release.global.used.{resource}"] = "0"
        self._write_runtime_binding(runtime_path, rows)
        pressure["final_runtime_binding"]["raw_sha256"] = _sha(runtime_path.read_bytes())
        with self.assertRaisesRegex(reader.ValidationError, "v1 contains v2-only"):
            reader._verify_runtime_binding(pressure, final_policy, 14)

        self._write_runtime_binding(runtime_path, rows, reader.RUNTIME_BINDING_SCHEMA_V2)
        pressure["final_runtime_binding"]["raw_sha256"] = _sha(runtime_path.read_bytes())
        valid, _, release_complete = reader._verify_runtime_binding(pressure, final_policy, 14)
        self.assertTrue(valid and release_complete)

        missing_key = "after_release.global.used.tasks"
        del rows[missing_key]
        self._write_runtime_binding(runtime_path, rows, reader.RUNTIME_BINDING_SCHEMA_V2)
        pressure["final_runtime_binding"]["raw_sha256"] = _sha(runtime_path.read_bytes())
        with self.assertRaisesRegex(reader.ValidationError, "omits a final after-release"):
            reader._verify_runtime_binding(pressure, final_policy, 14)
        rows[missing_key] = "0"

        rows["after_release.global.used.network"] = "1"
        self._write_runtime_binding(runtime_path, rows, reader.RUNTIME_BINDING_SCHEMA_V2)
        pressure["final_runtime_binding"]["raw_sha256"] = _sha(runtime_path.read_bytes())
        with self.assertRaisesRegex(reader.ValidationError, "live global application usage after owner release"):
            reader._verify_runtime_binding(pressure, final_policy, 14)
        rows["after_release.global.used.network"] = "0"

        rows["after_shutdown.unrecognized_field"] = "0"
        self._write_runtime_binding(runtime_path, rows, reader.RUNTIME_BINDING_SCHEMA_V2)
        pressure["final_runtime_binding"]["raw_sha256"] = _sha(runtime_path.read_bytes())
        with self.assertRaisesRegex(reader.ValidationError, "unknown field"):
            reader._verify_runtime_binding(pressure, final_policy, 14)

    def test_cooldown_quantization_fault_and_recorded_reconciliation(self) -> None:
        pressure = self._pressure_spec()
        pressure["policy"]["controls"]["cpu"] = {"floor": 10, "initial": 100, "ceiling": 1000, "low_bps": 4000, "high_bps": 8000}
        pressure["policy"]["controls"]["download"] = {"floor": 1, "initial": 50, "ceiling": 99, "low_bps": 4000, "high_bps": 8000}
        model = reader.PolicyModel(pressure, 10)
        state = model.states["cpu"]
        state.update({"latest": 9000, "latest_at": 300_000_000, "last_observation": 300_000_000,
                      "last_present": 300_000_000, "breaches": 3, "last_success": 200_000_000})
        decision = model._decision("cpu", 300_000_000)
        self.assertEqual(decision["no_change"], {"reason": "cooling_down", "remaining_min_ns": 900_000_000, "remaining_max_ns": 900_000_000})
        download = model.states["download"]
        download.update({"latest": 1000, "latest_at": 300_000_000, "last_observation": 300_000_000,
                         "last_present": 300_000_000, "breaches": 0})
        self.assertEqual(model._decision("download", 300_000_000)["no_change"], {"reason": "recovery_quantized"})

        ticket = {"resource": "cpu", "generation": 1, "from_limit": 100, "to_limit": 90,
                  "planned_at_bounds": (400_000_000, 400_000_010)}
        state["pending"] = ticket
        state["faulted"] = False
        model.seen_generations.add(1)
        model.ticket_count = 1
        model.pending_intervals["cpu"].append([1, 400_000_000, None])
        model.ticket_queue = [ticket]
        model.current_ticket = ticket
        model.ticket_stage = "pre"
        ticket_json = {"resource": "cpu", "generation": 1, "from_limit": 100, "to_limit": 90,
                       "planned_at": [400_000_000, 400_000_010]}
        model.validate_ticket_event({
            "kind": "pre_apply_readback", "ticket": ticket_json,
            "started_at": _bracket(401_000_000), "completed_at": _bracket(402_000_000),
            "outcome": "failed", "actual_limit": None, "error": "readback error", "matches_ticket": False,
        }, 403_000_000)
        model.validate_ticket_event({
            "kind": "acknowledgement", "ticket": ticket_json, "result": "Failed",
            "accepted": True, "current_limit": 100, "faulted": True, "pending_generation": None,
        }, 404_000_000)
        self.assertEqual(model._decision("cpu", 405_000_000)["no_change"], {"reason": "actuation_fault_latched"})
        model.reconciliation = {"resource": "cpu", "stage": "finish", "outcome": "value", "actual": 90,
                               "readback_completed": 999_000_000}
        model.finish_reconciliation({
            "resource": "cpu", "actual_limit": 90, "accepted": True, "current_limit": 90,
            "faulted": False, "pending_generation": None, "rejection": None,
        }, 1_000_000_000)
        self.assertFalse(state["faulted"])
        self.assertEqual(model._decision("cpu", 1_050_000_000)["no_change"], {"reason": "telemetry_unavailable"})
        for sample_at in (1_100_000_000, 1_200_000_000, 1_300_000_000, 1_400_000_000):
            model.observe(sample_at, {"cpu": 9000, "disk": None, "download": None})
        cooldown = model._decision("cpu", 1_400_000_300)["no_change"]
        self.assertEqual(cooldown["reason"], "cooling_down")
        self.assertLessEqual(cooldown["remaining_min_ns"], cooldown["remaining_max_ns"])

    def _pressure_spec(self) -> dict[str, Any]:
        body = json.loads(self.fixture.expectation_bytes)
        body.pop("recipe_sha256")
        body["mode"] = "pressure_validation"
        body["identity"]["pressure_qualification"] = True
        body["app_capacity_artifact_sha256"] = "c" * 64
        body["external_pressure_proof"] = {
            "path": str(self.fixture.root / "pressure-readback.json"), "raw_sha256": "d" * 64,
            "validator_sha256": _sha(PRESSURE_READER_PATH.read_bytes()), "recipe_raw_sha256": "e" * 64,
        }
        body["final_runtime_binding"] = {"path": str(self.fixture.root / "runtime-binding.tsv"), "raw_sha256": "f" * 64}
        body["minimum_pressure_overlap_seconds"] = 1
        return body

    @staticmethod
    def _write_runtime_binding(
        path: Path, rows: dict[str, str], schema: str = reader.RUNTIME_BINDING_SCHEMA_V1,
    ) -> None:
        content = f"schema\t{schema}\n" + "".join(
            f"{key}\t{value}\n" for key, value in sorted(rows.items())
        )
        path.write_text(content, encoding="ascii")

    def _pressure_proof(self, validator_sha: str) -> dict[str, Any]:
        body = {
            "schema": reader.PRESSURE_READBACK_SCHEMA, "status": "valid",
            "recipe_sha256": "1" * 64, "recipe_raw_sha256": "e" * 64,
            "validator_sha256": validator_sha, "condition_sha256": "2" * 64,
            "identity": {
                "host_id": self.fixture.identity["host_id"], "run_id": self.fixture.identity["run_id"],
                "pair_id": "pair-01", "condition_id": "condition-01", "member": "member-a",
                "nonce": self.fixture.identity["report_nonce"], "allocator": self.fixture.identity["allocator"],
                "executor": self.fixture.identity["executor"], "phase": "external_pressure",
            },
            "run_sha256": "3" * 64, "events_sha256": "4" * 64,
            "launch_record_sha256": "5" * 64, "process_binding_sha256": "6" * 64,
            "readiness_marker_sha256": "7" * 64, "sample_count": 20,
            "application_overlap_nanoseconds": 1_400_000_000,
            "application_process": {"pid": self.fixture.identity["process_id"], "start_ticks": 99,
                                     "nonce": self.fixture.identity["report_nonce"],
                                     "executable_sha256": self.fixture.identity["binary_sha256"]},
            "application_window": {"observed_start_monotonic_ns": 5_250_000_000,
                                   "observed_exit_monotonic_ns": 6_650_000_000},
            "continuous_ready_window": {"start_monotonic_ns": 5_250_000_000,
                                         "end_monotonic_ns": 6_650_000_000},
            "readiness_windows_passed": True, "cleanup_rechecked": True,
            "physical_nic_claimed": False,
        }
        return {**body, "readback_sha256": reader.digest_object(body)}


def run_feedback_offline_fixture(request_path: Path, expected_request_raw_sha256: str) -> dict[str, Any]:
    """Public replay harness for genuine captured ProbeV2 and pressure bytes."""
    request, request_raw_sha = reader.read_canonical(
        request_path, "feedback offline fixture request", 4 * 1024 * 1024,
        expected_request_raw_sha256,
    )
    reader.exact(request, {
        "schema", "expectation", "trace_directory", "artifact_sha256",
        "replay_context", "pressure_replay_request", "expected_readback",
    }, "feedback offline fixture request")
    if request["schema"] != FEEDBACK_OFFLINE_FIXTURE_SCHEMA:
        raise reader.ValidationError("unsupported feedback offline fixture request schema")
    expectation_pin = reader.exact(request["expectation"], {"path", "raw_sha256"},
                                   "feedback offline fixture expectation pin")
    expected_readback_pin = reader.exact(request["expected_readback"], {"path", "raw_sha256"},
                                         "feedback offline fixture readback pin")
    checked_context = reader._validate_feedback_offline_context(request["replay_context"])
    reader._require_offline_files(checked_context, {expected_readback_pin["path"]},
                                  "origin-host feedback readback")
    actual = reader.verify_feedback_offline(
        Path(expectation_pin["path"]), expectation_pin["raw_sha256"],
        Path(request["trace_directory"]), request["artifact_sha256"],
        replay_context=request["replay_context"],
        pressure_replay_request=request["pressure_replay_request"],
    )
    expected, expected_raw_sha = reader.read_canonical(
        Path(expected_readback_pin["path"]), "origin-host feedback readback",
        reader.MAX_EXPECTATION_BYTES, expected_readback_pin["raw_sha256"],
    )
    if expected_raw_sha != expected_readback_pin["raw_sha256"] or actual != expected:
        raise reader.ValidationError("offline feedback result differs from the exact origin-host readback bytes")
    if actual.get("validated") is not True or actual.get("qualification_eligible") is not False:
        raise reader.ValidationError("offline feedback fixture returned an invalid or eligible result")
    return {"request_raw_sha256": request_raw_sha, "readback": actual}



class HelperTests(unittest.TestCase):
    def test_canonical_parser_rejects_duplicate_keys_nonfinite_values_and_boolean_integer(self) -> None:
        with self.assertRaises(reader.ValidationError):
            reader.parse_json(b'{"value":1,"value":2}', "duplicate", 128)
        with self.assertRaises(reader.ValidationError):
            reader.parse_json(b'{"value":NaN}', "nonfinite", 128)
        with self.assertRaises(reader.ValidationError):
            reader.uint(True, "bool-as-integer")

    def test_closed_recorded_probe_api_is_named_and_requires_capture_context(self) -> None:
        function = reader.validate_calibrated_construction_probe_v2_closed_recorded_v1
        parameters = inspect.signature(function).parameters
        self.assertEqual(list(parameters), [
            "probe_pin", "source_manifest_pin", "capacity_artifact_pin", "identity",
            "replay_context", "expected_policy", "capacity_floor_policy_id",
        ])
        self.assertEqual(parameters["replay_context"].default,
                         inspect.Parameter.empty)
        self.assertNotIn("closed_recorded", parameters)


class OfflineProbeReplayContextTests(unittest.TestCase):
    def test_closed_recorded_probe_rejects_selected_and_other_elf_map_entries_before_io(self) -> None:
        identity = {
            "host_id": "closed-map-host", "workload": "mixed",
            "profile": "mixed", "binary_sha256": "a" * 64,
        }
        source_manifest = _source_v5_manifest(identity)
        source_root = SCRIPT_DIR.parent.resolve()
        source_path = Path(tempfile.mkdtemp(prefix="feedback-closed-source-pin-")) / "source.json"
        self.addCleanup(shutil.rmtree, source_path.parent, ignore_errors=True)
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_raw = reader.canonical_bytes(source_manifest)
        source_path.write_bytes(source_raw)
        source_pin = {"path": str(source_path), "raw_sha256": _sha(source_raw)}
        temp_root = source_path.parent
        probe_pin = {
            "path": str(temp_root / "probe.json"), "raw_sha256": "b" * 64,
            "allocator": "allocatbelt", "binary_sha256": "a" * 64,
        }
        capacity_pin = {"path": str(temp_root / "capacity.tsv"),
                        "raw_sha256": "c" * 64}
        capacity_bundle = {
            "request": {"path": str(temp_root / "request.json"), "raw_sha256": "d" * 64},
            "artifact": capacity_pin,
            "receipt": {"path": str(temp_root / "capacity-receipt.json"), "raw_sha256": "e" * 64},
        }
        identity["source_sha256"] = source_manifest["source"]["source_tree_sha256"]
        replay_context = {
            "schema": reader.FEEDBACK_OFFLINE_CONTEXT_SCHEMA,
            "evidence_path_map": {
                "schema": reader.EVIDENCE_PATH_MAP_SCHEMA,
                "entries": [],
            },
            "probe_capture_pin": {
                "path": str(temp_root / "capture.json"),
                "raw_sha256": "f" * 64, "receipt_sha256": "1" * 64,
            },
            "capacity_bundle": capacity_bundle,
        }
        original_methods = {
            "lstat": Path.lstat, "stat": Path.stat,
            "resolve": Path.resolve, "open": Path.open,
        }

        def denied(path_value: object, label: str) -> None:
            try:
                rendered = os.fsdecode(os.fspath(path_value))
            except (TypeError, ValueError):
                return
            if rendered in forbidden:
                raise AssertionError(f"closed probe API touched Source ELF with {label}")

        def path_method(name: str):
            original = original_methods[name]

            def guarded(path_value: Path, *args: Any, **kwargs: Any):
                denied(path_value, name)
                return original(path_value, *args, **kwargs)
            return guarded

        def denied_os(path_value: object, label: str) -> None:
            try:
                rendered = os.fsdecode(os.fspath(path_value))
            except (TypeError, ValueError):
                return
            if rendered in forbidden:
                raise AssertionError(f"closed probe API touched Source ELF with {label}")

        real_os_open, real_os_stat, real_os_lstat = os.open, os.stat, os.lstat
        real_builtin_open, real_io_open = open, io.open

        def os_method(method, label: str):
            def guarded(path_value: object, *args: Any, **kwargs: Any):
                denied_os(path_value, label)
                return method(path_value, *args, **kwargs)
            return guarded

        def guarded_open(path_value: object, *args: Any, **kwargs: Any):
            return os_method(real_os_open, "open")(path_value, *args, **kwargs)

        def guarded_stat(path_value: object, *args: Any, **kwargs: Any):
            return os_method(real_os_stat, "stat")(path_value, *args, **kwargs)

        def guarded_lstat(path_value: object, *args: Any, **kwargs: Any):
            return os_method(real_os_lstat, "lstat")(path_value, *args, **kwargs)

        def guarded_builtin_open(path_value: object, *args: Any, **kwargs: Any):
            denied(path_value, "open")
            return real_builtin_open(path_value, *args, **kwargs)

        def guarded_io_open(path_value: object, *args: Any, **kwargs: Any):
            denied(path_value, "open")
            return real_io_open(path_value, *args, **kwargs)

        artifact_records = {
            label: source_manifest["artifacts"][label]
            for label in ("allocatbelt", "mimalloc-secure", "mimalloc-standard", "system")
        }
        artifact_records.update({
            "soak-allocatbelt": source_manifest["soak_artifacts"]["allocatbelt"],
            "analyzer": source_manifest["analysis_artifact"],
            "resource-domain-calibration": source_manifest["resource_domain_calibration"]["binary"],
        })
        forbidden = {
            str(source_root / artifact["path"])
            for artifact in artifact_records.values()
        }
        for label, artifact in artifact_records.items():
            artifact_path = str(source_root / artifact["path"])
            replay_context["evidence_path_map"]["entries"] = [
                {"origin": artifact_path, "local": artifact_path},
            ]
            with self.subTest(allocator=label):
                with patch.object(Path, "lstat", new=path_method("lstat")), \
                        patch.object(Path, "stat", new=path_method("stat")), \
                        patch.object(Path, "resolve", new=path_method("resolve")), \
                        patch.object(Path, "open", new=path_method("open")), \
                        patch.object(os, "open", new=guarded_open), \
                        patch.object(os, "stat", new=guarded_stat), \
                        patch.object(os, "lstat", new=guarded_lstat), \
                        patch("builtins.open", new=guarded_builtin_open), \
                        patch.object(io, "open", new=guarded_io_open), \
                        patch.object(subprocess, "Popen",
                                     side_effect=AssertionError("closed probe API attempted Popen")):
                    with self.assertRaisesRegex(
                            reader.ValidationError, "executable artifact"):
                        reader.validate_calibrated_construction_probe_v2_closed_recorded_v1(
                            probe_pin, source_pin, capacity_pin, identity,
                            replay_context=replay_context,
                        )

    def test_offline_context_uses_closed_sorted_identity_mapping(self) -> None:
        with tempfile.TemporaryDirectory(prefix="feedback-offline-map-", dir="/var/tmp") as directory:
            root = Path(directory).resolve(strict=True)
            context = {
                "schema": reader.FEEDBACK_OFFLINE_CONTEXT_SCHEMA,
                "evidence_path_map": {
                    "schema": reader.EVIDENCE_PATH_MAP_SCHEMA,
                    "entries": [{"origin": str(root), "local": str(root)}],
                },
                "probe_capture_pin": {
                    "path": str(root / "capture.json"), "raw_sha256": "a" * 64,
                    "receipt_sha256": "b" * 64,
                },
                "capacity_bundle": {
                    "request": {"path": str(root / "request.json"), "raw_sha256": "c" * 64},
                    "artifact": {"path": str(root / "capacity.tsv"), "raw_sha256": "d" * 64},
                    "receipt": {"path": str(root / "receipt.json"), "raw_sha256": "e" * 64},
                },
            }
            checked = reader._validate_feedback_offline_context(context)
            self.assertEqual(checked["mapped_directories"], frozenset({str(root)}))
            self.assertEqual(checked["capacity_bundle"], context["capacity_bundle"])

            aliased = json.loads(json.dumps(context))
            aliased["evidence_path_map"]["entries"][0]["local"] = str(root / "local-copy")
            with self.assertRaisesRegex(reader.ValidationError, "identity paths"):
                reader._validate_feedback_offline_context(aliased)

            unknown = {**context, "validated": True}
            with self.assertRaisesRegex(reader.ValidationError, "unexpected key set"):
                reader._validate_feedback_offline_context(unknown)

    def test_captured_probe_v2_replays_exact_nonempty_typed_tree_without_origin_paths(self) -> None:
        class View:
            def __init__(self, objects: dict[str, bytes]):
                self.objects = objects

            def has_file(self, path: str | Path) -> bool:
                return str(path) in self.objects

            def read(self, path: str | Path, _label: str, maximum: int):
                raw = self.objects[str(path)]
                reader.require(len(raw) <= maximum, "test view parser cap")
                return raw, hashlib.sha256(raw).hexdigest()

            def open_snapshot(self, *_args: Any):
                path, label, maximum = _args
                raw = self.objects[str(path)]
                reader.require(len(raw) <= maximum, f"{label} test snapshot cap")
                @contextlib.contextmanager
                def snapshot():
                    yield io.BytesIO(raw), hashlib.sha256(raw).hexdigest(), len(raw)
                return snapshot()

        with tempfile.TemporaryDirectory(prefix="feedback-captured-tree-") as directory:
            base = Path(directory) / "origin" / "job"
            output_root = base / "probe-output"
            tmp_root = output_root / "tmp"
            capture_path = output_root / "capture-receipt.json"
            stdout_path = output_root / "stdout.bin"
            stderr_path = output_root / "stderr.bin"
            owner_path = output_root / "owner-result.json"
            inventory_path = output_root / "tmpdir-inventory.json"
            trace_path = tmp_root / "opaque.trace"
            trace = b"captured trace bytes\n"
            trace_entry = {
                "path": str(trace_path), "kind": "file", "uid": os.getuid(),
                "mode": 0o600, "size": len(trace),
                "raw_sha256": hashlib.sha256(trace).hexdigest(),
            }
            inventory_body = {
                "schema": reader.PROBE_TMPDIR_INVENTORY_SCHEMA,
                "entries": [trace_entry],
            }
            inventory = {
                **inventory_body,
                "inventory_sha256": hashlib.sha256(
                    reader.canonical_bytes(inventory_body),
                ).hexdigest(),
            }
            inventory_raw = reader.canonical_bytes(inventory)
            owner_body = {
                "schema": reader.PROBE_OWNER_RESULT_SCHEMA,
                "direct": {}, "start_callback_count": 0,
                "start_callback_proofs": [],
            }
            owner = {
                **owner_body,
                "owner_result_sha256": hashlib.sha256(
                    reader.canonical_bytes(owner_body),
                ).hexdigest(),
            }
            owner_raw = reader.canonical_bytes(owner)
            raw_files = {
                str(capture_path): b"captured owner receipt bytes\n",
                str(stdout_path): b"{}\n", str(stderr_path): b"",
                str(owner_path): owner_raw,
                str(inventory_path): inventory_raw,
                str(trace_path): trace,
            }
            pin = lambda path, raw: {
                "path": str(path), "raw_sha256": hashlib.sha256(raw).hexdigest(),
            }
            capture_pin = {
                **pin(capture_path, raw_files[str(capture_path)]),
                "receipt_sha256": "a" * 64,
            }
            inventory_pin = {
                **pin(inventory_path, inventory_raw),
                "inventory_sha256": inventory["inventory_sha256"],
            }
            owner_pin = {
                **pin(owner_path, owner_raw),
                "owner_result_sha256": owner["owner_result_sha256"],
            }
            capture = {
                "stdout": pin(stdout_path, raw_files[str(stdout_path)]),
                "stderr": pin(stderr_path, raw_files[str(stderr_path)]),
                "owner_result_pin": owner_pin,
                "tmpdir_inventory_pin": inventory_pin,
                "tmpdir_initial": {
                    "path": str(tmp_root), "device": 1, "inode": 2,
                    "mode": 0o700, "mount": {}, "available_bytes": 8192,
                    "available_inodes": 32, "bytes_limit": 4096,
                    "inode_limit": 16,
                },
                "tmpdir_final": {
                    "path": str(tmp_root), "device": 1, "inode": 2,
                    "mode": 0o700, "mount": {}, "bytes_used": len(trace),
                    "file_count": 1, "directory_count": 0,
                    "bytes_limit": 4096, "inode_limit": 16,
                    "available_bytes": 8192, "available_inodes": 32,
                },
                "storage_budget": {
                    "tmpdir_bytes": 4096, "tmpdir_inodes": 16,
                    "stdout_bytes": 1024, "stderr_bytes": 64 * 1024,
                    "owner_result_bytes": reader.MAX_PROBE_OWNER_RESULT_BYTES,
                    "inventory_bytes": reader.MAX_PROBE_TMPDIR_INVENTORY_BYTES,
                    "failure_bytes": reader.MAX_PROBE_CAPTURE_FAILURE_BYTES,
                    "receipt_bytes": 1024 * 1024, "output_inodes": 8,
                },
            }
            tree = {
                "owner_job_sha256": "b" * 64, "root_path": str(tmp_root),
                "role": "opaque_trace",
                "owner_receipt_pin": {
                    "path": capture_pin["path"],
                    "raw_sha256": capture_pin["raw_sha256"],
                    "semantic_sha256": capture_pin["receipt_sha256"],
                },
                "inventory_pin": {
                    "path": inventory_pin["path"],
                    "raw_sha256": inventory_pin["raw_sha256"],
                    "semantic_sha256": inventory_pin["inventory_sha256"],
                },
                "inventory_sha256": inventory_pin["inventory_sha256"],
                "entry_count": 1, "byte_count": len(trace),
                "entries": [trace_entry],
            }
            paths = sorted(raw_files)
            context = {
                "schema": reader.FEEDBACK_CAPTURED_OFFLINE_CONTEXT_SCHEMA,
                "artifact_view": View(raw_files),
                "captured_origin_paths": paths,
                "evidence_file_paths": paths,
                "evidence_directory_paths": sorted({str(output_root), str(tmp_root)}),
                "source_symlink_paths": [], "tree_inventories": [tree],
                "probe_capture_pin": capture_pin,
                "capacity_bundle": {
                    "request": {"path": str(base / "capacity-request.json"), "raw_sha256": "c" * 64},
                    "artifact": {"path": str(base / "capacity.tsv"), "raw_sha256": "d" * 64},
                    "receipt": {"path": str(base / "capacity-receipt.json"), "raw_sha256": "e" * 64},
                },
            }
            checked = reader._validate_feedback_offline_context(context)
            self.assertFalse(output_root.exists(), "archived origin output must not be statted or recreated")
            self.assertEqual(reader._preflight_probe_capture_tree(
                capture, checked, capture_path,
            ), [trace_entry])

            altered = dict(context)
            altered["tree_inventories"] = [{**tree, "byte_count": len(trace) + 1}]
            checked_altered = reader._validate_feedback_offline_context(altered)
            with self.assertRaisesRegex(reader.ValidationError, "typed tree differs"):
                reader._preflight_probe_capture_tree(
                    capture, checked_altered, capture_path,
                )


    def test_pressure_pair_request_rejects_caller_supplied_success_flags_before_io(self) -> None:
        request = {
            "schema": reader.PRESSURE_PAIR_REPLAY_REQUEST_SCHEMA,
            "source_manifest": {}, "source_root": "/no/read",
            "pair": {}, "module_pins": {}, "validated": True,
        }
        with self.assertRaisesRegex(reader.ValidationError, "unexpected key set"):
            reader._verify_pressure_pair_replay_request(
                request, {}, {}, {"mapped_paths": frozenset(),
                                  "mapped_directories": frozenset(),
                                  "mapped_files": frozenset()},
            )


    def test_omitted_nested_json_path_fails_before_nested_read(self) -> None:
        with tempfile.TemporaryDirectory(prefix="feedback-offline-closure-") as directory:
            root = Path(directory).resolve(strict=True)
            parent = root / "request.json"
            child = root / "nested.json"
            document = {"capacity": {"path": str(child)}}
            context = {
                "mapped_paths": frozenset({str(root), str(parent)}),
                "mapped_files": frozenset({str(parent)}),
                "mapped_directories": frozenset({str(root)}),
            }
            reads: list[str] = []
            original = reader.read_canonical

            def guarded(path: Path, *args: Any, **kwargs: Any):
                reads.append(str(path))
                if str(path) not in context["mapped_files"]:
                    raise AssertionError(f"unmapped file read: {path}")
                return original(path, *args, **kwargs)

            with patch.object(reader, "read_canonical", side_effect=guarded):
                with self.assertRaisesRegex(reader.ValidationError, "omits exact"):
                    reader._preflight_feedback_nested_json_paths([document], context)
            self.assertEqual(reads, [])


if __name__ == "__main__":
    unittest.main()
