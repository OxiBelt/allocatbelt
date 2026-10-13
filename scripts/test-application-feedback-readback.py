#!/usr/bin/env python3
"""Focused native fixtures for the application feedback trace reader.

Run only on the designated SSH-MCP native host. Fixtures are synthetic trace
artifacts; they do not launch an application or establish performance.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch


SCRIPT_DIR = Path(__file__).resolve().parent
READER_PATH = SCRIPT_DIR / "application-feedback-readback.py"
PRESSURE_READER_PATH = SCRIPT_DIR / "application-pressure-readback.py"


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


reader = _load("application_feedback_readback_test_target", READER_PATH)


class Fixture:
    def __init__(self, root: Path, workload: str = "disk"):
        self.root = root
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
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
            "profile": "mixed" if workload == "mixed" else "steady",
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
        sample_times = [base + 200_000_000 + index * 100_000_000 for index in range(14)]
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
        events.append(self._event(sequence, "stop_requested", base + 1_501_000_000))
        sequence += 1
        events.append(self._event(sequence, "worker_joined", base + 1_502_000_000, panicked=False))
        self.events_path = self.trace / "feedback-events.jsonl"
        self.events_path.write_bytes(b"".join(_json_line(event) for event in events))

        row_times = [base + 150_000_000 + index * 100_000_000 for index in range(16)]
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
                self.policy, index, row_time, 14 if final else min(14, max(0, index - 1)), final,
                attached_sources=attached_sources,
            ))
        self.samples_path = self.trace / "resource-samples.tsv"
        self.samples_path.write_bytes(b"".join(sample_lines))

        event_sha = _sha(self.events_path.read_bytes())
        sample_sha = _sha(self.samples_path.read_bytes())
        phases = {
            "production_start": (base + 200_000_000, None),
            "production_end": (base + 1_300_000_000, None),
            "drain_end": (base + 1_400_000_000, None),
            "rss_before": (base + 190_000_000, (100, 120)),
            "rss_after_drain": (base + 1_410_000_000, (102, 125)),
            "shutdown_end": (base + 1_540_000_000, None),
            "rss_after_shutdown": (base + 1_580_000_000, (101, 125)),
            "owner_release": (base + 1_700_000_000, None),
        }
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
            "control\tcollector_charge_bytes\t4096\texpected_global_control_baseline\t8192\n",
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


def _freeze_fixture_expectation(fixture: Fixture, body: dict[str, Any]) -> None:
    raw, raw_sha = reader.build_pressure_expectation_recipe(body)
    fixture.expectation_bytes = raw
    fixture.expectation_sha = raw_sha
    fixture.expectation_path.write_bytes(raw)


def _sample_row(
    policy: dict[str, Any], sequence: int, lower: int, feedback_count: int, final: bool,
    *, attached_sources: dict[str, int] | None = None,
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
        for field, value in {
            "measured_lower_ns": lower + 100, "measured_upper_ns": lower + 110,
            "committed_bytes": 0, "completions": 0,
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


class HelperTests(unittest.TestCase):
    def test_canonical_parser_rejects_duplicate_keys_nonfinite_values_and_boolean_integer(self) -> None:
        with self.assertRaises(reader.ValidationError):
            reader.parse_json(b'{"value":1,"value":2}', "duplicate", 128)
        with self.assertRaises(reader.ValidationError):
            reader.parse_json(b'{"value":NaN}', "nonfinite", 128)
        with self.assertRaises(reader.ValidationError):
            reader.uint(True, "bool-as-integer")


if __name__ == "__main__":
    unittest.main()
