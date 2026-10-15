#!/usr/bin/env python3
"""Focused pure-contract checks for the SourceV5 fixed-pair executor."""

from __future__ import annotations

import ast
import copy
import contextlib
import errno
import hashlib
import importlib.util
import io
import json
import os
import signal
import stat
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("application-fixed-pair.py")
SPEC = importlib.util.spec_from_file_location("application_fixed_pair_under_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
FIXED = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = FIXED
SPEC.loader.exec_module(FIXED)


def _load_source_module(name: str, path: Path) -> types.ModuleType:
    raw = path.read_bytes()
    module = FIXED._load_pinned_module(raw, path.resolve(strict=True), name)
    return module


FEEDBACK_FIXTURE_PATH = Path(__file__).with_name("test-application-feedback-readback.py")
FEEDBACK_FIXTURE_SPEC = importlib.util.spec_from_file_location("fixed_pair_feedback_fixtures", FEEDBACK_FIXTURE_PATH)
assert FEEDBACK_FIXTURE_SPEC is not None and FEEDBACK_FIXTURE_SPEC.loader is not None
FEEDBACK_FIXTURES = importlib.util.module_from_spec(FEEDBACK_FIXTURE_SPEC)
sys.modules[FEEDBACK_FIXTURE_SPEC.name] = FEEDBACK_FIXTURES
FEEDBACK_FIXTURE_SPEC.loader.exec_module(FEEDBACK_FIXTURES)


def _real_binding_case(root: Path, *, write_expectations: bool) -> tuple[dict[str, object], list[dict[str, object]]]:
    source_root = root / "source"
    binary_path = source_root / "target" / "application-allocatbelt"
    binary_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    binary_path.write_bytes(b"synthetic pinned APP bytes; never executed by this fixture")
    binary_path.chmod(0o755)
    output_root = root / "output"
    output_root.mkdir(mode=0o700)
    reader_path = SCRIPT.with_name("application-runtime-readback.py")
    reader_raw = reader_path.read_bytes()
    reader_sha = hashlib.sha256(reader_raw).hexdigest()
    controller = _load_source_module("fixed_pair_real_campaign_controller", SCRIPT.with_name("application-campaign.py"))
    runtime_reader = controller.runtime_readback_module(reader_sha)
    binary_sha = hashlib.sha256(binary_path.read_bytes()).hexdigest()
    source_tree_sha = "a" * 64
    ceiling_sha = "e" * 64
    policy_sha = "b" * 64
    calibration_sha = "c" * 64
    calibration_output_sha = "d" * 64
    source = {
        "manifest_sha256": "f" * 64,
        "source": {"source_tree_sha256": source_tree_sha},
        "artifacts": {"allocatbelt": {"path": "target/application-allocatbelt", "sha256": binary_sha}},
        "fixed_runtime_policy": {"policy_sha256": policy_sha},
        "resource_domain_calibration": {
            "record": {"fixed_global_control_baseline": 20_896},
            "binary": {"path": "target/calibration", "sha256": calibration_sha},
            "output": {"path": "target/calibration.json", "sha256": calibration_output_sha},
        },
        "runtime_readback_validator": {"path": "scripts/application-runtime-readback.py", "sha256": reader_sha},
    }
    spec = {
        "campaign_id": "fixed-pair-test-campaign",
        "cells": [{"family": "cpu", "profile": "steady", "resource_ceiling_sha256": ceiling_sha}],
        "deadlines": {"trace_seconds": 30, "drain_seconds": 6, "shutdown_seconds": 10, "process_seconds": 80},
    }
    job = {
        "host_id": "host-a", "phase": "confirmation", "comparison_family": "fixed_policy",
        "family": "cpu", "workload": "cpu", "profile": "steady", "mode": "capacity",
        "load_percent": None, "rate_per_second": None, "arrivals": None, "ordinal": 2,
        "allocator": "allocatbelt", "comparison_kind": "executor", "pair_kind": "matched",
        "oracle": None, "run_id": "fixed-pair-test-run",
    }
    bindings = controller.build_runtime_process_bindings(job, spec, source)
    context = {
        "job": job,
        "spec": spec,
        "source": source,
        "source_root": source_root,
        "campaign_artifacts_root": root / "oracles",
        "output_root": output_root,
        "controller": controller,
        "loaded_modules": {"runtime_reader": runtime_reader},
        "host_value": {"controls": {"cpu_set": "0"}},
        "cpu_ids": [0],
        "observed_host": {"network_namespace_inode": 12345},
    }
    members = FIXED._construct_members(context, bindings)
    context["members"] = members
    if write_expectations:
        for member in members:
            path = Path(member["outputs"]["runtime_expectation"])
            path.write_bytes(runtime_reader.canonical_bytes(member["runtime_expectation"]["value"]))
            path.chmod(0o600)
    return context, bindings


def _synthetic_attempt(member: dict[str, object], overlay_sha256: str, status: int) -> dict[str, object]:
    descriptor = member["descriptor"]
    pid = 41000 + member["ordinal"]
    supervision = {
        "cleanup_status": "verified", "leader_reaped": True,
        "remaining_session_members": [], "cleanup_errors": [],
        "group_signal_after_leader_reap_count": 0, "signals": [],
    }
    start = {
        "schema": FIXED.APP_STARTED_SCHEMA, "role": "fixed_application_member",
        "pid": pid, "start_ticks": 51000 + member["ordinal"],
    }
    terminal = {
        "schema": FIXED.APP_TERMINAL_SCHEMA, "overlay_sha256": overlay_sha256,
        "pid": pid, "descriptor": descriptor, "cleanup": supervision, "status": status,
    }
    return {
        "ordinal": member["ordinal"], "descriptor": descriptor, "attempted": True,
        "status": status, "child_return_code": status, "start": start,
        "terminal_event": terminal, "supervision": supervision,
        "tmpdir_initial": {"path": member["tmpdir"]["path"]},
        "tmpdir_final": {"path": member["tmpdir"]["path"]},
    }


def _run_synthetic_receipt_case(
    root: Path, statuses: list[int], *, row_failure_ordinal: int | None = None,
) -> tuple[dict[str, object], list[int], list[dict[str, object]]]:
    context, bindings = _real_binding_case(root, write_expectations=True)
    output_root = context["output_root"]
    bindings_path = output_root / "runtime-bindings.json"
    bindings_raw = FIXED.canonical_bytes(bindings)
    bindings_path.write_bytes(bindings_raw)
    bindings_path.chmod(0o600)
    overlay_path = output_root / "fixed-pair-execution-overlay.json"
    overlay_path.write_bytes(b"synthetic overlay pin; not a dispatchable artifact\n")
    overlay_path.chmod(0o600)
    overlay_sha256 = "9" * 64
    overlay = {
        "campaign_id": context["spec"]["campaign_id"],
        "host_id": context["job"]["host_id"],
        "job": {"value": context["job"]},
        "sources": {"historical_runner_sha256": "8" * 64},
        "modules": {}, "execution_source": {},
        "members": context["members"], "output_root": str(output_root),
        "deadlines": {"outer_seconds": 60},
        "runtime_bindings": {"pin": {"path": str(bindings_path), "sha256": hashlib.sha256(bindings_raw).hexdigest()}},
    }
    context["runtime_bindings_raw"] = bindings_raw
    context["runtime_bindings_sha256"] = hashlib.sha256(bindings_raw).hexdigest()
    attempts = [_synthetic_attempt(member, overlay_sha256, status) for member, status in zip(context["members"], statuses, strict=True)]
    launched: list[int] = []

    def launch(_overlay: object, _context: object, member: dict[str, object], *_args: object) -> dict[str, object]:
        launched.append(member["ordinal"])
        return attempts[member["ordinal"]]

    def validate(_context: object, member: dict[str, object], attempt: dict[str, object], _row: object) -> tuple[dict[str, object] | None, str | None]:
        if attempt["status"] == 0:
            return {"member_ordinal": member["ordinal"]}, None
        return None, f"synthetic APP exit status {attempt['status']}"

    original_process_row = FIXED._process_row

    def process_row(ctx: dict[str, object], member: dict[str, object], attempt: dict[str, object]) -> dict[str, str]:
        if member["ordinal"] == row_failure_ordinal:
            raise FIXED.FixedPairError("injected process-row construction fault")
        return original_process_row(ctx, member, attempt)

    snapshot = {"pinned_inputs": "unchanged synthetic receipt test"}
    with (
        patch.object(FIXED, "_read_overlay", return_value=(overlay, b"{}\n", overlay_sha256, context, overlay)),
        patch.object(FIXED, "_launch_root_is_unused"),
        patch.object(FIXED, "_snapshot_source_inputs", side_effect=[snapshot, snapshot]),
        patch.object(FIXED, "_run_construction_probe", side_effect=lambda _ctx, member, _sha: {
            "member_ordinal": member["ordinal"], "reader": {"validated": True},
        }),
        patch.object(FIXED, "_launch_member", side_effect=launch),
        patch.object(FIXED, "_process_row", side_effect=process_row),
        patch.object(FIXED, "_validate_attempt_row", side_effect=validate),
    ):
        receipt_pin = FIXED.run_fixed_pair_overlay(
            {"path": str(overlay_path), "sha256": overlay_sha256}, lambda _event: None, lambda _event: None,
        )
    raw, actual_sha, _info = FIXED.read_stable(Path(receipt_pin["path"]), "synthetic fixed-pair receipt", FIXED.MAX_RECEIPT_BYTES)
    if actual_sha != receipt_pin["sha256"]:
        raise AssertionError("fixed-pair receipt pin differs from its sealed bytes")
    return json.loads(raw.decode("utf-8")), launched, attempts


def _verify_fixture_probe_offline(root: Path, fixture: object, reader: types.ModuleType) -> None:
    source = fixture.source
    identity = fixture.identity
    probe_path = fixture.construction_probe_path
    probe_raw = probe_path.read_bytes()
    probe_sha = hashlib.sha256(probe_raw).hexdigest()
    reader_path = SCRIPT.with_name("application-feedback-readback.py")
    reader_sha = hashlib.sha256(reader_path.read_bytes()).hexdigest()
    overlay_sha = "7" * 64
    binary = {
        "path": str(root / "source" / "application-allocatbelt"),
        "sha256": source["artifacts"]["allocatbelt"]["sha256"],
    }
    descriptor = {"pair": "bounded", "executor": "bounded", "allocator": "allocatbelt"}
    probe_argv = [binary["path"], "--emit-feedback-policy-only", "--workload", identity["workload"], "--profile", identity["profile"]]
    replay_stdout_path = root / "replay-probe.stdout.json"
    stderr_path = root / "actual-probe.stderr.txt"
    replay_stderr_path = root / "replay-probe.stderr.txt"
    replay_stdout_path.write_bytes(probe_raw)
    stderr_path.write_bytes(b"")
    replay_stderr_path.write_bytes(b"")
    recipe_fields = {
        "schema", "mode", "identity", "policy", "app_capacity_artifact_sha256", "construction_probe",
        "host_binding", "external_pressure_proof", "final_runtime_binding", "minimum_production_seconds",
        "minimum_pressure_overlap_seconds",
    }
    recipe = {key: fixture.expectation[key] for key in recipe_fields}
    cleanup = {
        "group_signal_after_leader_reap_count": 0, "signals": [], "leader_reaped": True,
        "remaining_session_members": [], "cleanup_status": "verified", "cleanup_errors": [],
    }
    storage = {"path": str(root / "probe-tmp"), "mount": {"fixture": "synthetic"}}
    member = {
        "ordinal": 0, "descriptor": descriptor, "binary": binary,
        "outputs": {"probe_tmpdir": str(root / "probe-tmp")},
    }
    receipt = {
        "schema": FIXED.PROBE_SCHEMA, "role": "uncalibrated_construction_only",
        "overlay_sha256": overlay_sha, "member_ordinal": 0, "descriptor": descriptor,
        "binary": binary, "argv": probe_argv, "pid": identity["process_id"], "start_ticks": 9001,
        "stdout": {"path": str(probe_path), "sha256": probe_sha, "bytes": len(probe_raw)},
        "stderr": {"path": str(stderr_path), "sha256": hashlib.sha256(b"").hexdigest(), "bytes": 0},
        "replay": {
            "pid": identity["process_id"] + 1, "start_ticks": 9002,
            "stdout": {"path": str(replay_stdout_path), "sha256": probe_sha, "bytes": len(probe_raw)},
            "stderr": {"path": str(replay_stderr_path), "sha256": hashlib.sha256(b"").hexdigest(), "bytes": 0},
            "byte_equal": True, "cleanup": cleanup,
        },
        "cleanup": cleanup, "reader_expectation": recipe,
        "reader": {"validated": True, "probe_sha256": probe_sha, "sha256": reader_sha},
        "tmpdir_initial": storage, "tmpdir_final": storage,
    }
    context = {
        "loaded_modules": {"feedback_reader": reader},
        "modules": {"feedback_reader": {"sha256": reader_sha}}, "source": source,
    }
    overlay = {"job": {"value": {"workload": identity["workload"], "profile": identity["profile"]}}}
    with patch.object(FIXED, "_verify_tmpdir_storage"):
        FIXED._verify_construction_probe(context, overlay, member, receipt, overlay_sha)


class FixedPairPureContractTests(unittest.TestCase):
    def test_overlay_top_level_schema_is_closed(self) -> None:
        expected = {
            "schema", "campaign_id", "host_id", "spec", "plan", "sources", "execution_source",
            "modules", "job", "runtime_bindings", "members", "deadlines", "artifact_budgets", "output_root",
        }
        self.assertEqual(FIXED.OVERLAY_SCHEMA, "allocatbelt.application-fixed-pair-execution-overlay.v1")
        self.assertEqual(len(expected), 14)

    def test_pair_descriptor_order_retains_original_parity(self) -> None:
        controller = types.SimpleNamespace(process_descriptors=lambda _job: [
            {"pair": "bounded", "executor": "bounded", "allocator": "allocatbelt"},
            {"pair": "tokio", "executor": "tokio", "allocator": "allocatbelt"},
        ])
        even = {"phase": "confirmation", "comparison_kind": "executor", "ordinal": 2}
        odd = {"phase": "confirmation", "comparison_kind": "executor", "ordinal": 1}
        self.assertEqual([item["pair"] for item in FIXED._member_descriptors(even, controller)], ["bounded", "tokio"])
        self.assertEqual([item["pair"] for item in FIXED._member_descriptors(odd, controller)], ["tokio", "bounded"])

    def test_allocator_match_order_retains_original_parity(self) -> None:
        controller = types.SimpleNamespace(process_descriptors=lambda _job: [
            {"pair": "candidate", "executor": "bounded", "allocator": "allocatbelt"},
            {"pair": "baseline", "executor": "bounded", "allocator": "mimalloc-secure"},
        ])
        even = {"phase": "confirmation", "comparison_kind": "allocator", "ordinal": 2}
        odd = {"phase": "confirmation", "comparison_kind": "allocator", "ordinal": 1}
        self.assertEqual([item["pair"] for item in FIXED._member_descriptors(even, controller)], ["baseline", "candidate"])
        self.assertEqual([item["pair"] for item in FIXED._member_descriptors(odd, controller)], ["candidate", "baseline"])

    def test_aa_order_is_not_parity_reversed(self) -> None:
        controller = types.SimpleNamespace(process_descriptors=lambda _job: [
            {"pair": "tokio-a", "executor": "tokio", "allocator": "allocatbelt"},
            {"pair": "tokio-b", "executor": "tokio", "allocator": "allocatbelt"},
        ])
        odd = {"phase": "aa", "comparison_kind": "executor", "ordinal": 1}
        self.assertEqual([item["pair"] for item in FIXED._member_descriptors(odd, controller)], ["tokio-a", "tokio-b"])

    def test_normal_argv_preserves_original_open_loop_inputs(self) -> None:
        job = {
            "mode": "open_loop", "workload": "mixed", "profile": "burst",
            "rate_per_second": 731, "arrivals": 450_000,
        }
        descriptor = {"executor": "tokio", "allocator": "allocatbelt", "pair": "tokio"}
        deadlines = {"trace_seconds": 70, "drain_seconds": 9, "shutdown_seconds": 12, "process_seconds": 95}
        argv = FIXED._member_argv(job, descriptor, Path("/frozen/app"), deadlines)
        self.assertEqual(argv[-4:], ["--rate", "731", "--arrivals", "450000"])
        self.assertEqual(argv[argv.index("--executor") + 1], "tokio")
        self.assertEqual(argv[argv.index("--process-deadline-seconds") + 1], "95")

    def test_capacity_argv_does_not_replace_original_sentinel_or_horizon(self) -> None:
        job = {"mode": "capacity", "workload": "cpu", "profile": "steady"}
        descriptor = {"executor": "bounded", "allocator": "system", "pair": "candidate"}
        deadlines = {"trace_seconds": 30, "drain_seconds": 6, "shutdown_seconds": 10, "process_seconds": 80}
        argv = FIXED._member_argv(job, descriptor, Path("/frozen/system-app"), deadlines)
        self.assertNotIn("--rate", argv)
        self.assertNotIn("--arrivals", argv)
        self.assertEqual(argv[argv.index("--trace-deadline-seconds") + 1], "30")

    def test_environment_is_explicit_and_contains_complete_fixed_identity(self) -> None:
        job = {"run_id": "run-1", "workload": "http", "profile": "steady"}
        descriptor = {"pair": "bounded", "executor": "bounded", "allocator": "mimalloc-standard"}
        binding = {
            "report_nonce": "a" * 32,
            "resource_ceiling_sha256": "b" * 64,
            "policy_sha256": "c" * 64,
        }
        source = {"source": {"source_tree_sha256": "d" * 64}, "artifacts": {"mimalloc-standard": {"sha256": "e" * 64}}}
        outputs = {
            "shutdown": "/out/member.shutdown.tsv", "ids": "/out/member.ids.tsv",
            "capacity_families": "/out/member.capacity-families.tsv", "runtime_readback": "/out/member.runtime.tsv",
        }
        environment = FIXED._derive_expected_environment(
            job, descriptor, binding, source, Path("/out/tmp/member"), outputs, None, None,
        )
        self.assertEqual(environment["ALLOCATBELT_APP_EXECUTOR"], "allocatbelt")
        self.assertEqual(environment["ALLOCATBELT_APP_ORACLE_FILE"], "")
        self.assertEqual(environment["TMPDIR"], "/out/tmp/member")
        self.assertNotIn("LD_PRELOAD", environment)
        self.assertNotIn("BASH_ENV", environment)
        self.assertEqual(environment["ALLOCATBELT_APP_BINARY_SHA256"], "e" * 64)

    def test_cleanup_proof_requires_unreaped_group_signals(self) -> None:
        good = {
            "group_signal_after_leader_reap_count": 0,
            "signals": [{"group_signal": {"leader_unreaped": True}}],
            "leader_reaped": True,
            "remaining_session_members": [],
            "cleanup_status": "verified",
            "cleanup_errors": [],
        }
        FIXED._verify_cleanup_record(good, "fixture", require_success=True)
        bad = dict(good)
        bad["signals"] = [{"group_signal": {"leader_unreaped": False}}]
        with self.assertRaises(FIXED.FixedPairError):
            FIXED._verify_cleanup_record(bad, "fixture", require_success=False)

    def test_failed_cleanup_can_be_reported_without_claiming_success(self) -> None:
        failed = {
            "group_signal_after_leader_reap_count": 0,
            "cleanup_status": "failed",
            "leader_reaped": False,
            "cleanup_errors": ["ownership scan unavailable"],
        }
        FIXED._verify_cleanup_record(failed, "fixture", require_success=False)
        with self.assertRaises(FIXED.FixedPairError):
            FIXED._verify_cleanup_record(failed, "fixture", require_success=True)

    def test_actual_controller_outer_bindings_feed_rows_and_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            context, bindings = _real_binding_case(Path(temporary), write_expectations=True)
            self.assertEqual(len(bindings), 2)
            rows = []
            for member, binding in zip(context["members"], bindings, strict=True):
                # This is the captured controller's real return shape: the
                # immutable recipe stays nested while its digest and other
                # execution bindings remain on the outer object.
                self.assertEqual(set(binding["recipe"]), {"schema", "identity", "run", "fixed_global_control_baseline"})
                self.assertNotIn("recipe_sha256", binding["recipe"])
                self.assertNotIn("identity", binding)
                self.assertEqual(member["runtime_recipe"]["value"], binding["recipe"])
                self.assertEqual(member["runtime_recipe"]["sha256"], binding["recipe_sha256"])
                self.assertEqual(member["runtime_binding"], binding)
                self.assertEqual(member["runtime_expectation"]["value"]["recipe"], binding["recipe"])
                self.assertEqual(member["runtime_expectation"]["sha256"], binding["expectation_sha256"])
                self.assertEqual(binding["recipe"]["identity"]["report_nonce"], binding["report_nonce"])
                self.assertEqual(binding["recipe"]["identity"]["source_sha256"], context["source"]["source"]["source_tree_sha256"])
                self.assertEqual(binding["recipe"]["identity"]["binary_sha256"], member["binary"]["sha256"])
                self.assertEqual(binding["recipe"]["identity"]["resource_ceiling_sha256"], binding["resource_ceiling_sha256"])
                self.assertEqual(binding["recipe"]["identity"]["policy_sha256"], binding["policy_sha256"])
                self.assertEqual(
                    hashlib.sha256(context["loaded_modules"]["runtime_reader"].canonical_bytes(member["runtime_expectation"]["value"])).hexdigest(),
                    binding["expectation_sha256"],
                )
                row = FIXED._process_row(context, member, {"status": 0})
                self.assertEqual(row["runtime_recipe_sha256"], binding["recipe_sha256"])
                self.assertEqual(row["runtime_expectation_sha256"], binding["expectation_sha256"])
                self.assertEqual(row["resource_ceiling_sha256"], binding["resource_ceiling_sha256"])
                self.assertEqual(row["policy_sha256"], binding["policy_sha256"])
                self.assertEqual(row["fixed_global_control_baseline"], str(binding["fixed_global_control_baseline"]))
                rows.append(row)

            FIXED._write_pair_metadata(context, [{"status": 0}, {"status": 0}])
            metadata_header, metadata_rows, _metadata_raw, _metadata_sha = FIXED._read_tsv(
                context["output_root"] / "metadata.tsv", "fixed-pair test metadata", FIXED.MAX_RUNTIME_BYTES,
            )
            self.assertEqual(metadata_header, ["key", "value"])
            metadata = {row["key"]: row["value"] for row in metadata_rows}
            for member, binding in zip(context["members"], bindings, strict=True):
                suffix = f"{member['descriptor']['pair']}_{member['descriptor']['executor']}"
                self.assertEqual(metadata[f"report_nonce_{suffix}"], binding["report_nonce"])
                self.assertEqual(metadata[f"policy_sha256_{suffix}"], binding["policy_sha256"])
                self.assertEqual(metadata[f"resource_ceiling_sha256_{suffix}"], binding["resource_ceiling_sha256"])
                self.assertEqual(metadata[f"fixed_global_control_baseline_{suffix}"], str(binding["fixed_global_control_baseline"]))
            self.assertEqual(len(rows), 2)

    def test_uncalibrated_v4_projection_accepts_all_original_probe_contexts(self) -> None:
        matrix = [
            (workload, profile)
            for workload in ("cpu", "memory", "disk", "http")
            for profile in ("steady", "burst", "oversubscribed")
        ] + [("mixed", profile) for profile in ("mixed", "burst", "oversubscribed")]
        expected_sources = {
            "cpu": {"disk": False, "download": False},
            "memory": {"disk": False, "download": False},
            "disk": {"disk": True, "download": False},
            "http": {"disk": False, "download": True},
            "mixed": {"disk": True, "download": True},
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reader_path = SCRIPT.with_name("application-feedback-readback.py")
            reader = _load_source_module("fixed_pair_selected_feedback_reader", reader_path)
            for index, (workload, profile) in enumerate(matrix):
                with self.subTest(workload=workload, profile=profile):
                    fixture = FEEDBACK_FIXTURES.Fixture(root / f"fixture-{index}", workload, profile=profile)
                    fixture.install_v4_source_v5()
                    probe = json.loads(fixture.construction_probe_path.read_bytes())
                    policy = FIXED._probe_feedback_policy(reader, fixture.source, probe, fixture.identity)
                    self.assertEqual(policy, fixture.policy)
                    self.assertEqual(policy["capacity_sources"], {"disk": False, "download": False})
                    self.assertEqual(probe["rust_control_context"]["required_byte_sources"], expected_sources[workload])
                    observed_sha = reader.validate_construction_probe(fixture.expectation, fixture.source)
                    self.assertEqual(observed_sha, fixture.construction_probe_pin["raw_sha256"])
                    _verify_fixture_probe_offline(root / f"fixture-{index}", fixture, reader)

    def test_selected_reader_rejects_sensor_and_source_projection_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reader = _load_source_module(
                "fixed_pair_selected_feedback_reader_mutation", SCRIPT.with_name("application-feedback-readback.py"),
            )
            fixture = FEEDBACK_FIXTURES.Fixture(root / "valid", "disk", profile="steady")
            fixture.install_v4_source_v5()

            probe = json.loads(fixture.construction_probe_path.read_bytes())
            probe["rust_control_context"]["required_byte_sources"]["disk"] = False
            mutated_probe_path = root / "probe-with-missing-disk-sensor.json"
            mutated_probe_raw = reader.canonical_bytes(probe)
            mutated_probe_path.write_bytes(mutated_probe_raw)
            mutated_recipe = copy.deepcopy(fixture.expectation)
            mutated_recipe["construction_probe"]["path"] = str(mutated_probe_path)
            mutated_recipe["construction_probe"]["raw_sha256"] = hashlib.sha256(mutated_probe_raw).hexdigest()
            with self.assertRaises(reader.ValidationError):
                reader.validate_construction_probe(mutated_recipe, fixture.source)

            mutated_source = copy.deepcopy(fixture.source)
            mutated_source["fixed_runtime_policy"]["policy"]["workloads"]["disk"]["scope_limits"]["network_operation_limit"] += 1
            with self.assertRaises(reader.ValidationError):
                reader.validate_construction_probe(fixture.expectation, mutated_source)

    def test_success_and_member_failures_seal_each_attempt_once(self) -> None:
        cases = (
            ("success", [0, 0], "valid_pair", None),
            ("first-member-failure", [17, 0], "failed_or_invalid", None),
            ("second-member-failure", [0, 19], "failed_or_invalid", None),
            ("row-construction-fault", [0, 0], "failed_or_invalid", 0),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, statuses, expected_status, row_failure_ordinal in cases:
                with self.subTest(case=name):
                    receipt, launched, attempts = _run_synthetic_receipt_case(
                        root / name, statuses, row_failure_ordinal=row_failure_ordinal,
                    )
                    self.assertEqual(receipt["status"], expected_status)
                    self.assertIs(receipt["qualification_eligible"], False)
                    self.assertIs(receipt["execution_ready"], False)
                    self.assertIs(receipt["campaign_chronology_complete"], False)
                    self.assertEqual(launched, [0, 1])
                    self.assertEqual([item["ordinal"] for item in attempts], [0, 1])
                    self.assertEqual([item["status"] for item in attempts], statuses)
                    self.assertEqual(len(receipt["member_attempts"]), 2)
                    self.assertEqual(len(receipt["process_rows"]), 2)
                    for attempted in receipt["member_attempts"]:
                        self.assertTrue(attempted["attempted"])
                        self.assertEqual(attempted["terminal_event"]["schema"], FIXED.APP_TERMINAL_SCHEMA)
                        self.assertEqual(attempted["terminal_event"]["pid"], attempted["start"]["pid"])
                        self.assertEqual(attempted["terminal_event"]["status"], attempted["status"])
                    if name == "row-construction-fault":
                        self.assertIn("injected process-row construction fault", " ".join(receipt["errors"]))
                        self.assertEqual(receipt["process_rows"][0]["row_validation"], "invalid")
                        self.assertIsNone(receipt["process_metrics"][0])
                        self.assertIn("process row construction failed", receipt["process_validation_errors"][0])

    def test_tmpdir_monitor_caps_bytes_and_inode_count(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertFalse(FIXED._tmpdir_exceeded(root, 16, 1))
            (root / "scratch").write_bytes(b"0123456789abcdefg")
            self.assertTrue(FIXED._tmpdir_exceeded(root, 16, 2))
            self.assertTrue(FIXED._tmpdir_exceeded(root, 100, 0))

    def test_tmpdir_monitor_survives_actual_directory_churn(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            started = threading.Event()
            finished = threading.Event()
            stop = threading.Event()
            worker_errors: list[Exception] = []

            def churn() -> None:
                try:
                    for index in range(8192):
                        if stop.is_set():
                            break
                        child = root / f"ephemeral-{index}"
                        child.mkdir(mode=0o700)
                        (child / "payload").write_bytes(b"live")
                        if index == 0:
                            started.set()
                        (child / "payload").unlink()
                        child.rmdir()
                except Exception as error:
                    worker_errors.append(error)
                finally:
                    finished.set()

            worker = threading.Thread(target=churn)
            worker.start()
            concurrent_scans = 0
            try:
                self.assertTrue(started.wait(timeout=5))
                scans = 0
                while not finished.is_set() and scans < 1024:
                    if not finished.is_set():
                        concurrent_scans += 1
                    self.assertFalse(FIXED._tmpdir_exceeded(root, 4096, 8))
                    scans += 1
            finally:
                stop.set()
                worker.join(timeout=10)
            self.assertGreater(concurrent_scans, 0)
            self.assertFalse(worker.is_alive())
            self.assertEqual(worker_errors, [])

    def test_tmpdir_monitor_tolerates_only_descendant_enoent_windows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vanished_dir = root / "vanished-dir"
            vanished_dir.mkdir()
            original_stat = FIXED.os.stat
            stat_removed = [False]

            def remove_before_stat(path: object, *args: object, **kwargs: object) -> os.stat_result:
                if path == "vanished-dir" and kwargs.get("dir_fd") is not None and not stat_removed[0]:
                    os.rmdir(path, dir_fd=kwargs["dir_fd"])
                    stat_removed[0] = True
                return original_stat(path, *args, **kwargs)

            with patch.object(FIXED.os, "stat", side_effect=remove_before_stat):
                self.assertFalse(FIXED._tmpdir_exceeded(root, 64, 4))
            self.assertTrue(stat_removed[0])

        for kind in ("directory", "file"):
            with self.subTest(disappearing_entry=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                entry = root / "vanished"
                if kind == "directory":
                    entry.mkdir()
                else:
                    entry.write_bytes(b"brief")
                original_open = FIXED.os.open
                open_removed = [False]

                def remove_before_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
                    if path == "vanished" and kwargs.get("dir_fd") is not None and not open_removed[0]:
                        if kind == "directory":
                            os.rmdir(path, dir_fd=kwargs["dir_fd"])
                        else:
                            os.unlink(path, dir_fd=kwargs["dir_fd"])
                        open_removed[0] = True
                    return original_open(path, flags, *args, **kwargs)

                with patch.object(FIXED.os, "open", side_effect=remove_before_open):
                    self.assertFalse(FIXED._tmpdir_exceeded(root, 64, 4))
                self.assertTrue(open_removed[0])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "unlink-after-open").write_bytes(b"small")
            original_open = FIXED.os.open
            unlinked = [False]

            def unlink_after_successful_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
                descriptor = original_open(path, flags, *args, **kwargs)
                if (path == "unlink-after-open" and kwargs.get("dir_fd") is not None and
                        not unlinked[0]):
                    self.assertTrue(flags & getattr(os, "O_PATH", 0))
                    os.unlink(path, dir_fd=kwargs["dir_fd"])
                    unlinked[0] = True
                return descriptor

            with patch.object(FIXED.os, "open", side_effect=unlink_after_successful_open):
                self.assertFalse(FIXED._tmpdir_exceeded(root, 64, 4))
            self.assertTrue(unlinked[0])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "unlink-after-open").write_bytes(b"small")
            original_open = FIXED.os.open
            unlinked = [False]

            def unlink_for_strict_snapshot(path: object, flags: int, *args: object, **kwargs: object) -> int:
                descriptor = original_open(path, flags, *args, **kwargs)
                if (path == "unlink-after-open" and kwargs.get("dir_fd") is not None and
                        not unlinked[0]):
                    os.unlink(path, dir_fd=kwargs["dir_fd"])
                    unlinked[0] = True
                return descriptor

            with patch.object(FIXED.os, "open", side_effect=unlink_for_strict_snapshot):
                with self.assertRaises(FIXED.FixedPairError):
                    FIXED._tmpdir_usage_snapshot(
                        root, 64, 4, None, allow_descendant_enoent=False,
                    )
            self.assertTrue(unlinked[0])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "oversized").write_bytes(b"known size")
            original_open = FIXED.os.open
            removed = [False]

            def remove_oversized_before_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
                if path == "oversized" and kwargs.get("dir_fd") is not None and not removed[0]:
                    os.unlink(path, dir_fd=kwargs["dir_fd"])
                    removed[0] = True
                return original_open(path, flags, *args, **kwargs)

            with patch.object(FIXED.os, "open", side_effect=remove_oversized_before_open):
                self.assertTrue(FIXED._tmpdir_exceeded(root, 4, 4))
            self.assertTrue(removed[0])

        def run_named_after_unlink(file_size: int, byte_limit: int, *, strict: bool) -> bool | None:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "named-after").write_bytes(b"x" * file_size)
                original_open = FIXED.os.open
                original_stat = FIXED.os.stat
                original_fstat = FIXED.os.fstat
                file_descriptor: list[int] = []
                name_stat_count = [0]
                unlinked = [False]

                def capture_file_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
                    descriptor = original_open(path, flags, *args, **kwargs)
                    if path == "named-after" and kwargs.get("dir_fd") is not None:
                        file_descriptor.append(descriptor)
                    return descriptor

                def unlink_during_named_stat(path: object, *args: object, **kwargs: object) -> os.stat_result:
                    result = original_stat(path, *args, **kwargs)
                    if path == "named-after" and kwargs.get("dir_fd") is not None:
                        name_stat_count[0] += 1
                        if name_stat_count[0] == 2:
                            self.assertTrue(file_descriptor)
                            os.unlink(path, dir_fd=kwargs["dir_fd"])
                            held = original_fstat(file_descriptor[0])
                            self.assertEqual(held.st_nlink, 0)
                            self.assertEqual(
                                (result.st_dev, result.st_ino, result.st_uid, stat.S_IFMT(result.st_mode)),
                                (held.st_dev, held.st_ino, held.st_uid, stat.S_IFMT(held.st_mode)),
                            )
                            unlinked[0] = True
                            return held
                    return result

                with (
                    patch.object(FIXED.os, "open", side_effect=capture_file_open),
                    patch.object(FIXED.os, "stat", side_effect=unlink_during_named_stat),
                ):
                    if strict:
                        with self.assertRaises(FIXED.FixedPairError):
                            FIXED._tmpdir_usage_snapshot(
                                root, byte_limit, 8, None,
                                allow_descendant_enoent=False,
                            )
                        exceeded = None
                    else:
                        exceeded = FIXED._tmpdir_exceeded(root, byte_limit, 8)
                self.assertEqual(name_stat_count[0], 2)
                self.assertTrue(unlinked[0])
                return exceeded

        self.assertFalse(run_named_after_unlink(5, 64, strict=False))
        self.assertTrue(run_named_after_unlink(65, 64, strict=False))
        self.assertIsNone(run_named_after_unlink(5, 64, strict=True))

    def test_tmpdir_monitor_rejects_root_loss_replacement_and_symlink(self) -> None:
        for replacement in ("missing", "directory", "symlink"):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as temporary:
                parent = Path(temporary)
                root = parent / "root"
                moved = parent / "moved"
                root.mkdir(mode=0o700)
                info = root.lstat()
                expected_identity = (info.st_dev, info.st_ino)
                original_scandir = FIXED.os.scandir
                changed = [False]

                def change_root_then_scan(path: object) -> object:
                    if isinstance(path, int) and not changed[0]:
                        os.rename(root, moved)
                        if replacement == "directory":
                            root.mkdir(mode=0o700)
                        elif replacement == "symlink":
                            root.symlink_to(moved, target_is_directory=True)
                        changed[0] = True
                    return original_scandir(path)

                with patch.object(FIXED.os, "scandir", side_effect=change_root_then_scan):
                    self.assertTrue(FIXED._tmpdir_exceeded(
                        root, 64, 4, expected_root_identity=expected_identity,
                    ))
                self.assertTrue(changed[0])

    def test_tmpdir_monitor_rejects_root_mode_change_during_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original_scandir = FIXED.os.scandir
            changed = [False]

            def change_root_mode_then_scan(path: object) -> object:
                if isinstance(path, int) and not changed[0]:
                    os.chmod(root, 0o711)
                    changed[0] = True
                return original_scandir(path)

            with patch.object(FIXED.os, "scandir", side_effect=change_root_mode_then_scan):
                self.assertTrue(FIXED._tmpdir_exceeded(root, 64, 4))
            self.assertTrue(changed[0])

    def test_tmpdir_monitor_rejects_descendant_rename_and_symlink_substitution(self) -> None:
        for replacement in ("directory", "symlink"):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                root = base / "root"
                root.mkdir(mode=0o700)
                (root / "child").mkdir(mode=0o700)
                outside = base / "outside"
                outside.mkdir(mode=0o700)
                original_open = FIXED.os.open
                substituted = [False]

                def substitute_then_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
                    if path == "child" and kwargs.get("dir_fd") is not None and not substituted[0]:
                        os.rmdir(path, dir_fd=kwargs["dir_fd"])
                        if replacement == "directory":
                            os.mkdir(path, 0o700, dir_fd=kwargs["dir_fd"])
                        else:
                            os.symlink(outside, path, dir_fd=kwargs["dir_fd"])
                        substituted[0] = True
                    return original_open(path, flags, *args, **kwargs)

                with patch.object(FIXED.os, "open", side_effect=substitute_then_open):
                    self.assertTrue(FIXED._tmpdir_exceeded(root, 64, 8))
                self.assertTrue(substituted[0])

    def test_tmpdir_monitor_revalidates_names_after_open(self) -> None:
        for replacement in ("missing", "directory", "symlink"):
            with self.subTest(directory_replacement=replacement), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                root = base / "root"
                root.mkdir(mode=0o700)
                (root / "child").mkdir(mode=0o700)
                outside = base / "outside"
                outside.mkdir(mode=0o700)
                original_open = FIXED.os.open
                original_fstat = FIXED.os.fstat
                child_descriptor: list[int] = []
                parent_descriptor: list[int] = []
                child_fstat_count = [0]
                replaced = [False]

                def capture_child_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
                    descriptor = original_open(path, flags, *args, **kwargs)
                    if path == "child" and kwargs.get("dir_fd") is not None:
                        child_descriptor.append(descriptor)
                        parent_descriptor.append(kwargs["dir_fd"])
                    return descriptor

                def replace_child_after_traversal(descriptor: int) -> os.stat_result:
                    info = original_fstat(descriptor)
                    if child_descriptor and descriptor == child_descriptor[0]:
                        child_fstat_count[0] += 1
                        if child_fstat_count[0] == 2:
                            os.rename(
                                "child", "moved", src_dir_fd=parent_descriptor[0],
                                dst_dir_fd=parent_descriptor[0],
                            )
                            if replacement == "directory":
                                os.mkdir("child", 0o700, dir_fd=parent_descriptor[0])
                            elif replacement == "symlink":
                                os.symlink(outside, "child", dir_fd=parent_descriptor[0])
                            replaced[0] = True
                    return info

                with (
                    patch.object(FIXED.os, "open", side_effect=capture_child_open),
                    patch.object(FIXED.os, "fstat", side_effect=replace_child_after_traversal),
                ):
                    exceeded = FIXED._tmpdir_exceeded(root, 64, 8)
                self.assertTrue(replaced[0])
                self.assertEqual(exceeded, replacement != "missing")

        for replacement in ("missing", "regular", "symlink"):
            with self.subTest(file_replacement=replacement), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                root = base / "root"
                root.mkdir(mode=0o700)
                (root / "entry").write_bytes(b"original")
                outside = base / "outside"
                outside.mkdir(mode=0o700)
                original_open = FIXED.os.open
                parent_descriptor: list[int] = []
                replaced = [False]

                def replace_file_after_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
                    descriptor = original_open(path, flags, *args, **kwargs)
                    if (path == "entry" and kwargs.get("dir_fd") is not None and
                            not replaced[0]):
                        parent_descriptor.append(kwargs["dir_fd"])
                        os.unlink("entry", dir_fd=parent_descriptor[0])
                        if replacement == "regular":
                            replacement_fd = original_open(
                                "entry", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                                0o600, dir_fd=parent_descriptor[0],
                            )
                            try:
                                os.write(replacement_fd, b"new")
                            finally:
                                os.close(replacement_fd)
                        elif replacement == "symlink":
                            os.symlink(outside, "entry", dir_fd=parent_descriptor[0])
                        replaced[0] = True
                    return descriptor

                with patch.object(FIXED.os, "open", side_effect=replace_file_after_open):
                    exceeded = FIXED._tmpdir_exceeded(root, 64, 8)
                self.assertTrue(replaced[0])
                self.assertEqual(exceeded, replacement != "missing")

    def test_tmpdir_monitor_rejects_unsafe_entries_and_other_io_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "root"
            root.mkdir(mode=0o700)
            outside = base / "outside"
            outside.mkdir(mode=0o700)
            (root / "link").symlink_to(outside, target_is_directory=True)
            self.assertTrue(FIXED._tmpdir_exceeded(root, 64, 8))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.mkfifo(root / "pipe")
            self.assertTrue(FIXED._tmpdir_exceeded(root, 64, 8))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "file"
            source.write_bytes(b"one inode")
            os.link(source, root / "hard-link")
            self.assertTrue(FIXED._tmpdir_exceeded(root, 64, 8))

        for failure in (PermissionError(errno.EACCES, "denied"), OSError(errno.EIO, "I/O error")):
            with self.subTest(error=failure.errno), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "member").write_bytes(b"present")
                original_stat = FIXED.os.stat

                def fail_member_stat(path: object, *args: object, **kwargs: object) -> os.stat_result:
                    if path == "member" and kwargs.get("dir_fd") is not None:
                        raise failure
                    return original_stat(path, *args, **kwargs)

                with patch.object(FIXED.os, "stat", side_effect=fail_member_stat):
                    self.assertTrue(FIXED._tmpdir_exceeded(root, 64, 8))

    def test_tmpdir_monitor_enforces_directory_depth_and_inode_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            current = root
            for index in range(FIXED.TMPDIR_MONITOR_MAX_DEPTH + 1):
                current = current / f"depth-{index}"
                current.mkdir(mode=0o700)
            self.assertTrue(FIXED._tmpdir_exceeded(root, 4096, 128))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "first").write_bytes(b"1")
            (root / "second").write_bytes(b"2")
            self.assertTrue(FIXED._tmpdir_exceeded(root, 4096, 1))

    def test_executor_source_has_no_waitpid_poll_or_post_reap_killpg_path(self) -> None:
        tree = ast.parse(SCRIPT.read_text())
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        names = []
        for call in calls:
            if isinstance(call.func, ast.Attribute):
                names.append(call.func.attr)
            elif isinstance(call.func, ast.Name):
                names.append(call.func.id)
        self.assertIn("waitid", names)
        self.assertNotIn("poll", names)
        self.assertNotIn("waitpid", names)
        source = SCRIPT.read_text()
        self.assertEqual(source.count("os.killpg("), 1)

    def test_canonical_receipt_bytes_are_stable(self) -> None:
        value = {"schema": FIXED.RECEIPT_SCHEMA, "qualified": False, "b": 2, "a": 1}
        self.assertEqual(FIXED.canonical_bytes(value), b'{"a":1,"b":2,"qualified":false,"schema":"allocatbelt.application-fixed-pair-execution-receipt.v1"}\n')

    def test_real_cli_parser_passes_launch_and_verify_pins(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            overlay_path = root / "overlay.json"
            receipt_path = root / "receipt.json"
            overlay_path.write_bytes(b"cli overlay fixture\n")
            receipt_path.write_bytes(b"cli receipt fixture\n")
            overlay_sha = "1" * 64
            receipt_sha = "2" * 64
            launch_overlay = {"output_root": str(root)}
            captured: dict[str, object] = {}

            def read_overlay(pin: dict[str, object]) -> tuple[dict[str, object], bytes, str, dict[str, object], dict[str, object]]:
                captured.setdefault("read_pins", []).append(dict(pin))
                return launch_overlay, b"{}\n", overlay_sha, {}, launch_overlay

            def run_pair(pin: dict[str, object], _started: object, _terminal: object) -> dict[str, str]:
                captured["launch_pin"] = dict(pin)
                return {"path": str(receipt_path.resolve()), "sha256": receipt_sha}

            def verify_pair(overlay_pin: dict[str, object], receipt_pin: dict[str, object]) -> dict[str, str]:
                captured["verify_pins"] = (dict(overlay_pin), dict(receipt_pin))
                return {"status": "valid_pair"}

            with (
                patch.object(FIXED, "_read_overlay", side_effect=read_overlay),
                patch.object(FIXED, "_cli_event_callbacks", return_value=(lambda _event: None, lambda _event: None, lambda: None)),
                patch.object(FIXED, "run_fixed_pair_overlay", side_effect=run_pair),
                patch.object(FIXED, "verify_fixed_pair_overlay", side_effect=verify_pair),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                launch_status = FIXED.main(["launch", "--overlay", str(overlay_path), "--sha256", overlay_sha])
            self.assertEqual(launch_status, 0)
            self.assertEqual(captured["launch_pin"], {"path": str(overlay_path.resolve()), "sha256": overlay_sha})
            self.assertEqual(captured["verify_pins"], (
                {"path": str(overlay_path.resolve()), "sha256": overlay_sha},
                {"path": str(receipt_path.resolve()), "sha256": receipt_sha},
            ))

            captured.clear()
            with (
                patch.object(FIXED, "verify_fixed_pair_overlay", side_effect=verify_pair),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                verify_status = FIXED.main([
                    "verify", "--overlay", str(overlay_path), "--overlay-sha256", overlay_sha,
                    "--receipt", str(receipt_path), "--receipt-sha256", receipt_sha,
                ])
            self.assertEqual(verify_status, 0)
            self.assertEqual(captured["verify_pins"], (
                {"path": str(overlay_path.resolve()), "sha256": overlay_sha},
                {"path": str(receipt_path.resolve()), "sha256": receipt_sha},
            ))

    def test_real_verify_cli_refuses_malformed_overlay_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            overlay_path = root / "overlay.json"
            receipt_path = root / "receipt.json"
            overlay_path.write_bytes(b"not an overlay\n")
            receipt_path.write_bytes(b"not a receipt\n")
            overlay_path.chmod(0o600)
            receipt_path.chmod(0o600)
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as refused:
                FIXED.main([
                    "verify", "--overlay", str(overlay_path), "--overlay-sha256", "bad-digest",
                    "--receipt", str(receipt_path), "--receipt-sha256", "2" * 64,
                ])
            self.assertEqual(refused.exception.code, 1)
            self.assertIn("application-fixed-pair refused:", stderr.getvalue())
            self.assertNotIn("AttributeError", stderr.getvalue())

    def test_captured_helper_ignores_replaced_source_and_conflicting_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fixed-pair-captured-module-") as temporary:
            root = Path(temporary)
            path = root / "pinned-helper.py"
            path.write_text("VALUE = 'disk-before-capture'\n", encoding="utf-8")
            raw = b"VALUE = 'verified-buffer'\n"
            cache = root / "__pycache__"
            cache.mkdir(mode=0o700)
            (cache / "pinned-helper.cpython-311.pyc").write_bytes(b"conflicting cached code")
            path.write_text("VALUE = 'replacement-after-capture'\n", encoding="utf-8")
            module = FIXED._load_pinned_module(raw, path, "replacement_negative")
            self.assertEqual(module.VALUE, "verified-buffer")
            self.assertEqual(module.__file__, str(path))
            self.assertIs(sys.modules[module.__name__], module)

    def test_offline_peer_api_checks_identity_receipts_without_live_host_reads(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fixed-pair-peer-replay-") as temporary:
            root = Path(temporary)
            source_root = root / "source"
            input_root = root / "input"
            artifact_root = root / "artifacts"
            output_root = root / "pair-output"
            for path in (source_root, input_root, artifact_root, output_root):
                path.mkdir(mode=0o700)
            spec_path, plan_path = input_root / "spec.json", input_root / "plan.json"
            observed_path = input_root / "observed.json"
            controls = {"cpu_set": "0", "kernel_release": "Linux-fixture", "cpu_model": "x86-64-v3 fixture"}
            host_record = {
                "host_id": "host-a", "venue": "bare_metal",
                "host_fingerprint_sha256": FIXED.sha256_bytes(FIXED.canonical_bytes(controls)),
                "controls": controls,
            }
            spec_value = {"hosts": [host_record]}
            spec_raw = FIXED.canonical_bytes(spec_value)
            spec_path.write_bytes(spec_raw)
            plan_path.write_bytes(b"{}\n")
            observed_raw = FIXED.canonical_bytes(host_record)
            observed_path.write_bytes(observed_raw)
            overlay_value = {
                "schema": FIXED.OVERLAY_SCHEMA,
                "campaign_id": "campaign-test", "host_id": "host-a",
                "spec": {"pin": {"path": str(spec_path), "sha256": FIXED.sha256_bytes(spec_raw)},
                         "semantic_sha256": FIXED.sha256_bytes(FIXED.canonical_bytes(spec_value))},
                "plan": {"pin": {"path": str(plan_path), "sha256": "3" * 64}, "semantic_sha256": "4" * 64},
                "sources": {
                    "manifests": {},
                    "selected": {"host_id": "host-a", "root": str(source_root), "git_commit": "a" * 40,
                                 "source_tree_sha256": "5" * 64, "build_sha256": "6" * 64},
                    "campaign_artifacts_root": str(artifact_root),
                    "observed_host": {
                        "pin": {"path": str(observed_path), "sha256": FIXED.sha256_bytes(observed_raw)},
                        "host_fingerprint_sha256": host_record["host_fingerprint_sha256"],
                        "controls_sha256": host_record["host_fingerprint_sha256"],
                        "process_affinity": [0], "network_namespace_inode": 77,
                    },
                    "historical_runner_sha256": "9" * 64,
                    "output_mount": {},
                },
                "execution_source": {}, "modules": {},
                "job": {"value": {"run_id": "original-run"}, "sha256": "a" * 64},
                "runtime_bindings": {}, "members": [], "deadlines": {}, "artifact_budgets": {},
                "output_root": str(output_root),
            }
            overlay_path = output_root / "fixed-pair-execution-overlay.json"
            overlay_raw = FIXED.canonical_bytes(overlay_value)
            overlay_path.write_bytes(overlay_raw)
            overlay_path.chmod(0o600)
            overlay_pin = {"path": str(overlay_path), "sha256": FIXED.sha256_bytes(overlay_raw)}
            execution_receipt_body = {
                "schema": FIXED.RECEIPT_SCHEMA,
                "overlay_sha256": overlay_pin["sha256"],
                "campaign_id": "campaign-test", "host_id": "host-a", "run_id": "original-run",
                "component_status": FIXED.EXECUTION_STATUS,
                "qualification_eligible": False, "execution_ready": False,
                "campaign_chronology_complete": False, "status": "valid_pair",
                "historical_runner_sha256": "9" * 64,
                "execution_modules": {}, "execution_source": {},
                "source_pins_before": {}, "source_pins_after": {}, "inputs_unchanged": True,
                "construction_probes": [], "member_attempts": [],
                "process_header": FIXED.PAIR_PROCESS_HEADER_FALLBACK,
                "processes_sha256": None, "metadata_sha256": None,
                "process_rows": [], "process_metrics": [], "process_validation_errors": [],
                "output_artifacts": [], "errors": [],
            }
            execution_receipt_value = {
                **execution_receipt_body,
                "receipt_sha256": FIXED.sha256_bytes(FIXED.canonical_bytes(execution_receipt_body)),
            }
            execution_receipt_path = output_root / "fixed-pair-execution-receipt.json"
            execution_receipt_raw = FIXED.canonical_bytes(execution_receipt_value)
            execution_receipt_path.write_bytes(execution_receipt_raw)
            execution_receipt_path.chmod(0o600)
            receipt_pin = {"path": str(execution_receipt_path), "sha256": FIXED.sha256_bytes(execution_receipt_raw)}
            output_mount = {
                "mount_id": 1, "major_minor": "8:1", "mount_root": "/",
                "mount_point": str(root), "filesystem_type": "ext4", "mount_source": "/dev/vda1",
                "device": 2049, "available_bytes": FIXED.MAX_PAIR_OUTPUT_BYTES + 2 * FIXED.MAX_TMPDIR_BYTES,
                "available_inodes": 100_000,
            }
            host_fields = {
                "schema": FIXED.HOST_VERIFICATION_IDENTITY_SCHEMA,
                "host_id": "host-a", "observed_host_raw_sha256": overlay_value["sources"]["observed_host"]["pin"]["sha256"],
                "process_affinity": [0], "network_namespace_inode": 77, "output_mount": output_mount,
            }
            host_identity = {**host_fields, "host_verification_sha256": FIXED.sha256_bytes(FIXED.canonical_bytes(host_fields))}
            host_body = {
                "schema": FIXED.HOST_VERIFICATION_SCHEMA, "strict_verified": True,
                "qualification_eligible": False, "execution_ready": False,
                "campaign_chronology_complete": False, "overlay_raw_sha256": overlay_pin["sha256"],
                "execution_receipt_raw_sha256": receipt_pin["sha256"],
                "execution_receipt_sha256": execution_receipt_value["receipt_sha256"],
                "status": "valid_pair", "run_id": "original-run", "host_verification": host_identity,
            }
            host_value = {**host_body, "receipt_sha256": FIXED.sha256_bytes(FIXED.canonical_bytes(host_body))}
            host_path = input_root / "host-verification.json"
            host_raw = FIXED.canonical_bytes(host_value)
            host_path.write_bytes(host_raw)
            host_path.chmod(0o600)
            host_pin = {"path": str(host_path), "raw_sha256": FIXED.sha256_bytes(host_raw),
                        "host_verification_sha256": host_value["receipt_sha256"]}
            path_rows = [
                {"origin": str(path), "local": str(path)}
                for path in (source_root, input_root, artifact_root, output_root)
            ]
            evidence_map = {"schema": FIXED.EVIDENCE_PATH_MAP_SCHEMA, "entries": sorted(path_rows, key=lambda row: row["origin"])}
            expected_replay = {
                "schema": FIXED.RECEIPT_SCHEMA, "verified": True, "status": "valid_pair",
                "qualification_eligible": False, "receipt_sha256": receipt_pin["sha256"],
                "overlay_sha256": overlay_pin["sha256"], "run_id": "original-run",
            }
            # This fixture exercises public peer-receipt/path-map binding. The
            # full lower-level replay remains a native evidence requirement.
            with (
                patch.object(FIXED, "_verify_fixed_pair_overlay_replay", return_value=expected_replay),
                patch.object(FIXED, "_live_network_namespace_inode", side_effect=AssertionError("offline replay sampled local netns")),
                patch.object(FIXED.os, "sched_getaffinity", side_effect=AssertionError("offline replay sampled local affinity")),
                patch.object(FIXED, "_mount_identity", side_effect=AssertionError("offline replay sampled local mountinfo")),
            ):
                result = FIXED.verify_fixed_pair_overlay_offline(overlay_pin, receipt_pin, host_pin, evidence_map)
            self.assertEqual(result["host_verification_sha256"], host_value["receipt_sha256"])
            self.assertEqual(result["status"], "valid_pair")

            translated = copy.deepcopy(evidence_map)
            translated["entries"][0]["local"] = str(input_root)
            with self.assertRaisesRegex(FIXED.FixedPairError, "identity paths"):
                FIXED.verify_fixed_pair_overlay_offline(overlay_pin, receipt_pin, host_pin, translated)

            wrong_identity = copy.deepcopy(host_value)
            wrong_identity["host_verification"]["schema"] = FIXED.HOST_VERIFICATION_SCHEMA
            identity_body = {key: value for key, value in wrong_identity["host_verification"].items()
                             if key != "host_verification_sha256"}
            wrong_identity["host_verification"]["host_verification_sha256"] = FIXED.sha256_bytes(
                FIXED.canonical_bytes(identity_body),
            )
            wrong_outer_body = {key: value for key, value in wrong_identity.items() if key != "receipt_sha256"}
            wrong_identity["receipt_sha256"] = FIXED.sha256_bytes(FIXED.canonical_bytes(wrong_outer_body))
            wrong_identity_raw = FIXED.canonical_bytes(wrong_identity)
            host_path.write_bytes(wrong_identity_raw)
            host_pin = {
                "path": str(host_path), "raw_sha256": FIXED.sha256_bytes(wrong_identity_raw),
                "host_verification_sha256": wrong_identity["receipt_sha256"],
            }
            with patch.object(FIXED, "_verify_fixed_pair_overlay_replay", return_value=expected_replay):
                with self.assertRaisesRegex(FIXED.FixedPairError, "strict fixed-pair host identity receipt differs"):
                    FIXED.verify_fixed_pair_overlay_offline(overlay_pin, receipt_pin, host_pin, evidence_map)

    def test_offline_peer_public_api_replays_failed_pair_through_real_host_loader(self) -> None:
        fixture_path = SCRIPT.with_name("test-application-campaign-inputs.py")
        fixture_spec = importlib.util.spec_from_file_location("fixed_pair_source5_replay_fixtures", fixture_path)
        assert fixture_spec is not None and fixture_spec.loader is not None
        fixture_module = importlib.util.module_from_spec(fixture_spec)
        sys.modules[fixture_spec.name] = fixture_module
        fixture_spec.loader.exec_module(fixture_module)
        campaign = fixture_module.campaign

        target_root = SCRIPT.parent.parent / "target"
        target_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="fixed-pair-real-offline-replay-", dir=target_root) as temporary:
            root = Path(temporary)
            source_root, input_root = root / "source", root / "input"
            artifact_root, evidence_root = root / "artifacts", root / "evidence"
            source_root.mkdir(mode=0o700)
            input_root.mkdir(mode=0o700)
            artifact_root.mkdir(mode=0o700)
            evidence_root.mkdir(mode=0o700)
            (source_root / "scripts").mkdir(mode=0o700)
            controller_path = source_root / "scripts" / "application-campaign.py"
            controller_path.write_bytes((SCRIPT.parent / "application-campaign.py").read_bytes())
            controller_path.chmod(0o644)

            spec, sources = fixture_module.spec_v3_fixture()
            allowed_cpus = sorted(os.sched_getaffinity(0))
            selected_host = spec["hosts"][0]["host_id"]
            host_record = next(item for item in spec["hosts"] if item["host_id"] == selected_host)
            host_record["controls"]["cpu_set"] = ",".join(str(cpu) for cpu in allowed_cpus)
            host_record["host_fingerprint_sha256"] = FIXED.sha256_bytes(
                FIXED.canonical_bytes(host_record["controls"]),
            )
            source_manifest_pins = {}
            for host_id, source in sources.items():
                source_path = input_root / "source" / f"{host_id}.json"
                source_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                source_raw = FIXED.canonical_bytes(source)
                source_path.write_bytes(source_raw)
                source_manifest_pins[host_id] = {
                    "path": str(source_path), "sha256": FIXED.sha256_bytes(source_raw),
                }
            spec_path = input_root / "spec-v3.json"
            spec_raw = FIXED.canonical_bytes(spec)
            spec_path.write_bytes(spec_raw)
            spec_sha = FIXED.sha256_bytes(spec_raw)
            jobs = campaign.build_jobs(spec, "exploration")
            exact_job = next(item for item in jobs if item["host_id"] == selected_host)
            plan_body = {
                "schema": campaign.PLAN_SCHEMA_V3,
                "campaign_id": spec["campaign_id"], "spec_sha256": campaign.digest_object(spec),
                "source_manifests": {host: value["manifest_sha256"] for host, value in sources.items()},
                "jobs": {"exploration": jobs},
            }
            plan = {**plan_body, "plan_sha256": campaign.digest_object(plan_body, "plan_sha256")}
            plan_path = input_root / "plan-v3.json"
            plan_raw = FIXED.canonical_bytes(plan)
            plan_path.write_bytes(plan_raw)
            plan_sha = FIXED.sha256_bytes(plan_raw)
            observed_host_path = input_root / "hosts" / f"{selected_host}.json"
            observed_host_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            observed_host_raw = FIXED.canonical_bytes(host_record)
            observed_host_path.write_bytes(observed_host_raw)

            selected_source = sources[selected_host]
            source_files = selected_source["source"]["files"]
            source_by_path = {item["path"]: item for item in source_files}
            module_pins = {
                name: {"path": relative, "sha256": source_by_path[relative]["sha256"]}
                for name, relative in FIXED.MODULE_PATHS.items()
            }
            execution_records = sorted(
                (source_by_path[path] for path in FIXED.MODULE_PATHS.values()),
                key=lambda item: item["path"].encode("utf-8"),
            )
            inventory_module = _load_source_module(
                "fixed_pair_offline_source_inventory",
                SCRIPT.with_name("application-source-inventory.py"),
            )

            controller = types.SimpleNamespace(
                PAIR_PROCESS_HEADER=FIXED.PAIR_PROCESS_HEADER_FALLBACK,
                SOURCE_SCHEMA_V5="allocatbelt.application-source-manifest.v5",
                verify_source_manifest=lambda *_args, **_kwargs: None,
                validate_spec=lambda *_args, **_kwargs: {"campaign_id": spec["campaign_id"]},
                campaign_inputs_source_sha256=lambda _sources: "c" * 64,
                verify_plan=lambda *_args, **_kwargs: None,
            )
            launch_helper = types.SimpleNamespace(_parse_cpu_set=lambda _value: allowed_cpus)
            loaded_modules = {
                "campaign_controller": controller,
                "inventory_verifier": inventory_module,
                "runtime_reader": types.SimpleNamespace(),
                "feedback_reader": types.SimpleNamespace(),
                "campaign_inputs": types.SimpleNamespace(),
                "launch_identity_helper": launch_helper,
            }

            def load_controller(_raw, _path, label):
                if label == "campaign_controller":
                    return controller
                return FIXED._load_pinned_module(_raw, _path, label)

            def captured_module_pins(_source, _source_root, _execution):
                return module_pins, execution_records, inventory_module, loaded_modules

            def runtime_bindings(context):
                bindings = [
                    {"pair": "bounded", "executor": "bounded", "allocator": exact_job["allocator"]},
                    {"pair": "tokio", "executor": "tokio", "allocator": exact_job["allocator"]},
                ]
                manifest_body = {"schema": "offline-fixture-runtime-bindings.v1", "run_id": exact_job["run_id"]}
                manifest = {**manifest_body,
                            "manifest_sha256": FIXED.sha256_bytes(FIXED.canonical_bytes(manifest_body))}
                raw = FIXED.canonical_bytes(manifest)
                digest = FIXED.sha256_bytes(raw)
                runtime_path = context["output_root"] / ".fixed-pair-runtime-bindings.json"
                if context.get("write_runtime_bindings") is True:
                    FIXED.write_exclusive(runtime_path, raw, "offline fixture runtime bindings")
                else:
                    stored, stored_sha, _info = FIXED.read_stable(runtime_path, "offline fixture runtime bindings", FIXED.MAX_RUNTIME_BYTES)
                    FIXED.require(stored == raw and stored_sha == digest, "fixture runtime binding bytes changed")
                return bindings, manifest, raw, digest

            def members(context, _bindings):
                root_path = context["output_root"]
                return [
                    {"ordinal": index, "tmpdir": {"path": str(root_path / f"member-{index}-tmp")},
                     "outputs": {"root": str(root_path), "tmpdir": str(root_path / f"member-{index}-tmp"),
                                 "probe_tmpdir": str(root_path / f"probe-{index}-tmp")}}
                    for index in range(2)
                ]

            original_pins = {
                "spec": {"path": str(spec_path), "sha256": spec_sha},
                "spec_semantic_sha256": campaign.digest_object(spec),
                "plan": {"path": str(plan_path), "sha256": plan_sha},
                "plan_semantic_sha256": plan["plan_sha256"],
                "source_manifests": source_manifest_pins,
                "campaign_artifacts_root": str(artifact_root),
            }
            execution_pins = {
                "source_root": str(source_root), "selected_host_id": selected_host,
                "modules": module_pins,
            }
            pair_output = root / "pair-output"
            observed_pin = {"path": str(observed_host_path), "sha256": FIXED.sha256_bytes(observed_host_raw)}
            with (
                patch.object(FIXED, "_load_pinned_module", side_effect=load_controller),
                patch.object(FIXED, "_module_pins", side_effect=captured_module_pins),
                patch.object(FIXED, "_runtime_bindings_for_job", side_effect=runtime_bindings),
                patch.object(FIXED, "_construct_members", side_effect=members),
                patch.object(FIXED, "_snapshot_source_inputs", return_value={"fixture_source_snapshot": True}),
            ):
                overlay_pin = FIXED.build_fixed_pair_overlay(
                    original_pins, execution_pins, exact_job, observed_pin, pair_output,
                )
                overlay, _overlay_raw, overlay_sha, _context, _reconstructed = FIXED._read_overlay(
                    overlay_pin,
                )
                output_tree = FIXED._hash_output_tree(overlay)
                failed_receipt_body = FIXED._receipt_body(
                    overlay, overlay_sha, "failed_or_invalid", ["fixture contains no dispatched APP"],
                    None, None, [], [], [], [], [], None, None, output_tree,
                )
                execution_receipt_pin = FIXED._write_receipt(pair_output, failed_receipt_body)
                verification_parent = root / "verification"
                verification_parent.mkdir(mode=0o700)
                host_verification_result = FIXED.verify_fixed_pair_overlay_with_host_receipt(
                    overlay_pin, execution_receipt_pin,
                    verification_parent / "host-verification.json",
                )
                self.assertEqual(host_verification_result["status"], "failed_or_invalid")
                self.assertEqual(set(host_verification_result), {
                    "path", "raw_sha256", "host_verification_sha256", "status", "overlay_sha256",
                })
                host_verification_pin = {
                    key: host_verification_result[key]
                    for key in ("path", "raw_sha256", "host_verification_sha256")
                }
                self.assertEqual(set(host_verification_pin), {
                    "path", "raw_sha256", "host_verification_sha256",
                })

            evidence_map_rows = [
                {"origin": str(path), "local": str(path)}
                for path in (source_root, input_root, artifact_root, pair_output, Path(host_verification_pin["path"]))
            ]
            evidence_map = {
                "schema": FIXED.EVIDENCE_PATH_MAP_SCHEMA,
                "entries": sorted(evidence_map_rows, key=lambda item: item["origin"]),
            }
            with (
                patch.object(FIXED, "_load_pinned_module", side_effect=load_controller),
                patch.object(FIXED, "_module_pins", side_effect=captured_module_pins),
                patch.object(FIXED, "_runtime_bindings_for_job", side_effect=runtime_bindings),
                patch.object(FIXED, "_construct_members", side_effect=members),
                patch.object(FIXED, "_snapshot_source_inputs", return_value={"fixture_source_snapshot": True}),
                patch.object(FIXED, "_live_network_namespace_inode", side_effect=AssertionError("offline replay sampled local netns")),
                patch.object(FIXED.os, "sched_getaffinity", side_effect=AssertionError("offline replay sampled local affinity")),
                patch.object(FIXED, "_mount_identity", side_effect=AssertionError("offline replay sampled local mountinfo")),
            ):
                result = FIXED.verify_fixed_pair_overlay_offline(
                    overlay_pin, execution_receipt_pin, host_verification_pin, evidence_map,
                )
            self.assertTrue(result["verified"])
            self.assertEqual(result["status"], "failed_or_invalid")
            self.assertFalse(result["qualification_eligible"])


if __name__ == "__main__":
    unittest.main()
