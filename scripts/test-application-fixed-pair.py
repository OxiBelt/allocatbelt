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

ARCHIVE = _load_source_module(
    "fixed_pair_source5_archive_under_test",
    SCRIPT.with_name("application-source5-evidence-archive.py"),
)


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


def _verify_fixture_probe_offline(
    root: Path, fixture: object, reader: types.ModuleType, *, captured: bool = False,
) -> None:
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
    if captured:
        paths = [probe_path, replay_stdout_path, stderr_path, replay_stderr_path]
        stage, references = _stage_replay_test_files(root, paths)
        for path in paths:
            path.unlink()
        context["artifact_view"] = FIXED.CapturedFixedPairArtifactsV1(references, stage)
    overlay = {"job": {"value": {"workload": identity["workload"], "profile": identity["profile"]}}}
    with patch.object(FIXED, "_verify_tmpdir_storage"):
        FIXED._verify_construction_probe(context, overlay, member, receipt, overlay_sha)


class FixedPairPureContractTests(unittest.TestCase):
    def test_recorded_roots_allow_absent_origins_while_strict_offline_root_requires_presence(self) -> None:
        """Recorded path checks are lexical; the old offline root check stays physical."""
        with tempfile.TemporaryDirectory(prefix="fixed-recorded-roots-") as temporary:
            root = Path(temporary)
            source_root = root / "shared-source"
            source_root.mkdir()
            absent_parent = root / "retired-origin-host"
            output_root = absent_parent / "private-output"
            artifact_root = absent_parent / "campaign-artifacts"

            actual_output, actual_artifacts = FIXED._recorded_origin_roots(
                str(output_root), str(artifact_root), source_root,
            )
            self.assertEqual(actual_output, output_root)
            self.assertEqual(actual_artifacts, artifact_root)
            self.assertFalse(output_root.exists())
            self.assertFalse(artifact_root.exists())
            with self.assertRaises(FIXED.FixedPairError):
                FIXED._private_output_root_offline(str(output_root), source_root)

            with self.assertRaisesRegex(FIXED.FixedPairError, "outside the selected source tree"):
                FIXED._recorded_origin_roots(
                    str(source_root / "retired-output"), str(artifact_root), source_root,
                )
            with self.assertRaisesRegex(FIXED.FixedPairError, "normalized absolute origin"):
                FIXED._recorded_origin_roots(
                    str(root / ".." / "aliased-output"), str(artifact_root), source_root,
                )

    def test_recorded_archive_loader_binds_typed_two_kvm_and_legacy_cohorts(self) -> None:
        """Load only actual typed archive bytes for each exact SpecV3 cohort."""
        source_root = SCRIPT.parent.parent
        controller = _load_source_module(
            "fixed_pair_recorded_profile_controller",
            SCRIPT.with_name("application-campaign.py"),
        )
        relative = "scripts/application-source5-evidence-archive.py"
        archive_path = source_root / relative
        archive_raw, archive_sha, archive_info = FIXED.read_stable(
            archive_path, "recorded archive-loader fixture source", FIXED.MAX_SOURCE_BYTES,
        )
        archive_mode = f"{stat.S_IFMT(archive_info.st_mode) | stat.S_IMODE(archive_info.st_mode):06o}"
        archive_record = {
            "path": relative, "kind": "file", "mode": archive_mode,
            "sha256": archive_sha, "size": len(archive_raw),
        }

        def make_context(host_ids, *, profile=None, source_host_ids=None,
                         venues=None, record_mutator=None):
            selected_venues = venues or ["kvm_guest"] * len(host_ids)
            spec = {
                "schema": controller.SPEC_SCHEMA_V3,
                "hosts": [
                    {"host_id": host_id, "venue": venue,
                     "host_fingerprint_sha256": "a" * 64, "controls": {}}
                    for host_id, venue in zip(host_ids, selected_venues)
                ],
            }
            if profile is not None:
                spec["qualification_profile"] = profile
            source_ids = host_ids if source_host_ids is None else source_host_ids
            sources = {
                host_id: {"source": {"files": [dict(archive_record)]}}
                for host_id in source_ids
            }
            if record_mutator is not None:
                record_mutator(sources)
            return {"source_root": source_root, "sources": sources,
                    "spec": spec, "controller": controller}

        two_host_ids = ["agent-8845HS-dev", "agent-EPYC-4585PX-dev"]
        two_host_context = make_context(
            two_host_ids, profile=controller.TWO_KVM_QUALIFICATION_PROFILE,
        )
        with patch.object(FIXED, "_load_pinned_module",
                          wraps=FIXED._load_pinned_module) as load_module:
            archive = FIXED._load_recorded_checkpoint_archive(two_host_context)
        self.assertEqual(archive.CHECKPOINT_SCHEMA_V2,
                         "allocatbelt.application-source5-evidence-job-checkpoint.v2")
        load_module.assert_called_once()
        self.assertEqual(load_module.call_args.args[0], archive_raw)
        self.assertEqual(load_module.call_args.args[1], archive_path)

        legacy_ids = ["agent-bare-metal", "agent-kvm-a", "agent-kvm-b"]
        legacy_context = make_context(
            legacy_ids, venues=["bare_metal", "kvm_guest", "kvm_guest"],
        )
        self.assertEqual(
            FIXED._load_recorded_checkpoint_archive(legacy_context).CHECKPOINT_SCHEMA_V2,
            archive.CHECKPOINT_SCHEMA_V2,
        )

        rejected = [
            (make_context(two_host_ids), "SpecV3 host list differs"),
            (make_context(two_host_ids, profile="unknown"), "qualification profile"),
            (make_context(two_host_ids, profile=controller.TWO_KVM_QUALIFICATION_PROFILE,
                          source_host_ids=two_host_ids[:1]), "exact SpecV3 host cohort"),
            (make_context(two_host_ids, profile=controller.TWO_KVM_QUALIFICATION_PROFILE,
                          source_host_ids=two_host_ids + ["extra-host"]), "exact SpecV3 host cohort"),
            (make_context([two_host_ids[0], two_host_ids[0]],
                          profile=controller.TWO_KVM_QUALIFICATION_PROFILE), "identities are duplicated"),
            (make_context(two_host_ids, profile=controller.TWO_KVM_QUALIFICATION_PROFILE,
                          venues=["bare_metal", "kvm_guest"]), "exactly two KVM guests"),
        ]
        for context, message in rejected:
            with self.subTest(message=message), self.assertRaisesRegex(FIXED.FixedPairError, message):
                FIXED._load_recorded_checkpoint_archive(context)

        def mismatched_sha(sources):
            sources[two_host_ids[1]]["source"]["files"][0]["sha256"] = "0" * 64

        with self.assertRaisesRegex(FIXED.FixedPairError, "different transitive"):
            FIXED._load_recorded_checkpoint_archive(make_context(
                two_host_ids, profile=controller.TWO_KVM_QUALIFICATION_PROFILE,
                record_mutator=mismatched_sha,
            ))

        def duplicate_archive_entry(sources):
            sources[two_host_ids[1]]["source"]["files"].append(dict(archive_record))

        with self.assertRaisesRegex(FIXED.FixedPairError, "no unique"):
            FIXED._load_recorded_checkpoint_archive(make_context(
                two_host_ids, profile=controller.TWO_KVM_QUALIFICATION_PROFILE,
                record_mutator=duplicate_archive_entry,
            ))

        def wrong_all_hashes(sources):
            for source in sources.values():
                source["source"]["files"][0]["sha256"] = "0" * 64

        with self.assertRaisesRegex(FIXED.FixedPairError, "differs from its typed transitive pin"):
            FIXED._load_recorded_checkpoint_archive(make_context(
                two_host_ids, profile=controller.TWO_KVM_QUALIFICATION_PROFILE,
                record_mutator=wrong_all_hashes,
            ))

        def wrong_all_modes(sources):
            wrong_mode = "100755" if archive_mode == "100644" else "100644"
            for source in sources.values():
                source["source"]["files"][0]["mode"] = wrong_mode

        with self.assertRaisesRegex(FIXED.FixedPairError, "differs from its typed transitive pin"):
            FIXED._load_recorded_checkpoint_archive(make_context(
                two_host_ids, profile=controller.TWO_KVM_QUALIFICATION_PROFILE,
                record_mutator=wrong_all_modes,
            ))

    def test_recorded_zero_tmp_gate_uses_exact_proofs_and_never_opens_absent_origins(self) -> None:
        """Exercise storage projection only; this does not prove GPG authority or APP execution."""
        with tempfile.TemporaryDirectory(prefix="fixed-recorded-tmp-proof-") as temporary:
            root = Path(temporary)
            output_root = root / "private-output"
            output_root.mkdir(mode=0o700)
            output_root.chmod(0o700)
            root_mount = FIXED._mount_identity(output_root)
            if root_mount["filesystem_type"] in {"tmpfs", "ramfs", "devtmpfs"}:
                self.skipTest("recorded fixed proof requires the strict non-memory output mount contract")
            budgets = {"tmpdir_bytes": 1024, "tmpdir_inodes": 8}
            rows = []
            attempts = []
            probes = []
            for ordinal in range(2):
                app_path = output_root / f"member-{ordinal}-tmp"
                app_initial = FIXED._prepare_member_tmpdir(app_path, output_root, budgets)
                app_final = FIXED._tmpdir_usage(app_path, {
                    "bytes_limit": budgets["tmpdir_bytes"],
                    "inode_limit": budgets["tmpdir_inodes"],
                })
                attempts.append({"ordinal": ordinal, "tmpdir_final": app_final})
                rows.append((app_initial, app_final, app_path, None, ordinal))

                probe_path = output_root / f"probe-{ordinal}-tmp"
                probe_initial = FIXED._prepare_member_tmpdir(probe_path, output_root, budgets)
                probe_final = FIXED._tmpdir_usage(probe_path, {
                    "bytes_limit": budgets["tmpdir_bytes"],
                    "inode_limit": budgets["tmpdir_inodes"],
                })
                probes.append({"member_ordinal": ordinal, "tmpdir_final": probe_final})
                rows.append((probe_initial, probe_final, probe_path, "probe_tmpdir", ordinal))

            receipt_body = {
                "schema": FIXED.RECEIPT_SCHEMA, "status": "valid_pair",
                "member_attempts": attempts, "construction_probes": probes,
            }
            receipt_semantic_sha = FIXED.sha256_bytes(
                FIXED.canonical_bytes(receipt_body),
            )
            receipt = {**receipt_body, "receipt_sha256": receipt_semantic_sha}
            receipt_raw = FIXED.canonical_bytes(receipt)
            receipt_path = output_root / "fixed-pair-execution-receipt.json"
            receipt_path.write_bytes(receipt_raw)
            receipt_path.chmod(0o600)
            receipt_pin = {
                "path": str(receipt_path),
                "raw_sha256": FIXED.sha256_bytes(receipt_raw),
                "semantic_sha256": receipt_semantic_sha,
            }
            receipt_proofs = ARCHIVE._zero_fixed_tmp_proofs(
                receipt, receipt_pin, "component_receipt",
                include_probe_tmp_proofs=True,
            )
            key = lambda proof: (proof["role"], proof["member_ordinal"],
                                 proof.get("domain", ""))
            checkpoint_proofs = sorted(receipt_proofs, key=key)
            self.assertEqual(len(checkpoint_proofs), 4)
            FIXED._require_recorded_fixed_checkpoint_zero_proofs(
                checkpoint_proofs, checkpoint_proofs,
            )

            for _initial, _final, path, _domain, _ordinal in rows:
                path.rmdir()
            self.assertTrue(all(not path.exists() for _initial, _final, path, _domain, _ordinal in rows))
            for initial, final, path, domain, ordinal in rows:
                proof = FIXED._recorded_tmp_proof_for_member(
                    checkpoint_proofs, ordinal, domain, f"TMP member {ordinal}",
                )
                FIXED._verify_tmpdir_storage_recorded_offline(
                    initial, final, str(path), budgets["tmpdir_bytes"],
                    budgets["tmpdir_inodes"], root_mount,
                    f"TMP member {ordinal}", proof=proof,
                    expected_domain=domain, expected_ordinal=ordinal,
                )
                with self.assertRaises(FIXED.FixedPairError):
                    FIXED._verify_tmpdir_storage_offline(
                        initial, final, str(path), budgets["tmpdir_bytes"],
                        budgets["tmpdir_inodes"], root_mount,
                        f"strict TMP member {ordinal}",
                    )

            with self.assertRaisesRegex(FIXED.FixedPairError, "receipt-derived"):
                FIXED._require_recorded_fixed_checkpoint_zero_proofs(
                    checkpoint_proofs[:-1], checkpoint_proofs,
                )
            altered = [dict(proof) for proof in checkpoint_proofs]
            altered[0]["inode"] += 1
            with self.assertRaisesRegex(FIXED.FixedPairError, "receipt-derived"):
                FIXED._require_recorded_fixed_checkpoint_zero_proofs(
                    altered, checkpoint_proofs,
                )
            member_swapped = [dict(proof) for proof in checkpoint_proofs]
            member_swapped[0]["member_ordinal"] = 1
            member_swapped[1]["member_ordinal"] = 0
            with self.assertRaisesRegex(FIXED.FixedPairError, "receipt-derived"):
                FIXED._require_recorded_fixed_checkpoint_zero_proofs(
                    member_swapped, checkpoint_proofs,
                )
            wrong_domain = dict(checkpoint_proofs[0], domain="probe_tmpdir")
            with self.assertRaises(FIXED.FixedPairError):
                FIXED._verify_tmpdir_storage_recorded_offline(
                    rows[0][0], rows[0][1], str(rows[0][2]),
                    budgets["tmpdir_bytes"], budgets["tmpdir_inodes"],
                    root_mount, "wrong-domain TMP member", proof=wrong_domain,
                    expected_domain=None, expected_ordinal=0,
                )
            wrong_member = dict(checkpoint_proofs[0], member_ordinal=1)
            with self.assertRaisesRegex(FIXED.FixedPairError, "differ from its signed checkpoint"):
                FIXED._verify_tmpdir_storage_recorded_offline(
                    rows[0][0], rows[0][1], str(rows[0][2]),
                    budgets["tmpdir_bytes"], budgets["tmpdir_inodes"],
                    root_mount, "wrong-member TMP proof", proof=wrong_member,
                    expected_domain=None, expected_ordinal=0,
                )
            nonzero = dict(rows[0][1], bytes_used=1)
            with self.assertRaisesRegex(FIXED.FixedPairError, "not exactly zero"):
                FIXED._verify_tmpdir_storage_recorded_offline(
                    rows[0][0], nonzero, str(rows[0][2]),
                    budgets["tmpdir_bytes"], budgets["tmpdir_inodes"],
                    root_mount, "nonzero TMP member", proof=checkpoint_proofs[0],
                    expected_domain=None, expected_ordinal=0,
                )

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

    def test_tmpdir_monitor_does_not_count_vanished_names_as_usage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            names = [f"vanished-{index}" for index in range(12)]
            for name in names:
                (root / name).write_bytes(b"x")
            original_scandir = FIXED.os.scandir
            vanished: list[str] = []

            class DeleteAfterYield:
                def __init__(self, iterator: object, directory_fd: int) -> None:
                    self.iterator = iterator
                    self.directory_fd = directory_fd

                def __enter__(self) -> DeleteAfterYield:
                    return self

                def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
                    self.iterator.close()

                def __iter__(self) -> DeleteAfterYield:
                    return self

                def __next__(self) -> os.DirEntry[str]:
                    child = next(self.iterator)
                    if child.name in names:
                        os.unlink(child.name, dir_fd=self.directory_fd)
                        vanished.append(child.name)
                    return child

            def delete_after_scandir_yield(path: object) -> object:
                iterator = original_scandir(path)
                if isinstance(path, int):
                    return DeleteAfterYield(iterator, path)
                return iterator

            with patch.object(FIXED.os, "scandir", side_effect=delete_after_scandir_yield):
                self.assertFalse(FIXED._tmpdir_exceeded(root, 64, 8))
            self.assertCountEqual(vanished, names)
            self.assertEqual(list(root.iterdir()), [])

            for name in names[:9]:
                (root / name).write_bytes(b"x")
            self.assertTrue(FIXED._tmpdir_exceeded(root, 64, 8))

    def test_tmpdir_monitor_survives_sequential_unique_create_yield_delete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root_identity = (root.stat().st_dev, root.stat().st_ino)
            original_scandir = FIXED.os.scandir
            yielded = []
            removed = []

            class SequentialEntries:
                def __init__(self) -> None:
                    self.index = 0
                    self.current = None

                def __enter__(self):
                    return self

                def cleanup_current(self) -> None:
                    if self.current is not None:
                        (self.current / "payload").unlink()
                        self.current.rmdir()
                        removed.append(self.current.name)
                        self.current = None

                def __exit__(self, _type, _value, _traceback) -> None:
                    self.cleanup_current()

                def __iter__(self):
                    return self

                def __next__(self):
                    self.cleanup_current()
                    if self.index == 64:
                        raise StopIteration
                    self.current = root / f"unique-{self.index}"
                    self.current.mkdir(mode=0o700)
                    (self.current / "payload").write_bytes(b"live")
                    with original_scandir(root) as actual_entries:
                        entry = next(item for item in actual_entries
                                     if item.name == self.current.name)
                    yielded.append(entry.name)
                    self.index += 1
                    return entry

            def sequential_root_stream(path):
                if isinstance(path, int):
                    info = FIXED.os.fstat(path)
                    if (info.st_dev, info.st_ino) == root_identity:
                        return SequentialEntries()
                return original_scandir(path)

            with patch.object(FIXED.os, "scandir", side_effect=sequential_root_stream):
                self.assertFalse(FIXED._tmpdir_exceeded(root, 4096, 8))
            self.assertEqual(len(yielded), 64)
            self.assertEqual(removed, yielded)
            self.assertEqual(list(root.iterdir()), [])

    def _vanishing_file_scandir(self, consumed, closed):
        original_scandir = FIXED.os.scandir

        class VanishingFiles:
            def __init__(self, descriptor):
                self.descriptor = descriptor
                self.iterator = original_scandir(descriptor)

            def __enter__(self):
                return self

            def __exit__(self, _type, _value, _traceback):
                self.iterator.close()
                closed.append(self.descriptor)

            def __iter__(self):
                return self

            def __next__(self):
                child = next(self.iterator)
                consumed.append(child.name)
                if child.name.startswith("ghost-"):
                    os.unlink(child.name, dir_fd=self.descriptor)
                return child

        def wrapped(path):
            return VanishingFiles(path) if isinstance(path, int) else original_scandir(path)

        return wrapped

    def test_tmpdir_enumeration_work_exhaustion_fails_closed_after_vanishing_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index in range(4):
                (root / f"ghost-{index}").write_bytes(b"x")
            consumed, closed = [], []
            with patch.object(FIXED, "TMPDIR_MONITOR_MAX_ENUMERATED_ENTRIES", 3), \
                    patch.object(FIXED.os, "scandir", side_effect=self._vanishing_file_scandir(consumed, closed)):
                with self.assertRaisesRegex(FIXED.FixedPairError, "enumeration-work bound"):
                    FIXED._tmpdir_usage_snapshot(root, 64, 1, None, allow_descendant_enoent=True)
            self.assertEqual(len(consumed), 4)
            self.assertEqual(len(closed), 1)
            self.assertEqual(list(root.iterdir()), [])

    def test_tmpdir_enumeration_work_counter_spans_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("first", "second"):
                child = root / name
                child.mkdir(mode=0o700)
                (child / f"ghost-{name}").write_bytes(b"x")
            consumed, closed = [], []
            with patch.object(FIXED, "TMPDIR_MONITOR_MAX_ENUMERATED_ENTRIES", 3), \
                    patch.object(FIXED.os, "scandir", side_effect=self._vanishing_file_scandir(consumed, closed)):
                with self.assertRaisesRegex(FIXED.FixedPairError, "enumeration-work bound"):
                    FIXED._tmpdir_usage_snapshot(root, 64, 2, None, allow_descendant_enoent=True)
            self.assertEqual(len(consumed), 4)
            self.assertEqual(len(closed), 3)
            self.assertEqual(set(consumed), {"first", "second", "ghost-first", "ghost-second"})

    def test_tmpdir_enumeration_preserves_larger_existing_output_inode_allowance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index in range(4):
                (root / f"retained-{index}").write_bytes(b"x")
            with patch.object(FIXED, "TMPDIR_MONITOR_MAX_ENUMERATED_ENTRIES", 3):
                usage = FIXED._tmpdir_usage_snapshot(root, 64, 4, None, allow_descendant_enoent=True)
            self.assertEqual(usage, {"bytes_used": 4, "inode_count": 4})

    def test_tmpdir_live_stat_racing_unlink_keeps_real_observed_bytes(self) -> None:
        for live, byte_limit in ((True, 4), (True, 3), (False, 4)):
            with self.subTest(live=live, byte_limit=byte_limit), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "entry").write_bytes(b"live")
                original_stat = FIXED.os.stat
                original_open = FIXED.os.open
                observed = []

                def unlink_during_lookup(path, *args, **kwargs):
                    if path == "entry" and kwargs.get("dir_fd") is not None and not observed:
                        descriptor = original_open(path, os.O_RDONLY | os.O_NOFOLLOW,
                                                   dir_fd=kwargs["dir_fd"])
                        try:
                            os.unlink(path, dir_fd=kwargs["dir_fd"])
                            actual = os.fstat(descriptor)
                            self.assertEqual(actual.st_nlink, 0)
                            self.assertEqual(actual.st_size, 4)
                            observed.append(actual)
                            return actual
                        finally:
                            os.close(descriptor)
                    return original_stat(path, *args, **kwargs)

                with patch.object(FIXED.os, "stat", side_effect=unlink_during_lookup):
                    if live and byte_limit == 4:
                        usage = FIXED._tmpdir_usage_snapshot(root, 4, 1, None,
                                                             allow_descendant_enoent=True)
                        self.assertEqual(usage, {"bytes_used": 4, "inode_count": 1})
                    elif live:
                        with self.assertRaisesRegex(FIXED.FixedPairError, "byte bound"):
                            FIXED._tmpdir_usage_snapshot(root, byte_limit, 1, None,
                                                         allow_descendant_enoent=True)
                    else:
                        with self.assertRaisesRegex(FIXED.FixedPairError, "hard link or invalid regular file"):
                            FIXED._tmpdir_usage_snapshot(root, 4, 1, None,
                                                         allow_descendant_enoent=False)
                self.assertEqual(len(observed), 1)
                self.assertEqual(list(root.iterdir()), [])

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
                child = root / "child"
                child.mkdir(mode=0o700)
                original_child = child.lstat()
                original_child_identity = (original_child.st_dev, original_child.st_ino)
                moved = base / "moved-child"
                outside = base / "outside"
                outside.mkdir(mode=0o700)
                original_open = FIXED.os.open
                substituted = [False]

                def substitute_then_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
                    if path == "child" and kwargs.get("dir_fd") is not None and not substituted[0]:
                        os.rename(path, moved, src_dir_fd=kwargs["dir_fd"])
                        retained = moved.lstat()
                        self.assertEqual(
                            (retained.st_dev, retained.st_ino), original_child_identity,
                        )
                        if replacement == "directory":
                            os.mkdir(path, 0o700, dir_fd=kwargs["dir_fd"])
                        else:
                            os.symlink(outside, path, dir_fd=kwargs["dir_fd"])
                        replacement_info = os.stat(
                            path, dir_fd=kwargs["dir_fd"], follow_symlinks=False,
                        )
                        self.assertNotEqual(
                            (replacement_info.st_dev, replacement_info.st_ino),
                            original_child_identity,
                        )
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
            archive_source = SCRIPT.with_name("application-source5-evidence-archive.py")
            archive_path = source_root / "scripts" / archive_source.name
            archive_path.write_bytes(archive_source.read_bytes())
            archive_path.chmod(stat.S_IMODE(archive_source.stat(follow_symlinks=False).st_mode))

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

            # This failed-pair integration fixture keeps these exact boundaries
            # synthetic: the campaign validator, inventory/module pins,
            # runtime bindings, member construction, and source snapshot are
            # mocked. It uses real captured envelopes and a real strict-host
            # receipt, dispatches no APP, and has no SourceA/GPG checkpoint.
            controller = types.SimpleNamespace(
                PAIR_PROCESS_HEADER=FIXED.PAIR_PROCESS_HEADER_FALLBACK,
                SOURCE_SCHEMA_V5="allocatbelt.application-source-manifest.v5",
                qualification_host_count=campaign.qualification_host_count,
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

            original_pinned_module_loader = FIXED._load_pinned_module

            def load_controller(_raw, _path, label):
                if label == "campaign_controller":
                    return controller
                return original_pinned_module_loader(_raw, _path, label)

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
                    if context.get("artifact_view") is None:
                        stored, stored_sha, _info = FIXED.read_stable(runtime_path, "offline fixture runtime bindings", FIXED.MAX_RUNTIME_BYTES)
                    else:
                        stored, stored_sha = context["artifact_view"].read(runtime_path, "offline fixture runtime bindings", FIXED.MAX_RUNTIME_BYTES)
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

            # Keep the genuine strict-host receipt emitted above, and move only
            # this failed pair's raw outputs into the readback boundary shape.
            # Source reconstruction is still the explicit synthetic fixture;
            # no APP was dispatched and this is not a numeric success witness.
            stage_root = root / "capture-stage"
            stage_root.mkdir(mode=0o700)
            references = {}
            origins = [pair_output / name for name in output_tree["files"]]
            origins += [Path(execution_receipt_pin["path"]),
                        Path(host_verification_pin["path"])]
            for index, origin in enumerate(origins):
                raw = origin.read_bytes()
                local = stage_root / f"{index:06d}"
                local.write_bytes(raw)
                local.chmod(0o400)
                references[str(origin)] = {
                    "origin_path": str(origin), "path": str(local),
                    "role": "fixed_pair_receipt", "host_id": selected_host,
                    "raw_sha256": FIXED.sha256_bytes(raw), "semantic_sha256": None,
                    "byte_count": len(raw), "maximum_bytes": FIXED.MAX_PAIR_OUTPUT_BYTES,
                }
            for origin in origins:
                origin.unlink()
            unrelated_origin = str(root / "other-job-probe-v2" / "tmp" / "payload")
            unrelated_capture = stage_root / "unrelated-probe-v2"
            unrelated_capture.write_bytes(b"unrelated authenticated whole-job object")
            unrelated_capture.chmod(0o400)
            unrelated_raw = unrelated_capture.read_bytes()
            references[unrelated_origin] = {
                "origin_path": unrelated_origin, "path": str(unrelated_capture),
                "role": "opaque_trace", "host_id": selected_host,
                "raw_sha256": FIXED.sha256_bytes(unrelated_raw), "semantic_sha256": None,
                "byte_count": len(unrelated_raw), "maximum_bytes": FIXED.MAX_TMPDIR_BYTES,
            }
            with (
                patch.object(FIXED, "_live_network_namespace_inode", side_effect=AssertionError("captured replay sampled local netns")),
                patch.object(FIXED.os, "sched_getaffinity", side_effect=AssertionError("captured replay sampled local affinity")),
                patch.object(FIXED, "_mount_identity", side_effect=AssertionError("captured replay sampled local mountinfo")),
            ):
                prepared = FIXED.prepare_captured_fixed_pair_replay_v1(
                    overlay_pin, execution_receipt_pin, host_verification_pin,
                    references, stage_root,
                )
                self.assertTrue(prepared["envelope_verified"])
                self.assertFalse(prepared["full_replay_verified"])
                self.assertFalse(prepared["qualification_eligible"])
                self.assertEqual(prepared["host_verification_pin"], host_verification_pin)
                self.assertEqual(prepared["artifact_view"].output_tree(), output_tree)
            self.assertTrue(all(not path.exists() for path in origins))
            with (
                patch.object(FIXED, "_load_pinned_module", side_effect=load_controller),
                patch.object(FIXED, "_module_pins", side_effect=captured_module_pins),
                patch.object(FIXED, "_runtime_bindings_for_job", side_effect=runtime_bindings),
                patch.object(FIXED, "_construct_members", side_effect=members),
                patch.object(FIXED, "_snapshot_source_inputs", return_value={"fixture_source_snapshot": True}),
                patch.object(FIXED, "_live_network_namespace_inode", side_effect=AssertionError("captured replay sampled local netns")),
                patch.object(FIXED.os, "sched_getaffinity", side_effect=AssertionError("captured replay sampled local affinity")),
                patch.object(FIXED, "_mount_identity", side_effect=AssertionError("captured replay sampled local mountinfo")),
                patch.object(FIXED.subprocess, "Popen", side_effect=AssertionError("captured replay launched a process")),
            ):
                captured = FIXED.verify_fixed_pair_overlay_captured_v1(
                    overlay_pin, execution_receipt_pin, host_verification_pin,
                    references, stage_root,
                )
                malformed_checkpoint = FIXED.canonical_bytes({"schema": "unsupported"})
                malformed_checkpoint_pin = {
                    "path": str(root / "archived-checkpoint.json"),
                    "raw_sha256": FIXED.sha256_bytes(malformed_checkpoint),
                    "semantic_sha256": "f" * 64,
                }
                global_json_origins = [
                    (spec_path, spec_raw), (plan_path, plan_raw),
                    (observed_host_path, observed_host_raw),
                    *(
                        (Path(pin["path"]), Path(pin["path"]).read_bytes())
                        for pin in source_manifest_pins.values()
                    ),
                ]
                global_json_stage = stage_root / "historical-global-json"
                global_json_stage.mkdir(mode=0o700)
                global_json_captures = {}
                for index, (origin, raw) in enumerate(global_json_origins):
                    digest = FIXED.sha256_bytes(raw)
                    local = global_json_stage / f"{index:04d}.json"
                    local.write_bytes(raw)
                    local.chmod(0o400)
                    global_json_captures[(str(origin), digest)] = local
                    origin.unlink()
                self.assertTrue(all(not origin.exists() for origin, _raw in global_json_origins))
                global_json_reads = []

                def global_json_reader(pin, maximum):
                    self.assertEqual(set(pin), {"path", "raw_sha256"})
                    local = global_json_captures[(pin["path"], pin["raw_sha256"])]
                    local_info = local.lstat()
                    self.assertTrue(stat.S_ISREG(local_info.st_mode))
                    self.assertEqual(stat.S_IMODE(local_info.st_mode), 0o400)
                    raw, _sha, _info = FIXED.read_stable(
                        local, "captured historical JSON", maximum,
                    )
                    global_json_reads.append(pin["path"])
                    return raw

                with self.assertRaisesRegex(
                    FIXED.FixedPairError, "unavailable|cannot safely open",
                ):
                    FIXED.verify_fixed_pair_overlay_captured_v1(
                        overlay_pin, execution_receipt_pin,
                        host_verification_pin, references, stage_root,
                    )
                with (
                    patch.object(FIXED, "_load_pinned_module", side_effect=load_controller),
                    patch.object(FIXED, "_module_pins", side_effect=captured_module_pins),
                    patch.object(FIXED, "_runtime_bindings_for_job", side_effect=runtime_bindings),
                    patch.object(FIXED, "_construct_members", side_effect=members),
                    patch.object(FIXED, "_snapshot_source_inputs", return_value={"fixture_source_snapshot": True}),
                ):
                    with self.assertRaisesRegex(
                        FIXED.FixedPairError,
                        "SourceV5 archive rejected the recorded fixed checkpoint",
                    ):
                        FIXED.verify_fixed_pair_overlay_recorded_captured_v1(
                            overlay_pin, execution_receipt_pin,
                            host_verification_pin, references, stage_root,
                            checkpoint_pin=malformed_checkpoint_pin,
                            checkpoint_raw=malformed_checkpoint,
                            global_artifact_reader=global_json_reader,
                        )
                self.assertIn(str(spec_path), global_json_reads)
                self.assertIn(str(plan_path), global_json_reads)
                self.assertIn(str(observed_host_path), global_json_reads)
                self.assertTrue(all(not origin.exists() for origin, _raw in global_json_origins))
                for origin, raw in global_json_origins:
                    origin.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    origin.write_bytes(raw)

                with patch.object(
                    FIXED, "_verify_fixed_pair_overlay_replay",
                    side_effect=AssertionError("malformed checkpoint reached numeric replay"),
                ):
                    with self.assertRaisesRegex(
                        FIXED.FixedPairError,
                        "SourceV5 archive rejected the recorded fixed checkpoint",
                    ):
                        FIXED.verify_fixed_pair_overlay_recorded_captured_v1(
                            overlay_pin, execution_receipt_pin, host_verification_pin,
                            references, stage_root,
                            checkpoint_pin=malformed_checkpoint_pin,
                            checkpoint_raw=malformed_checkpoint,
                        )

                # This canonical, structurally valid v2 checkpoint exercises
                # the real Source5 archive parser and the owner/host/job joins.
                # Its component receipt is deliberately failed, so no APP
                # start/PID is fabricated and the owner must reject its absent
                # four zero proofs before entering numeric replay.
                archive_test_path = SCRIPT.with_name(
                    "test-application-source5-evidence-archive.py",
                )
                archive_test_spec = importlib.util.spec_from_file_location(
                    "fixed_pair_recorded_archive_fixtures", archive_test_path,
                )
                assert archive_test_spec is not None and archive_test_spec.loader is not None
                archive_test_fixtures = importlib.util.module_from_spec(archive_test_spec)
                sys.modules[archive_test_spec.name] = archive_test_fixtures
                archive_test_spec.loader.exec_module(archive_test_fixtures)
                probe_sample = archive_test_fixtures.probe_tree_fixture(
                    root / "recorded-checkpoint-probe-tree",
                )
                recorded_receipt = captured["execution_receipt"]
                recorded_receipt_raw = FIXED.canonical_bytes(recorded_receipt)
                recorded_host_raw = Path(
                    references[host_verification_pin["path"]]["path"],
                ).read_bytes()
                recorded_host = json.loads(recorded_host_raw)
                owner_pins = {
                    "component_receipt": {
                        "path": execution_receipt_pin["path"],
                        "raw_sha256": FIXED.sha256_bytes(recorded_receipt_raw),
                        "semantic_sha256": recorded_receipt["receipt_sha256"],
                    },
                    "fixed_pair_host_receipt": {
                        "path": host_verification_pin["path"],
                        "raw_sha256": host_verification_pin["raw_sha256"],
                        "semantic_sha256": recorded_host["receipt_sha256"],
                    },
                    "probe_capture_receipt_member0": probe_sample["owner_pins"][
                        "probe_capture_receipt_member0"
                    ],
                }
                component_row = {
                    "origin_path": execution_receipt_pin["path"],
                    "role": "component_receipt",
                    "byte_count": len(recorded_receipt_raw),
                    "raw_sha256": FIXED.sha256_bytes(recorded_receipt_raw),
                    "semantic_sha256": recorded_receipt["receipt_sha256"],
                }
                host_row = {
                    "origin_path": host_verification_pin["path"],
                    "role": "fixed_pair_host_receipt",
                    "byte_count": len(recorded_host_raw),
                    "raw_sha256": FIXED.sha256_bytes(recorded_host_raw),
                    "semantic_sha256": recorded_host["receipt_sha256"],
                }
                checkpoint_entries = [
                    component_row, host_row,
                    *(row for row in probe_sample["rows"]
                      if row["role"] != "component_receipt"),
                ]
                checkpoint_entries.sort(key=lambda row: row["origin_path"])
                plan_binding = overlay["plan"]
                source_binding = overlay["sources"]["manifests"][selected_host]
                plan_rows = [job for job in plan["jobs"][overlay["job"]["value"]["phase"]]
                             if job["host_id"] == selected_host]
                checkpoint_body = {
                    "schema": ARCHIVE.CHECKPOINT_SCHEMA_V2,
                    "request_pin": {
                        "path": str(root / "recorded-checkpoint-request.json"),
                        "raw_sha256": "1" * 64,
                        "semantic_sha256": "2" * 64,
                    },
                    "context": {
                        "schema": ARCHIVE.CONTEXT_SCHEMA_V1,
                        "campaign_id": overlay["campaign_id"],
                        "host_id": selected_host,
                        "phase": overlay["job"]["value"]["phase"],
                        "job_index": plan_rows.index(overlay["job"]["value"]),
                        "source_manifest_pin": {
                            "path": source_binding["pin"]["path"],
                            "raw_sha256": source_binding["pin"]["sha256"],
                            "semantic_sha256": source_binding["manifest_sha256"],
                        },
                        "execution_manifest_pin": {
                            "path": str(root / "recorded-execution-manifest.json"),
                            "raw_sha256": "3" * 64,
                            "semantic_sha256": "4" * 64,
                        },
                        "plan_pin": {
                            "path": plan_binding["pin"]["path"],
                            "raw_sha256": plan_binding["pin"]["sha256"],
                            "semantic_sha256": plan_binding["semantic_sha256"],
                        },
                        "resource_budget_pin": {
                            "path": str(root / "recorded-resource-budget.json"),
                            "raw_sha256": "5" * 64,
                            "semantic_sha256": "6" * 64,
                        },
                        "predecessor_ack_pin": None,
                        "authorized_signer_fingerprint": "A" * 40,
                    },
                    "job_record_pin": {
                        "path": str(root / "job-records" /
                                    f"{overlay['job']['value']['run_id']}.json"),
                        "raw_sha256": "7" * 64,
                    },
                    "authorization": {"authorization_id": "structural-fixture"},
                    "predecessor_ack_pin": None,
                    "owner_receipt_pins": owner_pins,
                    "empty_tmp_proofs": [],
                    "object_manifest_pin": {
                        "path": str(root / "recorded-object-manifest.json"),
                        "raw_sha256": "8" * 64,
                        "semantic_sha256": "9" * 64,
                    },
                    "entries": checkpoint_entries,
                    "tree_inventories": [probe_sample["tree"]],
                }
                checkpoint = {
                    **checkpoint_body,
                    "checkpoint_sha256": FIXED.sha256_bytes(
                        FIXED.canonical_bytes(checkpoint_body),
                    ),
                }
                checkpoint_raw = FIXED.canonical_bytes(checkpoint)
                checkpoint_pin = {
                    "path": str(root / "recorded-checkpoint.json"),
                    "raw_sha256": FIXED.sha256_bytes(checkpoint_raw),
                    "semantic_sha256": checkpoint["checkpoint_sha256"],
                }
                with patch.object(
                    FIXED, "_verify_fixed_pair_overlay_replay",
                    side_effect=AssertionError("failed receipt reached numeric replay"),
                ):
                    with self.assertRaisesRegex(
                        FIXED.FixedPairError,
                        "requires exactly four receipt-derived zero TMP proofs",
                    ):
                        FIXED.verify_fixed_pair_overlay_recorded_captured_v1(
                            overlay_pin, execution_receipt_pin,
                            host_verification_pin, references, stage_root,
                            checkpoint_pin=checkpoint_pin,
                            checkpoint_raw=checkpoint_raw,
                        )
                wrong_host_checkpoint = copy.deepcopy(checkpoint)
                wrong_host_checkpoint["context"]["host_id"] = "different-host"
                wrong_host_body = {
                    key: value for key, value in wrong_host_checkpoint.items()
                    if key != "checkpoint_sha256"
                }
                wrong_host_checkpoint["checkpoint_sha256"] = FIXED.sha256_bytes(
                    FIXED.canonical_bytes(wrong_host_body),
                )
                wrong_host_raw = FIXED.canonical_bytes(wrong_host_checkpoint)
                wrong_host_pin = {
                    "path": str(root / "wrong-host-checkpoint.json"),
                    "raw_sha256": FIXED.sha256_bytes(wrong_host_raw),
                    "semantic_sha256": wrong_host_checkpoint["checkpoint_sha256"],
                }
                with patch.object(
                    FIXED, "_verify_fixed_pair_overlay_replay",
                    side_effect=AssertionError("wrong-host checkpoint reached numeric replay"),
                ):
                    with self.assertRaisesRegex(
                        FIXED.FixedPairError,
                        "differs from the original SourceV5 host/job/Plan generation",
                    ):
                        FIXED.verify_fixed_pair_overlay_recorded_captured_v1(
                            overlay_pin, execution_receipt_pin,
                            host_verification_pin, references, stage_root,
                            checkpoint_pin=wrong_host_pin,
                            checkpoint_raw=wrong_host_raw,
                        )
            original_verification = {key: value for key, value in result.items()
                                     if key != "host_verification_sha256"}
            self.assertEqual(captured["verification"], original_verification)
            self.assertEqual(captured["overlay"], overlay)
            self.assertTrue(captured["full_replay_verified"])
            self.assertFalse(captured["qualification_eligible"])
            original_component = {
                "schema": "allocatbelt.application-source5-fixed-component.v1",
                "overlay": {"path": overlay_pin["path"], "raw_sha256": overlay_pin["sha256"]},
                "receipt": {"path": execution_receipt_pin["path"], "raw_sha256": execution_receipt_pin["sha256"]},
                "verification": original_verification,
            }
            captured_component = {**original_component, "verification": captured["verification"]}
            self.assertEqual(FIXED.canonical_bytes(captured_component), FIXED.canonical_bytes(original_component))
            self.assertTrue(all(not path.exists() for path in origins))
            unbound_origin = str(pair_output / "unbound.json")
            unbound_local = stage_root / "unbound-capture"
            unbound_local.write_bytes(b"{}\n")
            unbound_local.chmod(0o400)
            references[unbound_origin] = {
                "origin_path": unbound_origin, "path": str(unbound_local),
                "role": "fixed_pair_artifact", "host_id": selected_host,
                "raw_sha256": FIXED.sha256_bytes(b"{}\n"), "semantic_sha256": None,
                "byte_count": 3, "maximum_bytes": FIXED.MAX_PAIR_OUTPUT_BYTES,
            }
            with self.assertRaisesRegex(FIXED.FixedPairError, "undeclared member under the fixed output root"):
                FIXED.prepare_captured_fixed_pair_replay_v1(
                    overlay_pin, execution_receipt_pin, host_verification_pin,
                    references, stage_root,
                )


def _stage_replay_test_files(root: Path, paths: list[Path]):
    """Build real0400 captures for synthetic raw-reader unit fixtures only."""
    stage = root / "reader-stage"
    stage.mkdir(mode=0o700)
    references = {}
    for index, origin in enumerate(paths):
        raw = origin.read_bytes()
        local = stage / f"{index:06d}"
        local.write_bytes(raw)
        local.chmod(0o400)
        references[str(origin)] = {
            "origin_path": str(origin), "path": str(local),
            "role": "fixed_pair_artifact", "host_id": "host-a",
            "raw_sha256": FIXED.sha256_bytes(raw), "semantic_sha256": None,
            "byte_count": len(raw), "maximum_bytes": FIXED.MAX_PAIR_OUTPUT_BYTES,
        }
    return stage, references


class CapturedFixedPairReplayTests(unittest.TestCase):
    def test_full_cardinality_open_loop_ids_replay_captures_with_resident_oracle(self):
        # This is a synthetic numeric-reader fixture, not an executed APP pair.
        # Keep the existing Spec fixture's full standalone arrival minimum.
        with tempfile.TemporaryDirectory(prefix="fixed-capture-open-loop-") as temporary:
            root = Path(temporary).resolve()
            fixtures = _load_source_module("fixed_captured_open_loop_fixtures", SCRIPT.with_name("test-application-campaign.py"))
            controller = fixtures.campaign
            spec, sources = fixtures.spec_fixture()
            source = sources["host-1"]
            cell = next(item for item in spec["cells"] if item["family"] == "cpu" and item["profile"] == "steady")
            count = cell["arrivals"]
            self.assertEqual(count, 100_000)
            self.assertEqual(count, spec["protocol"]["standalone_min_successes"])
            rate = count
            duration = count * 1_000_000_000 // rate
            checksum = 77
            digest = sum(checksum ^ index for index in range(count)) & ((1 << 64) - 1)
            oracle_root = root / "oracles"
            oracle_root.mkdir(mode=0o700)
            oracle_path = oracle_root / "cpu-steady.tsv"
            source_sha = source["source"]["source_tree_sha256"]
            binary_sha = source["artifacts"]["allocatbelt"]["sha256"]
            header = [
                "schema\tallocatbelt-app-oracle-v2", f"source_sha256\t{source_sha}",
                f"binary_sha256\t{binary_sha}", "profile\tsteady", "workload\tcpu",
                "mode\topen_loop", f"average_rate_per_second\t{rate}",
                f"pulse_rate_per_second\t{rate}", f"arrivals\t{count}",
                f"trace_duration_ns\t{duration}", f"kernel_config\t{controller.oracle_kernel_config('cpu')}",
                "id\tscheduled_ns\tworkload\texpected_checksum",
            ]
            oracle_path.write_text("\n".join(header) + "\n" + "".join(
                f"{index}\t{index * 1_000_000_000 // rate}\tcpu\t{checksum}\n"
                for index in range(count)), encoding="utf-8")
            oracle = {"relative_path": oracle_path.name, "allocator": "allocatbelt",
                      "sha256": FIXED.sha256_bytes(oracle_path.read_bytes())}
            job = {"host_id": "host-1", "phase": "confirmation", "ordinal": 2,
                   "run_id": "captured-open-loop-reader-fixture", "family": "cpu", "workload": "cpu",
                   "profile": "steady", "allocator": "allocatbelt", "comparison_family": "fixed_policy",
                   "comparison_kind": "executor", "pair_kind": "matched", "mode": "open_loop",
                   "load_percent": 90, "rate_per_second": rate, "arrivals": count, "oracle": oracle}
            binding = controller.build_runtime_process_bindings(job, spec, source)[0]
            self.assertEqual((binding["pair"], binding["executor"]), ("bounded", "bounded"))
            pair = root / "pair"
            pair.mkdir(mode=0o700)
            prefix = "bounded-bounded"
            row_header = ("schema allocator executor workload mode async_workers blocking_workers topology logical_window global_task_limit retained_window arrival_rate_per_second requested_arrivals attempted admitted rejected_full rejected_resource completed_on_time completed_late errors cancellations unresolved lost result_digest expected_digest capacity_publications_per_second successful_throughput_through_drain_per_second setup_ns timer_pair_median_ns wall_through_drain_ns drain_tail_ns response_p50_ns response_p95_ns response_p99_ns producer_lateness_mean_ns producer_lateness_max_ns max_observed_managed_bytes retained_managed_bytes managed_limit_bytes disk_limit_ops network_limit_ops final_managed_bytes final_disk_ops final_network_ops rss_before_kib rss_after_drain_kib rss_after_shutdown_kib hwm_before_kib hwm_after_drain_kib hwm_after_shutdown_kib shutdown_ns rejected_logical_window rejected_backend_full").split()
            row = {name: "0" for name in row_header}
            row.update(schema="2", allocator="allocatbelt", executor="allocatbelt", workload="cpu", mode="open_loop",
                       arrival_rate_per_second=str(rate), requested_arrivals=str(count), attempted=str(count),
                       admitted=str(count), completed_on_time=str(count), result_digest=str(digest), expected_digest=str(digest),
                       successful_throughput_through_drain_per_second=str(rate), response_p50_ns="100",
                       response_p95_ns="100", response_p99_ns="100", rss_after_drain_kib="100", rss_after_shutdown_kib="100")
            stdout = pair / f"{prefix}.stdout.tsv"
            stdout.write_text("\t".join(row_header) + "\n" + "\t".join(row[name] for name in row_header) + "\n", encoding="utf-8")
            metadata = {"execution_scope": "qualification", "comparison_family": "fixed_policy",
                        "report_nonce_bounded_bounded": binding["report_nonce"],
                        "policy_sha256_bounded_bounded": binding["policy_sha256"],
                        "resource_ceiling_sha256_bounded_bounded": binding["resource_ceiling_sha256"],
                        "fixed_global_control_baseline_bounded_bounded": str(binding["fixed_global_control_baseline"])}
            (pair / "metadata.tsv").write_text("key\tvalue\n" + "".join(f"{key}\t{value}\n" for key, value in sorted(metadata.items())), encoding="utf-8")
            identity = {"report_nonce": binding["report_nonce"], "run_id": job["run_id"],
                        "executor": "allocatbelt", "allocator": "allocatbelt", "workload": "cpu", "profile": "steady",
                        "source_sha256": source_sha, "binary_sha256": binary_sha}
            phases = {"production_trace": duration, "production_cpu_started_ns": 100,
                      "production_cpu_ended_ns": 100 + count * 200, "production_through_drain_cpu_ns": count * 200,
                      "successful_completions": count, "cpu_ns_per_successful_completion": 200}
            shutdown = pair / f"{prefix}.shutdown.tsv"
            shutdown.write_text("schema\tallocatbelt-app-phase-v1\t\n" +
                                "".join(f"identity\t{key}\t{value}\n" for key, value in identity.items()) +
                                "".join(f"phase\t{key}\t{value}\n" for key, value in phases.items()), encoding="utf-8")
            ids = pair / f"{prefix}.ids.tsv"
            ids.write_text("schema\tallocatbelt-app-arrivals-v3\nidentity\t" + "\t".join(
                [binding["report_nonce"], job["run_id"], "allocatbelt", "allocatbelt", "cpu", "steady", source_sha, binary_sha]) +
                "\nid\tworkload\tscheduled_ns\tcompletion_ns\tterminal\tchecksum\texpected_checksum\n" + "".join(
                    f"{index}\tcpu\t{index * 1_000_000_000 // rate}\t{index * 1_000_000_000 // rate + 100}\tcompleted\t{checksum}\t{checksum}\n"
                    for index in range(count)), encoding="utf-8")
            _metric, _fields, expected, validation, receipt_text = fixtures.runtime_fixture_for(binding, source, include_artifacts=True)
            runtime = pair / f"{prefix}.runtime.tsv"
            expectation = pair / f"{prefix}.expectation.json"
            validation_path = pair / f"{prefix}.validation.json"
            runtime.write_text(receipt_text, encoding="utf-8")
            expectation.write_bytes(controller.runtime_readback_module().canonical_bytes(expected))
            validation_path.write_bytes(controller.canonical_bytes(validation))
            process = {"pair": "bounded", "executor": "bounded", "allocator": "allocatbelt",
                       "stdout": stdout.name, "stdout_sha256": controller.sha256_file(stdout),
                       "shutdown_sha256": controller.sha256_file(shutdown), "capacity_family_sha256": "not_applicable",
                       "ids_sha256": controller.sha256_file(ids), "runtime_readback": runtime.name,
                       "runtime_readback_sha256": controller.sha256_file(runtime), "runtime_expectation": expectation.name,
                       "runtime_expectation_sha256": controller.sha256_file(expectation), "runtime_validation": validation_path.name,
                       "runtime_validation_sha256": controller.sha256_file(validation_path),
                       "runtime_recipe_sha256": binding["recipe_sha256"], "resource_ceiling_sha256": binding["resource_ceiling_sha256"],
                       "policy_sha256": binding["policy_sha256"], "fixed_global_control_baseline": str(binding["fixed_global_control_baseline"]),
                       "validator_sha256": source["runtime_readback_validator"]["sha256"], "source_manifest_sha256": source["manifest_sha256"],
                       "calibration_binary_sha256": source["resource_domain_calibration"]["binary"]["sha256"],
                       "calibration_output_sha256": source["resource_domain_calibration"]["output"]["sha256"]}
            baseline = controller.extract_process_metrics(pair, process, job, source, spec, oracle_root)
            paths = sorted(pair.iterdir())
            stage, references = _stage_replay_test_files(root, paths)
            for path in paths:
                path.unlink()
            view = FIXED.CapturedFixedPairArtifactsV1(references, stage)
            old_read, old_snapshot = controller.read_stable_bytes, controller.stable_file_snapshot
            def no_origin_read(path, label, maximum):
                if path.parent == pair:
                    raise AssertionError("captured open-loop metrics read origin output")
                return old_read(path, label, maximum)
            def no_origin_snapshot(path, label, maximum):
                if path.parent == pair:
                    raise AssertionError("captured ID stream read origin output")
                return old_snapshot(path, label, maximum)
            with patch.object(controller, "read_stable_bytes", side_effect=no_origin_read), patch.object(controller, "stable_file_snapshot", side_effect=no_origin_snapshot):
                captured = controller.extract_process_metrics(pair, process, job, source, spec, oracle_root, artifact_view=view)
            self.assertEqual(captured, baseline)
            self.assertEqual(captured["completed"], count)
            self.assertEqual(captured["family_successes"], {"cpu": count})
            self.assertEqual(captured["ids_path"], ids.name)
            self.assertTrue(oracle_path.is_file())
            self.assertTrue(all(not path.exists() for path in paths))
            local_ids = Path(references[str(ids)]["path"])
            raw = local_ids.read_bytes()
            changed = raw.replace(b"0\tcpu\t0\t100\tcompleted\t77\t77\n",
                                  b"0\tcpu\t0\t100\tcompleted\t77\t78\n", 1)
            self.assertNotEqual(changed, raw)
            local_ids.chmod(0o600)
            local_ids.write_bytes(changed)
            local_ids.chmod(0o400)
            forged_sha = FIXED.sha256_bytes(changed)
            references[str(ids)] = {**references[str(ids)], "raw_sha256": forged_sha,
                                     "byte_count": len(changed)}
            forged_process = {**process, "ids_sha256": forged_sha}
            view = FIXED.CapturedFixedPairArtifactsV1(references, stage)
            with self.assertRaisesRegex(controller.CampaignError, "per-ID oracle/timestamp mismatch at 0"):
                controller.extract_process_metrics(pair, forged_process, job, source, spec, oracle_root, artifact_view=view)

    def test_fixed_probe_replay_delegates_capture_to_pinned_feedback_reader(self):
        with tempfile.TemporaryDirectory(prefix="fixed-capture-probe-") as temporary:
            root = Path(temporary).resolve()
            fixture = FEEDBACK_FIXTURES.Fixture(root / "fixture", "disk", profile="steady")
            fixture.install_v4_source_v5()
            reader = _load_source_module("fixed_captured_probe_delegate", SCRIPT.with_name("application-feedback-readback.py"))
            _verify_fixture_probe_offline(root / "fixture", fixture, reader, captured=True)
            self.assertFalse(fixture.construction_probe_path.exists())

    def test_runtime_v2_numeric_replay_uses_captured_bytes_without_writes(self):
        with tempfile.TemporaryDirectory(prefix="fixed-capture-runtime-") as temporary:
            root = Path(temporary).resolve()
            context, bindings = _real_binding_case(root, write_expectations=True)
            fixtures = _load_source_module("fixed_captured_runtime_fixtures", SCRIPT.with_name("test-application-campaign.py"))
            member = context["members"][0]
            _metric, fields, _expected, validation, receipt_text = fixtures.runtime_fixture_for(
                member["runtime_binding"], context["source"], include_artifacts=True,
            )
            outputs = member["outputs"]
            receipt_path = Path(outputs["runtime_readback"])
            validation_path = Path(outputs["runtime_validation"])
            receipt_path.write_text(receipt_text, encoding="utf-8")
            validation_path.write_bytes(context["loaded_modules"]["runtime_reader"].canonical_bytes(validation))
            for path in (receipt_path, validation_path):
                path.chmod(0o600)
            baseline = FIXED._validate_runtime_v2(context, member)
            paths = [receipt_path, Path(outputs["runtime_expectation"]), validation_path]
            stage, references = _stage_replay_test_files(root, paths)
            for path in paths:
                path.unlink()
            context["artifact_view"] = FIXED.CapturedFixedPairArtifactsV1(references, stage)
            with (
                patch.object(FIXED, "write_exclusive", side_effect=AssertionError("captured replay wrote an output")),
                patch.object(FIXED, "read_stable", side_effect=AssertionError("captured runtime replay read an origin")),
            ):
                observed = FIXED._validate_runtime_v2(context, member)
            self.assertEqual(observed, baseline)
            self.assertEqual(observed[0]["after_release"]["global_live_tenants"], 0)
            self.assertEqual(observed[0]["after_release"]["global_used_control"], context["source"]["resource_domain_calibration"]["record"]["fixed_global_control_baseline"])
            self.assertTrue(all(not path.exists() for path in paths))
            validation_reference = references.pop(str(validation_path))
            context["artifact_view"] = FIXED.CapturedFixedPairArtifactsV1(references, stage)
            with patch.object(FIXED, "write_exclusive", side_effect=AssertionError("missing validation was regenerated")):
                with self.assertRaisesRegex(FIXED.FixedPairError, "refuses to create a missing runtime validation"):
                    FIXED._validate_runtime_v2(context, member)
            references[str(validation_path)] = validation_reference
            fields["after_release.global.used.control"] = str(context["source"]["resource_domain_calibration"]["record"]["fixed_global_control_baseline"] + 1)
            reader = context["loaded_modules"]["runtime_reader"]
            forged_raw = (f"schema\t{reader.SCHEMA}\n" + "".join(f"{key}\t{value}\n" for key, value in sorted(fields.items()))).encode("utf-8")
            local = Path(references[str(receipt_path)]["path"])
            local.chmod(0o600)
            local.write_bytes(forged_raw)
            local.chmod(0o400)
            references[str(receipt_path)] = {**references[str(receipt_path)],
                                            "raw_sha256": FIXED.sha256_bytes(forged_raw),
                                            "byte_count": len(forged_raw)}
            context["artifact_view"] = FIXED.CapturedFixedPairArtifactsV1(references, stage)
            with self.assertRaisesRegex(FIXED.FixedPairError, "final owner cleanup mismatch: after_release.global.used.control"):
                FIXED._validate_runtime_v2(context, member)

    def test_feedback_probe_reader_consumes_capture_and_rejects_repinned_semantic_drift(self):
        with tempfile.TemporaryDirectory(prefix="fixed-capture-feedback-") as temporary:
            root = Path(temporary).resolve()
            fixture = FEEDBACK_FIXTURES.Fixture(root / "fixture", "disk", profile="steady")
            fixture.install_v4_source_v5()
            reader = _load_source_module("fixed_captured_feedback_reader", SCRIPT.with_name("application-feedback-readback.py"))
            origin = fixture.construction_probe_path
            stage, references = _stage_replay_test_files(root, [origin])
            origin.unlink()
            view = FIXED.CapturedFixedPairArtifactsV1(references, stage)
            with patch.object(reader, "read_canonical", side_effect=AssertionError("captured feedback reader opened origin")):
                observed = reader.validate_construction_probe(fixture.expectation, fixture.source, artifact_reader=view.read)
            self.assertEqual(observed, fixture.construction_probe_pin["raw_sha256"])
            local = Path(references[str(origin)]["path"])
            probe = json.loads(local.read_bytes())
            probe["rust_control_context"]["required_byte_sources"]["disk"] = False
            raw = reader.canonical_bytes(probe)
            local.chmod(0o600)
            local.write_bytes(raw)
            local.chmod(0o400)
            references[str(origin)] = {**references[str(origin)], "raw_sha256": FIXED.sha256_bytes(raw), "byte_count": len(raw)}
            recipe = copy.deepcopy(fixture.expectation)
            recipe["construction_probe"]["raw_sha256"] = FIXED.sha256_bytes(raw)
            view = FIXED.CapturedFixedPairArtifactsV1(references, stage)
            with self.assertRaisesRegex(reader.ValidationError, "required byte sources"):
                reader.validate_construction_probe(recipe, fixture.source, artifact_reader=view.read)


class RecordedGlobalMetadataReaderTests(unittest.TestCase):
    def test_recorded_load_uses_captured_historical_json_and_resident_source_inputs(self):
        fixture_path = SCRIPT.with_name("test-application-campaign-inputs.py")
        fixture_spec = importlib.util.spec_from_file_location(
            "fixed_pair_global_json_fixtures", fixture_path,
        )
        assert fixture_spec is not None and fixture_spec.loader is not None
        fixture_module = importlib.util.module_from_spec(fixture_spec)
        sys.modules[fixture_spec.name] = fixture_module
        fixture_spec.loader.exec_module(fixture_module)
        campaign = fixture_module.campaign
        spec_value, sources = fixture_module.spec_v3_fixture()
        fixture_module.fixtures.add_frozen_rates(spec_value, include_oracles=True)

        source_root = SCRIPT.parent.parent.resolve(strict=True)
        allowed_cpus = sorted(os.sched_getaffinity(0))
        selected_host = spec_value["hosts"][0]["host_id"]
        host_value = next(
            item for item in spec_value["hosts"] if item["host_id"] == selected_host
        )
        host_value["controls"]["cpu_set"] = ",".join(map(str, allowed_cpus))
        host_value["host_fingerprint_sha256"] = FIXED.sha256_bytes(
            FIXED.canonical_bytes(host_value["controls"]),
        )

        with tempfile.TemporaryDirectory(prefix="fixed-recorded-global-json-") as temporary:
            root = Path(temporary).resolve()
            input_root = root / "historical-inputs"
            input_root.mkdir(mode=0o700)

            def write_input(pin, raw):
                path = input_root / pin["relative_path"]
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                path.write_bytes(raw)
                pin["raw_sha256"] = FIXED.sha256_bytes(raw)
                return path

            current_payloads = []
            for template in spec_value["qualification_inputs"]["capacity_templates"]:
                request_raw = campaign.canonical_bytes({
                    "schema": "allocatbelt.application-capacity-request-template.v1",
                    "minimum_interval_seconds": 10,
                })
                storage = None
                if template["workload"] in ("disk", "mixed"):
                    storage = {
                        "scope": "application_file_io",
                        "root_path": str(root / "application-files"),
                        "filesystem_type": "ext4",
                        "device_major_minor": "8:1",
                        "minimum_free_bytes": 4096,
                    }
                network = None
                if template["workload"] in ("http", "mixed"):
                    network = {
                        "scope": "ipv4_loopback_application_bytes",
                        "interface": "lo", "address": "127.0.0.1",
                        "namespace_inode": 77,
                    }
                context_raw = campaign.canonical_bytes({
                    "schema": "allocatbelt.application-capacity-context-template.v1",
                    "storage": storage, "network": network,
                })
                current_payloads.extend((
                    write_input(template["request_template"], request_raw),
                    write_input(template["context_template"], context_raw),
                ))
            for condition in spec_value["qualification_inputs"]["pressure_conditions"]:
                current_payloads.extend((
                    write_input(condition["condition"], b"resident pressure condition\n"),
                    write_input(
                        condition["pressure_calibration"]["artifact"],
                        b"resident pressure calibration artifact\n",
                    ),
                    write_input(
                        condition["pressure_calibration"]["receipt"],
                        b"resident pressure calibration receipt\n",
                    ),
                ))
                condition["condition_sha256"] = condition["condition"]["raw_sha256"]

            source_manifest_pins = {}
            for host_id, source_value in sources.items():
                reference = next(
                    item for item in spec_value["source_manifests"]
                    if item["host_id"] == host_id
                )
                relative = f"source/{host_id}.json"
                reference["relative_path"] = relative
                source_raw = FIXED.canonical_bytes(source_value)
                source_path = input_root / relative
                source_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                source_path.write_bytes(source_raw)
                source_manifest_pins[host_id] = {
                    "path": str(source_path),
                    "sha256": FIXED.sha256_bytes(source_raw),
                }

            spec_path = input_root / "spec-v3.json"
            spec_raw = FIXED.canonical_bytes(spec_value)
            spec_path.write_bytes(spec_raw)
            jobs = campaign.build_jobs(spec_value, "exploration")
            exact_job = next(item for item in jobs if item["host_id"] == selected_host)
            plan_body = {
                "schema": campaign.PLAN_SCHEMA_V3,
                "campaign_id": spec_value["campaign_id"],
                "spec_sha256": campaign.digest_object(spec_value),
                "source_manifests": {
                    host_id: item["manifest_sha256"]
                    for host_id, item in sources.items()
                },
                "jobs": {"exploration": jobs},
            }
            plan_value = {
                **plan_body,
                "plan_sha256": campaign.digest_object(plan_body, "plan_sha256"),
            }
            plan_path = input_root / "plan-v3.json"
            plan_raw = FIXED.canonical_bytes(plan_value)
            plan_path.write_bytes(plan_raw)

            observed_host_path = input_root / "observed-host.json"
            observed_host_raw = FIXED.canonical_bytes(host_value)
            observed_host_path.write_bytes(observed_host_raw)
            original_pins = {
                "spec": {"path": str(spec_path), "sha256": FIXED.sha256_bytes(spec_raw)},
                "spec_semantic_sha256": campaign.digest_object(spec_value),
                "plan": {"path": str(plan_path), "sha256": FIXED.sha256_bytes(plan_raw)},
                "plan_semantic_sha256": plan_value["plan_sha256"],
                "source_manifests": source_manifest_pins,
                "campaign_artifacts_root": str(root / "historical-artifacts"),
            }
            execution_modules = {
                name: {
                    "path": relative,
                    "sha256": next(
                        item["sha256"] for item in sources[selected_host]["source"]["files"]
                        if item["path"] == relative
                    ),
                }
                for name, relative in FIXED.MODULE_PATHS.items()
            }
            execution_pins = {
                "source_root": str(source_root),
                "selected_host_id": selected_host,
                "modules": execution_modules,
            }
            output_root = root / "historical-output"
            observed_pin = {
                "path": str(observed_host_path),
                "sha256": FIXED.sha256_bytes(observed_host_raw),
            }
            host_identity_body = {
                "schema": FIXED.HOST_VERIFICATION_IDENTITY_SCHEMA,
                "host_id": selected_host,
                "observed_host_raw_sha256": observed_pin["sha256"],
                "process_affinity": allowed_cpus,
                "network_namespace_inode": 77,
                "output_mount": {},
            }
            host_identity = {
                **host_identity_body,
                "host_verification_sha256": FIXED.sha256_bytes(
                    FIXED.canonical_bytes(host_identity_body),
                ),
            }
            offline_facts = {
                "schema": FIXED.HOST_VERIFICATION_SCHEMA,
                "host_verification": host_identity,
            }

            global_origins = [
                (spec_path, spec_raw), (plan_path, plan_raw),
                (observed_host_path, observed_host_raw),
                *(
                    (Path(pin["path"]), Path(pin["path"]).read_bytes())
                    for pin in source_manifest_pins.values()
                ),
            ]
            global_stage = root / "captured-global-json"
            global_stage.mkdir(mode=0o700)
            captures = {}
            for index, (origin, raw) in enumerate(global_origins):
                digest = FIXED.sha256_bytes(raw)
                local = global_stage / f"{index:04d}.json"
                local.write_bytes(raw)
                local.chmod(0o400)
                captures[(str(origin), digest)] = local
                origin.unlink()
            self.assertTrue(all(not origin.exists() for origin, _raw in global_origins))
            self.assertTrue(all(path.is_file() for path in current_payloads))

            read_caps = {
                str(spec_path): FIXED.MAX_SPEC_BYTES,
                str(plan_path): FIXED.MAX_PLAN_BYTES,
                str(observed_host_path): FIXED.MAX_MANIFEST_BYTES,
                **{
                    pin["path"]: FIXED.MAX_MANIFEST_BYTES
                    for pin in source_manifest_pins.values()
                },
            }
            reads = []

            def global_reader(pin, maximum):
                self.assertEqual(set(pin), {"path", "raw_sha256"})
                self.assertEqual(maximum, read_caps[pin["path"]])
                local = captures[(pin["path"], pin["raw_sha256"])]
                info = local.lstat()
                self.assertTrue(stat.S_ISREG(info.st_mode))
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o400)
                raw, _sha, _info = FIXED.read_stable(local, "captured historical JSON", maximum)
                reads.append(pin["path"])
                return raw

            original_loader = FIXED._load_pinned_module

            def load_controller(raw, path, label):
                module = original_loader(raw, path, label)
                if label == "campaign_controller":
                    def verify_source_manifest(value, source_root=None, verify_artifacts=True):
                        campaign.verify_source_manifest(value, verify_artifacts=False)
                        if source_root is not None:
                            campaign.source_inventory_module().verify_source_tree(
                                source_root, value["source"]["source_tree_sha256"],
                                value["source"]["files"],
                            )

                    def verify_plan(value, validator_sha256=None, campaign_inputs_module_sha256=None):
                        FIXED.require(
                            value["plan_sha256"] == campaign.digest_object(value, "plan_sha256"),
                            "recorded fixture plan semantic digest differs",
                        )
                        FIXED.require(
                            validator_sha256 == sources[selected_host]["runtime_readback_validator"]["sha256"] and
                            campaign_inputs_module_sha256 == campaign.campaign_inputs_source_sha256(sources),
                            "recorded fixture plan SourceV5 module pins differ",
                        )

                    module.verify_source_manifest = verify_source_manifest
                    module.verify_plan = verify_plan
                return module

            with patch.object(FIXED, "_load_pinned_module", side_effect=load_controller):
                context = FIXED._load_source_inputs(
                    original_pins, execution_pins, exact_job, observed_pin,
                    str(output_root), create_output=False,
                    offline_facts=offline_facts, recorded_host=True,
                    global_artifact_reader=global_reader,
                )
            self.assertEqual(context["spec_path"], spec_path)
            self.assertEqual(context["plan_path"], plan_path)
            self.assertEqual(context["input_root"], input_root)
            self.assertTrue(context["input_root"].is_dir())
            self.assertTrue(all(path.is_file() for path in current_payloads))
            self.assertIn(str(spec_path), reads)
            self.assertIn(str(plan_path), reads)
            self.assertIn(str(observed_host_path), reads)
            self.assertEqual(len(reads), 2 + len(source_manifest_pins) + 1)
            self.assertEqual(set(reads), set(read_caps))
            with self.assertRaisesRegex(FIXED.FixedPairError, "unavailable|cannot safely open"):
                FIXED._load_source_inputs(
                    original_pins, execution_pins, exact_job, observed_pin,
                    str(output_root), create_output=False,
                    offline_facts=offline_facts, recorded_host=True,
                )

            with self.assertRaisesRegex(FIXED.FixedPairError, "differs from its raw SHA-256"):
                FIXED._read_recorded_global_json_pin(
                    {"path": str(spec_path), "sha256": "0" * 64},
                    "original SpecV3", FIXED.MAX_SPEC_BYTES,
                    lambda _pin, _maximum: spec_raw,
                )

            def missing_reader(_pin, _maximum):
                raise FIXED.FixedPairError("captured historical JSON pin is missing")

            with self.assertRaisesRegex(FIXED.FixedPairError, "pin is missing"):
                FIXED._read_recorded_global_json_pin(
                    {"path": str(spec_path), "sha256": FIXED.sha256_bytes(spec_raw)},
                    "original SpecV3", FIXED.MAX_SPEC_BYTES, missing_reader,
                )

            changed_host = copy.deepcopy(host_value)
            changed_host["controls"]["kernel_release"] += "-changed"
            changed_host["host_fingerprint_sha256"] = FIXED.sha256_bytes(
                FIXED.canonical_bytes(changed_host["controls"]),
            )
            changed_host_raw = FIXED.canonical_bytes(changed_host)
            changed_host_pin = {
                "path": str(observed_host_path),
                "sha256": FIXED.sha256_bytes(changed_host_raw),
            }
            changed_identity_body = {
                **host_identity_body,
                "observed_host_raw_sha256": changed_host_pin["sha256"],
            }
            changed_identity = {
                **changed_identity_body,
                "host_verification_sha256": FIXED.sha256_bytes(
                    FIXED.canonical_bytes(changed_identity_body),
                ),
            }
            with self.assertRaisesRegex(
                FIXED.FixedPairError,
                "differs from the original SpecV3 host entry",
            ):
                FIXED._offline_host_observation(
                    {"schema": FIXED.HOST_VERIFICATION_SCHEMA,
                     "host_verification": changed_identity},
                    changed_host_pin, spec_value, selected_host,
                    global_artifact_reader=lambda _pin, _maximum: changed_host_raw,
                )


class RecordedFixedCheckpointV3Tests(unittest.TestCase):
    """Structural SourceV5 checkpoint join; this is not APP evidence."""

    def test_fixed_owner_derives_v3_proofs_from_the_exact_receipt(self):
        fixture_path = SCRIPT.with_name("test-application-source5-evidence-archive.py")
        fixture_spec = importlib.util.spec_from_file_location(
            "fixed_pair_v3_archive_fixtures", fixture_path,
        )
        assert fixture_spec is not None and fixture_spec.loader is not None
        fixture_module = importlib.util.module_from_spec(fixture_spec)
        sys.modules[fixture_spec.name] = fixture_module
        fixture_spec.loader.exec_module(fixture_module)

        with tempfile.TemporaryDirectory(prefix="fixed-owner-v3-closure-") as temporary:
            root = Path(temporary)
            output = root / "output"
            output.mkdir(mode=0o700)
            sample = fixture_module.fixed_host_receipt_fixture(
                root, state="valid_pair",
            )
            fixture = sample["fixture"]
            request, request_pin = ARCHIVE.build_fixed_checkpoint_request_v3(
                sample["context"], fixture["job_record_pin"],
                fixture["record_raw"], fixture["plan_raw"], sample["rows"],
                sample["owner_receipts"], output / "request.json",
            )
            request_raw = (output / "request.json").read_bytes()
            manifest_pin = {
                "path": str(root / "archive" / "objects" / "manifest.json"),
                "raw_sha256": "a" * 64,
                "semantic_sha256": "b" * 64,
            }
            checkpoint, checkpoint_pin = ARCHIVE.build_job_checkpoint(
                request_pin, request_raw, sample["context"],
                fixture["job_record_pin"], fixture["record_raw"],
                fixture["plan_raw"], sample["rows"],
                sample["owner_receipts"], manifest_pin,
                output / "checkpoint.json",
            )
            checkpoint_raw = (output / "checkpoint.json").read_bytes()

            archive_path = SCRIPT.with_name("application-source5-evidence-archive.py")
            archive_raw = archive_path.read_bytes()
            archive_info = archive_path.stat(follow_symlinks=False)
            archive_mode = f"{stat.S_IFMT(archive_info.st_mode) | stat.S_IMODE(archive_info.st_mode):06o}"
            archive_entry = {
                "path": "scripts/application-source5-evidence-archive.py",
                "kind": "file", "mode": archive_mode,
                "sha256": FIXED.sha256_bytes(archive_raw),
                "size": len(archive_raw),
            }
            host_ids = ("host-a", "host-b", "host-c")
            source = {"source": {"files": [archive_entry]}}
            owner_context = {
                "source_root": SCRIPT.parent.parent.resolve(strict=True),
                "sources": {host_id: source for host_id in host_ids},
                "spec": {
                    "schema": "allocatbelt.application-campaign-spec.v3",
                    "hosts": [
                        {"host_id": "host-a", "venue": "bare_metal",
                         "host_fingerprint_sha256": "1" * 64, "controls": {}},
                        {"host_id": "host-b", "venue": "kvm_guest",
                         "host_fingerprint_sha256": "2" * 64, "controls": {}},
                        {"host_id": "host-c", "venue": "kvm_guest",
                         "host_fingerprint_sha256": "3" * 64, "controls": {}},
                    ],
                },
                "controller": types.SimpleNamespace(
                    qualification_host_count=lambda _spec: 3,
                ),
                "plan": fixture["plan"],
            }
            overlay = json.loads(sample["overlay_raw"])
            execution_row = next(
                row for row in sample["rows"]
                if row["role"] == "component_receipt"
            )
            host_pin = fixture["record"]["evidence"]["host_receipt"]
            prepared = {
                "overlay": overlay,
                "execution_receipt": json.loads(
                    sample["owner_receipts"][execution_row["origin_path"]],
                ),
                "host_verification_receipt": json.loads(
                    sample["owner_receipts"][host_pin["path"]],
                ),
                "host_verification_pin": host_pin,
            }
            proofs = FIXED._recorded_fixed_zero_tmp_proofs(
                owner_context, prepared, checkpoint_pin, checkpoint_raw,
            )
            self.assertEqual(checkpoint["schema"], ARCHIVE.CHECKPOINT_SCHEMA_V3)
            self.assertEqual(proofs, request["empty_tmp_proofs"])
            self.assertEqual(len(proofs), 4)

            reordered = dict(checkpoint)
            reordered["empty_tmp_proofs"] = list(
                reversed(checkpoint["empty_tmp_proofs"]),
            )
            checkpoint_body = {
                key: value for key, value in reordered.items()
                if key != "checkpoint_sha256"
            }
            reordered["checkpoint_sha256"] = FIXED.sha256_bytes(
                FIXED.canonical_bytes(checkpoint_body),
            )
            reordered_raw = FIXED.canonical_bytes(reordered)
            reordered_pin = {
                "path": checkpoint_pin["path"],
                "raw_sha256": FIXED.sha256_bytes(reordered_raw),
                "semantic_sha256": reordered["checkpoint_sha256"],
            }
            with self.assertRaisesRegex(
                FIXED.FixedPairError,
                "SourceV5 archive rejected the recorded fixed checkpoint",
            ):
                FIXED._recorded_fixed_zero_tmp_proofs(
                    owner_context, prepared, reordered_pin, reordered_raw,
                )

class CapturedFixedPairArtifactViewTests(unittest.TestCase):
    """Physical capture checks; synthetic origin metadata is never host proof."""

    @contextlib.contextmanager
    def _case(self):
        with tempfile.TemporaryDirectory(prefix="fixed-capture-primitives-") as temporary:
            root = Path(temporary).resolve()
            stage = root / "stage"
            stage.mkdir(mode=0o700)
            output = root / "absent-origin" / "pair"
            host = root / "absent-origin" / "host-receipt.json"
            data = b"original output bytes\n"
            origin = output / "app-events.jsonl"
            originals = {
                origin: data,
                output / "fixed-pair-execution-receipt.json": b"execution envelope\n",
                host: b"strict host envelope\n",
            }
            references = {}
            for index, (name, raw) in enumerate(originals.items()):
                local = stage / f"{index:06d}"
                local.write_bytes(raw)
                local.chmod(0o400)
                references[str(name)] = {
                    "origin_path": str(name), "path": str(local),
                    "role": "fixed_pair_artifact", "host_id": "host-a",
                    "raw_sha256": FIXED.sha256_bytes(raw), "semantic_sha256": None,
                    "byte_count": len(raw), "maximum_bytes": FIXED.MAX_PAIR_OUTPUT_BYTES,
                }
            fact = {"sha256": FIXED.sha256_bytes(data), "size": len(data),
                    "device": 123456789, "inode": 987654321, "mode": 0o600}
            inventory = {"files": {"app-events.jsonl": fact}, "total_bytes": len(data),
                         "maximum_bytes": FIXED.MAX_PAIR_OUTPUT_BYTES}
            overlay = {"output_root": str(output), "members": [], "host_id": "host-a",
                       "runtime_bindings": {"pin": {"path": str(output / ".fixed-pair-runtime-bindings.json")}}}
            yield stage, origin, host, data, references, overlay, {"output_artifacts": inventory}

    def test_nonexistent_origins_and_original_metadata_remain_separate(self):
        with self._case() as (stage, origin, host, data, references, overlay, receipt):
            view = FIXED.CapturedFixedPairArtifactsV1(references, stage)
            view.bind_output_inventory(overlay, receipt, str(host))
            self.assertEqual(view.read(origin, "output", len(data))[0], data)
            with view.open_snapshot(origin, "text stream", len(data)) as (snapshot, _sha, _size):
                with io.TextIOWrapper(snapshot, encoding="utf-8") as text:
                    self.assertEqual(text.read(), data.decode("utf-8"))
            self.assertEqual(view.output_tree(), receipt["output_artifacts"])
            self.assertFalse(origin.exists())
            local_info = Path(references[str(origin)]["path"]).stat()
            self.assertEqual(stat.S_IMODE(local_info.st_mode), 0o400)
            self.assertNotEqual(local_info.st_ino, receipt["output_artifacts"]["files"]["app-events.jsonl"]["inode"])

    def test_physical_mode_symlink_and_hardlink_are_rejected(self):
        for variant in ("mode", "symlink", "hardlink"):
            with self.subTest(variant=variant), self._case() as case:
                stage, origin, _host, data, references, _overlay, _receipt = case
                local = Path(references[str(origin)]["path"])
                if variant == "mode":
                    local.chmod(0o600)
                elif variant == "symlink":
                    actual = stage / "actual"
                    local.rename(actual)
                    local.symlink_to(actual.name)
                else:
                    os.link(local, stage / "second-link")
                with self.assertRaises((FIXED.FixedPairError, OSError)):
                    view = FIXED.CapturedFixedPairArtifactsV1(references, stage)
                    view.read(origin, "output", len(data))

    def test_corrupt_same_size_payload_is_rejected(self):
        with self._case() as (stage, origin, _host, data, references, _overlay, _receipt):
            local = Path(references[str(origin)]["path"])
            local.chmod(0o600)
            local.write_bytes(b"!" * len(data))
            local.chmod(0o400)
            view = FIXED.CapturedFixedPairArtifactsV1(references, stage)
            with self.assertRaisesRegex(FIXED.FixedPairError, "raw bytes differ"):
                view.read(origin, "output", len(data))

    def test_reader_ceiling_is_checked_before_open(self):
        with self._case() as (stage, origin, _host, data, references, _overlay, _receipt):
            view = FIXED.CapturedFixedPairArtifactsV1(references, stage)
            with patch.object(FIXED.os, "open", side_effect=AssertionError("over-ceiling IO")):
                with self.assertRaisesRegex(FIXED.FixedPairError, "original reader byte ceiling"):
                    view.read(origin, "output", len(data) - 1)

    def test_missing_or_undeclared_inventory_members_are_rejected(self):
        for variant in ("missing", "extra"):
            with self.subTest(variant=variant), self._case() as case:
                stage, origin, host, _data, references, overlay, receipt = case
                if variant == "missing":
                    del references[str(origin)]
                else:
                    extra = str(origin.parent / "undeclared.txt")
                    references[extra] = {**references[str(origin)], "origin_path": extra,
                                         "path": str(stage / "extra")}
                    Path(references[extra]["path"]).write_bytes(b"")
                    Path(references[extra]["path"]).chmod(0o400)
                view = FIXED.CapturedFixedPairArtifactsV1(references, stage)
                with self.assertRaisesRegex(FIXED.FixedPairError, "exact origin inventory|unexpected pair output"):
                    view.bind_output_inventory(overlay, receipt, str(host))

    def test_capture_mutation_during_replay_is_rejected(self):
        with self._case() as (stage, origin, _host, data, references, _overlay, _receipt):
            view = FIXED.CapturedFixedPairArtifactsV1(references, stage)
            local = Path(references[str(origin)]["path"])
            with self.assertRaisesRegex(FIXED.FixedPairError, "changed during replay"):
                with view.open_snapshot(origin, "output", len(data)) as (stream, _sha, _size):
                    self.assertEqual(stream.read(), data)
                    local.chmod(0o600)

    def test_origin_names_are_pure_bounded_canonical_names(self):
        for value in ("relative", "/a/../b", "/a//b", "/a\\b", "/a\nb", "/a\tb", "/a\x7fb", "/" + "x" * 4096):
            with self.subTest(value=value[:80]):
                with self.assertRaises(FIXED.FixedPairError):
                    FIXED._captured_origin_path(value, "origin")
        self.assertEqual(str(FIXED._captured_origin_path("/absent/origin", "origin")), "/absent/origin")

    def test_binding_closes_access_to_unrelated_capture_rows(self):
        with self._case() as (stage, origin, host, data, references, overlay, receipt):
            unrelated = str(origin.parent.parent / "other-pair" / "output")
            local = stage / "unrelated"
            local.write_bytes(data)
            local.chmod(0o400)
            references[unrelated] = {**references[str(origin)], "origin_path": unrelated,
                                      "path": str(local)}
            view = FIXED.CapturedFixedPairArtifactsV1(references, stage)
            view.bind_output_inventory(overlay, receipt, str(host))
            with self.assertRaisesRegex(FIXED.FixedPairError, "absent from the exact admitted capture"):
                view.read(unrelated, "unrelated", len(data))


if __name__ == "__main__":
    unittest.main()
