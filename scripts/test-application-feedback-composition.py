#!/usr/bin/env python3
"""Native tests for SourceV5 calibrated feedback composition.

These tests use synthetic trace/capacity fixtures and one no-workload Rust
policy-probe invocation. They never start an application pressure workload.
Run only on the designated SSH-MCP native host.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
SOURCE_ROOT = SCRIPT_DIR.parent


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


reader = _load("feedback_composition_reader_target", SCRIPT_DIR / "application-feedback-readback.py")
composition = _load("feedback_composition_target", SCRIPT_DIR / "application-feedback-composition.py")
capacity = _load("feedback_composition_capacity_target", SCRIPT_DIR / "application-byte-capacity.py")
feedback_fixtures = _load("feedback_composition_feedback_fixtures", SCRIPT_DIR / "test-application-feedback-readback.py")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write(path: Path, raw: bytes) -> None:
    path.write_bytes(raw)
    os.chmod(path, 0o600)


def _artifact_binary(source: dict[str, Any], allocator: str) -> Path:
    artifact = source["artifacts"][allocator]
    relative = Path(artifact["path"])
    if relative.is_absolute() or ".." in relative.parts:
        raise AssertionError("SourceV5 application artifact path is not portable")
    return SOURCE_ROOT.joinpath(*relative.parts)


def _raise_capacity_sample_rates(feedback: Any) -> None:
    rows = feedback.samples_path.read_text(encoding="ascii").splitlines()
    header = rows[1].split("\t")
    disk_column = header.index("disk_meter_committed_bytes")
    download_column = header.index("download_meter_committed_bytes")
    sequence_column = header.index("sample_sequence")
    for index in range(2, len(rows)):
        columns = rows[index].split("\t")
        sequence = int(columns[sequence_column])
        columns[disk_column] = str(sequence * 2_000_000_000)
        columns[download_column] = str(sequence * 3_000_000_000)
        rows[index] = "\t".join(columns)
    feedback.repin("samples", ("\n".join(rows) + "\n").encode("ascii"))


def _capacity_bundle(root: Path, source_manifest_path: Path) -> tuple[Any, dict[str, Any], dict[str, Any]]:
    source_manifest, source_raw, source_sha = composition._read_canonical(
        source_manifest_path, "component SourceV5 manifest", _sha(source_manifest_path.read_bytes()),
    )
    app_binary = _artifact_binary(source_manifest, "allocatbelt")
    app_raw = app_binary.read_bytes()
    app_sha = _sha(app_raw)
    feedback = feedback_fixtures.Fixture(
        root / "feedback", "mixed", profile="mixed", capacity_trace=True,
    )
    app_artifact = source_manifest["artifacts"]["allocatbelt"]
    if app_artifact["sha256"] != app_sha or _sha(app_binary.read_bytes()) != app_sha:
        raise AssertionError("the SourceV5 manifest app artifact bytes differ from the actual source-bound binary")
    feedback.source = source_manifest
    feedback.source_path.write_bytes(source_raw)
    feedback.source_pin = {"path": str(feedback.source_path), "raw_sha256": source_sha}
    feedback.identity.update({
        "host_id": source_manifest["build"]["host_id"],
        "source_sha256": source_manifest["source"]["source_tree_sha256"],
        "binary_sha256": app_sha,
        "executor": "allocatbelt",
        "mode": "capacity",
        "pressure_qualification": False,
    })
    feedback.policy = feedback_fixtures._v4_policy_from_source(feedback.identity, source_manifest)
    probe_raw = feedback_fixtures.reader.canonical_bytes(feedback._construction_probe())
    feedback.construction_probe_path.write_bytes(probe_raw)
    feedback.construction_probe_pin = {
        "path": str(feedback.construction_probe_path), "raw_sha256": _sha(probe_raw),
        "allocator": "allocatbelt", "binary_sha256": app_sha,
    }
    body = {
        "schema": reader.EXPECTATION_SCHEMA_V4,
        "construction_probe": dict(feedback.construction_probe_pin),
        "mode": "capacity_calibration",
        "identity": dict(feedback.identity),
        "policy": feedback.policy,
        "app_capacity_artifact_sha256": None,
        "host_binding": dict(feedback.source_pin),
        "external_pressure_proof": None,
        "final_runtime_binding": None,
        "minimum_production_seconds": 30,
        "minimum_pressure_overlap_seconds": 0,
    }
    feedback_fixtures._freeze_fixture_expectation(feedback, body)
    feedback.capacity_trace = True
    feedback._write_trace()
    _raise_capacity_sample_rates(feedback)

    validation = feedback.verify()
    validation_path = root / "feedback-validation.json"
    validation_raw = capacity.canonical(validation)
    _write(validation_path, validation_raw)
    context = {
        "schema": "allocatbelt.application-capacity-context.v1",
        "identity": dict(feedback.identity), "stage": "pre_confirmation",
        "storage": {"scope": "synthetic_composition_fixture"},
        "network": {"scope": "synthetic_composition_fixture"},
    }
    context_path = root / "capacity-context.json"
    _write(context_path, capacity.canonical(context))
    request = {
        "schema": capacity.REQUEST_SCHEMA,
        "calibration_id": "composition-capacity-fixture",
        "identity": dict(feedback.identity),
        "source_manifest": {"path": str(feedback.source_path), "sha256": feedback.source_pin["raw_sha256"]},
        "validation": {"path": str(validation_path), "sha256": _sha(validation_raw)},
        "expectation": {"path": str(feedback.expectation_path), "sha256": feedback.expectation_sha},
        "expectation_sha256": feedback.expectation_sha,
        "validator_sha256": feedback.source["qualification_harness"]["feedback_validator"]["sha256"],
        "trace_directory": str(feedback.trace),
        "context": {"path": str(context_path), "sha256": _sha(context_path.read_bytes())},
        "minimum_interval_seconds": 10,
    }
    request_raw = capacity.canonical(request)
    request_path = root / "capacity-request.json"
    _write(request_path, request_raw)
    request_sha = _sha(request_raw)
    capacity_raw, receipt = capacity.produce(request, request_sha)
    artifact_path = root / "application-byte-capacity.tsv"
    _write(artifact_path, capacity_raw)
    receipt_raw = capacity.canonical(receipt)
    receipt_path = root / "capacity-receipt.json"
    _write(receipt_path, receipt_raw)
    bundle = {
        "request": {"path": str(request_path), "raw_sha256": request_sha},
        "artifact": {"path": str(artifact_path), "raw_sha256": _sha(capacity_raw)},
        "receipt": {"path": str(receipt_path), "raw_sha256": _sha(receipt_raw)},
    }
    return feedback, bundle, dict(receipt)


class CompositionContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="feedback-composition-", dir="/var/tmp")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_resolver_request_requires_the_full_producer_bundle_and_has_no_pid_field(self) -> None:
        request = {
            "schema": composition.REQUEST_SCHEMA,
            "source_root": str(SOURCE_ROOT),
            "source_manifest": {"path": str(self.root / "source.json"), "raw_sha256": "a" * 64},
            "context": {"host_id": "host", "workload": "mixed", "profile": "mixed", "calibration_id": "cal-1"},
            "construction_probe": {
                "path": str(self.root / "probe.json"), "raw_sha256": "b" * 64,
                "allocator": "allocatbelt", "binary_sha256": "c" * 64,
            },
            "capacity_bundle": {
                "request": {"path": str(self.root / "request.json"), "raw_sha256": "d" * 64},
                "artifact": {"path": str(self.root / "capacity.tsv"), "raw_sha256": "e" * 64},
                "receipt": {"path": str(self.root / "receipt.json"), "raw_sha256": "f" * 64},
            },
        }
        composition._validate_resolve_request(request)
        hash_only = json.loads(json.dumps(request))
        hash_only["capacity_bundle"].pop("request")
        with self.assertRaisesRegex(composition.CompositionError, "unexpected key set"):
            composition._validate_resolve_request(hash_only)
        pid_before_launch = dict(request, process_id=12345)
        with self.assertRaisesRegex(composition.CompositionError, "unexpected key set"):
            composition._validate_resolve_request(pid_before_launch)

    def test_final_expectation_parser_requires_capacity_artifact_and_actual_positive_pid(self) -> None:
        fixture = feedback_fixtures.Fixture(self.root / "feedback", "mixed")
        body = json.loads(fixture.expectation_bytes)
        body.pop("recipe_sha256")
        body["schema"] = reader.EXPECTATION_SCHEMA_V5
        body["mode"] = "pressure_validation"
        body["identity"]["mode"] = "open_loop"
        body["identity"]["pressure_qualification"] = True
        body["app_capacity_artifact_sha256"] = "1" * 64
        artifact_path = self.root / "capacity.tsv"
        _write(artifact_path, b"fixture\n")
        body["app_capacity_artifact"] = {"path": str(artifact_path), "raw_sha256": "1" * 64}
        for bucket in body["policy"]["rate_buckets"].values():
            bucket["initial_bytes_per_second"] = bucket["ceiling_bytes_per_second"]
        body["external_pressure_proof"] = {
            "path": str(self.root / "pressure.json"), "raw_sha256": "2" * 64,
            "validator_sha256": "3" * 64, "recipe_raw_sha256": "4" * 64,
        }
        body["final_runtime_binding"] = {"path": str(self.root / "runtime.tsv"), "raw_sha256": "5" * 64}
        body["minimum_pressure_overlap_seconds"] = 1
        frozen, _ = reader.build_pressure_expectation_recipe(body)
        recipe = json.loads(frozen)
        self.assertEqual(recipe["schema"], reader.EXPECTATION_SCHEMA_V5)
        self.assertEqual(recipe["app_capacity_artifact"]["raw_sha256"], recipe["app_capacity_artifact_sha256"])
        for allocator in reader.APPLICATION_ALLOCATOR_LABELS:
            for executor in reader.V5_EXECUTOR_LABELS:
                role = json.loads(json.dumps(body))
                role["identity"]["allocator"] = allocator
                role["identity"]["executor"] = executor
                role["construction_probe"]["allocator"] = allocator
                reader.build_pressure_expectation_recipe(role)

        no_capacity_pin = dict(body)
        no_capacity_pin.pop("app_capacity_artifact")
        with self.assertRaisesRegex(reader.ValidationError, "unexpected key set"):
            reader.build_pressure_expectation_recipe(no_capacity_pin)
        wrong_capacity_pin = json.loads(json.dumps(body))
        wrong_capacity_pin["app_capacity_artifact"]["raw_sha256"] = "6" * 64
        with self.assertRaisesRegex(reader.ValidationError, "digest fields disagree"):
            reader.build_pressure_expectation_recipe(wrong_capacity_pin)
        for invalid in (True, 1.5, -1):
            mutated = json.loads(json.dumps(body))
            mutated["policy"]["rate_buckets"]["disk"]["initial_bytes_per_second"] = invalid
            with self.assertRaises(reader.ValidationError):
                reader.build_pressure_expectation_recipe(mutated)
        for executor in ("bounded", "tokio", "other"):
            mutated = json.loads(json.dumps(body))
            mutated["identity"]["executor"] = executor
            with self.assertRaisesRegex(reader.ValidationError, "executor"):
                reader.build_pressure_expectation_recipe(mutated)
        zero_pid = json.loads(json.dumps(body))
        zero_pid["identity"]["process_id"] = 0
        with self.assertRaisesRegex(reader.ValidationError, "process_id"):
            reader.build_pressure_expectation_recipe(zero_pid)

    def test_source5_app_cli_full_v4_bundle_replay_resolves_v5_policy_ineligible(self) -> None:
        manifest_env = os.environ.get("ALLOCATBELT_FEEDBACK_V5_SOURCE_MANIFEST")
        if not manifest_env or not Path(manifest_env).is_file():
            self.skipTest("SourceV5 component manifest and actual APP artifacts were not supplied to this native test run")
        source_manifest_path = Path(manifest_env).resolve(strict=True)
        _feedback, bundle, capacity_receipt = _capacity_bundle(self.root, source_manifest_path)
        source_manifest = _feedback.source
        source_manifest_raw_before = reader.canonical_bytes(source_manifest)
        source_manifest_sha_before = reader.sha256_bytes(source_manifest_raw_before)
        values = dict(line.split("\t") for line in Path(bundle["artifact"]["path"]).read_text(encoding="ascii").splitlines())
        self.assertGreater(int(values["disk.bytes_per_second"]), reader.CAPACITY_RATE_ROOF)
        self.assertGreater(int(values["download.bytes_per_second"]), reader.CAPACITY_RATE_ROOF)
        self.assertFalse(capacity_receipt["qualification_eligible"])
        for allocator in reader.APPLICATION_ALLOCATOR_LABELS:
            binary = _artifact_binary(source_manifest, allocator)
            binary_sha = _sha(binary.read_bytes())
            probe_path = self.root / f"calibrated-probe-v2-{allocator}.json"
            command = [
                str(binary), "--emit-feedback-policy-only", "--workload", "mixed", "--profile", "mixed",
                "--capacity-calibration-file", bundle["artifact"]["path"],
                "--capacity-calibration-sha256", bundle["artifact"]["raw_sha256"],
                "--host-id", _feedback.identity["host_id"], "--source-sha256",
                _feedback.source["source"]["source_tree_sha256"],
            ]
            process = subprocess.Popen(command, cwd=SOURCE_ROOT, stdin=subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
            probe_pid = process.pid
            try:
                stdout, stderr = process.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                self.fail(f"actual APP probe timed out: {stderr.decode('utf-8', 'replace')}")
            self.assertEqual(process.returncode, 0, stderr.decode("utf-8", "replace"))
            probe_raw = stdout
            probe = reader.parse_json(probe_raw, f"actual Rust probe v2 ({allocator})", reader.MAX_CONSTRUCTION_PROBE_BYTES)
            self.assertEqual(probe["schema"], "allocatbelt.application-feedback-policy-probe.v2")
            self.assertEqual(probe_raw, reader.canonical_bytes(probe))
            _write(probe_path, probe_raw)
            probe_pin = {
                "path": str(probe_path), "raw_sha256": _sha(probe_raw),
                "allocator": allocator, "binary_sha256": binary_sha,
            }
            identity = {
                "host_id": _feedback.identity["host_id"], "workload": "mixed", "profile": "mixed",
                "allocator": allocator, "source_sha256": source_manifest["source"]["source_tree_sha256"],
                "binary_sha256": binary_sha,
            }
            if allocator == reader.APPLICATION_ALLOCATOR_LABELS[0]:
                _base, _algorithm, _workers = reader._static_policy_from_source_v5(
                    source_manifest, identity, probe["collector"], probe["rust_control_context"]["algorithm"],
                )
                for label, mutate in (
                    ("bool tenant control", lambda item: item.__setitem__("tenant_control_used_with_admission", True)),
                    ("float tenant tasks", lambda item: item.__setitem__("tenant_tasks_used_with_admission", 1.5)),
                    ("negative collector charge", lambda item: item.__setitem__("control_charge_bytes", -1)),
                    ("extra V2 collector field", lambda item: item.__setitem__("unrecognized", 1)),
                ):
                    collector = dict(probe["collector"])
                    mutate(collector)
                    with self.assertRaises(reader.ValidationError, msg=label):
                        reader._static_policy_from_source_v5(
                            source_manifest, identity, collector, probe["rust_control_context"]["algorithm"],
                        )
                    mutated_probe = json.loads(json.dumps(probe))
                    mutated_probe["collector"] = collector
                    with self.assertRaises(reader.ValidationError, msg=f"full V2 evidence: {label}"):
                        reader._validate_calibrated_construction_evidence(source_manifest, mutated_probe, identity)
                mismatched_probe = json.loads(json.dumps(probe))
                mismatched_probe["collector"]["tenant_control_used_with_admission"] += 1
                with self.assertRaisesRegex(reader.ValidationError, "observations differ"):
                    reader._validate_calibrated_construction_evidence(source_manifest, mismatched_probe, identity)
                self.assertEqual(reader.canonical_bytes(source_manifest), source_manifest_raw_before)
            self.assertEqual(
                reader.validate_calibrated_construction_probe_v2(
                    probe_pin, source_manifest, bundle["artifact"], identity,
                ),
                probe_pin["raw_sha256"],
            )
            reader._validate_calibrated_construction_evidence(source_manifest, probe, identity)
            self.assertEqual(reader.canonical_bytes(source_manifest), source_manifest_raw_before)
            self.assertEqual(reader.digest_object(source_manifest), source_manifest_sha_before)
            self.assertEqual(_feedback.source_path.read_bytes(), source_manifest_raw_before)

            request = {
                "schema": composition.REQUEST_SCHEMA,
                "source_root": str(SOURCE_ROOT),
                "source_manifest": _feedback.source_pin,
                "context": {
                    "host_id": _feedback.identity["host_id"], "workload": "mixed", "profile": "mixed",
                    "calibration_id": "composition-capacity-fixture",
                },
                "construction_probe": probe_pin,
                "capacity_bundle": bundle,
            }
            request_path = self.root / f"composition-request-{allocator}.json"
            _write(request_path, composition.canonical(request))
            policy_path = self.root / f"resolved-policy-{allocator}.json"
            composition_receipt_path = self.root / f"composition-receipt-{allocator}.json"
            status = composition.main([
                "resolve", "--request", str(request_path), "--policy-output", str(policy_path),
                "--receipt-output", str(composition_receipt_path),
            ])
            self.assertEqual(status, 0)
            self.assertEqual(reader.canonical_bytes(source_manifest), source_manifest_raw_before)
            self.assertEqual(reader.digest_object(source_manifest), source_manifest_sha_before)
            self.assertEqual(_feedback.source_path.read_bytes(), source_manifest_raw_before)
            policy, _, policy_sha = composition._read_canonical(policy_path, "resolved policy", _sha(policy_path.read_bytes()))
            receipt, _, _ = composition._read_canonical(composition_receipt_path, "composition receipt", _sha(composition_receipt_path.read_bytes()))
            self.assertEqual(policy["context"]["allocator"], allocator)
            self.assertEqual(policy["policy"]["controls"]["disk"]["initial"], reader.CAPACITY_RATE_ROOF)
            self.assertEqual(policy["policy"]["controls"]["download"]["initial"], reader.CAPACITY_RATE_ROOF)
            self.assertEqual(policy["policy"]["rate_buckets"]["disk"]["initial_bytes_per_second"], reader.CAPACITY_RATE_ROOF)
            self.assertEqual(receipt["resolved_policy_raw_sha256"], policy_sha)
            self.assertFalse(receipt["execution_ready"])
            self.assertFalse(receipt["qualification_eligible"])
            self.assertFalse(receipt["controller_chronology_proven"])
            finalize_request = {
                "schema": composition.FINALIZE_SCHEMA,
                "source_root": str(SOURCE_ROOT),
                "source_manifest": _feedback.source_pin,
                "resolved_policy": {"path": str(policy_path), "raw_sha256": _sha(policy_path.read_bytes())},
                "composition_receipt": {"path": str(composition_receipt_path), "raw_sha256": _sha(composition_receipt_path.read_bytes())},
                "construction_probe": probe_pin,
                "capacity_bundle": bundle,
                "expectation_header": {
                    "identity": {
                        "host_id": _feedback.identity["host_id"], "run_id": f"construction-probe-fixture-{allocator}",
                        "report_nonce": "0123456789abcdef0123456789abcdef", "process_id": probe_pid,
                        "allocator": allocator, "executor": "allocatbelt", "workload": "mixed", "profile": "mixed",
                        "mode": "capacity", "source_sha256": identity["source_sha256"],
                        "binary_sha256": binary_sha, "pressure_qualification": True,
                    },
                    "external_pressure_proof": {
                        "path": str(self.root / "pressure-readback.json"), "raw_sha256": "a" * 64,
                        "validator_sha256": "b" * 64, "recipe_raw_sha256": "c" * 64,
                    },
                    "final_runtime_binding": {"path": str(self.root / "runtime-binding.tsv"), "raw_sha256": "d" * 64},
                    "minimum_production_seconds": 10, "minimum_pressure_overlap_seconds": 1,
                },
            }
            finalize_request_path = self.root / f"finalize-request-{allocator}.json"
            finalize_expectation_path = self.root / f"finalized-expectation-{allocator}.json"
            finalize_receipt_path = self.root / f"finalization-receipt-{allocator}.json"
            _write(finalize_request_path, composition.canonical(finalize_request))
            finalize_status = composition.main([
                "finalize", "--request", str(finalize_request_path),
                "--expectation-output", str(finalize_expectation_path),
                "--receipt-output", str(finalize_receipt_path),
            ])
            self.assertEqual(finalize_status, 0)
            finalized, _, _ = composition._read_canonical(
                finalize_expectation_path, "finalized expectation", _sha(finalize_expectation_path.read_bytes()),
            )
            self.assertEqual(finalized["identity"]["process_id"], probe_pid)
            self.assertEqual(finalized["identity"]["run_id"], f"construction-probe-fixture-{allocator}")
            self.assertFalse(finalized["recipe_sha256"] == "0" * 64)
            finalization_receipt, _, _ = composition._read_canonical(
                finalize_receipt_path, "finalization receipt", _sha(finalize_receipt_path.read_bytes()),
            )
            self.assertFalse(finalization_receipt["execution_ready"])
            self.assertFalse(finalization_receipt["qualification_eligible"])
            self.assertFalse(finalization_receipt["controller_chronology_proven"])
            self.assertEqual(reader.canonical_bytes(source_manifest), source_manifest_raw_before)
            self.assertEqual(reader.digest_object(source_manifest), source_manifest_sha_before)
            self.assertEqual(_feedback.source_path.read_bytes(), source_manifest_raw_before)

            if allocator == reader.APPLICATION_ALLOCATOR_LABELS[0]:
                original_request_raw = Path(bundle["request"]["path"]).read_bytes()
                original_receipt_raw = Path(bundle["receipt"]["path"]).read_bytes()
                original_artifact_raw = Path(bundle["artifact"]["path"]).read_bytes()

                def finalize_expect_failure(label: str, altered_bundle: dict[str, Any]) -> None:
                    altered_request = json.loads(json.dumps(finalize_request))
                    altered_request["capacity_bundle"] = altered_bundle
                    bad_request_path = self.root / f"finalize-request-{label}.json"
                    _write(bad_request_path, composition.canonical(altered_request))
                    bad_expectation = self.root / f"bad-expectation-{label}.json"
                    bad_receipt = self.root / f"bad-finalization-{label}.json"
                    status = composition.main([
                        "finalize", "--request", str(bad_request_path),
                        "--expectation-output", str(bad_expectation), "--receipt-output", str(bad_receipt),
                    ])
                    self.assertEqual(status, 2, label)
                    self.assertFalse(bad_expectation.exists())
                    self.assertFalse(bad_receipt.exists())

                try:
                    _write(Path(bundle["request"]["path"]), original_request_raw + b" ")
                    finalize_expect_failure("mutated-request", bundle)
                finally:
                    _write(Path(bundle["request"]["path"]), original_request_raw)
                try:
                    Path(bundle["receipt"]["path"]).unlink()
                    finalize_expect_failure("deleted-receipt", bundle)
                finally:
                    _write(Path(bundle["receipt"]["path"]), original_receipt_raw)
                try:
                    _write(Path(bundle["artifact"]["path"]), original_artifact_raw + b" ")
                    finalize_expect_failure("replaced-artifact", bundle)
                finally:
                    _write(Path(bundle["artifact"]["path"]), original_artifact_raw)
                absent_bundle = json.loads(json.dumps(bundle))
                absent_bundle["receipt"]["path"] = str(self.root / "absent-receipt.json")
                finalize_expect_failure("absent-replacement-path", absent_bundle)
                self.assertEqual(reader.canonical_bytes(source_manifest), source_manifest_raw_before)
                self.assertEqual(reader.digest_object(source_manifest), source_manifest_sha_before)
                self.assertEqual(_feedback.source_path.read_bytes(), source_manifest_raw_before)


            mutations = (
                ("capacity below floor", lambda item: item.update({"disk.bytes_per_second": str(reader.CAPACITY_RATE_FLOOR - 1)}), reader.CAPACITY_RATE_FLOOR - 1, "application_bytes_per_second"),
                ("missing relevant source", lambda item: item.update({"disk.bytes_per_second": "missing", "disk.units": "missing"}), None, "missing"),
            )
            for label, mutate, probe_rate, probe_units in mutations:
                artifact_fields = dict(values)
                mutate(artifact_fields)
                altered_raw = "".join(f"{key}\t{artifact_fields[key]}\n" for key in sorted(artifact_fields)).encode("ascii")
                altered_path = self.root / f"{allocator}-{label.replace(' ', '-')}.tsv"
                _write(altered_path, altered_raw)
                altered_pin = {"path": str(altered_path), "raw_sha256": _sha(altered_raw)}
                altered_probe = json.loads(json.dumps(probe))
                altered_probe["capacity_calibration"]["artifact_sha256"] = _sha(altered_raw)
                altered_probe["capacity_calibration"]["disk"]["bytes_per_second"] = probe_rate
                altered_probe["capacity_calibration"]["disk"]["units"] = probe_units
                with self.assertRaises(reader.ValidationError, msg=label):
                    reader.resolve_calibrated_feedback_policy_v5(source_manifest, altered_probe, altered_pin, identity)

            forged = json.loads(json.dumps(probe))
            forged["capacity_calibration"]["resolution"]["controls"]["disk"]["initial"] += 1
            with self.assertRaises(reader.ValidationError):
                reader.resolve_calibrated_feedback_policy_v5(source_manifest, forged, bundle["artifact"], identity)
            forged = json.loads(json.dumps(probe))
            forged["after_release"]["live_tenants"] = True
            with self.assertRaises(reader.ValidationError):
                reader._validate_calibrated_construction_evidence(source_manifest, forged, identity)
            forged = json.loads(json.dumps(probe))
            forged["construction"]["rate_buckets"]["disk"]["reservations"] = 1
            with self.assertRaises(reader.ValidationError):
                reader._validate_calibrated_construction_evidence(source_manifest, forged, identity)
            forged = json.loads(json.dumps(probe))
            forged["after_release"]["zero_dimensions"]["cpu"] = 1
            with self.assertRaises(reader.ValidationError):
                reader._validate_calibrated_construction_evidence(source_manifest, forged, identity)

            if allocator == reader.APPLICATION_ALLOCATOR_LABELS[0]:
                wrong_pin = {"path": bundle["artifact"]["path"], "raw_sha256": "0" * 64}
                with self.assertRaisesRegex(reader.ValidationError, "raw SHA-256 differs"):
                    reader._read_capacity_artifact_v5(wrong_pin)
                for label, mutate in (
                    ("bool", lambda value: value["rust_control_context"]["controls"]["disk"].__setitem__("initial", True)),
                    ("float", lambda value: value["rust_control_context"]["controls"]["download"].__setitem__("ceiling", 1.5)),
                    ("negative", lambda value: value["rust_control_context"]["rate_buckets"]["upload"].__setitem__("max_reservations", -1)),
                    ("identity", lambda value: value["capacity_calibration"]["identity"].__setitem__("host_id", "other-host")),
                ):
                    malformed = json.loads(json.dumps(probe))
                    mutate(malformed)
                    with self.assertRaises(reader.ValidationError, msg=label):
                        reader.resolve_calibrated_feedback_policy_v5(source_manifest, malformed, bundle["artifact"], identity)
                duplicate = b'{"schema":"a","schema":"b"}\n'
                with self.assertRaises(reader.ValidationError):
                    reader.parse_json(duplicate, "duplicate probe", 128)


class BoundedProbeProcessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="feedback-probe-process-", dir="/var/tmp")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def _script(self, name: str, body: str) -> Path:
        path = self.root / name
        path.write_text(f"#!{sys.executable}\n" + body, encoding="ascii")
        os.chmod(path, 0o700)
        return path

    def test_probe_returns_stdout_when_stderr_reaches_eof_first(self) -> None:
        binary = self._script(
            "stderr-first",
            "import os, sys, time\nos.close(2)\ntime.sleep(0.05)\nsys.stdout.write('probe-output\\n')\nsys.stdout.flush()\n",
        )
        raw = reader._run_feedback_probe(
            binary, self.root,
            {"workload": "mixed", "profile": "mixed", "host_id": "host", "source_sha256": "a" * 64},
            self.root / "unused-capacity.tsv", "b" * 64,
        )
        self.assertEqual(raw, b"probe-output\n")

    def test_nonzero_probe_after_stdout_eof_reports_captured_stderr(self) -> None:
        binary = self._script(
            "stdout-first",
            "import os, sys\nos.close(1)\nsys.stderr.write('probe failure\\n')\nsys.stderr.flush()\nsys.exit(7)\n",
        )
        with self.assertRaisesRegex(reader.ValidationError, "probe failure"):
            reader._run_feedback_probe(
                binary, self.root,
                {"workload": "mixed", "profile": "mixed", "host_id": "host", "source_sha256": "a" * 64},
                self.root / "unused-capacity.tsv", "b" * 64,
            )

    def test_capture_limit_and_timeout_cleanup_are_bounded(self) -> None:
        oversized = self._script("oversized", "import sys\nsys.stdout.buffer.write(b'x' * 4097)\nsys.stdout.flush()\n")
        with self.assertRaisesRegex(reader.ValidationError, "output exceeds"):
            reader._capture_bounded_process(
                [str(oversized)], self.root, "test APP probe", maximum_output_bytes=4096,
            )
        with self.assertRaisesRegex(reader.ValidationError, "deadline"):
            reader._capture_bounded_process(
                [sys.executable, "-c", "import time; time.sleep(5)"],
                self.root, "test APP probe timeout", timeout_seconds=0.05,
            )

    def test_term_ignoring_child_is_killed_within_cleanup_bound(self) -> None:
        started = time.monotonic()
        with self.assertRaisesRegex(reader.ValidationError, "deadline"):
            reader._capture_bounded_process(
                [sys.executable, "-c", "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(10)"],
                self.root, "TERM-ignore probe", timeout_seconds=0.05,
            )
        elapsed = time.monotonic() - started
        self.assertLess(
            elapsed,
            0.05 + reader.PROBE_CLEANUP_TOTAL_SECONDS + 0.5,
        )

    def test_exited_leader_pipe_holding_descendant_is_cleaned_by_owned_group(self) -> None:
        child = (
            "import os,signal,time; child=os.fork(); "
            f"(open({str(self.root / 'pipe-holder.pid')!r}, 'w').write(str(os.getpid())), "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN), time.sleep(10), os._exit(0)) if child == 0 else os._exit(0)"
        )
        started = time.monotonic()
        with self.assertRaisesRegex(reader.ValidationError, "deadline"):
            reader._capture_bounded_process(
                [sys.executable, "-c", child], self.root,
                "leader-exit pipe-holder probe", timeout_seconds=0.5,
            )
        elapsed = time.monotonic() - started
        self.assertLess(
            elapsed,
            0.5 + reader.PROBE_CLEANUP_TOTAL_SECONDS + 0.5,
        )
        pid_path = self.root / "pipe-holder.pid"
        self.assertTrue(pid_path.is_file(), "forked pipe holder must launch before the bounded timeout")
        child_pid = int(pid_path.read_text(encoding="ascii"))
        stat_path = Path(f"/proc/{child_pid}/stat")
        if stat_path.exists():
            try:
                stat_line = stat_path.read_text(encoding="ascii")
            except FileNotFoundError:
                stat_line = ""
            child_state = stat_line.rsplit(")", 1)[1].split()[0] if stat_line else "X"
            self.assertIn(child_state, {"Z", "X"}, "owned pipe holder must not remain live after cleanup")

    def test_nondefault_sigchld_refuses_to_launch_without_reapable_owner(self) -> None:
        previous = signal.signal(signal.SIGCHLD, signal.SIG_IGN)
        try:
            with self.assertRaisesRegex(reader.ValidationError, "default SIGCHLD disposition"):
                reader._capture_bounded_process(
                    [sys.executable, "-c", "raise SystemExit(0)"],
                    self.root, "SIGCHLD ownership probe",
                )
        finally:
            signal.signal(signal.SIGCHLD, previous)

    def test_spawn_failure_preserves_labelled_diagnostic(self) -> None:
        with self.assertRaisesRegex(reader.ValidationError, "cannot execute missing probe"):
            reader._capture_bounded_process(
                [str(self.root / "missing-probe")], self.root, "missing probe",
            )


if __name__ == "__main__":
    unittest.main()
