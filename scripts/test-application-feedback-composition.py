#!/usr/bin/env python3
"""Component tests for SourceV5 calibrated feedback composition.

Ordinary fixture coverage uses synthetic trace/capacity evidence and is not a
qualification witness. The required native capture gate uses the explicit
ALLOCATBELT_FEEDBACK_V5_NATIVE_CAPTURE_REQUIRED mode with source/host inputs.
Neither path starts an application pressure workload. Run native mode only on
the designated SSH-MCP host.
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
from unittest import mock


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
source_inventory = _load("feedback_composition_source_inventory", SCRIPT_DIR / "application-source-inventory.py")


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

    def test_composition_and_reader_close_the_same_capture_paths(self) -> None:
        capture = {
            "output_mount": {"mount_point": "/", "mount_root": "/metadata-only"},
            "tmpdir_final": {"root": "/capture/tmp", "tmpdir_path": "/capture/tmp"},
            "inventory": [{"directory": "/capture", "path": "/capture/stdout.bin"}],
            "application_tmpdir_path": "/capture/app-tmp",
            "pressure_scratch_path": "/capture/scratch",
            "environment": {"TMPDIR": "/capture/tmp"},
            "probe_argv": ["/source/app", "--capacity", "/capture/capacity.tsv"],
            "description": "/not-an-evidence-path",
        }
        expected = {
            "/", "/capture", "/capture/tmp", "/capture/stdout.bin",
            "/capture/app-tmp", "/capture/scratch", "/source/app", "/capture/capacity.tsv",
        }
        self.assertEqual(composition._absolute_paths(capture), expected)
        self.assertEqual(reader._absolute_json_paths(capture), expected)

    def test_source_policy_context_does_not_mutate_pinned_source(self) -> None:
        for schema in (
            "allocatbelt.application-feedback-policy-artifact.v1",
            "allocatbelt.application-feedback-policy-artifact.v2",
        ):
            with self.subTest(schema=schema):
                body = {
                    "schema": schema, "version": "runtime-feedback-policy-v1",
                    "reader_contract": {}, "algorithm": {}, "source_pins": {},
                    "contexts": {"mixed/mixed": {
                        "workers": 4, "minimum_dense_observations": 1,
                        "controls": {"disk": {"floor": 1}},
                    }},
                }
                if schema.endswith(".v2"):
                    body["capacity_floor_policy"] = {"policy_id": reader.CAPACITY_FLOOR_POLICY_ID}
                source = {"feedback_policy": {
                    "schema": schema, "policy": body,
                    "policy_sha256": reader.digest_object(body),
                }}
                original = composition.canonical(source)
                context = composition._source_policy_context(
                    source, {"workload": "mixed", "profile": "mixed"},
                )
                context["capacity_floor_policy_id"] = reader.CAPACITY_FLOOR_POLICY_ID
                context["controls"]["disk"]["floor"] = 2
                self.assertEqual(composition.canonical(source), original)

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
        selected = json.loads(json.dumps(request))
        selected["schema"] = composition.REQUEST_SCHEMA_V2
        selected["capacity_floor_policy_id"] = reader.CAPACITY_FLOOR_POLICY_ID
        composition._validate_resolve_request(selected)
        unknown_floor = json.loads(json.dumps(selected))
        unknown_floor["capacity_floor_policy_id"] = "unknown_floor_policy"
        with self.assertRaisesRegex(composition.CompositionError, "unknown"):
            composition._validate_resolve_request(unknown_floor)
        missing_floor = json.loads(json.dumps(selected))
        missing_floor.pop("capacity_floor_policy_id")
        with self.assertRaisesRegex(composition.CompositionError, "unexpected key set"):
            composition._validate_resolve_request(missing_floor)
        hash_only = json.loads(json.dumps(request))
        hash_only["capacity_bundle"].pop("request")
        with self.assertRaisesRegex(composition.CompositionError, "unexpected key set"):
            composition._validate_resolve_request(hash_only)
        pid_before_launch = dict(request, process_id=12345)
        with self.assertRaisesRegex(composition.CompositionError, "unexpected key set"):
            composition._validate_resolve_request(pid_before_launch)

    def test_source5_offline_inventory_closure_preserves_typed_nested_symlink(self) -> None:
        root = self.root / "source-tree"
        (root / "vendor" / "deep").mkdir(parents=True)
        license_path = root / "LICENSE"
        link_path = root / "vendor" / "deep" / "LICENSE"
        license_raw = b"license fixture\n"
        target = "../../LICENSE"
        license_path.write_bytes(license_raw)
        link_path.symlink_to(target)

        def inventory(link_target: str = target, *, include_middle: bool = False) -> list[dict[str, Any]]:
            target_bytes = link_target.encode("utf-8")
            records: list[dict[str, Any]] = [
                {
                    "path": "LICENSE", "kind": "file", "mode": "100644",
                    "sha256": _sha(license_raw), "size": len(license_raw),
                },
                {
                    "path": "vendor/deep/LICENSE", "kind": "symlink", "mode": "120000",
                    "target": link_target, "sha256": _sha(target_bytes), "size": len(target_bytes),
                },
            ]
            if include_middle:
                middle_target = "../../LICENSE"
                middle_raw = middle_target.encode("utf-8")
                records.append({
                    "path": "vendor/deep/middle", "kind": "symlink", "mode": "120000",
                    "target": middle_target, "sha256": _sha(middle_raw), "size": len(middle_raw),
                })
            return sorted(records, key=lambda item: item["path"].encode("utf-8"))

        def replay_context(paths: list[Path]) -> tuple[Any, Any]:
            entries = [
                {"origin": str(path), "local": str(path)}
                for path in sorted(set(paths), key=lambda item: str(item))
            ]
            value = {
                "schema": reader.FEEDBACK_OFFLINE_CONTEXT_SCHEMA,
                "evidence_path_map": {"schema": reader.EVIDENCE_PATH_MAP_SCHEMA, "entries": entries},
                "probe_capture_pin": {
                    "path": str(self.root / "capture.json"),
                    "raw_sha256": "a" * 64, "receipt_sha256": "b" * 64,
                },
                "capacity_bundle": {
                    "request": {"path": str(self.root / "request.json"), "raw_sha256": "c" * 64},
                    "artifact": {"path": str(self.root / "capacity.tsv"), "raw_sha256": "d" * 64},
                    "receipt": {"path": str(self.root / "receipt.json"), "raw_sha256": "e" * 64},
                },
            }
            return reader._validate_feedback_offline_context(value), composition._offline_context(value)

        valid_records = inventory()
        paths = [root, license_path, link_path]
        reader_context, composition_context = replay_context(paths)
        self.assertEqual(reader_context["mapped_files"], frozenset({str(license_path)}))
        self.assertEqual(reader_context["mapped_symlinks"], frozenset({str(link_path)}))
        self.assertEqual(composition_context["mapped_files"], frozenset({str(license_path)}))
        self.assertEqual(composition_context["mapped_symlinks"], frozenset({str(link_path)}))
        reader._source5_offline_inventory_closure(
            root, valid_records, set(), reader_context, "test SourceV5",
        )
        composition._source5_offline_inventory_closure(
            root, valid_records, set(), composition_context, "test SourceV5",
        )
        inventory_document = {"schema": source_inventory.SCHEMA, "entries": valid_records}
        self.assertEqual(source_inventory.validate_records(inventory_document), valid_records)

        link_path.unlink()
        link_path.symlink_to("../../../abcd")
        outside_contexts = replay_context(paths)
        for module, context in zip((reader, composition), outside_contexts):
            with self.assertRaisesRegex(
                (reader.ValidationError, composition.CompositionError),
                "literal target/hash/size differs from its SourceV5 typed record",
            ):
                module._source5_offline_inventory_closure(
                    root, valid_records, set(), context, "test SourceV5",
                )

        unindexed_chain_target = root / "middlex"
        unindexed_chain_target.symlink_to("LICENSE")
        link_path.unlink()
        link_path.symlink_to("../../middlex")
        chained_live_contexts = replay_context(paths)
        for module, context in zip((reader, composition), chained_live_contexts):
            with self.assertRaisesRegex(
                (reader.ValidationError, composition.CompositionError),
                "literal target/hash/size differs from its SourceV5 typed record",
            ):
                module._source5_offline_inventory_closure(
                    root, valid_records, set(), context, "test SourceV5",
                )

        link_path.unlink()
        link_path.symlink_to("../../../outside")
        escaping_records = inventory("../../../outside")
        escaping_contexts = replay_context(paths)
        for module, context in zip((reader, composition), escaping_contexts):
            module._source5_offline_inventory_closure(
                root, escaping_records, set(), context, "test SourceV5",
            )
        with self.assertRaises(source_inventory.InventoryError):
            source_inventory.validate_records({
                "schema": source_inventory.SCHEMA, "entries": escaping_records,
            })

        middle_path = root / "vendor" / "deep" / "middle"
        middle_path.symlink_to("../../LICENSE")
        link_path.unlink()
        link_path.symlink_to("middle")
        chained_records = inventory("middle", include_middle=True)
        chain_contexts = replay_context([root, license_path, link_path, middle_path])
        for module, context in zip((reader, composition), chain_contexts):
            module._source5_offline_inventory_closure(
                root, chained_records, set(), context, "test SourceV5",
            )
        with self.assertRaises(source_inventory.InventoryError):
            source_inventory.validate_records({
                "schema": source_inventory.SCHEMA, "entries": chained_records,
            })

        (root / "vendor" / "deep" / "LICENSE").unlink()
        (root / "vendor" / "deep" / "LICENSE").symlink_to("middle")
        license_path.unlink()
        license_path.symlink_to(self.root / "replacement-target")
        (self.root / "replacement-target").write_bytes(b"replacement\n")
        replaced_contexts = replay_context([root, license_path, link_path, middle_path])
        for module, context in zip((reader, composition), replaced_contexts):
            with self.assertRaisesRegex(
                (reader.ValidationError, composition.CompositionError), "path map symlinks differ",
            ):
                module._source5_offline_inventory_closure(
                    root, valid_records, set(), context, "test SourceV5",
                )

    def test_required_native_source5_symlink_literal_change_is_rejected(self) -> None:
        capture_mode = os.environ.get("ALLOCATBELT_FEEDBACK_V5_NATIVE_CAPTURE_REQUIRED", "0")
        manifest_env = os.environ.get("ALLOCATBELT_FEEDBACK_V5_SOURCE_MANIFEST")
        observed_host_env = os.environ.get("ALLOCATBELT_FEEDBACK_V5_OBSERVED_HOST")
        if capture_mode == "0" and not manifest_env and not observed_host_env:
            self.skipTest("ordinary fixture mode only; no native symlink acceptance is claimed")
        self.assertEqual(
            capture_mode, "1",
            "the native symlink identity regression requires REQUIRED=1 and cannot be accepted as a skip",
        )
        self.assertTrue(manifest_env and Path(manifest_env).is_file(),
                        "native symlink regression needs the raw-pinned SourceV5 manifest")
        self.assertTrue(observed_host_env and Path(observed_host_env).is_file(),
                        "native symlink regression needs the pinned observed-host context")
        manifest_path = Path(manifest_env).resolve(strict=True)
        manifest_raw = manifest_path.read_bytes()
        source_manifest = reader.parse_json(
            manifest_raw, "native symlink SourceV5 manifest", reader.MAX_SOURCE_MANIFEST_BYTES,
        )
        self.assertEqual(manifest_raw, reader.canonical_bytes(source_manifest))
        self.assertEqual(source_manifest["schema"], reader.SOURCE_MANIFEST_SCHEMA_V5)
        self.assertEqual(
            source_manifest["manifest_sha256"],
            reader.digest_object({key: value for key, value in source_manifest.items()
                                  if key != "manifest_sha256"}),
        )
        host_path = Path(observed_host_env).resolve(strict=True)
        host_raw = host_path.read_bytes()
        observed_host = reader.parse_json(
            host_raw, "native symlink observed-host context", reader.MAX_SOURCE_MANIFEST_BYTES,
        )
        self.assertEqual(host_raw, reader.canonical_bytes(observed_host))
        self.assertEqual(observed_host["schema"], "allocatbelt.application-capacity-host-context.v1")

        inventory = source_manifest["source"]["files"]
        native_link = next(
            record for record in inventory
            if record.get("kind") == "symlink" and record.get("path") == "crates/allocatbelt/LICENSE"
        )
        self.assertEqual(native_link["target"], "../../LICENSE")
        expected_target = native_link["target"].encode("utf-8")
        self.assertEqual(native_link["size"], len(expected_target))
        self.assertGreaterEqual(len(expected_target), len(b"../../../"))
        substituted_target = b"../../../" + b"x" * (
            len(expected_target) - len(b"../../../")
        )
        self.assertEqual(len(substituted_target), len(expected_target))
        self.assertNotEqual(substituted_target, expected_target)

        mapped_files: set[Path] = {manifest_path, host_path}
        mapped_directories: set[Path] = {SOURCE_ROOT.resolve(strict=True)}
        mapped_symlinks: set[Path] = set()
        for record in inventory:
            path = SOURCE_ROOT.joinpath(*Path(record["path"]).parts)
            if record["kind"] == "symlink":
                self.assertTrue(stat.S_ISLNK(path.lstat().st_mode), f"typed symlink is missing: {path}")
                mapped_symlinks.add(path)
            else:
                self.assertTrue(path.is_file() and not path.is_symlink(),
                                f"typed regular file is missing or linked: {path}")
                mapped_files.add(path)
        source_artifact_paths = {
            str(SOURCE_ROOT.joinpath(*Path(item["path"]).parts))
            for item in source_manifest["artifacts"].values()
        }
        for path_text in source_artifact_paths:
            path = Path(path_text)
            self.assertTrue(path.is_file() and not path.is_symlink(),
                            f"SourceV5 artifact is missing or linked: {path}")
            mapped_files.add(path)
        mapped_paths = mapped_files | mapped_directories | mapped_symlinks
        context_value = {
            "schema": reader.FEEDBACK_OFFLINE_CONTEXT_SCHEMA,
            "evidence_path_map": {
                "schema": reader.EVIDENCE_PATH_MAP_SCHEMA,
                "entries": [
                    {"origin": str(path), "local": str(path)}
                    for path in sorted(mapped_paths, key=lambda item: str(item))
                ],
            },
            "probe_capture_pin": {
                "path": str(self.root / "capture.json"),
                "raw_sha256": "a" * 64, "receipt_sha256": "b" * 64,
            },
            "capacity_bundle": {
                "request": {"path": str(self.root / "request.json"), "raw_sha256": "c" * 64},
                "artifact": {"path": str(self.root / "capacity.tsv"), "raw_sha256": "d" * 64},
                "receipt": {"path": str(self.root / "receipt.json"), "raw_sha256": "e" * 64},
            },
        }
        checked_contexts = (
            (reader, reader._validate_feedback_offline_context(context_value)),
            (composition, composition._offline_context(context_value)),
        )
        real_readlink = os.readlink

        def substitute_pinned_link(path: Any, *args: Any, **kwargs: Any) -> Any:
            actual = real_readlink(path, *args, **kwargs)
            return substituted_target if actual == expected_target else actual

        for module, checked_context in checked_contexts:
            with mock.patch.object(os, "readlink", side_effect=substitute_pinned_link):
                with self.assertRaisesRegex(
                    (reader.ValidationError, composition.CompositionError),
                    "literal target/hash/size differs from its SourceV5 typed record",
                ):
                    module._source5_offline_inventory_closure(
                        SOURCE_ROOT, inventory, source_artifact_paths,
                        checked_context, "native SourceV5",
                    )

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
        capture_mode = os.environ.get("ALLOCATBELT_FEEDBACK_V5_NATIVE_CAPTURE_REQUIRED", "0")
        if capture_mode not in ("0", "1"):
            self.fail("ALLOCATBELT_FEEDBACK_V5_NATIVE_CAPTURE_REQUIRED must be 0 or 1")
        manifest_env = os.environ.get("ALLOCATBELT_FEEDBACK_V5_SOURCE_MANIFEST")
        observed_host_env = os.environ.get("ALLOCATBELT_FEEDBACK_V5_OBSERVED_HOST")
        if capture_mode == "1" and (
            not manifest_env or not observed_host_env or
            not Path(manifest_env).is_file() or not Path(observed_host_env).is_file()
        ):
            self.fail("required native ProbeV2 gate needs both raw-pinned SourceV5 and observed-host inputs")
        if bool(manifest_env) != bool(observed_host_env):
            self.fail("partial SourceV5 native inputs cannot silently bypass the ProbeV2 capture")
        if not manifest_env and capture_mode == "0":
            self.skipTest("ordinary fixture mode only; no native ProbeV2 acceptance is claimed")
        if not Path(manifest_env).is_file() or not Path(observed_host_env).is_file():
            self.fail("native SourceV5 manifest and observed-host paths must name existing files")
        source_manifest_path = Path(manifest_env).resolve(strict=True)
        _feedback, bundle, capacity_receipt = _capacity_bundle(self.root, source_manifest_path)
        source_manifest = _feedback.source
        floor_policy_descriptor = source_manifest["feedback_policy"]["policy"].get("capacity_floor_policy")
        if capture_mode == "1":
            self.assertEqual(
                floor_policy_descriptor.get("policy_id") if type(floor_policy_descriptor) is dict else None,
                reader.CAPACITY_FLOOR_POLICY_ID,
                "required native ProbeV2 gate must pin the selected capacity-floor rule in every SourceV5 manifest",
            )
        self.assertIs(
            type(floor_policy_descriptor), dict,
            "this SourceV5 replay case requires a selected floor descriptor; default ProbeV2 needs a separate genuine unselected SourceV5 case",
        )
        capacity_floor_policy_id = floor_policy_descriptor.get("policy_id")
        self.assertEqual(
            capacity_floor_policy_id, reader.CAPACITY_FLOOR_POLICY_ID,
            "composition fixture requires the selected SourceV5 floor policy supported by ProbeV2",
        )
        source_manifest_raw_before = reader.canonical_bytes(source_manifest)
        source_manifest_sha_before = reader.sha256_bytes(source_manifest_raw_before)
        values = dict(line.split("\t") for line in Path(bundle["artifact"]["path"]).read_text(encoding="ascii").splitlines())
        self.assertGreater(int(values["disk.bytes_per_second"]), reader.CAPACITY_RATE_ROOF)
        self.assertGreater(int(values["download.bytes_per_second"]), reader.CAPACITY_RATE_ROOF)
        self.assertFalse(capacity_receipt["qualification_eligible"])
        for allocator in reader.APPLICATION_ALLOCATOR_LABELS:
            offline_replay_context: dict[str, Any] | None = None
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
            command.extend(["--capacity-floor-policy-id", capacity_floor_policy_id])
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
                    capacity_floor_policy_id=capacity_floor_policy_id,
                ),
                probe_pin["raw_sha256"],
            )
            reader._validate_calibrated_construction_evidence(source_manifest, probe, identity)
            self.assertEqual(reader.canonical_bytes(source_manifest), source_manifest_raw_before)
            self.assertEqual(reader.digest_object(source_manifest), source_manifest_sha_before)
            self.assertEqual(_feedback.source_path.read_bytes(), source_manifest_raw_before)

            if allocator == reader.APPLICATION_ALLOCATOR_LABELS[0]:
                # This fresh synthetic artifact keeps the captured source/run
                # identity and changes only the two independent byte rates.
                # It exercises the actual ProbeV2 CLI and reader, not a lowered
                # expected receipt or a re-labeled original capacity artifact.
                fields = dict(
                    line.split("\t")
                    for line in Path(bundle["artifact"]["path"]).read_text(encoding="ascii").splitlines()
                )
                fields["disk.bytes_per_second"] = "4617956"
                fields["download.bytes_per_second"] = "4617956"
                low_capacity_raw = ("".join(f"{name}\t{fields[name]}\n" for name in sorted(fields))).encode("ascii")
                low_capacity_path = self.root / "capacity-low-relative-floor.tsv"
                _write(low_capacity_path, low_capacity_raw)
                low_capacity_pin = {"path": str(low_capacity_path), "raw_sha256": _sha(low_capacity_raw)}
                self.assertLess(
                    4_617_956, reader.CAPACITY_RATE_FLOOR,
                    "the selected relative-floor witness must remain below the legacy static floor",
                )
                selected_command = [
                    str(binary), "--emit-feedback-policy-only", "--workload", "mixed", "--profile", "mixed",
                    "--capacity-calibration-file", low_capacity_pin["path"],
                    "--capacity-calibration-sha256", low_capacity_pin["raw_sha256"],
                    "--host-id", _feedback.identity["host_id"], "--source-sha256",
                    _feedback.source["source"]["source_tree_sha256"],
                    "--capacity-floor-policy-id", capacity_floor_policy_id,
                ]
                selected_process = subprocess.run(
                    selected_command, cwd=SOURCE_ROOT, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
                )
                self.assertEqual(selected_process.returncode, 0, selected_process.stderr.decode("utf-8", "replace"))
                selected_probe = reader.parse_json(
                    selected_process.stdout, "actual low-capacity ProbeV2", reader.MAX_CONSTRUCTION_PROBE_BYTES,
                )
                self.assertEqual(selected_probe["schema"], "allocatbelt.application-feedback-policy-probe.v2")
                selected_probe_path = self.root / "calibrated-probe-relative-floor.json"
                _write(selected_probe_path, selected_process.stdout)
                selected_probe_pin = {
                    "path": str(selected_probe_path), "raw_sha256": _sha(selected_process.stdout),
                    "allocator": allocator, "binary_sha256": binary_sha,
                }
                resolved = reader.resolve_calibrated_feedback_policy_v5(
                    source_manifest, selected_probe, low_capacity_pin, identity,
                    capacity_floor_policy_id=capacity_floor_policy_id,
                )
                self.assertEqual(resolved["controls"]["disk"]["floor"], 461795)
                self.assertEqual(resolved["controls"]["download"]["floor"], 461795)
                self.assertEqual(resolved["controls"]["download"]["initial"], 4617956)
                self.assertEqual(resolved["rate_buckets"]["download"]["initial_bytes_per_second"], 4617956)
                self.assertEqual(
                    reader.validate_calibrated_construction_probe_v2(
                        selected_probe_pin, source_manifest, low_capacity_pin, identity,
                        capacity_floor_policy_id=capacity_floor_policy_id,
                    ),
                    selected_probe_pin["raw_sha256"],
                )
                with self.assertRaisesRegex(reader.ValidationError, "unknown"):
                    reader.resolve_calibrated_feedback_policy_v5(
                        source_manifest, selected_probe, low_capacity_pin, identity,
                        capacity_floor_policy_id="unknown_floor_policy",
                    )
                with self.assertRaisesRegex(reader.ValidationError, "unexpected key set"):
                    reader.resolve_calibrated_feedback_policy_v5(
                        source_manifest, selected_probe, low_capacity_pin, identity,
                    )
                mismatched_selector = json.loads(json.dumps(selected_probe))
                mismatched_selector["capacity_floor_policy_id"] = "unknown_floor_policy"
                with self.assertRaisesRegex(reader.ValidationError, "top-level capacity-floor ID differs"):
                    reader.resolve_calibrated_feedback_policy_v5(
                        source_manifest, mismatched_selector, low_capacity_pin, identity,
                        capacity_floor_policy_id=capacity_floor_policy_id,
                    )

            request = {
                "schema": composition.REQUEST_SCHEMA_V2,
                "source_root": str(SOURCE_ROOT),
                "source_manifest": _feedback.source_pin,
                "context": {
                    "host_id": _feedback.identity["host_id"], "workload": "mixed", "profile": "mixed",
                    "calibration_id": "composition-capacity-fixture",
                },
                "construction_probe": probe_pin,
                "capacity_bundle": bundle,
            }
            request["capacity_floor_policy_id"] = capacity_floor_policy_id
            request_path = self.root / f"composition-request-{allocator}.json"
            request_raw = composition.canonical(request)
            _write(request_path, request_raw)
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
            self.assertEqual(policy["schema"], composition.POLICY_SCHEMA_V2)
            self.assertEqual(receipt["schema"], composition.RECEIPT_SCHEMA_V2)
            self.assertEqual(policy["capacity_floor_policy_id"], capacity_floor_policy_id)
            self.assertEqual(policy["policy"]["capacity_floor_policy_id"], capacity_floor_policy_id)
            self.assertEqual(receipt["capacity_floor_policy_id"], capacity_floor_policy_id)
            with self.assertRaisesRegex(composition.CompositionError, "unknown"):
                composition._validate_resolve_request({
                    **request, "capacity_floor_policy_id": "unknown_floor_policy",
                })
            self.assertEqual(policy["policy"]["controls"]["disk"]["initial"], reader.CAPACITY_RATE_ROOF)
            self.assertEqual(policy["policy"]["controls"]["download"]["initial"], reader.CAPACITY_RATE_ROOF)
            self.assertEqual(policy["policy"]["rate_buckets"]["disk"]["initial_bytes_per_second"], reader.CAPACITY_RATE_ROOF)
            self.assertEqual(receipt["resolved_policy_raw_sha256"], policy_sha)
            self.assertFalse(receipt["execution_ready"])
            self.assertFalse(receipt["qualification_eligible"])
            self.assertFalse(receipt["controller_chronology_proven"])
            if allocator == reader.APPLICATION_ALLOCATOR_LABELS[0]:
                observed_host_path = Path(observed_host_env).resolve(strict=True)
                def probe_storage_budget(receipt_bytes: int = reader.MAX_PROBE_CAPTURE_RECEIPT_BYTES) -> dict[str, int]:
                    return {
                        "tmpdir_bytes": 4 * 1024 * 1024, "tmpdir_inodes": 256,
                        "stdout_bytes": reader.MAX_PROBE_OUTPUT_BYTES,
                        "stderr_bytes": composition.MAX_PROBE_STDERR_BYTES,
                        "owner_result_bytes": composition.MAX_PROBE_OWNER_RESULT_BYTES,
                        "inventory_bytes": composition.MAX_PROBE_TMPDIR_INVENTORY_BYTES,
                        "failure_bytes": composition.MAX_PROBE_CAPTURE_FAILURE_BYTES,
                        "receipt_bytes": receipt_bytes, "output_inodes": 7,
                    }

                undersized_capture_id = hashlib.sha256(
                    (str(self.root) + allocator + probe_pin["raw_sha256"] + "budget").encode("utf-8"),
                ).hexdigest()[:32]
                with mock.patch.object(
                    subprocess, "Popen", side_effect=AssertionError("undersized budget reached Popen"),
                ):
                    with self.assertRaisesRegex(composition.CompositionError, "computed bound"):
                        composition.capture_calibrated_probe_v2(
                            request, _sha(request_raw),
                            {"path": str(observed_host_path),
                             "raw_sha256": _sha(observed_host_path.read_bytes())},
                            output_root=self.root, capture_id=undersized_capture_id,
                            capture_timeout_ns=30_000_000_000,
                            storage_budget=probe_storage_budget(receipt_bytes=1),
                        )
                self.assertFalse((self.root / undersized_capture_id / "owner-result.json").exists())
                capture_id = hashlib.sha256(
                    (str(self.root) + allocator + probe_pin["raw_sha256"]).encode("utf-8"),
                ).hexdigest()[:32]
                capture_pin = composition.capture_calibrated_probe_v2(
                    request, _sha(request_raw),
                    {"path": str(observed_host_path), "raw_sha256": _sha(observed_host_path.read_bytes())},
                    output_root=self.root, capture_id=capture_id,
                    capture_timeout_ns=30_000_000_000,
                    storage_budget=probe_storage_budget(),
                )
                failed_capture_id = hashlib.sha256(
                    (str(self.root) + allocator + probe_pin["raw_sha256"] + "deadline").encode("utf-8"),
                ).hexdigest()[:32]
                with self.assertRaisesRegex(composition.CompositionError, "capture failed"):
                    composition.capture_calibrated_probe_v2(
                        request, _sha(request_raw),
                        {"path": str(observed_host_path), "raw_sha256": _sha(observed_host_path.read_bytes())},
                        output_root=self.root, capture_id=failed_capture_id, capture_timeout_ns=1,
                        storage_budget=probe_storage_budget(),
                    )
                failed_capture_path = self.root / failed_capture_id / "capture-receipt.json"
                failed_capture_value, _failed_capture_raw, _failed_capture_sha = composition._read_canonical(
                    failed_capture_path, "failed owned ProbeV2 capture", _sha(failed_capture_path.read_bytes()),
                )
                failed_owner_path = Path(failed_capture_value["owner_result_pin"]["path"])
                failed_owner_value, _failed_owner_raw, _failed_owner_sha = composition._read_canonical(
                    failed_owner_path, "failed capture's retained FixedR8 owner result",
                    failed_capture_value["owner_result_pin"]["raw_sha256"],
                    composition.MAX_PROBE_OWNER_RESULT_BYTES,
                )
                self.assertTrue(
                    failed_capture_value["exit_status"] != 0 or
                    failed_owner_value["direct"]["timing"]["elapsed_ns"] > 1 or
                    failed_capture_value["output_matches_probe"] is False,
                )
                self.assertFalse(failed_capture_value["qualification_eligible"])
                self.assertFalse(failed_capture_value["execution_ready"])
                self.assertFalse(failed_capture_value["controller_chronology_proven"])
                self.assertTrue(Path(failed_capture_value["stdout"]["path"]).is_file())
                self.assertTrue(Path(failed_capture_value["stderr"]["path"]).is_file())

                post_storage_capture_id = hashlib.sha256(
                    (str(self.root) + allocator + probe_pin["raw_sha256"] + "post-storage").encode("utf-8"),
                ).hexdigest()[:32]
                real_source_loader = composition._captured_source_module

                def fail_only_after_real_owner_load(
                    source_reader: Any, source_value: dict[str, Any], relative: str, label: str,
                ) -> tuple[Any, str]:
                    module, module_sha = real_source_loader(source_reader, source_value, relative, label)
                    if relative == composition.FIXED_PAIR_OWNER:
                        def reject_post_capture_storage(*_args: Any, **_kwargs: Any) -> None:
                            raise composition.CompositionError("injected post-return storage verification failure")
                        module._verify_tmpdir_storage = reject_post_capture_storage
                    return module, module_sha

                with mock.patch.object(
                    composition, "_captured_source_module", side_effect=fail_only_after_real_owner_load,
                ):
                    with self.assertRaisesRegex(
                        composition.CompositionError, "post-return storage verification failure",
                    ):
                        composition.capture_calibrated_probe_v2(
                            request, _sha(request_raw),
                            {"path": str(observed_host_path),
                             "raw_sha256": _sha(observed_host_path.read_bytes())},
                            output_root=self.root, capture_id=post_storage_capture_id,
                            capture_timeout_ns=30_000_000_000,
                            storage_budget=probe_storage_budget(),
                        )
                post_storage_directory = self.root / post_storage_capture_id
                post_storage_owner_path = post_storage_directory / "owner-result.json"
                post_storage_failure_path = post_storage_directory / "capture-failure.json"
                post_owner, _post_owner_raw, post_owner_raw_sha = composition._read_canonical(
                    post_storage_owner_path, "retained original FixedR8 owner result",
                    _sha(post_storage_owner_path.read_bytes()), composition.MAX_PROBE_OWNER_RESULT_BYTES,
                )
                post_failure, _post_failure_raw, _post_failure_sha = composition._read_canonical(
                    post_storage_failure_path, "bounded post-capture failure record",
                    _sha(post_storage_failure_path.read_bytes()), composition.MAX_PROBE_CAPTURE_FAILURE_BYTES,
                )
                self.assertEqual(post_failure["schema"], composition.PROBE_CAPTURE_FAILURE_SCHEMA)
                self.assertEqual(set(post_failure), {
                    "schema", "capture_id", "stage", "error_type", "error_message",
                    "owner_result_pin", "owner_result_overflow", "tmpdir_inventory_pin",
                    "stdout", "stderr", "qualification_eligible", "execution_ready",
                    "controller_chronology_proven", "failure_sha256",
                })
                self.assertEqual(
                    post_failure["failure_sha256"],
                    _sha(composition.canonical({
                        key: value for key, value in post_failure.items() if key != "failure_sha256"
                    })),
                )
                self.assertEqual(post_failure["stage"], "post_capture_validation")
                self.assertEqual(post_failure["owner_result_pin"]["path"], str(post_storage_owner_path))
                self.assertEqual(post_failure["owner_result_pin"]["raw_sha256"], post_owner_raw_sha)
                self.assertEqual(post_owner["direct"]["status"], 0)
                self.assertEqual(
                    post_owner["owner_result_sha256"],
                    _sha(composition.canonical({
                        key: value for key, value in post_owner.items() if key != "owner_result_sha256"
                    })),
                )
                self.assertEqual(post_owner["direct"]["supervision"]["cleanup_status"], "verified")
                self.assertEqual(post_owner["start_callback_count"], 1)
                self.assertFalse(post_failure["qualification_eligible"])
                self.assertFalse(post_failure["execution_ready"])
                self.assertFalse(post_failure["controller_chronology_proven"])
                capture_directory = Path(capture_pin["path"]).parent
                capacity_request_value, _capacity_request_raw, _capacity_request_sha = \
                    composition._read_canonical(
                        Path(bundle["request"]["path"]), "test capacity request",
                        bundle["request"]["raw_sha256"],
                    )
                capacity_expectation_pin = capacity_request_value["expectation"]
                capacity_expectation_value, _capacity_expectation_raw, _capacity_expectation_sha = \
                    composition._read_canonical(
                        Path(capacity_expectation_pin["path"]), "test capacity expectation",
                        capacity_expectation_pin["sha256"],
                    )
                capture_receipt_value, _capture_raw, _capture_sha = composition._read_canonical(
                    Path(capture_pin["path"]), "test ProbeV2 capture receipt", capture_pin["raw_sha256"],
                )
                captured_receipt_body = {
                    key: value for key, value in capture_receipt_value.items()
                    if key != "receipt_sha256"
                }
                produced_envelope, produced_envelope_raw = composition._seal_probe_capture_receipt(
                    captured_receipt_body,
                )
                self.assertEqual(produced_envelope, capture_receipt_value)
                self.assertEqual(produced_envelope_raw, _capture_raw)
                self.assertNotEqual(capture_pin["raw_sha256"], capture_pin["receipt_sha256"])
                self.assertEqual(
                    reader.validate_probe_capture_receipt_envelope(
                        _capture_raw, capture_pin["raw_sha256"], capture_pin["receipt_sha256"],
                    ),
                    capture_receipt_value,
                )
                with self.assertRaisesRegex(reader.ValidationError, "raw SHA-256 differs"):
                    reader.validate_probe_capture_receipt_envelope(
                        _capture_raw, capture_pin["receipt_sha256"], capture_pin["receipt_sha256"],
                    )
                with self.assertRaisesRegex(reader.ValidationError, "semantic digest"):
                    reader.validate_probe_capture_receipt_envelope(
                        _capture_raw, capture_pin["raw_sha256"], capture_pin["raw_sha256"],
                    )
                inventory_sidecar_pin = capture_receipt_value["tmpdir_inventory_pin"]
                capture_inventory_value, _inventory_raw, _inventory_sha = composition._read_canonical(
                    Path(inventory_sidecar_pin["path"]), "test ProbeV2 TMPDIR inventory",
                    inventory_sidecar_pin["raw_sha256"], composition.MAX_PROBE_TMPDIR_INVENTORY_BYTES,
                )
                mapped_files: set[Path] = set()
                mapped_directories: set[Path] = set()
                mapped_symlinks: set[Path] = set()

                def add_mapped_path(path_value: str | Path) -> None:
                    path = Path(path_value).resolve(strict=True)
                    if path.is_dir():
                        mapped_directories.add(path)
                    else:
                        self.assertTrue(path.is_file(), f"unexpected offline input type: {path}")
                        mapped_files.add(path)

                def add_mapped_source_symlink(path_value: str | Path) -> None:
                    path = Path(path_value)
                    self.assertTrue(stat.S_ISLNK(path.lstat().st_mode),
                                    f"expected typed SourceV5 symlink: {path}")
                    self.assertEqual(path.parent.resolve(strict=True), path.parent)
                    mapped_symlinks.add(path)

                mapped_directories.update({SOURCE_ROOT.resolve(strict=True), self.root.resolve(strict=True),
                                           observed_host_path.parent, capture_directory.resolve(strict=True),
                                           (self.root / failed_capture_id).resolve(strict=True),
                                           post_storage_directory.resolve(strict=True),
                                           Path(capacity_request_value["trace_directory"]).resolve(strict=True)})
                add_mapped_path(source_manifest_path)
                add_mapped_path(observed_host_path)
                add_mapped_path(probe_path)
                add_mapped_path(policy_path)
                add_mapped_path(composition_receipt_path)
                for record in source_manifest["source"]["files"]:
                    source_path = SOURCE_ROOT.joinpath(*Path(record["path"]).parts)
                    if record["kind"] == "symlink":
                        add_mapped_source_symlink(source_path)
                    else:
                        add_mapped_path(source_path)
                for artifact in source_manifest["artifacts"].values():
                    add_mapped_path(SOURCE_ROOT.joinpath(*Path(artifact["path"]).parts))
                for pin_value in bundle.values():
                    add_mapped_path(pin_value["path"])
                add_mapped_path(capacity_expectation_pin["path"])
                add_mapped_path(capture_pin["path"])
                for inventory_item in capture_inventory_value["entries"]:
                    add_mapped_path(inventory_item["path"])
                add_mapped_path(failed_capture_path)
                add_mapped_path(post_storage_failure_path)
                for raw_path in (
                    composition._absolute_paths(request)
                    | composition._absolute_paths(source_manifest)
                    | composition._absolute_paths(capacity_request_value)
                    | composition._absolute_paths(capacity_expectation_value)
                    | composition._absolute_paths(capture_receipt_value)
                    | composition._absolute_paths(failed_capture_value)
                ):
                    add_mapped_path(raw_path)
                trace_directory = Path(capacity_request_value["trace_directory"]).resolve(strict=True)
                for name in composition.CAPACITY_TRACE_FILES:
                    add_mapped_path(trace_directory / name)
                map_paths = mapped_files | mapped_directories | mapped_symlinks
                offline_replay_context = {
                    "schema": reader.FEEDBACK_OFFLINE_CONTEXT_SCHEMA,
                    "evidence_path_map": {
                        "schema": reader.EVIDENCE_PATH_MAP_SCHEMA,
                        "entries": [
                            {"origin": str(path), "local": str(path)}
                            for path in sorted(map_paths, key=lambda item: str(item))
                        ],
                    },
                    "probe_capture_pin": capture_pin,
                    "capacity_bundle": bundle,
                }
                failed_context = json.loads(json.dumps(offline_replay_context))
                failed_context["probe_capture_pin"] = {
                    "path": str(failed_capture_path),
                    "raw_sha256": _sha(failed_capture_path.read_bytes()),
                    "receipt_sha256": failed_capture_value["receipt_sha256"],
                }
                with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("offline failure replay attempted Popen")):
                    with self.assertRaises((reader.ValidationError, composition.CompositionError)):
                        reader.validate_calibrated_construction_probe_v2_offline(
                            probe_pin, request["source_manifest"], bundle["artifact"], identity,
                            capacity_floor_policy_id=capacity_floor_policy_id,
                            replay_context=failed_context,
                        )
                missing_source_map = json.loads(json.dumps(offline_replay_context))
                missing_source_map["evidence_path_map"]["entries"] = [
                    item for item in missing_source_map["evidence_path_map"]["entries"]
                    if item["origin"] != str(SOURCE_ROOT)
                ]
                with mock.patch.object(
                    composition, "_read_canonical",
                    side_effect=AssertionError("offline map preflight read nested evidence"),
                ):
                    with self.assertRaisesRegex(composition.CompositionError, "path map omits"):
                        composition.compose_calibrated_policy_v5_offline(
                            request, _sha(request_raw), replay_context=missing_source_map,
                        )
                trace_directory = Path(capacity_request_value["trace_directory"]).resolve(strict=True)
                omitted_map_inputs = [
                    trace_directory,
                    *(trace_directory / name for name in composition.CAPACITY_TRACE_FILES),
                    Path(capacity_request_value["validation"]["path"]).resolve(strict=True),
                    Path(capacity_expectation_pin["path"]).resolve(strict=True),
                    *(Path(bundle[name]["path"]).resolve(strict=True) for name in bundle),
                    SOURCE_ROOT / "scripts/application-feedback-readback.py",
                ]
                real_read_canonical = composition._read_canonical
                trace_file_paths = {trace_directory / name for name in composition.CAPACITY_TRACE_FILES}

                def reject_trace_open(path: Path, label: str, *args: Any, **kwargs: Any) -> Any:
                    self.assertNotIn(Path(path), trace_file_paths, f"preflight opened unallowlisted {label}")
                    return real_read_canonical(path, label, *args, **kwargs)

                for omitted_path in omitted_map_inputs:
                    incomplete_context = json.loads(json.dumps(offline_replay_context))
                    incomplete_context["evidence_path_map"]["entries"] = [
                        entry for entry in incomplete_context["evidence_path_map"]["entries"]
                        if entry["origin"] != str(omitted_path)
                    ]
                    with mock.patch.object(composition, "_read_canonical", side_effect=reject_trace_open), \
                         mock.patch.object(composition, "_load_verified_inputs",
                                           side_effect=AssertionError("offline dependency executed before map closure")), \
                         mock.patch.object(composition, "_captured_source_module",
                                           side_effect=AssertionError("captured module executed before map closure")):
                        with self.assertRaisesRegex(composition.CompositionError, "path map"):
                            composition.compose_calibrated_policy_v5_offline(
                                request, _sha(request_raw), replay_context=incomplete_context,
                            )
                    real_reader_read = reader.read_stable

                    def reject_reader_trace_read(path: Path, label: str, maximum: int) -> Any:
                        self.assertNotIn(Path(path), trace_file_paths,
                                         f"reader preflight opened unallowlisted {label}")
                        return real_reader_read(path, label, maximum)

                    with mock.patch.object(reader, "read_stable", side_effect=reject_reader_trace_read), \
                         mock.patch.object(reader, "_verify_source_manifest_v5",
                                           side_effect=AssertionError("SourceV5 verifier executed before map closure")), \
                         mock.patch.object(reader, "_captured_source5_module",
                                           side_effect=AssertionError("reader dependency executed before map closure")), \
                         mock.patch.object(subprocess, "Popen",
                                           side_effect=AssertionError("reader offline path attempted Popen")):
                        with self.assertRaisesRegex(reader.ValidationError, "path map"):
                            reader.validate_calibrated_construction_probe_v2_offline(
                                probe_pin, request["source_manifest"], bundle["artifact"], identity,
                                capacity_floor_policy_id=capacity_floor_policy_id,
                                replay_context=incomplete_context,
                            )
                with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("offline replay attempted Popen")), \
                     mock.patch.object(reader.os, "statvfs",
                                       side_effect=AssertionError("offline replay queried current storage")), \
                     mock.patch.object(reader.os, "sched_getaffinity",
                                       side_effect=AssertionError("offline replay queried current affinity")), \
                     mock.patch.object(reader.platform, "release",
                                       side_effect=AssertionError("offline replay queried current host")):
                    self.assertEqual(
                        reader.validate_calibrated_construction_probe_v2_offline(
                            probe_pin, request["source_manifest"], bundle["artifact"], identity,
                            capacity_floor_policy_id=capacity_floor_policy_id,
                            replay_context=offline_replay_context,
                        ),
                        probe_pin["raw_sha256"],
                    )
                    offline_policy, offline_receipt = composition.compose_calibrated_policy_v5_offline(
                        request, _sha(request_raw), replay_context=offline_replay_context,
                    )
                self.assertEqual(offline_policy, policy)
                self.assertEqual(offline_receipt, receipt)
                failed_schema_context = json.loads(json.dumps(offline_replay_context))
                failed_schema_context["probe_capture_pin"] = {
                    "path": str(post_storage_failure_path),
                    "raw_sha256": _sha(post_storage_failure_path.read_bytes()),
                    "receipt_sha256": post_failure["failure_sha256"],
                }
                with mock.patch.object(subprocess, "Popen",
                                       side_effect=AssertionError("offline failure replay attempted Popen")), \
                     mock.patch.object(composition, "_captured_source_module",
                                       side_effect=AssertionError("failure schema reached dependency execution")):
                    with self.assertRaisesRegex(composition.CompositionError, "unexpected key set"):
                        composition.compose_calibrated_policy_v5_offline(
                            request, _sha(request_raw), replay_context=failed_schema_context,
                        )
                with mock.patch.object(subprocess, "Popen",
                                       side_effect=AssertionError("offline failure replay attempted Popen")), \
                     mock.patch.object(reader, "_captured_source5_module",
                                       side_effect=AssertionError("failure schema reached dependency execution")):
                    with self.assertRaisesRegex(reader.ValidationError, "unexpected key set"):
                        reader.validate_calibrated_construction_probe_v2_offline(
                            probe_pin, request["source_manifest"], bundle["artifact"], identity,
                            capacity_floor_policy_id=capacity_floor_policy_id,
                            replay_context=failed_schema_context,
                        )
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
            finalize_request_raw = composition.canonical(finalize_request)
            _write(finalize_request_path, finalize_request_raw)
            offline_finalized: dict[str, Any] | None = None
            if offline_replay_context is not None:
                with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("offline finalization attempted Popen")):
                    offline_finalized = composition.finalize_calibrated_feedback_expectation_v5_offline(
                        finalize_request, _sha(finalize_request_raw),
                        replay_context=offline_replay_context,
                    )
            finalize_status = composition.main([
                "finalize", "--request", str(finalize_request_path),
                "--expectation-output", str(finalize_expectation_path),
                "--receipt-output", str(finalize_receipt_path),
            ])
            self.assertEqual(finalize_status, 0)
            finalized, _, _ = composition._read_canonical(
                finalize_expectation_path, "finalized expectation", _sha(finalize_expectation_path.read_bytes()),
            )
            self.assertEqual(finalized["schema"], reader.EXPECTATION_SCHEMA_V6)
            self.assertEqual(finalized["policy"]["capacity_floor_policy_id"], capacity_floor_policy_id)
            self.assertEqual(finalized["identity"]["process_id"], probe_pid)
            self.assertEqual(finalized["identity"]["run_id"], f"construction-probe-fixture-{allocator}")
            self.assertFalse(finalized["recipe_sha256"] == "0" * 64)
            finalization_receipt, _, _ = composition._read_canonical(
                finalize_receipt_path, "finalization receipt", _sha(finalize_receipt_path.read_bytes()),
            )
            self.assertEqual(finalization_receipt["schema"], composition.FINALIZE_RECEIPT_SCHEMA)
            self.assertFalse(finalization_receipt["execution_ready"])
            self.assertFalse(finalization_receipt["qualification_eligible"])
            self.assertFalse(finalization_receipt["controller_chronology_proven"])
            if offline_finalized is not None:
                offline_finalized_raw, _offline_finalized_sha = reader.build_pressure_expectation_recipe(
                    offline_finalized,
                )
                self.assertEqual(offline_finalized_raw, finalize_expectation_path.read_bytes())
                # These empty files and zero-event trace rows are path-map
                # shape fixtures only. The API must stop before reading them
                # as pressure evidence because no full pressure replay request
                # is present in this phase's context.
                blocked_trace_directory = self.root / "blocked-feedback-trace"
                blocked_trace_directory.mkdir(mode=0o700)
                blocked_trace_files = [blocked_trace_directory / name for name in reader.TRACE_FILES]
                for path in blocked_trace_files:
                    _write(path, b"fixture-only\n")
                pressure_pin_path = self.root / "pressure-readback.json"
                runtime_pin_path = self.root / "runtime-binding.tsv"
                _write(pressure_pin_path, b"fixture-only\n")
                _write(runtime_pin_path, b"fixture-only\n")
                blocked_context = json.loads(json.dumps(offline_replay_context))
                blocked_entries = blocked_context["evidence_path_map"]["entries"]
                blocked_entries.extend(
                    {"origin": str(path), "local": str(path)}
                    for path in [blocked_trace_directory, *blocked_trace_files,
                                 pressure_pin_path, runtime_pin_path, finalize_expectation_path]
                )
                blocked_context["evidence_path_map"]["entries"] = sorted(
                    blocked_entries, key=lambda entry: entry["origin"],
                )
                blocked_trace_set = {Path(path) for path in blocked_trace_files}
                real_read_stable = reader.read_stable

                def reject_unrequested_trace_read(path: Path, label: str, maximum: int) -> Any:
                    self.assertNotIn(Path(path), blocked_trace_set,
                                     f"blocked feedback replay opened fixture trace {label}")
                    self.assertNotIn(Path(path), {pressure_pin_path, runtime_pin_path},
                                     f"blocked feedback replay opened fixture proof {label}")
                    return real_read_stable(path, label, maximum)

                with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("offline feedback attempted Popen")):
                    with mock.patch.object(reader, "read_stable", side_effect=reject_unrequested_trace_read):
                        with self.assertRaisesRegex(
                            reader.ValidationError, "closed independent pressure-pair request is required",
                        ):
                            reader.verify_feedback_offline(
                                finalize_expectation_path, _sha(finalize_expectation_path.read_bytes()),
                                blocked_trace_directory,
                                {"manifest": "1" * 64, "events": "2" * 64, "samples": "3" * 64},
                                replay_context=blocked_context,
                            )
            self.assertEqual(reader.canonical_bytes(source_manifest), source_manifest_raw_before)
            self.assertEqual(reader.digest_object(source_manifest), source_manifest_sha_before)
            self.assertEqual(_feedback.source_path.read_bytes(), source_manifest_raw_before)

            if allocator == reader.APPLICATION_ALLOCATOR_LABELS[0]:
                if offline_replay_context is not None:
                    capture_receipt_path = Path(offline_replay_context["probe_capture_pin"]["path"])
                    capture_owner_path = capture_receipt_path.parent / "owner-result.json"
                    capture_inventory_path = capture_receipt_path.parent / "tmpdir-inventory.json"
                    original_capture_receipt = capture_receipt_path.read_bytes()
                    original_owner_result = capture_owner_path.read_bytes()
                    original_inventory_raw = capture_inventory_path.read_bytes()

                    def reseal_capture(
                        mutate: Any, *, mutate_owner: bool,
                    ) -> dict[str, Any]:
                        capture_value = json.loads(original_capture_receipt)
                        capture_body = {key: value for key, value in capture_value.items()
                                        if key != "receipt_sha256"}
                        owner_value = json.loads(original_owner_result)
                        if mutate_owner:
                            mutate(capture_body, owner_value)
                            owner_body = {key: value for key, value in owner_value.items()
                                          if key != "owner_result_sha256"}
                            owner_value["owner_result_sha256"] = _sha(composition.canonical(owner_body))
                            owner_raw = composition.canonical(owner_value)
                            _write(capture_owner_path, owner_raw)
                            capture_body["owner_result_pin"]["raw_sha256"] = _sha(owner_raw)
                            capture_body["owner_result_pin"]["owner_result_sha256"] = owner_value["owner_result_sha256"]
                        else:
                            mutate(capture_body, owner_value)
                        capture_raw = composition.canonical({
                            **capture_body,
                            "receipt_sha256": _sha(composition.canonical(capture_body)),
                        })
                        _write(capture_receipt_path, capture_raw)
                        altered_context = json.loads(json.dumps(offline_replay_context))
                        capture_value = json.loads(capture_raw)
                        altered_context["probe_capture_pin"] = {
                            "path": str(capture_receipt_path), "raw_sha256": _sha(capture_raw),
                            "receipt_sha256": capture_value["receipt_sha256"],
                        }
                        return altered_context

                    try:
                        semantic_context = reseal_capture(
                            lambda capture_body, _owner: capture_body["source_manifest"].__setitem__(
                                "semantic_sha256", "0" * 64,
                            ),
                            mutate_owner=False,
                        )
                        with mock.patch.object(subprocess, "Popen",
                                               side_effect=AssertionError("offline replay attempted Popen")):
                            with self.assertRaisesRegex(
                                (reader.ValidationError, composition.CompositionError),
                                "SourceV5 raw/semantic/tree roles",
                            ):
                                composition.compose_calibrated_policy_v5_offline(
                                    request, _sha(request_raw), replay_context=semantic_context,
                                )

                        def alter_environment(capture_body: dict[str, Any], owner_value: dict[str, Any]) -> None:
                            environment = dict(capture_body["environment"])
                            environment["LANG"] = "C.UTF-8"
                            capture_body["environment"] = environment
                            direct = owner_value["direct"]
                            direct["environment"] = environment
                            environment_sha = _sha(composition.canonical(environment))
                            direct["environment_sha256"] = environment_sha
                            direct["start"]["environment_sha256"] = environment_sha
                            capture_body["start_callback_proof"]["environment_sha256"] = environment_sha
                            capture_body["start"]["owner_proof"]["environment_sha256"] = environment_sha
                            role = {key: value for key, value in capture_body["start"].items()
                                    if key != "start_sha256"}
                            capture_body["start"]["start_sha256"] = _sha(composition.canonical(role))
                            owner_value["start_callback_proofs"] = [capture_body["start_callback_proof"]]

                        environment_context = reseal_capture(alter_environment, mutate_owner=True)
                        with mock.patch.object(subprocess, "Popen",
                                               side_effect=AssertionError("offline environment replay attempted Popen")):
                            with self.assertRaisesRegex(
                                reader.ValidationError, "environment/affinity/netns differs",
                            ):
                                reader.validate_calibrated_construction_probe_v2_offline(
                                    probe_pin, request["source_manifest"], bundle["artifact"], identity,
                                    capacity_floor_policy_id=capacity_floor_policy_id,
                                    replay_context=environment_context,
                                )

                        def add_environment_entry(capture_body: dict[str, Any], owner_value: dict[str, Any]) -> None:
                            environment = dict(capture_body["environment"])
                            environment["UNDECLARED"] = "unexpected"
                            capture_body["environment"] = environment
                            direct = owner_value["direct"]
                            direct["environment"] = environment
                            environment_sha = _sha(composition.canonical(environment))
                            direct["environment_sha256"] = environment_sha
                            direct["start"]["environment_sha256"] = environment_sha
                            capture_body["start_callback_proof"]["environment_sha256"] = environment_sha
                            capture_body["start"]["owner_proof"]["environment_sha256"] = environment_sha
                            role = {key: value for key, value in capture_body["start"].items()
                                    if key != "start_sha256"}
                            capture_body["start"]["start_sha256"] = _sha(composition.canonical(role))
                            owner_value["start_callback_proofs"] = [capture_body["start_callback_proof"]]

                        extra_environment_context = reseal_capture(add_environment_entry, mutate_owner=True)
                        with mock.patch.object(subprocess, "Popen",
                                               side_effect=AssertionError("offline extra-environment replay attempted Popen")):
                            with self.assertRaisesRegex(reader.ValidationError,
                                                        "strict environment has an unexpected key set"):
                                reader.validate_calibrated_construction_probe_v2_offline(
                                    probe_pin, request["source_manifest"], bundle["artifact"], identity,
                                    capacity_floor_policy_id=capacity_floor_policy_id,
                                    replay_context=extra_environment_context,
                                )

                        def alter_affinity(capture_body: dict[str, Any], owner_value: dict[str, Any]) -> None:
                            altered = [65_000]
                            capture_body["affinity"] = altered
                            owner_value["direct"]["cpu_affinity"] = altered

                        affinity_context = reseal_capture(alter_affinity, mutate_owner=True)
                        with mock.patch.object(subprocess, "Popen",
                                               side_effect=AssertionError("offline affinity replay attempted Popen")):
                            with self.assertRaisesRegex(
                                (reader.ValidationError, composition.CompositionError),
                                "environment/affinity/netns differs",
                            ):
                                composition.compose_calibrated_policy_v5_offline(
                                    request, _sha(request_raw), replay_context=affinity_context,
                                )

                        def alter_netns(capture_body: dict[str, Any], owner_value: dict[str, Any]) -> None:
                            capture_body["netns"] += 1
                            owner_value["direct"]["network_namespace_inode"] = capture_body["netns"]

                        netns_context = reseal_capture(alter_netns, mutate_owner=True)
                        with mock.patch.object(subprocess, "Popen",
                                               side_effect=AssertionError("offline finalizer replay attempted Popen")):
                            with self.assertRaisesRegex(
                                (reader.ValidationError, composition.CompositionError),
                                "environment/affinity/netns differs",
                            ):
                                composition.finalize_calibrated_feedback_expectation_v5_offline(
                                    finalize_request, _sha(finalize_request_raw),
                                    replay_context=netns_context,
                                )
                    finally:
                        _write(capture_receipt_path, original_capture_receipt)
                        _write(capture_owner_path, original_owner_result)

                    tmp_path = capture_receipt_path.parent / "tmp"
                    original_tmp_mode = stat.S_IMODE(tmp_path.lstat().st_mode)
                    os.chmod(tmp_path, 0o777)
                    try:
                        with mock.patch.object(subprocess, "Popen",
                                               side_effect=AssertionError("offline TMPDIR check attempted Popen")):
                            with self.assertRaisesRegex(
                                (reader.ValidationError, composition.CompositionError),
                                "output/TMPDIR roots are not owned private directories",
                            ):
                                composition.compose_calibrated_policy_v5_offline(
                                    request, _sha(request_raw), replay_context=offline_replay_context,
                                )
                    finally:
                        os.chmod(tmp_path, original_tmp_mode)

                    if hasattr(os, "geteuid") and os.geteuid() == 0:
                        captured_tmp_uid = tmp_path.lstat().st_uid
                        os.chown(tmp_path, captured_tmp_uid + 1, -1)
                        try:
                            with mock.patch.object(subprocess, "Popen",
                                                   side_effect=AssertionError("offline TMPDIR owner check attempted Popen")):
                                with self.assertRaisesRegex(
                                    composition.CompositionError,
                                    "output/TMPDIR roots are not owned private directories",
                                ):
                                    composition.compose_calibrated_policy_v5_offline(
                                        request, _sha(request_raw), replay_context=offline_replay_context,
                                    )
                        finally:
                            os.chown(tmp_path, captured_tmp_uid, -1)

                    output_directory_path = capture_receipt_path.parent
                    original_output_mode = stat.S_IMODE(output_directory_path.lstat().st_mode)
                    os.chmod(output_directory_path, 0o777)
                    try:
                        with mock.patch.object(subprocess, "Popen",
                                               side_effect=AssertionError("offline output-root check attempted Popen")):
                            with self.assertRaisesRegex(
                                composition.CompositionError, "output root is not an owned private directory",
                            ):
                                composition.compose_calibrated_policy_v5_offline(
                                    request, _sha(request_raw), replay_context=offline_replay_context,
                                )
                    finally:
                        os.chmod(output_directory_path, original_output_mode)

                    def context_with_unmapped_inventory_entry(
                        kind: str, child_path: Path,
                    ) -> dict[str, Any]:
                        capture_value = json.loads(original_capture_receipt)
                        capture_body = {key: value for key, value in capture_value.items()
                                        if key != "receipt_sha256"}
                        inventory_value = json.loads(original_inventory_raw)
                        inventory_body = {key: value for key, value in inventory_value.items()
                                          if key != "inventory_sha256"}
                        if kind == "file":
                            raw = child_path.read_bytes()
                            item = {
                                "path": str(child_path), "kind": "file", "uid": os.getuid(),
                                "mode": stat.S_IMODE(child_path.lstat().st_mode),
                                "size": len(raw), "raw_sha256": _sha(raw),
                            }
                        else:
                            item = {
                                "path": str(child_path), "kind": "directory", "uid": os.getuid(),
                                "mode": stat.S_IMODE(child_path.lstat().st_mode),
                                "size": None, "raw_sha256": None,
                            }
                        inventory_body["entries"].append(item)
                        inventory_body["entries"].sort(key=lambda value: value["path"])
                        inventory_value = {
                            **inventory_body,
                            "inventory_sha256": _sha(composition.canonical(inventory_body)),
                        }
                        inventory_raw = composition.canonical(inventory_value)
                        _write(capture_inventory_path, inventory_raw)
                        capture_body["tmpdir_inventory_pin"]["raw_sha256"] = _sha(inventory_raw)
                        capture_body["tmpdir_inventory_pin"]["inventory_sha256"] = inventory_value["inventory_sha256"]
                        capture_raw = composition.canonical({
                            **capture_body,
                            "receipt_sha256": _sha(composition.canonical(capture_body)),
                        })
                        _write(capture_receipt_path, capture_raw)
                        value = json.loads(capture_raw)
                        result = json.loads(json.dumps(offline_replay_context))
                        result["probe_capture_pin"] = {
                            "path": str(capture_receipt_path), "raw_sha256": _sha(capture_raw),
                            "receipt_sha256": value["receipt_sha256"],
                        }
                        return result

                    unmapped_inventory_file = tmp_path / "declared-but-unmapped.bin"
                    _write(unmapped_inventory_file, b"mapped inventory payload\n")
                    try:
                        file_map_context = context_with_unmapped_inventory_entry(
                            "file", unmapped_inventory_file,
                        )
                        with mock.patch.object(subprocess, "Popen",
                                               side_effect=AssertionError("offline omitted-file replay attempted Popen")), \
                             mock.patch.object(composition, "_captured_source_module",
                                               side_effect=AssertionError("omitted file reached module execution")), \
                             mock.patch.object(reader, "_captured_source5_module",
                                               side_effect=AssertionError("omitted file reached reader module execution")):
                            with self.assertRaisesRegex(
                                (reader.ValidationError, composition.CompositionError), "path map omits exact",
                            ):
                                composition.compose_calibrated_policy_v5_offline(
                                    request, _sha(request_raw), replay_context=file_map_context,
                                )
                    finally:
                        _write(capture_receipt_path, original_capture_receipt)
                        _write(capture_inventory_path, original_inventory_raw)
                        unmapped_inventory_file.unlink()

                    unmapped_inventory_directory = tmp_path / "declared-but-unmapped-directory"
                    unmapped_inventory_directory.mkdir(mode=0o700)
                    try:
                        directory_map_context = context_with_unmapped_inventory_entry(
                            "directory", unmapped_inventory_directory,
                        )
                        with mock.patch.object(subprocess, "Popen",
                                               side_effect=AssertionError("offline omitted-directory replay attempted Popen")), \
                             mock.patch.object(composition, "_captured_source_module",
                                               side_effect=AssertionError("omitted directory reached module execution")), \
                             mock.patch.object(reader, "_captured_source5_module",
                                               side_effect=AssertionError("omitted directory reached reader module execution")):
                            with self.assertRaisesRegex(
                                (reader.ValidationError, composition.CompositionError), "path map omits exact",
                            ):
                                reader.validate_calibrated_construction_probe_v2_offline(
                                    probe_pin, request["source_manifest"], bundle["artifact"], identity,
                                    capacity_floor_policy_id=capacity_floor_policy_id,
                                    replay_context=directory_map_context,
                                )
                    finally:
                        _write(capture_receipt_path, original_capture_receipt)
                        _write(capture_inventory_path, original_inventory_raw)
                        unmapped_inventory_directory.rmdir()

                    unexpected_tmp_child = tmp_path / "unmapped-child.bin"
                    _write(unexpected_tmp_child, b"unmapped child payload\n")
                    try:
                        with mock.patch.object(subprocess, "Popen",
                                               side_effect=AssertionError("offline unmapped TMPDIR attempted Popen")), \
                             mock.patch.object(composition, "_captured_source_module",
                                               side_effect=AssertionError("unmapped TMPDIR reached module execution")), \
                             mock.patch.object(reader, "_captured_source5_module",
                                               side_effect=AssertionError("unmapped TMPDIR reached reader module execution")):
                            with self.assertRaisesRegex(
                                composition.CompositionError, "path map omits exact ProbeV2 TMPDIR descendant",
                            ):
                                composition.compose_calibrated_policy_v5_offline(
                                    request, _sha(request_raw), replay_context=offline_replay_context,
                                )
                    finally:
                        unexpected_tmp_child.unlink()
                    stdout_capture_path = capture_receipt_path.parent / "stdout.bin"
                    captured_stdout = stdout_capture_path.read_bytes()
                    stdout_capture_path.unlink()
                    try:
                        with mock.patch.object(subprocess, "Popen", side_effect=AssertionError("offline replay attempted Popen")):
                            with self.assertRaises((reader.ValidationError, composition.CompositionError)):
                                composition.compose_calibrated_policy_v5_offline(
                                    request, _sha(request_raw), replay_context=offline_replay_context,
                                )
                    finally:
                        _write(stdout_capture_path, captured_stdout)
                    self.assertEqual(capture_receipt_path.read_bytes(), original_capture_receipt)
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
                ("capacity zero", lambda item: item.update({"disk.bytes_per_second": "0"}), 0, "application_bytes_per_second", "not a canonical positive integer"),
                ("missing relevant source", lambda item: item.update({"disk.bytes_per_second": "missing", "disk.units": "missing"}), None, "missing", "required application-byte capacity source is missing"),
            )
            for label, mutate, probe_rate, probe_units, expected_error in mutations:
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
                with self.assertRaisesRegex(reader.ValidationError, expected_error, msg=label):
                    reader.resolve_calibrated_feedback_policy_v5(
                        source_manifest, altered_probe, altered_pin, identity,
                        capacity_floor_policy_id=capacity_floor_policy_id,
                    )

            forged = json.loads(json.dumps(probe))
            forged["capacity_calibration"]["resolution"]["controls"]["disk"]["initial"] += 1
            with self.assertRaises(reader.ValidationError):
                reader.resolve_calibrated_feedback_policy_v5(
                    source_manifest, forged, bundle["artifact"], identity,
                    capacity_floor_policy_id=capacity_floor_policy_id,
                )
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
                        reader.resolve_calibrated_feedback_policy_v5(
                            source_manifest, malformed, bundle["artifact"], identity,
                            capacity_floor_policy_id=capacity_floor_policy_id,
                        )
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
