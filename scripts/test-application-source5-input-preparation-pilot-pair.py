#!/usr/bin/env python3
"""Focused pure-data tests for Source5 capacity-pilot pair projection."""
from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import inspect
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


INPUTPREP_PATH = Path(__file__).with_name("application-source5-input-preparation.py")


def load_inputprep():
    spec = importlib.util.spec_from_file_location(
        "source5_inputprep_pilot_pair_data_contract", INPUTPREP_PATH,
    )
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {INPUTPREP_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class Source5InputPrepPilotPairData(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_inputprep()
        cls.source = INPUTPREP_PATH.read_text()
        cls.tree = ast.parse(cls.source, filename=str(INPUTPREP_PATH))
        cls.functions = {
            node.name: node for node in cls.tree.body
            if isinstance(node, ast.FunctionDef)
        }

    def _fixture(self):
        job = {
            "run_id": "run-capacity-pair-001",
            "ordinal": 3,
            "allocator": "allocatbelt",
        }
        receipt = {
            "run_id": job["run_id"],
            "host_id": "agent-test-host",
            "status": "valid_pair",
            "process_metrics": [],
            "process_rows": [],
        }
        for executor in ("bounded", "tokio"):
            receipt["process_metrics"].append({
                "executor": executor,
                "allocator": "allocatbelt",
                "mode": "capacity",
                "completed_on_time": 7,
                "completed_late": 1,
            })
            receipt["process_rows"].append({
                "executor": executor,
                "allocator": "allocatbelt",
                "mode": "capacity",
                "completed_on_time": 7,
                "completed_late": 1,
                "attempted": 8,
                "admitted": 8,
                "rejected_full": 0,
                "rejected_resource": 0,
            })
        kwargs = {
            "overlay_pin": {
                "path": "/closed/overlay.json", "sha256": "1" * 64,
            },
            "receipt_pin": {
                "path": "/closed/receipt.json", "sha256": "2" * 64,
            },
            "overlay_raw_sha256": "1" * 64,
            "receipt_raw_sha256": "2" * 64,
            "verified_receipt_sha256": "3" * 64,
            "host_verification_pin": {
                "path": "/closed/host-verification.json",
                "raw_sha256": "4" * 64,
                "host_verification_sha256": "5" * 64,
            },
            "prepared_host_binding_sha256": "6" * 64,
        }
        return job, receipt, "agent-test-host", kwargs

    def _project(self, job, receipt, host_id, kwargs, pair_index=0):
        return self.module._capacity_pilot_pair_data_v1(
            job, receipt, host_id, pair_index, **kwargs,
        )

    def test_original_pair_projection_and_seven_field_raw_hash(self) -> None:
        job, receipt, host_id, kwargs = self._fixture()
        pair = self._project(job, receipt, host_id, kwargs)
        hash_inputs = {
            "overlay_raw_sha256": kwargs["overlay_raw_sha256"],
            "receipt_raw_sha256": kwargs["receipt_raw_sha256"],
            "verified_receipt_sha256": kwargs["verified_receipt_sha256"],
            "host_verification_raw_sha256": kwargs["host_verification_pin"]["raw_sha256"],
            "host_verification_sha256": kwargs["host_verification_pin"]["host_verification_sha256"],
            "prepared_host_binding_sha256": kwargs["prepared_host_binding_sha256"],
            "run_id": job["run_id"],
        }
        expected = hashlib.sha256(self.module._canonical(hash_inputs)).hexdigest()
        self.assertEqual(pair["raw_pair_sha256"], expected)
        self.assertEqual(set(pair), {
            "ordinal", "bounded_status", "tokio_status", "raw_pair_sha256",
            "bounded_on_time", "bounded_late", "bounded_attempted",
            "bounded_admitted", "bounded_rejected", "tokio_on_time",
            "tokio_late", "tokio_attempted", "tokio_admitted",
            "tokio_rejected",
        })
        self.assertEqual(pair["ordinal"], 3)
        self.assertEqual((pair["bounded_on_time"], pair["bounded_late"],
                          pair["bounded_attempted"], pair["bounded_admitted"],
                          pair["bounded_rejected"]), (7, 1, 8, 8, 0))
        self.assertNotIn("qualification_eligible", pair)
        self.assertNotIn("verified", pair)

        for field in (
            "overlay_raw_sha256", "receipt_raw_sha256",
            "verified_receipt_sha256", "prepared_host_binding_sha256",
        ):
            changed = copy.deepcopy(kwargs)
            changed[field] = "f" * 64
            with self.subTest(hash_field=field):
                self.assertNotEqual(
                    self._project(job, receipt, host_id, changed)["raw_pair_sha256"],
                    expected,
                )
        for field in ("raw_sha256", "host_verification_sha256"):
            changed = copy.deepcopy(kwargs)
            changed["host_verification_pin"][field] = "f" * 64
            with self.subTest(hash_field=field):
                self.assertNotEqual(
                    self._project(job, receipt, host_id, changed)["raw_pair_sha256"],
                    expected,
                )
        changed_job = copy.deepcopy(job)
        changed_job["run_id"] = "run-capacity-pair-002"
        changed_receipt = copy.deepcopy(receipt)
        changed_receipt["run_id"] = changed_job["run_id"]
        self.assertNotEqual(
            self._project(changed_job, changed_receipt, host_id, kwargs)["raw_pair_sha256"],
            expected,
        )

    def test_captured_raw_digests_survive_pin_mutation_and_are_passed_by_caller(self) -> None:
        job, receipt, host_id, kwargs = self._fixture()
        saved_overlay_raw_sha = kwargs["overlay_raw_sha256"]
        saved_receipt_raw_sha = kwargs["receipt_raw_sha256"]
        kwargs["overlay_pin"]["sha256"] = "f" * 64
        kwargs["receipt_pin"]["sha256"] = "e" * 64
        pair = self._project(job, receipt, host_id, kwargs)
        hash_inputs = {
            "overlay_raw_sha256": saved_overlay_raw_sha,
            "receipt_raw_sha256": saved_receipt_raw_sha,
            "verified_receipt_sha256": kwargs["verified_receipt_sha256"],
            "host_verification_raw_sha256": kwargs["host_verification_pin"]["raw_sha256"],
            "host_verification_sha256": kwargs["host_verification_pin"]["host_verification_sha256"],
            "prepared_host_binding_sha256": kwargs["prepared_host_binding_sha256"],
            "run_id": job["run_id"],
        }
        self.assertEqual(
            pair["raw_pair_sha256"],
            hashlib.sha256(self.module._canonical(hash_inputs)).hexdigest(),
        )

        exporter = self.functions["_export_capacity_pilot_impl"]
        projection_call = next(
            node for node in ast.walk(exporter)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and
            node.func.id == "_capacity_pilot_pair_data_v1"
        )
        keyword_values = {item.arg: item.value for item in projection_call.keywords}
        for keyword, expected_name in (
            ("overlay_raw_sha256", "overlay_raw_sha"),
            ("receipt_raw_sha256", "receipt_raw_sha"),
        ):
            self.assertIsInstance(keyword_values[keyword], ast.Name)
            self.assertEqual(keyword_values[keyword].id, expected_name)

    def test_allocator_and_mode_mismatches_are_rejected(self) -> None:
        for collection, index, field, value in (
            ("process_rows", 0, "allocator", "other-allocator"),
            ("process_rows", 1, "mode", "throughput"),
            ("process_metrics", 0, "allocator", "other-allocator"),
            ("process_metrics", 1, "mode", "throughput"),
        ):
            job, receipt, host_id, kwargs = self._fixture()
            receipt[collection][index][field] = value
            with self.subTest(collection=collection, field=field):
                with self.assertRaisesRegex(
                        self.module.PreparationError,
                        "APP allocator/mode differs"):
                    self._project(job, receipt, host_id, kwargs)

    def test_accounting_and_metric_mismatches_are_rejected(self) -> None:
        cases = (
            ("process_rows", 0, "admitted", 9),
            ("process_rows", 1, "attempted", 9),
            ("process_rows", 0, "rejected_full", 1),
            ("process_metrics", 1, "completed_late", 2),
        )
        for collection, index, field, value in cases:
            job, receipt, host_id, kwargs = self._fixture()
            receipt[collection][index][field] = value
            with self.subTest(collection=collection, field=field):
                with self.assertRaisesRegex(
                        self.module.PreparationError,
                        "capacity accounting does not reconcile"):
                    self._project(job, receipt, host_id, kwargs)

    def test_duplicate_executor_rows_or_metrics_are_rejected(self) -> None:
        for collection in ("process_rows", "process_metrics"):
            job, receipt, host_id, kwargs = self._fixture()
            receipt[collection][1]["executor"] = "bounded"
            with self.subTest(collection=collection):
                with self.assertRaisesRegex(
                        self.module.PreparationError,
                        "not one bounded/Tokio pair"):
                    self._project(job, receipt, host_id, kwargs)

    def test_pure_projection_uses_only_data_and_never_reads_origins(self) -> None:
        job, receipt, host_id, kwargs = self._fixture()
        helper = self.functions["_capacity_pilot_pair_data_v1"]
        parameters = list(inspect.signature(
            self.module._capacity_pilot_pair_data_v1,
        ).parameters)
        self.assertEqual(parameters, [
            "job", "receipt_value", "host_id", "pair_index",
            "overlay_pin", "receipt_pin", "overlay_raw_sha256",
            "receipt_raw_sha256", "verified_receipt_sha256",
            "host_verification_pin",
            "prepared_host_binding_sha256",
        ])
        self.assertFalse(any(
            "provider" in name or "proof" in name or "skip" in name or
            "callback" in name or "reader" in name
            for name in parameters
        ))
        calls = {
            node.func.id if isinstance(node.func, ast.Name) else
            node.func.attr if isinstance(node.func, ast.Attribute) else ""
            for node in ast.walk(helper) if isinstance(node, ast.Call)
        }
        self.assertTrue(calls <= {
            "_require", "_exact", "_row_uint", "_sha256", "_canonical",
            "set", "len", "get", "type",
        })
        with patch.object(
                self.module, "_read_stable",
                side_effect=AssertionError("pure pilot projection read a path"),
        ), patch.object(
                self.module, "_read_capacity_pilot_envelope",
                side_effect=AssertionError("pure pilot projection opened an envelope"),
        ), patch.object(
                self.module.Path, "open",
                side_effect=AssertionError("pure pilot projection opened a path"),
        ):
            pair = self._project(job, receipt, host_id, kwargs)
        self.assertEqual(pair["raw_pair_sha256"],
                         hashlib.sha256(self.module._canonical({
                             "overlay_raw_sha256": kwargs["overlay_raw_sha256"],
                             "receipt_raw_sha256": kwargs["receipt_raw_sha256"],
                             "verified_receipt_sha256": kwargs["verified_receipt_sha256"],
                             "host_verification_raw_sha256": kwargs["host_verification_pin"]["raw_sha256"],
                             "host_verification_sha256": kwargs["host_verification_pin"]["host_verification_sha256"],
                             "prepared_host_binding_sha256": kwargs["prepared_host_binding_sha256"],
                             "run_id": job["run_id"],
                         })).hexdigest())


if __name__ == "__main__":
    raise SystemExit(unittest.main())
