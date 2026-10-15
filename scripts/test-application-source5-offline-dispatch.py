#!/usr/bin/env python3
"""Contract and later genuine-capture entry points for Source5 offline replay."""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
DISPATCH_PATH = ROOT / "scripts/application-source5-offline-dispatch.py"
PRESSURE_PATH = ROOT / "scripts/application-pressure-pair.py"
CONTROLLER_PATH = ROOT / "scripts/application-source5-campaign.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def replay_genuine_job_fixture(
    request: object, captured_evidence: object, job_record_pin: object,
) -> dict:
    """Native fixture hook: pass a real closed store, never fabricated flags."""
    dispatcher = load_module("source5_offline_dispatch_fixture", DISPATCH_PATH)
    result = dispatcher.verify_source5_job_artifacts_offline(
        request, captured_evidence, job_record_pin,
    )
    if result["qualification_eligible"] is not False or result["execution_ready"] is not False:
        raise AssertionError("component replay attempted to set campaign readiness")
    if result["component_replayed"] is not True:
        raise AssertionError("the genuine component replay did not complete")
    return result


class OfflineDispatcherContractTests(unittest.TestCase):
    def test_captured_store_rejects_path_aliases_before_nested_reads(self) -> None:
        dispatcher = load_module("source5_offline_dispatch_alias_test", DISPATCH_PATH)
        captured = {
            "schema": dispatcher.CAPTURED_SCHEMA,
            "entries": [{
                "role": "evidence_index", "host_id": "host-a",
                "origin_path": "/capture/index.json",
                "local_path": "/capture/copied-index.json",
                "raw_sha256": hashlib.sha256(b"x").hexdigest(),
                "semantic_sha256": None, "byte_count": 1, "raw_bytes": b"x",
            }],
        }
        with self.assertRaises(dispatcher.Source5OfflineDispatchError):
            dispatcher._store_rows(captured)

    def test_captured_store_defers_hashing_until_exact_index_closure(self) -> None:
        dispatcher = load_module("source5_offline_dispatch_closure_test", DISPATCH_PATH)
        with tempfile.TemporaryDirectory(prefix="source5-dispatch-closure-") as directory:
            root = Path(directory).resolve(strict=True)
            index_path = root / "c-index.json"
            origin_path = root / "d-origin.json"
            extra_path = root / "a-unindexed-source.py"
            extra_raw = b"unindexed nested source bytes"
            extra_path.write_bytes(extra_raw)
            origin_raw = b"origin"
            origin_sha = hashlib.sha256(origin_raw).hexdigest()
            extra_sha = hashlib.sha256(extra_raw).hexdigest()
            for role_swap in (False, True):
                with self.subTest(role_swap=role_swap), extra_path.open("rb") as extra_stream:
                    indexed_extra = {
                        "role": "typed_source_file", "host_id": "host-a",
                        "origin_path": str(extra_path), "local_path": str(extra_path),
                        "raw_sha256": extra_sha, "semantic_sha256": None,
                        "byte_count": len(extra_raw),
                    }
                    index = {
                        "schema": dispatcher.INDEX_SCHEMA,
                        "campaign_id": "campaign", "host_id": "host-a",
                        "source_root": str(root / "source"),
                        "input_root": str(root / "input"),
                        "output_root": str(root / "output"),
                        "entries": [indexed_extra] if role_swap else [],
                    }
                    index["index_sha256"] = dispatcher._digest(
                        dispatcher._canonical(index),
                    )
                    index_raw = dispatcher._canonical(index)
                    index_sha = hashlib.sha256(index_raw).hexdigest()
                    source_row = {
                        **indexed_extra,
                        "role": ("normal_app_output" if role_swap else
                                 "typed_source_file"),
                        "raw_bytes": extra_stream,
                    }
                    entries = [
                        source_row,
                        {
                            "role": "evidence_index", "host_id": "host-a",
                            "origin_path": str(index_path), "local_path": str(index_path),
                            "raw_sha256": index_sha,
                            "semantic_sha256": index["index_sha256"],
                            "byte_count": len(index_raw), "raw_bytes": index_raw,
                        },
                        {
                            "role": "origin_receipt", "host_id": "host-a",
                            "origin_path": str(origin_path), "local_path": str(origin_path),
                            "raw_sha256": origin_sha, "semantic_sha256": "a" * 64,
                            "byte_count": len(origin_raw), "raw_bytes": origin_raw,
                        },
                    ]
                    entries.sort(key=lambda row: row["origin_path"])
                    captured = {"schema": dispatcher.CAPTURED_SCHEMA,
                                "entries": entries}
                    request = {
                        "schema": "allocatbelt.application-source5-host-journal-request.v1",
                        "scope": "prospective_exploration", "campaign_id": "campaign",
                        "host_id": "host-a", "source_root": str(root / "source"),
                        "input_root": str(root / "input"),
                        "output_root": str(root / "output"),
                        "execution_manifest": {
                            "path": str(root / "execution.json"),
                            "raw_sha256": "b" * 64, "semantic_sha256": "c" * 64,
                        },
                        "provenance": {}, "journal": {},
                        "origin_receipt": {
                            "path": str(origin_path), "raw_sha256": origin_sha,
                            "semantic_sha256": "a" * 64,
                        },
                        "evidence_index": {
                            "path": str(index_path), "raw_sha256": index_sha,
                            "semantic_sha256": index["index_sha256"],
                        },
                    }
                    nested_reads = []
                    original_chunks = dispatcher._entry_chunks

                    def tracked_chunks(value, count, label):
                        if str(extra_path) in label:
                            nested_reads.append(label)
                        yield from original_chunks(value, count, label)

                    expected = ("captured Source5 store differs from the exact evidence index closure"
                                if not role_swap else
                                "captured Source5 row differs from index metadata")
                    with patch.object(dispatcher, "_entry_chunks",
                                      side_effect=tracked_chunks):
                        rows = dispatcher._store_rows(captured)
                        with self.assertRaisesRegex(
                            dispatcher.Source5OfflineDispatchError, expected,
                        ):
                            dispatcher._index_and_manifest_preflight(request, rows)
                    self.assertEqual(nested_reads, [])

    def test_captured_raw_digest_is_still_checked_when_consumed(self) -> None:
        dispatcher = load_module("source5_offline_dispatch_deferred_hash_test", DISPATCH_PATH)
        captured = {
            "schema": dispatcher.CAPTURED_SCHEMA,
            "entries": [{
                "role": "evidence_index", "host_id": "host-a",
                "origin_path": "/capture/index.json",
                "local_path": "/capture/index.json",
                "raw_sha256": "0" * 64,
                "semantic_sha256": None, "byte_count": 1, "raw_bytes": b"x",
            }],
        }
        rows = dispatcher._store_rows(captured)
        with self.assertRaisesRegex(dispatcher.Source5OfflineDispatchError,
                                    "differ from their raw pin"):
            dispatcher._hash_entry(rows["/capture/index.json"])

    def test_unknown_role_is_rejected_before_component_dispatch(self) -> None:
        dispatcher = load_module("source5_offline_dispatch_role_test", DISPATCH_PATH)
        captured = {
            "schema": dispatcher.CAPTURED_SCHEMA,
            "entries": [{
                "role": "untyped_json", "host_id": "host-a",
                "origin_path": "/capture/item", "local_path": "/capture/item",
                "raw_sha256": hashlib.sha256(b"x").hexdigest(),
                "semantic_sha256": None, "byte_count": 1, "raw_bytes": b"x",
            }],
        }
        with self.assertRaises(dispatcher.Source5OfflineDispatchError):
            dispatcher._store_rows(captured)

    def test_pressure_api_keeps_legacy_call_fail_closed_and_adds_typed_context(self) -> None:
        tree = ast.parse(PRESSURE_PATH.read_bytes(), filename=str(PRESSURE_PATH))
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name == "validate_pressure_pair_artifacts_offline"]
        self.assertEqual(len(functions), 1)
        function = functions[0]
        self.assertEqual(function.args.kwonlyargs[-1].arg, "source5_journal_context")
        self.assertIsInstance(function.args.kw_defaults[-1], ast.Constant)
        self.assertIsNone(function.args.kw_defaults[-1].value)
        source = ast.unparse(function)
        self.assertIn("verified_source5_prerequisites is not None", source)
        self.assertIn("strict_result_sha256", source)
        self.assertIn("_verify_offline_normal_app_member", source)

    def test_dispatcher_is_a_typed_source5_execution_module(self) -> None:
        tree = ast.parse(CONTROLLER_PATH.read_bytes(), filename=str(CONTROLLER_PATH))
        text = ast.unparse(tree)
        self.assertIn("scripts/application-source5-offline-dispatch.py", text)
        dispatch_tree = ast.parse(DISPATCH_PATH.read_bytes(), filename=str(DISPATCH_PATH))
        names = {node.name for node in dispatch_tree.body
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        self.assertIn("verify_source5_job_artifacts_offline", names)
        self.assertIn("verify_source5_pressure_prerequisites_offline", names)
        self.assertNotIn("Popen", {node.id for node in ast.walk(dispatch_tree)
                                    if isinstance(node, ast.Name)})

    def test_full_source_role_closure_precedes_captured_module_loading(self) -> None:
        dispatch_tree = ast.parse(DISPATCH_PATH.read_bytes(), filename=str(DISPATCH_PATH))
        closure = next(node for node in dispatch_tree.body
                       if isinstance(node, ast.FunctionDef) and
                       node.name == "_validate_full_source_index_closure")
        closure_text = ast.unparse(closure)
        artifacts = next(node for node in dispatch_tree.body
                         if isinstance(node, ast.FunctionDef) and
                         node.name == "_source_manifest_artifacts")
        artifact_text = ast.unparse(artifacts)
        for token in ("typed_source_symlink", "_local_symlink_snapshot",
                      "_source_manifest_artifacts"):
            self.assertIn(token, closure_text)
        for token in ("normal_app_output", "source5_soak_artifact",
                      "analysis_artifact", "capacity_artifact"):
            self.assertIn(token, artifact_text)
        entry = next(node for node in dispatch_tree.body
                     if isinstance(node, ast.FunctionDef) and
                     node.name == "verify_source5_job_artifacts_offline")
        calls = [node for node in ast.walk(entry)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
        preflight_lines = [node.lineno for node in calls
                           if node.func.id == "_index_and_manifest_preflight"]
        module_lines = [node.lineno for node in calls
                        if node.func.id == "_load_pinned_module"]
        self.assertEqual(len(preflight_lines), 1)
        self.assertTrue(module_lines)
        self.assertLess(preflight_lines[0], min(module_lines))

    def test_normal_app_origin_pins_join_to_full_attested_process(self) -> None:
        tree = ast.parse(PRESSURE_PATH.read_bytes(), filename=str(PRESSURE_PATH))
        function = next(node for node in tree.body
                        if isinstance(node, ast.FunctionDef) and
                        node.name == "_verify_offline_normal_app_member")
        source = ast.unparse(function)
        for token in ("origin_attestation_pin", "origin_cleanup_pin",
                      "origin_supervision_pin", "process_identity == process",
                      "executable_device", "executable_inode"):
            self.assertIn(token, source)

    def test_both_offline_calibration_paths_use_captured_scope_replay(self) -> None:
        tree = ast.parse(PRESSURE_PATH.read_bytes(), filename=str(PRESSURE_PATH))
        functions = {node.name: ast.unparse(node) for node in tree.body
                     if isinstance(node, ast.FunctionDef)}
        self.assertIn("verify_calibration_scope_v2_offline",
                      functions["_verify_pressure_condition"])
        self.assertIn("offline_context", functions["_verify_pressure_recipe_host_inputs"])
        self.assertIn("_validate_calibration(",
                      functions["_verify_pressure_recipe_host_inputs"])

    def test_pressure_source_closure_precedes_dispatcher_and_reader_loading(self) -> None:
        tree = ast.parse(PRESSURE_PATH.read_bytes(), filename=str(PRESSURE_PATH))
        entry = next(node for node in tree.body
                     if isinstance(node, ast.FunctionDef) and
                     node.name == "validate_pressure_pair_artifacts_offline")
        calls = [node for node in ast.walk(entry)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
        preflight = [node.lineno for node in calls
                     if node.func.id == "_source5_preflight_capture_context"]
        module_load = [node.lineno for node in calls
                       if node.func.id == "_load_module"]
        source_load = [node.lineno for node in calls
                       if node.func.id == "_load_campaign_inputs"]
        self.assertEqual(len(preflight), 1)
        self.assertTrue(module_load and source_load)
        self.assertLess(preflight[0], min(module_load))
        self.assertLess(preflight[0], min(source_load))

    def test_top_level_path_preflight_does_not_parse_by_json_suffix(self) -> None:
        tree = ast.parse(PRESSURE_PATH.read_bytes(), filename=str(PRESSURE_PATH))
        function = next(node for node in tree.body
                        if isinstance(node, ast.FunctionDef) and
                        node.name == "_preflight_pair_json_path_closure")
        source = ast.unparse(function)
        self.assertNotIn("endswith", source)
        self.assertNotIn("read_json(", source)
        self.assertIn("_pair_absolute_paths", source)


if __name__ == "__main__":
    unittest.main()
