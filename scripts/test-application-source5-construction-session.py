#!/usr/bin/env python3
"""Static contract checks for the private SourceA construction boundary.

These checks inspect source syntax only. They do not import SourceA, create a
session, read captured evidence, or claim a positive 720-window replay.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
import tempfile
import types
import unittest
from unittest import mock
from pathlib import Path


SOURCE_PATH = Path(__file__).with_name("application-campaign-chronology.py")


class SourceAConstructionSessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SOURCE_PATH.read_text(encoding="utf-8")
        cls.tree = ast.parse(cls.source, filename=str(SOURCE_PATH))
        cls.functions = {
            node.name: node for node in cls.tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        cls.classes = {
            node.name: node for node in cls.tree.body
            if isinstance(node, ast.ClassDef)
        }

    def _function(self, name: str) -> ast.FunctionDef:
        value = self.functions.get(name)
        self.assertIsNotNone(value, f"missing SourceA function {name}")
        assert isinstance(value, ast.FunctionDef)
        return value

    def _class_method(self, class_name: str, method_name: str) -> ast.FunctionDef:
        node = self.classes.get(class_name)
        self.assertIsNotNone(node, f"missing SourceA class {class_name}")
        assert isinstance(node, ast.ClassDef)
        method = next((item for item in node.body
                       if isinstance(item, ast.FunctionDef) and
                       item.name == method_name), None)
        self.assertIsNotNone(method,
                             f"missing {class_name}.{method_name}")
        assert isinstance(method, ast.FunctionDef)
        return method

    def test_locked_constructor_accepts_only_data_and_existing_lock(self) -> None:
        function = self._function("construct_source5_prepared_inputs_locked")
        arguments = [argument.arg for argument in function.args.args]
        arguments.extend(argument.arg for argument in function.args.kwonlyargs)
        self.assertEqual(arguments, [
            "current_lock", "plan_pin", "spec_pin", "source_root",
            "input_root", "host_id", "observed_host_pin", "output_root",
            "construction_inputs", "ancestor_pins",
            "metadata_capture_manifest_pin", "metadata_capture_stage_root",
            "scratch_declaration", "timeout_declaration", "cancel_event",
        ])
        decorator_names = {
            ast.unparse(decorator) for decorator in function.decorator_list
        }
        self.assertIn("_serialize_locked_api", decorator_names)
        forbidden = {
            "artifact_reader", "captured_pilot_read_providers", "provider",
            "verifier", "completion", "execution_manifest",
            "width_contract_pin", "registered", "ready",
        }
        self.assertTrue(forbidden.isdisjoint(arguments))

    def test_constructor_does_not_seed_from_future_v5_state(self) -> None:
        function = self._function("construct_source5_prepared_inputs_locked")
        source = ast.get_source_segment(self.source, function) or ""
        for forbidden in (
            "state.source5_finished", "state['source5_finished']",
            "current_width_contract", "source5_execution_manifest_pin",
            "_prepared_input_replay_arguments",
        ):
            self.assertNotIn(forbidden, source)
        calls = {
            node.func.id for node in ast.walk(function)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertIn("_source5_verify_captured_prepared_ack_cohort_held", calls)
        self.assertIn("_source5_recorded_numeric_ancestor_context_held", calls)

    def test_initial_spec_control_is_guarded_before_inputprep_host_binding(self) -> None:
        function = self._function(
            "_source5_construction_bootstrap_lineage_inputs",
        )
        segment = ast.get_source_segment(self.source, function) or ""
        self.assertIn("_source5_construction_current_control_snapshot(", segment)
        self.assertIn("control_snapshots[-1]", segment)
        self.assertLess(
            segment.index("_source5_construction_current_control_snapshot("),
            segment.index("inputprep.verify_prepared_host_binding_metadata_v1("),
        )
        self.assertLess(
            segment.index("_source5_construction_recheck_file("),
            segment.index("inputprep.verify_prepared_host_binding_metadata_v1("),
        )

    def test_provider_keeps_exact_h3_lease_around_both_owner_replays(self) -> None:
        provider = self._class_method(
            "_Source5PreparedInputConstructionPilotProvider", "open_view",
        )
        segment = ast.get_source_segment(self.source, provider) or ""
        for required in (
            "session.h_client.open_view(ordinal)",
            "_source5_verify_recorded_numeric_ancestor_held",
            "yield inputprep_view", "objects_by_origin", "checkpoint_pin",
            "checkpoint_raw", "session.complete_window",
            "session.fail_window",
        ):
            self.assertIn(required, segment)
        self.assertIn("purpose == \"exploration\"", self.source)
        self.assertIn("use == \"capacity_pilot_export\"", self.source)

    def test_cursor_and_h_ledger_require_exact_720_windows(self) -> None:
        session = self.classes.get("_Source5PreparedInputConstructionSession")
        self.assertIsNotNone(session)
        assert isinstance(session, ast.ClassDef)
        source = ast.get_source_segment(self.source, session) or ""
        self.assertIn("self.global_cursor == 720", source)
        self.assertIn("self.provider_cursors[host] == 360", source)
        ledger = self._function("_source5_construction_verify_h_ledger")
        ledger_source = ast.get_source_segment(self.source, ledger) or ""
        self.assertIn("cursor == 720", ledger_source)
        self.assertIn("pending is None", ledger_source)

    def test_writer_is_called_only_after_source_argument_reconstruction(self) -> None:
        function = self._function("construct_source5_prepared_inputs_locked")
        source = ast.get_source_segment(self.source, function) or ""
        calls = {node.func.id for node in ast.walk(function)
                  if isinstance(node, ast.Call) and
                  isinstance(node.func, ast.Name)}
        self.assertIn(
            "_complete_prepared_inputs_closed_recorded_source_a_v1", source,
        )
        self.assertIn("_source5_construction_writer_inputs", calls)
        self.assertIn("_source5_construction_readback_inputs", calls)

    def test_registration_stub_remains_unconditionally_refused(self) -> None:
        function = self._function(
            "register_source5_prepared_exploration_capacity_locked",
        )
        segment = ast.get_source_segment(self.source, function) or ""
        self.assertIn("_source5_require_authenticated_pilot_provider_cohort()",
                      segment)
        self.assertIn("Source5 V5 registration is disabled", self.source)


class SourceAConstructionBoundaryBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        module_name = "_sourcea_construction_session_test_target"
        spec = importlib.util.spec_from_file_location(module_name, SOURCE_PATH)
        if spec is None or spec.loader is None:
            raise RuntimeError("could not create a SourceA chronology test module")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        cls.target = module

    def _reader(self, root: Path, capture: object,
                capture_keys: set[tuple[str, str]]):
        return self.target._Source5PreparedInputConstructionArtifactReader(
            capture, self.target.time.monotonic_ns() + 60_000_000_000, None,
            capture_pin_keys=capture_keys, input_root=root,
        )

    def _session(self):
        planner = types.SimpleNamespace()
        modules = {"planner": planner}
        return self.target._Source5PreparedInputConstructionSession(
            self.target._SOURCE5_PREPARED_INPUT_CONSTRUCTION_SESSION_SECRET,
            object(), {}, {}, {"head_sha256": "0" * 64, "record_count": 0},
            None, [], [], [], None, None, modules, ["host-a", "host-b"],
            self.target.time.monotonic_ns() + 60_000_000_000, None,
        )

    def test_resident_reader_requires_explicit_pin_and_enforces_byte_cap(self) -> None:
        class NoCapture:
            def read(self, pin, maximum):
                raise AssertionError("resident input unexpectedly used old capture")

        with tempfile.TemporaryDirectory(prefix="sourcea-reader-") as directory:
            root = Path(directory)
            path = root / "current-input.json"
            raw = b"current input bytes"
            path.write_bytes(raw)
            pin = {"path": str(path),
                   "raw_sha256": self.target.sha256_bytes(raw)}
            reader = self._reader(root, NoCapture(), set())
            self.assertIsNotNone(self.target._source5_construction_allow_resident_pin(
                reader, root, pin, len(raw), "test current resident input",
            ))
            self.assertEqual(reader(pin, len(raw)), raw)
            with self.assertRaises(self.target.ChronologyError):
                reader(pin, len(raw) - 1)
            unlisted_path = root / "ambient-input.json"
            unlisted_raw = b"present but not allowlisted"
            unlisted_path.write_bytes(unlisted_raw)
            unlisted_pin = {"path": str(unlisted_path),
                            "raw_sha256": self.target.sha256_bytes(unlisted_raw)}
            with self.assertRaises(self.target.ChronologyError):
                reader(unlisted_pin, len(unlisted_raw))
            with tempfile.TemporaryDirectory(prefix="sourcea-external-oracle-") as outside:
                external = Path(outside) / "oracle.tsv"
                external_raw = b"external but snapshot-only oracle"
                external.write_bytes(external_raw)
                external_pin = {
                    "path": str(external),
                    "raw_sha256": self.target.sha256_bytes(external_raw),
                }
                with self.assertRaises(self.target.ChronologyError):
                    reader(external_pin, len(external_raw))

    def test_closed_capture_has_priority_without_origin_fallback(self) -> None:
        class Capture:
            def __init__(self, raw):
                self.raw = raw
                self.calls = []

            def read(self, pin, maximum):
                self.calls.append((dict(pin), maximum))
                return self.raw

        with tempfile.TemporaryDirectory(prefix="sourcea-capture-priority-") as directory:
            root = Path(directory)
            absent_origin = root / "historical-origin.json"
            raw = b"closed capture bytes"
            pin = {"path": str(absent_origin),
                   "raw_sha256": self.target.sha256_bytes(raw)}
            key = (pin["path"], pin["raw_sha256"])
            capture = Capture(raw)
            reader = self._reader(root, capture, {key})
            self.assertIsNone(self.target._source5_construction_allow_resident_pin(
                reader, root, pin, len(raw), "test closed historical origin",
            ))
            self.assertEqual(reader.resident_pins, {})
            self.assertEqual(reader(pin, len(raw)), raw)
            self.assertEqual(capture.calls, [(pin, len(raw))])
            with self.assertRaises(self.target.ChronologyError):
                reader(pin, len(raw) - 1)

    def test_external_oracle_snapshot_detects_postvalidation_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sourcea-oracle-snapshot-") as directory:
            root = Path(directory)
            path = root / "oracle.tsv"
            original = b"oracle payload v1\n"
            path.write_bytes(original)
            snapshot = self.target._source5_construction_snapshot_file(
                str(path), self.target.sha256_bytes(original), 1024,
                "test checked oracle payload",
            )
            path.write_bytes(b"oracle payload v2\n")
            with self.assertRaises(self.target.ChronologyError):
                self.target._source5_construction_recheck_file(
                    snapshot, "test mutated oracle payload",
                )

    def test_initial_spec_control_requires_resident_pin_and_mutation_guard(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sourcea-control-root-") as directory:
            root = Path(directory)
            with tempfile.TemporaryDirectory(prefix="sourcea-control-outside-") as outside:
                external = Path(outside) / "initial-spec.json"
                external_raw = b"must not read outside current input root"
                external.write_bytes(external_raw)
                external_pin = {
                    "path": str(external),
                    "raw_sha256": self.target.sha256_bytes(external_raw),
                    "semantic_sha256": "a" * 64,
                }
                with mock.patch.object(
                    self.target, "_source5_construction_snapshot_file",
                    side_effect=AssertionError("outside bytes were opened"),
                ):
                    with self.assertRaises(self.target.ChronologyError):
                        self.target._source5_construction_current_control_snapshot(
                            root, external_pin, 1024,
                            "test old initial Spec control",
                        )

            missing = root / "missing-initial-spec.json"
            missing_pin = {
                "path": str(missing), "raw_sha256": "b" * 64,
                "semantic_sha256": "c" * 64,
            }
            with self.assertRaises(self.target.ChronologyError):
                self.target._source5_construction_current_control_snapshot(
                    root, missing_pin, 1024,
                    "test absent initial Spec control",
                )

            current = root / "initial-spec.json"
            original = b"retained initial Spec control bytes"
            current.write_bytes(original)
            current_pin = {
                "path": str(current),
                "raw_sha256": self.target.sha256_bytes(original),
                "semantic_sha256": "d" * 64,
            }
            snapshot = self.target._source5_construction_current_control_snapshot(
                root, current_pin, 1024,
                "test retained initial Spec control",
            )
            self.assertEqual(snapshot["raw_sha256"], current_pin["raw_sha256"])
            current.write_bytes(b"mutated initial Spec control bytes")
            with self.assertRaises(self.target.ChronologyError):
                self.target._source5_construction_recheck_file(
                    snapshot, "test mutated initial Spec control",
                )

    def test_bootstrap_rejects_missing_or_external_control_before_ip_or_capture_read(self) -> None:
        class HeaderReader:
            def __init__(self, pin, raw):
                self.pin = pin
                self.raw = raw
                self.calls = []

            def __call__(self, pin, maximum):
                self.calls.append(dict(pin))
                if pin == self.pin:
                    return self.raw
                raise AssertionError("bootstrap attempted a non-header capture read")

        with tempfile.TemporaryDirectory(prefix="sourcea-bootstrap-input-") as directory:
            root = Path(directory)
            with tempfile.TemporaryDirectory(prefix="sourcea-bootstrap-outside-") as outside:
                outside_path = Path(outside) / "initial-spec.json"
                outside_path.write_bytes(b"outside control bytes")
                cases = [
                    (outside_path, self.target.sha256_bytes(b"outside control bytes")),
                    (root / "missing-initial-spec.json", "e" * 64),
                ]
                for spec_path, spec_sha256 in cases:
                    header_path = str(root / "captured-header.json")
                    header_raw = self.target.canonical_bytes({
                        "campaign_id": "test-campaign",
                        "host_id": "host-a",
                        "scope": "initial_only",
                        "qualification_eligible": False,
                        "initial": {
                            "spec_pin": {
                                "path": str(spec_path),
                                "raw_sha256": spec_sha256,
                                "semantic_sha256": "f" * 64,
                            },
                            "plan_pin": {
                                "path": str(root / "old-plan.json"),
                                "raw_sha256": "1" * 64,
                                "semantic_sha256": "2" * 64,
                            },
                        },
                    })
                    header_pin = {
                        "path": header_path,
                        "raw_sha256": self.target.sha256_bytes(header_raw),
                    }
                    reader = HeaderReader(header_pin, header_raw)
                    binder_calls = []
                    inputprep = types.SimpleNamespace(
                        MAX_REQUEST_BYTES=1024,
                        verify_prepared_host_binding_metadata_v1=(
                            lambda *args: binder_calls.append(args)
                        ),
                    )
                    modules = {
                        "input_preparation": inputprep,
                        "controller": types.SimpleNamespace(),
                    }
                    ancestors = {"host-a": {"bridge_header": header_pin,
                                             "record_index": {
                                                 "path": str(root / "index.json"),
                                                 "raw_sha256": "3" * 64,
                                             }}}
                    if spec_path == outside_path:
                        with mock.patch.object(
                            self.target, "_source5_construction_snapshot_file",
                            side_effect=AssertionError("outside bytes were read"),
                        ):
                            with self.assertRaises(self.target.ChronologyError):
                                self.target._source5_construction_bootstrap_lineage_inputs(
                                    reader, {"input_root": root,
                                             "campaign_id": "test-campaign"},
                                    {}, ancestors, {}, modules, ["host-a"],
                                )
                    else:
                        with self.assertRaises(self.target.ChronologyError):
                            self.target._source5_construction_bootstrap_lineage_inputs(
                                reader, {"input_root": root,
                                         "campaign_id": "test-campaign"},
                                {}, ancestors, {}, modules, ["host-a"],
                            )
                    self.assertEqual(reader.calls, [header_pin])
                    self.assertEqual(binder_calls, [])

    def test_provider_rejects_second_host_before_global_cursor(self) -> None:
        session = self._session()
        provider = self.target._Source5PreparedInputConstructionPilotProvider(
            session, "host-b",
        )
        job = {"host_id": "host-b", "phase": "exploration",
               "run_id": "second-host-first", "ordinal": 1}
        with self.assertRaises(self.target.ChronologyError):
            session.begin_window(provider, job, "exploration",
                                 "capacity_pilot_export")
        self.assertTrue(session.failed)
        self.assertEqual(session.global_cursor, 0)
        self.assertFalse(session.active)
        self.assertFalse(session.lease_lock.locked())

    def test_provider_rejects_a_job_other_than_the_exact_next_row(self) -> None:
        session = self._session()
        expected = {"host_id": "host-a", "phase": "exploration",
                    "run_id": "next-window", "ordinal": 1}
        row = ({"job": expected}, {"job": expected}, {}, {}, {})
        session.numeric_context = {"rows_by_host": {
            "host-a": [row] * 360, "host-b": [],
        }}
        provider = self.target._Source5PreparedInputConstructionPilotProvider(
            session, "host-a",
        )
        supplied = {**expected, "run_id": "later-window"}
        with self.assertRaises(self.target.ChronologyError):
            session.begin_window(provider, supplied, "exploration",
                                 "capacity_pilot_export")
        self.assertTrue(session.failed)
        self.assertEqual(session.global_cursor, 0)
        self.assertEqual(session.provider_cursors["host-a"], 0)
        self.assertFalse(session.active)
        self.assertFalse(session.lease_lock.locked())

    def test_provider_latches_an_overlapping_lease_attempt(self) -> None:
        session = self._session()
        provider = self.target._Source5PreparedInputConstructionPilotProvider(
            session, "host-a",
        )
        session.lease_lock.acquire()
        job = {"host_id": "host-a", "phase": "exploration",
               "run_id": "first-window", "ordinal": 1}
        try:
            with self.assertRaises(self.target.ChronologyError):
                session.begin_window(provider, job, "exploration",
                                     "capacity_pilot_export")
            self.assertTrue(session.failed)
            self.assertEqual(session.global_cursor, 0)
        finally:
            session.lease_lock.release()

    def test_provider_latches_owner_error_even_if_h_suppresses_it(self) -> None:
        class SuppressingLease:
            def __init__(self, yielded):
                self.yielded = yielded
                self.exit_error = None

            def __enter__(self):
                return self.yielded

            def __exit__(self, error_type, error, traceback):
                self.exit_error = error
                return error is not None

        class HClient:
            def __init__(self, lease):
                self.lease = lease

            def open_view(self, ordinal):
                self.ordinal = ordinal
                return self.lease

        session = self._session()
        job = {"host_id": "host-a", "phase": "exploration",
               "run_id": "first-window", "ordinal": 1}
        row = ({"job": job}, {"job": job}, {}, {}, {})
        session.numeric_context = {"rows_by_host": {
            "host-a": [row] * 360, "host-b": [],
        }}
        session.plan = {"window_index": [{
            "chunk_ordinal": 0, "owner_host_id": "host-a", "job_index": 0,
        }]}
        session.plan_pin = {}
        session.chunks = [{}]
        session.plan_module.validate_prepared_input_construction_read_window_v1 = (
            lambda plan, pin, chunk, ordinal: {
                "owner_host_id": "host-a", "job_index": 0, "job": job,
            }
        )
        lease = SuppressingLease({
            "payload_view": {}, "objects_by_origin": {}, "stage_root": "/tmp",
        })
        session.h_client = HClient(lease)
        provider = self.target._Source5PreparedInputConstructionPilotProvider(
            session, "host-a",
        )
        with mock.patch.object(self.target, "_source5_construction_check_live"):
            with mock.patch.object(
                self.target, "_source5_verify_recorded_numeric_ancestor_held",
                side_effect=ValueError("injected owner replay failure"),
            ):
                with self.assertRaisesRegex(ValueError,
                                            "injected owner replay failure"):
                    with provider.open_view(
                        job, "exploration", use="capacity_pilot_export",
                    ):
                        self.fail("provider yielded after an owner replay error")
        self.assertIsNotNone(lease.exit_error)
        self.assertTrue(session.failed)
        self.assertEqual(session.global_cursor, 0)
        self.assertEqual(session.provider_cursors["host-a"], 0)
        self.assertFalse(session.active)
        self.assertFalse(session.lease_lock.locked())
        with self.assertRaises(self.target.ChronologyError):
            provider.require_complete()


if __name__ == "__main__":
    unittest.main()
