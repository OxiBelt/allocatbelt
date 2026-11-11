#!/usr/bin/env python3
"""Focused contracts for private held Source5 kernels and bounded ACK waits."""
from __future__ import annotations

import ast
import importlib.util
import inspect
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

_SOURCE5_CHRONOLOGY_SOURCE_PATH = "scripts/application-campaign-chronology.py"


CONTROLLER_PATH = Path(__file__).with_name("application-source5-campaign.py")


def load_controller():
    spec = importlib.util.spec_from_file_location(
        "source5_d1_held_kernel_contract", CONTROLLER_PATH,
    )
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {CONTROLLER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class Source5OwnedHeldKernelContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_controller()
        cls.source = CONTROLLER_PATH.read_text()
        cls.tree = ast.parse(cls.source, filename=str(CONTROLLER_PATH))
        cls.functions = {
            node.name: node for node in cls.tree.body
            if isinstance(node, ast.FunctionDef)
        }

    def _calls(self, name: str) -> set[str]:
        node = self.functions[name]
        result = set()
        for item in ast.walk(node):
            if not isinstance(item, ast.Call):
                continue
            if isinstance(item.func, ast.Name):
                result.add(item.func.id)
            elif isinstance(item.func, ast.Attribute):
                result.add(item.func.attr)
        return result

    def test_bounded_ack_wait_has_only_fixed_data_and_cancel_inputs(self) -> None:
        wait = self.module._source5_wait_for_ack_bundle_owned_bounded_held
        self.assertEqual(
            list(inspect.signature(wait).parameters),
            ["path", "maximum_bytes", "deadline_ns", "cancel_event"],
        )
        self.assertFalse(any(
            name in inspect.signature(wait).parameters
            for name in ("provider", "callback", "scope", "ready", "verified")
        ))

    def test_bounded_ack_wait_reads_exact_private_bundle(self) -> None:
        payload = b"signed-ack-bundle"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "response.tar"
            path.write_bytes(payload)
            path.chmod(0o600)
            raw, pin = self.module._source5_wait_for_ack_bundle_owned_bounded_held(
                path, len(payload),
                deadline_ns=time.monotonic_ns() + 5_000_000_000,
                cancel_event=None,
            )
        self.assertEqual(raw, payload)
        self.assertEqual(set(pin), {"path", "raw_sha256", "byte_count"})
        self.assertEqual(pin["path"], str(path))
        self.assertEqual(pin["byte_count"], len(payload))
        self.assertEqual(pin["raw_sha256"], self.module.sha256(payload))

    def test_bounded_ack_wait_rejects_cancellation_before_path_access(self) -> None:
        cancel = threading.Event()
        cancel.set()
        path = Path("/not-opened-by-the-cancelled-owned-ack-wait")
        with patch.object(
                self.module.Path, "lstat",
                side_effect=AssertionError("cancelled wait touched receiver path")):
            with self.assertRaises(self.module.Source5CampaignError):
                self.module._source5_wait_for_ack_bundle_owned_bounded_held(
                    path, 1024,
                    deadline_ns=time.monotonic_ns() + 5_000_000_000,
                    cancel_event=cancel,
                )

    def test_bounded_ack_wait_sleeps_only_to_its_poll_or_deadline_bound(self) -> None:
        cancel = threading.Event()
        path = Path("/bounded-owned-ack-receiver-not-yet-published")
        waits = []

        def bounded_wait(event, timeout):
            waits.append(timeout)
            event.set()
            return True

        with patch.object(self.module.Path, "lstat", side_effect=FileNotFoundError), \
                patch.object(self.module.threading.Event, "wait", new=bounded_wait):
            with self.assertRaises(self.module.Source5CampaignError):
                self.module._source5_wait_for_ack_bundle_owned_bounded_held(
                    path, 1024,
                    deadline_ns=time.monotonic_ns() + 5_000_000_000,
                    cancel_event=cancel,
                )
        self.assertEqual(len(waits), 1)
        self.assertGreater(waits[0], 0)
        self.assertLessEqual(waits[0], 0.25)

    def test_bounded_ack_wait_checks_expiry_before_path_access(self) -> None:
        path = Path("/not-opened-by-the-expired-owned-ack-wait")
        with patch.object(
                self.module.Path, "lstat",
                side_effect=AssertionError("expired wait touched receiver path")):
            with self.assertRaises(self.module.Source5CampaignError):
                self.module._source5_wait_for_ack_bundle_owned_bounded_held(
                    path, 1024, deadline_ns=time.monotonic_ns(),
                    cancel_event=None,
                )

    def test_legacy_public_phase_signatures_remain_unchanged(self) -> None:
        expected = {
            "run_fixed_phase": ["context", "phase"],
            "run_pressure_phase": ["context", "materials_index"],
            "run_soak_phase": ["context", "materials_index"],
            "analyze_phase": ["context", "phase"],
            "_source5_refresh_phase_prerequisite_gates_locked": [
                "context", "lock", "phase",
            ],
        }
        for name, parameters in expected.items():
            function = getattr(self.module, name)
            self.assertEqual(list(inspect.signature(function).parameters), parameters)
        public_load = inspect.signature(self.module.load_context)
        self.assertEqual(list(public_load.parameters), [
            "manifest_path", "host_id", "manifest_value", "manifest_raw_sha256",
            "allow_preparatory_core", "lineage_artifact_reader",
        ])
        self.assertEqual(public_load.parameters["manifest_value"].default, None)
        self.assertEqual(public_load.parameters["manifest_raw_sha256"].default, None)
        self.assertIs(public_load.parameters["allow_preparatory_core"].default, False)
        self.assertEqual(public_load.parameters["lineage_artifact_reader"].default, None)

    def test_failed_context_load_closes_every_tracked_module(self) -> None:
        primary_error = RuntimeError("selected H context load failed")
        created = []
        closed = []
        original_close = self.module._source5_h_close_modules_independently

        def fail_after_loading(*_args, **_kwargs):
            created.append(self.module._load_module(
                b"loaded = True", Path("/synthetic/c3a-first.py"), "c3a_first",
            ))
            created.append(self.module._load_module(
                b"loaded = False", Path("/synthetic/c3a-second.py"), "c3a_second",
            ))
            raise primary_error

        def close_every_module(modules):
            modules = list(modules)
            closed.extend(modules)
            return original_close(modules)

        try:
            with patch.object(self.module, "_load_context_impl",
                              side_effect=fail_after_loading), \
                    patch.object(self.module, "_source5_h_close_modules_independently",
                                 side_effect=close_every_module):
                with self.assertRaises(RuntimeError) as caught:
                    self.module._source5_context_load_transaction(
                        Path("/synthetic/manifest.json"), "host-a",
                    )
            self.assertIs(caught.exception, primary_error)
            self.assertEqual(closed, created)
            self.assertTrue(all(sys.modules.get(module.__name__) is not module
                                for module in created))
        finally:
            for module in created:
                if sys.modules.get(module.__name__) is module:
                    sys.modules.pop(module.__name__, None)

    def test_private_context_modules_use_isolated_registry_names(self) -> None:
        names = []
        for index in range(2):
            created = []

            def build_private_module(*_args, **_kwargs):
                module = self.module._load_module(
                    b"loaded = True", Path(f"/synthetic/c3a-scope-{index}.py"),
                    "c3a_scope_shared_source",
                )
                created.append(module)
                return SimpleNamespace()

            try:
                with patch.object(self.module, "_load_context_impl",
                                  side_effect=build_private_module):
                    self.module._source5_context_load_transaction(
                        Path("/synthetic/manifest.json"), "host-a",
                        active_sourcea_module=self.module,
                        active_sourcea_lock=object(),
                    )
                self.assertEqual(len(created), 1)
                names.append(created[0].__name__)
            finally:
                self.module._source5_h_close_modules_independently(created)
        self.assertNotEqual(names[0], names[1])
        self.assertIn("source5ctx_", names[0])

    def test_private_context_constructor_injects_the_active_sourcea_module(self) -> None:
        sourcea_path = CONTROLLER_PATH.with_name("application-campaign-chronology.py")
        sourcea_name = f"sourcea_c3a_context_identity_{os.getpid()}"
        previous = sys.modules.get(sourcea_name)
        sourcea_spec = importlib.util.spec_from_file_location(
            sourcea_name, sourcea_path,
        )
        self.assertIsNotNone(sourcea_spec)
        self.assertIsNotNone(sourcea_spec.loader)
        sourcea = importlib.util.module_from_spec(sourcea_spec)
        sys.modules[sourcea_name] = sourcea
        foreign_name = f"sourcea_c3a_same_bytes_foreign_{os.getpid()}"
        foreign_previous = sys.modules.get(foreign_name)
        foreign = None
        try:
            sourcea_spec.loader.exec_module(sourcea)
            raw = sourcea_path.read_bytes()
            pin = {
                "path": _SOURCE5_CHRONOLOGY_SOURCE_PATH,
                "sha256": sourcea.sha256_bytes(raw),
            }
            with tempfile.TemporaryDirectory(prefix="sourcea-c3a-lock-") as temporary:
                output_root = Path(temporary) / "output"
                output_root.mkdir(mode=0o700)
                with sourcea.campaign_host_lock(
                        output_root, "c3a-context", "host-a") as lock:
                    with self.assertRaisesRegex(
                            self.module.Source5CampaignError,
                            "host differs from its exact active SourceA lock"):
                        self.module._source5_load_context_with_active_sourcea_held(
                            Path("/not-read-by-host-mismatch"), "host-b", sourcea, lock,
                        )
                    selected = self.module._source5_context_chronology_from_active_sourcea(
                        sourcea, lock, _SOURCE5_CHRONOLOGY_SOURCE_PATH,
                        sourcea_path, pin, raw,
                    )
                    self.assertIs(selected, sourcea)
                    self.assertIs(sourcea._source5_own_chronology_module(), sourcea)
                    foreign_spec = importlib.util.spec_from_file_location(
                        foreign_name, sourcea_path,
                    )
                    self.assertIsNotNone(foreign_spec)
                    self.assertIsNotNone(foreign_spec.loader)
                    foreign = importlib.util.module_from_spec(foreign_spec)
                    sys.modules[foreign_name] = foreign
                    foreign_spec.loader.exec_module(foreign)
                    with self.assertRaisesRegex(
                            self.module.Source5CampaignError,
                            "actual active SourceA module and its live lock"):
                        self.module._source5_context_chronology_from_active_sourcea(
                            foreign, lock, _SOURCE5_CHRONOLOGY_SOURCE_PATH,
                            sourcea_path, pin, raw,
                        )
                    implementation = ast.get_source_segment(
                        self.source, self.functions["_load_context_impl"],
                    )
                    public_loader = ast.get_source_segment(
                        self.source, self.functions["load_context"],
                    )
                    private_loader = ast.get_source_segment(
                        self.source,
                        self.functions["_source5_load_context_with_active_sourcea_held"],
                    )
                    self.assertIn("_source5_context_chronology_from_active_sourcea", implementation)
                    self.assertIn("_active_sourcea_module is not None", implementation)
                    self.assertNotIn("_active_sourcea_module", public_loader)
                    self.assertIn("_source5_context_load_transaction", public_loader)
                    self.assertIn("active_sourcea_module=active_sourcea_module", private_loader)
                    self.assertEqual(
                        list(inspect.signature(
                            self.module._source5_load_context_with_active_sourcea_held,
                        ).parameters),
                        ["manifest_path", "host_id", "active_sourcea_module",
                         "active_sourcea_lock"],
                    )
        finally:
            if previous is None:
                if sys.modules.get(sourcea_name) is sourcea:
                    sys.modules.pop(sourcea_name, None)
            else:
                sys.modules[sourcea_name] = previous
            if foreign is not None:
                if foreign_previous is None:
                    if sys.modules.get(foreign_name) is foreign:
                        sys.modules.pop(foreign_name, None)
                else:
                    sys.modules[foreign_name] = foreign_previous

    def test_owned_held_bridges_are_real_and_use_only_c3_primitives(self) -> None:
        pairs = {
            "_source5_h_authorize_job_held": "_source5_owned_authorize_job_held",
            "_source5_h_run_authorized_job_held": "_source5_owned_run_authorized_job_held",
            "_source5_h_refresh_analysis_gate_held": "_source5_owned_refresh_analysis_gate_held",
            "_source5_h_record_analysis_held": "_source5_owned_record_analysis_held",
            "_source5_h_verify_completed_pressure_job_held":
                "_source5_owned_verify_completed_pressure_job_held",
            "_source5_h_authorization_context_held":
                "_source5_owned_authorization_context_held",
            "_source5_h_verify_capacity_ancestor_held":
                "_source5_owned_verify_capacity_ancestor_held",
            "_source5_h_replay_phase_records_held":
                "_source5_owned_replay_phase_records_held",
        }
        for h_name, sourcea_name in pairs.items():
            self.assertIn(h_name, self.functions)
            self.assertIn(sourcea_name, self.source)
            calls = self._calls(h_name)
            self.assertNotIn("campaign_host_lock", calls, h_name)
            self.assertNotIn("authorize_source5_job_locked", calls, h_name)
            self.assertNotIn("run_authorized_source5_job_locked", calls, h_name)
            self.assertNotIn("record_source5_analysis_locked", calls, h_name)
            self.assertNotIn("refresh_source5_analysis_gate_locked", calls, h_name)
        guard_calls = self._calls("_source5_h_require_owned_context_held")
        self.assertIn("getattr", guard_calls)
        self.assertIn("require", guard_calls)
        self.assertIn("_source5_owned_require_h_context_held", self.source)

    def test_held_job_and_analysis_kernels_do_not_reacquire_or_call_decorated_apis(self) -> None:
        for name in (
            "_source5_h_fixed_job_held",
            "_source5_h_pressure_job_held",
            "_source5_h_soak_job_held",
            "_source5_h_analyze_phase_held",
            "_source5_h_final_phase_results_held",
            "_source5_h_wait_verify_and_reclaim_archive_job_owned_held",
        ):
            self.assertIn(name, self.functions)
            calls = self._calls(name)
            self.assertNotIn("campaign_host_lock", calls, name)
            self.assertNotIn("authorize_source5_job_locked", calls, name)
            self.assertNotIn("run_authorized_source5_job_locked", calls, name)
            self.assertNotIn("record_source5_analysis_locked", calls, name)
            self.assertNotIn("refresh_source5_analysis_gate_locked", calls, name)
        self.assertIn("_source5_h_wait_verify_and_reclaim_archive_job_owned_held",
                      self._calls("_source5_h_fixed_job_held"))
        self.assertIn("_source5_h_wait_verify_and_reclaim_archive_job_owned_held",
                      self._calls("_source5_h_pressure_job_held"))
        self.assertIn("_source5_h_wait_verify_and_reclaim_archive_job_owned_held",
                      self._calls("_source5_h_soak_job_held"))
        self.assertIn("_source5_h_replay_phase_records_held",
                      self._calls("_source5_h_analyze_phase_held"))
        self.assertIn("_source5_h_record_analysis_held",
                      self._calls("_source5_h_analyze_phase_held"))

    def test_current_phase_analysis_never_reuses_the_old_h3_client(self) -> None:
        for name in (
            "_source5_h_replay_phase_records_held",
            "_source5_h_final_phase_results_held",
            "_source5_h_analyze_phase_held",
        ):
            node = self.functions[name]
            segment = ast.get_source_segment(self.source, node)
            self.assertIsInstance(segment, str)
            self.assertNotIn("session.h_client", segment, name)
            self.assertNotIn("session.providers", segment, name)
            calls = self._calls(name)
            self.assertNotIn("source5_completed_archive_read_provider", calls, name)
            self.assertNotIn("archived_job_read_view", calls, name)
        self.assertIn("_source5_owned_replay_phase_records_held", self.source)

    def test_active_pending_lifecycle_uses_separate_boundary_guard(self) -> None:
        guard = ast.get_source_segment(
            self.source, self.functions["_source5_h_require_owned_context_held"],
        )
        clean = ast.get_source_segment(
            self.source, self.functions["_source5_h_require_clean_frontier_held"],
        )
        authorize = ast.get_source_segment(
            self.source, self.functions["_source5_h_authorize_job_held"],
        )
        run = ast.get_source_segment(
            self.source, self.functions["_source5_h_run_authorized_job_held"],
        )
        self.assertNotIn("source5_pending", guard)
        self.assertIn("source5_pending", clean)
        self.assertIn("_source5_h_require_clean_frontier_held", authorize)
        self.assertIn("_source5_h_require_owned_context_held", run)
        self.assertIn("_source5_owned_run_authorized_job_held", run)
        self.assertNotIn("_source5_h_require_clean_frontier_held", run)

    def test_owned_exploration_and_final_analysis_fail_closed_before_replay(self) -> None:
        final = ast.get_source_segment(
            self.source, self.functions["_source5_h_final_phase_results_held"],
        )
        analysis = ast.get_source_segment(
            self.source, self.functions["_source5_h_analyze_phase_held"],
        )
        self.assertIn("require(False", final)
        self.assertNotIn("_source5_h_replay_phase_records_held", final)
        self.assertNotIn("_capacity_pilot", analysis)
        self.assertNotIn("capacity-rate-candidate", analysis)
        self.assertIn("exact InputPrep-owned pilot projection", analysis)

    def test_pressure_ancestry_data_is_not_passed_as_a_sourcea_certificate(self) -> None:
        build = ast.get_source_segment(
            self.source, self.functions["_source5_h_build_pressure_recipe_held"],
        )
        kernel = ast.get_source_segment(
            self.source, self.functions["_source5_h_pressure_job_held"],
        )
        self.assertIn('recipe[3]["capacity_ancestor"] = ancestor', build)
        self.assertIn('"authorization_state"', build)
        self.assertNotIn("pressure_predecessor_certificate=ancestor", build)
        self.assertNotIn("pressure_predecessor_certificate", kernel)
        self.assertIn('"capacity_ancestor"', build)

    def test_public_run_host_does_not_select_private_owned_kernels(self) -> None:
        calls = self._calls("run_host")
        for name in (
            "_source5_h_fixed_job_held",
            "_source5_h_pressure_job_held",
            "_source5_h_soak_job_held",
            "_source5_h_analyze_phase_held",
        ):
            self.assertNotIn(name, calls)

    def test_owned_phase_refresh_map_is_fixed_and_exploration_is_not_launchable(self) -> None:
        refresh = self.functions["_source5_h_refresh_phase_prerequisites_held"]
        mapping_call = next(
            node for node in ast.walk(refresh)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get" and isinstance(node.func.value, ast.Dict)
        )
        mapping = {
            key.value: tuple(item.value for item in value.elts)
            for key, value in zip(
                mapping_call.func.value.keys,
                mapping_call.func.value.values,
                strict=True,
            )
        }
        self.assertEqual(mapping, {
            "aa": ("exploration",),
            "confirmation": ("exploration", "aa"),
            "pressure": ("fixed_analysis",),
            "soak": ("pressure_analysis",),
        })
        fixed_job = self.functions["_source5_h_fixed_job_held"]
        accepted_phase_set = next(
            node for node in ast.walk(fixed_job)
            if isinstance(node, ast.Set) and
            {item.value for item in node.elts if isinstance(item, ast.Constant)} ==
                {"aa", "confirmation"}
        )
        self.assertEqual({item.value for item in accepted_phase_set.elts},
                         {"aa", "confirmation"})


    def test_legacy_analysis_persistence_returns_registered_artifact_pin(self) -> None:
        record = {"phase": "aa", "phase_gate_passed": True}
        analysis_pin = {"path": "/private/aa-analysis.json", "raw_sha256": "a" * 64}
        manifest_pin = {"path": "/private/manifest.json", "raw_sha256": "b" * 64}
        lock = object()
        registration_calls = []
        chronology = SimpleNamespace(
            record_source5_analysis_locked=lambda *args, **kwargs: (
                registration_calls.append((args, kwargs)) or {"head": "c" * 64}
            ),
        )
        context = SimpleNamespace(
            manifest={"schema": self.module.EXECUTION_SCHEMA_V4},
            manifest_pin=manifest_pin,
            chronology=chronology,
        )
        provider = object()
        with patch.object(
                self.module, "_source5_write_analysis_artifact_held",
                return_value=(record, analysis_pin)) as writer, \
                patch.object(
                    self.module, "source5_completed_archive_read_provider",
                    return_value=provider) as provider_factory:
            result = self.module._persist_analysis(
                context, lock, "aa", "aa", {"passed": True}, True, True,
            )
        writer.assert_called_once()
        provider_factory.assert_called_once_with(context)
        self.assertEqual(len(registration_calls), 1)
        args, kwargs = registration_calls[0]
        self.assertEqual(args, (lock, self.module.api_pin(manifest_pin), analysis_pin))
        self.assertIs(kwargs["captured_read_context"], provider)
        self.assertEqual(result, {
            "record": record,
            "pin": analysis_pin,
            "chronology": {"head": "c" * 64},
        })

    def test_path_contract_accepts_a_real_posix_path_and_rejects_strings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "materials.json"
            self.assertIsNot(type(path), Path)
            self.assertIs(
                self.module._source5_h_require_path_argument(
                    path, "focused path contract",
                ),
                path,
            )
            with self.assertRaises(self.module.Source5CampaignError):
                self.module._source5_h_require_path_argument(
                    str(path), "focused path contract",
                )
        for name in (
            "_pressure_materials_index",
            "_build_pressure_recipe_data_held",
            "_build_soak_helper_input",
            "_source5_h_soak_job_held",
            "_source5_wait_for_ack_bundle_owned_bounded_held",
        ):
            self.assertIn("_source5_h_require_path_argument", self._calls(name), name)
        for name in ("_source5_h_pressure_job_held", "_source5_h_soak_job_held"):
            self.assertTrue(any(
                isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and
                node.func.id == "isinstance" and len(node.args) == 2 and
                isinstance(node.args[1], ast.Name) and node.args[1].id == "Path"
                for node in ast.walk(self.functions[name])
            ), name)

    def test_owned_fixed_and_pressure_numeric_analysis_refuse_before_replay(self) -> None:
        for phase in ("fixed_analysis", "pressure_analysis"):
            with self.subTest(phase=phase), \
                    patch.object(
                        self.module, "_source5_h_replay_phase_records_held",
                        side_effect=AssertionError("refusal reached record replay"),
                    ) as replay, \
                    patch.object(
                        self.module, "_source5_numeric_for_pairs",
                        side_effect=AssertionError("refusal reached ambient numeric reader"),
                    ) as numeric:
                with self.assertRaisesRegex(
                        self.module.Source5CampaignError,
                        "current completed-owner trace provider"):
                    self.module._source5_h_analyze_phase_held(
                        None, None, None, phase,
                    )
                replay.assert_not_called()
                numeric.assert_not_called()

    def test_owned_pressure_recipe_refuses_before_capacity_origin_reads(self) -> None:
        with patch.object(
                self.module, "_capacity_bundle_from_completion",
                side_effect=AssertionError("opened ambient capacity origins"),
        ) as capacity_reader, patch.object(
                self.module, "read_stable",
                side_effect=AssertionError("opened a pressure origin"),
        ) as stable_reader:
            with self.assertRaisesRegex(
                    self.module.Source5CampaignError,
                    "scope-owned closed capacity projection"):
                self.module._source5_h_build_pressure_recipe_held(
                    None, None, None, {}, 0, {}, [],
                )
        capacity_reader.assert_not_called()
        stable_reader.assert_not_called()

    def test_owned_pressure_job_refuses_before_material_index_read(self) -> None:
        with patch.object(
                self.module, "_pressure_materials_index",
                side_effect=AssertionError("opened the ambient pressure index"),
        ) as materials_reader, patch.object(
                self.module, "_capacity_bundle_from_completion",
                side_effect=AssertionError("opened ambient capacity origins"),
        ) as capacity_reader:
            with self.assertRaisesRegex(
                    self.module.Source5CampaignError,
                    "scope-owned closed capacity projection"):
                self.module._source5_h_pressure_job_held(
                    None, None, None, 0, {}, Path("/must-not-be-opened"),
                )
        materials_reader.assert_not_called()
        capacity_reader.assert_not_called()

    def test_owned_refusal_guards_precede_the_new_origin_consumers(self) -> None:
        expected_first_calls = {
            "_source5_h_analyze_phase_held":
                "_source5_h_require_owned_numeric_analysis_provider_held",
            "_source5_h_build_pressure_recipe_held":
                "_source5_h_require_owned_pressure_capacity_seam_held",
            "_source5_h_pressure_job_held":
                "_source5_h_require_owned_pressure_capacity_seam_held",
        }
        for name, expected in expected_first_calls.items():
            node = self.functions[name]
            first_call = next(
                item for item in node.body
                if not (isinstance(item, ast.Expr) and
                        isinstance(item.value, ast.Constant) and
                        isinstance(item.value.value, str))
            )
            self.assertIsInstance(first_call, ast.Expr, name)
            self.assertIsInstance(first_call.value, ast.Call, name)
            self.assertIsInstance(first_call.value.func, ast.Name, name)
            self.assertEqual(first_call.value.func.id, expected, name)

    def test_bounded_ack_wait_rejects_noninteger_or_unbounded_cap(self) -> None:
        for maximum_bytes in (True, 0, (1 << 48) + 1):
            with self.subTest(maximum_bytes=maximum_bytes):
                with self.assertRaises(self.module.Source5CampaignError):
                    self.module._source5_wait_for_ack_bundle_owned_bounded_held(
                        Path("/not-opened-by-an-invalid-owned-ack-cap"),
                        maximum_bytes,
                        deadline_ns=time.monotonic_ns() + 5_000_000_000,
                        cancel_event=None,
                    )


if __name__ == "__main__":
    raise SystemExit(unittest.main())
