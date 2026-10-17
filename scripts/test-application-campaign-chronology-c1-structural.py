#!/usr/bin/env python3
"""Static regressions for SourceA C1's non-authorizing V5 bootstrap."""
from __future__ import annotations

import ast
import builtins
import copy
import importlib.util
import symtable
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
SOURCE_PATH = SCRIPT_DIR / "application-campaign-chronology.py"


class SourceAStructuralBootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SOURCE_PATH.read_text()
        cls.tree = ast.parse(cls.source, filename=str(SOURCE_PATH))
        compile(cls.source, str(SOURCE_PATH), "exec")
        spec = importlib.util.spec_from_file_location(
            "sourcea_c1r3_structural_behavior", SOURCE_PATH,
        )
        if spec is None or spec.loader is None:
            raise AssertionError("cannot load the local chronology module")
        cls.module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.module
        spec.loader.exec_module(cls.module)
        cls.functions = {
            node.name: node for node in cls.tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        cls.classes = {
            node.name: node for node in cls.tree.body
            if isinstance(node, ast.ClassDef)
        }

    def _function_calls(self, name: str) -> list[str]:
        node = self.functions[name]
        result = []
        for item in ast.walk(node):
            if not isinstance(item, ast.Call):
                continue
            if isinstance(item.func, ast.Name):
                result.append(item.func.id)
            elif isinstance(item.func, ast.Attribute):
                result.append(item.func.attr)
        return result

    def test_structural_entries_are_top_level_definitions(self) -> None:
        expected = {
            "_source5_v5_structural_generation_pins",
            "_source5_prepared_capacity_registration_data_identity",
            "_source5_analysis_identity_data",
            "_source5_require_current_analysis_terminal_horizon",
            "_source5_analysis_structural_state_identity",
            "_source5_authorization_data_identity",
            "_source5_v5_structural_profile_completion",
            "_source5_v5_structural_width_path",
            "_source5_v5_structural_width_projection",
            "_validate_source5_manifest_value_v5_structural",
            "_prepare_source5_v5_structural_context_held",
            "_read_source5_v5_journal_structural",
        }
        self.assertTrue(expected.issubset(self.functions))
        self.assertIn("_Source5V5StructuralContext", self.classes)

    def test_bootstrap_orders_profile_width_then_journal_under_same_lock(self) -> None:
        node = self.functions["_prepare_source5_v5_structural_context_held"]
        calls = [item.func.id for item in sorted(
            (item for item in ast.walk(node)
             if isinstance(item, ast.Call) and isinstance(item.func, ast.Name)),
            key=lambda item: item.lineno,
        )]
        profile = calls.index("_source5_v5_structural_profile_completion")
        width = calls.index("_source5_v5_structural_width_projection")
        journal = calls.index("_read_source5_v5_journal_structural")
        self.assertLess(profile, width)
        self.assertLess(width, journal)
        self.assertGreaterEqual(calls.count("_source5_v5_structural_lock_identity"), 2)
        setup_calls = self._function_calls(
            "_prepare_source5_v5_structural_context_held",
        )
        self.assertIn("_prepare_source5_v5_structural_context_setup_held",
                      setup_calls)
        self.assertIn(
            "_prepare_source5_context_setup_held",
            self._function_calls("_prepare_source5_v5_structural_context_setup_held"),
        )
        shared_setup = self.functions["_prepare_source5_context_setup_held"]
        structural_branch = next(
            item for item in ast.walk(shared_setup)
            if isinstance(item, ast.If) and isinstance(item.test, ast.Name) and
            item.test.id == "structural_v5_manifest"
        )
        structural_calls = [
            item.func.id for statement in structural_branch.body
            for item in ast.walk(statement)
            if isinstance(item, ast.Call) and isinstance(item.func, ast.Name)
        ]
        self.assertIn("_validate_source5_manifest_value_v5_structural",
                      structural_calls)
        self.assertIn("_validate_source5_manifest_value",
                      [item.func.id for statement in structural_branch.orelse
                       for item in ast.walk(statement)
                       if isinstance(item, ast.Call) and isinstance(item.func, ast.Name)])

        profile_calls = self._function_calls("_source5_v5_structural_profile_completion")
        self.assertIn("_source5_issue_owned_prepared_completion_role_context", profile_calls)
        self.assertIn("MAX_SOURCE5_OWNED_PREPARED_COMPLETION_BYTES",
                      self.source)
        width_calls = self._function_calls("_source5_v5_structural_width_projection")
        self.assertIn("_source5_captured_source_module", width_calls)
        self.assertIn("validate_prepared_exploration_width_contract_v2", self.source)

    def test_named_v5_setup_selects_structural_manifest_route(self) -> None:
        lock = object()
        pin = object()
        sentinel_result = object()
        with patch.object(
                self.module, "_prepare_source5_context_setup_held",
                return_value=sentinel_result) as shared_setup:
            result = self.module._prepare_source5_v5_structural_context_setup_held(
                lock, pin,
            )
        self.assertIs(result, sentinel_result)
        shared_setup.assert_called_once_with(
            lock, pin, structural_v5_manifest=True,
        )

    def test_structural_context_carries_data_without_authority_fields(self) -> None:
        node = self.classes["_Source5V5StructuralContext"]
        fields = {item.target.id for item in node.body
                  if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name)}
        self.assertEqual(fields, {
            "manifest", "prepared", "state", "manifest_pin", "profile_pin",
            "width_pin", "lock_identity",
        })
        self.assertFalse(any(
            token in field.lower()
            for field in fields
            for token in ("proof", "scope", "ready", "verified", "authority")
        ))

    def test_legacy_final_analysis_keeps_original_valid_soak_semantics(self) -> None:
        host_id = "agent-A"
        prepared = {
            "source5_execution_schema": self.module.SOURCE5_EXECUTION_SCHEMA_V4,
            "host_id": host_id,
            "plan": {"jobs": {"soak": [{
                "phase": "soak", "host_id": host_id, "run_id": "soak-0",
            }]}},
        }
        state = {
            "source5_finished": {
                ("soak", "soak-0"): {
                    "state": "valid_soak",
                    "terminal": {"state": "valid_soak", "status": 0},
                },
            },
            "source5_analyses": {
                phase: {"phase": phase}
                for phase in (
                    "exploration", "aa", "fixed_analysis",
                    "pressure_analysis", "soak",
                )
            },
        }
        identity = {
            "details": {"phase": "final_analysis"},
            "source_phase": "soak",
        }
        self.module._source5_analysis_structural_state_identity(
            identity, prepared, state,
        )

    def test_v5_analysis_requires_exact_current_terminal_horizons(self) -> None:
        host_id = "agent-A"
        jobs = {
            "exploration": [{"host_id": host_id, "run_id": "old-explore-0"}],
            "aa": [{"host_id": host_id, "run_id": "aa-0"}],
            "confirmation": [{"host_id": host_id, "run_id": "confirm-0"}],
            "pressure": [{"host_id": host_id, "run_id": "pressure-0"}],
            "soak": [{"host_id": host_id, "run_id": "soak-0"}],
        }
        prepared = {
            "source5_execution_schema": self.module.SOURCE5_EXECUTION_SCHEMA_V5,
            "host_id": host_id, "plan": {"jobs": jobs},
        }
        finished = {
            ("aa", "aa-0"): {"state": "valid_pair"},
            ("confirmation", "confirm-0"): {"state": "valid_pair"},
            ("pressure", "pressure-0"): {"state": "valid_pair"},
            ("soak", "soak-0"): {"state": "valid_soak"},
        }
        prior = {
            phase: {"phase": phase}
            for phase in (
                "exploration", "aa", "fixed_analysis",
                "pressure_analysis", "soak",
            )
        }
        final_identity = {
            "details": {"phase": "final_analysis"},
            "source_phase": "soak",
        }
        self.module._source5_analysis_structural_state_identity(
            final_identity, prepared,
            {"source5_finished": finished, "source5_analyses": prior},
        )
        bad_horizons = []
        missing_pressure = copy.deepcopy(finished)
        del missing_pressure[("pressure", "pressure-0")]
        bad_horizons.append(missing_pressure)
        wrong_state = copy.deepcopy(finished)
        wrong_state[("aa", "aa-0")]["state"] = "invalid_pair"
        bad_horizons.append(wrong_state)
        extra_current_job = copy.deepcopy(finished)
        extra_current_job[("aa", "unexpected-aa")] = {"state": "valid_pair"}
        bad_horizons.append(extra_current_job)
        for bad in bad_horizons:
            with self.subTest(bad=bad), self.assertRaises(self.module.ChronologyError):
                self.module._source5_analysis_structural_state_identity(
                    final_identity, prepared,
                    {"source5_finished": bad, "source5_analyses": prior},
                )

        detached_exploration = {
            "details": {"phase": "exploration"},
            "source_phase": "exploration",
        }
        self.module._source5_analysis_structural_state_identity(
            detached_exploration, prepared,
            {"source5_finished": {}, "source5_analyses": {}},
        )

    def test_owned_width_requires_input_root_but_legacy_v5_keeps_artifact_root(self) -> None:
        with tempfile.TemporaryDirectory(
                prefix="allocatbelt-source5-c1-width-root-") as temporary:
            root = Path(temporary).resolve()
            input_root = root / "inputs"
            artifact_root = root / "artifacts"
            width_root = artifact_root / "campaign" / "source5" / "agent-A"
            input_root.mkdir()
            width_root.mkdir(mode=0o700, parents=True)
            owned_width = input_root / "owned-width.json"
            legacy_width = width_root / "legacy-width.json"
            owned_width.write_bytes(b"owned-width")
            legacy_width.write_bytes(b"legacy-width")
            prepared = {
                "input_root": input_root,
                "campaign_id": "campaign",
                "host_id": "agent-A",
            }
            owned_pin = {"path": str(owned_width), "raw_sha256": "a" * 64,
                         "semantic_sha256": "b" * 64}
            legacy_pin = {"path": str(legacy_width), "raw_sha256": "c" * 64,
                          "semantic_sha256": "d" * 64}
            owned_manifest = {
                "prepared_replay_inputs": {"agent-A": {}},
                "artifact_root": str(artifact_root),
            }
            legacy_manifest = {
                "schema": self.module.SOURCE5_EXECUTION_SCHEMA_V5,
                "artifact_root": str(artifact_root),
            }
            self.assertEqual(
                self.module._source5_v5_structural_width_path(
                    owned_manifest, prepared, owned_pin,
                ),
                owned_width,
            )
            self.assertEqual(
                self.module._source5_v5_structural_width_path(
                    legacy_manifest, prepared, legacy_pin,
                ),
                legacy_width,
            )
            with self.assertRaises(self.module.ChronologyError):
                self.module._source5_v5_structural_width_path(
                    owned_manifest, prepared, legacy_pin,
                )

    def test_v5_exploration_authorization_is_rejected_before_current_map_mutation(self) -> None:
        prepared = {
            "source5_execution_schema": self.module.SOURCE5_EXECUTION_SCHEMA_V5,
            "campaign_id": "campaign", "host_id": "agent-A",
        }
        details = {
            key: None for key in
            self.module._source5_authorization_detail_fields(prepared)
        }
        details["phase"] = "exploration"
        state = {
            "registration": None,
            "prepared_capacity_registration": {},
            "cleanup_blocked": False,
            "source5_cleanup_blocked": False,
            "source5_failed_owner_window": False,
            "pending": None,
            "source5_pending": None,
            "source5_analyses": {},
            "source5_authorized": {},
            "source5_seen_jobs": set(),
            "source5_finished": {},
        }
        before = copy.deepcopy(state)
        with self.assertRaisesRegex(
                self.module.ChronologyError,
                "imported ancestor and cannot launch an APP"):
            self.module._check_event_semantics(
                state, "source5_authorized", details, "e" * 64,
                prepared, replay=True, apply=True,
            )
        self.assertEqual(state, before)

    def test_named_v5_manifest_core_defers_completion_and_old_capacity_reads(self) -> None:
        with tempfile.TemporaryDirectory(
                prefix="allocatbelt-source5-c1-manifest-route-") as temporary:
            root = Path(temporary).resolve()
            input_root = root / "inputs"
            artifact_root = root / "artifacts"
            output_root = root / "output"
            source_root = root / "source"
            for directory in (input_root, artifact_root, output_root, source_root):
                directory.mkdir(mode=0o700 if directory in {artifact_root, output_root}
                                else 0o755)
            hosts = ["agent-A", "agent-B"]
            spec_path = input_root / "campaign-spec.json"
            plan_path = input_root / "campaign-plan.json"
            spec_raw_sha = "1" * 64
            plan_raw_sha = "2" * 64
            plan_jobs = {
                phase: [] for phase in (
                    "exploration", "aa", "confirmation", "pressure", "soak",
                )
            }
            spec = {
                "campaign_id": "structural-current-campaign",
                "hosts": [{"host_id": host} for host in hosts],
                "rates": [{"fixture": True}],
                "oracles": [{"fixture": True}],
            }
            plan = {"host_ids": hosts, "jobs": plan_jobs}
            prepared = {
                "campaign_id": spec["campaign_id"],
                "host_id": hosts[0], "input_root": input_root,
                "source_root": source_root, "output_root": output_root,
                "spec": spec, "plan": plan,
                "controller": types.SimpleNamespace(
                    build_jobs=lambda _spec, phase: plan_jobs[phase],
                ),
                "prepared": {
                    "spec_path": spec_path,
                    "spec_raw_sha256": spec_raw_sha,
                    "spec_semantic_sha256": "3" * 64,
                    "plan_path": plan_path,
                    "plan_raw_sha256": plan_raw_sha,
                    "plan_semantic_sha256": "4" * 64,
                },
            }
            generation = {
                "completion": {
                    "path": str(input_root / "prepared-inputs-completion.json"),
                    "raw_sha256": "5" * 64, "semantic_sha256": "6" * 64,
                },
                "provenance": {
                    "schema": self.module.SOURCE5_PREPARED_INPUTS_PROVENANCE_SCHEMA_V2,
                    "preparation_pin": {
                        "path": str(input_root / "preparation-intent.json"),
                        "raw_sha256": "7" * 64,
                    },
                    "final_spec_pin": {"path": str(spec_path),
                                        "raw_sha256": spec_raw_sha},
                    "final_plan_pin": {"path": str(plan_path),
                                        "raw_sha256": plan_raw_sha},
                    "exploration_lineage": {
                        host: {
                            "bridge_header": {
                                "path": str(root / "closed-old-capture" /
                                            host / "header.json"),
                                "raw_sha256": "8" * 64,
                            },
                            "record_index": {
                                "path": str(root / "closed-old-capture" /
                                            host / "index.json"),
                                "raw_sha256": "9" * 64,
                            },
                        }
                        for host in hosts
                    },
                },
            }
            width_map = {
                host: {
                    "artifact": {"path": str(input_root / f"{host}-width.json"),
                                 "raw_sha256": "a" * 64},
                    "semantic_sha256": "b" * 64,
                }
                for host in hosts
            }
            manifest_body = {
                "schema": self.module.SOURCE5_EXECUTION_SCHEMA_V5,
                "campaign_id": spec["campaign_id"], "hosts": hosts,
                "original_inputs": {}, "execution_sources": {},
                "modules": {}, "observed_hosts": {},
                "artifact_root": str(artifact_root),
                "output_root": str(output_root),
                "phase_order": [
                    "exploration", "aa", "confirmation", "fixed_analysis",
                    "pressure", "pressure_analysis", "soak", "final_analysis",
                ],
                "protocol_sha256": "c" * 64,
                "qualification_eligible": False,
                "scope": self.module.SOURCE5_EXECUTION_SCOPE_V5,
                "prepared_input_generation": generation,
                "prepared_capacity_registration": {},
                "archive_signer_contexts": {},
                "journal_width_contracts": width_map,
                "prepared_replay_inputs": {
                    host: {"path": str(input_root / f"{host}-profile.json"),
                           "raw_sha256": "d" * 64,
                           "semantic_sha256": "e" * 64}
                    for host in hosts
                },
            }
            manifest = {
                **manifest_body,
                "manifest_sha256": self.module.sha256_bytes(
                    self.module.canonical_bytes(manifest_body),
                ),
            }
            raw = self.module.canonical_bytes(manifest)
            completion_path = Path(generation["completion"]["path"])
            self.assertFalse(completion_path.exists())
            with patch.object(
                    self.module, "_source5_validate_manifest_source_bindings"), \
                    patch.object(
                        self.module, "_verify_source5_prepared_input_generation",
                        side_effect=AssertionError("ordinary completion origins must not be opened")), \
                    patch.object(
                        self.module, "_read_stable",
                        side_effect=AssertionError("structural manifest validation must not read old origins")) as reader, \
                    patch.object(
                        self.module, "_read_pin",
                        side_effect=AssertionError("structural manifest validation must not read capacity receipts")) as pin_reader:
                checked = self.module._validate_source5_manifest_value_v5_structural(
                    manifest, raw, prepared,
                )
            self.assertEqual(checked, manifest)
            self.assertIsNone(prepared["source5_prepared_input_completion"])
            self.assertFalse(completion_path.exists())
            reader.assert_not_called()
            pin_reader.assert_not_called()

    def test_data_decoders_do_not_call_live_authority_paths(self) -> None:
        forbidden = {
            "_source5_require_v5_replay_authority",
            "_source5_issue_captured_analysis_proof",
            "_source5_issue_prepared_registration_proof",
            "_source5_validate_captured_analysis_proof",
            "_source5_validate_prepared_registration_proof",
            "_consume_source5_authorization",
            "_append_event", "_append_event_impl",
            "_verify_source5_prepared_input_generation",
            "_source5_captured_source_module",
            "_load_module",
        }
        for name in (
            "_source5_prepared_capacity_registration_data_identity",
            "_source5_analysis_identity_data",
            "_source5_analysis_structural_state_identity",
            "_source5_authorization_data_identity",
        ):
            self.assertTrue(forbidden.isdisjoint(self._function_calls(name)), name)

        authorization_calls = self._function_calls("_source5_authorization_data_identity")
        self.assertNotIn("_source5_reference", authorization_calls)
        self.assertNotIn("_source_file", authorization_calls)

    def test_all_seven_v5_live_refusals_remain_at_their_original_sinks(self) -> None:
        gate_calls: dict[str, int] = {}
        for node in self.tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            count = sum(
                isinstance(item, ast.Call) and isinstance(item.func, ast.Name) and
                item.func.id == "_source5_require_v5_replay_authority"
                for item in ast.walk(node)
            )
            if count:
                gate_calls[node.name] = count
        self.assertEqual(gate_calls, {
            "_source5_analysis_identity": 1,
            "refresh_source5_analysis_gate_locked": 1,
            "_validate_source5_authorization": 1,
            "authorize_source5_job_locked": 1,
            "record_source5_analysis_locked": 1,
            "verify_source5_capacity_ancestor_locked": 1,
            "source5_authorization_context_locked": 1,
        })

    def test_new_helpers_have_no_unbound_global_names(self) -> None:
        module_table = symtable.symtable(self.source, str(SOURCE_PATH), "exec")
        module_names = set(module_table.get_identifiers())
        builtin_names = set(dir(builtins))
        helper_names = (
            "_source5_v5_structural_completion_summary",
            "_source5_v5_structural_generation_pins",
            "_source5_prepared_capacity_registration_data_identity",
            "_source5_analysis_identity_data",
            "_source5_require_current_analysis_terminal_horizon",
            "_source5_analysis_structural_state_identity",
            "_source5_authorization_data_identity",
            "_source5_v5_structural_profile_completion",
            "_source5_v5_structural_width_path",
            "_source5_v5_structural_width_projection",
            "_validate_source5_manifest_value_v5_structural",
            "_validate_source5_manifest_value_core",
            "_prepare_source5_context_setup_held",
            "_prepare_source5_v5_structural_context_setup_held",
            "_source5_v5_structural_lock_identity",
            "_prepare_source5_v5_structural_context_held",
            "_read_source5_v5_journal_structural",
        )
        function_tables = {
            (child.get_name(), child.get_lineno()): child
            for child in module_table.get_children()
        }
        for name in helper_names:
            node = self.functions[name]
            table = function_tables[(name, node.lineno)]
            for symbol in table.get_symbols():
                if symbol.is_global() and symbol.is_referenced():
                    self.assertIn(symbol.get_name(), module_names | builtin_names,
                                  f"{name} references unbound global {symbol.get_name()}")

    def test_cli_main_guard_remains_after_all_source_definitions(self) -> None:
        guards = [node for node in self.tree.body if isinstance(node, ast.If) and
                  isinstance(node.test, ast.Compare) and
                  isinstance(node.test.left, ast.Name) and
                  node.test.left.id == "__name__"]
        self.assertEqual(len(guards), 1)
        self.assertGreater(
            guards[0].lineno,
            self.functions["_prepare_source5_v5_structural_context_held"].lineno,
        )


if __name__ == "__main__":
    raise SystemExit(unittest.main())
