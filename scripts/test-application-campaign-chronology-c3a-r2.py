#!/usr/bin/env python3
"""Focused R2 regressions for C3a binding shape, body pins, and final callback closure."""
from __future__ import annotations

import copy
import importlib.util
import json
import os
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch
from pathlib import Path
from types import SimpleNamespace

SOURCE_PATH = Path(__file__).with_name("application-campaign-chronology.py")


def _load_sourcea_module():
    name = f"sourcea_c3a_r2_lifecycle_{os.getpid()}"
    previous = sys.modules.get(name)
    spec = importlib.util.spec_from_file_location(name, SOURCE_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {SOURCE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        if previous is None:
            if sys.modules.get(name) is module:
                sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
        raise
    return name, previous, module


class SourceAC3aR2DataContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module_name, cls.previous_module, cls.module = _load_sourcea_module()

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.previous_module is None:
            if sys.modules.get(cls.module_name) is cls.module:
                sys.modules.pop(cls.module_name, None)
        else:
            sys.modules[cls.module_name] = cls.previous_module

    def test_sealed_refresh_policy_producer_and_consumer_share_exact_shape(self) -> None:
        module = self.module
        scope_entry = {
            "route": module._Source5OwnedReplayRoute.SEALED_REFRESH,
            "allowed_sinks": module._SOURCE5_OWNED_OPERATION_ROUTE_SINKS[
                module._Source5OwnedReplayRoute.SEALED_REFRESH
            ],
        }
        binding_fragment = module._source5_owned_h_context_action_policy(scope_entry)
        module._source5_owned_h_context_require_action_policy(
            binding_fragment, scope_entry,
        )
        self.assertEqual(binding_fragment, {
            "allowed_actions": frozenset(),
            "allowed_sink_names": (),
        })

    def _verified_body_fixture(self, root: Path):
        module = self.module
        root.mkdir(mode=0o700)
        host_ids = ("host-a", "host-b")
        sources = {}
        source_pins = []
        source_refs = {}
        for host in host_ids:
            source_body = {
                "schema": "test-source-manifest.v1",
                "source": {
                    "source_tree_sha256":
                        ("a" if host == "host-a" else "b") * 64,
                },
                "files": [],
            }
            source_semantic = module._source5_owned_scope_digest(
                source_body, f"test {host} source manifest",
            )
            source_value = {**source_body, "manifest_sha256": source_semantic}
            source_path = root / f"{host}-source.json"
            source_raw = module.canonical_bytes(source_value)
            source_path.write_bytes(source_raw)
            source_path.chmod(0o600)
            source_pin = {
                "host_id": host, "path": str(source_path),
                "raw_sha256": module.sha256_bytes(source_raw),
                "semantic_sha256": source_semantic,
                "source_tree_sha256": source_value["source"]["source_tree_sha256"],
            }
            sources[host] = source_value
            source_pins.append(source_pin)
            source_refs[host] = dict(source_pin)

        spec = {
            "schema": "test-spec.v1", "campaign_id": "c3a-body",
            "hosts": [{"host_id": host} for host in host_ids],
            "source_manifests": [
                {"host_id": host, "relative_path": f"{host}-source.json",
                 "sha256": sources[host]["manifest_sha256"]}
                for host in host_ids
            ],
            "rates": [1], "oracles": [],
        }
        spec_semantic = module._source5_owned_scope_digest(spec, "test Spec body")
        spec_path = root / "spec.json"
        spec_raw = module.canonical_bytes(spec)
        spec_path.write_bytes(spec_raw)
        spec_path.chmod(0o600)
        spec_pin = {
            "path": str(spec_path), "raw_sha256": module.sha256_bytes(spec_raw),
            "semantic_sha256": spec_semantic,
        }
        plan = {
            "schema": "test-plan.v1", "campaign_id": "c3a-body",
            "host_ids": list(host_ids), "spec_sha256": spec_semantic,
            "source_manifests": {
                host: sources[host]["manifest_sha256"] for host in host_ids
            },
            "jobs": {
                "exploration": [
                    {"host_id": "host-a", "job": {"run_id": "run-1"}},
                ],
            },
        }
        plan_semantic = module._source5_owned_scope_digest(
            plan, "test Plan body before its own digest",
        )
        plan["plan_sha256"] = plan_semantic
        plan_path = root / "plan.json"
        plan_raw = module.canonical_bytes(plan)
        plan_path.write_bytes(plan_raw)
        plan_path.chmod(0o600)
        plan_pin = {
            "path": str(plan_path), "raw_sha256": module.sha256_bytes(plan_raw),
            "semantic_sha256": plan_semantic,
        }
        prepared = {
            "host_id": "host-a", "spec": spec, "plan": plan,
            "source": sources["host-a"], "sources": sources,
            "source_manifest_raw_refs": source_refs,
            "prepared": {
                "spec_semantic_sha256": spec_semantic,
                "plan_semantic_sha256": plan_semantic,
            },
            "original_pins": {
                "spec": spec_pin, "plan": plan_pin,
                "source_manifests": source_pins,
            },
        }
        snapshot_pins = [("Spec", spec_pin), ("Plan", plan_pin)] + [
            (row["host_id"], row) for row in source_pins
        ]
        snapshots = [
            module._source5_construction_snapshot_file(
                pin["path"], pin["raw_sha256"], 1024 * 1024,
                f"test C2 captured {label} input",
            )
            for label, pin in snapshot_pins
        ]
        session = SimpleNamespace(
            prepared=prepared, input_snapshots=snapshots,
        )
        body_binding = module._source5_owned_h_context_verified_input_body_binding(session)
        context = SimpleNamespace(
            host_id="host-a", spec=copy.deepcopy(spec), spec_raw=spec_raw,
            spec_pin={"path": spec_pin["path"], "raw_sha256": spec_pin["raw_sha256"]},
            spec_semantic_sha256=spec_semantic,
            plan=copy.deepcopy(plan), plan_raw=plan_raw,
            plan_pin={"path": plan_pin["path"], "raw_sha256": plan_pin["raw_sha256"]},
            plan_semantic_sha256=plan_semantic,
            source=copy.deepcopy(sources["host-a"]),
            sources=copy.deepcopy(sources),
        )
        return context, body_binding, session

    def test_spec_plan_and_source_body_mutations_fail_with_pins_unchanged(self) -> None:
        with tempfile.TemporaryDirectory(prefix="sourcea-c3a-r2-body-") as directory:
            original, body_binding, session = self._verified_body_fixture(Path(directory) / "inputs")
            self.assertEqual(
                self.module._source5_owned_h_context_verified_input_body_binding(session),
                body_binding,
            )
            session.input_snapshots[0]["raw_sha256"] = "f" * 64
            with self.assertRaises(self.module.ChronologyError):
                self.module._source5_owned_h_context_verified_input_body_binding(session)
            cases = (
                ("Spec rates",
                 lambda context: context.spec["rates"].__setitem__(0, 99)),
                ("Plan jobs",
                 lambda context: context.plan["jobs"]["exploration"][0]["job"].__setitem__(
                     "run_id", "changed",
                 )),
                ("selected Source",
                 lambda context: context.source["source"].__setitem__(
                     "source_tree_sha256", "f" * 64,
                 )),
                ("peer Source",
                 lambda context: context.sources["host-b"]["source"].__setitem__(
                     "source_tree_sha256", "e" * 64,
                 )),
            )
            for label, mutate in cases:
                with self.subTest(label=label):
                    context = copy.deepcopy(original)
                    spec_pin = copy.deepcopy(context.spec_pin)
                    plan_pin = copy.deepcopy(context.plan_pin)
                    spec_semantic = context.spec_semantic_sha256
                    plan_semantic = context.plan_semantic_sha256
                    mutate(context)
                    self.assertEqual(context.spec_pin, spec_pin)
                    self.assertEqual(context.plan_pin, plan_pin)
                    self.assertEqual(context.spec_semantic_sha256, spec_semantic)
                    self.assertEqual(context.plan_semantic_sha256, plan_semantic)
                    with self.assertRaises(self.module.ChronologyError):
                        self.module._source5_owned_h_context_validate_input_bodies(
                            context, body_binding,
                        )

    def _run_current_data_cancel_mutation(self, target: str, mutate_on: int):
        module = self.module
        with tempfile.TemporaryDirectory(prefix=f"sourcea-c3a-r2-{target}-") as directory:
            root = Path(directory)
            input_root = root / "input"
            input_root.mkdir(mode=0o700)
            control_path = input_root / "profile-control.json"
            control_raw = b"current-profile-control"
            control_path.write_bytes(control_raw)
            control_path.chmod(0o600)
            control_snapshot = module._source5_construction_snapshot_file(
                str(control_path), module.sha256_bytes(control_raw), 4096,
                "C3a current profile control",
            )
            journal_path = root / "journal-state.json"
            journal_value = {
                "head": "a" * 64, "record_count": 1,
                "registration_head": "b" * 64,
            }
            journal_path.write_bytes(module.canonical_bytes(journal_value))
            journal_path.chmod(0o600)

            completion_pin = {
                "path": str(root / "completion.json"),
                "raw_sha256": "c" * 64, "semantic_sha256": "d" * 64,
            }
            provenance = {"schema": "test-provenance.v2", "digest": "e" * 64}
            profile_pin = {
                "path": str(control_path),
                "raw_sha256": module.sha256_bytes(control_raw),
                "semantic_sha256": "f" * 64,
            }
            width_pin = {
                "path": str(root / "width.json"),
                "raw_sha256": "1" * 64, "semantic_sha256": "2" * 64,
            }
            manifest = {
                "schema": module.SOURCE5_EXECUTION_SCHEMA_V5,
                "scope": "final_prepared_exploration_reuse",
                "campaign_id": "c3a-callback", "hosts": ["host-a"],
                "prepared_input_generation": {
                    "completion": completion_pin, "provenance": provenance,
                },
                "prepared_replay_inputs": {"host-a": profile_pin},
                "modules": {"host-a": {}},
                "journal_width_contracts": {},
                "manifest_sha256": "0" * 64,
            }
            manifest["manifest_sha256"] = module._source5_owned_scope_digest(
                {key: value for key, value in manifest.items()
                 if key != "manifest_sha256"},
                "C3a callback test manifest",
            )
            manifest_path = root / "execution-manifest.json"
            manifest_raw = module.canonical_bytes(manifest)
            manifest_path.write_bytes(manifest_raw)
            manifest_path.chmod(0o600)
            manifest_raw_sha = module.sha256_bytes(manifest_raw)
            execution_pin = {
                "path": str(manifest_path), "raw_sha256": manifest_raw_sha,
                "semantic_sha256": manifest["manifest_sha256"],
            }
            prepared = {
                "host_id": "host-a", "campaign_id": "c3a-callback",
                "input_root": input_root, "output_root": root,
                "source5_execution_schema": module.SOURCE5_EXECUTION_SCHEMA_V5,
                "source5_execution_manifest": manifest,
                "source5_execution_manifest_raw_sha256": manifest_raw_sha,
                "source5_execution_manifest_pin": {
                    "path": str(manifest_path), "raw_sha256": manifest_raw_sha,
                },
                "source5_journal_width_projection": {
                    "contract": {
                        "schema": module.SOURCE5_JOURNAL_WIDTH_CONTRACT_SCHEMA_V2,
                    },
                },
                "source5_prepared_input_replay_required": True,
            }
            initial_stat = journal_path.stat()
            initial_file_key = (
                initial_stat.st_dev, initial_stat.st_ino, initial_stat.st_mode,
                initial_stat.st_size, initial_stat.st_mtime_ns, initial_stat.st_ctime_ns,
            )
            state = {**journal_value, "file_stat": initial_file_key}
            frontier = {"head_sha256": state["head"], "record_count": 1}
            scope = module._Source5OwnedOperationScope(
                module._SOURCE5_OWNED_OPERATION_SCOPE_SECRET,
            )
            deadline_ns = time.monotonic_ns() + 10_000_000_000
            body_binding = {"test": "body-pin"}
            scope_entry = {
                "frontier": {
                    "head_sha256": state["head"], "record_count": 1,
                    "file_stat": initial_file_key,
                },
                "binding": {"deadline_ns": deadline_ns},
                "current_h_context_input_body_binding_sha256":
                    module.sha256_bytes(module.canonical_bytes(body_binding)),
            }
            cancel_calls = []

            def cancel_callback():
                cancel_calls.append(target)
                if len(cancel_calls) == mutate_on:
                    if target == "input":
                        with control_path.open("ab") as stream:
                            stream.write(b"-mutated")
                    elif target == "journal":
                        with journal_path.open("ab") as stream:
                            stream.write(b"\n")
                return False

            class CaptureReader:
                def _open_root_checked(self):
                    return os.open(input_root, os.O_RDONLY |
                                   getattr(os, "O_DIRECTORY", 0))

            def check_deadline(_label):
                module.require(
                    not cancel_callback(),
                    "C3a test callback unexpectedly requested cancellation",
                )

            session = SimpleNamespace(
                check_deadline=check_deadline,
                prepared=prepared, execution_manifest_pin=execution_pin,
                route=module._Source5OwnedReplayRoute.SEALED_REFRESH,
                registration_head="b" * 64, frontier=frontier,
                journal_file_key=initial_file_key,
                input_snapshots=[control_snapshot], source_file_snapshots=[],
                root_snapshots=[], capture_reader=CaptureReader(),
                source_module_pins={"host-a": {}}, profile_pin=profile_pin,
                width_pin=width_pin, completion_pin=completion_pin,
                provenance=provenance, lock=object(), deadline_ns=deadline_ns,
            )

            def read_state(_lock, _prepared):
                current_info = journal_path.stat()
                current_key = (
                    current_info.st_dev, current_info.st_ino, current_info.st_mode,
                    current_info.st_size, current_info.st_mtime_ns, current_info.st_ctime_ns,
                )
                value = json.loads(journal_path.read_text())
                value["file_stat"] = current_key
                return value

            body_patch = {"test": "body-pin"}
            with patch.object(
                    module, "_source5_owned_scope_require",
                    side_effect=lambda *_args, **_kwargs: scope_entry), \
                    patch.object(
                        module, "_source5_owned_h_context_verified_input_body_binding",
                        return_value=body_patch), \
                    patch.object(
                        module, "_validate_source5_manifest_value_v5_structural",
                        return_value=manifest), \
                    patch.object(
                        module, "_source5_owned_replay_input_pin_map",
                        return_value={"host-a": profile_pin}), \
                    patch.object(
                        module, "_source5_journal_width_contract_pin_map",
                        return_value={"host-a": width_pin}), \
                    patch.object(
                        module, "_read_source5_v5_journal_structural",
                        side_effect=read_state):
                result = None
                caught = None
                try:
                    result = module._source5_owned_h_context_current_operation_data(
                        session, scope,
                    )
                except module.ChronologyError as error:
                    caught = error
            return (
                result, caught, len(cancel_calls), control_path.read_bytes(),
                journal_path.read_bytes(),
            )

    def test_last_false_cancel_callback_precedes_final_control_and_journal_closure(self) -> None:
        for target in ("input", "journal"):
            with self.subTest(target=target):
                _result, caught, calls, control_raw, journal_raw = \
                    self._run_current_data_cancel_mutation(target, mutate_on=1)
                self.assertIsInstance(caught, self.module.ChronologyError)
                self.assertEqual(calls, 1)
                if target == "input":
                    self.assertEqual(control_raw, b"current-profile-control-mutated")
                else:
                    self.assertEqual(journal_raw, self.module.canonical_bytes({
                        "head": "a" * 64, "record_count": 1,
                        "registration_head": "b" * 64,
                    }) + b"\n")

        result, caught, calls, control_raw, journal_raw = \
            self._run_current_data_cancel_mutation("journal", mutate_on=2)
        self.assertIsNone(caught)
        self.assertEqual(calls, 1)
        self.assertEqual(control_raw, b"current-profile-control")
        self.assertEqual(journal_raw, self.module.canonical_bytes({
            "head": "a" * 64, "record_count": 1,
            "registration_head": "b" * 64,
        }))
        self.assertEqual(result[1]["state"]["head"], "a" * 64)


if __name__ == "__main__":
    unittest.main()
