"""Capacity-only generation tests with explicit Source/stage replay boundaries.

Real pinned private files are used. A mocked stage verifier supplies the
45-context producer projection; these cases establish no native capacity.
"""
import contextlib
import copy
import builtins
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import symtable
from types import SimpleNamespace
import unittest
from unittest import mock

path = Path(__file__).with_name("application-source5-input-preparation.py")
spec = importlib.util.spec_from_file_location("capacity_generation_tests", path)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class CapacityGenerationTests(unittest.TestCase):
    def test_final_completion_has_no_unbound_globals_after_capacity_extraction(self):
        table = symtable.symtable(path.read_text(), str(path), "exec")
        function = next(child for child in table.get_children()
                        if child.get_name() == "complete_prepared_inputs")
        unresolved = [symbol.get_name() for symbol in function.get_symbols()
                      if symbol.is_referenced() and symbol.is_global() and
                      symbol.get_name() not in vars(m) and
                      symbol.get_name() not in vars(builtins)]
        self.assertEqual(unresolved, [])

    @contextlib.contextmanager
    def case(self):
        with tempfile.TemporaryDirectory(prefix="source5-capacity-generation-") as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            prep_path = root / "preparation.json"
            prep_path.write_bytes(b"{}\n")
            prep_path.chmod(0o600)
            prep_pin = {"path": str(prep_path), "sha256": hashlib.sha256(prep_path.read_bytes()).hexdigest()}
            hosts = ["host-1", "host-2", "host-3"]
            cells = [{"workload": "mixed", "profile": f"context-{i}"} for i in range(15)]
            preparation = {
                "core": {"campaign_id": "campaign", "hosts": [{"host_id": h} for h in hosts], "cells": cells},
                "preparation_sha256": "a" * 64,
                "source_pins": {h: {"modules": {"capacity_stage": {"sha256": "b" * 64}}} for h in hosts},
                "observed_hosts": {h: {"relative_path": h + ".observed.json", "raw_sha256": "c" * 64} for h in hosts},
            }
            budgets, inputs, results = {}, [], {}
            for host in hosts:
                (root / (host + ".observed.json")).write_bytes(b"{}\n")
                budget_path = root / (host + ".budget.json")
                budget_path.write_bytes(b"{}\n")
                budget_path.chmod(0o600)
                budgets[host] = {"path": str(budget_path),
                                 "raw_sha256": hashlib.sha256(budget_path.read_bytes()).hexdigest(),
                                 "semantic_sha256": "d" * 64}
                stage = root / "capacity-output" / "campaign" / host / "capacity"
                stage.mkdir(parents=True)
                value = {"host_id": host, "stage_directory": str(stage), "resource_monitor": {"report_count": 30}}
                completion_path = stage / "completion.json"
                completion_path.write_bytes(m._canonical(value))
                completion_path.chmod(0o600)
                pin = {"path": str(completion_path), "raw_sha256": hashlib.sha256(completion_path.read_bytes()).hexdigest()}
                inputs.append({"host_id": host, "completion_pin": pin,
                               "verification_receipt_pin": {"path": str(root / (host + ".host.json")),
                                                            "raw_sha256": "e" * 64, "receipt_sha256": "f" * 64},
                               "evidence_path_map": {"fixture": "identity"}})
                results[host] = {
                    "host_id": host, "complete": True, "qualification_eligible": False,
                    "preparation_raw_sha256": prep_pin["sha256"],
                    "preparation_semantic_sha256": preparation["preparation_sha256"],
                    "resource_budget": copy.deepcopy(budgets[host]), "completion_sha256": "1" * 64,
                    "ledger_raw_sha256": "2" * 64, "terminal_head": "3" * 64,
                    "capacity_preparation_templates_sha256": "4" * 64,
                    "entries": [{"capacity_key": {"host_id": host, **cell, "calibration_id": f"capacity-{i}"}}
                                for i, cell in enumerate(cells)],
                }
            stage_module = SimpleNamespace(
                _validate_evidence_path_map=mock.Mock(side_effect=lambda value: value),
                _map_evidence_path=mock.Mock(side_effect=lambda path, mapping: path),
                verify_capacity_preparation_bounded_offline=mock.Mock(
                    side_effect=lambda *args: copy.deepcopy(results[args[4]])),
            )
            with mock.patch.object(m, "read_preparation_intent", return_value=(preparation, {h: {} for h in hosts}, object(), object())), \
                 mock.patch.object(m, "_capture_typed_source_file", return_value=(b"captured stage bytes", path, {"sha256": "b" * 64})), \
                 mock.patch.object(m, "_execute_captured_module", return_value=stage_module):
                yield SimpleNamespace(root=root, preparation=preparation, prep_pin=prep_pin,
                                      budgets=budgets, inputs=inputs, results=results, stage=stage_module)

    def replay(self, c):
        return m.replay_prepared_capacity_inputs_bounded(
            c.prep_pin, c.inputs, c.budgets, m.SOURCE_ROOT, c.root,
        )

    def build(self, c):
        return m.build_prepared_capacity_generation_bounded(
            c.prep_pin, c.inputs, c.budgets, m.SOURCE_ROOT, c.root,
            c.root / "prepared-capacity-generation.json",
        )

    def test_capacity_only_replays_all_45_contexts_without_final_spec(self):
        with self.case() as c:
            value = self.replay(c)
            self.assertEqual(c.stage.verify_capacity_preparation_bounded_offline.call_count, 3)
            self.assertEqual(sum(len(row["entries"]) for row in value["capacity_preparations"]), 45)
            self.assertEqual(value["schema"], m.PREPARED_CAPACITY_GENERATION_SCHEMA)
            self.assertTrue(value["complete"])
            self.assertFalse(value["qualification_eligible"])
            self.assertFalse({"final_spec", "final_plan", "rates", "oracles"} & set(value))

    def test_persisted_generation_replays_same_original_inputs(self):
        with self.case() as c:
            pin = self.build(c)
            result = m.verify_prepared_capacity_generation_bounded(pin, c.prep_pin, m.SOURCE_ROOT, c.root)
            self.assertEqual(result, self.replay(c))
            self.assertEqual((c.root / "prepared-capacity-generation.json").stat().st_mode & 0o777, 0o600)

    def test_identical_rebuild_is_idempotent(self):
        with self.case() as c:
            self.assertEqual(self.build(c), self.build(c))

    def test_missing_host_or_budget_cannot_create_generation(self):
        with self.case() as c:
            c.inputs.pop()
            with self.assertRaisesRegex(m.PreparationError, "all three"):
                self.replay(c)
        with self.case() as c:
            c.budgets.pop("host-3")
            with self.assertRaisesRegex(m.PreparationError, "all three"):
                self.replay(c)

    def test_reordered_original_hosts_are_rejected(self):
        with self.case() as c:
            c.inputs.reverse()
            with self.assertRaisesRegex(m.PreparationError, "frozen host order"):
                self.replay(c)

    def test_capacity_verifier_failure_propagates(self):
        with self.case() as c:
            c.stage.verify_capacity_preparation_bounded_offline.side_effect = ValueError("original receipt changed")
            with self.assertRaisesRegex(m.PreparationError, "original receipt changed"):
                self.replay(c)

    def test_incomplete_or_foreign_original_capacity_rejected(self):
        for key, value in (("complete", False), ("qualification_eligible", True),
                           ("preparation_raw_sha256", "0" * 64)):
            with self.subTest(key=key), self.case() as c:
                c.results["host-2"][key] = value
                with self.assertRaisesRegex(m.PreparationError, "another generation"):
                    self.replay(c)

    def test_duplicate_capacity_context_rejected(self):
        with self.case() as c:
            entries = c.results["host-1"]["entries"]
            entries[-1] = copy.deepcopy(entries[0])
            with self.assertRaisesRegex(m.PreparationError, "repeats or crosses"):
                self.replay(c)

    def test_changed_capacity_budget_rejected(self):
        with self.case() as c:
            c.results["host-2"]["resource_budget"]["raw_sha256"] = "0" * 64
            with self.assertRaisesRegex(m.PreparationError, "different budget pin"):
                self.replay(c)

    def test_unrelated_source_or_input_root_rejected_before_stage_replay(self):
        with self.case() as c:
            with self.assertRaisesRegex(m.PreparationError, "actual Source/input roots"):
                m.replay_prepared_capacity_inputs_bounded(c.prep_pin, c.inputs, c.budgets, c.root, c.root)
            c.stage.verify_capacity_preparation_bounded_offline.assert_not_called()

    def test_generation_output_has_one_fixed_private_location(self):
        with self.case() as c:
            with self.assertRaisesRegex(m.PreparationError, "fixed private"):
                m.build_prepared_capacity_generation_bounded(c.prep_pin, c.inputs, c.budgets, m.SOURCE_ROOT, c.root, c.root / "other.json")
            c.stage.verify_capacity_preparation_bounded_offline.assert_not_called()

    def test_changed_generation_bytes_fail_original_raw_pin(self):
        with self.case() as c:
            pin = self.build(c)
            p = Path(pin["path"])
            p.write_bytes(p.read_bytes() + b" ")
            with self.assertRaises(m.PreparationError):
                m.verify_prepared_capacity_generation_bounded(pin, c.prep_pin, m.SOURCE_ROOT, c.root)

    def test_repinned_qualification_claim_rejected(self):
        with self.case() as c:
            pin = self.build(c)
            value = m.json.loads(Path(pin["path"]).read_bytes())
            value["qualification_eligible"] = True
            body = {k: v for k, v in value.items() if k != "generation_sha256"}
            value["generation_sha256"] = hashlib.sha256(m._canonical(body)).hexdigest()
            raw = m._canonical(value)
            Path(pin["path"]).write_bytes(raw)
            pin.update(raw_sha256=hashlib.sha256(raw).hexdigest(), semantic_sha256=value["generation_sha256"])
            with self.assertRaisesRegex(m.PreparationError, "schema, flags"):
                m.verify_prepared_capacity_generation_bounded(pin, c.prep_pin, m.SOURCE_ROOT, c.root)

    def test_replay_rejects_changed_producer_after_generation_was_sealed(self):
        with self.case() as c:
            pin = self.build(c)
            c.results["host-3"]["ledger_raw_sha256"] = "9" * 64
            with self.assertRaisesRegex(m.PreparationError, "full original bounded"):
                m.verify_prepared_capacity_generation_bounded(pin, c.prep_pin, m.SOURCE_ROOT, c.root)


if __name__ == "__main__":
    unittest.main()
