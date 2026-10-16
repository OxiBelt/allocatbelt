#!/usr/bin/env python3
"""Source-pinned owner-schema catalogue regressions; no owner is executed."""

from __future__ import annotations

import hashlib
import ast
import importlib.util
import json
import sys
import types
from contextlib import ExitStack
from pathlib import Path
import unittest
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
MODULE_PATH = SCRIPT_DIR / "application-source5-evidence-catalogue.py"
SPEC = importlib.util.spec_from_file_location("source5_evidence_catalogue", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
catalogue = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(catalogue)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def source_fixture(root: Path = SCRIPT_DIR) -> tuple[dict[str, object], dict[str, bytes]]:
    raw_by_path = {
        relative: (root.parent / relative).read_bytes()
        for relative in catalogue.OWNER_PATHS.values()
    }
    rows = [{
        "path": relative, "kind": "file", "mode": "100644",
        "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw),
    } for relative, raw in sorted(raw_by_path.items())]
    body = {
        "schema": "allocatbelt.application-source-manifest.v5",
        "source": {"files": rows},
    }
    source = {**body, "manifest_sha256": hashlib.sha256(canonical(body)).hexdigest()}
    return source, raw_by_path


def repin_source(source: dict[str, object], raw_by_path: dict[str, bytes]) -> dict[str, object]:
    body = dict(source)
    body.pop("manifest_sha256", None)
    body["source"] = dict(body["source"])
    body["source"]["files"] = [
        {"path": relative, "kind": "file", "mode": "100644",
         "sha256": hashlib.sha256(raw_by_path[relative]).hexdigest(),
         "size": len(raw_by_path[relative])}
        for role, relative in sorted(catalogue.OWNER_PATHS.items(), key=lambda item: item[1])
    ]
    body["manifest_sha256"] = hashlib.sha256(canonical(body)).hexdigest()
    return body


class EvidenceCatalogueTests(unittest.TestCase):
    def test_closed_set_union_resolves_only_pinned_top_level_sequences(self) -> None:
        tree = ast.parse(
            'OWNED = ("stdout.log", "stderr.log")\n'
            'def inventory():\n'
            '    expected_direct = set(OWNED) | {"pressure"}\n',
        )
        self.assertEqual(catalogue._assigned_literal(
            tree, "inventory", "expected_direct", "Soak owner",
            dictionary=False,
        ), ["pressure", "stderr.log", "stdout.log"])
        unknown = ast.parse(
            'def inventory():\n'
            '    expected_direct = set(read_dynamic()) | {"pressure"}\n',
        )
        with self.assertRaises(catalogue.CatalogueError):
            catalogue._assigned_literal(
                unknown, "inventory", "expected_direct", "Soak owner",
                dictionary=False,
            )

    def test_fixed_member_slots_support_legacy_literal_and_shared_projection(self) -> None:
        legacy = ast.parse('def _construct_members():\n    outputs = {"stdout": 1}\n')
        self.assertEqual(catalogue._fixed_pair_member_slots(legacy), ["stdout"])
        shared = ast.parse(
            'def _construct_members(context, runtime_bindings):\n'
            '    return _project_members(context, runtime_bindings, identities)\n'
            'def _construct_members_closed_recorded(context, runtime_bindings):\n'
            '    return _project_members(context, runtime_bindings, identities)\n'
            'def _project_members(context, runtime_bindings, identities):\n'
            '    outputs = {"stdout": 1}\n',
        )
        self.assertEqual(catalogue._fixed_pair_member_slots(shared), ["stdout"])

    def test_rehashed_shared_projector_dispatch_drift_is_rejected(self) -> None:
        source, owner_bytes = source_fixture()
        fixed_path = catalogue.OWNER_PATHS["fixed_pair"]
        original = owner_bytes[fixed_path]
        call = b"return _project_members(context, runtime_bindings, identities)"
        self.assertEqual(original.count(call), 2)
        for ordinal in (0, 1):
            for replacement in (
                b"return _other_projector(context, runtime_bindings, identities)",
                b"return _project_members(context, identities, runtime_bindings)",
                b"return list(_project_members(context, runtime_bindings, identities))",
            ):
                with self.subTest(ordinal=ordinal, replacement=replacement):
                    chunks = original.split(call)
                    chunks[ordinal] += replacement
                    mutated = chunks[0] + (call if ordinal != 0 else b"") + chunks[1] + (call if ordinal != 1 else b"") + chunks[2]
                    changed = {**owner_bytes, fixed_path: mutated}
                    with self.assertRaises(catalogue.CatalogueError):
                        catalogue.inspect_owner_evidence_contracts(repin_source(source, changed), changed)

    def test_shared_projector_missing_or_ambiguous_schema_is_rejected(self) -> None:
        source, owner_bytes = source_fixture()
        fixed_path = catalogue.OWNER_PATHS["fixed_pair"]
        original = owner_bytes[fixed_path]
        for replacement in (b"output_paths = {", b"outputs = {}\n        outputs = {"):
            with self.subTest(replacement=replacement):
                changed = {**owner_bytes, fixed_path: original.replace(b"        outputs = {", b"        " + replacement, 1)}
                self.assertNotEqual(changed[fixed_path], original)
                with self.assertRaises(catalogue.CatalogueError):
                    catalogue.inspect_owner_evidence_contracts(repin_source(source, changed), changed)

    def test_cleanup_poll_interval_accepts_repeated_identical_source_calls(self) -> None:
        tree = ast.parse(
            "def cleanup():\n"
            "    time.sleep(0.01)\n"
            "    time.sleep(0.01)\n",
        )
        self.assertEqual(catalogue._function_call_numeric_argument(
            tree, "cleanup", "time", "sleep", 0,
            "cleanup schedule",
        ), 0.01)
        changed = ast.parse(
            "def cleanup():\n"
            "    time.sleep(0.01)\n"
            "    time.sleep(0.02)\n",
        )
        with self.assertRaises(catalogue.CatalogueError):
            catalogue._function_call_numeric_argument(
                changed, "cleanup", "time", "sleep", 0,
                "cleanup schedule",
            )

    def test_actual_pinned_owner_schemas_and_role_conflict_are_explicit(self) -> None:
        source, owner_bytes = source_fixture()
        result = catalogue.inspect_owner_evidence_contracts(source, owner_bytes)
        self.assertEqual(result["fixed_pair"]["file_slots_per_pair"], 32)
        pressure_slots = result["pressure_pair"]["member_output_slots"]
        self.assertIn("finalization_receipt", pressure_slots)
        self.assertEqual(
            result["pressure_pair"]["file_slots_per_member"],
            len(set(pressure_slots) - {"root", "trace_directory"}),
        )
        self.assertEqual(
            result["pressure_pair"]["file_slots_per_member"],
            len(set(result["pressure_pair"]["source5_path_builder_slots"]) -
                {"root", "trace_directory"}),
        )
        self.assertEqual(result["soak"]["reader_limits"]["MAX_TERMINAL_BYTES"],
                         32 * 1024 * 1024 * 1024)
        self.assertEqual(result["role_ceiling_conflicts"][
            "chronology_soak_role_bytes"], 1024 * 1024 * 1024)
        self.assertIs(result["role_ceiling_conflicts"][
            "requires_versioned_budget_role"], True)
        self.assertIs(result["exact_full_path_catalogue_complete"], False)
        self.assertIs(result["execution_ready"], False)
        self.assertIs(result["qualification_eligible"], False)
        self.assertEqual(result["cleanup_source_shape"][
            "maximum_session_members_per_snapshot"],
            result["fixed_pair"]["limits"]["MAX_PROC_ENTRIES"],
        )
        self.assertEqual(result["cleanup_source_shape"][
            "maximum_pidfd_signal_entries_per_snapshot"],
            result["fixed_pair"]["limits"]["MAX_PROC_ENTRIES"],
        )
        self.assertEqual(result["cleanup_source_shape"]["maximum_signal_snapshots"], 5)
        self.assertEqual(result["cleanup_source_shape"]["maximum_cleanup_errors"], 1348)
        self.assertEqual(result["cleanup_source_shape"]["maximum_error_text_bytes"], 8192)

    def test_unpinned_source_bytes_are_rejected(self) -> None:
        source, owner_bytes = source_fixture()
        changed = dict(owner_bytes)
        fixed_path = catalogue.OWNER_PATHS["fixed_pair"]
        changed[fixed_path] += b"\n# unpinned mutation\n"
        with self.assertRaises(catalogue.CatalogueError):
            catalogue.inspect_owner_evidence_contracts(source, changed)

    def test_rehashed_fixed_output_slot_change_is_rejected(self) -> None:
        source, owner_bytes = source_fixture()
        changed = dict(owner_bytes)
        fixed_path = catalogue.OWNER_PATHS["fixed_pair"]
        changed[fixed_path] = changed[fixed_path].replace(
            b'"probe_tmpdir": str(root / "probes" / "tmp" / slug),',
            b'"extra_slot": root, "probe_tmpdir": str(root / "probes" / "tmp" / slug),',
            1,
        )
        self.assertNotEqual(changed[fixed_path], owner_bytes[fixed_path])
        pinned = repin_source(source, changed)
        with self.assertRaises(catalogue.CatalogueError):
            catalogue.inspect_owner_evidence_contracts(pinned, changed)

    def test_rehashed_pressure_path_builder_drift_is_rejected(self) -> None:
        source, owner_bytes = source_fixture()
        changed = dict(owner_bytes)
        controller_path = catalogue.OWNER_PATHS["source5_controller"]
        changed[controller_path] = changed[controller_path].replace(
            b'"trace_directory": trace,', b'"trace_root": trace,', 1,
        )
        self.assertNotEqual(changed[controller_path],
                            owner_bytes[controller_path])
        pinned = repin_source(source, changed)
        with self.assertRaises(catalogue.CatalogueError):
            catalogue.inspect_owner_evidence_contracts(pinned, changed)

    def test_pressure_catalogue_caps_cover_every_typed_member_output_slot(self) -> None:
        source, owner_bytes = source_fixture()
        contract = catalogue.inspect_owner_evidence_contracts(source, owner_bytes)
        expected = set(contract["pressure_pair"]["member_output_slots"]) - {
            "root", "trace_directory",
        }
        controller_path = SCRIPT_DIR / "application-source5-campaign.py"
        tree = ast.parse(controller_path.read_bytes(), filename=str(controller_path))
        function = next(node for node in tree.body
                        if isinstance(node, ast.FunctionDef) and
                        node.name == "_source5_path_catalogue_records")
        cap_values = [
            node.value for node in ast.walk(function)
            if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == "member_caps"
                for target in node.targets
            )
        ]
        self.assertEqual(len(cap_values), 1)
        self.assertIsInstance(cap_values[0], ast.Dict)
        observed = {
            key.value for key in cap_values[0].keys
            if isinstance(key, ast.Constant) and type(key.value) is str
        }
        self.assertEqual(observed, expected)
        self.assertIn("finalization_receipt", observed)

    def test_owner_contract_digest_does_not_authorize_readiness(self) -> None:
        source, owner_bytes = source_fixture()
        result = catalogue.inspect_owner_evidence_contracts(source, owner_bytes)
        self.assertIs(catalogue.validate_contract_summary(result), result)
        altered = dict(result)
        altered["exact_full_path_catalogue_complete"] = True
        with self.assertRaises(catalogue.CatalogueError):
            catalogue.validate_contract_summary(altered)

    def test_final_run_owner_gate_precedes_phase_owner_dispatch(self) -> None:
        controller_path = SCRIPT_DIR / "application-source5-campaign.py"
        spec = importlib.util.spec_from_file_location("catalogue_admission_controller", controller_path)
        controller = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = controller
        spec.loader.exec_module(controller)
        context = types.SimpleNamespace(
            scope="final_frozen", host_id="host-admission",
            manifest={"schema": controller.EXECUTION_SCHEMA_V4, "campaign_id": "campaign-admission"})
        material = Path("/private/source-owned-material-index.json")
        owners = ("run_fixed_phase", "run_pressure_phase", "run_soak_phase", "analyze_phase",
                  "finalize_host_evidence")
        for phase in ("all", "exploration", "aa", "confirmation", "fixed_analysis",
                      "pressure", "pressure_analysis", "soak", "final_analysis"):
            with self.subTest(phase=phase), ExitStack() as stack:
                admission = stack.enter_context(mock.patch.object(
                    controller, "activate_source5_host_evidence_budget_v3",
                    side_effect=controller.Source5CampaignError("injected whole-host admission refusal")))
                runners = [stack.enter_context(mock.patch.object(controller, name)) for name in owners]
                with self.assertRaisesRegex(controller.Source5CampaignError, "injected whole-host admission refusal"):
                    controller.run_host(context, phase, material, material, material)
                admission.assert_called_once_with(context, material, material, material)
                for runner in runners:
                    runner.assert_not_called()
        events = []
        pin = {"path": "/private/budget.json", "raw_sha256": "a" * 64, "semantic_sha256": "b" * 64}
        with mock.patch.object(controller, "activate_source5_host_evidence_budget_v3",
                               side_effect=lambda *_args: events.append("admission") or pin), \
                mock.patch.object(controller, "run_fixed_phase",
                                  side_effect=lambda *_args: events.append("owner") or {"blocked": False}):
            result = controller.run_host(context, "aa", material, material, material)
        self.assertEqual(events, ["admission", "owner"])
        self.assertEqual(context.host_evidence_budget_pin, pin)
        self.assertFalse(result["campaign_qualification_eligible"])


if __name__ == "__main__":
    unittest.main()
