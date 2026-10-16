#!/usr/bin/env python3
"""Pure schema tests for the isolated Source5 preparatory budget module."""
from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
import types
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("application-source5-preparatory-budget.py")
SPEC = importlib.util.spec_from_file_location(
    "source5_preparatory_budget_under_test", MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
prep = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = prep
try:
    SPEC.loader.exec_module(prep)
except BaseException:
    sys.modules.pop(SPEC.name, None)
    raise


def sealed(value: dict, field: str) -> dict:
    body = {key: item for key, item in value.items() if key != field}
    return {**body, field: prep._sha(prep.canonical_bytes(body))}


def artifact(path: str, byte: str = "a") -> dict:
    return {"path": path, "raw_sha256": byte * 64}


def pin(path: str, byte: str = "b", semantic: str = "c") -> dict:
    return {
        "path": path, "raw_sha256": byte * 64,
        "semantic_sha256": semantic * 64,
    }


def core() -> dict:
    hosts = ["host-a", "host-b", "host-c"]
    spec_pin = artifact("/inputs/spec.json", "1")
    plan_pin = artifact("/inputs/plan.json", "2")
    generation = {
        "completion": pin("/inputs/prepared-capacity-generation.json", "3", "4"),
        "provenance": {
            "schema": "allocatbelt.application-source5-preparatory-capacity-provenance.v1",
            "preparation_pin": artifact("/inputs/preparation.json", "5"),
            "initial_spec_pin": spec_pin,
            "initial_plan_pin": plan_pin,
        },
    }
    registration = {
        "completion": pin("/inputs/prepared-capacity-generation.json", "3", "4"),
        "host_completion": pin("/inputs/capacity/host-a.json", "6", "7"),
        "host_verification": {
            "path": "/inputs/capacity/host-a-receipt.json",
            "raw_sha256": "8" * 64, "receipt_sha256": "9" * 64,
        },
        "ledger": {
            "path": "/output/chronology/host-a/capacity.jsonl",
            "raw_sha256": "a" * 64, "terminal_head": "b" * 64,
        },
        "capacity_schedule_sha256": "c" * 64,
        "registration_head": "d" * 64,
    }
    return {
        "schema": prep.PREPARATORY_EXECUTION_SCHEMA,
        "campaign_id": "campaign-prep",
        "host_id": "host-a", "hosts": hosts,
        "original_inputs": {
            "spec": {"artifact": spec_pin, "semantic_sha256": "e" * 64},
            "plan": {"artifact": plan_pin, "semantic_sha256": "f" * 64},
            "source_manifests": {},
            "campaign_artifacts_root": "/inputs/campaign-artifacts",
        },
        "execution_sources": {}, "modules": {}, "observed_hosts": {},
        "artifact_root": "/artifact", "output_root": "/output",
        "scope": "preparatory_exploration",
        "phase_order": ["exploration"],
        "protocol_sha256": "1" * 64,
        "preparatory_capacity_generation": generation,
        "preparatory_capacity_registration": registration,
        "archive_signer_contexts": {"host-a": {
            "artifact": artifact("/private/host-a-signer.json", "2"),
            "semantic_sha256": "3" * 64,
        }},
        "qualification_eligible": False,
    }


def width_rows() -> list[dict]:
    counts = {
        "source5_authorized": 1, "source5_app_started": 2,
        "source5_app_terminal": 2, "source5_job_terminal": 1,
    }
    widths = {event: 120 for event in prep.PREPARATORY_JOURNAL_EVENTS}
    result = []
    for index in range(360):
        job = {
            # Original Plan ordinals repeat across allocator/control cells;
            # run_id plus job_index closes each job unambiguously.
            "host_id": "host-a", "ordinal": index % 6 + 1,
            "run_id": f"prep-job-{index:03d}",
        }
        line_bytes = sum(counts[event] * widths[event]
                         for event in prep.PREPARATORY_JOURNAL_EVENTS)
        result.append({
            "phase": "exploration", "job_index": index,
            "ordinal": job["ordinal"], "run_id": job["run_id"],
            "job_sha256": prep._sha(prep.canonical_bytes(job)),
            "event_counts": dict(counts),
            "maximum_event_bytes_by_kind": dict(widths),
            "failed_event_counts": dict(counts),
            "failed_event_bytes_by_kind": dict(widths),
            "success_job_bytes": line_bytes,
            "failed_window_bytes": line_bytes,
            "failed_event_count": 6,
            "failed_event_count_uplift": 0,
            "byte_uplift": 0,
        })
    return result


class PreparatoryExecutionBasisTests(unittest.TestCase):
    def test_basis_excludes_later_artifact_pins_and_seals_single_selected_host(self) -> None:
        value = core()
        basis = prep.build_execution_basis(value)
        full = {
            **value,
            "preparatory_journal_width_contracts": {"host-a": {
                "artifact": artifact("/artifact/width.json", "4"),
                "semantic_sha256": "5" * 64,
            }},
            "preparatory_host_budgets": {"host-a": {
                "artifact": artifact("/artifact/budget.json", "6"),
                "semantic_sha256": "7" * 64,
            }},
            "preparatory_execution_basis_sha256": basis,
        }
        sealed_manifest = prep.seal_execution_manifest(full)
        self.assertEqual(prep.validate_execution_manifest(sealed_manifest),
                         sealed_manifest)
        changed_pins = copy.deepcopy(sealed_manifest)
        changed_pins["preparatory_host_budgets"]["host-a"]["artifact"] = \
            artifact("/artifact/another-budget.json", "8")
        changed_pins["preparatory_host_budgets"]["host-a"]["semantic_sha256"] = \
            "9" * 64
        changed_pins = sealed(changed_pins, "manifest_sha256")
        self.assertEqual(prep.build_execution_basis(changed_pins), basis)
        self.assertNotEqual(prep.build_execution_basis({
            **value, "host_id": "host-b",
            "archive_signer_contexts": {"host-b": value[
                "archive_signer_contexts"]["host-a"]},
        }), basis)

    def test_non_singleton_preparation_artifact_maps_are_rejected(self) -> None:
        value = core()
        value["preparatory_journal_width_contracts"] = {
            "host-a": {"artifact": artifact("/artifact/w.json"),
                       "semantic_sha256": "c" * 64},
            "host-b": {"artifact": artifact("/artifact/other.json"),
                       "semantic_sha256": "d" * 64},
        }
        value["preparatory_host_budgets"] = {"host-a": {}}
        value["preparatory_execution_basis_sha256"] = \
            prep.build_execution_basis(core())
        value["manifest_sha256"] = "f" * 64
        with self.assertRaises(prep.PreparatoryBudgetError):
            prep.execution_basis_projection(value)


class PreparatoryWidthContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original = {
            "execution_basis_sha256": "e" * 64,
            "initial_spec": pin("/inputs/spec.json"),
            "initial_plan": pin("/inputs/plan.json"),
            "capacity_generation": pin("/inputs/generation.json"),
        }
        self.contract = prep.build_journal_width_contract(
            campaign_id="campaign-prep", host_id="host-a",
            execution_basis_sha256="e" * 64,
            original_pins=self.original,
            initial_spec_pin=pin("/inputs/spec.json"),
            initial_plan_pin=pin("/inputs/plan.json"),
            capacity_generation_pin=pin("/inputs/generation.json"),
            source_manifest_pin=pin("/inputs/source.json"),
            owner_pins={"fixed_pair": pin("/source/fixed.py")},
            setup_line_bytes=333, job_rows=width_rows(),
        )

    def test_setup_is_separate_and_full_original_callback_horizon_is_kept(self) -> None:
        self.assertEqual(self.contract["original_callback_event_count"], 2160)
        self.assertEqual(self.contract["setup_event_count"], 1)
        self.assertEqual(self.contract["total_event_count"], 2161)
        self.assertEqual(self.contract["total_event_bytes"],
                         333 + (360 * 720))
        self.assertEqual(self.contract["phase_totals"], [{
            "phase": "exploration", "job_count": 360,
            "event_count": 2160, "success_event_bytes": 360 * 720,
        }])
        self.assertEqual(self.contract["setup_event_widths"], [{
            "event": prep.PREPARATORY_SETUP_EVENT,
            "phase": "registration", "count": 1,
            "maximum_line_bytes": 333,
        }])

    def test_resealed_width_mutation_is_rejected_by_fresh_projection(self) -> None:
        mutant = copy.deepcopy(self.contract)
        mutant["job_rows"][0]["maximum_event_bytes_by_kind"][
            "source5_authorized"] = 1
        mutant = sealed(mutant, "contract_sha256")
        with self.assertRaises(prep.PreparatoryBudgetError):
            prep.validate_journal_width_contract(
                mutant, expected_campaign_id="campaign-prep",
                expected_host_id="host-a",
                expected_execution_basis_sha256="e" * 64,
                expected_original_pins=self.original,
                expected_job_rows=self.contract["job_rows"],
            )


class PreparatoryBudgetTests(unittest.TestCase):
    def _width(self) -> dict:
        core_value = core()
        basis = prep.build_execution_basis(core_value)
        job_width = width_rows()
        original = {"execution_basis_sha256": basis}
        return prep.build_journal_width_contract(
            campaign_id="campaign-prep", host_id="host-a",
            execution_basis_sha256=basis, original_pins=original,
            initial_spec_pin=pin("/inputs/spec.json"),
            initial_plan_pin=pin("/inputs/plan.json"),
            capacity_generation_pin=pin("/inputs/generation.json"),
            source_manifest_pin=pin("/inputs/source.json"),
            owner_pins={"fixed_pair": pin("/source/fixed.py")},
            setup_line_bytes=333, job_rows=job_width,
        )

    def _read_schedule(self, width: dict) -> list[dict]:
        rows = []
        for index, row in enumerate(width["job_rows"]):
            job = {"host_id": "host-a", "ordinal": row["ordinal"],
                   "run_id": row["run_id"]}
            rows.append({
                "analysis_phase": "exploration", "owner_phase": "exploration",
                "job_index": index, "job": job,
                "job_sha256": row["job_sha256"], "request_ordinal": index,
                "use": "capacity_pilot_export",
                "caps": {
                    "bundle_bytes": 10240, "maximum_request_bytes": 1024,
                    "maximum_response_bytes": 1024, "object_count": 10,
                    "stage_bytes": 4096,
                },
            })
        return rows

    def test_read_schedule_closes_all_repeating_plan_ordinals_by_run_id(self) -> None:
        width = self._width()
        checked = prep._validate_read_schedule(self._read_schedule(width), width)
        self.assertEqual(len(checked), 360)
        self.assertEqual([row["request_ordinal"] for row in checked],
                         list(range(360)))
        self.assertEqual([row["job"]["ordinal"] for row in checked[:12]],
                         [1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6])

    def test_read_schedule_rejects_plan_ordinal_substitution(self) -> None:
        width = self._width()
        rows = self._read_schedule(width)
        rows[6]["job"]["ordinal"] = 7
        rows[6]["job_sha256"] = prep._sha(prep.canonical_bytes(rows[6]["job"]))
        with self.assertRaises(prep.PreparatoryBudgetError):
            prep._validate_read_schedule(rows, width)

    def test_owner_profile_role_swap_is_rejected_against_typed_owner_paths(self) -> None:
        paths = {role: f"scripts/{role}.py"
                 for role in prep.OWNER_PROFILE_SOURCE_ROLES}
        module_pin = {"path": prep.OWNER_CATALOGUE_SOURCE_PATH,
                      "sha256": "a" * 64}
        owner_pins = {
            role: {"path": path, "raw_sha256": "b" * 64,
                   "byte_count": 100}
            for role, path in paths.items()
        }
        budget = {
            "original_pins": {"typed_modules": {
                prep.OWNER_CATALOGUE_SOURCE_PATH: module_pin,
            }},
            "owner_contract": {"owner_source_pins": owner_pins},
        }
        selected_owner = types.SimpleNamespace(
            __source5_typed_pin__=module_pin, OWNER_PATHS=paths,
        )
        self.assertEqual(prep._preparatory_owner_catalogue_paths(
            budget, selected_owner,
        ), paths)
        swapped = copy.deepcopy(budget)
        swapped["owner_contract"]["owner_source_pins"]["fixed_pair"]["path"], \
            swapped["owner_contract"]["owner_source_pins"]["pressure_pair"]["path"] = \
                paths["pressure_pair"], paths["fixed_pair"]
        with self.assertRaises(prep.PreparatoryBudgetError):
            prep._preparatory_owner_catalogue_paths(swapped, selected_owner)

    def test_readback_slot_caps_and_control_path_are_exact(self) -> None:
        transient_roles = {
            "source5_archive_read_request_slot",
            "source5_archive_read_response_slot",
            "source5_archive_read_response_incoming",
            "source5_archive_read_bundle",
            "source5_archive_read_bundle_incoming",
            "source5_archive_read_stage",
        }
        control_role = "source5_archive_read_control_ledger"
        caps = {("exploration", "run-1"): {
            "request_bytes": 100, "response_bytes": 200,
            "bundle_bytes": 300, "stage_bytes": 400,
            "stage_inodes": 5, "maximum_object_bytes": 250,
        }}
        scratch = "/scratch"
        output = "/output"
        readback_root = Path(scratch) / "campaign-prep" / "host-a" / "archive-readback"
        values = {
            "source5_archive_read_request_slot": ("file", 100, 100, 1, "request.json"),
            "source5_archive_read_response_slot": ("file", 200, 200, 1, "response.json"),
            "source5_archive_read_response_incoming": ("file", 200, 200, 1, "response.json.incoming"),
            "source5_archive_read_bundle": ("file", 300, 300, 1, "response.tar"),
            "source5_archive_read_bundle_incoming": ("file", 300, 300, 1, "response.tar.incoming"),
            "source5_archive_read_stage": ("tree", 400, 250, 5, "stage"),
        }
        rows = {}
        for role, (kind, maximum, maximum_file, inodes, basename) in values.items():
            rows[role] = {
                "path": str(readback_root / basename), "kind": kind, "role": role,
                "host_id": "host-a", "max_bytes": maximum,
                "max_file_bytes": maximum_file, "max_inodes": inodes,
                "storage_root": scratch, "owner": "source5_controller",
                "phase": None, "run_id": None, "member_index": None,
                "aggregate_id": None, "aggregate_max_bytes": None,
                "origin_pin": None,
            }
        rows[control_role] = {
            "path": str(Path(output) / "campaign-prep" / "source5" / "host-a" /
                         "archive-read-control.jsonl"),
            "kind": "file", "role": control_role, "host_id": "host-a",
            "max_bytes": 500, "max_file_bytes": 500, "max_inodes": 1,
            "storage_root": output, "owner": "source5_controller",
            "phase": None, "run_id": None, "member_index": None,
            "aggregate_id": None, "aggregate_max_bytes": None,
            "origin_pin": None,
        }
        args = {
            "campaign_id": "campaign-prep", "host_id": "host-a",
            "output_root": output, "scratch_root": scratch,
            "readback_caps": caps, "slot_rows": rows,
            "transient_roles": transient_roles, "control_role": control_role,
            "control": {"maximum_bytes": 500, "maximum_line_bytes": 250,
                        "maximum_event_count": 720},
        }
        prep._validate_preparatory_read_slot_rows(**args)
        stage_mutant = copy.deepcopy(rows)
        stage_mutant["source5_archive_read_stage"]["max_bytes"] = 1
        with self.assertRaises(prep.PreparatoryBudgetError):
            prep._validate_preparatory_read_slot_rows(
                **{**args, "slot_rows": stage_mutant},
            )
        control_mutant = copy.deepcopy(rows)
        control_mutant[control_role]["max_file_bytes"] = 1
        with self.assertRaises(prep.PreparatoryBudgetError):
            prep._validate_preparatory_read_slot_rows(
                **{**args, "slot_rows": control_mutant},
            )

    def test_preparatory_readiness_requires_literal_booleans(self) -> None:
        readiness = {
            "preparatory_budget_complete": True,
            "preparatory_execution_ready": True,
            "full_horizon_execution_ready": False,
            "component_gate_ready": False,
            "qualification_eligible": False,
        }
        self.assertEqual(prep._validate_readiness(readiness), readiness)
        mutant = dict(readiness)
        mutant["preparatory_execution_ready"] = 1
        with self.assertRaises(prep.PreparatoryBudgetError):
            prep._validate_readiness(mutant)


if __name__ == "__main__":
    unittest.main()
