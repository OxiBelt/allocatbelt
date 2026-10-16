#!/usr/bin/env python3
"""Focused tests for preparatory remaining-space credits and raw provenance."""
from __future__ import annotations

import hashlib
import importlib.util
import tempfile
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


CONTROLLER_PATH = Path(__file__).with_name("application-source5-campaign.py")
SPEC = importlib.util.spec_from_file_location(
    "source5_preparatory_storage_controller_under_test", CONTROLLER_PATH,
)
assert SPEC is not None and SPEC.loader is not None
controller = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = controller
try:
    SPEC.loader.exec_module(controller)
except BaseException:
    sys.modules.pop(SPEC.name, None)
    raise


def reservation() -> dict:
    roots = [
        {"path": f"/private/{role}", "role": role,
         "reserved_bytes": 1000, "reserved_inodes": 20,
         "filesystem_id": str(index + 1)}
        for index, role in enumerate(("artifact", "output", "scratch", "evidence_store"))
    ]
    return {
        "pin": {"path": "/private/artifact/reservation.json",
                "raw_sha256": "a" * 64, "semantic_sha256": "b" * 64,
                "byte_count": 123},
        "roots": roots,
        "required_bytes_by_root": {row["path"]: 600 for row in roots},
        "required_inodes_by_root": {row["path"]: 12 for row in roots},
    }


class PreparatoryReadbackPathTests(unittest.TestCase):
    def test_control_ledger_path_uses_reserved_output_root(self) -> None:
        context = SimpleNamespace(
            output_root=Path("/reserved/output"), host_id="host-a",
            manifest={"campaign_id": "campaign-prep"},
        )
        self.assertEqual(
            controller._source5_preparatory_control_ledger_path(context),
            Path("/reserved/output/campaign-prep/source5/host-a/"
                 "archive-read-control.jsonl"),
        )


class PreparatorySealedHistoryBindingTests(unittest.TestCase):
    def _context_and_verifier(self):
        jobs = [{"host_id": "host-a", "ordinal": index + 1,
                 "run_id": f"prep-{index:03d}"} for index in range(360)]
        completion = {
            "path": "/inputs/generation.json", "raw_sha256": "a" * 64,
            "semantic_sha256": "b" * 64,
        }
        host_completion = {
            "path": "/inputs/host-completion.json", "raw_sha256": "c" * 64,
            "semantic_sha256": "d" * 64,
        }
        host_verification = {"path": "/inputs/host-verification.json",
                             "raw_sha256": "e" * 64,
                             "receipt_sha256": "f" * 64}
        ledger = {"path": "/output/capacity.jsonl", "raw_sha256": "1" * 64,
                  "terminal_head": "2" * 64}
        registration = {
            "completion": completion, "host_completion": host_completion,
            "host_verification": host_verification, "ledger": ledger,
            "capacity_schedule_sha256": "3" * 64,
            "registration_head": "4" * 64,
        }
        manifest = {
            "schema": controller.PREPARATORY_EXECUTION_SCHEMA,
            "campaign_id": "campaign-prep", "host_id": "host-a",
            "manifest_sha256": "5" * 64,
            "preparatory_capacity_generation": {"completion": completion},
        }
        width_pin = {"path": "/artifact/width.json", "raw_sha256": "6" * 64,
                     "semantic_sha256": "7" * 64}
        budget_pin = {"path": "/artifact/budget.json", "raw_sha256": "8" * 64,
                      "semantic_sha256": "9" * 64}
        state = {
            "prepared_capacity_registration": {
                "completion": completion, "host_completion": host_completion,
                "host_verification": host_verification,
                "capacity_ledger": ledger,
                "capacity_schedule_sha256": registration["capacity_schedule_sha256"],
            },
            "registration": None, "stage_completion": None,
            "registration_head": registration["registration_head"],
            "head": "a" * 64, "record_count": 7,
            "pending": None, "source5_pending": None,
            "cleanup_blocked": False, "source5_cleanup_blocked": False,
            "source5_failed_owner_window": False,
        }
        verification = {
            "schema": "allocatbelt.application-source5-preparatory-execution-verification.v1",
            "campaign_id": "campaign-prep", "host_id": "host-a",
            "execution_manifest": {
                "path": "/output/prep-manifest.json", "raw_sha256": "b" * 64,
                "semantic_sha256": manifest["manifest_sha256"],
            },
            "execution_basis_sha256": "c" * 64,
            "registration_head": registration["registration_head"],
            "initial_spec_pin": {"path": "/inputs/spec.json",
                                  "raw_sha256": "d" * 64,
                                  "semantic_sha256": "e" * 64},
            "initial_plan_pin": {"path": "/inputs/plan.json",
                                 "raw_sha256": "f" * 64,
                                 "semantic_sha256": "1" * 64},
            "capacity_generation_pin": completion,
            "journal_width_contract_pin": width_pin,
            "host_evidence_budget_pin": budget_pin,
            "job_count": 360,
            "job_list_sha256": controller.sha256(controller.canonical_bytes(jobs)),
            "journal_head": state["head"], "journal_record_count": 7,
            "qualification_eligible": False, "launch_authorized": False,
        }
        chronology = SimpleNamespace(
            _lock_token_is_live=lambda lock: True,
            _prepare_source5_context=lambda lock, pin: (
                manifest, {"prepared": True}, state, pin,
            ),
            _validate_source5_manifest_value=lambda *args, **kwargs: None,
        )
        chronology.validate_source5_preparatory_execution_manifest_locked = \
            lambda lock, pin: verification
        context = SimpleNamespace(
            chronology=chronology, manifest=manifest,
            manifest_pin={"path": "/output/prep-manifest.json",
                          "raw_sha256": "b" * 64},
            host_id="host-a", plan={"jobs": {"exploration": jobs}},
            preparatory_capacity_registration=registration,
            preparatory_execution_basis_sha256=verification[
                "execution_basis_sha256"],
            preparatory_width_pin=width_pin, preparatory_budget_pin=budget_pin,
            spec_pin={"path": "/inputs/spec.json", "raw_sha256": "d" * 64},
            spec_semantic_sha256="e" * 64,
            plan_pin={"path": "/inputs/plan.json", "raw_sha256": "f" * 64},
            plan_semantic_sha256="1" * 64,
        )
        return context, state, verification

    def test_post_setup_metadata_accepts_current_original_journal_head(self) -> None:
        context, state, verification = self._context_and_verifier()
        result = controller._validate_locked_context(context, object())
        self.assertEqual(verification["journal_record_count"], 7)
        self.assertIs(result["state"], state)
        self.assertEqual(result["capacity_replay"]["registration_head"],
                         verification["registration_head"])

    def test_post_setup_metadata_rejects_failed_window_and_head_mismatch(self) -> None:
        context, state, verification = self._context_and_verifier()
        state["source5_failed_owner_window"] = True
        with self.assertRaises(controller.Source5CampaignError):
            controller._validate_locked_context(context, object())
        state["source5_failed_owner_window"] = False
        verification["journal_record_count"] = 1
        with self.assertRaises(controller.Source5CampaignError):
            controller._validate_locked_context(context, object())


class PreparatoryRemainingStorageProjectionTests(unittest.TestCase):
    def test_projection_keeps_caller_reserve_and_subtracts_exact_credits(self) -> None:
        value = reservation()
        roots = [row["path"] for row in value["roots"]]
        byte_credits = {root: 100 for root in roots}
        inode_credits = {root: 2 for root in roots}
        remaining_bytes, remaining_inodes = \
            controller._source5_preparatory_remaining_projection(
                value, byte_credits, inode_credits,
            )
        self.assertEqual(remaining_bytes, {root: 900 for root in roots})
        self.assertEqual(remaining_inodes, {root: 18 for root in roots})

    def test_projection_rejects_overcredit_and_incomplete_root_domain(self) -> None:
        value = reservation()
        roots = [row["path"] for row in value["roots"]]
        byte_credits = {root: 0 for root in roots}
        inode_credits = {root: 0 for root in roots}
        byte_credits[roots[0]] = value["required_bytes_by_root"][roots[0]] + 1
        with self.assertRaises(controller.Source5CampaignError):
            controller._source5_preparatory_remaining_projection(
                value, byte_credits, inode_credits,
            )
        byte_credits[roots[0]] = 0
        inode_credits.pop(roots[-1])
        with self.assertRaises(controller.Source5CampaignError):
            controller._source5_preparatory_remaining_projection(
                value, byte_credits, inode_credits,
            )

    def test_catalogue_file_credit_requires_the_exact_raw_pin(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-prep-credit-") as temporary:
            path = Path(temporary) / "job-catalogue.jsonl"
            raw = b'{"job_index":0}\n'
            path.write_bytes(raw)
            path.chmod(0o600)
            row = {
                "path": str(path), "kind": "file",
                "role": "source5_job_row_catalogue",
                "storage_root": temporary,
                "max_file_bytes": len(raw),
                "origin_pin": {
                    "raw_sha256": hashlib.sha256(raw).hexdigest(),
                    "semantic_sha256": None,
                },
            }
            self.assertEqual(
                controller._source5_credit_preparatory_catalogue_file(
                    row, "test pinned job catalogue",
                ), (len(raw), 1),
            )
            path.write_bytes(b'{"job_index":1}\n')
            with self.assertRaises(controller.Source5CampaignError):
                controller._source5_credit_preparatory_catalogue_file(
                    row, "test changed job catalogue",
                )

    def test_setup_journal_credit_is_bound_to_sourcea_replayed_head(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-prep-journal-") as temporary:
            path = Path(temporary) / "dispatch-journal.jsonl"
            record = {
                "schema": "allocatbelt.application-source5-dispatch-journal.v1",
                "sequence": 1, "monotonic_ns": 1,
                "campaign_id": "campaign-prep", "host_id": "host-a",
                "boot_id_sha256": "c" * 64,
                "original_pins": {},
                "event": controller.PREPARATORY_SETUP_EVENT,
                "details": {},
            }
            unsigned = {"previous_sha256": "0" * 64, "record": record}
            head = hashlib.sha256(controller.canonical_bytes(unsigned)).hexdigest()
            envelope = {**unsigned, "record_sha256": head}
            raw = controller.canonical_bytes(envelope)
            path.write_bytes(raw)
            path.chmod(0o600)
            context = SimpleNamespace(manifest={
                "campaign_id": "campaign-prep", "host_id": "host-a",
            }, host_id="host-a")
            row = {"path": str(path), "max_file_bytes": len(raw)}
            core = {
                "journal_head": head, "registration_head": head,
                "journal_record_count": 1,
            }
            self.assertEqual(
                controller._source5_credit_preparatory_journal(
                    context, row, core,
                ), (len(raw), 1),
            )
            altered = dict(envelope)
            altered["record"] = {**record, "event": "source5_authorized"}
            path.write_bytes(controller.canonical_bytes(altered))
            with self.assertRaises(controller.Source5CampaignError):
                controller._source5_credit_preparatory_journal(
                    context, row, core,
                )


if __name__ == "__main__":
    unittest.main()
