#!/usr/bin/env python3
"""Focused tests for Source5 setup-only capacity registration and replay."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import types
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest import mock


DEFAULT_TARGET = Path(__file__).with_name("application-campaign-chronology.py")
TARGET_PATH = Path(os.environ.get("ALLOCATBELT_CHRONOLOGY_TARGET",
                                 str(DEFAULT_TARGET)))


def load_target():
    spec = importlib.util.spec_from_file_location(
        "preparatory_registration_chronology_target", TARGET_PATH,
    )
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load chronology target: {TARGET_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


chronology = load_target()


def canonical(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def private(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True)
    os.chmod(path, 0o700)
    return path


def write_private(path: Path, raw: bytes, mode: int = 0o600) -> Path:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    path.write_bytes(raw)
    os.chmod(path, mode)
    return path


class PreparationFixture:
    """Private inputs plus a narrow fake Source helper at the actual loader seam."""

    def __init__(self, root: Path):
        self.root = root
        self.input_root = private(root / "inputs")
        self.source_root = private(root / "source")
        private(self.source_root / "scripts")
        self.output_root = private(root / "output")
        self.campaign_id = "campaign-prep-test"
        self.host_ids = ["host-a", "host-b", "host-c"]
        self.host_id = self.host_ids[0]
        self.helper_path = self.source_root / "scripts" / "application-source5-input-preparation.py"
        self.helper_raw = b"# fixture boundary; never executed as Source\n"
        write_private(self.helper_path, self.helper_raw, 0o644)

        self.core = {"capacity_only": True, "campaign_id": self.campaign_id}
        self.sources = {
            host: {"source_tree_sha256": f"{index + 1:064x}"}
            for index, host in enumerate(self.host_ids)
        }
        intent_body = {
            "schema": "allocatbelt.application-source5-preparation-intent.fixture",
            "core": self.core, "campaign_id": self.campaign_id,
        }
        self.intent = {
            **intent_body, "preparation_sha256": sha(canonical(intent_body)),
        }
        self.preparation_path = self.input_root / "preparation-intent.json"
        self.preparation_raw = write_private(self.preparation_path,
                                             canonical(self.intent)).read_bytes()

        self.spec_path = self.input_root / "initial-spec.json"
        self.spec = {
            "schema": "allocatbelt.application-campaign-spec.v3",
            "campaign_id": self.campaign_id,
            "rates": [], "oracles": [], "core": self.core,
            "hosts": [{"host_id": host} for host in self.host_ids],
        }
        self.spec_raw = write_private(self.spec_path, canonical(self.spec)).read_bytes()
        self.plan_path = self.input_root / "initial-plan.json"
        self.plan = {
            "schema": "allocatbelt.application-campaign-plan.v3",
            "campaign_id": self.campaign_id,
            "capacity_process_templates_sha256": "a" * 64,
        }
        self.plan_raw = write_private(self.plan_path, canonical(self.plan)).read_bytes()

        self.capacity_rows = [self._capacity_row(host, index)
                              for index, host in enumerate(self.host_ids)]
        self.generation = self._seal_preparatory_generation()

        self.prepared = {
            "campaign_id": self.campaign_id, "host_id": self.host_id,
            "output_root": self.output_root,
            "input_root": self.input_root, "source_root": self.source_root,
            "spec": self.spec, "plan": self.plan, "sources": copy.deepcopy(self.sources),
            "source": {"schema": "fixture SourceV5 boundary"},
            "original_pins": {
                "spec": {"path": str(self.spec_path),
                         "raw_sha256": sha(self.spec_raw)},
                "plan": {"path": str(self.plan_path),
                         "raw_sha256": sha(self.plan_raw)},
                "source_manifests": {
                    host: {"path": str(self.input_root / f"{host}.source.json"),
                           "raw_sha256": f"{index + 1:064x}"}
                    for index, host in enumerate(self.host_ids)
                },
            },
            "boot_id_sha256": "b" * 64,
            "prepared": {
                "spec_path": self.spec_path,
                "spec_raw_sha256": sha(self.spec_raw),
                "spec_semantic_sha256": "c" * 64,
                "plan_path": self.plan_path,
                "plan_raw_sha256": sha(self.plan_raw),
                "plan_semantic_sha256": "d" * 64,
                "host_context_path": self.input_root / "host-context.json",
                "host_context_raw_sha256": "e" * 64,
            },
        }
        self.spec_pin = {
            "path": str(self.spec_path), "raw_sha256": sha(self.spec_raw),
            "semantic_sha256": "c" * 64,
        }
        self.plan_pin = {
            "path": str(self.plan_path), "raw_sha256": sha(self.plan_raw),
            "semantic_sha256": "d" * 64,
        }
        self.observed_pin = {
            "path": str(self.input_root / "observed-host.json"),
            "raw_sha256": "f" * 64,
        }

    def _capacity_row(self, host: str, index: int) -> dict:
        entries = [{"slot": slot, "path": f"{host}/capacity/{slot}.json"}
                   for slot in range(15)]
        completion_path = self.input_root / f"{host}-capacity-completion.json"
        return {
            "host_id": host,
            "completion": {"path": str(completion_path),
                           "raw_sha256": f"{index + 10:064x}"},
            "completion_sha256": f"{index + 20:064x}",
            "host_verification": {
                "path": str(self.input_root / f"{host}-host-verification.json"),
                "raw_sha256": f"{index + 30:064x}",
                "receipt_sha256": f"{index + 40:064x}",
            },
            "ledger": {
                "path": str(self.input_root / f"{host}-capacity-ledger.jsonl"),
                "raw_sha256": f"{index + 50:064x}",
                "terminal_head": f"{index + 60:064x}",
            },
            "capacity_preparation_templates_sha256":
                self.plan["capacity_process_templates_sha256"],
            "entries": entries,
        }

    def _seal_preparatory_generation(self) -> dict:
        prep_pin = {"path": str(self.preparation_path),
                    "raw_sha256": sha(self.preparation_raw)}
        prep_projection = {
            **prep_pin, "semantic_sha256": self.intent["preparation_sha256"],
        }
        body = {
            "schema": "allocatbelt.application-source5-prepared-capacity-generation.v1",
            "campaign_id": self.campaign_id,
            "complete": True, "qualification_eligible": False,
            "preparation": prep_projection,
            "capacity_preparations": self.capacity_rows,
        }
        generation = {**body, "generation_sha256": sha(canonical(body))}
        self.completion_path = self.input_root / "prepared-capacity-generation.json"
        self.completion_raw = write_private(
            self.completion_path, canonical(generation),
        ).read_bytes()
        self.completion_pin = {
            "path": str(self.completion_path),
            "raw_sha256": sha(self.completion_raw),
            "semantic_sha256": generation["generation_sha256"],
        }
        self.provenance = {
            "schema": chronology.SOURCE5_PREPARATORY_CAPACITY_PROVENANCE_SCHEMA,
            "preparation_pin": prep_pin,
            "initial_spec_pin": {"path": str(self.spec_path),
                                 "raw_sha256": sha(self.spec_raw)},
            "initial_plan_pin": {"path": str(self.plan_path),
                                 "raw_sha256": sha(self.plan_raw)},
        }
        return generation

    def fake_helper(self):
        fixture = self

        class Inputs:
            @staticmethod
            def preparation_core_from_spec(spec):
                return spec["core"]

        def read_preparation_intent(pin, source_root, input_root):
            raw = Path(pin["path"]).read_bytes()
            if sha(raw) != pin["sha256"]:
                raise ValueError("preparation intent raw pin changed")
            return json.loads(raw), fixture.sources, fixture.campaign_id, Inputs()

        def verify_capacity(completion_pin, prep_pin, source_root, input_root):
            raw = Path(completion_pin["path"]).read_bytes()
            if sha(raw) != completion_pin["raw_sha256"]:
                raise ValueError("capacity-generation raw pin changed")
            value = json.loads(raw)
            if value.get("generation_sha256") != completion_pin["semantic_sha256"]:
                raise ValueError("capacity-generation semantic pin changed")
            if sha(Path(prep_pin["path"]).read_bytes()) != prep_pin["sha256"]:
                raise ValueError("preparation-intent raw pin changed")
            return value

        def verify_final(completion_pin, provenance, source_root, input_root):
            raw = Path(completion_pin["path"]).read_bytes()
            if sha(raw) != completion_pin["raw_sha256"]:
                raise ValueError("final completion raw pin changed")
            return json.loads(raw)

        return types.SimpleNamespace(
            read_preparation_intent=read_preparation_intent,
            _verify_spec_source_refs=lambda spec, intent, sources: None,
            verify_prepared_capacity_generation_bounded=verify_capacity,
            verify_prepared_inputs_completion=verify_final,
        )

    @contextmanager
    def source_helper_boundary(self):
        helper = self.fake_helper()
        row = {
            "path": "scripts/application-source5-input-preparation.py",
            "kind": "file", "mode": "100644",
            "sha256": sha(self.helper_raw), "size": len(self.helper_raw),
        }
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(
                chronology, "_source_file",
                return_value=(self.helper_raw, sha(self.helper_raw), row),
            ))
            stack.enter_context(mock.patch.object(
                chronology, "_load_module", return_value=helper,
            ))
            yield helper

    def make_registration_line(self, details: dict) -> bytes:
        record = {
            "schema": chronology.JOURNAL_SCHEMA, "sequence": 1,
            "monotonic_ns": 1, "campaign_id": self.campaign_id,
            "host_id": self.host_id,
            "boot_id_sha256": self.prepared["boot_id_sha256"],
            "original_pins": self.prepared["original_pins"],
            "event": "source5_prepared_capacity_registered",
            "details": details,
        }
        unsigned = {"previous_sha256": "0" * 64, "record": record}
        return chronology.canonical_bytes({
            **unsigned,
            "record_sha256": sha(chronology.canonical_bytes(unsigned)),
        })


def rewrite_first_record(raw: bytes, mutate) -> bytes:
    envelope = json.loads(raw.splitlines()[0])
    record = copy.deepcopy(envelope["record"])
    mutate(record)
    unsigned = {"previous_sha256": envelope["previous_sha256"],
                "record": record}
    record_sha = sha(chronology.canonical_bytes(unsigned))
    return chronology.canonical_bytes({**unsigned, "record_sha256": record_sha})


class PreparatoryGenerationVerifierTests(unittest.TestCase):
    def test_actual_private_generation_uses_the_captured_source_helper_boundary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-prep-verifier-") as tmp:
            fixture = PreparationFixture(Path(tmp))
            generation = {
                "completion": fixture.completion_pin,
                "provenance": fixture.provenance,
            }
            with fixture.source_helper_boundary() as helper:
                verified = chronology._verify_source5_prepared_input_generation(
                    None, fixture.prepared, generation,
                )
            self.assertEqual(verified, fixture.generation)
            self.assertEqual(
                [row["host_id"] for row in verified["capacity_preparations"]],
                fixture.host_ids,
            )
            self.assertFalse(verified["qualification_eligible"])

    def test_mutated_source_core_or_cohort_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-prep-core-") as tmp:
            fixture = PreparationFixture(Path(tmp))
            fixture.prepared["spec"]["core"] = {"capacity_only": False}
            with fixture.source_helper_boundary():
                with self.assertRaisesRegex(
                        chronology.ChronologyError,
                        "changed its frozen core or Source cohort"):
                    chronology._verify_source5_prepared_input_generation(
                        None, fixture.prepared, {
                            "completion": fixture.completion_pin,
                            "provenance": fixture.provenance,
                        },
                    )

        with tempfile.TemporaryDirectory(prefix="source5-prep-cohort-") as tmp:
            fixture = PreparationFixture(Path(tmp))
            fixture.prepared["sources"]["host-a"]["source_tree_sha256"] = "f" * 64
            with fixture.source_helper_boundary():
                with self.assertRaisesRegex(
                        chronology.ChronologyError,
                        "changed its frozen core or Source cohort"):
                    chronology._verify_source5_prepared_input_generation(
                        None, fixture.prepared, {
                            "completion": fixture.completion_pin,
                            "provenance": fixture.provenance,
                        },
                    )

    def test_changed_initial_spec_or_plan_raw_pin_is_rejected(self) -> None:
        for field in ("initial_spec_pin", "initial_plan_pin"):
            with self.subTest(field=field):
                with tempfile.TemporaryDirectory(prefix="source5-prep-pin-") as tmp:
                    fixture = PreparationFixture(Path(tmp))
                    provenance = copy.deepcopy(fixture.provenance)
                    provenance[field]["raw_sha256"] = "f" * 64
                    with fixture.source_helper_boundary():
                        with self.assertRaisesRegex(
                                chronology.ChronologyError,
                                "changed its original",
                        ):
                            chronology._verify_source5_prepared_input_generation(
                                None, fixture.prepared, {
                                    "completion": fixture.completion_pin,
                                    "provenance": provenance,
                                },
                            )

    def test_mixed_or_foreign_provenance_is_rejected_by_pure_replay(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-prep-provenance-") as tmp:
            fixture = PreparationFixture(Path(tmp))
            details = {
                "campaign_id": fixture.campaign_id,
                "host_id": fixture.host_id,
                "completion": fixture.completion_pin,
                "provenance": fixture.provenance,
                "host_completion": {
                    **fixture.capacity_rows[0]["completion"],
                    "semantic_sha256": fixture.capacity_rows[0]["completion_sha256"],
                },
                "host_verification": fixture.capacity_rows[0]["host_verification"],
                "capacity_ledger": fixture.capacity_rows[0]["ledger"],
                "capacity_schedule_sha256": fixture.plan[
                    "capacity_process_templates_sha256"],
                "entries": fixture.capacity_rows[0]["entries"],
                "qualification_eligible": False,
                "controller_chronology_proven": False,
            }
            line = fixture.make_registration_line(details)

            mixed = rewrite_first_record(
                line,
                lambda record: record["details"]["provenance"].update({
                    "final_spec_pin": fixture.provenance["initial_spec_pin"],
                }),
            )
            with self.assertRaises(chronology.ChronologyError):
                chronology.replay_journal_bytes(
                    mixed, fixture.prepared["original_pins"],
                    fixture.campaign_id, fixture.host_id,
                    fixture.prepared["boot_id_sha256"],
                )

            foreign = rewrite_first_record(
                line,
                lambda record: record["details"].update({
                    "provenance": {
                        "schema": "allocatbelt.application-source5-prepared-inputs-provenance.v999",
                        "preparation_pin": fixture.provenance["preparation_pin"],
                        "final_spec_pin": fixture.provenance["initial_spec_pin"],
                        "final_plan_pin": fixture.provenance["initial_plan_pin"],
                    },
                }),
            )
            with self.assertRaisesRegex(chronology.ChronologyError,
                                        "provenance schema differs"):
                chronology.replay_journal_bytes(
                    foreign, fixture.prepared["original_pins"],
                    fixture.campaign_id, fixture.host_id,
                    fixture.prepared["boot_id_sha256"],
                )

    def test_final_generation_rejects_empty_rate_and_oracle_spec(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-prep-final-gate-") as tmp:
            fixture = PreparationFixture(Path(tmp))
            with mock.patch.object(chronology, "_prepare_inputs", return_value=fixture.prepared):
                with chronology.campaign_host_lock(
                        fixture.output_root, fixture.campaign_id, fixture.host_id) as lock:
                    with self.assertRaisesRegex(
                            chronology.ChronologyError,
                            "requires the separately frozen final SpecV3"):
                        chronology.register_source5_prepared_capacity_locked(
                            lock, fixture.plan_pin, fixture.spec_pin,
                            fixture.source_root, fixture.input_root, fixture.host_id,
                            fixture.observed_pin, fixture.output_root,
                            fixture.completion_pin, fixture.provenance,
                        )


class PreparatoryRegistrationJournalTests(unittest.TestCase):
    def _register(self, fixture: PreparationFixture, lock):
        with mock.patch.object(chronology, "_prepare_inputs",
                               return_value=fixture.prepared):
            return chronology.register_source5_preparatory_capacity_locked(
                lock, fixture.plan_pin, fixture.spec_pin,
                fixture.source_root, fixture.input_root, fixture.host_id,
                fixture.observed_pin, fixture.output_root,
                fixture.completion_pin, fixture.provenance,
            )

    def test_fd_owned_registration_appends_and_replays_one_setup_event(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-prep-registration-") as tmp:
            fixture = PreparationFixture(Path(tmp))
            with fixture.source_helper_boundary():
                with chronology.campaign_host_lock(
                        fixture.output_root, fixture.campaign_id,
                        fixture.host_id) as lock:
                    result = self._register(fixture, lock)
                    journal = chronology._journal_path(lock)
                    raw = journal.read_bytes()
                    self.assertEqual(stat.S_IMODE(journal.stat().st_mode), 0o600)
                    self.assertTrue(result["registered"])
                    self.assertFalse(result["qualification_eligible"])
                    self.assertFalse(result["controller_chronology_proven"])
                    replay = chronology.replay_journal_bytes(
                        raw, fixture.prepared["original_pins"],
                        fixture.campaign_id, fixture.host_id,
                        fixture.prepared["boot_id_sha256"],
                    )
                    self.assertEqual(replay["record_count"], 1)
                    self.assertEqual(replay["registrations"][0]["event"],
                                     "source5_prepared_capacity_registered")
                    self.assertFalse(replay["qualification_eligible"])
                    with self.assertRaisesRegex(
                            chronology.ChronologyError,
                            "must precede every campaign execution event"):
                        self._register(fixture, lock)
                    self.assertEqual(journal.read_bytes(), raw)

            with fixture.source_helper_boundary():
                with chronology.campaign_host_lock(
                        fixture.output_root, fixture.campaign_id,
                        fixture.host_id) as reopened_lock:
                    state = chronology._read_journal(reopened_lock,
                                                     fixture.prepared)
                    self.assertEqual(state["record_count"], 1)
                    self.assertIsNotNone(state["prepared_capacity_registration"])
                    self.assertEqual(state["source5_seen_jobs"], set())

    def test_changed_raw_initial_pin_blocks_real_journal_replay(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-prep-journal-pin-") as tmp:
            fixture = PreparationFixture(Path(tmp))
            with fixture.source_helper_boundary():
                with chronology.campaign_host_lock(
                        fixture.output_root, fixture.campaign_id,
                        fixture.host_id) as lock:
                    self._register(fixture, lock)
                    journal = chronology._journal_path(lock)
                    raw = journal.read_bytes()
            tampered = rewrite_first_record(
                raw,
                lambda record: record["details"]["provenance"][
                    "initial_spec_pin"].update({"raw_sha256": "f" * 64}),
            )
            write_private(journal, tampered)
            with fixture.source_helper_boundary():
                with chronology.campaign_host_lock(
                        fixture.output_root, fixture.campaign_id,
                        fixture.host_id) as reopened_lock:
                    with self.assertRaisesRegex(
                            chronology.ChronologyError,
                            "changed its original spec bytes"):
                        chronology._read_journal(reopened_lock,
                                                 fixture.prepared)

    def test_duplicate_setup_registration_record_is_rejected_by_pure_replay(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-prep-duplicate-") as tmp:
            fixture = PreparationFixture(Path(tmp))
            with fixture.source_helper_boundary():
                with chronology.campaign_host_lock(
                        fixture.output_root, fixture.campaign_id,
                        fixture.host_id) as lock:
                    self._register(fixture, lock)
                    raw = chronology._journal_path(lock).read_bytes()
            envelope = json.loads(raw)
            second = copy.deepcopy(envelope["record"])
            second["sequence"] = 2
            second["monotonic_ns"] += 1
            unsigned = {"previous_sha256": envelope["record_sha256"],
                        "record": second}
            second_sha = sha(chronology.canonical_bytes(unsigned))
            duplicate = raw + chronology.canonical_bytes({
                **unsigned, "record_sha256": second_sha,
            })
            with self.assertRaisesRegex(chronology.ChronologyError,
                                        "must be the first journal event"):
                chronology.replay_journal_bytes(
                    duplicate, fixture.prepared["original_pins"],
                    fixture.campaign_id, fixture.host_id,
                    fixture.prepared["boot_id_sha256"],
                )

    def test_host_lock_binding_rejects_foreign_prepared_host(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-prep-host-lock-") as tmp:
            fixture = PreparationFixture(Path(tmp))
            fixture.prepared["host_id"] = "host-b"
            with chronology.campaign_host_lock(
                    fixture.output_root, fixture.campaign_id,
                    "host-a") as lock:
                with mock.patch.object(chronology, "_prepare_inputs",
                                       return_value=fixture.prepared):
                    with self.assertRaisesRegex(
                            chronology.ChronologyError,
                            "lock token does not own these inputs"):
                        chronology.register_source5_preparatory_capacity_locked(
                            lock, fixture.plan_pin, fixture.spec_pin,
                            fixture.source_root, fixture.input_root,
                            "host-b", fixture.observed_pin,
                            fixture.output_root, fixture.completion_pin,
                            fixture.provenance,
                        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
