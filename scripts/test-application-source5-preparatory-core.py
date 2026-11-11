#!/usr/bin/env python3
"""Actual-file signer checks and non-authorizing preparatory lock boundaries."""
from __future__ import annotations

import copy
import contextlib
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


SOURCE = Path(__file__).with_name("application-campaign-chronology.py")
spec = importlib.util.spec_from_file_location("preparatory_core_chronology_target", SOURCE)
assert spec is not None and spec.loader is not None
chronology = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = chronology
spec.loader.exec_module(chronology)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write(path, raw, mode=0o600):
    path.write_bytes(raw)
    path.chmod(mode)
    return {"path": str(path), "raw_sha256": sha(raw)}


class SignerFixture:
    def __init__(self, root):
        self.root = root
        self.path = root / "signer.json"
        self.host = "host-a"
        self.core = {"campaign_id": "campaign-preparatory", "archive_signer_contexts": {}}
        self.body = {
            "schema": "allocatbelt.application-source5-archive-signer-context.v1",
            "campaign_id": self.core["campaign_id"], "host_id": self.host,
            "authorized_primary_fingerprint": "ABCDEF1234" * 4,
            "maximum_signature_bytes": 4096,
            "keyring_pin": write(root / "keyring.gpg", b"public verification fixture\n"),
            "gpgv_pin": write(root / "gpgv-fixture", b"executable bytes; never executed\n", 0o700),
            "signature_format": "binary_detached_primary_sha256_v1",
        }
        self.seal()

    def seal(self):
        semantic = sha(chronology.canonical_bytes(self.body))
        self.value = {**self.body, "signer_context_sha256": semantic}
        self.raw = chronology.canonical_bytes(self.value)
        self.wrapper = {"artifact": write(self.path, self.raw), "semantic_sha256": semantic}
        self.core["archive_signer_contexts"] = {self.host: self.wrapper}

    def verify(self):
        return chronology._source5_preparatory_signer_context(self.core, self.host)


class PreparatorySignerContextTests(unittest.TestCase):
    def test_actual_private_context_and_tool_bytes_return_their_exact_pins(self):
        with tempfile.TemporaryDirectory(prefix="prep-signer-") as tmp:
            fixture = SignerFixture(Path(tmp))
            value, pin = fixture.verify()
            self.assertEqual(value, fixture.value)
            self.assertEqual(pin, {**fixture.wrapper["artifact"],
                                   "semantic_sha256": fixture.wrapper["semantic_sha256"]})
            self.assertEqual(fixture.path.read_bytes(), fixture.raw)

    def test_resealed_identity_format_fingerprint_and_quota_mutants_are_rejected(self):
        mutants = {
            "schema": "other-schema", "campaign_id": "other-campaign", "host_id": "host-b",
            "authorized_primary_fingerprint": "abcdef1234" * 4,
            "maximum_signature_bytes": True, "signature_format": "armored",
        }
        for key, value in mutants.items():
            with self.subTest(key=key), tempfile.TemporaryDirectory(prefix="prep-signer-mutant-") as tmp:
                fixture = SignerFixture(Path(tmp))
                fixture.body[key] = value
                fixture.seal()
                with self.assertRaisesRegex(chronology.ChronologyError, "schema/identity/format/quota"):
                    fixture.verify()

    def test_semantic_pin_substitution_is_rejected_despite_matching_raw_bytes(self):
        with tempfile.TemporaryDirectory(prefix="prep-signer-semantic-") as tmp:
            fixture = SignerFixture(Path(tmp))
            fixture.wrapper["semantic_sha256"] = "0" * 64
            with self.assertRaises(chronology.ChronologyError):
                fixture.verify()

    def test_noncanonical_json_is_rejected_after_repinning_its_actual_bytes(self):
        with tempfile.TemporaryDirectory(prefix="prep-signer-json-") as tmp:
            fixture = SignerFixture(Path(tmp))
            fixture.wrapper["artifact"] = write(fixture.path, json.dumps(fixture.value, indent=2).encode())
            with self.assertRaisesRegex(chronology.ChronologyError, "canonical JSON"):
                fixture.verify()

    def test_context_bytes_cannot_change_under_an_unchanged_raw_pin(self):
        with tempfile.TemporaryDirectory(prefix="prep-signer-raw-") as tmp:
            fixture = SignerFixture(Path(tmp))
            fixture.path.write_bytes(fixture.raw + b" ")
            with self.assertRaisesRegex(chronology.ChronologyError, "private raw pin"):
                fixture.verify()

    def test_actual_keyring_and_gpgv_tampering_are_rejected(self):
        for name in ("keyring_pin", "gpgv_pin"):
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix="prep-signer-tool-") as tmp:
                fixture = SignerFixture(Path(tmp))
                Path(fixture.body[name]["path"]).write_bytes(b"changed exact tool bytes\n")
                with self.assertRaisesRegex(chronology.ChronologyError, "raw/tool pin"):
                    fixture.verify()

    def test_gpgv_requires_actual_execute_permission(self):
        with tempfile.TemporaryDirectory(prefix="prep-signer-exec-") as tmp:
            fixture = SignerFixture(Path(tmp))
            Path(fixture.body["gpgv_pin"]["path"]).chmod(0o600)
            with self.assertRaisesRegex(chronology.ChronologyError, "raw/tool pin"):
                fixture.verify()

    def test_signer_file_must_be_private_and_have_only_one_link(self):
        for fault in ("public-mode", "hardlink"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="prep-signer-inode-") as tmp:
                fixture = SignerFixture(Path(tmp))
                if fault == "public-mode":
                    fixture.path.chmod(0o644)
                else:
                    os.link(fixture.path, fixture.root / "extra-link")
                with self.assertRaisesRegex(chronology.ChronologyError, "private raw pin"):
                    fixture.verify()

    def test_signer_and_tool_symlink_aliases_cannot_replace_canonical_pins(self):
        for name in ("signer", "keyring_pin", "gpgv_pin"):
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix="prep-signer-alias-") as tmp:
                fixture = SignerFixture(Path(tmp))
                if name == "signer":
                    alias = fixture.root / "signer-alias"
                    alias.symlink_to(fixture.path)
                    fixture.wrapper["artifact"]["path"] = str(alias)
                else:
                    alias = fixture.root / "tool-alias"
                    alias.symlink_to(fixture.body[name]["path"])
                    fixture.body[name]["path"] = str(alias)
                    fixture.seal()
                with self.assertRaisesRegex(chronology.ChronologyError, "not canonical"):
                    fixture.verify()

    def test_a_raw_pinned_sparse_tool_over_the_limit_is_rejected_before_reading(self):
        with tempfile.TemporaryDirectory(prefix="prep-signer-bounded-") as tmp:
            fixture = SignerFixture(Path(tmp))
            path = Path(fixture.body["keyring_pin"]["path"])
            with path.open("wb") as stream:
                stream.truncate(16 * 1024 * 1024 + 1)
            with self.assertRaisesRegex(chronology.ChronologyError, "finite size bound"):
                fixture.verify()

    def test_unknown_content_fields_are_rejected_even_after_resealing(self):
        with tempfile.TemporaryDirectory(prefix="prep-signer-fields-") as tmp:
            fixture = SignerFixture(Path(tmp))
            fixture.body["verified"] = True
            fixture.seal()
            with self.assertRaises(chronology.ChronologyError):
                fixture.verify()

    def test_64_digit_primary_fingerprint_uses_the_same_closed_profile(self):
        with tempfile.TemporaryDirectory(prefix="prep-signer-primary-") as tmp:
            fixture = SignerFixture(Path(tmp))
            fixture.body["authorized_primary_fingerprint"] = "ABCDEF12" * 8
            fixture.seal()
            self.assertEqual(fixture.verify()[0], fixture.value)


class PreparatoryCoreLockBoundaryTests(unittest.TestCase):
    def core(self):
        core = {key: None for key in chronology.SOURCE5_PREPARATORY_EXECUTION_CORE_FIELDS}
        core.update(schema=chronology.SOURCE5_PREPARATORY_EXECUTION_SCHEMA_V1,
                    campaign_id="campaign-lock", host_id="host-a",
                    scope="preparatory_exploration", phase_order=["exploration"],
                    qualification_eligible=False)
        return core

    def test_other_profiles_cannot_reach_input_preparation_or_issue_a_launch(self):
        mutants = {"schema": chronology.SOURCE5_EXECUTION_SCHEMA_V4,
                   "scope": "final_prepared_bounded", "phase_order": ["aa"],
                   "qualification_eligible": True, "host_id": "host-b",
                   "campaign_id": "other-campaign"}
        with tempfile.TemporaryDirectory(prefix="prep-core-lock-") as tmp:
            root = Path(tmp)
            with chronology.campaign_host_lock(root, "campaign-lock", "host-a") as lock:
                with mock.patch.object(chronology, "_prepare_inputs") as prepare:
                    for key, value in mutants.items():
                        with self.subTest(key=key):
                            core = self.core()
                            core[key] = value
                            with self.assertRaises(chronology.ChronologyError):
                                chronology.validate_source5_preparatory_execution_core_locked(lock, core)
                    prepare.assert_not_called()
                self.assertFalse(chronology._journal_path(lock).exists())

    def test_released_actual_lock_cannot_be_reused_for_core_verification(self):
        with tempfile.TemporaryDirectory(prefix="prep-core-released-") as tmp:
            with chronology.campaign_host_lock(Path(tmp), "campaign-lock", "host-a") as lock:
                pass
            with mock.patch.object(chronology, "_prepare_inputs") as prepare:
                with self.assertRaises(chronology.ChronologyError):
                    chronology.validate_source5_preparatory_execution_core_locked(lock, self.core())
                prepare.assert_not_called()


class PreparatoryRegistrationBindingTests(unittest.TestCase):
    """Replay real setup bytes; stub only the already-separated input boundary."""

    @classmethod
    def setUpClass(cls):
        path = SOURCE.with_name("test-application-campaign-preparatory-registration.py")
        spec = importlib.util.spec_from_file_location("prep_core_setup_fixtures", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        cls.setup_fixtures = module

    def _fixture(self, root):
        fixture = self.setup_fixtures.PreparationFixture(root)
        fixture.prepared["plan"]["jobs"] = {"exploration": [
            {"host_id": fixture.host_id, "phase": "exploration", "run_id": f"fixture-{i}"}
            for i in range(360)
        ]}
        return fixture, self.setup_fixtures.chronology

    def _register(self, fixture, module, lock):
        with mock.patch.object(module, "_prepare_inputs", return_value=fixture.prepared):
            result = module.register_source5_preparatory_capacity_locked(
                lock, fixture.plan_pin, fixture.spec_pin, fixture.source_root,
                fixture.input_root, fixture.host_id, fixture.observed_pin,
                fixture.output_root, fixture.completion_pin, fixture.provenance,
            )
        return {
            "preparatory_capacity_generation": {
                "completion": fixture.completion_pin, "provenance": fixture.provenance,
            },
            "preparatory_capacity_registration": {
                key: result[key] for key in (
                    "completion", "host_completion", "host_verification", "ledger",
                    "capacity_schedule_sha256", "registration_head",
                )
            },
        }

    def test_public_core_result_replays_actual_setup_and_does_not_append_or_authorize(self):
        with tempfile.TemporaryDirectory(prefix="prep-core-real-setup-") as tmp:
            fixture, module = self._fixture(Path(tmp))
            with fixture.source_helper_boundary():
                with module.campaign_host_lock(
                        fixture.output_root, fixture.campaign_id, fixture.host_id) as lock:
                    core = self._register(fixture, module, lock)
                    journal = module._journal_path(lock)
                    before = journal.read_bytes()
                    immutable = (core, fixture.prepared, fixture.generation, "f" * 64)
                    with mock.patch.object(module, "_source5_preparatory_immutable_inputs_held",
                                           return_value=immutable) as inputs:
                        result = module.validate_source5_preparatory_execution_core_locked(lock, core)
                    inputs.assert_called_once_with(lock, core)
                    self.assertEqual(result["journal_record_count"], 1)
                    self.assertEqual(result["journal_head"], result["registration_head"])
                    self.assertEqual(result["capacity_generation_pin"], fixture.completion_pin)
                    self.assertEqual(result["job_count"], 360)
                    self.assertEqual(result["job_list_sha256"], sha(module.canonical_bytes(
                        fixture.prepared["plan"]["jobs"]["exploration"])))
                    self.assertFalse(result["launch_authorized"])
                    self.assertFalse(result["qualification_eligible"])
                    self.assertEqual(journal.read_bytes(), before)

    def test_setup_only_check_remains_separate_from_non_authorizing_registration_binding(self):
        with tempfile.TemporaryDirectory(prefix="prep-core-history-binding-") as tmp:
            fixture, module = self._fixture(Path(tmp))
            with fixture.source_helper_boundary():
                with module.campaign_host_lock(
                        fixture.output_root, fixture.campaign_id, fixture.host_id) as lock:
                    core = self._register(fixture, module, lock)
                    state = module._read_journal(lock, fixture.prepared)
                    module._source5_preparatory_registration_binding(core, state, setup_only=True)
                    # This pure-helper row is a synthetic later frontier. It is
                    # never written, fed to journal replay, or treated as APP evidence.
                    later = {**state, "record_count": 7, "head": "e" * 64}
                    with self.assertRaisesRegex(module.ChronologyError, "clean setup event"):
                        module._source5_preparatory_registration_binding(core, later, setup_only=True)
                    self.assertIsNone(module._source5_preparatory_registration_binding(
                        core, later, setup_only=False))
                    self.assertEqual(state["record_count"], 1)

    def test_resealed_core_cannot_substitute_any_actual_registration_field(self):
        with tempfile.TemporaryDirectory(prefix="prep-core-registration-fields-") as tmp:
            fixture, module = self._fixture(Path(tmp))
            with fixture.source_helper_boundary():
                with module.campaign_host_lock(
                        fixture.output_root, fixture.campaign_id, fixture.host_id) as lock:
                    core = self._register(fixture, module, lock)
                    state = module._read_journal(lock, fixture.prepared)
                    for name in core["preparatory_capacity_registration"]:
                        with self.subTest(name=name):
                            changed = copy.deepcopy(core)
                            row = changed["preparatory_capacity_registration"]
                            if isinstance(row[name], dict):
                                row[name]["raw_sha256"] = "0" * 64
                            else:
                                row[name] = "0" * 64
                            with self.assertRaisesRegex(module.ChronologyError, "actual setup registration"):
                                module._source5_preparatory_registration_binding(
                                    changed, state, setup_only=False)

    def test_initial_provenance_cannot_be_replaced_by_a_final_generation(self):
        with tempfile.TemporaryDirectory(prefix="prep-core-provenance-") as tmp:
            fixture, module = self._fixture(Path(tmp))
            with fixture.source_helper_boundary():
                with module.campaign_host_lock(
                        fixture.output_root, fixture.campaign_id, fixture.host_id) as lock:
                    core = self._register(fixture, module, lock)
                    state = module._read_journal(lock, fixture.prepared)
                    changed = copy.deepcopy(core)
                    changed["preparatory_capacity_generation"]["provenance"]["schema"] = \
                        "allocatbelt.application-source5-prepared-inputs-provenance.v1"
                    with self.assertRaisesRegex(module.ChronologyError, "actual setup registration"):
                        module._source5_preparatory_registration_binding(
                            changed, state, setup_only=False)


class PreparatoryLiveProfileTests(unittest.TestCase):
    def test_profile_selects_bounded_wire_fields_without_final_horizon_identity(self):
        prep = {"source5_execution_schema": chronology.SOURCE5_PREPARATORY_EXECUTION_SCHEMA_V1,
                "source5_journal_event_ceiling": 2161, "source5_journal_byte_ceiling": 123456}
        self.assertTrue(chronology._source5_bounded_owner_profile(prep))
        self.assertTrue(chronology._source5_uses_cleanup_sidecars(prep))
        fields = chronology._source5_authorization_detail_fields(prep)
        self.assertEqual(fields, set(chronology.DETAIL_FIELDS["source5_authorized"]) |
                         {"host_evidence_budget", "tmpdir_budget"})
        self.assertEqual(chronology._journal_limits(prep), (2161, 123456))
        legacy = {"source5_execution_schema": chronology.SOURCE5_EXECUTION_SCHEMA}
        self.assertFalse(chronology._source5_bounded_owner_profile(legacy))
        self.assertFalse(chronology._source5_uses_cleanup_sidecars(legacy))
        self.assertEqual(chronology._source5_authorization_detail_fields(legacy),
                         set(chronology.DETAIL_FIELDS["source5_authorized"]))

    def test_preparatory_capacity_selector_keeps_initial_and_final_rows_separate(self):
        row = {"completion": {}, "host_completion": {"path": "/initial/host", "raw_sha256": "a" * 64},
               "host_verification": {}, "ledger": {"raw_sha256": "b" * 64, "terminal_head": "c" * 64},
               "capacity_schedule_sha256": "d" * 64, "registration_head": "e" * 64}
        initial = {"schema": chronology.SOURCE5_PREPARATORY_EXECUTION_SCHEMA_V1,
                   "preparatory_capacity_registration": row}
        self.assertIs(chronology._source5_selected_prepared_registration(initial), row)
        self.assertEqual(chronology._source5_capacity_manifest_record(initial, "host-a")["artifact"],
                         row["host_completion"])
        final = {"schema": chronology.SOURCE5_EXECUTION_SCHEMA_V4,
                 "prepared_capacity_registration": copy.deepcopy(row)}
        final["prepared_capacity_registration"]["host_completion"]["path"] = "/final/host"
        self.assertEqual(chronology._source5_capacity_manifest_record(final, "host-a")["artifact"]["path"],
                         "/final/host")

    def jobs(self):
        return [{"host_id": "host-a", "phase": "exploration", "ordinal": i % 6 + 1,
                 "run_id": f"original-{i}", "mode": "capacity", "comparison_kind": "capacity_pilot"}
                for i in range(360)]

    def test_next_job_requires_the_exact_successful_original_prefix(self):
        jobs = self.jobs()
        prepared = {"host_id": "host-a", "plan": {"jobs": {"exploration": jobs}}}
        details = {"job": jobs[1], "job_index": 1, "phase": "exploration"}
        key = ("exploration", jobs[0]["run_id"])
        state = {"source5_seen_jobs": {key}, "source5_finished": {key: {"state": "valid_pair"}}}
        self.assertIsNone(chronology._source5_preparatory_next_job(details, prepared, state))
        for fault in ("gap", "failed", "other-phase", "reused-run", "non-job"):
            with self.subTest(fault=fault):
                changed_details, changed_state = copy.deepcopy(details), copy.deepcopy(state)
                if fault == "gap":
                    changed_state["source5_seen_jobs"] = set()
                elif fault == "failed":
                    changed_state["source5_finished"][key]["state"] = "invalid_pair"
                elif fault == "other-phase":
                    changed_details["phase"] = "aa"
                elif fault == "reused-run":
                    changed_details["job"] = jobs[0]
                else:
                    changed_details["job"] = None
                with self.assertRaises(chronology.ChronologyError):
                    chronology._source5_preparatory_next_job(changed_details, prepared, changed_state)

    def test_actual_fd_profile_cannot_append_analysis_or_legacy_dispatch(self):
        with tempfile.TemporaryDirectory(prefix="prep-live-deny-event-") as tmp:
            root = Path(tmp)
            prepared = {"output_root": root, "campaign_id": "campaign-live", "host_id": "host-a",
                        "source5_execution_schema": chronology.SOURCE5_PREPARATORY_EXECUTION_SCHEMA_V1}
            with chronology.campaign_host_lock(root, "campaign-live", "host-a") as lock:
                with mock.patch.object(chronology, "_read_journal") as read:
                    for event in ("source5_analysis", "capacity_stage_completed", "dispatch_bound"):
                        with self.subTest(event=event):
                            with self.assertRaisesRegex(chronology.ChronologyError, "cannot append"):
                                chronology._append_event(lock, prepared, event, {})
                    read.assert_not_called()
                self.assertFalse(chronology._journal_path(lock).exists())

    def test_malformed_preparatory_authorization_uses_closed_detail_parser_first(self):
        prepared = {"source5_execution_schema": chronology.SOURCE5_PREPARATORY_EXECUTION_SCHEMA_V1}
        with self.assertRaises(chronology.ChronologyError):
            chronology._check_event_semantics({}, "source5_authorized", {}, "a" * 64,
                                               prepared, replay=True)

    def test_tmp_limits_come_from_real_preparatory_generation_budget_bytes(self):
        with tempfile.TemporaryDirectory(prefix="prep-live-tmp-budget-") as tmp:
            path = Path(tmp) / "resource-budget.json"
            body = {"ceilings": {"maximum_tmpdir_bytes": 8192, "maximum_tmpdir_inodes": 12}}
            value = {**body, "resource_budget_sha256": sha(chronology.canonical_bytes(body))}
            pin = {**write(path, chronology.canonical_bytes(value)),
                   "semantic_sha256": value["resource_budget_sha256"]}
            prepared = {"host_id": "host-a",
                        "source5_execution_schema": chronology.SOURCE5_PREPARATORY_EXECUTION_SCHEMA_V1,
                        "source5_preparatory_capacity_generation": {"resource_budgets": {"host-a": pin}},
                        "source5_prepared_input_completion": None}
            self.assertEqual(chronology._source5_prepared_tmpdir_budget(prepared), {
                "resource_budget_pin": pin, "maximum_tmpdir_bytes": 8192, "maximum_tmpdir_inodes": 12})
            path.write_bytes(path.read_bytes() + b" ")
            with self.assertRaisesRegex(chronology.ChronologyError, "raw pin differs"):
                chronology._source5_prepared_tmpdir_budget(prepared)

    def test_budget_reopen_requires_own_verified_context_and_exact_resident_bytes(self):
        with tempfile.TemporaryDirectory(prefix="prep-live-host-budget-") as tmp:
            root = Path(tmp)
            directory = root / "campaign-live" / "source5" / "host-a" / "evidence-budget"
            directory.mkdir(parents=True, mode=0o700)
            path = directory / "host-evidence-budget-preparatory-v1.json"
            body = {"schema": "allocatbelt.application-source5-preparatory-exploration-budget.v1",
                    "campaign_id": "campaign-live", "host_id": "host-a", "execution_basis_sha256": "e" * 64}
            value = {**body, "budget_sha256": sha(chronology.canonical_bytes(body))}
            pin = {**write(path, chronology.canonical_bytes(value)), "semantic_sha256": value["budget_sha256"]}
            manifest = {"schema": chronology.SOURCE5_PREPARATORY_EXECUTION_SCHEMA_V1,
                        "campaign_id": "campaign-live", "host_id": "host-a", "artifact_root": str(root),
                        "preparatory_host_budgets": {"host-a": {
                            "artifact": {k: pin[k] for k in ("path", "raw_sha256")},
                            "semantic_sha256": pin["semantic_sha256"]}}}
            prepared = {"source5_execution_schema": chronology.SOURCE5_PREPARATORY_EXECUTION_SCHEMA_V1,
                        "campaign_id": "campaign-live", "host_id": "host-a",
                        "source5_execution_manifest": manifest, "source5_preparatory_execution_basis_sha256": "e" * 64,
                        "source5_host_evidence_budget": value, "source5_host_evidence_budget_pin": pin}
            self.assertEqual(chronology._source5_host_budget_pin_and_value(pin, manifest, prepared), (pin, value))
            path.write_bytes(path.read_bytes() + b" ")
            with self.assertRaisesRegex(chronology.ChronologyError, "private raw identity"):
                chronology._source5_host_budget_pin_and_value(pin, manifest, prepared)

    def test_sealed_context_rejects_a_preparatory_manifest_in_legacy_prepared_state(self):
        manifest = {key: None for key in chronology.SOURCE5_PREPARATORY_EXECUTION_FIELDS}
        manifest["schema"] = chronology.SOURCE5_PREPARATORY_EXECUTION_SCHEMA_V1
        prepared = {"source5_execution_schema": chronology.SOURCE5_EXECUTION_SCHEMA_V4}
        with self.assertRaisesRegex(chronology.ChronologyError, "actual sealed Source-owned context"):
            chronology._validate_source5_manifest_value(manifest, chronology.canonical_bytes(manifest), prepared)


class PreparatoryPreviousArchiveTests(unittest.TestCase):
    """Actual fd/record/ledger reads; Source context, journal and GPG are test boundaries."""

    @contextlib.contextmanager
    def case(self):
        with tempfile.TemporaryDirectory(prefix="prep-previous-archive-") as tmp:
            root = Path(tmp)
            jobs = [{"phase": "exploration", "host_id": "host-a", "run_id": f"original-{i}",
                     "ordinal": i % 6 + 1, "mode": "capacity", "comparison_kind": "capacity_pilot"}
                    for i in range(360)]
            phase_root = root / "campaign" / "source5" / "host-a" / "exploration"
            record_root = phase_root / "job-records"
            record_root.mkdir(parents=True, mode=0o700)
            record = {"job": jobs[0], "state": "valid_pair"}
            raw = chronology.canonical_bytes(record)
            record_path = record_root / "original-0.json"
            write(record_path, raw)
            ledger = phase_root / "controller-ledger.jsonl"
            write(ledger, raw)
            prepared = {"campaign_id": "campaign", "host_id": "host-a", "output_root": root,
                        "source5_execution_schema": chronology.SOURCE5_PREPARATORY_EXECUTION_SCHEMA_V1,
                        "plan": {"jobs": {"exploration": jobs}},
                        "_source5_archived_replay_ledgers": {"exploration": {"original-0": sha(raw)}}}
            finished = {"state": "valid_pair", "details": {"job": jobs[0]}}
            state = {"head": "a" * 64, "record_count": 7,
                     "source5_finished": {("exploration", "original-0"): finished}}
            proof = {"archived_metadata": {"component_replay_required": True,
                                           "qualification_eligible": False,
                                           "job_record_raw_sha256": sha(raw)}}
            with chronology.campaign_host_lock(root, "campaign", "host-a") as lock:
                with contextlib.ExitStack() as stack:
                    stack.enter_context(mock.patch.object(chronology, "_source5_analysis_epoch", return_value="e" * 64))
                    stack.enter_context(mock.patch.object(chronology, "_source5_finished_structural_summary",
                                                        side_effect=lambda value: value))
                    stack.enter_context(mock.patch.object(chronology, "_read_journal", return_value=state))
                    verifier = stack.enter_context(mock.patch.object(
                        chronology, "_validate_source5_authorization", return_value=proof))
                    yield {"root": root, "jobs": jobs, "lock": lock, "prepared": prepared,
                           "state": state, "ledger": ledger, "record_path": record_path,
                           "record": record, "raw": raw, "proof": proof, "verifier": verifier}

    def admit(self, case, index=1):
        with case["lock"]._operation_lock:
            return chronology._source5_preparatory_previous_archive_held(
                case["lock"], case["prepared"], case["state"], case["jobs"][index])

    def test_existing_previous_record_uses_fresh_authority_for_the_exact_original(self):
        with self.case() as case:
            before = case["ledger"].read_bytes()
            self.assertIsNone(self.admit(case))
            case["verifier"].assert_called_once()
            actual = case["verifier"].call_args
            self.assertEqual(actual.args[0]["job"], case["jobs"][0])
            self.assertIsNot(actual.args[1], case["prepared"])
            self.assertEqual(case["ledger"].read_bytes(), before)

    def test_cached_ledger_cannot_hide_mutation_or_deletion_before_admission(self):
        for fault in ("mutate", "delete"):
            with self.subTest(fault=fault), self.case() as case:
                if fault == "mutate":
                    changed = {**case["record"], "changed": True}
                    case["ledger"].write_bytes(chronology.canonical_bytes(changed))
                else:
                    case["ledger"].unlink()
                with self.assertRaises((chronology.ChronologyError, OSError)):
                    self.admit(case)
                case["verifier"].assert_not_called()

    def test_ledger_mutation_during_authority_verification_is_rechecked(self):
        with self.case() as case:
            def verify(*args, **kwargs):
                case["ledger"].write_bytes(chronology.canonical_bytes({**case["record"], "changed": True}))
                return case["proof"]
            case["verifier"].side_effect = verify
            with self.assertRaisesRegex(chronology.ChronologyError, "journal/Source/record epoch"):
                self.admit(case)

    def test_missing_or_wrong_raw_record_authority_stops_the_next_owner(self):
        for proof in ({}, {"archived_metadata": {"component_replay_required": True,
                                                "qualification_eligible": False,
                                                "job_record_raw_sha256": "f" * 64}}):
            with self.subTest(proof=proof), self.case() as case:
                case["verifier"].return_value = proof
                with self.assertRaisesRegex(chronology.ChronologyError, "fresh durable signed ACK"):
                    self.admit(case)

    def test_first_original_and_legacy_profiles_do_not_request_a_previous_ack(self):
        with self.case() as case:
            case["ledger"].unlink()
            self.assertIsNone(self.admit(case, index=0))
            case["verifier"].assert_not_called()
            self.assertIsNone(chronology._source5_preparatory_previous_archive_held(
                object(), {"source5_execution_schema": chronology.SOURCE5_EXECUTION_SCHEMA_V4}, {}, None))

    def test_extra_future_ledger_row_cannot_enter_the_completed_prefix(self):
        with self.case() as case:
            future = {"job": case["jobs"][1], "state": "valid_pair"}
            case["ledger"].write_bytes(case["raw"] + chronology.canonical_bytes(future))
            with self.assertRaisesRegex(chronology.ChronologyError, "exact completed original prefix"):
                self.admit(case)
            case["verifier"].assert_not_called()


class PreparatoryTwoPinHostTests(unittest.TestCase):
    """Actual resident files; the selected Source-generation helper is a test boundary."""

    @contextlib.contextmanager
    def case(self):
        with tempfile.TemporaryDirectory(prefix="prep-two-pin-host-") as tmp:
            root = Path(tmp)
            inputs = root / "inputs"
            inputs.mkdir(mode=0o700)
            source = root / "source"
            source.mkdir(mode=0o700)
            fixed_dir = inputs / "fixed-spec-hosts"
            fixed_dir.mkdir(mode=0o700)
            controls = {"kernel_release": "fixture-kernel", "cpu_model": "fixture-cpu"}
            host = {"host_id": "host-a", "controls": controls,
                    "host_fingerprint_sha256": sha(chronology.canonical_bytes(controls))}
            spec = {"hosts": [host]}
            spec_pin = write(inputs / "spec.json", chronology.canonical_bytes(spec))
            prep_pin = write(inputs / "preparation.json", b"fixture preparation boundary\n")
            capacity = {"schema": "allocatbelt.application-capacity-host-context.v1",
                        "host_id": "host-a", "boot_id_sha256": "b" * 64,
                        "controls": controls, "controls_sha256": host["host_fingerprint_sha256"],
                        "kernel_release": "fixture-kernel", "cpu_model": "fixture-cpu",
                        "cpu_affinity": [1, 2], "network_namespace_inode": 81}
            capacity_pin = write(inputs / "capacity-context.json", chronology.canonical_bytes(capacity))
            fixed_pin = write(fixed_dir / "host-a.json", chronology.canonical_bytes(host))
            body = {"schema": "allocatbelt.application-source5-fixed-pair-host-binding.v1",
                    "host_id": "host-a", "fixed_spec_host_pin": fixed_pin,
                    "prepared_host_context_pin": capacity_pin,
                    "spec_host_semantic_sha256": sha(chronology.canonical_bytes(host)),
                    "boot_id_sha256": capacity["boot_id_sha256"], "kernel_release": capacity["kernel_release"],
                    "controls_sha256": capacity["controls_sha256"],
                    "process_affinity": capacity["cpu_affinity"],
                    "network_namespace_inode": capacity["network_namespace_inode"]}
            binding = {**body, "binding_sha256": sha(chronology.canonical_bytes(body))}
            result = {"fixed_spec_host_pin": fixed_pin, "prepared_host_binding": binding}
            generation = {"provenance": {"preparation_pin": prep_pin}}
            prepared = {"host_id": "host-a", "source_root": source, "input_root": inputs,
                        "spec": spec, "prepared": {"host_context": capacity},
                        "original_pins": {"spec": spec_pin, "observed_host": capacity_pin},
                        "source5_execution_schema": chronology.SOURCE5_PREPARATORY_EXECUTION_SCHEMA_V1,
                        "source5_execution_manifest": {"preparatory_capacity_generation": generation},
                        "source5_fixed_spec_host_pin": copy.deepcopy(fixed_pin),
                        "source5_prepared_fixed_host_binding": copy.deepcopy(binding)}
            expected_args = ({"path": prep_pin["path"], "sha256": prep_pin["raw_sha256"]},
                             {"path": spec_pin["path"], "sha256": spec_pin["raw_sha256"]},
                             source, inputs, "host-a")
            verifier = mock.Mock(return_value=result)
            selected_module = types.SimpleNamespace(verify_prepared_host_binding=verifier)
            with mock.patch.object(chronology, "_source5_captured_source_module", return_value=selected_module):
                yield {"prepared": prepared, "generation": generation, "result": result,
                       "binding": binding, "fixed_pin": fixed_pin, "capacity_pin": capacity_pin,
                       "fixed_path": fixed_dir / "host-a.json", "host": host,
                       "verifier": verifier, "expected_args": expected_args}

    def overlay(self, case):
        binding = case["binding"]
        return {"sources": {"observed_host": {
            "pin": {"path": case["fixed_pin"]["path"], "sha256": case["fixed_pin"]["raw_sha256"]},
            "host_fingerprint_sha256": binding["controls_sha256"],
            "controls_sha256": binding["controls_sha256"],
            "process_affinity": list(binding["process_affinity"]),
            "network_namespace_inode": binding["network_namespace_inode"],
        }}}

    def test_readonly_source_verifier_preserves_two_distinct_raw_host_pins(self):
        with self.case() as case:
            result = chronology._source5_preparatory_fixed_host_inputs(case["prepared"], case["generation"])
            case["verifier"].assert_called_once_with(*case["expected_args"])
            self.assertEqual(result, case["result"])
            self.assertNotEqual(result["fixed_spec_host_pin"], result["prepared_host_binding"]["prepared_host_context_pin"])
            self.assertEqual(case["prepared"]["original_pins"]["observed_host"], case["capacity_pin"])
            expected = {"path": case["fixed_pin"]["path"], "sha256": case["fixed_pin"]["raw_sha256"]}
            self.assertEqual(chronology._source5_fixed_preflight_host_pin(case["prepared"], self.overlay(case)), expected)

    def test_repinned_adapter_cannot_substitute_capacity_host_identity_or_facts(self):
        faults = {"prepared_host_context_pin": {"path": "/foreign/host", "raw_sha256": "f" * 64},
                  "process_affinity": [True, 2], "network_namespace_inode": 82,
                  "boot_id_sha256": "e" * 64, "kernel_release": "other-kernel"}
        for field, value in faults.items():
            with self.subTest(field=field), self.case() as case:
                binding = case["binding"]
                binding[field] = value
                binding["binding_sha256"] = sha(chronology.canonical_bytes({
                    k: v for k, v in binding.items() if k != "binding_sha256"}))
                with self.assertRaisesRegex(chronology.ChronologyError, "original pins or frozen facts"):
                    chronology._source5_preparatory_fixed_host_inputs(case["prepared"], case["generation"])

    def test_changed_or_missing_resident_spec_host_cannot_be_recreated(self):
        for fault in ("changed", "missing", "public-mode"):
            with self.subTest(fault=fault), self.case() as case:
                if fault == "changed":
                    case["fixed_path"].write_bytes(b"changed canonical data\n")
                elif fault == "missing":
                    case["fixed_path"].unlink()
                else:
                    case["fixed_path"].chmod(0o644)
                with self.assertRaises((chronology.ChronologyError, OSError)):
                    chronology._source5_preparatory_fixed_host_inputs(case["prepared"], case["generation"])
                if fault == "missing":
                    self.assertFalse(case["fixed_path"].exists())

    def test_fixed_overlay_cannot_use_capacity_pin_or_changed_live_affinity(self):
        for fault in ("capacity-pin", "affinity", "namespace"):
            with self.subTest(fault=fault), self.case() as case:
                overlay = self.overlay(case)
                observed = overlay["sources"]["observed_host"]
                if fault == "capacity-pin":
                    observed["pin"] = {"path": case["capacity_pin"]["path"], "sha256": case["capacity_pin"]["raw_sha256"]}
                elif fault == "affinity":
                    observed["process_affinity"] = [7]
                else:
                    observed["network_namespace_inode"] = 909
                with self.assertRaisesRegex(chronology.ChronologyError, "genuine two-pin adapter"):
                    chronology._source5_fixed_preflight_host_pin(case["prepared"], overlay)

    def test_stored_context_adapter_cannot_differ_from_fresh_source_verification(self):
        with self.case() as case:
            case["prepared"]["source5_prepared_fixed_host_binding"]["binding_sha256"] = "0" * 64
            with self.assertRaisesRegex(chronology.ChronologyError, "sealed two-pin host context"):
                chronology._source5_fixed_preflight_host_pin(case["prepared"], self.overlay(case))

    def test_legacy_fixed_host_pin_keeps_its_existing_source_without_new_helper(self):
        pin = {"path": "/legacy/observed.json", "raw_sha256": "a" * 64}
        prepared = {"source5_execution_schema": chronology.SOURCE5_EXECUTION_SCHEMA_V4,
                    "original_pins": {"observed_host": pin}}
        with mock.patch.object(chronology, "_source5_captured_source_module", side_effect=AssertionError("legacy helper read")):
            self.assertEqual(chronology._source5_fixed_preflight_host_pin(prepared, {}),
                             {"path": pin["path"], "sha256": pin["raw_sha256"]})


class PreparatoryPilotPublicationTests(unittest.TestCase):
    """SourceA publication checks use explicit wrapper/owner test boundaries.

    These cases exercise prepublication ordering and stage-slot binding only.
    They do not claim a completed 360-job signed ACK replay, numeric-owner run,
    or APP/qualification result.
    """

    @staticmethod
    def slot_rows(scratch, campaign_id="campaign-prep", host_id="host-a"):
        roles = {
            "source5_archive_read_request_slot": ("file", 128, 128, 1, "request.json"),
            "source5_archive_read_response_slot": ("file", 1024, 1024, 1, "response.json"),
            "source5_archive_read_response_incoming": (
                "file", 1024, 1024, 1, "response.json.incoming",
            ),
            "source5_archive_read_bundle": ("file", 4096, 4096, 1, "response.tar"),
            "source5_archive_read_bundle_incoming": (
                "file", 4096, 4096, 1, "response.tar.incoming",
            ),
            "source5_archive_read_stage": ("tree", 8192, 4096, 20, "stage"),
        }
        root = Path(scratch) / campaign_id / host_id / "archive-readback"
        rows = {}
        for role, (kind, maximum, maximum_file, inodes, name) in roles.items():
            rows[role] = {
                "path": str(root / name), "kind": kind, "role": role,
                "host_id": host_id, "max_bytes": maximum,
                "max_file_bytes": maximum_file, "max_inodes": inodes,
                "storage_root": str(scratch), "owner": "source5_controller",
                "phase": None, "run_id": None, "member_index": None,
                "aggregate_id": None, "aggregate_max_bytes": None,
                "origin_pin": None,
            }
        return rows

    def test_preparatory_stage_root_comes_from_exact_budgeted_slot(self):
        with tempfile.TemporaryDirectory(prefix="prep-read-stage-projection-") as temporary:
            rows = self.slot_rows(Path(temporary))
            expected = str(Path(temporary) / "campaign-prep" / "host-a" /
                           "archive-readback" / "stage")
            projected = {
                role: (row["kind"], row["max_bytes"], row["max_file_bytes"],
                       row["max_inodes"])
                for role, row in rows.items()
            }
            self.assertEqual(
                chronology._source5_preparatory_archive_read_stage_path(
                    rows, "campaign-prep", "host-a", projected,
                ), expected,
            )
            for fault in ("path", "root", "cap", "scope"):
                with self.subTest(fault=fault):
                    mutated = copy.deepcopy(rows)
                    stage = mutated["source5_archive_read_stage"]
                    if fault == "path":
                        stage["path"] = str(Path(temporary) / "unbudgeted-stage")
                    elif fault == "root":
                        stage["storage_root"] = str(Path(temporary) / "elsewhere")
                    elif fault == "cap":
                        stage["max_file_bytes"] = stage["max_bytes"] + 1
                    else:
                        stage["owner"] = "caller-selected"
                    with self.assertRaises(chronology.ChronologyError):
                        chronology._source5_preparatory_archive_read_stage_path(
                            mutated, "campaign-prep", "host-a", projected,
                        )

    def test_final_bundle_keeps_legacy_ceiling_while_prep_uses_catalogue_caps(self):
        with tempfile.TemporaryDirectory(prefix="prep-readback-size-policy-") as temporary:
            rows = self.slot_rows(Path(temporary))
            over_legacy = 16 * 1024 * 1024 + 1
            with self.assertRaisesRegex(chronology.ChronologyError,
                                        "legacy metadata ceiling"):
                chronology._source5_validate_captured_readback_pin_size(
                    "readback_response_pin", {"byte_count": over_legacy},
                    preparatory=False, readback_rows=None,
                )
            chronology._source5_validate_captured_readback_pin_size(
                "readback_bundle_pin", {"byte_count": over_legacy},
                preparatory=False, readback_rows=None,
            )
            chronology._source5_validate_captured_readback_pin_size(
                "readback_response_pin", {"byte_count": 1024},
                preparatory=True, readback_rows=rows,
            )
            chronology._source5_validate_captured_readback_pin_size(
                "readback_bundle_pin", {"byte_count": 4096},
                preparatory=True, readback_rows=rows,
            )
            for key, size in (("readback_response_pin", 1025),
                              ("readback_bundle_pin", 4097)):
                with self.subTest(key=key), self.assertRaisesRegex(
                        chronology.ChronologyError, "selected catalogue ceiling"):
                    chronology._source5_validate_captured_readback_pin_size(
                        key, {"byte_count": size}, preparatory=True,
                        readback_rows=rows,
                    )

    def test_sourcea_runs_all_result_checks_before_the_exporter_publishes(self):
        with tempfile.TemporaryDirectory(prefix="prep-pilot-source-hook-") as temporary:
            root = Path(temporary)
            output_root = root / "output"
            output_root.mkdir(mode=0o700)
            output = output_root / "capacity-pilot.json"
            source_root = Path(__file__).resolve().parent.parent
            campaign_id, host_id = "campaign-prep", "host-a"
            campaign = types.ModuleType("preparatory_pilot_campaign_boundary")
            campaign.preregistration_digest = lambda _spec: "a" * 64
            campaign.digest_object = lambda value: sha(chronology.canonical_bytes(value))
            input_preparation = types.ModuleType("preparatory_pilot_input_boundary")
            input_preparation.__file__ = str(
                source_root / "scripts/application-source5-input-preparation.py",
            )
            input_preparation.PILOT_SCHEMA = "allocatbelt.application-capacity-pilot.v1"
            input_preparation.export_capacity_pilot = None
            fixed_pair = types.ModuleType("preparatory_pilot_fixed_boundary")
            evidence_budget = types.ModuleType("preparatory_pilot_budget_boundary")
            manifest = {
                "schema": chronology.SOURCE5_PREPARATORY_EXECUTION_SCHEMA_V1,
                "manifest_sha256": "b" * 64,
                "original_inputs": {"campaign_artifacts_root": str(root / "artifacts")},
            }
            binding = {"binding_sha256": "c" * 64}
            job_rows, verified_records, pair_rows = [], [], []
            for index in range(360):
                job = {
                    "host_id": host_id, "run_id": f"original-{index:03d}",
                    "family": f"family-{index // 24:02d}", "profile": f"profile-{index // 6:02d}",
                    "allocator": f"allocator-{index % 4}", "ordinal": index % 6 + 1,
                }
                overlay_path, receipt_path, host_path = (
                    f"/original/{index:03d}/overlay.json",
                    f"/original/{index:03d}/receipt.json",
                    f"/original/{index:03d}/host.json",
                )
                evidence_map = {"schema": "fixture-map", "entries": []}
                host_receipt = {
                    "path": host_path, "raw_sha256": "d" * 64,
                    "host_verification_sha256": "e" * 64,
                }
                verified_records.append({
                    "overlay": {"path": overlay_path, "sha256": "1" * 64},
                    "receipt": {"path": receipt_path, "sha256": "2" * 64},
                    "host_verification": host_receipt,
                    "evidence_path_map": evidence_map,
                })
                job_rows.append({"job": job,
                                 "job_record_pin": {"path": f"/records/{index}.json",
                                                    "raw_sha256": "3" * 64},
                                 "record": {"fixture_boundary": index}})
                pair_rows.append({
                    "host_id": host_id, "run_id": job["run_id"],
                    "family": job["family"], "profile": job["profile"],
                    "allocator": job["allocator"], "ordinal": job["ordinal"],
                    "overlay": {"path": overlay_path, "raw_sha256": "1" * 64},
                    "receipt": {"path": receipt_path, "raw_sha256": "2" * 64},
                    "host_verification": host_receipt,
                    "prepared_host_binding_sha256": binding["binding_sha256"],
                    "evidence_path_map": evidence_map, "raw_pair_sha256": "f" * 64,
                })
            cells = [{"family": f"family-{family:02d}", "profile": f"profile-{family:02d}",
                      "allocator": f"allocator-{allocator}",
                      "pairs": [{"bounded_status": "valid", "tokio_status": "valid"}
                                for _ in range(6)]}
                     for family in range(15) for allocator in range(4)]
            pilot = {"schema": input_preparation.PILOT_SCHEMA,
                     "host_id": host_id, "spec_sha256": "a" * 64, "cells": cells}
            pilot_raw = chronology.canonical_bytes(pilot)
            dto = {
                "path": str(output), "raw_sha256": sha(pilot_raw),
                "semantic_sha256": campaign.digest_object(pilot),
                "prepared_host_binding": binding, "host_id": host_id,
                "pair_count": 360, "context_allocator_count": 60,
                "spec_preregistration_sha256": "a" * 64,
                "pair_evidence": pair_rows,
            }
            events = []
            publication_fault = [False]

            def publish(pins, _records, _host, *, captured_read_provider,
                        before_publication):
                self.assertIsNotNone(captured_read_provider)
                self.assertTrue(callable(before_publication))
                prospective = copy.deepcopy(dto)
                if publication_fault[0]:
                    prospective["pair_evidence"][0]["run_id"] = "substituted-run"
                before_publication(pilot_raw, prospective)
                events.append("before_publication")
                output.write_bytes(pilot_raw)
                output.chmod(0o600)
                events.append("published")
                return dto

            input_preparation.export_capacity_pilot = publish
            prepared = {
                "campaign_id": campaign_id, "host_id": host_id,
                "output_root": output_root, "source_root": source_root,
                "input_root": root / "inputs", "spec": {},
                "source5_execution_manifest": manifest,
                "source5_execution_manifest_pin": {"path": str(root / "exec.json"),
                                                    "raw_sha256": "4" * 64},
                "source5_host_evidence_budget": {},
                "_source5_preparatory_h_modules": {
                    "campaign": campaign, "input_preparation": input_preparation,
                    "fixed_pair": fixed_pair, "evidence_budget": evidence_budget,
                },
                "source5_preparatory_capacity_generation": {
                    "provenance": {"preparation_pin": {
                        "path": str(root / "preparation.json"), "raw_sha256": "5" * 64,
                    }},
                },
                "source5_fixed_spec_host_pin": {"path": str(root / "spec-host.json"),
                                                "raw_sha256": "6" * 64},
                "source5_prepared_fixed_host_binding": binding,
                "original_pins": {
                    "spec": {"path": str(root / "spec.json"), "raw_sha256": "7" * 64},
                    "plan": {"path": str(root / "plan.json"), "raw_sha256": "8" * 64},
                },
            }
            state = {"head": "9" * 64, "record_count": 12,
                     "source5_pending": None, "source5_cleanup_blocked": False,
                     "source5_failed_owner_window": False}
            provider = types.SimpleNamespace(
                require_complete=lambda: events.append("complete"),
                _require_scope=lambda: state,
            )
            rows = PreparatoryPilotPublicationTests.slot_rows(root / "scratch")
            fixed_inputs = {"fixed_spec_host_pin": prepared["source5_fixed_spec_host_pin"],
                            "prepared_host_binding": binding}
            with (mock.patch.object(chronology, "_prepare_source5_preparatory_context_held",
                                    return_value=(manifest, prepared, state, {})),
                  mock.patch.object(chronology, "_source5_preparatory_fixed_host_inputs",
                                    return_value=fixed_inputs),
                  mock.patch.object(chronology, "_source5_preparatory_capacity_pilot_reservation_held",
                                    return_value=({}, output, 1024 * 1024, rows)),
                  mock.patch.object(chronology, "_source5_preparatory_capacity_pilot_records_held",
                                    return_value=(verified_records, job_rows)),
                  mock.patch.object(chronology, "_Source5PreparatoryCapacityPilotReadProvider",
                                    return_value=provider)):
                result = chronology._source5_export_preparatory_capacity_pilot_held(
                    object(), {"path": str(root / "exec.json"), "sha256": "4" * 64},
                    types.SimpleNamespace(open_view=lambda *_args, **_kwargs: None),
                )
                self.assertEqual(events[0], "complete")
                self.assertEqual(events[-2:], ["before_publication", "published"])
                self.assertTrue(output.exists())
                self.assertEqual(result["pilot"]["raw_sha256"], sha(pilot_raw))
                self.assertFalse(result["qualification_eligible"])

                output.unlink()
                events.clear()
                publication_fault[0] = True
                with self.assertRaisesRegex(chronology.ChronologyError,
                                            r"evidence\[0\].*original job/pins/map"):
                    chronology._source5_export_preparatory_capacity_pilot_held(
                        object(), {"path": str(root / "exec.json"), "sha256": "4" * 64},
                        types.SimpleNamespace(open_view=lambda *_args, **_kwargs: None),
                    )
                self.assertFalse(output.exists())
                self.assertEqual(events, ["complete"])



if __name__ == "__main__":
    unittest.main()
