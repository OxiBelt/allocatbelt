"""Resume metadata tests with real private files and a real fd-owned lock.

Prepared Source/journal construction and signed ACK verification are explicit
test boundaries. These cases do not establish component or campaign validity.
"""
import contextlib
import copy
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


path = Path(__file__).with_name("application-campaign-chronology.py")
spec = importlib.util.spec_from_file_location("source5_resume_prefix_tests", path)
m = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = m
spec.loader.exec_module(m)


class ResumePrefixTests(unittest.TestCase):
    @contextlib.contextmanager
    def case(self, completed=2):
        with tempfile.TemporaryDirectory(prefix="source5-resume-prefix-") as temporary:
            root = Path(temporary).resolve()
            jobs = [{"phase": "confirmation", "host_id": "host",
                     "run_id": f"original-{i}", "ordinal": i + 1} for i in range(3)]
            phase_root = root / "campaign/source5/host/confirmation"
            record_root = phase_root / "job-records"
            record_root.mkdir(mode=0o700, parents=True)
            records, finished = [], {}
            for i, job in enumerate(jobs[:completed]):
                record = {"job": job, "state": "valid_pair", "record_sha256": str(i + 1) * 64,
                          "chronology": {"authorization_id": f"auth-{i}",
                                         "job_terminal_head": str(i + 4) * 64}}
                records.append(record)
                p = record_root / (job["run_id"] + ".json")
                p.write_bytes(m.canonical_bytes(record))
                p.chmod(0o600)
                finished[(job["phase"], job["run_id"])] = {
                    "state": "valid_pair", "details": {"job": job},
                }
            ledger = phase_root / "controller-ledger.jsonl"
            ledger.write_bytes(b"".join(m.canonical_bytes(record) for record in records))
            ledger.chmod(0o600)
            prepared = {"campaign_id": "campaign", "host_id": "host", "output_root": root,
                        "plan": {"jobs": {"confirmation": jobs}}}
            state = {"source5_pending": None, "pending": None,
                     "source5_cleanup_blocked": False, "cleanup_blocked": False,
                     "source5_failed_owner_window": False, "head": "a" * 64,
                     "record_count": completed * 6 + 1, "source5_seen_jobs": set(finished),
                     "source5_finished": finished}
            manifest = {"schema": m.SOURCE5_EXECUTION_SCHEMA_V4}
            pin = {"path": str(root / "execution.json"), "sha256": "b" * 64}
            calls = []
            with m.campaign_host_lock(root, "campaign", "host") as lock:
                def verify(details, actual_prepared, actual_state, *, archived_summary):
                    self.assertTrue(lock._operation_lock.locked())
                    self.assertIs(actual_prepared, prepared)
                    self.assertIs(actual_state, state)
                    job = details["job"]
                    calls.append(job["run_id"])
                    raw = (record_root / (job["run_id"] + ".json")).read_bytes()
                    return {"archived_metadata": {
                        "component_replay_required": True, "qualification_eligible": False,
                        "job_record_raw_sha256": hashlib.sha256(raw).hexdigest(),
                        "ack_pin": {"path": "/root-archive/" + job["run_id"],
                                    "raw_sha256": "c" * 64, "semantic_sha256": "d" * 64},
                    }}
                with mock.patch.object(m, "_prepare_source5_context", return_value=(manifest, prepared, state, pin)), \
                     mock.patch.object(m, "_source5_analysis_epoch", return_value="e" * 64), \
                     mock.patch.object(m, "_source5_finished_structural_summary", side_effect=lambda value: value), \
                     mock.patch.object(m, "_validate_source5_authorization", side_effect=verify) as authority:
                    yield {"lock": lock, "pin": pin, "manifest": manifest, "prepared": prepared,
                           "state": state, "jobs": jobs, "records": records,
                           "ledger": ledger, "record_root": record_root,
                           "authority": authority, "verify": verify, "calls": calls}

    def replay(self, case):
        return m.source5_phase_resume_prefix_locked(case["lock"], case["pin"], "confirmation")

    def test_successful_prefix_preserves_original_ordinals_without_mutation(self):
        with self.case() as c:
            before = copy.deepcopy(c["state"])
            proof = self.replay(c)
            self.assertEqual(proof["next_index"], 2)
            self.assertEqual(proof["job_count"], 3)
            self.assertEqual([r["job"] for r in proof["completed_records"]], c["jobs"][:2])
            self.assertEqual(c["calls"], [j["run_id"] for j in c["jobs"][:2]])
            self.assertEqual(c["state"], before)
            self.assertTrue(proof["component_replay_required"])
            self.assertTrue(proof["archive_reclaim_recheck_required"])
            self.assertFalse(proof["qualification_eligible"])
            self.assertFalse(c["lock"]._operation_lock.locked())

    def test_empty_retained_ledger_has_no_consumed_ordinal(self):
        with self.case(0) as c:
            self.assertEqual(self.replay(c)["next_index"], 0)
            self.assertEqual(c["calls"], [])

    def test_complete_prefix_does_not_replace_last_ordinal(self):
        with self.case(3) as c:
            self.assertEqual(self.replay(c)["next_index"], 3)

    def test_pending_or_failed_owner_windows_are_rejected(self):
        for field, value in (("source5_pending", "auth"), ("pending", "legacy"),
                             ("source5_cleanup_blocked", True), ("cleanup_blocked", True),
                             ("source5_failed_owner_window", True)):
            with self.subTest(field=field), self.case() as c:
                c["state"][field] = value
                with self.assertRaisesRegex(m.ChronologyError, "clean completed"):
                    self.replay(c)
                self.assertEqual(c["calls"], [])

    def test_seen_but_unrecorded_ordinal_cannot_be_retried(self):
        with self.case() as c:
            c["state"]["source5_seen_jobs"].add(("confirmation", "original-2"))
            with self.assertRaisesRegex(m.ChronologyError, "consumed original"):
                self.replay(c)

    def test_missing_terminal_cannot_be_skipped(self):
        with self.case() as c:
            del c["state"]["source5_finished"][("confirmation", "original-1")]
            with self.assertRaisesRegex(m.ChronologyError, "consumed original"):
                self.replay(c)

    def test_unsuccessful_terminal_cannot_be_skipped(self):
        with self.case() as c:
            c["state"]["source5_finished"][("confirmation", "original-0")]["state"] = "invalid_pair"
            with self.assertRaisesRegex(m.ChronologyError, "successful durable"):
                self.replay(c)

    def test_reordered_ledger_cannot_choose_next_ordinal(self):
        with self.case() as c:
            c["ledger"].write_bytes(b"".join(m.canonical_bytes(r) for r in reversed(c["records"])))
            with self.assertRaisesRegex(m.ChronologyError, "reordered"):
                self.replay(c)

    def test_changed_record_cannot_match_retained_ledger(self):
        with self.case() as c:
            record = copy.deepcopy(c["records"][0])
            record["record_sha256"] = "f" * 64
            (c["record_root"] / "original-0.json").write_bytes(m.canonical_bytes(record))
            with self.assertRaisesRegex(m.ChronologyError, "canonical original ledger"):
                self.replay(c)

    def test_nonprivate_record_is_rejected(self):
        with self.case() as c:
            (c["record_root"] / "original-0.json").chmod(0o644)
            with self.assertRaisesRegex(m.ChronologyError, "private single-link"):
                self.replay(c)

    def test_missing_signed_ack_is_not_local_origin_fallback(self):
        with self.case() as c:
            c["authority"].side_effect = None
            c["authority"].return_value = {}
            with self.assertRaisesRegex(m.ChronologyError, "fresh signed archive"):
                self.replay(c)

    def test_signed_ack_for_another_record_is_rejected(self):
        with self.case() as c:
            def wrong(*args, **kwargs):
                value = c["verify"](*args, **kwargs)
                value["archived_metadata"]["job_record_raw_sha256"] = "0" * 64
                return value
            c["authority"].side_effect = wrong
            with self.assertRaisesRegex(m.ChronologyError, "fresh signed archive"):
                self.replay(c)

    def test_ack_rejection_propagates_and_releases_plain_operation_mutex(self):
        with self.case() as c:
            c["authority"].side_effect = m.ChronologyError("signed ACK rejected")
            with self.assertRaisesRegex(m.ChronologyError, "signed ACK rejected"):
                self.replay(c)
            self.assertFalse(c["lock"]._operation_lock.locked())

    def test_cached_ledger_cannot_hide_a_change_during_ack_replay(self):
        with self.case() as c:
            def change(*args, **kwargs):
                value = c["verify"](*args, **kwargs)
                if len(c["calls"]) == 2:
                    with c["ledger"].open("ab") as f:
                        f.write(m.canonical_bytes({"job": c["jobs"][2]}))
                return value
            c["authority"].side_effect = change
            with self.assertRaisesRegex(m.ChronologyError, "ledger scope"):
                self.replay(c)

    def test_journal_change_during_ack_replay_invalidates_prefix(self):
        with self.case() as c:
            def change(*args, **kwargs):
                value = c["verify"](*args, **kwargs)
                c["state"]["head"] = "f" * 64
                return value
            c["authority"].side_effect = change
            with self.assertRaisesRegex(m.ChronologyError, "journal/ledger scope"):
                self.replay(c)

    def test_legacy_execution_cannot_claim_archived_restart(self):
        with self.case() as c:
            c["manifest"]["schema"] = m.SOURCE5_EXECUTION_SCHEMA_V3
            with self.assertRaisesRegex(m.ChronologyError, "clean completed"):
                self.replay(c)

    def test_live_lock_is_required(self):
        with self.assertRaises(m.ChronologyError):
            m.source5_phase_resume_prefix_locked(object(), {}, "confirmation")


if __name__ == "__main__":
    unittest.main()
