"""Controller seam tests; Source/GPG and APP boundaries are explicit mocks.

Real private files exercise prefix custody. These tests do not qualify an
application run, signed 360-owner export, or the full campaign.
"""
import contextlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ROOT = Path(__file__).parent
h = load("source5_preparatory_dispatch_controller", ROOT / "application-source5-campaign.py")
base = load("source5_preparatory_dispatch_base_cases", ROOT / "test-application-source5-campaign.py")


class PreparatoryRoutingTests(unittest.TestCase):
    def test_all_and_exploration_route_only_to_preparatory_execution(self):
        context = types.SimpleNamespace(scope=h.PREPARATORY_SCOPE)
        for phase in ("all", "exploration"):
            with self.subTest(phase=phase), mock.patch.object(
                    h, "run_preparatory_exploration", return_value={"fixture": phase}) as run, \
                    mock.patch.object(h, "analyze_phase") as analysis:
                self.assertEqual(h.run_host(context, phase), {"fixture": phase})
                run.assert_called_once_with(context)
                analysis.assert_not_called()

    def test_preparatory_scope_refuses_every_later_phase(self):
        context = types.SimpleNamespace(scope=h.PREPARATORY_SCOPE)
        for phase in ("aa", "confirmation", "fixed_analysis", "pressure",
                      "pressure_analysis", "soak", "final_analysis"):
            with self.subTest(phase=phase), mock.patch.object(
                    h, "run_preparatory_exploration") as run:
                with self.assertRaisesRegex(h.Source5CampaignError, "closed to original exploration"):
                    h.run_host(context, phase)
                run.assert_not_called()

    def test_export_cli_requires_manifest_and_host(self):
        args = h._parser().parse_args([
            "export-preparatory-capacity-pilot", "--manifest", "/private/execution.json",
            "--host-id", "original-host",
        ])
        self.assertEqual(args.command, "export-preparatory-capacity-pilot")
        self.assertEqual(args.manifest, Path("/private/execution.json"))
        self.assertEqual(args.host_id, "original-host")


class PreparatoryResumeTests(unittest.TestCase):
    @contextlib.contextmanager
    def case(self):
        helper = base.Source5ResumePrefixControllerTests()
        helper.controller = h
        with tempfile.TemporaryDirectory(prefix="source5-prep-dispatch-prefix-") as temporary:
            context, jobs, phase_root, record, raw, ack_pin, state, prepared = \
                helper._prefix_fixture(Path(temporary))
            context.manifest["schema"] = h.PREPARATORY_EXECUTION_SCHEMA
            context.output_root = Path(temporary)
            rows = [
                {"path": str(phase_root / "job-records"), "kind": "tree",
                 "role": "directory_node", "storage_root": str(context.output_root),
                 "host_id": context.host_id, "max_inodes": 1},
                {"path": str(phase_root / "controller-ledger.jsonl"), "kind": "file",
                 "role": "source5_phase_ledger", "storage_root": str(context.output_root),
                 "host_id": context.host_id, "max_inodes": 1, "phase": "exploration",
                 "max_file_bytes": 4096},
            ]
            context.modules[h.EVIDENCE_BUDGET_SOURCE_PATH] = types.SimpleNamespace(
                verify_path_catalogue_chunks=lambda catalogue: catalogue,
                iter_path_catalogue_rows=lambda catalogue: iter(catalogue["rows"]))
            context.preparatory_budget = {"path_catalogue": {"rows": rows}}
            context.preparatory_budget_raw = h.canonical_bytes(context.preparatory_budget)
            context.preparatory_budget_pin = {"raw_sha256": h.sha256(context.preparatory_budget_raw)}
            prefix = context.chronology.source5_phase_resume_prefix_locked(None, None, None)
            context.chronology.source5_preparatory_exploration_resume_prefix_locked = \
                mock.Mock(return_value=prefix)
            context.chronology.source5_phase_resume_prefix_locked = mock.Mock(
                side_effect=AssertionError("legacy phase API must not authorize prep resume"))
            closure = {"job_record": record, "job_record_raw": raw, "ack_pin": ack_pin}
            with contextlib.ExitStack() as stack:
                for name, value in {
                    "_validate_locked_context": {"prepared": prepared, "state": state},
                    "_phase_root": phase_root,
                    "_phase_ledger_records": [record],
                    "_source5_job_record_byte_bound": 4096,
                    "_source5_verify_persisted_archive_read_closure": closure,
                }.items():
                    stack.enter_context(mock.patch.object(h, name, return_value=value))
                metadata = stack.enter_context(mock.patch.object(h, "_source5_verify_completed_archive_metadata"))
                reclaim = stack.enter_context(mock.patch.object(h, "_source5_recheck_reclaimed_job_origins"))
                stack.enter_context(mock.patch.object(h, "_source5_match_finished_record"))
                yield context, jobs, phase_root, record, prefix, metadata, reclaim

    def test_preparatory_resume_uses_two_argument_sourcea_api_and_rechecks_reclaim(self):
        with self.case() as (context, jobs, root, record, prefix, metadata, reclaim):
            lock = object()
            self.assertEqual(h._source5_validate_resume_prefix_locked(
                context, lock, "exploration", jobs), (1, [record]))
            context.chronology.source5_preparatory_exploration_resume_prefix_locked.assert_called_once_with(
                lock, h.api_pin(context.manifest_pin))
            context.chronology.source5_phase_resume_prefix_locked.assert_not_called()
            metadata.assert_called_once()
            reclaim.assert_called_once()
            self.assertEqual((root / "job-records" / (jobs[0]["run_id"] + ".json")).read_bytes(),
                             h.canonical_bytes(record))

    def test_preparatory_resume_rejects_later_phase(self):
        with self.case() as (context, jobs, _root, _record, _prefix, _metadata, _reclaim):
            with self.assertRaisesRegex(h.Source5CampaignError, "closed to original exploration"):
                h._source5_validate_resume_prefix_locked(context, object(), "aa", jobs)
            context.chronology.source5_preparatory_exploration_resume_prefix_locked.assert_not_called()

    def test_changed_source_epoch_is_rejected_before_metadata_reuse(self):
        with self.case() as (context, jobs, _root, _record, prefix, metadata, reclaim):
            prefix["source_epoch"] = "0" * 64
            with self.assertRaisesRegex(h.Source5CampaignError, "current Source/journal epoch"):
                h._source5_validate_resume_prefix_locked(context, object(), "exploration", jobs)
            metadata.assert_not_called()
            reclaim.assert_not_called()

    def test_changed_retained_record_is_rejected_before_reclaim(self):
        with self.case() as (context, jobs, root, _record, _prefix, metadata, reclaim):
            (root / "job-records" / (jobs[0]["run_id"] + ".json")).write_bytes(b"{}\n")
            with self.assertRaisesRegex(h.Source5CampaignError, "exact row/pin"):
                h._source5_validate_resume_prefix_locked(context, object(), "exploration", jobs)
            metadata.assert_not_called()
            reclaim.assert_not_called()

    def test_unexplained_retained_output_is_rejected(self):
        with self.case() as (context, jobs, root, _record, _prefix, metadata, _reclaim):
            (root / "unexpected").write_bytes(b"unexplained")
            with self.assertRaisesRegex(h.Source5CampaignError, "unsafe or unexplained"):
                h._source5_validate_resume_prefix_locked(context, object(), "exploration", jobs)
            metadata.assert_not_called()


class PreparatoryReadProviderTests(unittest.TestCase):
    def context(self):
        schedule = [{"request_ordinal": index,
                     "job": {"run_id": f"original-{index}", "ordinal": index + 1},
                     "analysis_phase": "exploration", "use": "capacity_pilot_export"}
                    for index in range(360)]
        return types.SimpleNamespace(
            manifest={"schema": h.PREPARATORY_EXECUTION_SCHEMA},
            scope=h.PREPARATORY_SCOPE, source5_archive_read_schedule=schedule)

    @contextlib.contextmanager
    def io(self, cursor, *, pending=False):
        state = {"cursor": cursor, "pending": pending}
        calls = []

        @contextlib.contextmanager
        def completed(_context, row):
            calls.append(("replay", row["request_ordinal"]))
            yield {"fixture_ordinal": row["request_ordinal"]}

        @contextlib.contextmanager
        def live(context, job, purpose):
            index = state["cursor"]
            self.assertEqual(context.source5_archive_read_schedule[index]["job"], job)
            self.assertEqual(purpose, "exploration")
            calls.append(("complete_pending" if state["pending"] else "publish", index))
            yield {"fixture_ordinal": index}
            state["cursor"] += 1
            state["pending"] = False

        with mock.patch.object(h, "_source5_archive_read_control_ledger_state",
                               side_effect=lambda *_args, **_kwargs:
                               (state["cursor"], "0" * 64, state["cursor"] * 2,
                                {"fixture_pending": True} if state["pending"] else None)), \
                mock.patch.object(h, "_source5_replay_completed_archive_read_view", side_effect=completed), \
                mock.patch.object(h, "archived_job_read_view", side_effect=live):
            yield state, calls

    def test_fresh_export_consumes_exact_original_360_rows(self):
        context = self.context()
        with self.io(0) as (state, calls):
            provider = h._Source5PreparatoryArchiveReadProvider(context)
            for row in context.source5_archive_read_schedule:
                with provider.open_view(row["job"], "exploration", use="capacity_pilot_export") as view:
                    self.assertEqual(view["fixture_ordinal"], row["request_ordinal"])
            self.assertEqual(state["cursor"], 360)
            self.assertEqual(calls, [("publish", index) for index in range(360)])

    def test_partial_export_restart_replays_prefix_and_appends_only_suffix(self):
        context = self.context()
        with self.io(137) as (state, calls):
            provider = h._Source5PreparatoryArchiveReadProvider(context)
            for row in context.source5_archive_read_schedule:
                with provider.open_view(row["job"], "exploration", use="capacity_pilot_export"):
                    pass
            self.assertEqual(state["cursor"], 360)
            self.assertEqual(calls, [("replay", index) for index in range(137)] +
                             [("publish", index) for index in range(137, 360)])

    def test_pending_suffix_window_closes_before_completed_prefix_is_replayed(self):
        context = self.context()
        with self.io(137, pending=True) as (state, calls):
            provider = h._Source5PreparatoryArchiveReadProvider(context)
            for row in context.source5_archive_read_schedule:
                with provider.open_view(row["job"], "exploration", use="capacity_pilot_export"):
                    pass
            self.assertEqual(state["cursor"], 360)
            self.assertFalse(state["pending"])
            self.assertEqual(calls, [("complete_pending", 137)] +
                             [("replay", index) for index in range(138)] +
                             [("publish", index) for index in range(138, 360)])

    def test_complete_export_restart_has_no_new_control_rows(self):
        context = self.context()
        with self.io(360) as (state, calls):
            provider = h._Source5PreparatoryArchiveReadProvider(context)
            for row in context.source5_archive_read_schedule:
                with provider.open_view(row["job"], "exploration", use="capacity_pilot_export"):
                    pass
            self.assertEqual(state["cursor"], 360)
            self.assertEqual(calls, [("replay", index) for index in range(360)])

    def test_skipped_job_is_rejected_before_io(self):
        context = self.context()
        with self.io(0) as (_state, calls):
            provider = h._Source5PreparatoryArchiveReadProvider(context)
            with self.assertRaisesRegex(h.Source5CampaignError, "original export order"):
                with provider.open_view(context.source5_archive_read_schedule[1]["job"],
                                        "exploration", use="capacity_pilot_export"):
                    self.fail("unexpected read")
            self.assertEqual(calls, [])

    def test_wrong_use_is_rejected_before_io(self):
        context = self.context()
        with self.io(0) as (_state, calls):
            provider = h._Source5PreparatoryArchiveReadProvider(context)
            with self.assertRaisesRegex(h.Source5CampaignError, "original export order"):
                with provider.open_view(context.source5_archive_read_schedule[0]["job"],
                                        "exploration", use="phase_analysis"):
                    self.fail("unexpected read")
            self.assertEqual(calls, [])

    def test_failed_consumer_does_not_advance_original_ordinal(self):
        context = self.context()
        with self.io(0) as (state, calls):
            provider = h._Source5PreparatoryArchiveReadProvider(context)
            with self.assertRaisesRegex(RuntimeError, "consumer failed"):
                with provider.open_view(context.source5_archive_read_schedule[0]["job"],
                                        "exploration", use="capacity_pilot_export"):
                    raise RuntimeError("consumer failed")
            self.assertEqual(provider.index, 0)
            self.assertEqual(state["cursor"], 0)
            self.assertEqual(calls, [("publish", 0)])

    def test_extra_export_row_is_rejected(self):
        context = self.context()
        with self.io(360) as (_state, calls):
            provider = h._Source5PreparatoryArchiveReadProvider(context)
            provider.index = 360
            with self.assertRaisesRegex(h.Source5CampaignError, "no additional original row"):
                with provider.open_view(context.source5_archive_read_schedule[0]["job"],
                                        "exploration", use="capacity_pilot_export"):
                    self.fail("unexpected read")
            self.assertEqual(calls, [])

    def test_foreign_profile_is_rejected(self):
        context = self.context()
        context.manifest["schema"] = h.EXECUTION_SCHEMA_V4
        with self.assertRaisesRegex(h.Source5CampaignError, "exact 360-row schedule"):
            h._Source5PreparatoryArchiveReadProvider(context)


class PreparatoryPhaseRootTests(unittest.TestCase):
    @contextlib.contextmanager
    def case(self):
        with tempfile.TemporaryDirectory(prefix="source5-prep-phase-children-") as temporary:
            root = Path(temporary).resolve()
            phase = root / "exploration"
            phase.mkdir(mode=0o700)
            rows = []
            for name in ("job-records", "cleanup-sidecars", "fixed-host-receipts"):
                (phase / name).mkdir(mode=0o700)
                rows.append({"path": str(phase / name), "kind": "tree", "role": "directory_node",
                             "storage_root": str(root), "host_id": "host", "max_inodes": 1})
            rows.extend([
                {"path": str(phase / "controller-ledger.jsonl"), "kind": "file",
                 "role": "source5_phase_ledger", "phase": "exploration",
                 "storage_root": str(root), "host_id": "host", "max_file_bytes": 4096},
                {"path": str(phase / "capacity-pilot.json"), "kind": "file",
                 "role": "capacity_artifact", "phase": "exploration", "run_id": None,
                 "storage_root": str(root), "host_id": "host", "max_file_bytes": 4096},
            ])
            ledger = phase / "controller-ledger.jsonl"
            ledger.write_bytes(b"fixture retained ledger\n")
            ledger.chmod(0o600)
            module = types.SimpleNamespace(
                verify_path_catalogue_chunks=lambda value: value,
                iter_path_catalogue_rows=lambda value: iter(value["rows"]))
            budget = {"path_catalogue": {"rows": rows}}
            raw = h.canonical_bytes(budget)
            context = types.SimpleNamespace(
                manifest={"schema": h.PREPARATORY_EXECUTION_SCHEMA}, host_id="host", output_root=root,
                preparatory_budget=budget, preparatory_budget_raw=raw,
                preparatory_budget_pin={"raw_sha256": h.sha256(raw)},
                modules={h.EVIDENCE_BUDGET_SOURCE_PATH: module})
            yield context, phase

    def test_catalogued_receipt_and_cleanup_directories_survive_resume(self):
        with self.case() as (context, phase):
            h._source5_validate_phase_root_children(context, phase, "exploration", 1)

    def test_reserved_future_pilot_declaration_does_not_block_initial_dispatch(self):
        with self.case() as (context, phase):
            h._source5_validate_phase_root_children(context, phase, "exploration", 0)
            self.assertFalse((phase / "capacity-pilot.json").exists())

    def test_existing_pilot_requires_complete_original_prefix(self):
        with self.case() as (context, phase):
            pilot = phase / "capacity-pilot.json"
            pilot.write_bytes(b"fixture pilot bytes\n")
            pilot.chmod(0o600)
            with self.assertRaisesRegex(h.Source5CampaignError, "unsafe or unexplained"):
                h._source5_validate_phase_root_children(context, phase, "exploration", 359)
            h._source5_validate_phase_root_children(context, phase, "exploration", 360)

    def test_unlisted_phase_child_is_rejected(self):
        with self.case() as (context, phase):
            (phase / "foreign").mkdir(mode=0o700)
            with self.assertRaisesRegex(h.Source5CampaignError, "unsafe or unexplained"):
                h._source5_validate_phase_root_children(context, phase, "exploration", 1)

    def test_catalogued_directory_alias_is_rejected(self):
        with self.case() as (context, phase):
            child = phase / "fixed-host-receipts"
            child.rmdir()
            child.symlink_to(phase / "job-records", target_is_directory=True)
            with self.assertRaisesRegex(h.Source5CampaignError, "traverses an alias"):
                h._source5_validate_phase_root_children(context, phase, "exploration", 1)

    def test_nonprivate_catalogued_directory_is_rejected(self):
        with self.case() as (context, phase):
            (phase / "cleanup-sidecars").chmod(0o755)
            with self.assertRaisesRegex(h.Source5CampaignError, "private directory"):
                h._source5_validate_phase_root_children(context, phase, "exploration", 1)

    def test_nonprivate_direct_file_is_rejected(self):
        with self.case() as (context, phase):
            (phase / "controller-ledger.jsonl").chmod(0o644)
            with self.assertRaisesRegex(h.Source5CampaignError, "bounded private file"):
                h._source5_validate_phase_root_children(context, phase, "exploration", 1)


class PreparatoryReclaimAnchorTests(unittest.TestCase):
    @contextlib.contextmanager
    def case(self):
        with tempfile.TemporaryDirectory(prefix="source5-prep-reclaim-anchor-") as temporary:
            root = Path(temporary).resolve()
            artifact, output = root / "artifacts", root / "output"
            artifact.mkdir(mode=0o700)
            output.mkdir(mode=0o700)
            context = types.SimpleNamespace(
                manifest={"schema": h.PREPARATORY_EXECUTION_SCHEMA}, scope=h.PREPARATORY_SCOPE,
                artifact_root=artifact, output_root=output)
            entries, rows = [], []
            for domain, name in ((artifact, "pair-result.json"), (output, "strict-host-receipt.json")):
                path = domain / name
                raw = ("actual local " + name + "\n").encode()
                path.write_bytes(raw)
                path.chmod(0o600)
                entries.append({"origin_path": str(path), "byte_count": len(raw),
                                "raw_sha256": h.sha256(raw)})
                rows.append({"path": str(path), "kind": "file", "storage_root": str(domain),
                             "origin_pin": None, "phase": "exploration", "run_id": "original-1",
                             "max_file_bytes": len(raw)})
            yield root, context, {"entries": entries}, rows

    def test_artifact_and_output_receipt_have_one_private_nofollow_anchor(self):
        with self.case() as (root, context, checkpoint, rows):
            archive = load("source5_preparatory_reclaim_actual_archive", ROOT / "application-source5-evidence-archive.py")
            anchor = h._source5_preparatory_reclaim_anchor(context, checkpoint=checkpoint, declarations=rows)
            self.assertEqual(anchor, root)
            for entry in checkpoint["entries"]:
                descriptor, literal = archive._staged_descriptor(entry["origin_path"], str(anchor), entry)
                self.assertEqual(descriptor["path"], entry["origin_path"])
                self.assertEqual(descriptor["raw_sha256"], entry["raw_sha256"])
                self.assertIsNone(literal)
                self.assertTrue(Path(entry["origin_path"]).exists())

    def test_anchor_is_checked_before_any_origin_is_present(self):
        with self.case() as (root, context, _checkpoint, _rows):
            for domain in (context.artifact_root, context.output_root):
                for path in domain.iterdir():
                    path.unlink()
            self.assertEqual(h._source5_preparatory_reclaim_anchor(context), root)

    def test_nonprivate_common_ancestor_is_rejected(self):
        with self.case() as (root, context, _checkpoint, _rows):
            root.chmod(0o755)
            with self.assertRaisesRegex(h.Source5CampaignError, "not owned and private"):
                h._source5_preparatory_reclaim_anchor(context)

    def test_nonprivate_reserved_origin_root_is_rejected(self):
        with self.case() as (_root, context, _checkpoint, _rows):
            context.output_root.chmod(0o755)
            with self.assertRaisesRegex(h.Source5CampaignError, "not owned and private"):
                h._source5_preparatory_reclaim_anchor(context)

    def test_origin_domain_alias_is_rejected(self):
        with self.case() as (root, context, _checkpoint, _rows):
            alias = root / "aliased-output"
            alias.symlink_to(context.output_root, target_is_directory=True)
            context.output_root = alias
            with self.assertRaisesRegex(h.Source5CampaignError, "canonical absolute"):
                h._source5_preparatory_reclaim_anchor(context)

    def test_unlisted_sibling_is_not_authorized_by_the_common_ancestor(self):
        with self.case() as (root, context, checkpoint, rows):
            path = root / "unlisted-secret"
            path.write_bytes(b"unlisted sibling\n")
            checkpoint["entries"].append({"origin_path": str(path), "byte_count": path.stat().st_size,
                                          "raw_sha256": h.sha256(path.read_bytes())})
            with self.assertRaisesRegex(h.Source5CampaignError, "exact signed job catalogue row"):
                h._source5_preparatory_reclaim_anchor(context, checkpoint=checkpoint, declarations=rows)
            self.assertEqual(path.read_bytes(), b"unlisted sibling\n")

    def test_immutable_catalogued_input_is_not_reclaimable(self):
        with self.case() as (_root, context, checkpoint, rows):
            rows[0]["origin_pin"] = {"raw_sha256": checkpoint["entries"][0]["raw_sha256"]}
            with self.assertRaisesRegex(h.Source5CampaignError, "exact signed job catalogue row"):
                h._source5_preparatory_reclaim_anchor(context, checkpoint=checkpoint, declarations=rows)

    def test_duplicate_origin_is_rejected(self):
        with self.case() as (_root, context, checkpoint, rows):
            checkpoint["entries"].append(dict(checkpoint["entries"][0]))
            with self.assertRaisesRegex(h.Source5CampaignError, "exact signed job catalogue row"):
                h._source5_preparatory_reclaim_anchor(context, checkpoint=checkpoint, declarations=rows)


class PreparatoryDispatchStorageTests(unittest.TestCase):
    @contextlib.contextmanager
    def case(self, completed=0):
        with tempfile.TemporaryDirectory(prefix="source5-prep-dispatch-space-") as temporary:
            base_root = Path(temporary).resolve()
            roots = {}
            for role in ("artifact", "output", "scratch", "evidence_store"):
                roots[role] = base_root / role
                roots[role].mkdir(mode=0o700)
            jobs = [{"phase": "exploration", "host_id": "host",
                     "run_id": f"original-{index}", "ordinal": index + 1}
                    for index in range(360)]
            phase = roots["output"] / "campaign/source5/host/exploration"
            phase.mkdir(parents=True, mode=0o700)
            for parent in (phase.parent, phase.parent.parent, phase.parent.parent.parent):
                parent.chmod(0o700)
            rows = []
            saved = {}

            def file(path, role, raw, *, origin=False, grouped=False):
                path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
                path.write_bytes(raw)
                path.chmod(0o600)
                domain = roots["artifact"] if path.is_relative_to(roots["artifact"]) else roots["output"]
                row = {"path": str(path), "kind": "file", "role": role,
                       "storage_root": str(domain), "max_bytes": 65536,
                       "max_file_bytes": 65536, "max_inodes": 1,
                       "phase": "exploration" if grouped else None,
                       "run_id": jobs[0]["run_id"] if grouped else None,
                       "origin_pin": {"raw_sha256": h.sha256(raw), "semantic_sha256": None}
                       if origin else None}
                rows.append(row)
                saved[str(path)] = raw
                return {"path": str(path), "raw_sha256": h.sha256(raw)}

            manifest = {"schema": h.PREPARATORY_EXECUTION_SCHEMA, "campaign_id": "campaign"}
            manifest_pin = file(roots["artifact"] / "execution.json", "execution_manifest",
                                h.canonical_bytes(manifest))
            width_pin = file(roots["artifact"] / "width.json", "preparatory_journal_width_contract",
                             b"{\"fixture_width\":true}\n")
            reservation_pin = file(roots["artifact"] / "reservation.json", "storage_reservation",
                                   b"{\"fixture_reservation\":true}\n")
            reservation_pin.update(semantic_sha256="a" * 64,
                                   byte_count=len(saved[reservation_pin["path"]]))
            immutable_pin = file(roots["artifact"] / "immutable.json", "source5_job_row_catalogue",
                                 b"immutable original raw bytes\n", origin=True)
            records = [{"job": jobs[0], "state": "valid_pair"}] if completed else []
            ledger_pin = file(phase / "controller-ledger.jsonl", "source5_phase_ledger",
                              b"".join(h.canonical_bytes(record) for record in records))
            journal_pin = file(roots["output"] / "journal.jsonl", "journal", b"fixture replayed journal\n")
            journal_stat = Path(journal_pin["path"]).stat()
            control_pin = file(roots["output"] / "control.jsonl", "source5_archive_read_control_ledger", b"")
            control_stat = Path(control_pin["path"]).stat()
            closures = {}
            declarations = []
            if completed:
                closure = {"job_record": records[0]}
                for key, role in (("job_record", "source5_job_record"),
                                  ("request", "source5_checkpoint_request"),
                                  ("checkpoint", "source5_checkpoint"),
                                  ("manifest", "source5_object_manifest"),
                                  ("ack", "source5_archive_ack"),
                                  ("signature", "source5_archive_signature")):
                    pin = file(roots["output"] / (key + ".json"), role,
                               ("fixture signed " + key + "\n").encode(), grouped=True)
                    declarations.append(rows[-1])
                    closure[key + "_pin"] = {**pin, "path": "/Root-private/" + key}
                closures[jobs[0]["run_id"]] = closure
            for root in roots.values():
                rows.append({"path": str(root), "kind": "tree", "role": "directory_node",
                             "storage_root": str(root), "max_bytes": 0, "max_file_bytes": 0,
                             "max_inodes": 1, "phase": None, "run_id": None, "origin_pin": None})
            budget_path = roots["artifact"] / "budget.json"
            rows.append({"path": str(budget_path), "kind": "file", "role": "host_evidence_budget",
                         "storage_root": str(roots["artifact"]), "max_bytes": 65536,
                         "max_file_bytes": 65536, "max_inodes": 1,
                         "phase": None, "run_id": None, "origin_pin": None})
            catalogue = {"rows": rows, "chunks": []}
            budget = {"path_catalogue": catalogue, "storage_reservation": {
                "pin": reservation_pin,
                "roots": [{"path": str(root), "role": role, "reserved_bytes": 1048576,
                           "reserved_inodes": 10000, "filesystem_id": str(root.stat().st_dev)}
                          for role, root in roots.items()],
                "required_bytes_by_root": {str(root): 1048576 for root in roots.values()},
                "required_inodes_by_root": {str(root): 10000 for root in roots.values()},
            }}
            budget_raw = h.canonical_bytes(budget)
            budget_path.write_bytes(budget_raw)
            budget_path.chmod(0o600)
            saved[str(budget_path)] = budget_raw
            finished = {("exploration", job["run_id"]): {"state": "valid_pair"}
                        for job in jobs[:completed]}
            state = {"source5_finished": finished, "source5_seen_jobs": set(finished),
                     "file_stat": (journal_stat.st_dev, journal_stat.st_ino, journal_stat.st_mode,
                                   journal_stat.st_size, journal_stat.st_mtime_ns, journal_stat.st_ctime_ns)}
            module = types.SimpleNamespace(
                verify_path_catalogue_chunks=lambda value: value,
                iter_path_catalogue_rows=lambda value: iter(value["rows"]),
                FAILURE_WINDOW_ONLY_ROLES=frozenset(),
                SOURCE5_ARCHIVE_READ_CONTROL_ROLE="source5_archive_read_control_ledger")
            context = types.SimpleNamespace(
                manifest=manifest, manifest_pin=manifest_pin, scope=h.PREPARATORY_SCOPE,
                host_id="host", artifact_root=roots["artifact"], output_root=roots["output"],
                plan={"jobs": {"exploration": jobs}},
                preparatory_budget=budget, preparatory_budget_raw=budget_raw,
                preparatory_budget_pin={"path": str(budget_path), "raw_sha256": h.sha256(budget_raw)},
                preparatory_width_contract={"fixture_width": True}, preparatory_width_pin=width_pin,
                modules={h.EVIDENCE_BUDGET_SOURCE_PATH: module},
                source5_archive_read_slot_paths={module.SOURCE5_ARCHIVE_READ_CONTROL_ROLE: control_pin["path"]},
                source5_archive_read_ledger_file_identity=(
                    control_stat.st_dev, control_stat.st_ino, control_stat.st_mode, control_stat.st_size,
                    control_stat.st_mtime_ns, control_stat.st_ctime_ns, control_stat.st_nlink, control_stat.st_uid),
                source5_archive_read_ledger_byte_count=0,
                source5_archive_read_ledger_raw_sha256=h.sha256(b""))
            with contextlib.ExitStack() as stack:
                for name, value in {
                    "_source5_validate_resume_prefix_locked": (completed, records),
                    "_validate_locked_context": {"state": state},
                    "_validate_source5_preparatory_profile_artifacts": None,
                    "_source5_archive_read_control_ledger_state": (0, "0" * 64, 0, None),
                    "_source5_verify_completed_archive_metadata": declarations,
                    "_source5_recheck_reclaimed_job_origins": None,
                    "_source5_job_path_declarations": declarations,
                }.items():
                    stack.enter_context(mock.patch.object(h, name, return_value=value))
                stack.enter_context(mock.patch.object(
                    h, "_source5_verify_persisted_archive_read_closure",
                    side_effect=lambda _context, _phase, job: closures[job["run_id"]]))
                yield context, rows, saved, roots, immutable_pin, completed

    def test_existing_budget_dispatch_rechecks_common_anchor_before_owner(self):
        with self.case() as (context, _rows, _saved, _roots, _immutable, completed):
            context.artifact_root.parent.chmod(0o755)
            with self.assertRaisesRegex(h.Source5CampaignError, "not owned and private"):
                h._source5_preparatory_dispatch_storage_requirements(context, object(), completed)

    def test_setup_frontier_credits_only_exact_current_bytes_once(self):
        with self.case() as (context, _rows, saved, roots, _immutable, completed):
            byte_count, inode_count = h._source5_preparatory_dispatch_storage_requirements(
                context, object(), completed)
            for root in roots.values():
                files = [raw for path, raw in saved.items() if Path(path).is_relative_to(root)]
                self.assertEqual(byte_count[str(root)], 1048576 - sum(map(len, files)))
                self.assertEqual(inode_count[str(root)], 10000 - len(files) - 1)

    def test_completed_signed_metadata_credits_actual_bytes_and_keeps_unused_caps(self):
        with self.case(1) as (context, _rows, saved, roots, _immutable, completed):
            byte_count, _inode_count = h._source5_preparatory_dispatch_storage_requirements(
                context, object(), completed)
            for root in roots.values():
                written = sum(len(raw) for path, raw in saved.items() if Path(path).is_relative_to(root))
                self.assertEqual(byte_count[str(root)], 1048576 - written)

    def test_changed_raw_pinned_file_is_not_space_credit(self):
        with self.case() as (context, _rows, _saved, _roots, immutable, completed):
            Path(immutable["path"]).write_bytes(b"changed original\n")
            with self.assertRaisesRegex(h.Source5CampaignError, "exact private raw identity"):
                h._source5_preparatory_dispatch_storage_requirements(context, object(), completed)

    def test_duplicate_catalogue_path_cannot_receive_two_credits(self):
        with self.case() as (context, rows, _saved, _roots, immutable, completed):
            rows.append(dict(next(row for row in rows if row["path"] == immutable["path"])))
            with self.assertRaisesRegex(h.Source5CampaignError, "credit aliases"):
                h._source5_preparatory_dispatch_storage_requirements(context, object(), completed)

    def test_unexplained_scratch_file_refuses_the_next_owner(self):
        with self.case() as (context, _rows, _saved, roots, _immutable, completed):
            (roots["scratch"] / "unexpected").write_bytes(b"unbudgeted")
            with self.assertRaisesRegex(h.Source5CampaignError, "scratch retains an unexplained"):
                h._source5_preparatory_dispatch_storage_requirements(context, object(), completed)

    def test_uncompleted_owner_output_refuses_the_next_owner(self):
        with self.case() as (context, rows, _saved, roots, _immutable, completed):
            path = roots["artifact"] / "future-helper.json"
            path.write_bytes(b"unexplained future ordinal\n")
            rows.append({"path": str(path), "kind": "file", "role": "source5_helper_input",
                         "storage_root": str(roots["artifact"]), "max_bytes": 65536,
                         "max_file_bytes": 65536, "max_inodes": 1,
                         "phase": "exploration", "run_id": "original-1", "origin_pin": None})
            with self.assertRaisesRegex(h.Source5CampaignError, "uncompleted original ordinal"):
                h._source5_preparatory_dispatch_storage_requirements(context, object(), completed)

    def test_journal_tail_change_after_sourcea_replay_refuses_credit(self):
        with self.case() as (context, rows, _saved, _roots, _immutable, completed):
            path = Path(next(row["path"] for row in rows if row["role"] == "journal"))
            path.write_bytes(path.read_bytes() + b"unreplayed tail\n")
            with self.assertRaisesRegex(h.Source5CampaignError, "journal changed after SourceA replay"):
                h._source5_preparatory_dispatch_storage_requirements(context, object(), completed)


if __name__ == "__main__":
    unittest.main()
