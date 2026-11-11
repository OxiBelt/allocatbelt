#!/usr/bin/env python3
"""Pre-APP capability checks with real local records/locks.

Full prepared-context validation and the fixed numeric owner are explicit
fixture boundaries. No APP launch, genuine prepared epoch, GPG handoff, or
complete pressure owner claim is made by this component suite.
"""
from contextlib import contextmanager
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock


def load(name):
    path = Path(__file__).with_name("application-campaign-chronology.py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class PressurePreAppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chronology = load("source5_preapp_component_a")

    @contextmanager
    def case(self):
        import tempfile
        m = self.chronology
        with tempfile.TemporaryDirectory(prefix="source5-pressure-preapp-") as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            fixed_job = {"phase": "confirmation", "host_id": "host", "run_id": "fixed-original", "ordinal": 1}
            job = {"phase": "pressure", "host_id": "host", "run_id": "pressure-original", "ordinal": 1,
                   "predecessor_run_ids": [fixed_job["run_id"]]}
            heads = [str(i) * 64 for i in range(8)]
            metrics = [{"member": 0}, {"member": 1}]
            metrics_sha = hashlib.sha256(m.canonical_bytes(metrics)).hexdigest()
            record = {"schema": m.SOURCE5_JOB_RECORD_SCHEMA, "state": "valid_pair",
                      "job": fixed_job, "process_metrics": metrics,
                      "qualification_eligible": False,
                      "chronology": {"authorization_id": "fixed-auth",
                                     "authorization_head": heads[1],
                                     "job_terminal_head": heads[2],
                                     "component_sha256": "b" * 64,
                                     "process_metrics_sha256": metrics_sha}}
            record["record_sha256"] = hashlib.sha256(m.canonical_bytes(record)).hexdigest()

            def write(path, value):
                path.parent.mkdir(parents=True, exist_ok=True)
                raw = m.canonical_bytes(value)
                path.write_bytes(raw)
                path.chmod(0o600)
                return {"path": str(path), "raw_sha256": hashlib.sha256(raw).hexdigest()}

            record_path = root / "campaign/source5/host/confirmation/job-records/fixed-original.json"
            pin = write(record_path, record)
            ledger_path = record_path.parent.parent / "controller-ledger.jsonl"
            write(ledger_path, record)
            pair = root / "pressure"
            pair.mkdir(mode=0o700)
            overlay_pin = write(root / "overlay.json", {"chronology": {
                "journal_head": heads[3], "journal_record_count": 3,
                "registration_head": heads[1],
            }})
            recipe = {"job": {"value": job}, "fixed_predecessor": {"record": pin},
                      "execution_overlay": {"artifact": overlay_pin}}
            recipe_pin = write(root / "recipe.json", recipe)
            helper = {"payload": {"recipe_pin": recipe_pin, "output_root": str(pair)}}
            helper_pin = write(root / "helper.json", helper)
            active = {"phase": "pressure", "job": job, "job_index": 0,
                      "authorization_id": "pressure-auth", "helper_input": helper_pin,
                      "output_root": str(pair)}
            manifest_pin = {"path": str(root / "execution.json"), "sha256": "f" * 64}
            manifest = {"schema": m.SOURCE5_EXECUTION_SCHEMA_V4}
            prepared = {"output_root": root, "source_root": Path(__file__).parent.parent,
                        "campaign_id": "campaign", "host_id": "host", "spec": {},
                        "plan": {"jobs": {"pressure": [job], "confirmation": [fixed_job]}},
                        "source5_execution_schema": m.SOURCE5_EXECUTION_SCHEMA_V4,
                        "source5_execution_manifest_pin": {"path": manifest_pin["path"],
                                                           "raw_sha256": manifest_pin["sha256"]},
                        "source5_execution_manifest_raw_sha256": manifest_pin["sha256"],
                        "source_manifest_raw_refs": {}, "original_pins": {},
                        "source": {"source": {"source_tree_sha256": "c" * 64}}}
            state = {"head": heads[3], "record_count": 3, "journal_heads": heads[:4],
                     "source5_seen_jobs": {("confirmation", fixed_job["run_id"])},
                     "source5_pending": None, "source5_authorized": {},
                     "source5_cleanup_blocked": False, "source5_failed_owner_window": False,
                     "source5_finished": {("confirmation", fixed_job["run_id"]): {
                         "state": "valid_pair", "details": {"job": fixed_job},
                     }}}
            proof = {"record": pin, "authorization_id": "fixed-auth",
                     "authorization_head": heads[1], "job_terminal_head": heads[2],
                     "record_sha256": record["record_sha256"], "metrics_sha256": metrics_sha,
                     "process_metrics": metrics}
            def pin_document(label):
                raw = m.canonical_bytes({"fixture_boundary": label})
                return raw, {"path": str(root / (label + ".json")),
                             "raw_sha256": hashlib.sha256(raw).hexdigest(),
                             "semantic_sha256": "a" * 64}

            checkpoint_raw, checkpoint_pin = pin_document("checkpoint")
            manifest_raw, object_manifest_pin = pin_document("object-manifest")
            request_raw, request_pin = pin_document("request")
            authority = {"checkpoint_pin": checkpoint_pin, "object_manifest_pin": object_manifest_pin,
                         "ack_pin": {"path": str(root / "root-owned-ack.json"),
                                     "raw_sha256": "b" * 64, "semantic_sha256": "c" * 64},
                         "signature_pin": {"path": str(root / "root-owned-ack.sig"),
                                           "raw_sha256": "d" * 64, "signer_fingerprint": "e" * 40},
                         "request_pin": request_pin}
            capture = {"schema": "allocatbelt.application-source5-archived-job-read-view.v1",
                       "campaign_id": "campaign", "host_id": "host", "phase": "confirmation",
                       "run_id": fixed_job["run_id"], "ordinal": fixed_job["ordinal"], "job_index": 0,
                       "job_sha256": hashlib.sha256(m.canonical_bytes(fixed_job)).hexdigest(),
                       "qualification_eligible": False, "may_reclaim": False,
                       "checkpoint_pin": checkpoint_pin, "checkpoint_raw": checkpoint_raw,
                       "manifest_pin": object_manifest_pin, "manifest_raw": manifest_raw,
                       "archive_request_pin": request_pin, "archive_request_raw": request_raw,
                       "archive_ack_pin": authority["ack_pin"], "signature_pin": authority["signature_pin"]}
            receipt = {"fixture_boundary": "original source receipt builder"}
            campaign = SimpleNamespace(fixed_pressure_predecessor_receipt=mock.Mock(return_value=receipt))
            with (m.campaign_host_lock(root, "campaign", "host") as lock,
                  mock.patch.object(m, "_prepare_source5_context",
                                    side_effect=lambda *_: (manifest, prepared, state, manifest_pin)),
                  mock.patch.object(m, "verify_source5_completed_fixed_phase_locked",
                                    return_value=proof) as fixed_owner,
                  mock.patch.object(m, "_source5_authorization_detail_fields", return_value=set(active)),
                  mock.patch.object(m, "_source5_finished_structural_summary",
                                    return_value={"fixture_boundary": "retained journal summary"}),
                  mock.patch.object(m, "_validate_source5_authorization",
                                    return_value={"archived_metadata": authority}),
                  mock.patch.object(m, "_source_file", return_value=(b"fixture source boundary", "d" * 64, {})),
                  mock.patch.object(m, "_load_module", return_value=campaign),
                  mock.patch.object(m, "verify_source5_capacity_ancestor_locked",
                                    return_value={"historical_journal_record_count": 3})):
                yield {"lock": lock, "prepared": prepared, "state": state, "manifest": manifest,
                       "manifest_pin": manifest_pin, "job": job, "fixed_job": fixed_job,
                       "record": record, "pin": pin, "proof": proof, "capture": capture,
                       "owner": fixed_owner, "active": active, "helper": helper,
                       "recipe_pin": recipe_pin, "pair": pair, "receipt": receipt,
                       "heads": heads, "write": write, "authority": authority}

    def issue(self, c):
        m = self.chronology
        return m.build_source5_pressure_predecessor_replay_held(
            c["lock"], c["manifest_pin"], c["job"], c["pin"],
            captured_evidence=c["capture"],
        )

    def bind_authorization_fixture(self, c, certificate):
        """Model just the existing append boundary; no authorization success claim."""
        m = self.chronology
        m._source5_pressure_predecessor_replay_record_held(
            certificate, c["lock"], c["manifest_pin"], c["prepared"], c["state"], c["job"],
            before_authorization=True,
        )
        with m._PRESSURE_PREDECESSOR_CONTEXT_LOCK:
            scope = m._PRESSURE_PREDECESSOR_REPLAYS[certificate]
            scope["authorization_id"] = c["active"]["authorization_id"]
            scope["authorization_sha256"] = hashlib.sha256(m.canonical_bytes(c["active"])).hexdigest()
            scope["authorization_head"] = c["heads"][4]
        c["state"].update(head=c["heads"][4], record_count=4,
                          journal_heads=c["heads"][:5], source5_pending="pressure-auth")
        c["state"]["source5_seen_jobs"].add(("pressure", c["job"]["run_id"]))
        c["state"]["source5_authorized"]["pressure-auth"] = {
            "details": c["active"], "authorization_head": c["heads"][4],
            "starts": [], "terminals": [],
        }

    def activate(self, c, certificate):
        return self.chronology.build_source5_pressure_predecessor_context_locked(
            c["lock"], c["manifest_pin"], c["active"], predecessor_replay=certificate,
        )

    def test_issuer_uses_full_fixed_owner_once_and_keeps_no_view_or_metrics(self):
        m = self.chronology
        with self.case() as c:
            with c["lock"]._operation_lock:
                certificate = self.issue(c)
            c["owner"].assert_called_once_with(
                c["lock"], c["manifest_pin"], c["pin"], captured_evidence=c["capture"],
            )
            scope = m._PRESSURE_PREDECESSOR_REPLAYS[certificate]
            self.assertNotIn("captured_evidence", scope)
            self.assertNotIn("prepared", scope)
            self.assertNotIn("process_metrics", json.loads(scope["proof_raw"]))
            self.assertLessEqual(len(scope["proof_raw"] + scope["pressure_job"] + scope["predecessor_job"]), 16 * 1024)

    def test_json_unregistered_and_foreign_module_certificates_fail(self):
        m = self.chronology
        other = load("source5_preapp_component_b")
        with self.case() as c:
            certificate = self.issue(c)
            for supplied in ({"component_replayed": True}, object.__new__(m.Source5PressurePredecessorReplay)):
                with self.subTest(kind=type(supplied).__name__), self.assertRaises(m.ChronologyError):
                    m._source5_pressure_predecessor_replay_record_held(
                        supplied, c["lock"], c["manifest_pin"], c["prepared"], c["state"], c["job"],
                        before_authorization=True,
                    )
            with self.assertRaises(other.ChronologyError):
                other._source5_pressure_predecessor_replay_record_held(
                    certificate, c["lock"], c["manifest_pin"], c["prepared"], c["state"], c["job"],
                    before_authorization=True,
                )

    def test_wrong_next_job_or_fixed_pin_is_rejected_before_owner(self):
        m = self.chronology
        with self.case() as c:
            with self.assertRaisesRegex(m.ChronologyError, "next exact original pressure job"):
                m.build_source5_pressure_predecessor_replay_held(
                    c["lock"], c["manifest_pin"], {**c["job"], "run_id": "replacement"},
                    c["pin"], captured_evidence=c["capture"],
                )
            with self.assertRaisesRegex(m.ChronologyError, "record pin"):
                m.build_source5_pressure_predecessor_replay_held(
                    c["lock"], c["manifest_pin"], c["job"],
                    {**c["pin"], "raw_sha256": "e" * 64}, captured_evidence=c["capture"],
                )
            c["owner"].assert_not_called()

    def test_issuer_owns_ack_binding_and_rejects_wrong_ack_before_numeric_owner(self):
        m = self.chronology
        with self.case() as c:
            c["capture"]["archive_ack_pin"] = {
                **c["authority"]["ack_pin"], "raw_sha256": "f" * 64,
            }
            with self.assertRaisesRegex(m.ChronologyError, "archive_ack_pin differs"):
                self.issue(c)
            c["owner"].assert_not_called()

    def test_controller_entry_wrappers_hold_the_actual_source_operation_mutex(self):
        m = self.chronology
        with self.case() as c:
            result = object()

            def within_source_operation(*args, **kwargs):
                self.assertTrue(c["lock"]._operation_lock.locked())
                return result

            with mock.patch.object(m, "build_source5_pressure_predecessor_replay_held",
                                   side_effect=within_source_operation) as issuer:
                self.assertIs(m.build_source5_pressure_predecessor_replay_locked(
                    c["lock"], c["manifest_pin"], c["job"], c["pin"],
                    captured_evidence=c["capture"],
                ), result)
                issuer.assert_called_once_with(c["lock"], c["manifest_pin"], c["job"], c["pin"],
                                               captured_evidence=c["capture"])
            self.assertFalse(c["lock"]._operation_lock.locked())
            with mock.patch.object(m, "_source5_verify_pressure_after_archive_held",
                                   side_effect=within_source_operation) as verifier:
                self.assertIs(m.verify_source5_completed_pressure_job_captured_locked(
                    c["lock"], c["manifest_pin"], c["pin"], captured_evidence=c["capture"],
                    pressure_predecessor_certificate=result,
                ), result)
                verifier.assert_called_once_with(c["lock"], c["manifest_pin"], c["pin"], c["capture"], result)
            self.assertFalse(c["lock"]._operation_lock.locked())

    def test_source_epoch_and_pre_authorization_head_expire_certificate(self):
        m = self.chronology
        for mutation in ("source", "head", "seen"):
            with self.subTest(mutation=mutation), self.case() as c:
                certificate = self.issue(c)
                if mutation == "source":
                    c["prepared"]["source"]["source"]["source_tree_sha256"] = "e" * 64
                elif mutation == "head":
                    c["state"]["head"] = "e" * 64
                else:
                    c["state"]["source5_seen_jobs"].add(("pressure", "another-original"))
                with self.assertRaises(m.ChronologyError):
                    self.bind_authorization_fixture(c, certificate)

    def test_bound_certificate_activates_once_after_view_is_closed(self):
        m = self.chronology
        with self.case() as c:
            certificate = self.issue(c)
            c["capture"].clear()
            self.bind_authorization_fixture(c, certificate)
            with c["lock"]._operation_lock:
                context = self.activate(c, certificate)
                value = m.validate_source5_pressure_predecessor_context(
                    context, lock=c["lock"], authorization_context=c["active"],
                    recipe_pin=c["recipe_pin"], output_root=c["pair"],
                )
            self.assertEqual(value["fixed_predecessor"]["receipt_value"], c["receipt"])
            self.assertEqual(value["fixed_predecessor"]["job_record"], c["pin"])
            with self.assertRaisesRegex(m.ChronologyError, "activate once before"):
                self.activate(c, certificate)
            self.assertEqual(c["owner"].call_count, 1)

    def test_replaced_retained_record_fails_before_context_or_app(self):
        m = self.chronology
        with self.case() as c:
            certificate = self.issue(c)
            self.bind_authorization_fixture(c, certificate)
            c["write"](Path(c["pin"]["path"]), {**c["record"], "state": "invalid_pair"})
            with self.assertRaises(m.ChronologyError):
                self.activate(c, certificate)
            self.assertEqual(c["state"]["source5_authorized"]["pressure-auth"]["starts"], [])

    def test_activation_rejects_an_existing_app_or_a_fork(self):
        m = self.chronology
        for mutation in ("app", "fork", "next"):
            with self.subTest(mutation=mutation), self.case() as c:
                certificate = self.issue(c)
                self.bind_authorization_fixture(c, certificate)
                if mutation == "app":
                    c["state"]["source5_authorized"]["pressure-auth"]["starts"].append({"pid": 1})
                elif mutation == "fork":
                    c["state"]["journal_heads"][3] = "e" * 64
                else:
                    c["state"]["source5_seen_jobs"].add(("pressure", "next"))
                with self.assertRaises(m.ChronologyError):
                    self.activate(c, certificate)

    def test_pressure_preflight_passes_actual_a_context_and_recipe_pin(self):
        m = self.chronology
        with self.case() as c:
            certificate = self.issue(c)
            self.bind_authorization_fixture(c, certificate)
            context = self.activate(c, certificate)
            preparation = mock.Mock()
            authorization = SimpleNamespace(prepared=c["prepared"], details=c["active"],
                                            helper_input=c["helper"], helper_module=SimpleNamespace(
                                                _prepare_prerequisites=preparation))
            self.assertIsNone(m._preflight_authorized_source5_helper(
                c["lock"], authorization, pressure_predecessor_context=context,
            ))
            kwargs = preparation.call_args.kwargs
            self.assertIs(kwargs["chronology_module"], m)
            self.assertIs(kwargs["pressure_predecessor_context"], context)
            self.assertEqual(kwargs["recipe_pin"], c["recipe_pin"])

    def test_one_use_authorization_snapshot_binds_certificate_identity(self):
        m = self.chronology
        with self.case() as c:
            certificate = self.issue(c)
            module = SimpleNamespace(run_pressure_pair_locked=lambda: None)
            helper = {**c["helper"], "helper": {"entrypoint": "run_pressure_pair_locked"}}
            details = {**c["active"], "helper_module": {"sha256": "d" * 64}}
            authorization = m.Source5JobAuthorization(
                c["lock"], c["prepared"], c["manifest_pin"], c["active"]["helper_input"],
                helper, module, Path(__file__), details, c["heads"][4], 1, certificate,
            )
            authorization.pressure_predecessor_certificate = None
            with self.assertRaisesRegex(m.ChronologyError, "changed after"):
                m._consume_source5_authorization(c["lock"], authorization)

    def test_post_archive_requires_activated_exact_authorization_and_no_next_job(self):
        m = self.chronology
        with self.case() as c:
            certificate = self.issue(c)
            self.bind_authorization_fixture(c, certificate)
            self.activate(c, certificate)
            finished = c["state"]["source5_authorized"].pop("pressure-auth")
            finished.update(state="valid_pair", authorization_id="pressure-auth")
            c["state"]["source5_finished"][("pressure", c["job"]["run_id"])] = finished
            c["state"]["source5_pending"] = None
            record, pin, proof = m._source5_pressure_predecessor_replay_record_held(
                certificate, c["lock"], c["manifest_pin"], c["prepared"], c["state"], c["job"],
            )
            self.assertEqual(record, c["record"])
            self.assertEqual(pin, c["pin"])
            self.assertEqual(proof["process_metrics"], c["record"]["process_metrics"])
            c["state"]["source5_seen_jobs"].add(("pressure", "next-original"))
            with self.assertRaisesRegex(m.ChronologyError, "different authorization"):
                m._source5_pressure_predecessor_replay_record_held(
                    certificate, c["lock"], c["manifest_pin"], c["prepared"], c["state"], c["job"],
                )

    def test_post_archive_wrapper_replays_owner_and_returns_original_seven_field_proof(self):
        m = self.chronology
        with self.case() as c:
            certificate = self.issue(c)
            self.bind_authorization_fixture(c, certificate)
            self.activate(c, certificate)
            finished = c["state"]["source5_authorized"].pop("pressure-auth")
            finished.update(state="valid_pair", authorization_id="pressure-auth")
            c["state"]["source5_finished"][("pressure", c["job"]["run_id"])] = finished
            c["state"]["source5_pending"] = None
            metric_sha = c["proof"]["metrics_sha256"]
            evidence = {"recipe": c["recipe_pin"], "overlay": {"path": "fixture-overlay", "raw_sha256": "a" * 64},
                        "readback": {"path": "fixture-readback", "raw_sha256": "b" * 64},
                        "processes": {"path": "fixture-processes", "raw_sha256": "c" * 64},
                        "host_receipt": {"path": "fixture-host", "raw_sha256": "d" * 64,
                                         "receipt_sha256": "e" * 64}}
            component = {"schema": "allocatbelt.application-source5-pressure-component.v1",
                         "validated": True, "qualification_eligible": False,
                         **{key: evidence[key] for key in ("recipe", "overlay", "readback", "processes")},
                         "pressure_metrics": c["record"]["process_metrics"]}
            pressure_record = {"schema": m.SOURCE5_JOB_RECORD_SCHEMA, "state": "valid_pair",
                               "job": c["job"], "pair_directory": str(c["pair"]),
                               "process_metrics": c["record"]["process_metrics"], "evidence": evidence,
                               "qualification_eligible": False,
                               "chronology": {"authorization_id": "pressure-auth",
                                              "authorization_head": c["heads"][4],
                                              "job_terminal_head": c["heads"][7],
                                              "process_metrics_sha256": metric_sha,
                                              "component_sha256": hashlib.sha256(m.canonical_bytes(component)).hexdigest()}}
            pressure_record["record_sha256"] = hashlib.sha256(m.canonical_bytes(pressure_record)).hexdigest()
            path = c["prepared"]["output_root"] / "campaign/source5/host/pressure/job-records/pressure-original.json"
            pin = c["write"](path, pressure_record)
            c["write"](path.parent.parent / "controller-ledger.jsonl", pressure_record)
            view = {"fixture_boundary": "authenticated current pressure owner view"}
            owner_context = object()
            owner = SimpleNamespace(verify_pressure_pair_with_captured_outputs=mock.Mock(
                return_value={"pressure_metrics": c["record"]["process_metrics"]}))
            with (mock.patch.object(m, "_source5_captured_authority_held", return_value=view),
                  mock.patch.object(m, "_source5_issue_captured_pressure_context_held", return_value=owner_context),
                  mock.patch.object(m, "_source5_captured_pressure_inputs", return_value=(
                      c["helper"], c["recipe_pin"], {"fixture": "parsed recipe"}, {})),
                  mock.patch.object(m, "_source5_captured_source_module", return_value=owner)):
                checked = m.verify_source5_completed_job_locked(
                    c["lock"], c["manifest_pin"], None, pin, captured_evidence=view,
                    pressure_predecessor_certificate=certificate,
                )
                self.assertEqual(set(checked), {"record", "authorization_id", "authorization_head",
                    "job_terminal_head", "record_sha256", "metrics_sha256", "process_metrics"})
                self.assertEqual(checked["record"], pin)
                self.assertIs(owner.verify_pressure_pair_with_captured_outputs.call_args.kwargs[
                    "chronology_module"], m)
                self.assertIs(owner.verify_pressure_pair_with_captured_outputs.call_args.kwargs[
                    "pressure_predecessor_context"], owner_context)
                owner.verify_pressure_pair_with_captured_outputs.return_value = {"pressure_metrics": []}
                with self.assertRaisesRegex(m.ChronologyError, "complete original metrics"):
                    m.verify_source5_completed_job_locked(
                        c["lock"], c["manifest_pin"], None, pin, captured_evidence=view,
                        pressure_predecessor_certificate=certificate,
                    )

    def test_dispatch_threads_one_context_through_preflight_run_and_strict_receipt(self):
        tree = ast.parse(Path(self.chronology.__file__).read_bytes())
        functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        run = functions["run_authorized_source5_job_locked"]
        calls = [node for node in ast.walk(run) if isinstance(node, ast.Call)]
        for name in ("_preflight_authorized_source5_helper", "run_pressure_pair_locked",
                     "verify_pressure_pair_with_host_receipt"):
            call = next(node for node in calls if
                        (isinstance(node.func, ast.Name) and node.func.id == name) or
                        (isinstance(node.func, ast.Attribute) and node.func.attr == name))
            self.assertIn("pressure_predecessor_context", ast.unparse(call))
        self.assertFalse(functions["build_source5_pressure_predecessor_replay_held"].decorator_list)
        self.assertFalse(functions["build_source5_pressure_predecessor_context_locked"].decorator_list)
        authorize = functions["authorize_source5_job_locked"]
        text = ast.unparse(authorize)
        self.assertLess(text.index("_source5_pressure_predecessor_replay_record_held("),
                        text.index("_append_event("))


if __name__ == "__main__":
    unittest.main()
