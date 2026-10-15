#!/usr/bin/env python3
"""Static/API regression checks for the Source5 controller boundary."""
from __future__ import annotations

import ast
import builtins
import hashlib
import importlib.util
import json
import signal
import stat
import sys
import symtable
import tempfile
import threading
import time
import types
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
CHRONOLOGY_PATH = ROOT / "scripts/application-campaign-chronology.py"
PRESSURE_PATH = ROOT / "scripts/application-pressure-pair.py"
CAMPAIGN_PATH = ROOT / "scripts/application-campaign.py"
CONTROLLER_PATH = ROOT / "scripts/application-source5-campaign.py"
PREPARATION_PATH = ROOT / "scripts/application-source5-input-preparation.py"


def load_source(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def function(tree: ast.Module, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    matches = [item for item in tree.body
               if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
               and item.name == name]
    if len(matches) != 1:
        raise AssertionError(f"expected one function named {name}, found {len(matches)}")
    return matches[0]


class Source5ChronologyApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_source("source5_chronology_test", CHRONOLOGY_PATH)
        cls.tree = ast.parse(CHRONOLOGY_PATH.read_bytes(), filename=str(CHRONOLOGY_PATH))
        cls.campaign = load_source("source5_campaign_deadline_test", CAMPAIGN_PATH)

    def test_app_cleanup_gate_rejects_unverified_pressure_or_fixed_cleanup(self) -> None:
        clean_fixed = {
            "cleanup_status": "verified", "leader_reaped": True,
            "group_signal_after_leader_reap_count": 0,
        }
        dirty_fixed = {**clean_fixed, "group_signal_after_leader_reap_count": 1}
        clean_pressure = {"status": "verified", "application_cleanup": None}
        dirty_pressure = {
            "status": "verified",
            "application_cleanup": {"status": "failed"},
        }
        self.assertTrue(self.module._source5_cleanup_is_clean(clean_fixed))
        self.assertFalse(self.module._source5_cleanup_is_clean(dirty_fixed))
        self.assertTrue(self.module._source5_cleanup_is_clean(clean_pressure))
        self.assertFalse(self.module._source5_cleanup_is_clean(dirty_pressure))

    def test_input_snapshot_retains_scope_and_all_authorized_inputs(self) -> None:
        value = {
            "schema": "allocatbelt.application-source5-helper-input.v1",
            "scope": "prospective_exploration",
            "phase": "exploration",
            "payload": {"overlay_pin": {"path": "/private/overlay", "sha256": "a" * 64}},
            "input_snapshot_sha256": "b" * 64,
            "qualification_eligible": False,
        }
        body = self.module._source5_input_body(value)
        self.assertEqual(body["scope"], "prospective_exploration")
        self.assertEqual(body["payload"], value["payload"])
        self.assertNotIn("input_snapshot_sha256", body)
        self.assertNotIn("qualification_eligible", body)

    def test_source5_launch_apis_keep_the_fd_lock_serializer(self) -> None:
        for name in (
            "authorize_source5_job_locked",
            "run_authorized_source5_job_locked",
            "record_source5_analysis_locked",
            "source5_chronology_snapshot_locked",
        ):
            node = function(self.tree, name)
            decorators = [ast.unparse(item) for item in node.decorator_list]
            self.assertIn("_serialize_locked_api", decorators, name)

    def test_source5_event_dispositions_are_versioned_and_one_use(self) -> None:
        events = self.module.EVENTS
        for name in (
            "source5_authorized", "source5_app_started", "source5_app_terminal",
            "source5_job_terminal", "source5_analysis",
        ):
            self.assertIn(name, events)
            self.assertIn(name, self.module.DETAIL_FIELDS)
        source = ast.unparse(function(self.tree, "_check_event_semantics"))
        self.assertIn("source5_seen_jobs", source)
        self.assertIn("source5_pending", source)
        self.assertIn("cannot be retried", source)

    def test_source5_authorization_capability_is_lock_bound_and_consumed_once(self) -> None:
        chronology = self.module

        class Lock:
            def __init__(self, fd: int) -> None:
                self.output_root = Path("/private/source5-test")
                self.campaign_id = "campaign-test"
                self.host_id = "host-test"
                self.fd = fd
                self._fd_key = (1, fd)

        def authorization(lock):
            helper_module = types.SimpleNamespace(run=lambda: None)
            return chronology.Source5JobAuthorization(
                lock,
                {"prepared_fixture": True},
                {"path": "/private/manifest.json", "sha256": "a" * 64},
                {"path": "/private/helper.json", "raw_sha256": "b" * 64},
                {"schema": "test", "helper": {"entrypoint": "run"}},
                helper_module, Path("/source/scripts/helper.py"),
                {"helper_module": {"sha256": "c" * 64}},
                "d" * 64, 1,
            )

        owner, foreign = Lock(11), Lock(12)
        token = authorization(owner)
        with self.assertRaises(chronology.ChronologyError):
            chronology._consume_source5_authorization(foreign, token)
        self.assertIs(chronology._consume_source5_authorization(owner, token), token)
        with self.assertRaises(chronology.ChronologyError):
            chronology._consume_source5_authorization(owner, token)

    def test_prepared_capacity_bridge_has_a_separate_locked_registration_api(self) -> None:
        chronology = self.module
        tree = self.tree
        api = function(tree, "register_source5_prepared_capacity_locked")
        args = {item.arg for item in api.args.args}
        self.assertTrue({"completion_pin", "provenance_pin", "lock"} <= args)
        source = ast.unparse(api)
        self.assertIn("_verify_source5_prepared_input_generation", source)
        self.assertIn("source5_prepared_capacity_registered", source)
        self.assertNotIn("register_capacity_completion_locked(", source)
        verifier = ast.unparse(function(
            tree, "_verify_source5_prepared_input_generation",
        ))
        self.assertIn("application-capacity-preparation-completion.v1",
                      verifier)

    def test_completion_and_numeric_replay_are_never_skipped_by_hash_only_cache(self) -> None:
        module_source = CHRONOLOGY_PATH.read_text()
        self.assertNotIn("_SOURCE5_PREPARED_COMPLETIONS", module_source)
        self.assertNotIn("_SOURCE5_VERIFIED_ANALYSES", module_source)
        completion = ast.unparse(function(
            self.tree, "_verify_source5_prepared_input_generation",
        ))
        analysis = ast.unparse(function(self.tree, "_recompute_source5_analysis"))
        self.assertIn("verify_prepared_inputs_completion", completion)
        self.assertIn("_source5_phase_records", analysis)
        self.assertIn("validate_aa_records", analysis)
        self.assertNotIn("cache_key", completion)
        self.assertNotIn("cache_key", analysis)

    def test_v2_manifest_capacity_projection_keeps_the_preparation_schema_explicit(self) -> None:
        manifest = {
            "schema": "allocatbelt.application-source5-campaign-execution.v2",
            "prepared_capacity_registration": {
                "host_completion": {"path": "/inputs/host-completion.json",
                                    "raw_sha256": "a" * 64},
                "capacity_schedule_sha256": "b" * 64,
                "ledger": {"path": "/inputs/ledger.jsonl",
                           "raw_sha256": "c" * 64,
                           "terminal_head": "d" * 64},
                "registration_head": "e" * 64,
            },
        }
        value = self.module._source5_capacity_manifest_record(manifest, "host-a")
        self.assertEqual(value, {
            "artifact": {"path": "/inputs/host-completion.json",
                         "raw_sha256": "a" * 64},
            "schedule_sha256": "b" * 64,
            "ledger_raw_sha256": "c" * 64,
            "terminal_head": "d" * 64,
            "registration_head": "e" * 64,
        })
        self.assertNotIn("capacity_completions", manifest)

    def test_v3_bounded_manifest_projects_the_budget_bound_v2_capacity_registration(self) -> None:
        budget = {
            "path": "/inputs/host-a/resource-budget.json",
            "raw_sha256": "1" * 64,
            "semantic_sha256": "2" * 64,
        }
        manifest = {
            "schema": "allocatbelt.application-source5-campaign-execution.v3",
            "scope": "final_prepared_bounded",
            "prepared_capacity_registration": {
                "host_completion": {"path": "/inputs/host-a/capacity-v2.json",
                                    "raw_sha256": "3" * 64},
                "capacity_schedule_sha256": "4" * 64,
                "ledger": {"path": "/inputs/host-a/ledger-v2.jsonl",
                           "raw_sha256": "5" * 64,
                           "terminal_head": "6" * 64},
                "registration_head": "7" * 64,
            },
        }
        value = self.module._source5_capacity_manifest_record(manifest, "host-a")
        self.assertEqual(value, {
            "artifact": {"path": "/inputs/host-a/capacity-v2.json",
                         "raw_sha256": "3" * 64},
            "schedule_sha256": "4" * 64,
            "ledger_raw_sha256": "5" * 64,
            "terminal_head": "6" * 64,
            "registration_head": "7" * 64,
        })
        controller_tree = ast.parse(CONTROLLER_PATH.read_bytes(), filename=str(CONTROLLER_PATH))
        load_context = function(controller_tree, "load_context")
        controller = ast.unparse(load_context)
        self.assertIn("EXECUTION_SCHEMA_V3", controller)
        self.assertIn("application-source5-preparation-completion.v2", controller)
        expected_budget_binding = ast.parse(
            'prepared_completion.get("resource_budgets", {}).get(host_id) == selected_budget',
        ).body[0].value
        self.assertTrue(any(
            isinstance(node, ast.Compare) and
            ast.dump(node, include_attributes=False) ==
            ast.dump(expected_budget_binding, include_attributes=False)
            for node in ast.walk(load_context)
        ), "v3 load_context must bind the selected host row to its frozen budget")
        self.assertIn("verify_source5_completed_fixed_phase_locked",
                      ast.unparse(function(controller_tree, "_fresh_fixed_phase_records")))

    def test_signal_terminal_keeps_raw_negative_code_and_normalized_status(self) -> None:
        chronology = self.module
        descriptor = {"pair": "bounded", "executor": "bounded",
                      "allocator": "allocatbelt"}
        authorization_id = "source5-signal-terminal"
        state = chronology._empty_journal({})
        state["source5_authorized"][authorization_id] = {
            "details": {"members": [descriptor],
                        "job": {"run_id": "source5-signal-terminal"}},
            "authorization_head": "a" * 64,
            "starts": [{"descriptor": descriptor, "pid": 411,
                        "start_ticks": 901, "event_head": "b" * 64}],
            "terminals": [],
        }
        state["source5_pending"] = authorization_id
        details = {
            "authorization_id": authorization_id, "member_index": 0,
            "descriptor": descriptor, "pid": 411, "status": 137,
            "child_return_code": -9, "signal": 9,
            "cleanup": {"status": "verified", "application_cleanup": None},
            "terminal_monotonic_ns": 1,
            "qualification_eligible": False,
        }
        chronology._check_event_semantics(
            state, "source5_app_terminal", details, "c" * 64, {},
            replay=True, apply=True,
        )
        saved = state["source5_authorized"][authorization_id]["terminals"][0]
        self.assertEqual(saved["child_return_code"], -9)
        self.assertEqual(saved["signal"], 9)
        self.assertEqual(saved["status"], 137)

    def test_pressure_signal_callback_and_journal_replay_preserve_raw_wait_status(self) -> None:
        chronology = self.module
        descriptor = {"pair": "bounded", "executor": "bounded",
                      "allocator": "allocatbelt"}
        authorization_id = "source5-pressure-signal-callback"
        prepared = {"campaign_id": "campaign-test", "host_id": "host-test"}
        state = chronology._empty_journal({})
        state["source5_authorized"][authorization_id] = {
            "details": {"members": [descriptor],
                        "job": {"run_id": "source5-pressure-signal"}},
            "authorization_head": "a" * 64,
            "starts": [{"descriptor": descriptor, "pid": 413,
                        "start_ticks": 903, "event_head": "b" * 64}],
            "terminals": [],
        }
        state["source5_pending"] = authorization_id
        event = {
            "campaign_id": "campaign-test", "host_id": "host-test",
            "run_id": "source5-pressure-signal", "member_ordinal": 0,
            "descriptor": descriptor, "pid": 413, "status": 137,
            "child_return_code": -9, "signal": 9,
            "cleanup": {"status": "verified", "application_cleanup": None},
            "terminal_monotonic_ns": 2,
        }
        appended = {}

        def append_event(_lock, _prepared, name, details):
            self.assertEqual(name, "source5_app_terminal")
            appended["details"] = details
            return {"record_sha256": "c" * 64}

        with patch.object(chronology, "_read_journal", return_value=state), \
             patch.object(chronology, "_append_event", append_event):
            chronology._source5_append_app_terminal(
                None, prepared, authorization_id, event,
            )
        details = appended["details"]
        self.assertEqual(details["status"], 137)
        self.assertEqual(details["child_return_code"], -9)
        self.assertEqual(details["signal"], 9)
        chronology._check_event_semantics(
            state, "source5_app_terminal", details, "c" * 64, {},
            replay=True, apply=True,
        )
        replayed = state["source5_authorized"][authorization_id]["terminals"][0]
        self.assertEqual(replayed["child_return_code"], -9)
        self.assertEqual(replayed["signal"], 9)
        malformed = {**details, "status": 9}
        invalid_state = chronology._empty_journal({})
        invalid_state["source5_authorized"][authorization_id] = {
            "details": {"members": [descriptor]},
            "authorization_head": "a" * 64,
            "starts": [{"descriptor": descriptor, "pid": 413,
                        "start_ticks": 903, "event_head": "b" * 64}],
            "terminals": [],
        }
        invalid_state["source5_pending"] = authorization_id
        with self.assertRaises(chronology.ChronologyError):
            chronology._check_event_semantics(
                invalid_state, "source5_app_terminal",
                malformed, "d" * 64, {}, replay=True, apply=False,
            )

    def test_blocked_terminal_can_seal_missing_callback_and_latch_launches(self) -> None:
        chronology = self.module
        descriptor = {"pair": "bounded", "executor": "bounded",
                      "allocator": "allocatbelt"}
        authorization_id = "source5-incomplete-terminal"
        state = chronology._empty_journal({})
        state["registration"] = {}
        state["source5_authorized"][authorization_id] = {
            "details": {
                "members": [descriptor, {"pair": "tokio", "executor": "tokio",
                                          "allocator": "allocatbelt"}],
                "job": {"run_id": "original-job"}, "phase": "exploration",
            },
            "authorization_head": "a" * 64,
            "starts": [{"descriptor": descriptor, "pid": 412,
                        "start_ticks": 902, "event_head": "b" * 64}],
            "terminals": [],
        }
        state["source5_pending"] = authorization_id
        terminal = {
            "authorization_id": authorization_id, "state": "blocked",
            "blocked_reason": "incomplete_app_lifecycle",
            "component_sha256": "c" * 64, "process_metrics_sha256": "d" * 64,
            "started_count": 1, "terminal_count": 0,
            "qualification_eligible": False,
        }
        chronology._check_event_semantics(
            state, "source5_job_terminal", terminal, "e" * 64, {},
            replay=True, apply=True,
        )
        self.assertTrue(state["source5_cleanup_blocked"])
        self.assertIsNone(state["source5_pending"])
        self.assertEqual(state["source5_finished"][("exploration", "original-job")]["state"],
                         "blocked")
        authorization = {key: None for key in chronology.DETAIL_FIELDS["source5_authorized"]}
        with self.assertRaises(chronology.ChronologyError):
            chronology._check_event_semantics(
                state, "source5_authorized", authorization, "f" * 64, {},
                replay=True, apply=True,
            )

    def test_watchdog_failure_blocks_a_clean_callback_terminal_and_latches_suffix(self) -> None:
        chronology = self.module
        members = [
            {"pair": "bounded", "executor": "bounded", "allocator": "allocatbelt"},
            {"pair": "tokio", "executor": "tokio", "allocator": "allocatbelt"},
        ]
        authorization_id = "source5-watchdog-failure"
        state = chronology._empty_journal({})
        state["registration"] = {}
        state["source5_authorized"][authorization_id] = {
            "details": {
                "members": members, "job": {"run_id": "original-job"},
                "phase": "exploration",
            },
            "authorization_head": "a" * 64,
            "starts": [
                {"descriptor": member, "pid": 512 + index,
                 "start_ticks": 702 + index, "event_head": str(index + 1) * 64}
                for index, member in enumerate(members)
            ],
            "terminals": [
                {"descriptor": member, "pid": 512 + index, "status": 0,
                 "cleanup": {"cleanup_status": "verified", "leader_reaped": True,
                             "group_signal_after_leader_reap_count": 0},
                 "event_head": str(index + 3) * 64}
                for index, member in enumerate(members)
            ],
        }
        state["source5_pending"] = authorization_id
        terminal = {
            "authorization_id": authorization_id, "state": "blocked",
            "blocked_reason": "deadline_watchdog_unverified",
            "component_sha256": "c" * 64, "process_metrics_sha256": "d" * 64,
            "started_count": 2, "terminal_count": 2,
            "qualification_eligible": False,
        }
        chronology._check_event_semantics(
            state, "source5_job_terminal", terminal, "e" * 64, {},
            replay=True, apply=True,
        )
        self.assertTrue(state["source5_cleanup_blocked"])
        self.assertIsNone(state["source5_pending"])
        authorization = {
            key: None for key in chronology.DETAIL_FIELDS["source5_authorized"]
        }
        with self.assertRaises(chronology.ChronologyError):
            chronology._check_event_semantics(
                state, "source5_authorized", authorization, "f" * 64, {},
                replay=True, apply=True,
            )

    def test_active_deadline_survives_a_nested_longer_campaign_alarm_and_restores_signals(self) -> None:
        chronology = self.module
        old_handler = signal.getsignal(signal.SIGUSR2)
        old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        watchdog = chronology._Source5DeadlineWatchdog(time.monotonic_ns() + 40_000_000)
        started = time.monotonic()
        with self.assertRaises(chronology.Source5DeadlineExceeded):
            with watchdog:
                with self.campaign.hard_wall_deadline(3.0, "nested longer timer"):
                    time.sleep(0.25)
        self.assertTrue(watchdog.expired)
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertIs(signal.getsignal(signal.SIGUSR2), old_handler)
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), old_mask)
        self.assertNotIn(signal.SIGUSR2, signal.sigpending())
        self.assertIsNotNone(watchdog._timer_thread)
        self.assertFalse(watchdog._timer_thread.is_alive())

    def test_watchdog_thread_start_fault_restores_handler_and_mask_without_late_signal(self) -> None:
        chronology = self.module
        old_handler = signal.getsignal(signal.SIGUSR2)
        old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        watchdog = chronology._Source5DeadlineWatchdog(time.monotonic_ns() + 80_000_000)

        def fail_start(_thread):
            raise RuntimeError("injected timer thread start fault")

        with patch.object(threading.Thread, "start", fail_start):
            with self.assertRaises(chronology.ChronologyError):
                with watchdog:
                    self.fail("watchdog setup fault must not enter its body")
        self.assertTrue(watchdog.lifecycle_failed)
        self.assertFalse(watchdog._active)
        self.assertFalse(watchdog._handler_installed)
        self.assertIs(signal.getsignal(signal.SIGUSR2), old_handler)
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), old_mask)
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR2})
        try:
            time.sleep(0.12)
            self.assertNotIn(signal.SIGUSR2, signal.sigpending())
        finally:
            if signal.SIGUSR2 in signal.sigpending():
                signal.sigwait({signal.SIGUSR2})
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)

    def test_watchdog_signal_drain_fault_restores_state_and_blocks_suffix(self) -> None:
        chronology = self.module
        old_handler = signal.getsignal(signal.SIGUSR2)
        old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        real_sigwait = signal.sigwait
        calls = {"count": 0}

        def fail_once(signals):
            calls["count"] += 1
            if calls["count"] == 1:
                raise OSError("injected sigwait drain fault")
            return real_sigwait(signals)

        watchdog = chronology._Source5DeadlineWatchdog(time.monotonic_ns() + 500_000_000)
        try:
            with patch.object(signal, "sigwait", fail_once):
                with self.assertRaises(chronology.ChronologyError):
                    with watchdog:
                        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR2})
                        signal.pthread_kill(threading.main_thread().ident,
                                            signal.SIGUSR2)
            self.assertTrue(watchdog.lifecycle_failed)
            self.assertIs(signal.getsignal(signal.SIGUSR2), old_handler)
            self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), old_mask)
            self.assertNotIn(signal.SIGUSR2, signal.sigpending())
            signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR2})
            time.sleep(0.55)
            self.assertNotIn(signal.SIGUSR2, signal.sigpending())
        finally:
            signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR2})
            if signal.SIGUSR2 in signal.sigpending():
                real_sigwait({signal.SIGUSR2})
            signal.signal(signal.SIGUSR2, old_handler)
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)

    def test_preflight_binds_overlay_job_before_any_execution_entrypoint(self) -> None:
        chronology = self.module
        canonical = chronology.canonical_bytes
        source_manifests = [
            {"host_id": host, "path": f"/inputs/{host}.json",
             "raw_sha256": chr(97 + index) * 64,
             "semantic_sha256": chr(100 + index) * 64,
             "source_tree_sha256": chr(103 + index) * 64}
            for index, host in enumerate(("host-a", "host-b", "host-c"))
        ]
        original = {
            "spec": {"path": "/inputs/spec.json", "raw_sha256": "a" * 64,
                     "semantic_sha256": "b" * 64},
            "plan": {"path": "/inputs/plan.json", "raw_sha256": "c" * 64,
                     "semantic_sha256": "d" * 64},
            "source_manifests": source_manifests,
            "observed_host": {"path": "/inputs/observed-host.json",
                              "raw_sha256": "e" * 64},
        }
        job = {"run_id": "campaign-host-a-exploration-01", "host_id": "host-a",
               "phase": "exploration"}
        descriptors = [
            {"pair": "bounded", "executor": "bounded", "allocator": "allocatbelt"},
            {"pair": "tokio", "executor": "tokio", "allocator": "allocatbelt"},
        ]
        overlay = {
            "campaign_id": "campaign", "host_id": "host-a",
            "job": {"value": job, "sha256": hashlib.sha256(canonical(job)).hexdigest()},
            "spec": {"pin": {"path": original["spec"]["path"],
                              "sha256": original["spec"]["raw_sha256"]},
                     "semantic_sha256": original["spec"]["semantic_sha256"]},
            "plan": {"pin": {"path": original["plan"]["path"],
                              "sha256": original["plan"]["raw_sha256"]},
                     "semantic_sha256": original["plan"]["semantic_sha256"]},
            "sources": {
                "manifests": {
                    pin["host_id"]: {
                        "pin": {"path": pin["path"], "sha256": pin["raw_sha256"]},
                        "manifest_sha256": pin["semantic_sha256"],
                    } for pin in source_manifests
                },
                "selected": {"root": "/source", "host_id": "host-a"},
                "observed_host": {"pin": {"path": original["observed_host"]["path"],
                                             "sha256": original["observed_host"]["raw_sha256"]}},
            },
            "output_root": "/private/job-output",
            "members": [{"descriptor": item} for item in descriptors],
        }
        prepared = {"campaign_id": "campaign", "host_id": "host-a",
                    "source_root": Path("/source"), "original_pins": original}
        details = {"phase": "exploration", "job": job,
                   "job_sha256": overlay["job"]["sha256"],
                   "members": descriptors, "output_root": overlay["output_root"]}
        helper_input = {"payload": {"overlay_pin": {"path": "/private/overlay.json",
                                                     "sha256": "f" * 64}}}
        launches = []

        class Fixed:
            def _read_overlay(self, _pin):
                return overlay, b"fixture-overlay", "f" * 64, {"job": job}, {"job": overlay["job"]}

            def run_fixed_pair_overlay(self, *_args):
                launches.append("fixed")

        authorization = types.SimpleNamespace(
            prepared=prepared, details=details, helper_input=helper_input,
            helper_module=Fixed(),
        )
        chronology._preflight_authorized_source5_helper(None, authorization)
        self.assertEqual(launches, [])

        other_job = {**job, "run_id": "campaign-host-a-exploration-02"}
        overlay["job"] = {"value": other_job,
                          "sha256": hashlib.sha256(canonical(other_job)).hexdigest()}
        with self.assertRaises(chronology.ChronologyError):
            chronology._preflight_authorized_source5_helper(None, authorization)
        self.assertEqual(launches, [])
        overlay["job"] = {"value": job,
                          "sha256": hashlib.sha256(canonical(job)).hexdigest()}
        details["members"] = list(reversed(descriptors))
        with self.assertRaises(chronology.ChronologyError):
            chronology._preflight_authorized_source5_helper(None, authorization)
        self.assertEqual(launches, [])
        details["members"] = descriptors
        overlay["spec"]["pin"]["sha256"] = "f" * 64
        with self.assertRaises(chronology.ChronologyError):
            chronology._preflight_authorized_source5_helper(None, authorization)
        self.assertEqual(launches, [])

        overlay["spec"]["pin"]["sha256"] = original["spec"]["raw_sha256"]
        overlay["job"] = {"value": other_job,
                          "sha256": hashlib.sha256(canonical(other_job)).hexdigest()}
        with tempfile.TemporaryDirectory(prefix="source5-preflight-api-") as temp:
            output_root = Path(temp)
            with chronology.campaign_host_lock(output_root, "campaign", "host-a") as lock:
                authorization_id = "source5-swapped-job-preflight"
                api_details = {
                    "authorization_id": authorization_id,
                    "phase": "exploration", "job": job,
                    "job_sha256": hashlib.sha256(canonical(job)).hexdigest(),
                    "members": descriptors,
                    "helper_module": {"sha256": "a" * 64},
                    "execution_manifest": {"path": "/private/manifest.json",
                                            "raw_sha256": "b" * 64},
                    "helper_input": {"path": "/private/helper.json",
                                     "raw_sha256": "c" * 64},
                    "effective_timeout_seconds": 60,
                    "output_root": overlay["output_root"],
                }
                api_helper_input = {
                    "helper": {"entrypoint": "run_fixed_pair_overlay"},
                    "payload": {"overlay_pin": {
                        "path": "/private/overlay.json", "sha256": "f" * 64,
                    }},
                }
                replay_state = {
                    "source5_authorized": {authorization_id: {
                        "details": api_details,
                        "authorization_head": "d" * 64,
                        "starts": [], "terminals": [],
                    }},
                    "source5_pending": authorization_id,
                    "source5_finished": {}, "head": "0" * 64,
                }
                token = chronology.Source5JobAuthorization(
                    lock, prepared,
                    {"path": "/private/manifest.json", "sha256": "b" * 64},
                    {"path": "/private/helper.json", "raw_sha256": "c" * 64},
                    api_helper_input, Fixed(), Path("/source/helper.py"),
                    api_details, "e" * 64, time.monotonic_ns(),
                )

                def terminal_event(_lock, _prepared, event_name, fields):
                    self.assertEqual(event_name, "source5_job_terminal")
                    replay_state["job_terminal"] = fields
                    replay_state["source5_pending"] = None
                    return {"record_sha256": "f" * 64}

                with patch.object(chronology, "_read_journal",
                                  return_value=replay_state), \
                     patch.object(chronology, "_append_event",
                                  terminal_event):
                    result = chronology.run_authorized_source5_job_locked(
                        lock, token,
                    )
                self.assertEqual(result["state"], "blocked")
                self.assertEqual(replay_state["job_terminal"]["blocked_reason"],
                                 "helper_preflight_failed")
                self.assertEqual(launches, [])

    def _run_public_job_with_callbacks(
        self, helper, *, inject_join_fault: bool = False,
        inject_cancel_fault: bool = False,
    ):
        chronology = self.module
        with tempfile.TemporaryDirectory(prefix="source5-deadline-api-") as temporary:
            output_root = Path(temporary)
            with chronology.campaign_host_lock(output_root, "campaign-test", "host-test") as lock:
                descriptors = [
                    {"pair": "bounded", "executor": "bounded",
                     "allocator": "allocatbelt"},
                    {"pair": "tokio", "executor": "tokio",
                     "allocator": "allocatbelt"},
                ]
                job = {"run_id": "campaign-test-host-test-exploration-01",
                       "host_id": "host-test", "phase": "exploration"}
                authorization_id = "source5-deadline-api"
                details = {
                    "authorization_id": authorization_id,
                    "phase": "exploration", "job": job,
                    "job_sha256": "a" * 64,
                    "members": descriptors,
                    "helper_module": {"sha256": "b" * 64},
                    "execution_manifest": {"path": "/private/manifest.json",
                                            "raw_sha256": "c" * 64},
                    "helper_input": {"path": "/private/helper.json",
                                     "raw_sha256": "d" * 64},
                    "effective_timeout_seconds": 1,
                }
                prepared = {"campaign_id": "campaign-test", "host_id": "host-test"}
                helper_input = {
                    "helper": {"entrypoint": "run_fixed_pair_overlay"},
                    "payload": {"overlay_pin": {"path": "/private/overlay.json",
                                                 "sha256": "e" * 64}},
                }
                terminal_state = {
                    "source5_authorized": {authorization_id: {
                        "details": details, "authorization_head": "f" * 64,
                        "starts": [], "terminals": [],
                    }},
                    "source5_pending": authorization_id,
                    "source5_finished": {}, "head": "0" * 64,
                    "source5_cleanup_blocked": False,
                    "registration": {},
                }
                helper_module = types.SimpleNamespace()
                helper_module.run_fixed_pair_overlay = helper
                helper_module.verify_fixed_pair_overlay = lambda *_args: {
                    "verified": False, "status": "blocked",
                }
                helper_module.MAX_RECEIPT_BYTES = 4096
                token = chronology.Source5JobAuthorization(
                    lock, prepared,
                    {"path": "/private/manifest.json", "sha256": "c" * 64},
                    {"path": "/private/helper.json", "raw_sha256": "d" * 64},
                    helper_input, helper_module, Path("/source/helper.py"),
                    details, "1" * 64, time.monotonic_ns() - 500_000_000,
                )

                def append_start(_lock, _prepared, auth_id, event):
                    index = len(terminal_state["source5_authorized"][auth_id]["starts"])
                    member = descriptors[index]
                    terminal_state["source5_authorized"][auth_id]["starts"].append({
                        "event_head": str(2 + index) * 64, "proof": event,
                        "descriptor": member, "pid": 321 + index,
                        "start_ticks": 123 + index,
                    })
                    return {"record_sha256": str(2 + index) * 64}

                def append_terminal(_lock, _prepared, auth_id, event):
                    index = len(terminal_state["source5_authorized"][auth_id]["terminals"])
                    terminal_state["source5_authorized"][auth_id]["terminals"].append({
                        "event_head": str(4 + index) * 64, "event": event,
                        "descriptor": descriptors[index], "pid": 321 + index,
                        "status": 0, "cleanup": event["cleanup"],
                    })
                    return {"record_sha256": str(4 + index) * 64}

                terminal_events = []

                def append_event(_lock, _prepared, event, fields):
                    self.assertEqual(event, "source5_job_terminal")
                    terminal_events.append(fields)
                    chronology._check_event_semantics(
                        terminal_state, event, fields, "4" * 64, {},
                        replay=True, apply=True,
                    )
                    terminal_state["job_terminal"] = fields
                    return {"record_sha256": "4" * 64}

                patchers = [
                    patch.object(chronology, "_preflight_authorized_source5_helper"),
                    patch.object(chronology, "_source5_append_app_started", append_start),
                    patch.object(chronology, "_source5_append_app_terminal", append_terminal),
                    patch.object(chronology, "_read_journal", return_value=terminal_state),
                    patch.object(chronology, "_append_event", append_event),
                ]
                if inject_join_fault:
                    real_join = threading.Thread.join
                    injected = {"done": False}

                    def fail_after_join(thread, *args, **kwargs):
                        if thread.name == "allocatbelt-source5-deadline" and not injected["done"]:
                            injected["done"] = True
                            real_join(thread, *args, **kwargs)
                            raise RuntimeError("injected finite-join report fault")
                        return real_join(thread, *args, **kwargs)

                    patchers.append(patch.object(threading.Thread, "join", fail_after_join))
                if inject_cancel_fault:
                    real_init = chronology._Source5DeadlineWatchdog.__init__
                    cancel_events = []

                    def capture_watchdog(watchdog, deadline_ns):
                        real_init(watchdog, deadline_ns)
                        cancel_events.append(watchdog._cancel_timer)

                    real_event_set = threading.Event.set
                    injected = {"done": False}

                    def fail_cancel_event_once(event):
                        if cancel_events and event is cancel_events[-1] and \
                                not injected["done"]:
                            injected["done"] = True
                            raise KeyboardInterrupt("injected watchdog cancellation interrupt")
                        return real_event_set(event)

                    patchers.extend((
                        patch.object(chronology._Source5DeadlineWatchdog,
                                    "__init__", capture_watchdog),
                        patch.object(threading.Event, "set", fail_cancel_event_once),
                    ))
                with ExitStack() as stack:
                    for patcher in patchers:
                        stack.enter_context(patcher)
                    result = chronology.run_authorized_source5_job_locked(lock, token)
                terminal_state["terminal_events"] = terminal_events
                return result, terminal_state

    def test_public_job_api_stays_blocked_when_callbacks_clean_after_short_deadline(self) -> None:
        chronology = self.module

        def helper(_pin, on_started, on_terminal):
            descriptors = [
                {"pair": "bounded", "executor": "bounded",
                 "allocator": "allocatbelt"},
                {"pair": "tokio", "executor": "tokio",
                 "allocator": "allocatbelt"},
            ]
            for index, descriptor in enumerate(descriptors):
                on_started({
                    "descriptor": descriptor, "pid": 321 + index,
                    "start_ticks": 123 + index,
                    "proof": {"pid": 321 + index, "start_ticks": 123 + index},
                })
            try:
                with self.campaign.hard_wall_deadline(3.0, "nested longer helper timer"):
                    time.sleep(0.8)
            except chronology.Source5DeadlineExceeded:
                for index, descriptor in enumerate(descriptors):
                    on_terminal({
                        "descriptor": descriptor, "pid": 321 + index,
                        "status": 0, "child_return_code": 0, "signal": None,
                        "cleanup": {"cleanup_status": "verified", "leader_reaped": True,
                                    "group_signal_after_leader_reap_count": 0},
                    })
            return None

        result, terminal_state = self._run_public_job_with_callbacks(helper)
        self.assertEqual(result["state"], "blocked")
        self.assertEqual(len(result["chronology"]["app_terminal_events"]), 2)
        self.assertEqual(len(result["chronology"]["app_start_events"]), 2)
        self.assertTrue(all(item["status"] == 0
                            for item in result["chronology"]["app_terminal_events"]))
        self.assertEqual(terminal_state["job_terminal"]["blocked_reason"],
                         "effective_deadline_exceeded")

    def test_public_job_api_blocks_clean_pair_after_watchdog_join_fault(self) -> None:
        chronology = self.module
        old_handler = signal.getsignal(signal.SIGUSR2)
        old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())

        def helper(_pin, on_started, on_terminal):
            descriptors = [
                {"pair": "bounded", "executor": "bounded",
                 "allocator": "allocatbelt"},
                {"pair": "tokio", "executor": "tokio",
                 "allocator": "allocatbelt"},
            ]
            for index, descriptor in enumerate(descriptors):
                on_started({
                    "descriptor": descriptor, "pid": 321 + index,
                    "start_ticks": 123 + index,
                    "proof": {"pid": 321 + index, "start_ticks": 123 + index},
                })
                on_terminal({
                    "descriptor": descriptor, "pid": 321 + index,
                    "status": 0, "child_return_code": 0, "signal": None,
                    "cleanup": {"cleanup_status": "verified", "leader_reaped": True,
                                "group_signal_after_leader_reap_count": 0},
                })
            return None

        result, terminal_state = self._run_public_job_with_callbacks(
            helper, inject_join_fault=True,
        )
        self.assertEqual(result["state"], "blocked")
        self.assertEqual(len(result["chronology"]["app_start_events"]), 2)
        self.assertEqual(len(result["chronology"]["app_terminal_events"]), 2)
        self.assertTrue(all(item["status"] == 0
                            for item in result["chronology"]["app_terminal_events"]))
        self.assertEqual(terminal_state["job_terminal"]["blocked_reason"],
                         "deadline_watchdog_unverified")
        self.assertIs(signal.getsignal(signal.SIGUSR2), old_handler)
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), old_mask)

    def test_public_job_api_blocks_clean_pair_after_cancel_event_interrupt(self) -> None:
        chronology = self.module
        old_handler = signal.getsignal(signal.SIGUSR2)
        old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        helper_calls = []

        def helper(_pin, on_started, on_terminal):
            helper_calls.append("called")
            descriptors = [
                {"pair": "bounded", "executor": "bounded",
                 "allocator": "allocatbelt"},
                {"pair": "tokio", "executor": "tokio",
                 "allocator": "allocatbelt"},
            ]
            for index, descriptor in enumerate(descriptors):
                on_started({
                    "descriptor": descriptor, "pid": 321 + index,
                    "start_ticks": 123 + index,
                    "proof": {"pid": 321 + index, "start_ticks": 123 + index},
                })
                on_terminal({
                    "descriptor": descriptor, "pid": 321 + index,
                    "status": 0, "child_return_code": 0, "signal": None,
                    "cleanup": {"cleanup_status": "verified", "leader_reaped": True,
                                "group_signal_after_leader_reap_count": 0},
                })
            return None

        result, terminal_state = self._run_public_job_with_callbacks(
            helper, inject_cancel_fault=True,
        )
        self.assertEqual(result["state"], "blocked")
        self.assertEqual(result["component"]["error_type"], "KeyboardInterrupt")
        self.assertEqual(len(result["chronology"]["app_start_events"]), 2)
        self.assertEqual(len(result["chronology"]["app_terminal_events"]), 2)
        self.assertTrue(all(item["status"] == 0
                            for item in result["chronology"]["app_terminal_events"]))
        self.assertEqual(terminal_state["job_terminal"]["blocked_reason"],
                         "deadline_watchdog_unverified")
        self.assertEqual(len(terminal_state["terminal_events"]), 1)
        self.assertTrue(terminal_state["source5_cleanup_blocked"])
        self.assertIsNone(terminal_state["source5_pending"])
        self.assertEqual(helper_calls, ["called"])
        suffix = {
            key: None for key in chronology.DETAIL_FIELDS["source5_authorized"]
        }
        with self.assertRaises(chronology.ChronologyError):
            chronology._check_event_semantics(
                terminal_state, "source5_authorized", suffix, "5" * 64, {},
                replay=True, apply=True,
            )
        self.assertIs(signal.getsignal(signal.SIGUSR2), old_handler)
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), old_mask)
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR2})
        try:
            time.sleep(0.6)
            self.assertNotIn(signal.SIGUSR2, signal.sigpending())
        finally:
            if signal.SIGUSR2 in signal.sigpending():
                signal.sigwait({signal.SIGUSR2})
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        self.assertIs(signal.getsignal(signal.SIGUSR2), old_handler)
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), old_mask)
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR2})
        try:
            time.sleep(0.6)
            self.assertNotIn(signal.SIGUSR2, signal.sigpending())
        finally:
            if signal.SIGUSR2 in signal.sigpending():
                signal.sigwait({signal.SIGUSR2})
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        self.assertIs(signal.getsignal(signal.SIGUSR2), old_handler)
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), old_mask)


class Source5PressureAndAnalysisApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pressure = load_source("source5_pressure_status_test", PRESSURE_PATH)
        cls.campaign = load_source("source5_pressure_analysis_campaign", CAMPAIGN_PATH)

    def test_signal_exit_maps_to_unsigned_supervisor_status_and_keeps_signal(self) -> None:
        self.assertEqual(self.pressure._source5_normalized_terminal_status(
            {"return_code": -9}), (137, 9))
        self.assertEqual(self.pressure._source5_normalized_terminal_status(
            {"return_code": 0}), (0, None))
        self.assertEqual(self.pressure._source5_normalized_terminal_status(
            {"return_code": None}), (125, None))

    def test_v2_pressure_and_capacity_calibration_ids_keep_distinct_roles(self) -> None:
        pressure = self.pressure
        capacity_key = {
            "host_id": "host-a", "workload": "cpu", "profile": "steady",
            "calibration_id": "capacity-01",
        }
        binding = {
            "calibration_id": "capacity-01",
            "pressure_calibration_id": "pressure-01",
        }
        self.assertIsNone(pressure._validate_source5_calibration_id_roles_v2(
            binding, "pressure-01", "condition-01", capacity_key,
        ))
        for malformed in (
            {**binding, "calibration_id": "pressure-01"},
            {**binding, "pressure_calibration_id": "capacity-01"},
            {**binding, "pressure_calibration_id": "condition-01"},
        ):
            with self.assertRaises(pressure.PressurePairError):
                pressure._validate_source5_calibration_id_roles_v2(
                    malformed, "pressure-01", "condition-01", capacity_key,
                )

    def test_context_calibration_host_receipt_is_bound_to_observed_host_and_cleanup(self) -> None:
        pressure = self.pressure
        observed = {
            "schema": "allocatbelt.application-capacity-host-context.v1",
            "host_id": "host-a", "boot_id_sha256": "a" * 64,
            "controls_sha256": "b" * 64, "controls": {},
            "kernel_release": "6.1.0-test", "cpu_model": "test-cpu",
            "cpu_affinity": [2, 3], "network_namespace_inode": 8821,
        }
        body = {
            "schema": "allocatbelt.application-pressure-calibration-host-verification.v1",
            "host_id": "host-a", "boot_id_sha256": "a" * 64,
            "kernel_release": "6.1.0-test", "allowed_cpu_affinity": [2, 3],
            "network_namespace_inode": 8821, "observed_host_raw_sha256": None,
            "owned_worker_pids_reaped": True,
        }
        with tempfile.TemporaryDirectory(prefix="source5-host-scope-") as temp:
            path = Path(temp) / "observed-host.json"
            raw = json.dumps(observed, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True).encode("ascii") + b"\n"
            path.write_bytes(raw)
            observed_sha = hashlib.sha256(raw).hexdigest()
            body["observed_host_raw_sha256"] = observed_sha
            body["host_verification_sha256"] = hashlib.sha256(
                pressure.canonical_bytes(body),
            ).hexdigest()
            receipt = {"host_verification": body}
            pin = {"path": str(path), "raw_sha256": observed_sha}
            self.assertEqual(pressure._verify_source5_host_verification_v2(
                receipt, pin, "host-a",
            ), body)
            wrong = dict(receipt)
            wrong["host_verification"] = {
                **body, "network_namespace_inode": 8822,
            }
            with self.assertRaises(pressure.PressurePairError):
                pressure._verify_source5_host_verification_v2(
                    wrong, pin, "host-a",
                )

    def test_resealed_a_a_analysis_cannot_claim_a_result_that_record_replay_rejects(self) -> None:
        chronology = load_source("source5_analysis_replay_test", CHRONOLOGY_PATH)
        campaign = self.campaign
        host_id = "host-a"
        job = {
            "host_id": host_id, "phase": "aa", "run_id": "aa-original-01",
            "control_id": "aa-bounded-cpu", "ordinal": 1, "mode": "capacity",
        }
        metrics = [
            {"executor": "bounded", "capacity_per_second": 100.0,
             "cpu_ns_per_completion": 4, "rss_after_drain_kib": 10},
            {"executor": "bounded", "capacity_per_second": 100.0,
             "cpu_ns_per_completion": 4, "rss_after_drain_kib": 10},
        ]
        metrics_sha = hashlib.sha256(campaign.canonical_bytes(metrics)).hexdigest()
        start_proofs = [
            {"pid": 501, "start_ticks": 601},
            {"pid": 502, "start_ticks": 602},
        ]
        start_heads = ["1" * 64, "2" * 64]
        terminal_heads = ["3" * 64, "4" * 64]
        component_sha = "5" * 64
        job_terminal_head = "6" * 64
        authorization_head = "7" * 64
        chronology_value = {
            "authorization_id": "source5-aa-original-01",
            "authorization_head": authorization_head,
            "app_started_heads": start_heads,
            "app_terminal_heads": terminal_heads,
            "job_terminal_head": job_terminal_head,
            "component_sha256": component_sha,
            "process_metrics_sha256": metrics_sha,
            "app_start_events": start_proofs,
            "app_terminal_events": [{}, {}],
            "member_processes": [{}, {}],
        }
        evidence_temp = tempfile.TemporaryDirectory(prefix="source5-aa-record-evidence-")
        self.addCleanup(evidence_temp.cleanup)
        evidence_root = Path(evidence_temp.name)

        def write_evidence(name: str, value: dict[str, str]) -> dict[str, str]:
            path = evidence_root / name
            raw = campaign.canonical_bytes(value)
            path.write_bytes(raw)
            return {"path": str(path),
                    "raw_sha256": hashlib.sha256(raw).hexdigest()}

        fixed_path = ROOT / "scripts/application-fixed-pair.py"
        fixed_raw = fixed_path.read_bytes()
        fixed_info = fixed_path.stat()
        fixed_record = {
            "path": "scripts/application-fixed-pair.py", "kind": "file",
            "mode": f"{stat.S_IFMT(fixed_info.st_mode) | stat.S_IMODE(fixed_info.st_mode):06o}",
            "sha256": hashlib.sha256(fixed_raw).hexdigest(),
            "size": len(fixed_raw),
        }
        overlay_evidence = write_evidence(
            "overlay.json", {"schema": "fixture-overlay"},
        )
        evidence = {
            "execution_manifest": write_evidence(
                "execution-manifest.json", {"schema": "fixture-manifest"},
            ),
            "helper_input": write_evidence(
                "helper-input.json", {
                    "schema": "fixture-helper-input",
                    "payload": {"overlay_pin": {
                        "path": overlay_evidence["path"],
                        "sha256": overlay_evidence["raw_sha256"],
                    }},
                },
            ),
            "helper_module": fixed_record,
            "overlay": overlay_evidence,
            "receipt": write_evidence("receipt.json", {"schema": "fixture-receipt"}),
        }
        record_body = {
            "schema": "allocatbelt.application-source5-job-record.v1",
            "state": "valid_pair", "job": job, "pair_directory": ".",
            "process_metrics": metrics, "evidence": evidence,
            "chronology": chronology_value,
            "qualification_eligible": False,
        }
        record = {
            **record_body,
            "record_sha256": hashlib.sha256(
                campaign.canonical_bytes(record_body),
            ).hexdigest(),
        }
        record_raw = campaign.canonical_bytes(record)
        finished = {
            "state": "valid_pair", "details": {
                "job": job,
                "execution_manifest": evidence["execution_manifest"],
                "helper_input": evidence["helper_input"],
                "helper_module": evidence["helper_module"],
            },
            "authorization_id": chronology_value["authorization_id"],
            "authorization_head": authorization_head,
            "record_sha256": job_terminal_head,
            "starts": [
                {"event_head": head, "proof": proof}
                for head, proof in zip(start_heads, start_proofs, strict=True)
            ],
            "terminals": [
                {"event_head": head} for head in terminal_heads
            ],
            "terminal": {
                "component_sha256": component_sha,
                "process_metrics_sha256": metrics_sha,
            },
        }
        with tempfile.TemporaryDirectory(prefix="source5-aa-analysis-replay-") as temp:
            root = Path(temp)
            phase_root = root / "campaign" / "source5" / host_id / "aa"
            record_dir = phase_root / "job-records"
            record_dir.mkdir(parents=True)
            ledger = phase_root / "controller-ledger.jsonl"
            ledger.write_bytes(record_raw)
            ledger.chmod(0o600)
            record_path = record_dir / f"{job['run_id']}.json"
            record_path.write_bytes(record_raw)
            record_path.chmod(0o600)

            controller_path = CONTROLLER_PATH.resolve(strict=True)
            controller_raw = controller_path.read_bytes()
            controller_sha = hashlib.sha256(controller_raw).hexdigest()
            inventory_mode = stat.S_IFMT(controller_path.stat().st_mode) | \
                stat.S_IMODE(controller_path.stat().st_mode)
            source = {
                "manifest_sha256": "8" * 64,
                "source": {"files": [
                    {
                        "path": "scripts/application-source5-campaign.py",
                        "kind": "file", "mode": f"{inventory_mode:06o}",
                        "sha256": controller_sha, "size": len(controller_raw),
                    },
                    fixed_record,
                ]},
                "qualification_harness": {
                    "campaign_controller": {
                        "sha256": hashlib.sha256(CAMPAIGN_PATH.read_bytes()).hexdigest(),
                    },
                },
            }
            prepared = {
                "campaign_id": "campaign", "host_id": host_id,
                "output_root": root, "source_root": ROOT,
                "source": source, "controller": campaign,
                "spec_raw_sha256": "9" * 64, "plan_raw_sha256": "a" * 64,
                "spec": {"protocol": {
                    "bootstrap_draws": 50_000, "bootstrap_seed": 3,
                }},
                "plan": {"jobs": {"aa": [job]}},
            }
            state = {
                "source5_finished": {("aa", job["run_id"]): finished},
                "source5_analyses": {
                    "exploration": {"phase_gate_passed": True},
                },
            }
            expected = campaign.validate_aa_records(
                [record], [job], host_id, 50_000, 3,
            )
            tampered = json.loads(campaign.canonical_bytes(expected))
            tampered["controls"][0]["passed"] = False
            analysis_body = {
                "schema": "allocatbelt.application-source5-phase-analysis.v1",
                "campaign_id": "campaign", "host_id": host_id,
                "phase": "aa", "job_count": 1,
                "job_set_sha256": hashlib.sha256(
                    campaign.canonical_bytes([job["run_id"]]),
                ).hexdigest(),
                "job_evidence_complete": True,
                "numeric_gates_passed": True,
                "phase_gate_passed": True,
                "campaign_qualification_eligible": False,
                "analysis": tampered,
            }
            analysis = {
                **analysis_body,
                "analysis_sha256": hashlib.sha256(
                    campaign.canonical_bytes(analysis_body),
                ).hexdigest(),
            }
            analysis_raw = campaign.canonical_bytes(analysis)
            analysis_path = root / "resealed-analysis.json"
            analysis_path.write_bytes(analysis_raw)
            analysis_path.chmod(0o600)
            details = {
                "phase": "aa",
                "analysis": {"path": str(analysis_path),
                             "raw_sha256": hashlib.sha256(analysis_raw).hexdigest()},
                "analysis_sha256": hashlib.sha256(analysis_raw).hexdigest(),
                "job_count": 1,
                "job_set_sha256": analysis_body["job_set_sha256"],
                "job_evidence_complete": True,
                "numeric_gates_passed": True, "phase_gate_passed": True,
                "campaign_qualification_eligible": False,
            }
            with self.assertRaisesRegex(
                    chronology.ChronologyError,
                    "aa analysis artifact differs from independently recomputed canonical analysis"):
                chronology._validate_source5_analysis(details, prepared, state)

            valid_body = {**analysis_body, "analysis": expected}
            valid_analysis = {
                **valid_body,
                "analysis_sha256": hashlib.sha256(
                    campaign.canonical_bytes(valid_body),
                ).hexdigest(),
            }
            valid_raw = campaign.canonical_bytes(valid_analysis)
            analysis_path.write_bytes(valid_raw)
            analysis_path.chmod(0o600)
            details["analysis"] = {
                "path": str(analysis_path),
                "raw_sha256": hashlib.sha256(valid_raw).hexdigest(),
            }
            details["analysis_sha256"] = details["analysis"]["raw_sha256"]
            chronology._validate_source5_analysis(details, prepared, state)

            Path(evidence["receipt"]["path"]).unlink()
            with self.assertRaises(chronology.ChronologyError):
                chronology._validate_source5_analysis(details, prepared, state)

    def test_locked_pressure_entry_uses_the_received_lock_and_callbacks(self) -> None:
        tree = ast.parse(PRESSURE_PATH.read_bytes(), filename=str(PRESSURE_PATH))
        node = function(tree, "run_pressure_pair_locked")
        args = {item.arg for item in node.args.args}
        self.assertTrue({"chronology_module", "lock", "authorization_context",
                         "on_app_started", "on_app_terminal"} <= args)
        source = ast.unparse(node)
        self.assertIn("chronology_module._lock_token_is_live(lock)", source)
        self.assertIn("on_app_started=on_app_started", source)
        self.assertIn("on_app_terminal=on_app_terminal", source)
        self.assertNotIn("campaign_host_lock(", source)

    def test_locked_overlay_replay_uses_ancestry_for_later_app_events(self) -> None:
        tree = ast.parse(PRESSURE_PATH.read_bytes(), filename=str(PRESSURE_PATH))
        source = ast.unparse(function(tree, "_verify_execution_overlay"))
        self.assertIn("verify_source5_capacity_ancestor_locked", source)
        self.assertIn("historical_journal_head", source)
        self.assertIn("historical_registration_head", source)

    def test_neutral_numeric_analysis_does_not_change_legacy_gate(self) -> None:
        tree = ast.parse(CAMPAIGN_PATH.read_bytes(), filename=str(CAMPAIGN_PATH))
        numeric = ast.unparse(function(tree, "analyze_confirmation_host_numeric"))
        gated = ast.unparse(function(tree, "analyze_confirmation_host_gated"))
        self.assertIn("numeric_gates_passed", numeric)
        self.assertIn("RUNTIME_QUALIFICATION_READBACK_SUPPORTED", numeric)
        self.assertIn("result.pop('numeric_gates_passed')", gated)
        self.assertIn("result['qualification_eligible']", gated)
        module_assignments = {
            item.targets[0].id: ast.literal_eval(item.value)
            for item in tree.body
            if isinstance(item, ast.Assign) and len(item.targets) == 1
            and isinstance(item.targets[0], ast.Name)
            and item.targets[0].id in {
                "RUNTIME_QUALIFICATION_READBACK_SUPPORTED",
                "EXTERNAL_PRESSURE_DRIVER_SUPPORTED",
            }
        }
        self.assertIs(module_assignments["RUNTIME_QUALIFICATION_READBACK_SUPPORTED"], False)
        self.assertIs(module_assignments["EXTERNAL_PRESSURE_DRIVER_SUPPORTED"], False)

    def test_legacy_wrapper_still_fails_when_numeric_gate_passes_but_capability_is_false(self) -> None:
        campaign = load_source("source5_campaign_wrapper_test", CAMPAIGN_PATH)
        original = campaign.analyze_confirmation_host_numeric
        try:
            campaign.analyze_confirmation_host_numeric = lambda *_args, **_kwargs: {
                "qualification_eligible": False,
                "numeric_gates_passed": True,
                "passed": True,
            }
            result = campaign.analyze_confirmation_host_gated(
                {}, "host-test", [], Path("/tmp/source5-wrapper-test"),
            )
        finally:
            campaign.analyze_confirmation_host_numeric = original
        self.assertIs(result["passed"], False)
        self.assertIs(result["qualification_eligible"], False)
        self.assertNotIn("numeric_gates_passed", result)


class Source5ControllerScopeTests(unittest.TestCase):
    def test_prospective_scope_stops_after_exploration(self) -> None:
        tree = ast.parse(CONTROLLER_PATH.read_bytes(), filename=str(CONTROLLER_PATH))
        source = ast.unparse(function(tree, "run_host"))
        self.assertIn("prospective_exploration", source)
        self.assertIn("phase in", source)
        self.assertIn("'exploration'", source)
        self.assertIn("separately_frozen_final_spec_plan_and_source_manifests", source)
        self.assertIn("campaign_qualification_eligible", source)

    def test_scheduler_replays_capacity_before_creating_phase_directory(self) -> None:
        tree = ast.parse(CONTROLLER_PATH.read_bytes(), filename=str(CONTROLLER_PATH))
        node = function(tree, "run_fixed_phase")
        lines = {
            item.func.id: item.lineno for item in ast.walk(node)
            if isinstance(item, ast.Call) and isinstance(item.func, ast.Name)
            and item.func.id in {"_validate_locked_context", "_private_directory"}
        }
        self.assertLess(lines["_validate_locked_context"], lines["_private_directory"])
        source = ast.unparse(node)
        self.assertIn("cannot be replaced", source)
        self.assertIn("complete_invalid_fixed_component_consumes_original_ordinal", source)

    def test_controller_exports_retained_capacity_rows_without_retiming(self) -> None:
        tree = ast.parse(CONTROLLER_PATH.read_bytes(), filename=str(CONTROLLER_PATH))
        source = ast.unparse(function(tree, "_capacity_pilot"))
        self.assertIn("application-capacity-pilot.v1", source)
        self.assertIn("raw_pair_sha256", source)
        self.assertIn("completed_on_time", source)
        self.assertIn("bounded_attempted", source)
        self.assertIn("tokio_attempted", source)
        self.assertNotIn("subprocess", source)

    def test_final_soak_routes_through_the_locked_adapter_and_keeps_campaign_false(self) -> None:
        tree = ast.parse(CONTROLLER_PATH.read_bytes(), filename=str(CONTROLLER_PATH))
        source = ast.unparse(function(tree, "run_host"))
        self.assertIn("run_soak_phase", source)
        self.assertIn("campaign_qualification_eligible", source)
        self.assertNotIn("no same-process Source5 APP callback API yet", source)
        soak = ast.unparse(function(tree, "run_soak_phase"))
        self.assertIn("authorize_source5_job_locked", soak)
        self.assertIn("run_authorized_source5_job_locked", soak)
        self.assertIn("cannot be replaced", soak)

    def test_bounded_pressure_replays_both_captured_probes_before_authorization(self) -> None:
        tree = ast.parse(CONTROLLER_PATH.read_bytes(), filename=str(CONTROLLER_PATH))
        capture = ast.unparse(function(tree, "_capture_source5_probe_bundle"))
        self.assertIn("capture_calibrated_probe_v2", capture)
        self.assertIn("validate_probe_capture_receipt_envelope", capture)
        self.assertIn("compose_calibrated_policy_v5_offline", capture)
        self.assertIn("len(capture_pins) == len(bundle_members) == 2", capture)
        builder = ast.unparse(function(tree, "_build_pressure_recipe"))
        self.assertLess(builder.index("_capture_source5_probe_bundle"),
                        builder.index("_validate_recipe_shape"))
        runner = ast.unparse(function(tree, "run_pressure_phase"))
        self.assertLess(runner.index("_build_pressure_recipe"),
                        runner.index("authorize_source5_job_locked"))
        self.assertIn("PRESSURE_HELPER_PAYLOAD_SCHEMA_V2", runner)
        self.assertIn("probe_capture_bundle", runner)

    def test_selected_floor_id_reaches_both_offline_composer_requests(self) -> None:
        tree = ast.parse(CONTROLLER_PATH.read_bytes(), filename=str(CONTROLLER_PATH))
        capture = ast.unparse(function(tree, "_capture_source5_probe_bundle"))
        self.assertIn("context.spec.get('capacity_floor_policy_id')", capture)
        self.assertIn("REQUEST_SCHEMA_V2", capture)
        self.assertIn("_validate_capacity_floor_policy_descriptor", capture)
        self.assertIn("source_floor_policy", capture)
        self.assertIn("expected_request['capacity_floor_policy_id']", capture)
        self.assertIn("capture_calibrated_probe_v2", capture)
        self.assertIn("capacity_floor_policy_id", capture)
        self.assertIn("static Source5 pressure cannot use a selected floor-policy artifact", capture)


class Source5NumericApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.campaign = load_source("source5_numeric_pilot_test", CAMPAIGN_PATH)
        cls.controller = load_source("source5_numeric_controller_test", CONTROLLER_PATH)

    def test_pressure_capture_budget_is_explicit_and_bounded_by_original_deadline(self) -> None:
        composition = types.SimpleNamespace(
            MAX_PROBE_CAPTURE_TIMEOUT_NS=30_000_000_000,
            MAX_PROBE_STDERR_BYTES=64 * 1024,
            MAX_PROBE_OWNER_RESULT_BYTES=16 * 1024 * 1024,
            MAX_PROBE_TMPDIR_INVENTORY_BYTES=16 * 1024 * 1024,
            MAX_PROBE_CAPTURE_FAILURE_BYTES=64 * 1024,
            MAX_PROBE_CAPTURE_RECEIPT_BYTES=16 * 1024 * 1024,
        )
        capture = {
            "capture_timeout_ns": 5_000_000_000,
            "storage_budget": {
                "tmpdir_bytes": 64 * 1024 * 1024,
                "tmpdir_inodes": 512,
                "stdout_bytes": 512 * 1024,
                "stderr_bytes": 64 * 1024,
                "owner_result_bytes": 16 * 1024 * 1024,
                "inventory_bytes": 16 * 1024 * 1024,
                "failure_bytes": 64 * 1024,
                "receipt_bytes": 16 * 1024 * 1024,
                "output_inodes": 32,
            },
        }
        deadlines = {
            "trace_seconds": 300, "drain_seconds": 30,
            "shutdown_seconds": 30, "process_seconds": 10,
            "outer_seconds": 600,
            "application_wall_timeout_seconds": 10,
            "application_term_grace_seconds": 1,
            "pressure_exit_observation_seconds": 10,
            "pressure_duration_seconds": 300,
            "pressure_total_seconds": 360,
        }
        self.assertEqual(
            self.controller._validate_probe_capture_contract(
                capture, deadlines, composition,
            ), capture,
        )
        with self.assertRaises(self.controller.Source5CampaignError):
            self.controller._validate_probe_capture_contract(
                {"capture_timeout_ns": 5_000_000_000}, deadlines, composition,
            )
        with self.assertRaises(self.controller.Source5CampaignError):
            self.controller._validate_probe_capture_contract(
                {**capture, "capture_timeout_ns": 10_000_000_001},
                deadlines, composition,
            )
        invalid_storage = dict(capture["storage_budget"])
        invalid_storage["tmpdir_inodes"] = 4097
        with self.assertRaises(self.controller.Source5CampaignError):
            self.controller._validate_probe_capture_contract(
                {**capture, "storage_budget": invalid_storage},
                deadlines, composition,
            )

    def test_pilot_freeze_and_final_rate_projection_preserve_raw_provenance(self) -> None:
        campaign = self.campaign
        cells = [
            {"family": family, "workload": workload, "profile": profile}
            for family, workload, profile in campaign.expected_profile_cells()
        ]
        spec = {
            "schema": campaign.SPEC_SCHEMA_V3,
            "campaign_id": "unit-only-rate-projection",
            "hosts": [{"host_id": "host-a"}],
            "cells": cells,
            "rates": [], "oracles": [],
        }
        groups = []
        for family, profile in sorted({(cell["family"], cell["profile"])
                                       for cell in cells}):
            for allocator in campaign.ALLOCATORS:
                pairs = []
                for ordinal in range(1, 7):
                    pairs.append({
                        "ordinal": ordinal,
                        "bounded_status": "valid", "tokio_status": "valid",
                        "bounded_on_time": 3000, "bounded_late": 0,
                        "bounded_attempted": 3000, "bounded_admitted": 3000,
                        "bounded_rejected": 0,
                        "tokio_on_time": 3000, "tokio_late": 0,
                        "tokio_attempted": 3000, "tokio_admitted": 3000,
                        "tokio_rejected": 0,
                        "raw_pair_sha256": "a" * 64,
                    })
                groups.append({"family": family, "profile": profile,
                               "allocator": allocator, "pairs": pairs})
        pilot = {
            "schema": "allocatbelt.application-capacity-pilot.v1",
            "spec_sha256": campaign.preregistration_digest(spec),
            "host_id": "host-a", "cells": groups,
        }
        raw_pilot_sha = "b" * 64
        frozen = campaign.freeze_rates(spec, pilot, raw_pilot_sha)
        rows = self.controller._frozen_rate_rows("host-a", frozen, raw_pilot_sha)
        self.assertEqual(len(rows), len(cells) * 2)
        self.assertTrue(all(row["pilot_manifest_sha256"] == raw_pilot_sha
                            for row in rows))
        final_rows = [
            {"host_id": "host-a", "family": row["family"],
             "profile": row["profile"], "load_percent": row["load_percent"],
             "arrivals_per_second": row["arrivals_per_second"],
             "pilot_manifest_sha256": raw_pilot_sha}
            for row in frozen["rates"]
        ]
        self.assertEqual(rows, final_rows)
        changed_provenance = [dict(row, pilot_manifest_sha256="c" * 64)
                              for row in rows]
        self.assertNotEqual(rows, changed_provenance)

    def test_resealed_analysis_gate_cannot_differ_from_recomputed_numeric_result(self) -> None:
        controller = self.controller
        expected = {
            "schema": "allocatbelt.application-host-analysis.v1",
            "numeric_gates_passed": False,
            "passed": False,
            "tests": [{"name": "unit-only", "passed": False}],
        }
        resealed = json.loads(controller.canonical_bytes(expected))
        resealed["numeric_gates_passed"] = True
        resealed["passed"] = True
        self.assertFalse(controller._source5_analysis_matches_replay(
            "fixed_analysis", resealed, expected,
        ))

    def test_persist_analysis_writes_a_bound_ineligible_failure_record(self) -> None:
        controller = self.controller
        job = {"run_id": "unit-only-exploration", "host_id": "host-a",
               "phase": "exploration"}
        with tempfile.TemporaryDirectory(prefix="source5-analysis-persist-") as temp:
            root = Path(temp)

            class Recorder:
                def __init__(self) -> None:
                    self.seen = None

                def record_source5_analysis_locked(self, _lock, _manifest_pin, pin):
                    raw = Path(pin["path"]).read_bytes()
                    value = json.loads(raw)
                    self.seen = value
                    return {"recorded": True,
                            "analysis_sha256": pin["raw_sha256"]}

            recorder = Recorder()
            context = types.SimpleNamespace(
                manifest={"campaign_id": "unit-only"},
                host_id="host-a",
                plan={"jobs": {"exploration": [job]}},
                artifact_root=root,
                output_root=root,
                scope="prospective_exploration",
                spec={},
                manifest_pin={"path": "/private/manifest.json",
                              "raw_sha256": "d" * 64},
                chronology=recorder,
            )
            result = controller._persist_analysis(
                context, object(), "exploration", "exploration",
                {"schema": "unit-only-analysis-fixture", "rows": []},
                True, False,
            )
            self.assertTrue(result["record"]["analysis_sha256"])
            self.assertIs(result["record"]["phase_gate_passed"], False)
            self.assertIs(result["record"]["campaign_qualification_eligible"], False)
            self.assertEqual(recorder.seen, result["record"])
            self.assertEqual(Path(result["pin"]["path"]).read_bytes(),
                             controller.canonical_bytes(result["record"]))


class Source5GlobalReferenceTests(unittest.TestCase):
    def test_owned_python_modules_have_no_unresolved_global_loads(self) -> None:
        allowed_implicit = {"__file__", "__name__"}
        for path in (CHRONOLOGY_PATH, PRESSURE_PATH, CONTROLLER_PATH,
                     CAMPAIGN_PATH, Path(__file__).resolve()):
            table = symtable.symtable(path.read_text(), str(path), "exec")
            module_names = set(table.get_identifiers())
            missing = set()
            pending = [table]
            while pending:
                current = pending.pop()
                for symbol in current.get_symbols():
                    name = symbol.get_name()
                    if (symbol.is_global() and symbol.is_referenced() and
                            name not in module_names and name not in allowed_implicit and
                            not hasattr(builtins, name)):
                        missing.add(name)
                pending.extend(current.get_children())
            self.assertEqual(missing, set(), f"{path} has unresolved global references")


if __name__ == "__main__":
    unittest.main()
