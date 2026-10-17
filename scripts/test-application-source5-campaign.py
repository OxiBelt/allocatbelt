#!/usr/bin/env python3
"""Static/API regression checks for the Source5 controller boundary."""
from __future__ import annotations

import ast
import builtins
import hashlib
import importlib.util
import io
import json
import os
import signal
import stat
import sys
import symtable
import tarfile
import tempfile
import threading
import time
import types
import unittest
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
CHRONOLOGY_PATH = ROOT / "scripts/application-campaign-chronology.py"
PRESSURE_PATH = ROOT / "scripts/application-pressure-pair.py"
CAMPAIGN_PATH = ROOT / "scripts/application-campaign.py"
CONTROLLER_PATH = ROOT / "scripts/application-source5-campaign.py"
PREPARATION_PATH = ROOT / "scripts/application-source5-input-preparation.py"
SOAK_RECIPE_TESTS_PATH = ROOT / "scripts/test-application-soak-recipe.py"
SOAK_READBACK_PATH = ROOT / "scripts/application-soak-readback.py"


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
        cls.controller = load_source(
            "source5_campaign_metadata_handoff_test", CONTROLLER_PATH,
        )

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
                "completion": {"path": "/inputs/preparation-completion.json",
                               "raw_sha256": "8" * 64,
                               "semantic_sha256": "9" * 64},
                "host_verification": {"path": "/inputs/host-verification.json",
                                      "raw_sha256": "a" * 64,
                                      "receipt_sha256": "b" * 64},
                "host_completion": {"path": "/inputs/host-completion.json",
                                    "raw_sha256": "a" * 64,
                                    "semantic_sha256": "c" * 64},
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
                "completion": {"path": "/inputs/preparation-completion.json",
                               "raw_sha256": "8" * 64,
                               "semantic_sha256": "9" * 64},
                "host_verification": {"path": "/inputs/host-verification.json",
                                      "raw_sha256": "a" * 64,
                                      "receipt_sha256": "b" * 64},
                "host_completion": {"path": "/inputs/host-a/capacity-v2.json",
                                    "raw_sha256": "3" * 64,
                                    "semantic_sha256": "c" * 64},
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
                    return {
                        "record_sha256": str(4 + index) * 64,
                        "details": {"cleanup": event["cleanup"]},
                    }

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

    def test_preparatory_loader_names_only_metadata_generation_and_binding_apis(self) -> None:
        load_context = function(
            ast.parse(CONTROLLER_PATH.read_bytes(), filename=str(CONTROLLER_PATH)),
            "load_context",
        )
        context_calls = {
            node.func.attr for node in ast.walk(load_context)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        context_source = ast.get_source_segment(
            CONTROLLER_PATH.read_text(encoding="utf-8"), load_context,
        )
        self.assertIn("verify_prepared_capacity_generation_bounded_metadata_v1",
                      context_calls)
        self.assertNotIn("verify_prepared_capacity_generation_bounded", context_calls)
        for name in (
            "materialize_prepared_host_binding_metadata_v1",
            "verify_prepared_host_binding_metadata_v1",
        ):
            self.assertIn(name, context_source)
        binding = function(
            ast.parse(CONTROLLER_PATH.read_bytes(), filename=str(CONTROLLER_PATH)),
            "_source5_prepared_host_binding",
        )
        binding_source = ast.get_source_segment(
            CONTROLLER_PATH.read_text(encoding="utf-8"), binding,
        )
        self.assertIn("materialize_prepared_host_binding_metadata_v1", binding_source)
        self.assertIn("verify_prepared_host_binding_metadata_v1", binding_source)
        self.assertNotIn('"materialize_prepared_host_binding"', binding_source)
        self.assertNotIn('"verify_prepared_host_binding"', binding_source)

    def test_h_prepared_host_binding_uses_real_metadata_materializer_and_verifier(self) -> None:
        """A nested structural peer-ELF fixture exercises H's real InputPrep calls."""
        support = load_source(
            "source5_preparatory_metadata_handoff_fixture_source",
            ROOT / "scripts/test-application-source5-input-preparation.py",
        )
        fixture_type = support.RecordedHistoricalGlobalReaderTests
        fixture_type.setUpClass()
        builder = fixture_type()
        preparation = load_source(
            "source5_preparatory_metadata_handoff_inputprep",
            PREPARATION_PATH,
        )
        with tempfile.TemporaryDirectory(prefix="source5-h-metadata-binding-") as temporary:
            fixture = builder._metadata_intent_fixture(Path(temporary))
            host_id = fixture["host_ids"][0]
            source_root = fixture["source_root"]
            input_root = fixture["input_root"]
            context = types.SimpleNamespace(
                manifest={
                    "schema": self.controller.PREPARATORY_EXECUTION_SCHEMA,
                    "preparatory_capacity_generation": {"provenance": {
                        "preparation_pin": {
                            "path": fixture["preparation_pin"]["path"],
                            "raw_sha256": fixture["preparation_pin"]["sha256"],
                        },
                    }},
                },
                modules={
                    self.controller.SOURCE5_INPUT_PREPARATION_SOURCE_PATH:
                        preparation,
                },
                spec_pin={
                    "path": fixture["spec_pin"]["path"],
                    "raw_sha256": fixture["spec_pin"]["sha256"],
                },
                source_root=source_root, input_root=input_root, host_id=host_id,
            )
            materialized = self.controller._source5_prepared_host_binding(
                context, materialize=True,
            )
            verified = self.controller._source5_prepared_host_binding(
                context, materialize=False,
            )
            self.assertEqual(materialized, verified)
            self.assertEqual(
                context.fixed_spec_host_pin,
                materialized["fixed_spec_host_pin"],
            )
            self.assertEqual(
                context.prepared_fixed_host_binding,
                materialized["prepared_host_binding"],
            )

    def test_named_capacity_generation_verifier_loads_nested_two_host_metadata(self) -> None:
        """Real metadata replay reaches the expected missing capacity-evidence edge."""
        support = load_source(
            "source5_prep_generation_metadata_fixture_source",
            ROOT / "scripts/test-application-source5-input-preparation.py",
        )
        fixture_type = support.RecordedHistoricalGlobalReaderTests
        fixture_type.setUpClass()
        fixture_builder = fixture_type()
        preparation = load_source(
            "source5_prep_generation_metadata_inputprep",
            PREPARATION_PATH,
        )
        with tempfile.TemporaryDirectory(prefix="source5-h-metadata-generation-") as temporary:
            fixture = fixture_builder._metadata_intent_fixture(Path(temporary))
            source_inputs = fixture["source_inputs"]
            source_root, input_root = fixture["source_root"], fixture["input_root"]
            host_ids = fixture["host_ids"]
            self.assertEqual(len(host_ids), 2)
            self.assertTrue(
                Path(fixture["preparation_pin"]["path"]).is_relative_to(input_root),
            )
            self.assertNotEqual(Path(fixture["preparation_pin"]["path"]).parent,
                                input_root)
            first_artifact = fixture["sources"][host_ids[0]]["artifacts"]["allocatbelt"]
            peer_artifact = fixture["sources"][host_ids[1]]["artifacts"]["allocatbelt"]
            self.assertEqual(first_artifact["path"], peer_artifact["path"])
            self.assertNotEqual(first_artifact["sha256"], peer_artifact["sha256"])
            ceilings = {
                "maximum_job_output_bytes": 1_073_741_824,
                "maximum_job_output_inodes": 1024,
                "maximum_generation_bytes": 2_147_483_648,
                "maximum_generation_inodes": 8192,
                "maximum_tmpdir_bytes": 1_073_741_824,
                "maximum_tmpdir_inodes": 4096,
                "maximum_trace_file_bytes": 536_870_912,
                "durable_receipt_reserve_bytes": 1_048_576,
                "durable_receipt_reserve_inodes": 8,
                "minimum_free_bytes": 2_147_483_648,
                "minimum_free_inodes": 10_000,
                "monitor_sample_interval_milliseconds": 100,
                "process_deadline_seconds":
                    fixture["preparation"]["core"]["deadlines"]["process_seconds"],
            }
            budgets = {}
            capacity_rows = []
            for index, host_id in enumerate(host_ids):
                budget = source_inputs.build_preparation_resource_budget(
                    fixture["preparation"], fixture["preparation_full_pin"],
                    host_id, ceilings,
                )
                budget_path = input_root / "resource-budgets" / f"{host_id}.json"
                budget_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                os.chmod(budget_path.parent, 0o700)
                budget_raw = source_inputs._canonical(budget)
                budget_path.write_bytes(budget_raw)
                budget_path.chmod(0o600)
                budget_pin = {
                    "path": str(budget_path),
                    "raw_sha256": hashlib.sha256(budget_raw).hexdigest(),
                    "semantic_sha256": budget["resource_budget_sha256"],
                }
                budgets[host_id] = budget_pin
                completion_path = input_root / "capacity-preparations" / host_id / \
                    "capacity-preparation-bounded-completion.json"
                completion_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                os.chmod(completion_path.parent.parent, 0o700)
                os.chmod(completion_path.parent, 0o700)
                capacity_rows.append({
                    "host_id": host_id,
                    "completion": {
                        "path": str(completion_path),
                        "raw_sha256": str(index + 1) * 64,
                    },
                    "host_verification": {
                        "path": str(completion_path.with_name("host-verification.json")),
                        "raw_sha256": str(index + 3) * 64,
                        "receipt_sha256": str(index + 4) * 64,
                    },
                    "evidence_path_map": {
                        "schema": support.capacity_stage.EVIDENCE_PATH_MAP_SCHEMA,
                        "entries": [{"origin": str(input_root),
                                     "local": str(input_root)}],
                    },
                    "completion_sha256": str(index + 5) * 64,
                    "ledger": {
                        "path": str(completion_path.with_name("capacity-ledger.jsonl")),
                        "raw_sha256": str(index + 6) * 64,
                        "terminal_head": str(index + 7) * 64,
                    },
                    "capacity_preparation_templates_sha256": str(index + 8) * 64,
                    "entries": [], "resource_budget": budget_pin,
                    "resource_monitor": {
                        "schema": "allocatbelt.application-capacity-preparation-resource-monitor.v1",
                        "report_count": 30,
                    },
                })
            body = {
                "schema": preparation.PREPARED_CAPACITY_GENERATION_SCHEMA,
                "campaign_id": fixture["preparation"]["core"]["campaign_id"],
                "preparation": {
                    "path": fixture["preparation_pin"]["path"],
                    "raw_sha256": fixture["preparation_pin"]["sha256"],
                    "semantic_sha256": fixture["preparation"]["preparation_sha256"],
                },
                "capacity_preparations": capacity_rows,
                "resource_budgets": budgets,
                "complete": True, "qualification_eligible": False,
            }
            generation_value = {
                **body,
                "generation_sha256": hashlib.sha256(
                    source_inputs._canonical(body),
                ).hexdigest(),
            }
            generation_path = input_root / "prepared-capacity-generation.json"
            generation_raw = source_inputs._canonical(generation_value)
            generation_path.write_bytes(generation_raw)
            generation_path.chmod(0o600)
            generation_pin = {
                "path": str(generation_path),
                "raw_sha256": hashlib.sha256(generation_raw).hexdigest(),
                "semantic_sha256": generation_value["generation_sha256"],
            }
            calls = []
            real_reader = preparation.read_preparation_intent_metadata_v1

            def read_metadata(*args, **kwargs):
                calls.append((args, kwargs))
                return real_reader(*args, **kwargs)

            with patch.object(preparation, "read_preparation_intent_metadata_v1",
                              side_effect=read_metadata):
                with self.assertRaises(preparation.PreparationError):
                    preparation.verify_prepared_capacity_generation_bounded_metadata_v1(
                        generation_pin, fixture["preparation_pin"],
                        source_root, input_root,
                    )
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][0], (
                fixture["preparation_pin"], source_root, input_root,
            ))
            self.assertFalse(generation_path.is_symlink())


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
        data_builder = ast.unparse(function(tree, "_build_pressure_recipe_data_held"))
        self.assertLess(data_builder.index("_capture_source5_probe_bundle"),
                        data_builder.index("_validate_recipe_shape"))
        wrapper = ast.unparse(function(tree, "_build_pressure_recipe"))
        self.assertIn("_build_pressure_recipe_data_held", wrapper)
        runner = ast.unparse(function(tree, "run_pressure_phase"))
        self.assertLess(runner.index("_build_pressure_recipe"),
                        runner.index("authorize_source5_job_locked"))
        self.assertIn("PRESSURE_HELPER_PAYLOAD_SCHEMA_V2", runner)
        self.assertIn("probe_capture_bundle", runner)

    def test_pressure_predecessor_certificate_is_live_only_and_owner_read_is_ordered(self) -> None:
        tree = ast.parse(CONTROLLER_PATH.read_bytes(), filename=str(CONTROLLER_PATH))
        wrapper_node = function(tree, "_build_pressure_recipe")
        wrapper = ast.unparse(wrapper_node)
        data_node = function(tree, "_build_pressure_recipe_data_held")
        data_helper = ast.unparse(data_node)
        self.assertIn("build_source5_pressure_predecessor_replay_locked", wrapper)
        self.assertIn("captured_evidence=captured_view", wrapper)
        data_helper_calls = [
            node for node in ast.walk(wrapper_node)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and
            node.func.id == "_build_pressure_recipe_data_held"
        ]
        self.assertEqual(len(data_helper_calls), 1)
        data_kwargs = {item.arg: item.value for item in data_helper_calls[0].keywords}
        self.assertIsInstance(data_kwargs["pressure_predecessor_certificate"], ast.Name)
        self.assertEqual(data_kwargs["pressure_predecessor_certificate"].id,
                         "pressure_predecessor_certificate")
        certificate_detail_assignments = [
            node for node in ast.walk(data_node)
            if isinstance(node, ast.Assign) and
            any(isinstance(target, ast.Subscript) and
                isinstance(target.value, ast.Name) and target.value.id == "details" and
                isinstance(target.slice, ast.Constant) and
                target.slice.value == "pressure_predecessor_certificate"
                for target in node.targets)
        ]
        self.assertEqual(len(certificate_detail_assignments), 1)
        self.assertIsInstance(certificate_detail_assignments[0].value, ast.Name)
        self.assertEqual(certificate_detail_assignments[0].value.id,
                         "pressure_predecessor_certificate")
        parents = {
            child: parent for parent in ast.walk(data_node)
            for child in ast.iter_child_nodes(parent)
        }
        ancestor = certificate_detail_assignments[0]
        while ancestor in parents and not isinstance(ancestor, ast.If):
            ancestor = parents[ancestor]
        self.assertIsInstance(ancestor, ast.If)
        self.assertIn("EXECUTION_SCHEMA_V4", ast.unparse(ancestor.test))
        issuer_calls = [
            node for node in ast.walk(wrapper_node)
            if isinstance(node, ast.Call) and
            getattr(node.func, "attr", None) ==
                "build_source5_pressure_predecessor_replay_locked"
        ]
        self.assertEqual(len(issuer_calls), 1)
        issuer = issuer_calls[0]
        self.assertEqual(len(issuer.args), 4)
        self.assertIsInstance(issuer.args[0], ast.Name)
        self.assertEqual(issuer.args[0].id, "lock")
        self.assertIsInstance(issuer.args[1], ast.Call)
        self.assertIsInstance(issuer.args[1].func, ast.Name)
        self.assertEqual(issuer.args[1].func.id, "api_pin")
        self.assertIsInstance(issuer.args[2], ast.Name)
        self.assertEqual(issuer.args[2].id, "job")
        self.assertIsInstance(issuer.args[3], ast.Name)
        self.assertEqual(issuer.args[3].id, "fixed_record_pin")
        self.assertEqual(
            [item.arg for item in issuer.keywords], ["captured_evidence"],
        )
        self.assertIsInstance(issuer.keywords[0].value, ast.Name)
        self.assertEqual(issuer.keywords[0].value.id, "captured_view")
        archive_calls = [
            node for node in ast.walk(wrapper_node)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and
            node.func.id == "archived_job_read_view"
        ]
        self.assertEqual(len(archive_calls), 1)
        self.assertLess(archive_calls[0].lineno, issuer.lineno)
        self.assertLess(issuer.lineno, data_helper_calls[0].lineno)
        recipe_assignments = [
            node for node in data_node.body
            if isinstance(node, ast.Assign) and
            any(isinstance(target, ast.Name) and target.id == "recipe"
                for target in node.targets)
        ]
        self.assertEqual(len(recipe_assignments), 1)
        self.assertNotIn("pressure_predecessor_certificate",
                         ast.unparse(recipe_assignments[0].value))
        self.assertNotIn("pressure_predecessor_certificate", ast.unparse(
            function(tree, "_helper_input_value"),
        ))

        runner_node = function(tree, "run_pressure_phase")
        runner = ast.unparse(runner_node)
        authorization_calls = [
            node for node in ast.walk(runner_node)
            if isinstance(node, ast.Call) and
            getattr(node.func, "attr", None) == "authorize_source5_job_locked"
        ]
        self.assertEqual(len(authorization_calls), 2)
        certificate_calls = [
            node for node in authorization_calls
            if any(item.arg == "pressure_predecessor_certificate"
                   for item in node.keywords)
        ]
        self.assertEqual(len(certificate_calls), 1)
        authorize_at = runner.index("authorize_source5_job_locked")
        certificate_at = runner.index("pressure_predecessor_certificate")
        self.assertLess(certificate_at, runner.index("run_authorized_source5_job_locked"))
        self.assertIn("pressure_predecessor_certificate=", runner)
        archive_at = runner.index("_source5_wait_verify_and_reclaim_archive_job")
        owner_read_at = runner.index("archived_job_read_view", archive_at)
        owner_verify_at = runner.index("verify_source5_completed_pressure_job_captured_locked", owner_read_at)
        self.assertLess(authorize_at, archive_at)
        self.assertLess(archive_at, owner_read_at)
        self.assertLess(owner_read_at, owner_verify_at)
        owner_context = runner[owner_read_at:owner_verify_at]
        self.assertIn("captured_view", owner_context)
        verify_calls = [
            node for node in ast.walk(runner_node)
            if isinstance(node, ast.Call) and
            getattr(node.func, "attr", None) ==
                "verify_source5_completed_pressure_job_captured_locked"
        ]
        self.assertEqual(len(verify_calls), 1)
        self.assertIn(
            "pressure_predecessor_certificate",
            {item.arg for item in verify_calls[0].keywords},
        )

    def test_pressure_phase_reuses_completed_owner_rows_without_new_archive_reads(self) -> None:
        tree = ast.parse(CONTROLLER_PATH.read_bytes(), filename=str(CONTROLLER_PATH))
        pressure = ast.unparse(function(tree, "_fresh_pressure_phase_records"))
        self.assertIn("source5_completed_archive_read_provider", pressure)
        self.assertIn("_source5_replay_phase_records_captured", pressure)
        self.assertIn("archive_purpose == 'pressure_analysis'", pressure)
        self.assertNotIn("archived_job_read_view", pressure)
        phase_replay = ast.unparse(function(tree, "_source5_replay_phase_records_captured"))
        self.assertIn("replay_source5_phase_records_captured_locked", phase_replay)
        self.assertIn("replayed == expected_records", phase_replay)

    def test_initial_final_analysis_uses_one_ordered_owner_provider_then_trace_rows(self) -> None:
        tree = ast.parse(CONTROLLER_PATH.read_bytes(), filename=str(CONTROLLER_PATH))
        final = function(tree, "_fresh_source5_final_phase_results")
        final_text = ast.unparse(final)
        self.assertIn("replay_source5_final_records_captured_locked", final_text)
        self.assertIn("final_read_provider = _Source5ScheduledArchiveReadProvider(context)",
                      final_text)
        self.assertIn("replayed_records == local_records", final_text)
        numeric_calls = [
            node for node in ast.walk(final)
            if isinstance(node, ast.Call) and
            getattr(node.func, "id", None) == "_source5_numeric_for_pairs"
        ]
        self.assertEqual(len(numeric_calls), 2)
        for call in numeric_calls:
            keywords = {item.arg: item.value for item in call.keywords}
            self.assertIn("captured_read_provider", keywords)
            self.assertIsInstance(keywords["captured_read_provider"], ast.Name)
            self.assertEqual(keywords["captured_read_provider"].id,
                             "final_read_provider")
        providers = [
            item for item in tree.body
            if isinstance(item, ast.ClassDef) and
            item.name == "_Source5ScheduledArchiveReadProvider"
        ]
        self.assertEqual(len(providers), 1)
        provider = providers[0]
        open_view = ast.unparse(provider)
        self.assertIn("row.get('use') == use", open_view)
        self.assertIn("row.get('job') == job", open_view)
        self.assertIn("archived_job_read_view(context, job, purpose)", open_view)

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

    def test_legacy_phase_entry_does_not_use_v4_freshness_registry(self) -> None:
        controller = load_source("source5_phase_entry_freshness_fixture", CONTROLLER_PATH)
        context = types.SimpleNamespace(
            manifest={"schema": controller.EXECUTION_SCHEMA_V3},
        )
        controller._source5_refresh_phase_prerequisite_gates_locked(
            context, object(), "aa",
        )


    def test_v4_successor_runners_refresh_before_their_first_authorization(self) -> None:
        tree = ast.parse(CONTROLLER_PATH.read_bytes(), filename=str(CONTROLLER_PATH))
        for name in ("run_fixed_phase", "run_pressure_phase", "run_soak_phase"):
            node = function(tree, name)
            refresh_lines = [
                item.lineno for item in ast.walk(node)
                if isinstance(item, ast.Call) and
                getattr(item.func, "id", None) ==
                    "_source5_refresh_phase_prerequisite_gates_locked"
            ]
            authorize_lines = [
                item.lineno for item in ast.walk(node)
                if isinstance(item, ast.Call) and
                getattr(item.func, "attr", None) ==
                    "authorize_source5_job_locked"
            ]
            self.assertTrue(refresh_lines, name)
            self.assertTrue(authorize_lines, name)
            self.assertLess(min(refresh_lines), min(authorize_lines), name)


    def test_v4_phase_entry_refreshes_exact_prior_analysis_gates_before_authorization(self) -> None:
        controller = load_source("source5_phase_entry_freshness_fixture", CONTROLLER_PATH)
        calls = []
        class Provider:
            def open_view(self, *_args, **_kwargs):
                raise AssertionError("phase-entry helper must pass IO only, not read directly")
        provider = Provider()
        class Chronology:
            def refresh_source5_analysis_gate_locked(
                self, lock, manifest_pin, phase, *, captured_read_context,
            ):
                calls.append((lock, manifest_pin, phase, captured_read_context))
                return {"phase_gate_passed": False}
        context = types.SimpleNamespace(
            manifest={"schema": controller.EXECUTION_SCHEMA_V4},
            manifest_pin={"path": "/private/manifest.json",
                          "raw_sha256": "a" * 64},
            chronology=Chronology(),
        )
        original_provider = controller.source5_completed_archive_read_provider
        controller.source5_completed_archive_read_provider = lambda _context: provider
        lock = object()
        try:
            controller._source5_refresh_phase_prerequisite_gates_locked(
                context, lock, "confirmation",
            )
        finally:
            controller.source5_completed_archive_read_provider = original_provider
        self.assertEqual([row[2] for row in calls], ["exploration", "aa"])
        self.assertTrue(all(row[0] is lock and row[1] == {
            "path": "/private/manifest.json", "sha256": "a" * 64,
        } and row[3] is provider for row in calls))
        self.assertIsNotNone(provider.open_view)



class Source5ArchiveCallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.controller = load_source(
            "source5_archive_caller_test", CONTROLLER_PATH,
        )

    def test_completed_job_builds_exact_catalogued_request_packet_and_offer(self) -> None:
        controller = self.controller
        job = {"host_id": "host-a", "phase": "confirmation",
               "ordinal": 1, "run_id": "original-confirmation-1"}
        job_raw = controller.canonical_bytes({"job": job})
        job_record_pin = {
            "path": "/private/output/confirmation/job-records/original-confirmation-1.json",
            "raw_sha256": hashlib.sha256(job_raw).hexdigest(),
        }
        plan_raw = controller.canonical_bytes({"plan": "fixture"})
        receipt_raw = controller.canonical_bytes({"receipt": "owner"})
        payload_raw = b"captured original owner bytes\n"
        declarations = []

        def add(path: str, role: str, maximum: int = 4096) -> None:
            declarations.append({
                "path": path, "kind": "file", "role": role,
                "max_bytes": maximum, "max_file_bytes": maximum,
                "max_inodes": 1, "phase": "confirmation",
                "run_id": job["run_id"], "member_index": None,
                "storage_root": "/private/artifacts", "origin_pin": None,
            })

        add("/private/artifacts/owner/receipt.json", "component_receipt")
        add("/private/output/confirmation/fixed-host-receipts/000001-" +
            "a" * 64 + ".json", "fixed_pair_host_receipt")
        add("/private/artifacts/owner/stdout.tsv", "normal_app_output")
        add("/private/output/confirmation/job-records/original-confirmation-1.json",
            "source5_job_record")
        add("/private/output/confirmation/checkpoints/000001.request.json",
            "source5_checkpoint_request")
        add("/private/scratch/confirmation/000001.tar",
            "source5_transfer_packet")
        add("/private/output/confirmation/000001.offer.json",
            "source5_transfer_offer")
        add("/private/output/confirmation/000001.ack.tar",
            "source5_ack_bundle")
        add("/private/output/confirmation/000001.ack.tar.incoming",
            "source5_ack_bundle_incoming")
        add("/private/output/confirmation/000001.cleanup.json",
            "source5_cleanup_sidecar")
        add("/private/artifacts/job-path-catalogue.jsonl",
            "source5_job_row_catalogue")

        captured_by_path = {
            "/private/artifacts/owner/receipt.json": receipt_raw,
            "/private/output/confirmation/fixed-host-receipts/000001-" +
            "a" * 64 + ".json": receipt_raw,
            "/private/artifacts/owner/stdout.tsv": payload_raw,
        }

        class ArchiveModule:
            CONTEXT_SCHEMA_V1 = "allocatbelt.application-source5-evidence-archive-context.v1"

            @staticmethod
            def build_checkpoint_request(
                archive_context, record_pin, record_bytes, plan_bytes,
                entries, owner_receipt_bytes, output_path, *,
                tree_inventories=None,
            ):
                calls.append("request")
                observed["context"] = archive_context
                observed["entries"] = entries
                observed["receipts"] = owner_receipt_bytes
                observed["tree_inventories"] = tree_inventories
                body = {"schema": "fixture-request"}
                digest = hashlib.sha256(controller.canonical_bytes(body)).hexdigest()
                request = {**body, "request_sha256": digest}
                raw = controller.canonical_bytes(request)
                return request, {
                    "path": str(output_path),
                    "raw_sha256": hashlib.sha256(raw).hexdigest(),
                    "semantic_sha256": digest,
                }

        class PacketModule:
            @staticmethod
            def export_transfer_packet(
                request_raw, request_pin, budget_path, packet_path,
                offer_path, receiver_path,
            ):
                calls.append("packet")
                return {
                    "path": str(packet_path), "raw_sha256": "d" * 64,
                    "byte_count": 512, "maximum_packet_bytes": 1024,
                }

            @staticmethod
            def publish_transfer_offer(
                request_raw, request_pin, packet_pin, budget_raw, budget_pin,
                offer_path, receiver_path,
            ):
                calls.append("offer")
                body = {
                    "schema": "fixture-offer",
                    "acknowledgement_receiver": {
                        "path": str(receiver_path), "maximum_bytes": 4096,
                    },
                }
                digest = hashlib.sha256(controller.canonical_bytes(body)).hexdigest()
                offer = {**body, "offer_sha256": digest}
                raw = controller.canonical_bytes(offer)
                return offer, {
                    "path": str(offer_path),
                    "raw_sha256": hashlib.sha256(raw).hexdigest(),
                    "semantic_sha256": digest,
                }

        context = types.SimpleNamespace(
            scope="final_frozen",
            manifest={"campaign_id": "campaign-a",
                      "manifest_sha256": "a" * 64,
                      "schema": controller.EXECUTION_SCHEMA_V4},
            manifest_pin={"path": "/private/execution.json",
                          "raw_sha256": "b" * 64},
            host_id="host-a",
            source_manifest_pins={"host-a": {
                "path": "/private/source.json", "raw_sha256": "c" * 64,
            }},
            sources={"host-a": {"manifest_sha256": "d" * 64}},
            plan_pin={"path": "/private/plan.json",
                      "raw_sha256": hashlib.sha256(plan_raw).hexdigest()},
            plan_semantic_sha256="f" * 64, plan_raw=plan_raw,
            host_evidence_budget_pin={
                "path": "/private/budget.json", "raw_sha256": "1" * 64,
                "semantic_sha256": "2" * 64,
            },
            host_evidence_budget_raw=b"budget\n",
            archive_signer_context={
                "authorized_primary_fingerprint": "A" * 40,
            },
            modules={
                controller.EVIDENCE_ARCHIVE_SOURCE_PATH: ArchiveModule,
                controller.EVIDENCE_TRANSFER_PACKET_SOURCE_PATH: PacketModule,
                controller.EVIDENCE_BUDGET_SOURCE_PATH: types.SimpleNamespace(
                    NON_EXPORTABLE_JOB_RECORD_ROLES={"source5_job_record",
                                                     "source5_job_disposition"},
                    FAILURE_WINDOW_ONLY_ROLES={"source5_job_disposition",
                                               "source5_cleanup_sidecar"},
                    TRANSIENT_JOB_EVIDENCE_ROLES={"source5_transfer_packet",
                                                   "source5_ack_bundle",
                                                   "source5_ack_bundle_incoming"},
                    ARCHIVE_LOCAL_METADATA_ROLES={
                        "source5_checkpoint_request", "source5_transfer_offer",
                        "source5_checkpoint", "source5_object_manifest",
                        "source5_archive_ack", "source5_archive_signature",
                        "source5_stage_map",
                    },
                    ALWAYS_LOCAL_EVIDENCE_ROLES={"source5_job_row_catalogue"},
                ),
            },
        )
        calls = []
        observed = {}

        def capture(_context, declaration):
            raw = captured_by_path[declaration["path"]]
            return {
                "origin_path": declaration["path"],
                "role": declaration["role"],
                "byte_count": len(raw),
                "raw_sha256": hashlib.sha256(raw).hexdigest(),
                "semantic_sha256": (
                    hashlib.sha256(raw[:-1]).hexdigest()
                    if declaration["role"] in {
                        "component_receipt", "fixed_pair_host_receipt",
                    } else None
                ),
            }

        def read_receipt(path, _label, _maximum):
            raw = (payload_raw if str(path).endswith("stdout.tsv")
                   else receipt_raw)
            return raw, hashlib.sha256(raw).hexdigest(), types.SimpleNamespace()

        with patch.object(controller, "_source5_job_path_declarations",
                           return_value=declarations), \
             patch.object(controller, "_source5_capture_file_declaration",
                          side_effect=capture), \
             patch.object(controller, "_private_directory",
                          side_effect=lambda value: Path(value)), \
             patch.object(controller, "read_stable", side_effect=read_receipt):
            handoff = controller._source5_create_transfer_offer(
                context, "confirmation", 0, job, job_record_pin,
                job_raw, None,
            )

        self.assertEqual(calls, ["request", "packet", "offer"])
        self.assertEqual([row["role"] for row in observed["entries"]], [
            "component_receipt", "normal_app_output",
            "fixed_pair_host_receipt",
        ])
        self.assertEqual(set(observed["receipts"]), {
            "/private/artifacts/owner/receipt.json",
            "/private/output/confirmation/fixed-host-receipts/000001-" +
            "a" * 64 + ".json",
        })
        self.assertEqual(observed["tree_inventories"], [])
        self.assertIsNone(observed["context"]["predecessor_ack_pin"])
        self.assertEqual(handoff["offer"]["acknowledgement_receiver"]["path"],
                         "/private/output/confirmation/000001.ack.tar")


class Source5ArchiveReadCancellationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.controller = load_source(
            "source5_archive_read_cancellation_test", CONTROLLER_PATH,
        )

    def test_cancelled_wait_does_not_publish_response_verified_control_event(self) -> None:
        controller = self.controller
        with tempfile.TemporaryDirectory(prefix="source5-archive-read-cancel-") as temporary:
            root = Path(temporary)
            read_directory = root / "readback"
            read_directory.mkdir(mode=0o700)
            control_directory = root / "control"
            control_directory.mkdir(mode=0o700)
            request_path = read_directory / "request.json"
            response_path = read_directory / "response.json"
            bundle_path = read_directory / "response.tar"
            stage_root = read_directory / "stage"
            control_ledger = control_directory / "read-control.jsonl"
            slots = {
                "source5_archive_read_control_ledger": str(control_ledger),
                "source5_archive_read_request_slot": str(request_path),
                "source5_archive_read_response_slot": str(response_path),
                "source5_archive_read_response_incoming": str(
                    read_directory / "response.json.incoming",
                ),
                "source5_archive_read_bundle": str(bundle_path),
                "source5_archive_read_bundle_incoming": str(
                    read_directory / "response.tar.incoming",
                ),
                "source5_archive_read_stage": str(stage_root),
            }
            job = {
                "host_id": "host-a", "phase": "confirmation",
                "ordinal": 1, "run_id": "original-confirmation-1",
            }
            object_row = {
                "owner_job_sha256": "a" * 64,
                "origin_path": "/private/source5/original-output.tsv",
                "raw_sha256": "b" * 64, "byte_count": 1,
            }
            schedule = [{
                "analysis_phase": "final_analysis",
                "owner_phase": "confirmation", "job_index": 0,
                "job": job, "job_sha256": "a" * 64,
                "request_ordinal": 0, "use": "final_replay",
                "caps": {
                    "bundle_bytes": 1024 * 1024,
                    "maximum_request_bytes": 16 * 1024 * 1024,
                    "maximum_response_bytes": 16 * 1024 * 1024,
                    "object_count": 1, "stage_bytes": 1,
                },
            }]
            context = types.SimpleNamespace(
                manifest={
                    "schema": controller.EXECUTION_SCHEMA_V4,
                    "campaign_id": "campaign-a",
                },
                host_id="host-a",
                source5_archive_read_schedule=schedule,
                source5_archive_read_slot_paths=slots,
                source5_archive_read_caps={
                    "control_ledger_bytes": 1024 * 1024,
                    "control_ledger_line_bytes": 64 * 1024,
                    "control_ledger_event_count": 2,
                },
                source5_archive_read_ledger_loaded=False,
            )
            closure = {
                "manifest": {"objects": [object_row]},
                "job_sha256": "a" * 64,
                "manifest_pin": {
                    "path": "/private/archive/object-manifest.json",
                    "raw_sha256": "c" * 64,
                    "semantic_sha256": "d" * 64,
                },
            }
            cancel_event = threading.Event()
            cancel_timer = threading.Timer(0.01, cancel_event.set)
            append = controller._source5_append_archive_read_control_event

            def append_then_cancel(*args, **kwargs):
                append(*args, **kwargs)
                if args[2] == "request_published":
                    cancel_timer.start()

            with patch.object(
                controller, "_source5_verify_persisted_archive_read_closure",
                return_value=closure,
            ), patch.object(
                controller, "_source5_append_archive_read_control_event",
                side_effect=append_then_cancel,
            ):
                try:
                    with self.assertRaises(controller.Source5CampaignError):
                        with controller.archived_job_read_view(
                            context, job, "final_analysis",
                            cancel_event=cancel_event,
                        ):
                            self.fail("an unpublished readback unexpectedly yielded")
                finally:
                    if cancel_timer.ident is not None:
                        cancel_timer.cancel()
                        cancel_timer.join()

            events = [
                json.loads(line)["record"]["action"]
                for line in control_ledger.read_text(encoding="ascii").splitlines()
            ]
            self.assertEqual(events, ["request_published"])
            self.assertEqual(context.source5_archive_read_event_count, 1)
            self.assertTrue(request_path.is_file())
            self.assertTrue(stage_root.is_dir())
            self.assertFalse(response_path.exists())
            self.assertFalse(bundle_path.exists())


class Source5NumericApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.campaign = load_source("source5_numeric_pilot_test", CAMPAIGN_PATH)
        cls.controller = load_source("source5_numeric_controller_test", CONTROLLER_PATH)

    def test_fixed_cleanup_sidecar_quota_covers_the_source_maximum_and_two_member_window(self) -> None:
        controller = self.controller
        context = types.SimpleNamespace(
            journal_width_cleanup_source_bytes=None,
            fixed_pair=types.SimpleNamespace(
                MAX_PROC_ENTRIES=262_144,
                TERM_GRACE_SECONDS=3.0,
                KILL_REAP_SECONDS=1.0,
            ),
        )
        maximum = controller.source5_cleanup_sidecar_source_byte_bound(context)
        self.assertEqual(maximum, 393_385_220)
        self.assertEqual(2 * maximum, 786_770_440)
        self.assertEqual(controller.MAX_SOURCE5_CLEANUP_ERROR_ENTRIES, 1348)
        self.assertEqual(controller.MAX_SOURCE5_CLEANUP_SIGNAL_SNAPSHOTS, 5)
        self.assertEqual(controller.MAX_SOURCE5_CLEANUP_ERROR_TEXT_BYTES, 8192)
        summary = controller._source5_fixed_cleanup_failure_summary(
            context, "sidecar",
        )
        self.assertEqual(summary["cleanup_status"], "not_started")

    def test_v4_analysis_recording_passes_completed_provider_and_legacy_omits_it(self) -> None:
        controller = self.controller
        provider = object()

        def run_record(schema: str):
            with tempfile.TemporaryDirectory(
                    prefix="source5-analysis-record-provider-") as temporary:
                artifact_root = Path(temporary) / "artifacts"
                artifact_root.mkdir(mode=0o700)
                job = {
                    "phase": "exploration", "host_id": "host-a",
                    "ordinal": 0, "run_id": "original-exploration-0",
                }
                calls = []

                def record_source5_analysis_locked(*args, **kwargs):
                    calls.append((args, kwargs))
                    return {"recorded": True}

                context = types.SimpleNamespace(
                    artifact_root=artifact_root,
                    manifest={"schema": schema, "campaign_id": "campaign-a"},
                    host_id="host-a", plan={"jobs": {"exploration": [job]}},
                    manifest_pin={
                        "path": "/private/execution/manifest.json",
                        "raw_sha256": "b" * 64,
                    },
                    chronology=types.SimpleNamespace(
                        record_source5_analysis_locked=
                            record_source5_analysis_locked,
                    ),
                )
                with patch.object(
                    controller, "_analysis_record",
                    return_value={"phase": "exploration"},
                ), patch.object(
                    controller, "write_new", return_value="c" * 64,
                ), patch.object(
                    controller, "source5_completed_archive_read_provider",
                    return_value=provider,
                ) as provider_factory:
                    result = controller._persist_analysis(
                        context, object(), "exploration", "exploration",
                        {"numeric_gates_passed": True}, True, True,
                    )
                return result, calls, provider_factory

        result_v4, calls_v4, factory_v4 = run_record(controller.EXECUTION_SCHEMA_V4)
        self.assertEqual(len(calls_v4), 1)
        self.assertEqual(calls_v4[0][1], {"captured_read_context": provider})
        factory_v4.assert_called_once()
        self.assertTrue(result_v4["chronology"]["recorded"])

        result_v3, calls_v3, factory_v3 = run_record(controller.EXECUTION_SCHEMA_V3)
        self.assertEqual(len(calls_v3), 1)
        self.assertEqual(calls_v3[0][1], {})
        factory_v3.assert_not_called()
        self.assertTrue(result_v3["chronology"]["recorded"])

    def test_journal_width_owner_pins_use_source_recomputed_union_of_both_profiles(self) -> None:
        controller = self.controller
        catalogue = load_source(
            "source5_width_owner_catalogue_fixture",
            ROOT / "scripts/application-source5-evidence-catalogue.py",
        )
        budget = load_source(
            "source5_width_owner_budget_fixture",
            ROOT / "scripts/application-source5-evidence-budget.py",
        )
        expected_catalogue_roles = {
            "fixed_pair", "pressure_pair", "source5_controller", "source5_soak",
            "soak_reader", "offline_dispatcher", "chronology",
            "evidence_transport",
        }
        expected_budget_roles = {
            "fixed_pair", "pressure_pair", "source5_controller", "source5_soak",
            "soak_reader", "feedback_composer", "feedback_reader",
            "pressure_reader", "evidence_transport",
        }
        source_paths = set(catalogue.OWNER_PATHS.values()) | {
            "scripts/application-feedback-composition.py",
            "scripts/application-feedback-readback.py",
            "scripts/application-pressure-readback.py",
        }
        source_files = []
        raw_by_path = {}
        for relative in sorted(source_paths):
            raw = (ROOT / relative).read_bytes()
            raw_by_path[relative] = raw
            source_files.append({
                "path": relative, "kind": "file", "mode": "100644",
                "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw),
            })
        symlink_target = "../fixture-target"
        symlink_raw = symlink_target.encode("utf-8")
        source_files.append({
            "path": "scripts/width-fixture-link", "kind": "symlink",
            "mode": "120000", "sha256": hashlib.sha256(symlink_raw).hexdigest(),
            "size": len(symlink_raw), "target": symlink_target,
        })
        source = {"source": {"files": source_files}}
        catalogue_pins = {
            role: {
                "path": path,
                "raw_sha256": hashlib.sha256(raw_by_path[path]).hexdigest(),
                "byte_count": len(raw_by_path[path]),
            }
            for role, path in catalogue.OWNER_PATHS.items()
        }
        context = types.SimpleNamespace(
            owner_evidence_contract={"owner_source_pins": catalogue_pins},
            modules={
                controller.EVIDENCE_CATALOGUE_SOURCE_PATH: catalogue,
                controller.EVIDENCE_BUDGET_SOURCE_PATH: budget,
            },
            source=source,
        )
        pins = controller._source5_journal_width_owner_pins(context)
        self.assertEqual(set(pins), expected_catalogue_roles | expected_budget_roles)
        self.assertEqual(len(pins), 11)
        for role in expected_catalogue_roles & expected_budget_roles:
            self.assertEqual(pins[role]["path"], catalogue_pins[role]["path"])
            self.assertEqual(pins[role]["raw_sha256"], catalogue_pins[role]["raw_sha256"])
            self.assertEqual(pins[role]["byte_count"], catalogue_pins[role]["byte_count"])
        self.assertEqual(set(pins) - expected_catalogue_roles,
                         expected_budget_roles - expected_catalogue_roles)
        malformed = dict(catalogue_pins)
        malformed["chronology"] = {**malformed["chronology"],
                                   "raw_sha256": "f" * 64}
        context.owner_evidence_contract = {"owner_source_pins": malformed}
        with self.assertRaises(controller.Source5CampaignError):
            controller._source5_journal_width_owner_pins(context)
        malformed = dict(catalogue_pins)
        campaign_path = catalogue_pins["source5_controller"]["path"]
        malformed["chronology"] = {
            **malformed["chronology"],
            "path": campaign_path,
            "raw_sha256": hashlib.sha256(
                raw_by_path[campaign_path],
            ).hexdigest(),
            "byte_count": len(raw_by_path[campaign_path]),
        }
        context.owner_evidence_contract = {"owner_source_pins": malformed}
        with self.assertRaises(controller.Source5CampaignError):
            controller._source5_journal_width_owner_pins(context)
        malformed = dict(catalogue_pins)
        malformed["fixed_pair"] = {**malformed["fixed_pair"],
                                   "raw_sha256": "f" * 64}
        context.owner_evidence_contract = {"owner_source_pins": malformed}
        with self.assertRaises(controller.Source5CampaignError):
            controller._source5_journal_width_owner_pins(context)

    def test_consistently_resealed_width_one_mutant_fails_pinned_preflight_projection(self) -> None:
        controller = self.controller
        kinds = (
            "source5_authorized", "source5_app_started",
            "source5_app_terminal", "source5_job_terminal",
        )
        counts = {
            "source5_authorized": 1, "source5_app_started": 2,
            "source5_app_terminal": 2, "source5_job_terminal": 1,
        }
        widths = {kind: 100 for kind in kinds}
        job = {
            "phase": "exploration", "job_index": 0, "ordinal": 1,
            "run_id": "original-run-1", "job_sha256": "a" * 64,
            "event_counts": counts,
            "maximum_event_bytes_by_kind": widths,
            "failed_event_counts": counts,
            "failed_event_bytes_by_kind": dict(widths),
            "success_job_bytes": 600, "failed_window_bytes": 600,
            "failed_event_count": 6, "failed_event_count_uplift": 0,
            "byte_uplift": 0,
        }
        winner = {
            "phase": "exploration", "job_index": 0, "ordinal": 1,
            "run_id": "original-run-1", "job_sha256": "a" * 64,
            "failed_event_count": 6, "failed_event_count_uplift": 0,
            "failed_window_bytes": 600, "success_job_bytes": 600,
            "byte_uplift": 0,
        }
        body = {
            "schema": "allocatbelt.application-source5-journal-width-contract.v1",
            "campaign_id": "campaign-a", "host_id": "host-a",
            "original_pins_sha256": "b" * 64,
            "plan_pin": {"path": "/private/plan.json",
                         "raw_sha256": "c" * 64,
                         "semantic_sha256": "d" * 64},
            "source_manifest_pin": {"path": "/private/source.json",
                                    "raw_sha256": "e" * 64,
                                    "semantic_sha256": "f" * 64},
            "owner_pins": {}, "job_rows": [job],
            "phase_totals": [{"phase": "exploration", "job_count": 1,
                              "event_count": 6,
                              "success_event_bytes": 600}],
            "fixed_event_widths": [{
                "event": "source5_prepared_capacity_registered",
                "phase": "registration", "count": 1,
                "maximum_line_bytes": 100,
            }],
            "total_event_count": 7, "total_event_bytes": 700,
            "failed_owner_window": winner,
        }
        contract = {
            **body,
            "contract_sha256": hashlib.sha256(
                controller.canonical_bytes(body),
            ).hexdigest(),
        }
        genuine_raw = controller.canonical_bytes(contract)
        genuine_pin = {
            "path": "/private/width-contract.json",
            "raw_sha256": hashlib.sha256(genuine_raw).hexdigest(),
            "semantic_sha256": contract["contract_sha256"],
        }
        genuine_projection = {
            "path": None,
            "raw_sha256": genuine_pin["raw_sha256"],
            "semantic_sha256": genuine_pin["semantic_sha256"],
            "contract": contract,
        }
        genuine_context = types.SimpleNamespace(
            journal_width_contract=contract,
            journal_width_contract_pin=genuine_pin,
        )
        controller._require_source5_journal_width_projection(
            genuine_context, genuine_projection,
        )

        mutant = json.loads(genuine_raw)
        for kind in kinds:
            mutant["job_rows"][0]["maximum_event_bytes_by_kind"][kind] = 1
            mutant["job_rows"][0]["failed_event_bytes_by_kind"][kind] = 1
        mutant["job_rows"][0]["success_job_bytes"] = 6
        mutant["job_rows"][0]["failed_window_bytes"] = 6
        mutant["phase_totals"][0]["success_event_bytes"] = 6
        mutant["fixed_event_widths"][0]["maximum_line_bytes"] = 1
        mutant["total_event_bytes"] = 7
        mutant["failed_owner_window"]["success_job_bytes"] = 6
        mutant["failed_owner_window"]["failed_window_bytes"] = 6
        mutant_body = {key: value for key, value in mutant.items()
                       if key != "contract_sha256"}
        mutant["contract_sha256"] = hashlib.sha256(
            controller.canonical_bytes(mutant_body),
        ).hexdigest()
        mutant_raw = controller.canonical_bytes(mutant)
        mutant_context = types.SimpleNamespace(
            journal_width_contract=mutant,
            journal_width_contract_pin={
                "path": genuine_pin["path"],
                "raw_sha256": hashlib.sha256(mutant_raw).hexdigest(),
                "semantic_sha256": mutant["contract_sha256"],
            },
        )
        with self.assertRaisesRegex(
                controller.Source5CampaignError,
                "deterministic source-side preflight recomputation"):
            controller._require_source5_journal_width_projection(
                mutant_context, genuine_projection,
            )

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

    def test_capacity_receipt_rows_follow_original_overlay_member_order(self) -> None:
        controller = self.controller
        for executors in (("bounded", "tokio"), ("tokio", "bounded")):
            overlay = {
                "members": [{
                    "descriptor": {
                        "pair": executor, "executor": executor,
                        "allocator": "allocatbelt",
                    },
                } for executor in executors],
            }
            receipt = {"process_rows": [
                {"pair": executor, "executor": executor,
                 "allocator": "allocatbelt", "completed_on_time": "10"}
                for executor in executors
            ]}
            self.assertEqual(
                controller._source5_capacity_process_rows_from_overlay(
                    overlay, receipt,
                ),
                receipt["process_rows"],
            )
            for malformed in (
                {"process_rows": list(reversed(receipt["process_rows"]))},
                {"process_rows": [receipt["process_rows"][0]] * 2},
            ):
                with self.subTest(executors=executors, malformed=malformed), \
                        self.assertRaises(controller.Source5CampaignError):
                    controller._source5_capacity_process_rows_from_overlay(
                        overlay, malformed,
                    )

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

    def test_exploration_and_aa_replays_preserve_immutable_analysis_fields(self) -> None:
        controller = self.controller
        fixtures = {
            "exploration": {
                "schema": "allocatbelt.application-source5-exploration-analysis.v1",
                "scope": "final_frozen",
                "pilot": {"path": "/campaign/exploration/capacity-pilot.json",
                          "raw_sha256": "a" * 64},
                "rate_candidate": {
                    "path": "/campaign/exploration/capacity-rate-candidate.json",
                    "raw_sha256": "b" * 64,
                },
                "rate_status": "verified_against_final_frozen_spec",
            },
            "aa": {
                "schema": "allocatbelt.application-aa-analysis.v1",
                "host_id": "host-a",
                "controls": [{
                    "control_id": "control-a", "pair_count": 6,
                    "comparisons": {
                        "capacity_per_second": {
                            "ratio": 1.0, "lower": 0.9, "upper": 1.1,
                            "interval_contains_one": True,
                        },
                    },
                    "passed": True,
                }],
                "passed": True,
            },
            "soak": {
                "schema": "allocatbelt.application-source5-soak-analysis.v1",
                "component": {
                    "path": "/campaign/soak/component.json",
                    "raw_sha256": "d" * 64,
                },
                "readback": {"passed": True, "readback_sha256": "e" * 64},
                "record_sha256": "f" * 64,
            },
            "final_analysis": {
                "phase_results": [{
                    "phase": phase, "numeric_gates_passed": True,
                    "analysis_sha256": chr(ord("a") + index) * 64,
                    "event_head": chr(ord("f") - index) * 64,
                    "records_sha256": chr(ord("1") + index) * 64,
                } for index, phase in enumerate((
                    "exploration", "aa", "fixed_analysis",
                    "pressure_analysis", "soak",
                ))],
                "numeric_gates_passed": True,
                "failed_phases": [],
                "campaign_qualification_eligible": False,
            },
        }
        for phase, baseline in fixtures.items():
            self.assertTrue(controller._source5_analysis_matches_replay(
                phase, baseline, json.loads(json.dumps(baseline)),
            ), phase)
            changed = json.loads(json.dumps(baseline))
            if phase == "exploration":
                changed["rate_candidate"]["raw_sha256"] = "c" * 64
            elif phase == "aa":
                changed["controls"][0]["comparisons"][
                    "capacity_per_second"]["lower"] = 0.8
            elif phase == "soak":
                changed["component"]["raw_sha256"] = "c" * 64
            else:
                changed["phase_results"][3]["event_head"] = "0" * 64
            self.assertFalse(controller._source5_analysis_matches_replay(
                phase, baseline, changed,
            ), phase)

    def test_final_analysis_refresh_replays_all_original_phases_without_publication(self) -> None:
        tree = ast.parse(CONTROLLER_PATH.read_bytes(), filename=str(CONTROLLER_PATH))
        node = function(tree, "_source5_replay_final_analysis_value")
        called = {
            item.func.id if isinstance(item.func, ast.Name) else
            item.func.attr if isinstance(item.func, ast.Attribute) else None
            for item in ast.walk(node) if isinstance(item, ast.Call)
        }
        self.assertIn("held_replay", called)
        self.assertIn("_source5_replay_exploration_analysis_value", called)
        self.assertIn("validate_aa_records", called)
        self.assertIn("_source5_numeric_for_pairs", called)
        self.assertIn("_source5_phase_records_replay_sha256", called)
        self.assertIn("_source5_final_decision_value", called)
        self.assertNotIn("write_new", called)
        self.assertNotIn("_persist_analysis", called)
        self.assertNotIn("record_source5_analysis_locked", called)

    def test_final_hook_gets_phase_event_pins_from_chronology_not_provider(self) -> None:
        controller = self.controller
        host_id = "host-final-authority"
        campaign_id = "campaign-final-authority"
        output_root = Path("/private/final-authority-output")
        artifact_root = Path("/private/final-authority-artifacts")
        source_root = Path("/private/final-authority-source")
        manifest_path = "/private/final-authority-input/manifest.json"
        manifest_sha = "a" * 64
        host_budget = {
            "schema": "allocatbelt.application-source5-host-evidence-budget.v2",
            "campaign_id": campaign_id, "host_id": host_id,
            "budget_sha256": "b" * 64,
        }
        host_budget_raw = controller.canonical_bytes(host_budget)
        host_budget_sha = hashlib.sha256(host_budget_raw).hexdigest()
        host_budget_pin = {
            "path": "/private/final-authority-output/host-budget.json",
            "raw_sha256": host_budget_sha,
            "semantic_sha256": host_budget["budget_sha256"],
        }
        analysis_events = [{
            "phase": phase,
            "analysis": {
                "path": str(artifact_root / campaign_id / "source5" /
                            host_id / "phase-analysis" / f"{phase}.json"),
                "raw_sha256": ("12345"[index]) * 64,
            },
            "analysis_sha256": ("12345"[index]) * 64,
            "event_head": ("67890"[index]) * 64,
        } for index, phase in enumerate((
            "exploration", "aa", "fixed_analysis", "pressure_analysis", "soak",
        ))]
        soak_job = {
            "phase": "soak", "host_id": host_id,
            "ordinal": 4, "run_id": "original-soak",
        }
        jobs = {phase: [] for phase in (
            "exploration", "aa", "confirmation", "pressure", "soak",
        )}
        jobs["soak"] = [soak_job]
        prior_analysis = {
            "schema": "allocatbelt.application-source5-final-host-numeric-decision.v1",
            "campaign_id": campaign_id, "host_id": host_id,
            "original_spec": {}, "original_plan": {},
            "prepared_input_completion": {}, "source_manifest": {},
            "prepared_host_binding_sha256": "e" * 64,
            "phase_results": [], "numeric_gates_passed": True,
            "failed_phases": [], "cohort_status": "not_verified",
            "cohort_blockers": [], "campaign_qualification_eligible": False,
        }
        phase_analysis_record_body = {
            "schema": controller.ANALYSIS_SCHEMA,
            "campaign_id": campaign_id, "host_id": host_id,
            "phase": "final_analysis", "job_count": 1,
            "job_set_sha256": controller.sha256(
                controller.canonical_bytes([soak_job["run_id"]]),
            ),
            "job_evidence_complete": True,
            "numeric_gates_passed": True, "phase_gate_passed": True,
            "campaign_qualification_eligible": False,
            "analysis": prior_analysis,
        }
        phase_analysis_record = {
            **phase_analysis_record_body,
            "analysis_sha256": controller.sha256(
                controller.canonical_bytes(phase_analysis_record_body),
            ),
        }
        phase_analysis_raw = controller.canonical_bytes(phase_analysis_record)
        phase_analysis_sha = hashlib.sha256(phase_analysis_raw).hexdigest()
        phase_analysis_path = (
            artifact_root / campaign_id / "source5" / host_id /
            "phase-analysis" / "final_analysis.json"
        )
        chronology_relative = "scripts/application-campaign-chronology.py"
        chronology_path = source_root / chronology_relative
        manifest = {
            "schema": controller.EXECUTION_SCHEMA_V4,
            "campaign_id": campaign_id,
            "modules": {host_id: {
                chronology_relative: {
                    "path": chronology_relative,
                    "sha256": "f" * 64,
                },
            }},
        }
        prepared = {
            "source5_execution_manifest_pin": {
                "path": manifest_path, "raw_sha256": manifest_sha,
            },
            "host_id": host_id, "campaign_id": campaign_id,
            "source5_host_evidence_budget_pin": host_budget_pin,
        }
        budget_module = types.SimpleNamespace(
            validate_host_evidence_budget_v2=lambda value, **_kwargs: value,
        )
        provider = types.SimpleNamespace(
            open_view=lambda *_args, **_kwargs: None,
        )
        helper_events = []
        chronology_module = types.SimpleNamespace(
            __file__=str(chronology_path),
            replay_source5_phase_records_captured_held=lambda *_args, **_kwargs: None,
            source5_phase_analysis_events_held=lambda *args: (
                helper_events.append(args) or analysis_events
            ),
        )
        context = types.SimpleNamespace(
            manifest=manifest,
            manifest_pin={"path": manifest_path, "raw_sha256": manifest_sha},
            host_id=host_id, campaign_id=campaign_id,
            output_root=output_root, artifact_root=artifact_root,
            source_root=source_root, scope="final_frozen",
            journal_width_contract={"contract_sha256": "9" * 64},
            plan={"jobs": jobs}, spec={"protocol": {}},
            campaign=types.SimpleNamespace(), chronology=chronology_module,
            modules={controller.EVIDENCE_BUDGET_SOURCE_PATH: budget_module},
        )
        lock = types.SimpleNamespace(
            campaign_id=campaign_id, host_id=host_id,
            output_root=output_root,
        )
        expected_pin = {
            "path": str(phase_analysis_path),
            "raw_sha256": phase_analysis_sha,
        }
        fresh_value = {"numeric_gates_passed": True, "fresh": True}
        final_helper_calls = []

        def final_replay_helper(*args):
            final_helper_calls.append(args)
            return fresh_value

        def read_json_stub(path, _label, _maximum, expected_sha256=None):
            if str(path) == host_budget_pin["path"]:
                self.assertEqual(expected_sha256, host_budget_sha)
                return host_budget, host_budget_raw, host_budget_sha
            self.assertEqual(str(path), str(phase_analysis_path))
            self.assertEqual(expected_sha256, phase_analysis_sha)
            return phase_analysis_record, phase_analysis_raw, phase_analysis_sha

        with patch.object(
            controller, "load_context", return_value=context,
        ), patch.object(
            controller, "read_stable",
            return_value=(b"selected chronology module", "f" * 64,
                          types.SimpleNamespace()),
        ), patch.object(
            controller, "read_json", side_effect=read_json_stub,
        ), patch.object(
            controller, "_source5_job_catalogue_pins", return_value={},
        ), patch.object(
            controller, "_source5_restore_archive_readback_context",
        ), patch.object(
            controller, "_source5_replay_final_analysis_value",
            side_effect=final_replay_helper,
        ), patch.object(
            controller, "_analysis_record",
            return_value={"phase": "final_analysis", "fresh": fresh_value},
        ):
            result = controller.replay_source5_phase_analysis_captured_locked(
                types.SimpleNamespace(prepared=prepared, manifest=manifest,
                                      captured_read_provider=provider),
                lock, "final_analysis", chronology_module=chronology_module,
                expected_analysis_pin=expected_pin,
            )

        self.assertEqual(result, {"phase": "final_analysis", "fresh": fresh_value})
        self.assertEqual(helper_events, [(
            lock, {"path": manifest_path, "sha256": manifest_sha},
        )])
        self.assertEqual(len(final_helper_calls), 1)
        self.assertIs(final_helper_calls[0][4], provider)
        self.assertIs(final_helper_calls[0][5],
                      chronology_module.replay_source5_phase_records_captured_held)
        self.assertIs(final_helper_calls[0][6], analysis_events)

    def test_final_analysis_replays_all_owners_before_traces_and_keeps_soak_separate(self) -> None:
        controller = self.controller
        host_id = "host-final"
        jobs = {
            "exploration": [{
                "phase": "exploration", "run_id": "original-exploration",
                "host_id": host_id, "ordinal": 0, "mode": "closed_loop",
            }],
            "aa": [{
                "phase": "aa", "run_id": "original-aa",
                "host_id": host_id, "ordinal": 1, "mode": "closed_loop",
            }],
            "confirmation": [{
                "phase": "confirmation", "run_id": "original-fixed",
                "host_id": host_id, "ordinal": 2, "mode": "open_loop",
            }],
            "pressure": [{
                "phase": "pressure", "run_id": "original-pressure",
                "host_id": host_id, "ordinal": 3, "mode": "open_loop",
            }],
            "soak": [{
                "phase": "soak", "run_id": "original-soak",
                "host_id": host_id, "ordinal": 4, "mode": "closed_loop",
            }],
        }
        owner_phase = {
            "exploration": "exploration", "aa": "aa",
            "fixed_analysis": "confirmation",
            "pressure_analysis": "pressure", "soak": "soak",
        }
        analysis_values = {
            "exploration": {"kind": "exploration"},
            "aa": {"kind": "aa", "passed": True},
            "fixed_analysis": {"kind": "fixed", "numeric_gates_passed": True},
            "pressure_analysis": {"kind": "pressure", "numeric_gates_passed": True},
            "soak": {
                "schema": "allocatbelt.application-source5-soak-analysis.v1",
                "component": {
                    "path": "/private/soak/component.json",
                    "raw_sha256": "d" * 64,
                },
                "readback": {"passed": True},
                "record_sha256": "e" * 64,
            },
        }
        analysis_sha = {
            phase: chr(ord("a") + index) * 64
            for index, phase in enumerate(owner_phase)
        }
        analysis_raw_sha = {
            phase: ("1234567890"[index]) * 64
            for index, phase in enumerate(owner_phase)
        }
        record_sha = {
            phase: ("67890"[index]) * 64
            for index, phase in enumerate(owner_phase)
        }
        analysis_values["soak"]["record_sha256"] = record_sha["soak"]
        event_head = {
            phase: chr(ord("f") - index) * 64
            for index, phase in enumerate(owner_phase)
        }
        prior_phase_records = {
            phase: {
                "analysis": analysis_values[phase],
                "analysis_sha256": analysis_sha[phase],
                "_artifact_raw_sha256": analysis_raw_sha[phase],
                "numeric_gates_passed": True,
                "phase_gate_passed": True,
            }
            for phase in owner_phase
        }
        prior_final = {
            "schema": "allocatbelt.application-source5-final-host-numeric-decision.v1",
            "campaign_id": "campaign-final", "host_id": host_id,
            "original_spec": {}, "original_plan": {},
            "prepared_input_completion": {}, "source_manifest": {},
            "prepared_host_binding_sha256": "a" * 64,
            "phase_results": [{
                "phase": phase, "numeric_gates_passed": True,
                "analysis_sha256": analysis_raw_sha[phase],
                "event_head": event_head[phase],
                "records_sha256": record_sha[phase],
            } for phase in owner_phase],
            "numeric_gates_passed": True, "failed_phases": [],
            "cohort_status": "not_verified", "cohort_blockers": [],
            "campaign_qualification_eligible": False,
        }
        artifact_root = Path("/campaign-artifacts")
        phase_analysis_events = [{
            "phase": phase,
            "analysis": {
                "path": str(artifact_root / "campaign-final" / "source5" /
                            host_id / "phase-analysis" / f"{phase}.json"),
                "raw_sha256": analysis_raw_sha[phase],
            },
            "analysis_sha256": analysis_raw_sha[phase],
            "event_head": event_head[phase],
        } for phase in owner_phase]
        records = {}
        for phase, phase_jobs in jobs.items():
            job = phase_jobs[0]
            analysis_phase = {
                "confirmation": "fixed_analysis",
                "pressure": "pressure_analysis",
            }.get(phase, phase)
            record = {
                "job": job, "state": "valid_soak" if phase == "soak"
                else "valid_pair", "qualification_eligible": False,
                "record_sha256": record_sha[analysis_phase],
                "evidence": {"kind": "source5_timed_soak" if phase == "soak"
                             else "source5_fixed_pair"},
            }
            if phase == "soak":
                record["evidence"]["soak_component"] = {
                    "path": "/private/soak/component.json",
                    "raw_sha256": "d" * 64,
                }
                record["process_metrics"] = [{"passed": True}]
            records[phase] = [record]

        schedule_ordinals = {
            ("exploration", "original-exploration", "final_replay"): 0,
            ("aa", "original-aa", "final_replay"): 1,
            ("confirmation", "original-fixed", "final_replay"): 2,
            ("pressure", "original-pressure", "final_replay"): 3,
            ("soak", "original-soak", "final_replay"): 4,
            ("confirmation", "original-fixed", "final_analyzer_trace"): 5,
            ("pressure", "original-pressure", "final_analyzer_trace"): 6,
        }
        view_calls = []
        events = []
        active_views = 0
        maximum_active_views = 0

        class RecordingProvider:
            @contextmanager
            def open_view(_self, job, purpose, *, use):
                nonlocal active_views, maximum_active_views
                self.assertEqual(purpose, "final_analysis")
                key = (job["phase"], job["run_id"], use)
                self.assertIn(key, schedule_ordinals)
                active_views += 1
                maximum_active_views = max(maximum_active_views, active_views)
                view_calls.append((*key, schedule_ordinals[key]))
                try:
                    yield {"request_ordinal": schedule_ordinals[key]}
                finally:
                    active_views -= 1

        provider = RecordingProvider()
        campaign = types.SimpleNamespace()

        def validate_phase_ledger(_records, _jobs, phase, _host):
            events.append(("pair-ledger", phase))

        def validate_aa_records(*_args):
            events.append(("analysis", "aa"))
            return analysis_values["aa"]

        campaign.validate_phase_ledger = validate_phase_ledger
        campaign.validate_aa_records = validate_aa_records
        context = types.SimpleNamespace(
            manifest={"campaign_id": "campaign-final"}, host_id=host_id,
            artifact_root=artifact_root,
            plan={"jobs": jobs},
            spec={"protocol": {"bootstrap_draws": 10,
                               "bootstrap_seed": 77}},
            campaign=campaign,
        )
        manifest_pin = {
            "path": "/private/execution/manifest.json",
            "raw_sha256": "b" * 64,
        }

        def held_replay(_lock, pin, phase, *, captured_read_context,
                        analysis_phase):
            self.assertEqual(pin, {
                "path": manifest_pin["path"],
                "sha256": manifest_pin["raw_sha256"],
            })
            self.assertIs(captured_read_context, provider)
            self.assertEqual(analysis_phase, "final_analysis")
            events.append(("owner", phase))
            record = records[phase][0]
            with provider.open_view(
                record["job"], "final_analysis", use="final_replay",
            ):
                pass
            return records[phase]

        def exploration_projection(_context, phase_records, previous,
                                   captured_provider, purpose):
            events.append(("analysis", "exploration"))
            self.assertEqual(phase_records, records["exploration"])
            self.assertEqual(previous, analysis_values["exploration"])
            self.assertIs(captured_provider, provider)
            self.assertEqual(purpose, "final_analysis")
            # The capacity projection reopens the already completed owner row.
            with provider.open_view(
                jobs["exploration"][0], purpose, use="final_replay",
            ):
                pass
            return analysis_values["exploration"], True

        def numeric_projection(_context, phase, phase_records, *,
                               archive_purpose, captured_read_provider):
            owner = "confirmation" if phase == "fixed_analysis" else "pressure"
            self.assertEqual(phase_records, records[owner])
            self.assertEqual(archive_purpose, "final_analysis")
            self.assertIs(captured_read_provider, provider)
            for job in jobs[owner]:
                with provider.open_view(
                    job, archive_purpose, use="final_analyzer_trace",
                ):
                    pass
            events.append(("analysis", phase))
            return analysis_values[phase]

        def build_final(_context, phase_results):
            self.assertEqual(phase_results, prior_final["phase_results"])
            events.append(("final-decision",))
            return prior_final

        replay_record_digests = {
            owner_phase[phase]: record_sha[phase] for phase in owner_phase
        }
        with patch.object(
            controller, "_source5_read_original_phase_analysis",
            side_effect=lambda _context, phase: prior_phase_records[phase],
        ), patch.object(
            controller, "_source5_phase_records_replay_sha256",
            side_effect=lambda _context, phase, _records:
                replay_record_digests[phase],
        ), patch.object(
            controller, "_source5_replay_exploration_analysis_value",
            side_effect=exploration_projection,
        ), patch.object(
            controller, "_source5_numeric_for_pairs",
            side_effect=numeric_projection,
        ), patch.object(
            controller, "_source5_analysis_matches_replay",
            return_value=True,
        ), patch.object(
            controller, "_source5_final_decision_value",
            side_effect=build_final,
        ):
            result = controller._source5_replay_final_analysis_value(
                context, object(), manifest_pin, prior_final, provider,
                held_replay, phase_analysis_events,
            )

        self.assertEqual(result, prior_final)
        owner_events = [event[1] for event in events if event[0] == "owner"]
        self.assertEqual(owner_events, [
            "exploration", "aa", "confirmation", "pressure", "soak",
        ])
        first_trace = next(
            index for index, call in enumerate(view_calls)
            if call[2] == "final_analyzer_trace"
        )
        self.assertTrue(all(call[2] == "final_replay"
                            for call in view_calls[:first_trace]))
        self.assertEqual(
            [call[2] for call in view_calls[first_trace:]],
            ["final_analyzer_trace", "final_analyzer_trace"],
        )
        self.assertEqual(
            [call[3] for call in view_calls],
            [0, 1, 2, 3, 4, 0, 5, 6],
        )
        self.assertEqual(maximum_active_views, 1)
        self.assertEqual(active_views, 0)
        ledger_phases = [event[1] for event in events
                         if event[0] == "pair-ledger"]
        self.assertNotIn("soak", ledger_phases)
        self.assertCountEqual(ledger_phases, [
            "exploration", "aa", "confirmation", "pressure",
        ])

    def test_final_replay_rejects_semantic_digest_or_event_head_substitution(self) -> None:
        controller = self.controller
        host_id = "host-final-mutant"
        campaign_id = "campaign-final-mutant"
        artifact_root = Path("/campaign-mutant-artifacts")
        phases = (
            "exploration", "aa", "fixed_analysis", "pressure_analysis", "soak",
        )
        raw_sha = {phase: str(index + 1) * 64
                   for index, phase in enumerate(phases)}
        event_head = {phase: chr(ord("a") + index) * 64
                      for index, phase in enumerate(phases)}
        phase_events = [{
            "phase": phase,
            "analysis": {
                "path": str(artifact_root / campaign_id / "source5" /
                            host_id / "phase-analysis" / f"{phase}.json"),
                "raw_sha256": raw_sha[phase],
            },
            "analysis_sha256": raw_sha[phase],
            "event_head": event_head[phase],
        } for phase in phases]
        prior_analysis = {
            "schema": "allocatbelt.application-source5-final-host-numeric-decision.v1",
            "campaign_id": campaign_id, "host_id": host_id,
            "original_spec": {}, "original_plan": {},
            "prepared_input_completion": {}, "source_manifest": {},
            "prepared_host_binding_sha256": "f" * 64,
            "phase_results": [{
                "phase": phase, "numeric_gates_passed": True,
                "analysis_sha256": raw_sha[phase],
                "event_head": event_head[phase],
                "records_sha256": "e" * 64,
            } for phase in phases],
            "numeric_gates_passed": True, "failed_phases": [],
            "cohort_status": "not_verified", "cohort_blockers": [],
            "campaign_qualification_eligible": False,
        }
        context = types.SimpleNamespace(
            artifact_root=artifact_root,
            manifest={"campaign_id": campaign_id}, host_id=host_id,
        )

        def forbidden_owner_replay(*_args, **_kwargs):
            self.fail("invalid phase-event metadata reached owner replay")

        semantic_substitute = [dict(row) for row in phase_events]
        semantic_substitute[0] = {
            **semantic_substitute[0], "analysis_sha256": "a" * 64,
        }
        head_substitute = [dict(row) for row in phase_events]
        head_substitute[0] = {
            **head_substitute[0], "event_head": "0" * 64,
        }
        for mutant in (semantic_substitute, head_substitute):
            with self.subTest(mutant=mutant[0]):
                with self.assertRaises(controller.Source5CampaignError):
                    controller._source5_replay_final_analysis_value(
                        context, object(), {"path": "/private/manifest",
                                           "raw_sha256": "b" * 64},
                        prior_analysis, object(), forbidden_owner_replay,
                        mutant,
                    )

    def test_rust_pipe_replay_normalization_keeps_input_pins_and_checks_process_proof(self) -> None:
        controller = self.controller
        base = {
            "bootstrap": {
                "input_sha256": "a" * 64,
                "input_bytes": 4096,
                "analyzer_binary_sha256": "e" * 64,
                "output_sha256": "b" * 64,
                "resident_peak_bytes": 1024,
                "analyzer_wall_seconds": 1.25,
                "input_transport": {
                    "schema": "allocatbelt.application-rust-analyzer-input-transport.v2",
                    "kind": "owned_stdin_pipe",
                    "input_sha256": "a" * 64,
                    "input_bytes": 4096,
                    "decoder_consumed_bytes": 4096,
                    "launch_transition": {
                        "schema": "allocatbelt.application-rust-analyzer-launch-transition.v1",
                        "kind": "pinned_binary_fd_gate_exec",
                        "status": "exec_confirmed_close_on_exec_pipe",
                        "launcher_sha256": "c" * 64,
                        "binary_sha256": "e" * 64,
                        "executable_identity": "elf_proc_inode_matched",
                    },
                    "process": {
                        "parent_pid": 100, "child_pid": 101,
                        "start_ticks": 200,
                        "pipe": {
                            "file_type": "fifo", "parent_fd": 3,
                            "child_fd": 0, "device": 12,
                            "inode": 34, "mode": 0o600,
                        },
                    },
                },
            },
            "numeric_gates_passed": False,
        }
        changed_process = json.loads(json.dumps(base))
        process = changed_process["bootstrap"]["input_transport"]["process"]
        process["parent_pid"] = 300
        process["child_pid"] = 301
        process["start_ticks"] = 400
        process["pipe"]["inode"] = 56
        self.assertTrue(controller._source5_analysis_matches_replay(
            "fixed_analysis", base, changed_process,
        ))

        changed_device = json.loads(json.dumps(base))
        changed_device["bootstrap"]["input_transport"]["process"]["pipe"]["device"] = 13
        self.assertFalse(controller._source5_analysis_matches_replay(
            "fixed_analysis", base, changed_device,
        ))

        changed_bytes = json.loads(json.dumps(base))
        changed_bytes["bootstrap"]["input_bytes"] = 4097
        changed_bytes["bootstrap"]["input_transport"]["input_bytes"] = 4097
        changed_bytes["bootstrap"]["input_transport"]["decoder_consumed_bytes"] = 4097
        self.assertFalse(controller._source5_analysis_matches_replay(
            "fixed_analysis", base, changed_bytes,
        ))

        changed_hash = json.loads(json.dumps(base))
        changed_hash["bootstrap"]["input_sha256"] = "c" * 64
        changed_hash["bootstrap"]["input_transport"]["input_sha256"] = "c" * 64
        self.assertFalse(controller._source5_analysis_matches_replay(
            "fixed_analysis", base, changed_hash,
        ))

        changed_launcher = json.loads(json.dumps(base))
        changed_launcher["bootstrap"]["input_transport"][
            "launch_transition"]["launcher_sha256"] = "f" * 64
        self.assertFalse(controller._source5_analysis_matches_replay(
            "fixed_analysis", base, changed_launcher,
        ))

        changed_launch_kind = json.loads(json.dumps(base))
        changed_launch_kind["bootstrap"]["input_transport"][
            "launch_transition"]["kind"] = "unguarded_exec"
        with self.assertRaises(controller.Source5CampaignError):
            controller._source5_analysis_matches_replay(
                "fixed_analysis", base, changed_launch_kind,
            )

        changed_launch_binary = json.loads(json.dumps(base))
        changed_launch_binary["bootstrap"]["input_transport"][
            "launch_transition"]["binary_sha256"] = "f" * 64
        with self.assertRaises(controller.Source5CampaignError):
            controller._source5_analysis_matches_replay(
                "fixed_analysis", base, changed_launch_binary,
            )

        changed_executable_fact = json.loads(json.dumps(base))
        changed_executable_fact["bootstrap"]["input_transport"][
            "launch_transition"]["executable_identity"] = "unverified"
        with self.assertRaises(controller.Source5CampaignError):
            controller._source5_analysis_matches_replay(
                "fixed_analysis", base, changed_executable_fact,
            )

        changed_kind = json.loads(json.dumps(base))
        changed_kind["bootstrap"]["input_transport"]["kind"] = "regular_file"
        with self.assertRaises(controller.Source5CampaignError):
            controller._source5_analysis_matches_replay(
                "fixed_analysis", base, changed_kind,
            )

        broken_process = json.loads(json.dumps(base))
        broken_process["bootstrap"]["input_transport"]["process"]["child_pid"] = 0
        with self.assertRaises(controller.Source5CampaignError):
            controller._source5_analysis_matches_replay(
                "fixed_analysis", base, broken_process,
            )

    def test_legacy_rust_pipe_transport_v1_remains_exact_and_replayable(self) -> None:
        controller = self.controller
        baseline = {
            "bootstrap": {
                "input_sha256": "a" * 64,
                "input_bytes": 512,
                "input_transport": {
                    "schema": "allocatbelt.application-rust-analyzer-input-transport.v1",
                    "kind": "owned_stdin_pipe",
                    "input_sha256": "a" * 64,
                    "input_bytes": 512,
                    "decoder_consumed_bytes": 512,
                    "process": {
                        "parent_pid": 100, "child_pid": 101,
                        "start_ticks": 200,
                        "pipe": {
                            "file_type": "fifo", "parent_fd": 3,
                            "child_fd": 0, "device": 12,
                            "inode": 34, "mode": 0o600,
                        },
                    },
                },
            },
        }
        replay = json.loads(json.dumps(baseline))
        process = replay["bootstrap"]["input_transport"]["process"]
        process["parent_pid"] = 300
        process["child_pid"] = 301
        process["start_ticks"] = 400
        process["pipe"]["inode"] = 56
        self.assertTrue(controller._source5_analysis_matches_replay(
            "fixed_analysis", baseline, replay,
        ))

        unknown = json.loads(json.dumps(baseline))
        unknown["bootstrap"]["input_transport"]["launch_transition"] = {}
        with self.assertRaises(controller.Source5CampaignError):
            controller._source5_analysis_matches_replay(
                "fixed_analysis", baseline, unknown,
            )

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


class Source5FixedHostReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.controller = load_source(
            "source5_fixed_host_receipt_test", CONTROLLER_PATH,
        )

    def test_v4_host_receipt_uses_exact_original_path_and_is_bound_before_record(self) -> None:
        controller = self.controller
        with tempfile.TemporaryDirectory(prefix="source5-fixed-host-receipt-") as temp:
            output_root = Path(temp) / "output"
            output_root.mkdir(mode=0o700)
            calls = []

            class FixedPair:
                @staticmethod
                def verify_fixed_pair_overlay_with_host_receipt(
                    overlay_pin, receipt_pin, host_receipt_path,
                ):
                    calls.append((overlay_pin, receipt_pin, host_receipt_path))
                    raw = b"receipt\n"
                    host_receipt_path.write_bytes(raw)
                    return {
                        "path": str(host_receipt_path),
                        "raw_sha256": controller.sha256(raw),
                        "host_verification_sha256": "b" * 64,
                        "status": "valid_pair",
                        "overlay_sha256": "c" * 64,
                    }

            context = types.SimpleNamespace(
                manifest={
                    "schema": controller.EXECUTION_SCHEMA_V4,
                    "campaign_id": "campaign-original",
                },
                host_id="host-original", output_root=output_root,
                fixed_pair=FixedPair,
            )
            job = {
                "phase": "confirmation", "ordinal": 12,
                "run_id": "original-confirmation-12",
            }
            overlay = {"path": "/private/overlay.json",
                       "raw_sha256": "d" * 64}
            receipt = {"path": "/private/receipt.json",
                       "raw_sha256": "e" * 64}
            pin = controller._source5_fixed_host_receipt_pin(
                context, job, overlay, receipt, "c" * 64, "valid_pair",
            )
            job_sha = controller.sha256(controller.canonical_bytes(job))
            expected_path = (output_root / "campaign-original" / "source5" /
                             "host-original" / "confirmation" /
                             "fixed-host-receipts" /
                             f"000012-{job_sha}.json")
            self.assertEqual(calls, [(
                controller.api_pin(overlay), controller.api_pin(receipt),
                expected_path,
            )])
            self.assertEqual(pin, {
                "path": str(expected_path),
                "raw_sha256": controller.sha256(b"receipt\n"),
                "host_verification_sha256": "b" * 64,
            })
            self.assertTrue(expected_path.is_file())

    def test_legacy_fixed_receipt_path_does_not_add_v4_sidecar(self) -> None:
        context = types.SimpleNamespace(
            manifest={"schema": "allocatbelt.application-source5-campaign-execution.v3"},
            fixed_pair=types.SimpleNamespace(),
        )
        self.assertIsNone(self.controller._source5_fixed_host_receipt_pin(
            context, {"phase": "confirmation", "ordinal": 1,
                   "run_id": "original-1"},
            {"path": "/private/overlay", "raw_sha256": "a" * 64},
            {"path": "/private/receipt", "raw_sha256": "b" * 64},
            "c" * 64, "valid_pair",
        ))


class Source5ArchiveReadApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.controller = load_source(
            "source5_archive_read_api_test", CONTROLLER_PATH,
        )

    def _fixture(self, root: Path, *, members: list[tuple[str, bytes, bytes]] | None = None):
        controller = self.controller
        campaign_id, host_id = "campaign-read-test", "host-read-test"
        job_sha = "a" * 64
        payload = b"authenticated archived evidence\x00"
        origin = "/private/original/evidence.bin"
        objects = [(origin, payload, job_sha)] if members is None else members
        request_rows = []
        manifest_rows = []
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w",
                          format=tarfile.USTAR_FORMAT) as bundle:
            for path, raw, owner_sha in sorted(objects):
                raw_sha = controller.sha256(raw)
                request_rows.append({
                    "owner_job_sha256": owner_sha,
                    "origin_path": path,
                    "raw_sha256": raw_sha,
                    "byte_count": len(raw),
                })
                object_id = controller._source5_archive_read_object_id(
                    path, raw_sha,
                )
                compact_name = ("objects/" +
                                controller.sha256(path.encode("utf-8")) +
                                "/" + raw_sha)
                info = tarfile.TarInfo(compact_name)
                info.size = len(raw)
                info.mode = 0o600
                info.uid = info.gid = info.mtime = 0
                bundle.addfile(info, io.BytesIO(raw))
                manifest_rows.append({
                    "origin_path": path, "role": "normal_app_output",
                    "object_id": object_id, "raw_sha256": raw_sha,
                    "semantic_sha256": None, "byte_count": len(raw),
                    "object_pin": {"path": "/private/archive/object.bin",
                                   "raw_sha256": raw_sha},
                })
        bundle_raw = tar_buffer.getvalue()
        request, request_raw, request_pin = \
            controller.build_source5_archive_read_request(
                campaign_id, host_id, "fixed_analysis", 0,
                request_rows, 256 * 1024,
            )
        response, response_raw, response_pin = \
            controller.build_source5_archive_read_response(
                request_raw, controller.sha256(bundle_raw), len(bundle_raw),
            )
        bundle_path = root / "response.tar"
        bundle_path.write_bytes(bundle_raw)
        bundle_path.chmod(0o600)
        stage_root = root / "stage"
        stage_root.mkdir(mode=0o700)
        manifest_body = {
            "schema": "allocatbelt.application-source5-evidence-object-manifest.v1",
            "campaign_id": campaign_id, "host_id": host_id,
            "phase": "confirmation", "job_index": 0,
            "job_ordinal": 1, "job_sha256": job_sha,
            "run_id": "read-test-original-job",
            "job_record_raw_sha256": "b" * 64,
            "predecessor_ack_pin": None,
            "objects": manifest_rows,
            "object_count": len(manifest_rows),
            "payload_bytes": sum(row["byte_count"] for row in manifest_rows),
        }
        manifest = {
            **manifest_body,
            "manifest_sha256": controller.sha256(
                controller.canonical_bytes(manifest_body),
            ),
        }
        return (request, request_raw, request_pin, response, response_raw,
                response_pin, bundle_path, stage_root, manifest, objects)

    def test_mutable_directory_identity_keeps_inode_type_mode_and_owner(self) -> None:
        controller = self.controller
        with tempfile.TemporaryDirectory(prefix="source5-recorded-directory-") as temp:
            root = Path(temp) / "scratch"
            root.mkdir(mode=0o700)
            before = root.lstat()
            (root / "child").mkdir(mode=0o700)
            os.utime(root, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
            after = root.lstat()
            self.assertFalse(controller._source5_same_file_identity(before, after))
            self.assertTrue(controller._source5_same_directory_identity(before, after))
            root.chmod(0o755)
            self.assertFalse(controller._source5_same_directory_identity(before, root.lstat()))
            root.chmod(0o700)
            retained = root.with_name("retained")
            root.rename(retained)
            root.mkdir(mode=0o700)
            self.assertFalse(controller._source5_same_directory_identity(before, root.lstat()))
            root.rmdir()
            root.symlink_to(retained, target_is_directory=True)
            self.assertFalse(controller._source5_same_directory_identity(before, root.lstat()))
            root.unlink()

    def test_recorded_wait_accepts_owned_publication_between_stat_and_open(self) -> None:
        controller = self.controller
        with tempfile.TemporaryDirectory(prefix="source5-recorded-open-race-") as temp:
            root = Path(temp)
            root.chmod(0o700)
            (root / "stage").mkdir(mode=0o700)
            (root / "request.json").write_bytes(b"request")
            (root / "request.json").chmod(0o600)
            space = os.statvfs(root)
            block = space.f_frsize or space.f_bsize
            original_open = controller.os.open
            published = []

            def publish_before_directory_open(path, flags, *args, **kwargs):
                if path == root and flags & os.O_DIRECTORY:
                    self.assertEqual(published, [])
                    previous = root.lstat()
                    for name in ("response.json", "response.tar"):
                        (root / name).write_bytes(b"published")
                        (root / name).chmod(0o600)
                    os.utime(root, ns=(previous.st_atime_ns,
                                       previous.st_mtime_ns + 1_000_000_000))
                    published.append(True)
                return original_open(path, flags, *args, **kwargs)

            with patch.object(controller.os, "open", side_effect=publish_before_directory_open):
                controller._source5_wait_for_recorded_read_publication(
                    root, "request.json", "response.json.incoming",
                    "response.json", "response.tar.incoming", "response.tar",
                    stage_name="stage", request_maximum_bytes=64,
                    response_maximum_bytes=64, bundle_maximum_bytes=64,
                    device_id=root.stat().st_dev, allocation_block_bytes=block,
                    deadline_ns=time.monotonic_ns() + 3_000_000_000,
                )
            self.assertEqual(published, [True])

    def test_read_schedule_adds_one_trace_window_per_original_open_loop_job(self) -> None:
        controller = self.controller
        phases = {
            "exploration": [{"phase": "exploration", "ordinal": 1,
                             "run_id": "explore-1", "mode": "capacity"}],
            "aa": [{"phase": "aa", "ordinal": 1,
                    "run_id": "aa-1", "mode": "capacity"}],
            "confirmation": [
                {"phase": "confirmation", "ordinal": 1,
                 "run_id": "fixed-capacity-1", "mode": "capacity"},
                {"phase": "confirmation", "ordinal": 2,
                 "run_id": "fixed-open-memory", "mode": "open_loop",
                 "family": "memory", "profile": "steady",
                 "load_percent": 70, "comparison_kind": "allocator",
                 "baseline_allocator": "mimalloc-secure",
                 "allocator": "allocatbelt"},
                {"phase": "confirmation", "ordinal": 3,
                 "run_id": "fixed-open-cpu", "mode": "open_loop",
                 "family": "cpu", "profile": "steady",
                 "load_percent": 70, "comparison_kind": "allocator",
                 "baseline_allocator": "mimalloc-secure",
                 "allocator": "allocatbelt"},
            ],
            "pressure": [{
                "phase": "pressure", "ordinal": 1,
                "run_id": "pressure-open-1", "mode": "open_loop",
                "family": "cpu", "profile": "steady",
                "load_percent": 70, "comparison_kind": "allocator",
                "baseline_allocator": "mimalloc-secure",
                "allocator": "allocatbelt",
                "predecessor_run_ids": ["fixed-open-cpu"],
            }],
            "soak": [{"phase": "soak", "ordinal": 1,
                      "run_id": "soak-1", "mode": "soak"}],
        }
        caps = {
            (phase, job["run_id"]): {
                "maximum_request_bytes": 4096,
                "maximum_response_bytes": 4096,
                "object_count": 1,
                "bundle_bytes": 64 * 1024,
            }
            for phase, rows in phases.items() for job in rows
        }
        context = types.SimpleNamespace(
            host_id="host-a", output_root=Path("/private/output"),
            manifest={"campaign_id": "campaign-a"},
        )
        with patch.object(controller, "_host_jobs",
                          side_effect=lambda _context, phase: phases[phase]):
            schedule = controller._source5_archive_read_schedule(context, caps)
        self.assertEqual(len(schedule), 21)
        phase_trace = [row for row in schedule
                       if row["use"] == "phase_analyzer_trace"]
        final_trace = [row for row in schedule
                       if row["use"] == "final_analyzer_trace"]
        self.assertEqual([row["job"]["run_id"] for row in phase_trace],
                         ["fixed-open-cpu", "fixed-open-memory",
                          "pressure-open-1"])
        self.assertEqual([row["job"]["run_id"] for row in final_trace],
                         ["fixed-open-cpu", "fixed-open-memory",
                          "pressure-open-1"])
        self.assertEqual([row["request_ordinal"] for row in schedule],
                         list(range(len(schedule))))

    def test_read_response_streams_exact_signed_objects_to_readonly_refs(self) -> None:
        controller = self.controller
        with tempfile.TemporaryDirectory(prefix="source5-archive-read-") as temp:
            fixture = self._fixture(Path(temp))
            (request, request_raw, _request_pin, _response, response_raw,
             _response_pin, bundle_path, stage_root, manifest, objects) = fixture
            result = controller.validate_source5_archive_read_response(
                request_raw, response_raw, bundle_path, stage_root,
                request["maximum_response_bytes"], manifest,
            )
            self.assertEqual(result["response_pin"]["raw_sha256"],
                             controller.sha256(response_raw))
            for origin, payload, _owner_sha in objects:
                reference = result["refs"][origin]
                staged = Path(reference["path"])
                self.assertEqual(staged.read_bytes(), payload)
                self.assertEqual(reference["raw_sha256"], controller.sha256(payload))
                self.assertEqual(stat.S_IMODE(staged.stat().st_mode), 0o400)

    def test_incoming_readback_publication_requires_complete_request_bound_pair(self) -> None:
        controller = self.controller
        with tempfile.TemporaryDirectory(prefix="source5-read-publish-") as temp:
            root = Path(temp)
            fixture = self._fixture(root)
            request, request_raw, _request_pin, _response, response_raw, \
                _response_pin, final_bundle, _stage, _manifest, _objects = fixture
            request_path = root / "request.json"
            request_path.write_bytes(request_raw)
            request_path.chmod(0o600)
            response_incoming = root / "response.json.incoming"
            response_incoming.write_bytes(response_raw)
            response_incoming.chmod(0o600)
            bundle_incoming = root / "response.tar.incoming"
            final_bundle.rename(bundle_incoming)
            result = controller.publish_source5_archive_readback(
                request_path, response_incoming, bundle_incoming,
            )
            self.assertEqual(result["response_pin"]["raw_sha256"],
                             controller.sha256(response_raw))
            self.assertEqual(result["bundle_pin"]["raw_sha256"],
                             controller.sha256(bundle_incoming.read_bytes())
                             if bundle_incoming.exists() else
                             controller.sha256((root / "response.tar").read_bytes()))
            self.assertTrue((root / "response.json").is_file())
            self.assertTrue((root / "response.tar").is_file())
            self.assertFalse(response_incoming.exists())
            self.assertFalse(bundle_incoming.exists())

    def test_incoming_readback_publication_rejects_partial_response_before_final_slots(self) -> None:
        controller = self.controller
        with tempfile.TemporaryDirectory(prefix="source5-read-publish-partial-") as temp:
            root = Path(temp)
            fixture = self._fixture(root)
            _request, request_raw, _request_pin, _response, _response_raw, \
                _response_pin, final_bundle, _stage, _manifest, _objects = fixture
            request_path = root / "request.json"
            request_path.write_bytes(request_raw)
            request_path.chmod(0o600)
            response_incoming = root / "response.json.incoming"
            response_incoming.write_bytes(b"{\"partial\":true}")
            response_incoming.chmod(0o600)
            bundle_incoming = root / "response.tar.incoming"
            final_bundle.rename(bundle_incoming)
            with self.assertRaises(controller.Source5CampaignError):
                controller.publish_source5_archive_readback(
                    request_path, response_incoming, bundle_incoming,
                )
            self.assertFalse((root / "response.json").exists())
            self.assertFalse((root / "response.tar").exists())

    def test_recorded_read_wait_tolerates_both_incoming_orders_and_paused_renames(self) -> None:
        controller = self.controller
        for first, second in (("response", "bundle"), ("bundle", "response")):
            with self.subTest(first=first), tempfile.TemporaryDirectory(
                    prefix="source5-recorded-read-publish-order-") as temp:
                root = Path(temp)
                os.chmod(root, 0o700)
                names = {
                    "request": "request.json",
                    "response_incoming": "response.json.incoming",
                    "response": "response.json",
                    "bundle_incoming": "response.tar.incoming",
                    "bundle": "response.tar",
                }
                stage = root / "stage"
                stage.mkdir(mode=0o700)
                (root / names["request"]).write_bytes(b"exact request")
                (root / names["request"]).chmod(0o600)
                space = os.statvfs(root)
                block = space.f_frsize or space.f_bsize
                deadline = time.monotonic_ns() + 3_000_000_000
                completed = threading.Event()
                errors = []

                def wait_for_pair() -> None:
                    try:
                        controller._source5_wait_for_recorded_read_publication(
                            root, names["request"],
                            names["response_incoming"], names["response"],
                            names["bundle_incoming"], names["bundle"],
                            stage_name=stage.name,
                            request_maximum_bytes=64,
                            response_maximum_bytes=64,
                            bundle_maximum_bytes=64,
                            device_id=root.stat().st_dev,
                            allocation_block_bytes=block,
                            deadline_ns=deadline,
                        )
                        completed.set()
                    except BaseException as error:
                        errors.append(error)
                        completed.set()

                waiter = threading.Thread(target=wait_for_pair)
                waiter.start()
                first_incoming = names[f"{first}_incoming"]
                first_final = names[first]
                (root / first_incoming).write_bytes((first + " bytes").encode())
                (root / first_incoming).chmod(0o600)
                time.sleep(0.04)
                self.assertFalse(completed.is_set())
                (root / first_incoming).rename(root / first_final)
                time.sleep(0.04)
                self.assertFalse(completed.is_set())
                second_incoming = names[f"{second}_incoming"]
                second_final = names[second]
                (root / second_incoming).write_bytes((second + " bytes").encode())
                (root / second_incoming).chmod(0o600)
                time.sleep(0.04)
                self.assertFalse(completed.is_set())
                (root / second_incoming).rename(root / second_final)
                waiter.join(timeout=2)
                self.assertFalse(waiter.is_alive())
                self.assertEqual(errors, [])
                self.assertTrue(completed.is_set())
                self.assertTrue((root / names["response"]).is_file())
                self.assertTrue((root / names["bundle"]).is_file())

    def test_recorded_read_wait_rejects_symlink_oversize_cancel_and_deadline(self) -> None:
        controller = self.controller
        for failure in ("symlink", "oversize", "cancelled", "deadline",
                        "stage_symlink", "stage_nonempty", "stage_mode"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(
                    prefix="source5-recorded-read-publish-reject-") as temp:
                root = Path(temp)
                os.chmod(root, 0o700)
                request = root / "request.json"
                request.write_bytes(b"request")
                request.chmod(0o600)
                response_incoming = root / "response.json.incoming"
                stage = root / "stage"
                if failure == "stage_symlink":
                    external_stage = Path(temp) / "external-stage"
                    external_stage.mkdir(mode=0o700)
                    stage.symlink_to(external_stage, target_is_directory=True)
                else:
                    stage.mkdir(mode=0o700)
                    if failure == "stage_nonempty":
                        (stage / "unexpected").write_bytes(b"unexpected")
                    elif failure == "stage_mode":
                        stage.chmod(0o755)
                cancelled = threading.Event()
                deadline = time.monotonic_ns() + 1_000_000_000
                if failure == "symlink":
                    external = Path(temp) / "external.bin"
                    external.write_bytes(b"response")
                    external.chmod(0o600)
                    response_incoming.symlink_to(external)
                elif failure == "oversize":
                    response_incoming.write_bytes(b"x" * 65)
                    response_incoming.chmod(0o600)
                elif failure == "cancelled":
                    cancelled.set()
                else:
                    deadline = time.monotonic_ns() - 1
                space = os.statvfs(root)
                block = space.f_frsize or space.f_bsize
                with self.assertRaises(controller.Source5CampaignError):
                    controller._source5_wait_for_recorded_read_publication(
                        root, request.name, response_incoming.name,
                        "response.json", "response.tar.incoming",
                        "response.tar", request_maximum_bytes=64,
                        stage_name=stage.name,
                        response_maximum_bytes=64, bundle_maximum_bytes=64,
                        device_id=root.stat().st_dev,
                        allocation_block_bytes=block, deadline_ns=deadline,
                        cancel_event=cancelled,
                    )

    def test_read_control_schedule_and_append_only_chain_replay_exact_plan_row(self) -> None:
        controller = self.controller
        with tempfile.TemporaryDirectory(prefix="source5-read-control-") as temp:
            root = Path(temp)
            output_root = root / "output"
            scratch_root = root / "scratch"
            output_root.mkdir(mode=0o700)
            scratch_root.mkdir(mode=0o700)
            campaign_id, host_id = "campaign-control", "host-control"
            exploration_job = {
                "phase": "exploration", "host_id": host_id,
                "ordinal": 1, "run_id": "original-exploration-1",
                "mode": "capacity",
            }
            aa_job = {
                "phase": "aa", "host_id": host_id,
                "ordinal": 1, "run_id": "original-aa-1",
                "mode": "capacity",
            }
            confirmation_job = {
                "phase": "confirmation", "host_id": host_id,
                "ordinal": 1, "run_id": "original-confirmation-1",
                "mode": "capacity",
            }
            pressure_job = {
                "phase": "pressure", "host_id": host_id,
                "ordinal": 1, "run_id": "original-pressure-1",
                "mode": "capacity",
                "predecessor_run_ids": [confirmation_job["run_id"]],
            }
            soak_job = {
                "phase": "soak", "host_id": host_id,
                "ordinal": 1, "run_id": "original-soak-1",
                "mode": "soak",
            }
            cap = {
                "maximum_request_bytes": 16 * 1024 * 1024,
                "maximum_response_bytes": 16 * 1024 * 1024,
                "maximum_bundle_bytes": 16 * 1024,
                "maximum_stage_bytes": 64,
                "maximum_stage_inodes": 2,
                "maximum_object_count": 1,
                "maximum_object_bytes": 64,
                "maximum_live_window_bytes": 32 * 1024,
                "maximum_live_window_inodes": 8,
                "request_bytes": 512, "response_bytes": 512,
                "bundle_bytes": 10 * 1024, "stage_bytes": 8,
                "stage_inodes": 2, "object_count": 1,
                "maximum_object_bytes": 64,
                "live_window_bytes": 16 * 1024,
                "live_window_inodes": 4,
            }
            context = types.SimpleNamespace(
                manifest={"campaign_id": campaign_id}, host_id=host_id,
                plan={"jobs": {
                    "exploration": [exploration_job], "aa": [aa_job],
                    "confirmation": [confirmation_job],
                    "pressure": [pressure_job], "soak": [soak_job],
                }},
                output_root=output_root,
            )
            readback_caps = {
                (phase, job["run_id"]): cap
                for phase, job in (
                    ("exploration", exploration_job), ("aa", aa_job),
                    ("confirmation", confirmation_job),
                    ("pressure", pressure_job), ("soak", soak_job),
                )
            }
            schedule = controller._source5_archive_read_schedule(
                context, readback_caps,
            )
            self.assertEqual(len(schedule), 11)
            self.assertEqual([row["analysis_phase"] for row in schedule], [
                "exploration", "aa", "fixed_analysis",
                "pressure_analysis", "pressure_analysis", "soak",
                "final_analysis", "final_analysis", "final_analysis",
                "final_analysis", "final_analysis",
            ])
            pressure_schedule = [
                row for row in schedule
                if row["analysis_phase"] == "pressure_analysis"
            ]
            self.assertEqual(
                [(row["owner_phase"], row["use"], row["job"]["run_id"])
                 for row in pressure_schedule],
                [
                    ("confirmation", "pressure_predecessor",
                     confirmation_job["run_id"]),
                    ("pressure", "phase_analysis", pressure_job["run_id"]),
                ],
            )
            readback_root = (scratch_root / campaign_id / host_id /
                             "archive-readback")
            readback_root.mkdir(mode=0o700, parents=True)
            source5_root = (output_root / campaign_id / "source5" / host_id)
            source5_root.mkdir(mode=0o700, parents=True)
            slots = {
                "source5_archive_read_request_slot": str(readback_root / "request.json"),
                "source5_archive_read_response_slot": str(readback_root / "response.json"),
                "source5_archive_read_response_incoming": str(readback_root / "response.json.incoming"),
                "source5_archive_read_bundle": str(readback_root / "response.tar"),
                "source5_archive_read_bundle_incoming": str(readback_root / "response.tar.incoming"),
                "source5_archive_read_stage": str(readback_root / "stage"),
                "source5_archive_read_control_ledger": str(source5_root / "archive-read-control.jsonl"),
            }
            projection = controller._source5_archive_read_control_ledger_byte_bound(
                context, schedule, slots,
            )
            context.source5_archive_read_slot_paths = slots
            context.source5_archive_read_caps = {
                "control_ledger_bytes": projection["maximum_bytes"],
                "control_ledger_line_bytes": projection["maximum_line_bytes"],
                "control_ledger_event_count": projection["maximum_event_count"],
            }
            context.source5_archive_read_schedule = schedule
            context.source5_archive_read_ordinal = 0
            context.source5_archive_read_event_count = 0
            context.source5_archive_read_previous_sha256 = "0" * 64
            context.source5_archive_read_pending_request_pin = None
            context.source5_archive_read_ledger_loaded = False
            item = schedule[0]
            job_sha = item["job_sha256"]
            manifest_path = (output_root / campaign_id / "chronology" /
                             host_id / "evidence-checkpoints" /
                             item["owner_phase"] /
                             f"{item['job']['ordinal']:06d}-{job_sha}.object-manifest.json")
            manifest_pin = {"path": str(manifest_path),
                            "raw_sha256": "a" * 64,
                            "semantic_sha256": "b" * 64}
            request_pin = {
                "path": slots["source5_archive_read_request_slot"],
                "raw_sha256": "c" * 64, "semantic_sha256": "d" * 64,
                "byte_count": 128,
            }
            controller._source5_append_archive_read_control_event(
                context, item, "request_published",
                request_pin=request_pin, response_pin=None, bundle_pin=None,
                object_manifest_pin=manifest_pin,
            )
            cursor, _head, count, pending = \
                controller._source5_archive_read_control_ledger_state(context)
            self.assertEqual((cursor, count, pending), (0, 1, request_pin))
            response_pin = {
                "path": slots["source5_archive_read_response_slot"],
                "raw_sha256": "e" * 64, "semantic_sha256": "f" * 64,
                "byte_count": 256,
            }
            bundle_pin = {
                "path": slots["source5_archive_read_bundle"],
                "raw_sha256": "1" * 64, "byte_count": 10 * 1024,
            }
            controller._source5_append_archive_read_control_event(
                context, item, "response_verified",
                request_pin=request_pin, response_pin=response_pin,
                bundle_pin=bundle_pin, object_manifest_pin=manifest_pin,
            )
            context.source5_archive_read_ledger_loaded = False
            cursor, _head, count, pending = \
                controller._source5_archive_read_control_ledger_state(context)
            self.assertEqual((cursor, count, pending), (1, 2, None))
            captured = {}
            captured_cursor, _captured_head, captured_count, captured_pending = \
                controller._source5_archive_read_control_ledger_state(
                    context, capture_request_ordinal=0,
                    capture_output=captured,
                )
            self.assertEqual((captured_cursor, captured_count,
                              captured_pending), (1, 2, None))
            self.assertEqual(set(captured), {
                "request_published", "response_verified",
            })
            self.assertEqual(captured["request_published"]["request_pin"],
                             request_pin)
            self.assertEqual(captured["response_verified"]["response_pin"],
                             response_pin)
            self.assertEqual(captured["response_verified"]["bundle_pin"],
                             bundle_pin)
            ledger_path = Path(slots["source5_archive_read_control_ledger"])
            lines = ledger_path.read_bytes().splitlines(keepends=True)
            self.assertEqual(len(lines), 2)
            second = json.loads(lines[1])
            second["record_sha256"] = "9" * 64
            lines[1] = controller.canonical_bytes(second)
            ledger_path.write_bytes(b"".join(lines))
            context.source5_archive_read_ledger_loaded = False
            with self.assertRaises(controller.Source5CampaignError):
                controller._source5_archive_read_control_ledger_state(context)

    def test_completed_read_selector_reuses_only_the_exact_completed_ordinal(self) -> None:
        controller = self.controller
        exploration = {
            "phase": "exploration", "run_id": "original-exploration-1",
        }
        fixed = {"phase": "confirmation", "run_id": "original-fixed-open-1"}
        exploration_row = {
            "request_ordinal": 0, "analysis_phase": "exploration",
            "use": "phase_analysis", "job": exploration,
        }
        fixed_phase_row = {
            "request_ordinal": 1, "analysis_phase": "fixed_analysis",
            "use": "phase_analysis", "job": fixed,
        }
        fixed_trace_row = {
            "request_ordinal": 2, "analysis_phase": "fixed_analysis",
            "use": "phase_analyzer_trace", "job": fixed,
        }
        final_row = {
            "request_ordinal": 3, "analysis_phase": "final_analysis",
            "use": "final_replay", "job": exploration,
        }
        predecessor_row = {
            "request_ordinal": 4, "analysis_phase": "pressure_analysis",
            "use": "pressure_predecessor", "job": fixed,
        }
        final_trace_row = {
            "request_ordinal": 5, "analysis_phase": "final_analysis",
            "use": "final_analyzer_trace", "job": fixed,
        }
        schedule = [exploration_row, fixed_phase_row,
                    fixed_trace_row, final_row, predecessor_row,
                    final_trace_row]
        self.assertIs(controller._source5_completed_archive_read_schedule_row(
            schedule, set(), exploration, "exploration", "phase_analysis",
        ), exploration_row)
        self.assertIs(controller._source5_completed_archive_read_schedule_row(
            schedule, {0}, exploration, "exploration", "phase_analysis",
        ), exploration_row)
        self.assertIs(controller._source5_completed_archive_read_schedule_row(
            schedule, set(), fixed, "fixed_analysis", "phase_analysis",
        ), fixed_phase_row)
        self.assertIs(controller._source5_completed_archive_read_schedule_row(
            schedule, {1}, fixed, "fixed_analysis", "phase_analyzer_trace",
        ), fixed_trace_row)
        self.assertIs(controller._source5_completed_archive_read_schedule_row(
            schedule, set(), exploration, "final_analysis", "final_replay",
        ), final_row)
        self.assertIs(controller._source5_completed_archive_read_schedule_row(
            schedule, {3}, exploration, "final_analysis", "final_replay",
        ), final_row)
        self.assertIs(controller._source5_completed_archive_read_schedule_row(
            schedule, set(), fixed, "pressure_analysis", "pressure_predecessor",
        ), predecessor_row)
        self.assertIs(controller._source5_completed_archive_read_schedule_row(
            schedule, set(), fixed, "final_analysis", "final_analyzer_trace",
        ), final_trace_row)
        with self.assertRaises(controller.Source5CampaignError):
            controller._source5_completed_archive_read_schedule_row(
                schedule, set(), {**exploration, "run_id": "other"},
                "exploration", "phase_analysis",
            )
        with self.assertRaises(controller.Source5CampaignError):
            controller._source5_completed_archive_read_schedule_row(
                schedule, set(), exploration, "final_analysis",
                "final_analyzer_trace",
            )
        with self.assertRaises(controller.Source5CampaignError):
            controller._source5_completed_archive_read_schedule_row(
                schedule, {5}, fixed, "final_analysis",
                "final_analyzer_trace",
            )

    def test_completed_provider_reuses_owner_ordinal_with_one_active_stage(self) -> None:
        controller = self.controller
        job = {
            "phase": "confirmation", "run_id": "original-fixed-open-1",
        }
        schedule = [{
            "request_ordinal": 7, "analysis_phase": "final_analysis",
            "use": "final_replay", "owner_phase": "confirmation",
            "job_index": 0, "job": job, "job_sha256": "a" * 64,
            "caps": {},
        }]
        with tempfile.TemporaryDirectory(
                prefix="source5-completed-owner-provider-") as temporary:
            ledger = Path(temporary) / "read-control.jsonl"
            ledger.write_bytes(b"retained completed control bytes\n")
            ledger.chmod(0o600)
            ledger_before = ledger.read_bytes()
            context = types.SimpleNamespace(
                manifest={
                    "schema": controller.EXECUTION_SCHEMA_V4,
                    "campaign_id": "campaign-completed-read",
                },
                host_id="host-a", source5_archive_read_schedule=schedule,
                source5_archive_read_slot_paths={
                    "source5_archive_read_control_ledger": str(ledger),
                },
                source5_archive_read_caps={},
            )
            active = 0
            maximum_active = 0
            entered = []
            first_view_entered = threading.Event()
            release_first_view = threading.Event()

            @contextmanager
            def replay_view(_context, row, *, cancel_event=None):
                nonlocal active, maximum_active
                self.assertIsNone(cancel_event)
                active += 1
                maximum_active = max(maximum_active, active)
                entered.append(row["request_ordinal"])
                try:
                    if len(entered) == 1:
                        first_view_entered.set()
                        if not release_first_view.wait(timeout=1):
                            raise AssertionError("first read stage was not released")
                    yield {"request_ordinal": row["request_ordinal"]}
                finally:
                    active -= 1

            observed = []
            errors = []
            second_call_started = threading.Event()

            def open_one_view(*, second: bool = False) -> None:
                try:
                    if second:
                        second_call_started.set()
                    with provider.open_view(
                        job, "final_analysis", use="final_replay",
                    ) as view:
                        observed.append(view["request_ordinal"])
                        time.sleep(0.03)
                except BaseException as error:
                    errors.append(error)

            with patch.object(
                controller, "_source5_archive_read_control_ledger_state",
                return_value=(8, "b" * 64, 16, None),
            ) as ledger_state, patch.object(
                controller, "_source5_replay_completed_archive_read_view",
                side_effect=replay_view,
            ), patch.object(
                controller, "_source5_append_archive_read_control_event",
                side_effect=AssertionError("completed replay appended a control event"),
            ):
                provider = controller.source5_completed_archive_read_provider(
                    context,
                )
                first = threading.Thread(target=open_one_view)
                second = threading.Thread(
                    target=open_one_view, kwargs={"second": True},
                )
                first.start()
                self.assertTrue(first_view_entered.wait(timeout=1))
                second.start()
                self.assertTrue(second_call_started.wait(timeout=1))
                time.sleep(0.02)
                self.assertEqual(active, 1)
                release_first_view.set()
                workers = [first, second]
                for worker in workers:
                    worker.join(timeout=2)
                self.assertTrue(all(not worker.is_alive() for worker in workers))
                ledger_state.assert_called_once_with(context, force_reload=True)

            self.assertEqual(errors, [])
            self.assertEqual(sorted(observed), [7, 7])
            self.assertEqual(entered, [7, 7])
            self.assertEqual(maximum_active, 1)
            self.assertEqual(active, 0)
            self.assertEqual(ledger.read_bytes(), ledger_before)

    def test_recorded_read_provider_lease_rejects_nested_and_competing_opens(self) -> None:
        controller = self.controller
        lock = threading.Lock()
        deadline = time.monotonic_ns() + 1_000_000_000
        competitor_done = threading.Event()
        competitor_errors = []
        started = time.monotonic()
        with controller._source5_recorded_read_provider_lease(
                lock, None, deadline):
            with self.assertRaises(controller.Source5CampaignError):
                with controller._source5_recorded_read_provider_lease(
                        lock, None, deadline):
                    self.fail("nested recorded-read lease unexpectedly entered")

            def competing_open() -> None:
                try:
                    with controller._source5_recorded_read_provider_lease(
                            lock, None, deadline):
                        competitor_errors.append(
                            "competing recorded-read lease unexpectedly entered",
                        )
                except controller.Source5CampaignError:
                    pass
                finally:
                    competitor_done.set()

            worker = threading.Thread(target=competing_open)
            worker.start()
            self.assertTrue(competitor_done.wait(timeout=0.5))
            worker.join(timeout=0.5)
            self.assertFalse(worker.is_alive())
        self.assertEqual(competitor_errors, [])
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertFalse(lock.locked())

    def test_completed_read_view_revalidates_without_appending_a_new_ordinal(self) -> None:
        tree = ast.parse(CONTROLLER_PATH.read_bytes(), filename=str(CONTROLLER_PATH))
        node = function(tree, "_source5_replay_completed_archive_read_view")
        called = {
            item.func.id if isinstance(item.func, ast.Name) else
            item.func.attr if isinstance(item.func, ast.Attribute) else None
            for item in ast.walk(node) if isinstance(item, ast.Call)
        }
        self.assertIn("_source5_archive_read_control_ledger_state", called)
        self.assertIn("_source5_verify_persisted_archive_read_closure", called)
        self.assertIn("validate_source5_archive_read_response", called)
        self.assertIn("_source5_unlink_exact_private_file", called)
        self.assertNotIn("_source5_append_archive_read_control_event", called)

    def test_completed_read_waits_for_sequential_response_and_bundle_publication(self) -> None:
        controller = self.controller
        for first_name, second_name, first_bytes, second_bytes in (
            ("response.json", "response.tar", b"closed response", b"closed bundle"),
            ("response.tar", "response.json", b"closed bundle", b"closed response"),
        ):
            with self.subTest(first=first_name), tempfile.TemporaryDirectory(
                    prefix="source5-read-pair-wait-") as temp:
                root = Path(temp)
                response = root / "response.json"
                bundle = root / "response.tar"
                (root / first_name).write_bytes(first_bytes)

                def publish_second() -> None:
                    time.sleep(0.05)
                    (root / second_name).write_bytes(second_bytes)

                publisher = threading.Thread(target=publish_second)
                publisher.start()
                controller._source5_wait_for_archive_read_pair(response, bundle)
                publisher.join(timeout=2)
                self.assertFalse(publisher.is_alive())
                self.assertEqual(response.read_bytes(), b"closed response")
                self.assertEqual(bundle.read_bytes(), b"closed bundle")

        with tempfile.TemporaryDirectory(prefix="source5-read-pair-cancel-") as temp:
            root = Path(temp)
            response = root / "response.json"
            bundle = root / "response.tar"
            response.write_bytes(b"partial response publication")
            cancelled = threading.Event()
            def cancel_wait() -> None:
                time.sleep(0.05)
                cancelled.set()

            canceller = threading.Thread(target=cancel_wait)
            canceller.start()
            with self.assertRaises(controller.Source5CampaignError):
                controller._source5_wait_for_archive_read_pair(
                    response, bundle, cancelled,
                )
            canceller.join(timeout=2)
            self.assertFalse(canceller.is_alive())
            self.assertFalse(bundle.exists())

    def test_interrupted_read_request_reuses_or_recreates_only_identical_bytes(self) -> None:
        controller = self.controller
        with tempfile.TemporaryDirectory(prefix="source5-read-request-resume-") as temp:
            root = Path(temp)
            request_path = root / "request.json"
            rows = [{
                "owner_job_sha256": "a" * 64,
                "origin_path": "/private/original/one.bin",
                "raw_sha256": "b" * 64,
                "byte_count": 1,
            }]
            _request, raw, pin = controller.build_source5_archive_read_request(
                "campaign-resume", "host-resume", "fixed_analysis", 3,
                rows, 10 * 1024,
            )
            expected = {
                "path": str(request_path), "raw_sha256": pin["raw_sha256"],
                "semantic_sha256": pin["semantic_sha256"],
                "byte_count": len(raw),
            }
            first = controller._source5_materialize_archive_read_request(
                request_path, raw, pin, 16 * 1024 * 1024, None,
            )
            self.assertEqual(first, expected)
            replayed = controller._source5_materialize_archive_read_request(
                request_path, raw, pin, 16 * 1024 * 1024, expected,
            )
            self.assertEqual(replayed, expected)
            request_path.unlink()
            recreated = controller._source5_materialize_archive_read_request(
                request_path, raw, pin, 16 * 1024 * 1024, expected,
            )
            self.assertEqual(recreated, expected)
            self.assertEqual(request_path.read_bytes(), raw)
            request_path.write_bytes(raw + b"{}"); request_path.chmod(0o600)
            with self.assertRaises(controller.Source5CampaignError):
                controller._source5_materialize_archive_read_request(
                    request_path, raw, pin, 16 * 1024 * 1024, expected,
                )

    def test_response_rejects_a_resealed_wrong_request_pin(self) -> None:
        controller = self.controller
        with tempfile.TemporaryDirectory(prefix="source5-archive-read-pin-") as temp:
            fixture = self._fixture(Path(temp))
            request, request_raw, _request_pin, response, _response_raw, _response_pin, \
                bundle_path, stage_root, manifest, _objects = fixture
            response["request_pin"]["raw_sha256"] = "f" * 64
            body = {key: value for key, value in response.items()
                    if key != "response_sha256"}
            response["response_sha256"] = controller.sha256(
                controller.canonical_bytes(body),
            )
            with self.assertRaises(controller.Source5CampaignError):
                controller.validate_source5_archive_read_response(
                    request_raw, controller.canonical_bytes(response),
                    bundle_path, stage_root,
                    request["maximum_response_bytes"], manifest,
                )

    def test_response_rejects_extra_tar_member_and_manifest_pin_mismatch(self) -> None:
        controller = self.controller
        with tempfile.TemporaryDirectory(prefix="source5-archive-read-closure-") as temp:
            root = Path(temp)
            fixture = self._fixture(root)
            request, request_raw, _request_pin, _response, _response_raw, _response_pin, \
                bundle_path, stage_root, manifest, objects = fixture
            origin, payload, _owner = objects[0]
            raw_sha = controller.sha256(payload)
            archive_id = controller._source5_archive_read_object_id(origin, raw_sha)
            extra_name = "objects/" + ("b" * 64) + "/" + ("c" * 64)
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w",
                              format=tarfile.USTAR_FORMAT) as bundle:
                for name, content in (
                    ("objects/" + controller.sha256(origin.encode()) + "/" + raw_sha,
                     payload),
                    (extra_name, b"unexpected"),
                ):
                    info = tarfile.TarInfo(name)
                    info.size, info.mode, info.uid, info.gid, info.mtime = \
                        len(content), 0o600, 0, 0, 0
                    bundle.addfile(info, io.BytesIO(content))
            extra_tar = buffer.getvalue()
            bundle_path.write_bytes(extra_tar)
            bundle_path.chmod(0o600)
            response, response_raw, _pin = \
                controller.build_source5_archive_read_response(
                    request_raw, controller.sha256(extra_tar), len(extra_tar),
                )
            with self.assertRaises(controller.Source5CampaignError):
                controller.validate_source5_archive_read_response(
                    request_raw, response_raw, bundle_path, stage_root,
                    request["maximum_response_bytes"], manifest,
                )
            self.assertEqual(manifest["objects"][0]["object_id"], archive_id)

            valid = root / "valid"
            valid.mkdir(mode=0o700)
            fixture = self._fixture(valid)
            request, request_raw, _request_pin, _response, response_raw, _response_pin, \
                bundle_path, stage_root, manifest, _objects = fixture
            manifest["objects"][0]["raw_sha256"] = "d" * 64
            with self.assertRaises(controller.Source5CampaignError):
                controller.validate_source5_archive_read_response(
                    request_raw, response_raw, bundle_path, stage_root,
                    request["maximum_response_bytes"], manifest,
                )


class Source5ReadControlStorageCreditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.controller = load_source(
            "source5_read_control_credit_controller_test", CONTROLLER_PATH,
        )

    def test_storage_credit_rejects_control_tail_mutation_after_chain_replay(self) -> None:
        controller = self.controller
        with tempfile.TemporaryDirectory(prefix="source5-read-control-credit-") as temp:
            path = Path(temp) / "control.jsonl"
            original = b"valid\n"
            path.write_bytes(original)
            path.chmod(0o600)
            info = path.stat(follow_symlinks=False)
            context = types.SimpleNamespace(
                source5_archive_read_ledger_file_identity=(
                    info.st_dev, info.st_ino, info.st_mode, info.st_size,
                    info.st_mtime_ns, info.st_ctime_ns,
                    info.st_nlink, info.st_uid,
                ),
                source5_archive_read_ledger_byte_count=len(original),
                source5_archive_read_ledger_raw_sha256=
                    hashlib.sha256(original).hexdigest(),
            )
            self.assertEqual(
                controller._source5_verified_control_ledger_credit(
                    context, path, 1024,
                ), len(original),
            )
            with path.open("r+b") as stream:
                stream.write(b"forged\n")
                stream.flush()
                os.fsync(stream.fileno())
            with self.assertRaisesRegex(
                    controller.Source5CampaignError,
                    "changed between authenticated replay and storage credit"):
                controller._source5_verified_control_ledger_credit(
                    context, path, 1024,
                )



class Source5RemainingReservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.controller = load_source(
            "source5_remaining_reservation_controller_test", CONTROLLER_PATH,
        )
        cls.budget = load_source(
            "source5_remaining_reservation_budget_test",
            ROOT / "scripts/application-source5-evidence-budget.py",
        )

    def test_remaining_root_overrides_use_exact_string_root_ids(self) -> None:
        controller = self.controller
        budget = self.budget
        with tempfile.TemporaryDirectory(prefix="source5-remaining-roots-") as temporary:
            base = Path(temporary)
            roots = []
            directories = {}
            for role in ("artifact", "output", "scratch", "evidence_store"):
                path = base / role
                path.mkdir(mode=0o700)
                directories[role] = path
                roots.append({
                    "path": str(path), "role": role,
                    "reserved_bytes": 1 << 40,
                    "reserved_inodes": 1 << 20,
                    "filesystem_id": str(path.stat().st_dev),
                })
            source_root = base / "source"
            input_root = base / "input"
            campaign_artifacts = base / "campaign-artifacts"
            for path in (source_root, input_root, campaign_artifacts):
                path.mkdir(mode=0o700)
            reservation = budget.build_storage_reservation_value(
                "campaign-remaining", "host-remaining", roots,
            )
            reservation_path = directories["artifact"] / "storage-reservation.json"
            reservation_raw = controller.canonical_bytes(reservation)
            reservation_path.write_bytes(reservation_raw)
            reservation_path.chmod(0o600)
            context = types.SimpleNamespace(
                modules={controller.EVIDENCE_BUDGET_SOURCE_PATH: budget},
                artifact_root=directories["artifact"],
                output_root=directories["output"],
                source_root=source_root, input_root=input_root,
                host_id="host-remaining",
                manifest={
                    "campaign_id": "campaign-remaining",
                    "original_inputs": {
                        "campaign_artifacts_root": str(campaign_artifacts),
                    },
                },
            )
            required_bytes = {row["path"]: 0 for row in reservation["roots"]}
            required_inodes = {row["path"]: 0 for row in reservation["roots"]}
            checked, pin = controller._validate_live_storage_reservation(
                context, reservation_path,
                required_bytes_by_root=required_bytes,
                required_inodes_by_root=required_inodes,
            )
            self.assertEqual(checked, reservation)
            self.assertEqual(pin["raw_sha256"], hashlib.sha256(reservation_raw).hexdigest())
            wrong_keys = dict(required_bytes)
            wrong_keys.pop(next(iter(wrong_keys)))
            with self.assertRaisesRegex(
                    controller.Source5CampaignError,
                    "does not close over exact caller roots"):
                controller._validate_live_storage_reservation(
                    context, reservation_path,
                    required_bytes_by_root=wrong_keys,
                    required_inodes_by_root=required_inodes,
                )



class Source5CapturedBudgetSchemaDispatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.controller = load_source(
            "source5_captured_budget_schema_dispatch_test", CONTROLLER_PATH,
        )

    def _context(self, *, include_v3: bool = True):
        controller = self.controller
        calls = []

        def validate_v2(value, *args, **kwargs):
            calls.append(("v2", value, args, kwargs))
            return value

        def validate_v3(value, *args, **kwargs):
            calls.append(("v3", value, args, kwargs))
            return value

        budget_values = {
            "HOST_BUDGET_SCHEMA_V2": (
                "allocatbelt.application-source5-host-evidence-budget.v2"
            ),
            "HOST_BUDGET_SCHEMA_V3": (
                "allocatbelt.application-source5-host-evidence-budget.v3"
            ),
            "validate_host_evidence_budget_v2": validate_v2,
        }
        if include_v3:
            budget_values["validate_host_evidence_budget_v3"] = validate_v3
        budget_module = types.SimpleNamespace(**budget_values)
        context = types.SimpleNamespace(
            modules={controller.EVIDENCE_BUDGET_SOURCE_PATH: budget_module},
            journal_width_contract={"contract_sha256": "a" * 64},
        )
        return context, calls

    def _legacy_v2_body(self):
        return {
            "schema": "allocatbelt.application-source5-host-evidence-budget.v2",
            "campaign_id": "campaign-budget-dispatch", "host_id": "host-a",
            "original_pins": {}, "schedule": {}, "owner_contract": {},
            "path_catalogue": {}, "storage_reservation": {},
            "role_byte_reservations": {}, "transport": {},
            "execution_blockers": ["legacy_false_ready"],
            "readiness": {
                "budget_complete": False, "execution_ready": False,
                "component_gate_ready": False, "qualification_eligible": False,
            },
            "budget_sha256": "d" * 64,
        }

    def test_legacy_13_field_v2_uses_the_positional_validator_api(self) -> None:
        controller = self.controller
        context, calls = self._context()
        body = self._legacy_v2_body()
        result = controller._source5_validate_captured_host_budget(
            context, body, context.modules[controller.EVIDENCE_BUDGET_SOURCE_PATH],
        )
        self.assertIs(result, body)
        self.assertEqual(calls, [("v2", body, (), {})])

    def test_width_bound_15_field_v2_passes_only_the_captured_width_bytes(self) -> None:
        controller = self.controller
        context, calls = self._context(include_v3=False)
        body = {
            **self._legacy_v2_body(),
            "execution_manifest_schema": controller.EXECUTION_SCHEMA_V4,
            "journal_width_contract_pin": {
                "path": "/private/width.json", "raw_sha256": "b" * 64,
                "semantic_sha256": "c" * 64,
            },
        }
        expected_raw = controller.canonical_bytes(context.journal_width_contract)
        result = controller._source5_validate_captured_host_budget(
            context, body, context.modules[controller.EVIDENCE_BUDGET_SOURCE_PATH],
        )
        self.assertIs(result, body)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][:3], ("v2", body, ()))
        self.assertEqual(calls[0][3], {
            "journal_width_contract_raw": expected_raw,
        })

    def test_v3_remains_width_bound_and_unknown_schema_fails_closed(self) -> None:
        controller = self.controller
        context, calls = self._context()
        body = {
            **self._legacy_v2_body(),
            "schema": "allocatbelt.application-source5-host-evidence-budget.v3",
            "execution_manifest_schema": controller.EXECUTION_SCHEMA_V4,
            "journal_width_contract_pin": {
                "path": "/private/width.json", "raw_sha256": "b" * 64,
                "semantic_sha256": "c" * 64,
            },
            "admission_profile": "source5_width_v4_captured_replay_v1",
        }
        expected_raw = controller.canonical_bytes(context.journal_width_contract)
        self.assertIs(controller._source5_validate_captured_host_budget(
            context, body, context.modules[controller.EVIDENCE_BUDGET_SOURCE_PATH],
        ), body)
        self.assertEqual(calls, [("v3", body, (), {
            "journal_width_contract_raw": expected_raw,
        })])
        body["schema"] = "unknown"
        with self.assertRaises(controller.Source5CampaignError):
            controller._source5_validate_captured_host_budget(
                context, body, context.modules[controller.EVIDENCE_BUDGET_SOURCE_PATH],
            )


class Source5FreshPhaseStartBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.controller = load_source(
            "source5_fresh_phase_controller_test", CONTROLLER_PATH,
        )
        cls.chronology = load_source(
            "source5_fresh_phase_chronology_test", CHRONOLOGY_PATH,
        )

    def _actual_locked_empty_state(self, root: Path):
        controller = self.controller
        chronology = self.chronology
        campaign_id = "campaign-fresh-phase"
        host_id = "host-fresh-phase"
        prepared = {
            "campaign_id": campaign_id,
            "host_id": host_id,
            "output_root": root,
            "original_pins": {
                "campaign_id": campaign_id,
                "host_id": host_id,
                "spec": {"raw_sha256": "a" * 64},
            },
            "source5_execution_schema": controller.EXECUTION_SCHEMA_V4,
            "source5_execution_manifest_raw_sha256": "b" * 64,
            "source5_journal_event_ceiling": 256,
            "source5_journal_byte_ceiling": 1024 * 1024,
        }
        job = {
            "phase": "exploration", "host_id": host_id,
            "ordinal": 1, "run_id": "original-fresh-exploration-1",
        }
        context = types.SimpleNamespace(
            manifest={
                "schema": controller.EXECUTION_SCHEMA_V4,
                "campaign_id": campaign_id,
            },
            output_root=root, artifact_root=root, host_id=host_id,
            plan={"jobs": {"exploration": [job]}},
            chronology=chronology,
        )
        return context, prepared, job

    def test_fresh_phase_regression_class_and_method_names_are_unique(self) -> None:
        tree = ast.parse(Path(__file__).read_bytes(), filename=__file__)
        class_names = [
            node.name for node in tree.body if isinstance(node, ast.ClassDef)
        ]
        self.assertEqual(len(class_names), len(set(class_names)))
        owner = next(
            node for node in tree.body
            if isinstance(node, ast.ClassDef) and
            node.name == "Source5FreshPhaseStartBoundaryTests"
        )
        test_names = [
            node.name for node in owner.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and
            node.name.startswith("test_")
        ]
        self.assertEqual(len(test_names), len(set(test_names)))

    def test_fresh_start_uses_live_sourcea_fdlock_journal_state(self) -> None:
        controller = self.controller
        with tempfile.TemporaryDirectory(prefix="source5-fresh-start-") as temp:
            root = Path(temp)
            context, prepared, job = self._actual_locked_empty_state(root)
            phase_root = controller._phase_root(context, "exploration")
            with context.chronology.campaign_host_lock(
                    root, context.manifest["campaign_id"], context.host_id,
                    timeout_seconds=5) as lock:
                state = context.chronology._read_journal(lock, prepared)
                self.assertEqual(state["record_count"], 0)
                self.assertEqual(state["source5_seen_jobs"], set())
                start, records = controller._source5_validate_fresh_phase_start_locked(
                    context, lock, "exploration", [job],
                    {"prepared": prepared, "state": state},
                )
                self.assertEqual(start, 0)
                self.assertEqual(records, [])
                self.assertFalse(phase_root.exists())
                self.assertTrue(lock.active)

    def test_retained_root_without_original_ledger_cannot_fall_back_to_fresh(self) -> None:
        controller = self.controller
        with tempfile.TemporaryDirectory(prefix="source5-retained-missing-ledger-") as temp:
            root = Path(temp)
            context, prepared, job = self._actual_locked_empty_state(root)
            phase_root = controller._phase_root(context, "exploration")
            (phase_root / "job-records").mkdir(parents=True, mode=0o700)
            with context.chronology.campaign_host_lock(
                    root, context.manifest["campaign_id"], context.host_id,
                    timeout_seconds=5) as lock:
                context.chronology._read_journal(lock, prepared)
                with self.assertRaisesRegex(
                        controller.Source5CampaignError,
                        "missing its original ledger",
                ):
                    controller._source5_validate_resume_prefix_locked(
                        context, lock, "exploration", [job],
                    )

    def test_declared_future_helper_path_blocks_phase_start(self) -> None:
        controller = self.controller
        with tempfile.TemporaryDirectory(prefix="source5-future-catalogue-path-") as temp:
            future = Path(temp) / "aa" / "future-run" / "helper-input.json"
            future.parent.mkdir(parents=True, mode=0o700)
            future.write_bytes(b"unexplained")
            future.chmod(0o600)
            catalogue = {"rows": [{
                "role": "source5_helper_input",
                "phase": "aa", "run_id": "future-run",
                "origin_pin": None, "path": str(future),
            }]}
            budget_module = types.SimpleNamespace(
                FAILURE_WINDOW_ONLY_ROLES=frozenset(),
                validate_path_catalogue_manifest=lambda value: value,
                verify_path_catalogue_chunks=lambda value: value,
                iter_path_catalogue_rows=lambda value: iter(value["rows"]),
            )
            with self.assertRaisesRegex(
                    controller.Source5CampaignError,
                    "uncompleted original ordinal",
            ):
                controller._source5_assert_uncompleted_catalogue_paths_absent(
                    types.SimpleNamespace(scope="final_frozen", modules={}),
                    {"path_catalogue": catalogue}, budget_module, set(),
                )

    def test_phase_runners_check_future_catalogue_paths_before_authorization(self) -> None:
        tree = ast.parse(CONTROLLER_PATH.read_bytes(), filename=str(CONTROLLER_PATH))
        for name in ("run_fixed_phase", "run_pressure_phase", "run_soak_phase"):
            node = function(tree, name)
            guard_lines = [
                item.lineno for item in ast.walk(node)
                if isinstance(item, ast.Call) and
                isinstance(item.func, ast.Name) and
                item.func.id == "_source5_require_uncompleted_catalogue_paths_absent"
            ]
            authorization_lines = [
                item.lineno for item in ast.walk(node)
                if isinstance(item, ast.Call) and
                getattr(item.func, "attr", None) == "authorize_source5_job_locked"
            ]
            self.assertTrue(guard_lines, name)
            self.assertTrue(authorization_lines, name)
            self.assertLess(min(guard_lines), min(authorization_lines), name)



class Source5ResumePrefixControllerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.controller = load_source(
            "source5_resume_prefix_controller_test", CONTROLLER_PATH,
        )

    def _prefix_fixture(self, root: Path):
        controller = self.controller
        host_id = "host-resume"
        phase = "exploration"
        jobs = [
            {"phase": phase, "host_id": host_id,
             "ordinal": index + 1, "run_id": f"original-{index + 1}"}
            for index in range(2)
        ]
        phase_root = root / "phase"
        record_dir = phase_root / "job-records"
        record_dir.mkdir(parents=True, mode=0o700)
        ledger_path = phase_root / "controller-ledger.jsonl"
        ledger_path.write_bytes(b"ledger-placeholder\n")
        ledger_path.chmod(0o600)
        body = {"job": jobs[0], "qualification_eligible": False}
        record = {**body, "record_sha256": controller.sha256(
            controller.canonical_bytes(body),
        )}
        raw = controller.canonical_bytes(record)
        record_path = record_dir / f"{jobs[0]['run_id']}.json"
        record_path.write_bytes(raw)
        record_path.chmod(0o600)
        ack_pin = {
            "path": "/archive/acks/exploration/original-1.json",
            "raw_sha256": "a" * 64, "semantic_sha256": "b" * 64,
        }
        expected_epoch = "c" * 64
        state = {
            "head": "d" * 64,
            "record_count": 41,
            "source5_finished": {(phase, jobs[0]["run_id"]): {
                "authorization_id": "authorization-original-1",
                "record_sha256": record["record_sha256"],
            }},
        }
        prepared = {"source": {"source_tree_sha256": "e" * 64}}
        manifest_pin = {
            "path": "/inputs/execution.json", "raw_sha256": "f" * 64,
        }
        context = types.SimpleNamespace(
            manifest={
                "schema": controller.EXECUTION_SCHEMA_V4,
                "campaign_id": "campaign-resume",
            },
            manifest_pin=manifest_pin,
            host_id=host_id,
            modules={controller.EVIDENCE_BUDGET_SOURCE_PATH: object()},
            chronology=types.SimpleNamespace(
                source5_phase_resume_prefix_locked=lambda _lock, _pin, _phase: None,
                _source5_analysis_epoch=lambda _prepared: expected_epoch,
            ),
        )
        row = {
            "job": jobs[0],
            "record": {"path": str(record_path), "raw_sha256": controller.sha256(raw)},
            "record_sha256": record["record_sha256"],
            "authorization_id": "authorization-original-1",
            "job_terminal_head": record["record_sha256"],
            "ack_pin": ack_pin,
        }
        prefix = {
            "schema": "allocatbelt.application-source5-resume-prefix.v1",
            "campaign_id": "campaign-resume", "host_id": host_id,
            "phase": phase,
            "execution_manifest": {
                "path": manifest_pin["path"],
                "raw_sha256": manifest_pin["raw_sha256"],
            },
            "source_epoch": expected_epoch,
            "journal_head": state["head"],
            "journal_record_count": state["record_count"],
            "job_count": len(jobs), "next_index": 1,
            "completed_records": [row],
            "component_replay_required": True,
            "archive_reclaim_recheck_required": True,
            "qualification_eligible": False,
        }
        context.chronology.source5_phase_resume_prefix_locked = \
            lambda _lock, _pin, _phase: prefix
        return context, jobs, phase_root, record, raw, ack_pin, state, prepared

    def test_selected_source_manifest_rebuilds_only_its_exact_pinned_bytes(self) -> None:
        controller = self.controller
        schema = "allocatbelt.application-source-manifest.v5"
        source_body = {
            "schema": schema, "campaign_id": "campaign-source-pin",
            "host_id": "host-source-pin", "files": [],
        }
        source = {
            **source_body,
            "manifest_sha256": controller.sha256(
                controller.canonical_bytes(source_body),
            ),
        }
        raw = controller.canonical_bytes(source)
        context = types.SimpleNamespace(
            sources={"host-source-pin": source},
            source_manifest_pins={"host-source-pin": {
                "path": "/inputs/source-manifest.json",
                "raw_sha256": controller.sha256(raw),
            }},
            host_id="host-source-pin",
            modules={controller.EVIDENCE_BUDGET_SOURCE_PATH:
                     types.SimpleNamespace(SOURCE_SCHEMA=schema)},
        )
        self.assertEqual(
            controller._source5_selected_source_manifest_raw(context), raw,
        )
        context.source_manifest_pins["host-source-pin"]["raw_sha256"] = "0" * 64
        with self.assertRaisesRegex(
                controller.Source5CampaignError, "raw/semantic closure"):
            controller._source5_selected_source_manifest_raw(context)

    def test_resume_prefix_skips_only_the_exact_source_closed_original_prefix(self) -> None:
        controller = self.controller
        with tempfile.TemporaryDirectory(prefix="source5-resume-prefix-") as temp:
            context, jobs, phase_root, record, raw, ack_pin, state, prepared = \
                self._prefix_fixture(Path(temp))
            record_path = phase_root / "job-records" / f"{jobs[0]['run_id']}.json"
            closure = {
                "job_record": record, "job_record_raw": raw,
                "ack_pin": ack_pin,
            }
            finished = state["source5_finished"][("exploration", jobs[0]["run_id"])]
            with patch.object(controller, "_validate_locked_context",
                               return_value={"prepared": prepared, "state": state}), \
                 patch.object(controller, "_phase_root", return_value=phase_root), \
                 patch.object(controller, "_phase_ledger_records",
                              return_value=[record]), \
                 patch.object(controller, "_source5_job_record_byte_bound",
                              return_value=1024), \
                 patch.object(controller, "_source5_match_finished_record"), \
                 patch.object(controller, "_source5_verify_persisted_archive_read_closure",
                              return_value=closure), \
                 patch.object(controller, "_source5_verify_completed_archive_metadata"), \
                 patch.object(controller, "_source5_recheck_reclaimed_job_origins"):
                next_index, records = controller._source5_validate_resume_prefix_locked(
                    context, object(), "exploration", jobs,
                )
            self.assertEqual(next_index, 1)
            self.assertEqual(records, [record])
            self.assertEqual(record_path.read_bytes(), raw)

    def test_resume_prefix_rejects_an_unexplained_phase_root_child(self) -> None:
        controller = self.controller
        with tempfile.TemporaryDirectory(prefix="source5-resume-extra-") as temp:
            context, jobs, phase_root, _record, _raw, _ack, state, prepared = \
                self._prefix_fixture(Path(temp))
            unexpected = phase_root / "unlisted-output.json"
            unexpected.write_bytes(b"unlisted")
            unexpected.chmod(0o600)
            with patch.object(controller, "_validate_locked_context",
                               return_value={"prepared": prepared, "state": state}), \
                 patch.object(controller, "_phase_root", return_value=phase_root):
                with self.assertRaisesRegex(
                        controller.Source5CampaignError,
                        "retained phase root is unsafe or unexplained"):
                    controller._source5_validate_resume_prefix_locked(
                        context, object(), "exploration", jobs,
                    )



class Source5SoakJobRecordBoundTests(unittest.TestCase):
    def test_source_plan_soak_record_bound_accepts_job_without_mode(self) -> None:
        controller = load_source(
            "source5_soak_job_record_bound_controller_test", CONTROLLER_PATH,
        )
        recipe_tests = load_source(
            "source5_soak_job_record_bound_recipe_test",
            SOAK_RECIPE_TESTS_PATH,
        )
        soak_readback = load_source(
            "source5_soak_job_record_bound_readback_test", SOAK_READBACK_PATH,
        )
        with tempfile.TemporaryDirectory(
                prefix="source5-soak-job-record-bound-") as temporary:
            fixture = recipe_tests.SourceV5CliFixture(Path(temporary))
            job = fixture.job
            self.assertEqual(job["phase"], "soak")
            self.assertNotIn("mode", job)
            original_job_raw = controller.canonical_bytes(job)
            context = types.SimpleNamespace(
                source=fixture.manifests["host-1"],
                manifest={
                    "campaign_id": fixture.spec["campaign_id"],
                    "schema": "allocatbelt.application-source5-test-context.v1",
                },
                host_id="host-1",
                modules={"scripts/application-soak-readback.py": soak_readback},
                manifest_pin={"path": str(fixture.input_root / "execution.json")},
                spec_pin={"path": str(fixture.spec_path)},
                plan_pin={"path": str(fixture.plan_path)},
                observed_host_pin={
                    "path": str(fixture.input_root / "observed-host.json"),
                },
                source_root=fixture.root,
                input_root=fixture.input_root,
                artifact_root=fixture.root / "artifact-root",
                output_root=fixture.output,
            )
            metric_cache = controller._SOURCE5_JOB_METRIC_BOUND_CACHE
            previous_cache = dict(metric_cache)
            metric_cache.clear()
            try:
                bound = controller._source5_job_record_byte_bound(
                    context, "soak", job,
                )
                self.assertGreater(bound, 0)
                self.assertLessEqual(bound, 4 * 1024 * 1024)
                self.assertEqual(
                    controller.canonical_bytes(job), original_job_raw,
                )
                soak_keys = [key for key in metric_cache if key[1] == "soak"]
                self.assertEqual(len(soak_keys), 1)
                self.assertEqual(len(soak_keys[0]), 9)
                self.assertIsNone(soak_keys[0][4])
                self.assertEqual(
                    soak_keys[0][5], len(job["run_id"].encode("utf-8", "strict")),
                )
                with self.assertRaises(controller.Source5CampaignError):
                    controller._source5_job_record_byte_bound(
                        context, "unknown", job,
                    )
            finally:
                metric_cache.clear()
                metric_cache.update(previous_cache)


class ConcretePathBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.controller = load_source("concrete_path_source5_controller", CONTROLLER_PATH)
        cls.chronology = load_source("concrete_path_sourcea", CHRONOLOGY_PATH)

    def test_public_preparatory_builder_accepts_concrete_paths_and_preserves_existing_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="preparatory-concrete-path-") as name:
            root = Path(name)
            artifact_root = root / "artifacts"
            campaign_id = "component-path-guard"
            host_id = "host-a"
            output = artifact_root / campaign_id / "source5" / host_id
            output.mkdir(mode=0o700, parents=True)
            existing = output / "preparatory-execution-manifest-v1.json"
            raw = b"existing immutable manifest\n"
            existing.write_bytes(raw)
            existing.chmod(0o600)
            core = {"campaign_id": campaign_id, "host_id": host_id,
                    "artifact_root": str(artifact_root)}
            reservation = root / "storage-reservation.json"
            with self.assertRaisesRegex(self.controller.Source5CampaignError,
                                        "manifest already exists"):
                self.controller.build_source5_preparatory_execution_manifest(
                    core, reservation, output,
                )
            self.assertEqual(existing.read_bytes(), raw)
            for wrong_reservation, wrong_output in (
                    (str(reservation), output), (reservation, str(output))):
                with self.assertRaisesRegex(self.controller.Source5CampaignError,
                                            "builder inputs are malformed"):
                    self.controller.build_source5_preparatory_execution_manifest(
                        core, wrong_reservation, wrong_output,
                    )

    def test_captured_concrete_path_keeps_exact_size_mode_and_no_follow_checks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="captured-concrete-path-") as name:
            root = Path(name)
            path = root / "captured.bin"
            raw = b"captured object bytes\n"
            path.write_bytes(raw)
            path.chmod(0o600)
            self.assertEqual(b"".join(self.chronology._source5_evidence_chunks(
                path, len(raw), "concrete captured object", maximum_bytes=len(raw),
            )), raw)
            for wrong_count in (len(raw) - 1, len(raw) + 1):
                with self.assertRaises(self.chronology.ChronologyError):
                    list(self.chronology._source5_evidence_chunks(
                        path, wrong_count, "incorrect captured size",
                    ))
            alias = root / "alias.bin"
            alias.symlink_to(path)
            with self.assertRaises(self.chronology.ChronologyError):
                list(self.chronology._source5_evidence_chunks(
                    alias, len(raw), "symlink captured object",
                ))
            path.chmod(0o644)
            with self.assertRaises(self.chronology.ChronologyError):
                list(self.chronology._source5_evidence_chunks(
                    path, len(raw), "nonprivate captured object",
                ))


if __name__ == "__main__":
    unittest.main()
