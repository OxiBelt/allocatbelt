#!/usr/bin/env python3
"""Serialize SourceV5 capacity registration and fixed-confirmation launches.

This module records transactions made through its locked APIs. It does not
change campaign readiness, validate work launched outside these APIs, or claim
that the existing controller ledger proves pre-Popen ordering.
"""
from __future__ import annotations

import contextlib
import fcntl
import io
import functools
import hashlib
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import types
from pathlib import Path, PurePosixPath
from typing import Any, NamedTuple


SOURCE_SCHEMA = "allocatbelt.application-source-manifest.v5"
SPEC_SCHEMA = "allocatbelt.application-campaign-spec.v3"
PLAN_SCHEMA = "allocatbelt.application-campaign-plan.v3"
CAPACITY_COMPLETION_SCHEMA = "allocatbelt.application-capacity-stage-completion.v1"
CHRONOLOGY_SCHEMA = "allocatbelt.application-campaign-chronology.v2"
JOURNAL_SCHEMA = "allocatbelt.application-campaign-dispatch-event.v2"
SOURCE5_EXECUTION_SCHEMA = "allocatbelt.application-source5-campaign-execution.v1"
SOURCE5_EXECUTION_SCHEMA_V2 = "allocatbelt.application-source5-campaign-execution.v2"
SOURCE5_EXECUTION_SCHEMA_V3 = "allocatbelt.application-source5-campaign-execution.v3"
SOURCE5_HELPER_INPUT_SCHEMA = "allocatbelt.application-source5-helper-input.v1"
SOURCE5_JOB_RECORD_SCHEMA = "allocatbelt.application-source5-job-record.v1"
SOURCE5_PRESSURE_HELPER_PAYLOAD_SCHEMA_V2 = "allocatbelt.application-source5-pressure-helper-payload.v2"
SOURCE5_PROBE_CAPTURE_BUNDLE_SCHEMA = "allocatbelt.application-source5-probe-capture-bundle.v1"
SOURCE5_PRESSURE_RECIPE_SCHEMA_V2 = "allocatbelt.application-pressure-pair-recipe.v2"
SOURCE5_PROBE_CAPTURE_RECEIPT_SCHEMA = "allocatbelt.application-feedback-probe-capture.v2"
SOURCE5_ORIGIN_JOURNAL_RECEIPT_SCHEMA_V1 = "allocatbelt.application-source5-origin-journal-receipt.v1"
SOURCE5_HOST_JOURNAL_REQUEST_SCHEMA_V1 = "allocatbelt.application-source5-host-journal-request.v1"
SOURCE5_CAPTURED_EVIDENCE_SCHEMA_V1 = "allocatbelt.application-source5-captured-evidence.v1"
SOURCE5_JOURNAL_EVIDENCE_INDEX_SCHEMA_V1 = "allocatbelt.application-source5-journal-evidence-index.v1"
SOURCE5_JOURNAL_REPLAY_SCHEMA_V1 = "allocatbelt.application-source5-host-journal-structural-replay.v1"
SOURCE5_JOURNAL_ANCESTRY_SCHEMA_V1 = "allocatbelt.application-source5-journal-ancestry-proof.v1"
SOURCE5_JOURNAL_PROVENANCE_SCHEMA_V1 = "allocatbelt.application-source5-journal-provenance.v1"
SOURCE5_FEEDBACK_POLICY_ARTIFACT_SCHEMA_V1 = "allocatbelt.application-feedback-policy-artifact.v1"
SOURCE5_FEEDBACK_POLICY_ARTIFACT_SCHEMA_V2 = "allocatbelt.application-feedback-policy-artifact.v2"
SOURCE5_PREPARATION_SCHEMA_V1 = "allocatbelt.application-source5-preparation.v1"
SOURCE5_PREPARATION_CORE_SCHEMA_V1 = "allocatbelt.application-source5-preparation-core.v1"
SOURCE5_PREPARATION_CORE_SCHEMA_V2 = "allocatbelt.application-source5-preparation-core.v2"
CAPACITY_FLOOR_POLICY_ID = "application_capacity_relative_tenth_v1"
CHRONOLOGY_SOURCE_PATH = "scripts/application-campaign-chronology.py"
CAPACITY_STAGE_SOURCE_PATH = "scripts/application-capacity-stage.py"
CONTROLLER_SOURCE_PATH = "scripts/application-campaign.py"
PAIR_RUNNER_SOURCE_PATH = "scripts/run-application-pair.sh"

MAX_SPEC_BYTES = 32 * 1024 * 1024
MAX_PLAN_BYTES = 256 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_SCRIPT_BYTES = 8 * 1024 * 1024
MAX_ANALYZER_BYTES = 1024 * 1024 * 1024
MAX_COMPLETION_BYTES = 16 * 1024 * 1024
MAX_JOURNAL_BYTES = 256 * 1024 * 1024
MAX_JOURNAL_EVENTS = 100_000
MAX_EVENT_BYTES = 4 * 1024 * 1024
MAX_PROBE_CAPTURE_RECEIPT_BYTES = 16 * 1024 * 1024
MAX_SOURCE5_JOURNAL_INDEX_BYTES = MAX_PLAN_BYTES
# Prepared Source5 manifests get a plan-derived per-host event ceiling. These
# absolutes are implementation bounds only; origin storage proof remains a
# separate prerequisite and the legacy journal limits below stay unchanged.
MAX_SOURCE5_JOURNAL_EVENTS = MAX_JOURNAL_EVENTS * 8
MAX_SOURCE5_JOURNAL_BYTES = MAX_ANALYZER_BYTES
MAX_SOURCE5_JOURNAL_EVIDENCE_ENTRIES = MAX_SOURCE5_JOURNAL_EVENTS * 8
MAX_SOURCE5_JOURNAL_JSON_BYTES = MAX_PLAN_BYTES
MAX_SOURCE5_JOURNAL_SOURCE_MANIFEST_BYTES = MAX_MANIFEST_BYTES
MAX_SOURCE5_TYPED_SOURCE_FILES = 100_000
MAX_SOURCE5_TYPED_SOURCE_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_SOURCE5_TYPED_SYMLINK_BYTES = 4 * 1024
SOURCE_INVENTORY_SCHEMA = "allocatbelt.application-source-inventory.v1"
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_ENVIRONMENT_BYTES = 60 * 1024
MAX_PATH_BYTES = 4096
MAX_TIMEOUT_SECONDS = 24 * 60 * 60
DISPATCH_TERM_GRACE_SECONDS = 0.2
DISPATCH_KILL_GRACE_SECONDS = 1.0
DISPATCH_REAP_GRACE_SECONDS = 0.25
DISPATCH_POLL_INTERVAL_SECONDS = 0.01
DISPATCH_CLEANUP_TOTAL_SECONDS = (
    DISPATCH_TERM_GRACE_SECONDS + DISPATCH_KILL_GRACE_SECONDS +
    DISPATCH_REAP_GRACE_SECONDS
)
U64_MAX = (1 << 64) - 1
PROCESS_GROUP_CLEANUP_STATES = {"not_started", "clean", "unclean", "unverified"}
PROCESS_REAP_STATUSES = {"not_started", "owned_reaped", "not_reaped", "unverified"}
SOURCE5_JOURNAL_EVIDENCE_ROLES = frozenset({
    "evidence_index", "origin_receipt", "journal", "execution_manifest",
    "preparation", "prepared_completion", "spec_v3", "plan_v3", "source_manifest", "observed_host",
    "typed_source_file", "typed_source_symlink", "capacity_completion", "capacity_ledger",
    "capacity_request", "capacity_artifact", "capacity_receipt",
    "source5_helper_input", "source5_job_record", "capacity_host_receipt",
    "component_receipt",
    "fixed_pair_artifact", "pressure_pair_artifact", "source5_soak_artifact",
    "normal_app_output", "analysis_artifact", "opaque_trace",
})
SOURCE5_JOURNAL_DEPENDENCY_ROLES = (
    ("campaign_controller", "scripts/application-campaign.py"),
    ("campaign_inputs", "scripts/application-campaign-inputs.py"),
    ("chronology", CHRONOLOGY_SOURCE_PATH),
    ("pair_runner", PAIR_RUNNER_SOURCE_PATH),
    ("capacity_stage", CAPACITY_STAGE_SOURCE_PATH),
    ("source5_input_preparation", "scripts/application-source5-input-preparation.py"),
    ("source5_controller", "scripts/application-source5-campaign.py"),
    ("fixed_pair", "scripts/application-fixed-pair.py"),
    ("pressure_pair", "scripts/application-pressure-pair.py"),
    ("pressure_readback", "scripts/application-pressure-readback.py"),
    ("feedback_reader", "scripts/application-feedback-readback.py"),
    ("feedback_composer", "scripts/application-feedback-composition.py"),
    ("source5_soak", "scripts/application-source5-soak.py"),
    ("soak_readback", "scripts/application-soak-readback.py"),
    ("capacity_producer", "scripts/application-byte-capacity.py"),
    ("offline_dispatcher", "scripts/application-source5-offline-dispatch.py"),
)

EVENTS = (
    "capacity_stage_completed", "capacity_registered", "dispatch_authorized",
    "dispatch_bound", "dispatch_exited", "dispatch_failed",
    "dispatch_interrupted", "dispatch_timeout",
    "source5_authorized", "source5_app_started", "source5_app_terminal",
    "source5_job_terminal", "source5_analysis",
    "source5_prepared_capacity_registered",
)
DETAIL_FIELDS = {
    "capacity_stage_completed": {
        "capacity_completion", "capacity_ledger", "capacity_schedule_sha256",
        "entry_count", "entries", "qualification_eligible",
        "controller_chronology_proven",
    },
    "capacity_registered": {
        "capacity_completion", "capacity_ledger", "capacity_schedule_sha256",
        "entry_count", "entries", "qualification_eligible",
        "controller_chronology_proven", "capacity_stage_event_head",
    },
    "dispatch_authorized": {
        "authorization_id", "job_index", "job", "job_sha256", "member_role",
        "pair_members", "pair_members_sha256", "capacity_registration_head",
        "capacity_completion_raw_sha256", "capacity_ledger_raw_sha256",
        "capacity_ledger_terminal_head", "capacity_schedule_sha256", "runner",
        "argv", "cwd", "environment", "environment_sha256", "runner_output",
        "campaign_artifacts_root", "shebang_interpreter",
        "runtime_bindings", "runtime_validator", "fixed_global_control_baseline",
        "outer_deadline_seconds", "effective_timeout_seconds", "stdout_path", "stderr_path",
        "confirmation_owner_marker",
        "qualification_eligible",
    },
    "dispatch_bound": {
        "authorization_id", "job_run_id", "member_role", "pid", "start_ticks",
        "runner_path", "runner_sha256", "process_executable_path",
        "process_executable_sha256", "cwd", "cpu_affinity",
        "network_namespace_inode", "environment", "environment_sha256",
        "actual_environment_sha256",
        "process_report_nonce", "member_report_nonces", "caller_role",
        "pair_members_sha256", "capacity_registration_head",
        "qualification_eligible",
    },
    "dispatch_exited": {
        "authorization_id", "job_run_id", "member_role", "pid", "return_code",
        "status", "signal", "elapsed_ns", "stdout", "stderr",
        "stdout_sha256", "stderr_sha256", "stdout_size", "stderr_size",
        "process_reaped", "process_reap_status", "process_group_cleanup_status",
        "cleanup_error_sha256",
        "capacity_registration_head", "qualification_eligible",
    },
    "dispatch_failed": {
        "authorization_id", "job_run_id", "member_role", "pid", "return_code",
        "error_type", "error_sha256", "elapsed_ns", "process_reaped",
        "process_reap_status", "process_group_cleanup_status", "cleanup_error_sha256",
        "capacity_registration_head", "qualification_eligible",
    },
    "dispatch_interrupted": {
        "authorization_id", "job_run_id", "member_role", "pid", "signal",
        "return_code", "elapsed_ns", "process_reaped",
        "process_reap_status", "process_group_cleanup_status", "cleanup_error_sha256",
        "capacity_registration_head", "qualification_eligible",
    },
    "dispatch_timeout": {
        "authorization_id", "job_run_id", "member_role", "pid", "return_code",
        "elapsed_ns", "effective_timeout_seconds", "process_reaped",
        "process_reap_status", "process_group_cleanup_status", "cleanup_error_sha256",
        "capacity_registration_head", "qualification_eligible",
    },
    "source5_authorized": {
        "authorization_id", "campaign_id", "host_id", "phase", "job_index",
        "job", "job_sha256", "members", "members_sha256", "execution_manifest",
        "helper_input", "helper_module", "capacity_registration_head",
        "capacity_completion", "capacity_ledger_raw_sha256",
        "capacity_terminal_head", "capacity_schedule_sha256", "prerequisites",
        "outer_deadline_seconds", "effective_timeout_seconds",
        "input_snapshot_sha256", "output_root", "qualification_eligible",
    },
    "source5_app_started": {
        "authorization_id", "member_index", "descriptor", "pid", "start_ticks",
        "proof_sha256", "proof", "qualification_eligible",
    },
    "source5_app_terminal": {
        "authorization_id", "member_index", "descriptor", "pid", "status",
        "child_return_code", "signal", "cleanup", "terminal_monotonic_ns",
        "qualification_eligible",
    },
    "source5_job_terminal": {
        "authorization_id", "state", "blocked_reason", "component_sha256",
        "process_metrics_sha256", "started_count", "terminal_count",
        "qualification_eligible",
    },
    "source5_analysis": {
        "phase", "analysis", "analysis_sha256", "job_count", "job_set_sha256",
        "job_evidence_complete", "numeric_gates_passed", "phase_gate_passed",
        "campaign_qualification_eligible",
    },
    "source5_prepared_capacity_registered": {
        "campaign_id", "host_id", "completion", "provenance",
        "host_completion", "host_verification", "capacity_ledger",
        "capacity_schedule_sha256", "entries", "qualification_eligible",
        "controller_chronology_proven",
    },
}


class ChronologyError(ValueError):
    """A pinned input, private lock, dispatch transaction, or journal is invalid."""


class Source5DeadlineExceeded(ChronologyError):
    """An authorized Source5 helper exceeded its active monotonic wall bound."""


class _Source5DeadlineWatchdog:
    """Enforce one authorization deadline across synchronous helper work."""

    def __init__(self, deadline_ns: int):
        self.deadline_ns = deadline_ns
        self.expired = False
        self.lifecycle_failed = False
        self.failure_reason: str | None = None
        self._lifecycle_interrupt: KeyboardInterrupt | None = None
        self._old_handler: Any = None
        self._active = False
        self._defer_depth = 0
        self._cancel_timer = threading.Event()
        self._timer_thread: threading.Thread | None = None
        self._main_thread_id: int | None = None
        self._old_mask: set[signal.Signals] | None = None
        self._sender_lock = threading.Lock()
        self._sender_enabled = False
        self._sender_fenced = False
        self._handler_installed = False
        self._signal_blocked = False
        self._thread_started = False
        self._restoration_complete = False

    def _fail_lifecycle(
        self, reason: str, error: BaseException | None = None,
    ) -> None:
        self.lifecycle_failed = True
        if self.failure_reason is None:
            self.failure_reason = reason
        if isinstance(error, KeyboardInterrupt) and self._lifecycle_interrupt is None:
            self._lifecycle_interrupt = error

    def _attempt_teardown(self, reason: str, operation, default=None):
        try:
            return operation()
        except BaseException as error:
            self._fail_lifecycle(reason, error)
            return default

    def _block_signal(self) -> bool:
        for _attempt in range(2):
            try:
                signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR2})
                self._signal_blocked = True
                return True
            except BaseException as error:
                self._fail_lifecycle("signal_mask_block_failed", error)
        return False

    def _close_sender(self) -> None:
        def set_cancel() -> bool:
            self._cancel_timer.set()
            return True

        def fence_sender() -> bool:
            with self._sender_lock:
                self._sender_enabled = False
            self._sender_fenced = True
            return True

        try:
            # Cancellation and fencing are separate. An interrupted wakeup
            # must still run the lock-protected sender fence in `finally`.
            cancelled = self._attempt_teardown(
                "timer_cancellation_failed", set_cancel, False,
            )
            if not cancelled:
                self._attempt_teardown("timer_cancellation_failed", set_cancel, False)
        except BaseException as error:
            self._fail_lifecycle("timer_cancellation_failed", error)
        finally:
            self._attempt_teardown(
                "timer_sender_fence_failed", fence_sender, False,
            )

    def _sender_alive(self, thread: threading.Thread) -> bool:
        try:
            return thread.is_alive()
        except BaseException as error:
            self._fail_lifecycle("timer_liveness_unverified", error)
            return True

    def _join_sender(self) -> None:
        thread = self._timer_thread
        if thread is None:
            return
        if not self._thread_started and not self._sender_alive(thread):
            return
        try:
            thread.join(timeout=0.25)
        except BaseException as error:
            self._fail_lifecycle("timer_join_failed", error)
        if self._sender_alive(thread):
            self._fail_lifecycle("timer_join_timeout")
            # The sender gate is already closed. Retry once to handle a
            # transient join fault while retaining a finite teardown bound.
            try:
                thread.join(timeout=0.25)
            except BaseException as error:
                self._fail_lifecycle("timer_join_failed", error)
        if self._sender_alive(thread):
            self._fail_lifecycle("timer_thread_unverified")

    def _drain_pending_signal(self) -> bool:
        for _attempt in range(2):
            try:
                pending = signal.sigpending()
            except BaseException as error:
                self._fail_lifecycle("pending_signal_query_failed", error)
                continue
            if signal.SIGUSR2 not in pending:
                return True
            try:
                received = signal.sigwait({signal.SIGUSR2})
                if received != signal.SIGUSR2:
                    self._fail_lifecycle("pending_signal_drain_mismatch")
            except BaseException as error:
                self._fail_lifecycle("pending_signal_drain_failed", error)
        try:
            return signal.SIGUSR2 not in signal.sigpending()
        except BaseException as error:
            self._fail_lifecycle("pending_signal_query_failed", error)
            return False

    def _restore_signal_state(self) -> None:
        try:
            self._restore_signal_state_steps()
        except BaseException as error:
            self._fail_lifecycle("watchdog_teardown_interrupted", error)
            # Retry the independent finite cleanup stages. Each stage has its
            # own boundary so one failure cannot bypass the remaining rollback.
            try:
                self._restore_signal_state_steps()
            except BaseException as retry_error:
                self._fail_lifecycle("watchdog_teardown_retry_interrupted", retry_error)
        finally:
            self._active = False

    def _restore_signal_state_steps(self) -> None:
        blocked = self._attempt_teardown(
            "signal_mask_block_failed", self._block_signal, False,
        )
        self._attempt_teardown("timer_sender_fence_failed", self._close_sender)
        if not self._sender_fenced:
            self._attempt_teardown("timer_sender_fence_failed", self._close_sender)
        self._attempt_teardown("timer_join_failed", self._join_sender)
        drained = False
        if blocked and self._sender_fenced:
            drained = self._attempt_teardown(
                "pending_signal_drain_failed", self._drain_pending_signal, False,
            )

        handler_restored = not self._handler_installed
        if blocked and self._sender_fenced and self._handler_installed:
            for _attempt in range(2):
                def restore_handler() -> bool:
                    signal.signal(signal.SIGUSR2, self._old_handler)
                    self._handler_installed = False
                    return True

                if self._attempt_teardown(
                    "signal_handler_restore_failed", restore_handler, False,
                ):
                    handler_restored = True
                    break

        # Keep SIGUSR2 blocked if sender, pending state, or handler cannot be
        # verified. The caller records a blocked authorization in that state.
        if blocked and self._sender_fenced and drained and handler_restored and \
                self._old_mask is not None:
            restored = False
            for _attempt in range(2):
                def restore_mask() -> bool:
                    signal.pthread_sigmask(signal.SIG_SETMASK, self._old_mask)
                    self._signal_blocked = signal.SIGUSR2 in self._old_mask
                    return True

                if self._attempt_teardown(
                    "signal_mask_restore_failed", restore_mask, False,
                ):
                    restored = True
                    break
            if not restored:
                self._signal_blocked = True
            self._restoration_complete = restored
        else:
            self._fail_lifecycle("signal_state_unverified")
            self._signal_blocked = blocked
            self._restoration_complete = False

    def _on_timeout_signal(self, _signum: int, _frame: Any) -> None:
        self.expired = True
        if self._defer_depth == 0:
            raise Source5DeadlineExceeded(
                "Source5 helper exceeded its effective authorization deadline",
            )

    def _wait_for_deadline(self) -> None:
        remaining_ns = self.deadline_ns - time.monotonic_ns()
        if remaining_ns > 0 and self._cancel_timer.wait(remaining_ns / 1_000_000_000):
            return
        if self._cancel_timer.is_set():
            return
        self.expired = True
        try:
            with self._sender_lock:
                if self._sender_enabled and not self._cancel_timer.is_set() and \
                        self._main_thread_id is not None:
                    signal.pthread_kill(self._main_thread_id, signal.SIGUSR2)
        except BaseException as error:
            self._fail_lifecycle("deadline_signal_send_failed", error)

    def __enter__(self) -> "_Source5DeadlineWatchdog":
        if not (threading.current_thread() is threading.main_thread() and
                hasattr(signal, "pthread_kill") and hasattr(signal, "pthread_sigmask")):
            self._fail_lifecycle("signal_api_unavailable")
            raise ChronologyError(
                "Source5 active wall deadlines require a main-thread targeted signal API",
            )
        try:
            old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR2})
        except BaseException as error:
            self._fail_lifecycle("signal_mask_setup_failed")
            raise ChronologyError(
                "Source5 deadline watchdog could not establish its signal mask",
            ) from error
        self._signal_blocked = True
        self._old_mask = set(old_mask)
        try:
            require(signal.SIGUSR2 not in old_mask,
                    "Source5 active wall deadline cannot run with SIGUSR2 blocked")
            previous = signal.getsignal(signal.SIGUSR2)
            require(previous in (signal.SIG_DFL, None),
                    "Source5 active wall deadline cannot replace a custom SIGUSR2 handler")
            remaining_ns = self.deadline_ns - time.monotonic_ns()
            if remaining_ns <= 0:
                self.expired = True
                raise Source5DeadlineExceeded(
                    "Source5 job deadline expired before its authorized helper call",
                )
            self._old_handler = previous
            self._main_thread_id = threading.main_thread().ident
            signal.signal(signal.SIGUSR2, self._on_timeout_signal)
            self._handler_installed = True
            self._active = True
            with self._sender_lock:
                self._sender_enabled = True
            self._timer_thread = threading.Thread(
                target=self._wait_for_deadline,
                name="allocatbelt-source5-deadline",
                daemon=True,
            )
            self._timer_thread.start()
            self._thread_started = True
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
            self._signal_blocked = False
        except BaseException as error:
            self._fail_lifecycle("watchdog_setup_failed", error)
            if self._handler_installed or self._thread_started:
                self._restore_signal_state()
            else:
                restored = False
                for _attempt in range(2):
                    try:
                        signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
                        self._signal_blocked = signal.SIGUSR2 in old_mask
                        restored = True
                        break
                    except BaseException:
                        self._fail_lifecycle("signal_mask_restore_failed")
                if not restored:
                    self._signal_blocked = True
            if isinstance(error, KeyboardInterrupt):
                raise
            raise ChronologyError(
                "Source5 deadline watchdog setup failed with authorization blocked",
            ) from error
        return self

    @contextlib.contextmanager
    def defer_during_journal_append(self):
        require(self._active, "Source5 deadline watchdog is not active")
        old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR2})
        self._defer_depth += 1
        try:
            yield
        finally:
            self._defer_depth -= 1
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)

    def raise_if_expired(self) -> None:
        if self.expired or time.monotonic_ns() >= self.deadline_ns:
            self.expired = True
            raise Source5DeadlineExceeded(
                "Source5 helper exceeded its effective authorization deadline",
            )

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        try:
            try:
                if not self._restoration_complete and (
                    self._active or self._handler_installed or self._timer_thread is not None
                ):
                    self._restore_signal_state()
            except BaseException as error:
                self._fail_lifecycle("watchdog_exit_interrupted", error)
            finally:
                if not self._restoration_complete:
                    self._attempt_teardown(
                        "watchdog_exit_retry_interrupted",
                        self._restore_signal_state,
                    )
                self._active = False
        except BaseException as error:
            self._fail_lifecycle("watchdog_exit_interrupted", error)
            self._active = False
        if self.lifecycle_failed:
            if self._lifecycle_interrupt is not None:
                raise self._lifecycle_interrupt
            raise ChronologyError(
                "Source5 deadline watchdog lifecycle is unverified; authorization is blocked",
            )
        if exc_type is None and time.monotonic_ns() >= self.deadline_ns:
            self.expired = True
            raise Source5DeadlineExceeded(
                "Source5 helper exceeded its effective authorization deadline",
            )
        return False


class ProcessCleanupResult(NamedTuple):
    process_reaped: bool
    process_reap_status: str
    return_code: int | None
    process_group_cleanup_status: str
    error_message: str | None


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ChronologyError(message)


def canonical_bytes(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ChronologyError(f"value is not canonical JSON: {error}") from error
    return (encoded + "\n").encode("ascii")


def _json_copy(value: object) -> Any:
    return json.loads(canonical_bytes(value))


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: object, label: str) -> str:
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
            f"{label} is not a lower-case SHA-256 digest")
    return value


def _token(value: object, label: str, maximum: int = 128) -> str:
    require(type(value) is str and 0 < len(value) <= maximum and
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value) is not None,
            f"{label} is malformed")
    return value


def _uint(value: object, label: str, *, positive: bool = False,
          maximum: int = U64_MAX) -> int:
    require(type(value) is int and 0 <= value <= maximum,
            f"{label} is not a bounded unsigned integer")
    require(not positive or value > 0, f"{label} must be positive")
    return value


def _exact(value: object, keys: set[str], label: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == keys,
            f"{label} has an unexpected field set")
    return value


def _path_text(path: Path, label: str) -> str:
    value = str(path)
    encoded = value.encode("utf-8", "strict")
    require(len(encoded) <= MAX_PATH_BYTES and "\x00" not in value and
            not any(ord(character) < 32 or ord(character) == 127 for character in value),
            f"{label} is not bounded path text")
    return value


def _relative(value: object, label: str) -> PurePosixPath:
    require(type(value) is str and value and "\\" not in value and "\x00" not in value,
            f"{label} is malformed")
    path = PurePosixPath(value)
    require(not path.is_absolute() and path.as_posix() == value and
            all(part not in ("", ".", "..") for part in path.parts),
            f"{label} is not a normalized relative path")
    return path


def _within(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except ValueError:
        return False


def _read_stable(path: Path, label: str, maximum: int) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        before_path = path.lstat()
        require(stat.S_ISREG(before_path.st_mode), f"{label} must be a regular nonsymlink file")
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ChronologyError(f"cannot safely open {label}: {error}") from error
    try:
        before = os.fstat(descriptor)
        key = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size,
                            item.st_mtime_ns, item.st_ctime_ns)
        require(stat.S_ISREG(before.st_mode) and key(before) == key(before_path),
                f"{label} changed while opening")
        require(0 <= before.st_size <= maximum, f"{label} exceeds its finite size bound")
        chunks: list[bytes] = []
        count = 0
        while count < before.st_size:
            block = os.read(descriptor, min(1024 * 1024, before.st_size - count))
            require(bool(block), f"{label} was truncated while reading")
            chunks.append(block)
            count += len(block)
        after = os.fstat(descriptor)
        after_path = path.lstat()
        require(key(before) == key(after) == key(after_path) and count == before.st_size,
                f"{label} changed while reading")
        return b"".join(chunks), before
    finally:
        os.close(descriptor)


def _parse_object(raw: bytes, label: str, maximum: int, *, canonical: bool = True) -> dict[str, Any]:
    require(len(raw) <= maximum, f"{label} exceeds its finite byte bound")
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise ChronologyError(f"{label} is not valid JSON: {error}") from error
    require(type(value) is dict, f"{label} must be an object")
    if canonical:
        require(canonical_bytes(value) == raw, f"{label} is not canonical JSON")
    return value


def _read_pin(pin: object, label: str, maximum: int) -> tuple[dict[str, Any], Path, bytes, str]:
    value = _exact(pin, {"path", "sha256"}, f"{label} pin")
    path = Path(value["path"])
    _path_text(path, f"{label} path")
    require(path.is_absolute(), f"{label} path must be absolute")
    try:
        require(path.resolve(strict=True) == path,
                f"{label} path contains a symlink or path alias")
    except OSError as error:
        raise ChronologyError(f"{label} path is unavailable: {error}") from error
    expected = _digest(value["sha256"], f"{label} raw SHA-256")
    raw, _info = _read_stable(path, label, maximum)
    raw_sha = sha256_bytes(raw)
    require(raw_sha == expected, f"{label} differs from its caller pin")
    return _parse_object(raw, label, maximum), path, raw, raw_sha


def _safe_root(path: Path, label: str) -> Path:
    _path_text(path, label)
    try:
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode), f"{label} must be a real directory")
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ChronologyError(f"{label} is unavailable: {error}") from error
    require(resolved == path, f"{label} contains a symlink or path alias")
    return resolved


def _ensure_private_directory(path: Path) -> None:
    if path.exists() or path.is_symlink():
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and
                info.st_uid == os.getuid(),
                f"private directory {path} must be an owned real directory with mode 0700")
        require(path.resolve(strict=True) == path, f"private directory {path} is aliased")
        return
    path.mkdir(mode=0o700)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and
            info.st_uid == os.getuid(), f"cannot establish private directory {path}")
    _fsync_directory(path.parent)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                         getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_exclusive(path: Path, raw: bytes, mode: int = 0o600) -> None:
    require(not path.exists() and not path.is_symlink(), f"refusing to replace {path}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    try:
        os.fchmod(descriptor, mode)
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


_LOCK_OWNER = object()
_LIVE_LOCK_TOKENS: dict[int, tuple[object, int, int, int, Any, Path, str, str, Path, Path]] = {}
_LOCK_CACHED_STATES: dict[int, tuple[object, dict[str, Any]]] = {}


class CampaignHostLock:
    """An fd-owned flock token; locked APIs reject caller booleans and other objects."""

    __slots__ = (
        "output_root", "campaign_id", "host_id", "directory", "lock_path", "fd",
        "active", "held", "_owner", "_fd_key", "_operation_lock",
    )

    def __init__(self, output_root: Path, campaign_id: str, host_id: str,
                 directory: Path, lock_path: Path, fd: int):
        self.output_root = output_root
        self.campaign_id = campaign_id
        self.host_id = host_id
        self.directory = directory
        self.lock_path = lock_path
        self.fd = fd
        self.active = True
        self.held = True
        self._owner = _LOCK_OWNER
        self._operation_lock = threading.Lock()
        info = os.fstat(fd)
        self._fd_key = (info.st_dev, info.st_ino)
        _LIVE_LOCK_TOKENS[id(self)] = (self, fd, info.st_dev, info.st_ino,
                                       self._operation_lock, output_root, campaign_id,
                                       host_id, directory, lock_path)

    def __enter__(self) -> CampaignHostLock:
        require(self.active and _lock_token_is_live(self),
                "campaign/host fd-owned lock token is not active")
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        if not self.active:
            return
        token = _LIVE_LOCK_TOKENS.get(id(self))
        operation_lock = token[4] if token is not None and token[0] is self else self._operation_lock
        with operation_lock:
            if not self.active:
                return
            try:
                if self.held:
                    fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                token = _LIVE_LOCK_TOKENS.get(id(self))
                if token is not None and token[0] is self:
                    del _LIVE_LOCK_TOKENS[id(self)]
                state_token = _LOCK_CACHED_STATES.get(id(self))
                if state_token is not None and state_token[0] is self:
                    del _LOCK_CACHED_STATES[id(self)]
                os.close(self.fd)
                self.active = False
                self.held = False


def _lock_token_is_live(lock: object) -> bool:
    if type(lock) is not CampaignHostLock or getattr(lock, "_owner", None) is not _LOCK_OWNER:
        return False
    token = _LIVE_LOCK_TOKENS.get(id(lock))
    if token is None or token[0] is not lock:
        return False
    try:
        info = os.fstat(token[1])
    except OSError:
        return False
    return token[1] == getattr(lock, "fd", None) and \
        (info.st_dev, info.st_ino) == (token[2], token[3]) == getattr(lock, "_fd_key", None) and \
        getattr(lock, "_operation_lock", None) is token[4] and \
        (getattr(lock, "output_root", None), getattr(lock, "campaign_id", None),
         getattr(lock, "host_id", None), getattr(lock, "directory", None),
         getattr(lock, "lock_path", None)) == token[5:]


def _serialize_locked_api(function: Any) -> Any:
    @functools.wraps(function)
    def invoke(lock: CampaignHostLock, *args: Any, **kwargs: Any) -> Any:
        require(_lock_token_is_live(lock),
                "locked chronology API requires its active fd-owned CampaignHostLock token")
        token = _LIVE_LOCK_TOKENS[id(lock)]
        with token[4]:
            return function(lock, *args, **kwargs)
    return invoke


def _cached_lock_state(lock: CampaignHostLock) -> dict[str, Any] | None:
    token = _LOCK_CACHED_STATES.get(id(lock))
    return token[1] if token is not None and token[0] is lock else None


def _set_cached_lock_state(lock: CampaignHostLock, state: dict[str, Any]) -> None:
    _LOCK_CACHED_STATES[id(lock)] = (lock, state)


_AUTH_OWNER = object()
_AUTHORIZATION_TOKENS: dict[int, dict[str, Any]] = {}
_AUTHORIZATION_TOKEN_LOCK = threading.Lock()


class DispatchAuthorization:
    """One-use in-process capability produced by a durable authorization event."""

    __slots__ = ("lock", "prepared", "plan_pin", "spec_pin", "source_root",
                 "input_root", "observed_host_pin", "capacity_output_root",
                 "completion_pin", "_details", "start_monotonic_ns", "used", "_owner")

    def __init__(self, lock: CampaignHostLock, prepared: dict[str, Any],
                 plan_pin: dict[str, Any], spec_pin: dict[str, Any],
                 source_root: Path, input_root: Path, observed_host_pin: dict[str, Any],
                 capacity_output_root: Path, completion_pin: dict[str, Any],
                 details: dict[str, Any], start_monotonic_ns: int):
        self.lock = lock
        self.prepared = prepared
        self.plan_pin = plan_pin
        self.spec_pin = spec_pin
        self.source_root = source_root
        self.input_root = input_root
        self.observed_host_pin = observed_host_pin
        self.capacity_output_root = capacity_output_root
        self.completion_pin = completion_pin
        self._details = _json_copy(details)
        self.start_monotonic_ns = start_monotonic_ns
        self.used = False
        self._owner = _AUTH_OWNER
        with _AUTHORIZATION_TOKEN_LOCK:
            _AUTHORIZATION_TOKENS[id(self)] = {
                "object": self, "lock": lock,
                "snapshot": _authorization_snapshot(self), "consumed": False,
            }

    @property
    def details(self) -> dict[str, Any]:
        """Return a detached copy of the durable authorization details."""
        return _json_copy(self._details)


def _authorization_snapshot(authorization: DispatchAuthorization) -> bytes:
    prepared = authorization.prepared
    value = {
        "plan_pin": authorization.plan_pin, "spec_pin": authorization.spec_pin,
        "source_root": str(authorization.source_root),
        "input_root": str(authorization.input_root),
        "host_id": prepared["host_id"], "output_root": str(prepared["output_root"]),
        "observed_host_pin": authorization.observed_host_pin,
        "capacity_output_root": str(authorization.capacity_output_root),
        "completion_pin": authorization.completion_pin,
        "details": authorization.details,
        "start_monotonic_ns": authorization.start_monotonic_ns,
        "original_pins": prepared["original_pins"],
    }
    return canonical_bytes(value)


def _consume_authorization(lock: CampaignHostLock, authorization: object) -> DispatchAuthorization:
    require(type(authorization) is DispatchAuthorization and
            getattr(authorization, "_owner", None) is _AUTH_OWNER,
            "launch requires a module-issued one-use DispatchAuthorization")
    with _AUTHORIZATION_TOKEN_LOCK:
        token = _AUTHORIZATION_TOKENS.get(id(authorization))
        require(token is not None and token["object"] is authorization and
                token["lock"] is lock and not token["consumed"] and not authorization.used,
                "dispatch authorization is foreign, belongs to another lock, or was already consumed")
        require(token["snapshot"] == _authorization_snapshot(authorization),
                "dispatch authorization was modified after its durable journal event")
        token["consumed"] = True
        authorization.used = True
    return authorization


def _ensure_private_tree(root: Path, directory: Path) -> None:
    root = _safe_root(root, "private campaign output root")
    _path_text(directory, "private output directory")
    require(directory.is_absolute() and _within(root, directory),
            "private output directory escaped its campaign root")
    relative = directory.relative_to(root)
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.exists() or cursor.is_symlink():
            info = cursor.lstat()
            require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and
                    info.st_uid == os.getuid() and cursor.resolve(strict=True) == cursor,
                    f"private output path component {cursor} is not an owned mode-0700 directory")
        else:
            cursor.mkdir(mode=0o700)
            info = cursor.lstat()
            require(stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid(),
                    f"cannot establish private output directory {cursor}")
            _fsync_directory(cursor.parent)


def _verify_owner_marker(prepared: dict[str, Any], owner_pin: object,
                         registration_head: str, *, create: bool) -> None:
    pin = _exact(owner_pin, {"path", "sha256"}, "confirmation ownership marker pin")
    phase_dir = _phase_directory(prepared)
    expected_path = phase_dir / ".chronology-owner.json"
    require(pin["path"] == str(expected_path),
            "confirmation owner marker path differs from the selected host directory")
    body = _owner_body(prepared, registration_head)
    raw = canonical_bytes(body)
    raw_sha = sha256_bytes(raw)
    require(pin["sha256"] == raw_sha, "confirmation owner marker hash differs")
    path = expected_path
    if not path.exists() and not path.is_symlink() and create:
        _write_exclusive(path, raw, 0o400)
    captured, info = _read_stable(path, "confirmation chronology owner marker", 64 * 1024)
    require(stat.S_IMODE(info.st_mode) == 0o400 and info.st_uid == os.getuid() and
            captured == raw and sha256_bytes(captured) == raw_sha,
            "confirmation directory is owned by a different or prior transaction")


def _ensure_confirmation_host_directory(prepared: dict[str, Any], owner_pin: object,
                                        registration_head: str) -> None:
    phase_dir = _phase_directory(prepared)
    _ensure_private_tree(prepared["output_root"], phase_dir.parent)
    _ensure_private_tree(prepared["output_root"], phase_dir)
    _verify_owner_marker(prepared, owner_pin, registration_head, create=True)


def _write_runtime_binding_file(output_root: Path, path: Path, raw: bytes) -> dict[str, str]:
    require(len(raw) <= 16 * 1024 * 1024, "runtime process binding manifest exceeds its finite bound")
    _ensure_private_tree(output_root, path.parent)
    _write_exclusive(path, raw, 0o600)
    captured, info = _read_stable(path, "chronology runtime binding manifest", 16 * 1024 * 1024)
    require(stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid() and captured == raw,
            "runtime binding manifest was not atomically persisted with private permissions")
    return {"path": str(path), "sha256": sha256_bytes(raw)}


def _verify_runtime_binding_file(pin: object, expected_raw: bytes,
                                 output_root: Path) -> None:
    value = _exact(pin, {"path", "sha256", "size"}, "runtime bindings file pin")
    path = Path(value["path"])
    _path_text(path, "runtime bindings file path")
    require(_within(output_root, path), "runtime binding manifest escaped campaign output")
    raw, info = _read_stable(path, "chronology runtime binding manifest", 16 * 1024 * 1024)
    require(stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid() and
            raw == expected_raw and len(raw) == value["size"] and
            sha256_bytes(raw) == _digest(value["sha256"], "runtime bindings raw SHA-256"),
            "runtime binding manifest bytes differ from the pinned original recipes")


def _live_process_identity(
    process: subprocess.Popen[bytes], stage_module: types.ModuleType,
    expected_executable: dict[str, str],
    expected_cwd: str, affinity: list[int], network_namespace_inode: int,
    expected_environment: dict[str, str],
    timeout_seconds: float = 1.0,
) -> dict[str, Any]:
    pid = process.pid
    require(type(pid) is int and 0 < pid <= (1 << 31) - 1,
            "direct pair-runner Popen returned an invalid PID")
    proc = Path(f"/proc/{pid}")
    deadline = time.monotonic() + timeout_seconds
    first_start_ticks: int | None = None
    while time.monotonic() < deadline:
        if _leader_exit_status_unreaped(process) is not None:
            break
        try:
            stat_text = (proc / "stat").read_text(encoding="ascii")
            tail = stat_text[stat_text.rfind(")") + 2:].split()
            require(len(tail) > 19, "pair-runner proc stat is truncated")
            start_ticks = int(tail[19])
            if first_start_ticks is None:
                first_start_ticks = start_ticks
            require(first_start_ticks == start_ticks,
                    "pair-runner PID was reused during process binding")
            executable = Path(os.readlink(proc / "exe")).resolve(strict=True)
            observed_cwd = os.readlink(proc / "cwd")
            if (str(executable) == expected_executable["path"] and
                    observed_cwd == expected_cwd):
                observer = getattr(stage_module, "_read_pid_identity", None)
                require(callable(observer), "captured stage lacks live process observation")
                observed = observer(
                    pid, executable, expected_executable["sha256"], expected_environment,
                )
                require(observed["start_ticks"] == start_ticks and observed["cwd"] == expected_cwd and
                        observed["executable_sha256"] == expected_executable["sha256"],
                        "captured stage process observer returned a different runner identity")
                require(observed["cpu_affinity"] == affinity and
                        observed["network_namespace_inode"] == network_namespace_inode and
                        observed["environment"] == expected_environment,
                        "actual pair-runner affinity or network namespace differs from the observed host")
                check_stat = (proc / "stat").read_text(encoding="ascii")
                check_tail = check_stat[check_stat.rfind(")") + 2:].split()
                require(int(check_tail[19]) == start_ticks and
                        _leader_exit_status_unreaped(process) is None,
                        "pair-runner PID/start identity changed during live observation")
                return {
                    "pid": pid, "start_ticks": start_ticks,
                    "process_executable_path": str(executable),
                    "process_executable_sha256": observed["executable_sha256"],
                    "cwd": observed["cwd"], "cpu_affinity": observed["cpu_affinity"],
                    "network_namespace_inode": observed["network_namespace_inode"],
                    "environment": observed["environment"],
                }
        except FileNotFoundError:
            break
        except (OSError, UnicodeError, ValueError, IndexError) as error:
            if _leader_exit_status_unreaped(process) is not None:
                break
            raise ChronologyError(f"cannot bind live pair-runner process: {error}") from error
        time.sleep(0.005)
    raise ChronologyError("direct pair-runner exited or failed live PID/start/executable binding")


def _leader_exit_status_unreaped(process: subprocess.Popen[bytes]) -> Any | None:
    """Observe runner exit while retaining its PID as the process-group owner."""
    _require_owned_child_wait_semantics()
    require(process.returncode is None,
            "pair-runner leader was reaped before process-group cleanup completed")
    try:
        result = os.waitid(os.P_PID, process.pid,
                          os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError as error:
        raise ChronologyError(
            "pair-runner ownership was lost before its process group was verified"
        ) from error
    except OSError as error:
        raise ChronologyError(f"cannot observe unreaped pair-runner exit: {error}") from error
    if result is not None and result.si_pid == process.pid:
        return result
    return None


def _require_owned_child_wait_semantics() -> None:
    require(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL,
            "fixed dispatch requires the default SIGCHLD disposition to preserve child ownership")
    require(callable(getattr(os, "waitid", None)) and hasattr(os, "WNOWAIT"),
            "fixed dispatch requires waitid(WNOWAIT) process ownership")


def _owned_session_members(session_id: int) -> tuple[list[int], list[int]]:
    """Return live PIDs in the runner PGID and live session members that escaped it."""
    group_members: list[int] = []
    escaped_members: list[int] = []
    try:
        entries = list(os.scandir("/proc"))
    except OSError as error:
        raise ChronologyError(f"cannot inspect process ownership during runner cleanup: {error}") from error
    saw_leader = False
    for entry in entries:
        if not entry.name.isdecimal():
            continue
        pid = int(entry.name)
        try:
            with open(f"/proc/{entry.name}/stat", encoding="ascii") as stat_file:
                stat_line = stat_file.read(8192)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ChronologyError(
                f"cannot inspect process {pid} during runner cleanup: {error}"
            ) from error
        closing = stat_line.rfind(")")
        require(closing >= 0, f"cannot parse process {pid} during runner cleanup")
        fields = stat_line[closing + 1 :].split()
        require(len(fields) >= 4, f"cannot parse process identity for {pid} during runner cleanup")
        state = fields[0]
        try:
            process_group_id = int(fields[2])
            observed_session_id = int(fields[3])
        except ValueError as error:
            raise ChronologyError(f"cannot parse process group for {pid} during runner cleanup") from error
        if pid == session_id:
            require(process_group_id == session_id and observed_session_id == session_id,
                    "pair-runner leader no longer anchors its original session")
            saw_leader = True
        if observed_session_id != session_id or state in {"Z", "X"}:
            continue
        if process_group_id == session_id:
            group_members.append(pid)
        else:
            escaped_members.append(pid)
    require(saw_leader, "pair-runner session leader disappeared before it was safely reaped")
    return group_members, escaped_members


def _signal_unreaped_owned_group(process: subprocess.Popen[bytes], signum: int) -> None:
    """Signal the isolated PGID only while its direct leader remains unreaped."""
    _leader_exit_status_unreaped(process)
    group_members, _escaped_members = _owned_session_members(process.pid)
    if not group_members:
        return
    # Procfs inspection does not preserve child ownership. Recheck SIGCHLD,
    # Popen state, and WNOWAIT after the scan immediately before killpg.
    _leader_exit_status_unreaped(process)
    try:
        os.killpg(process.pid, signum)
    except ProcessLookupError:
        return
    except OSError as error:
        raise ChronologyError(f"cannot signal the unreaped pair-runner group: {error}") from error


def _wait_owned_group_quiescent(process: subprocess.Popen[bytes], timeout_seconds: float) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while True:
        _leader_exit_status_unreaped(process)
        group_members, _escaped_members = _owned_session_members(process.pid)
        if not group_members:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(DISPATCH_POLL_INTERVAL_SECONDS, remaining))


def _bounded_emergency_reap(
    process: subprocess.Popen[bytes],
) -> ProcessCleanupResult:
    """Use the still-unreaped session leader to KILL and reap without procfs scans."""
    global _ACTIVE_DISPATCH_PROCESS
    try:
        _require_owned_child_wait_semantics()
    except BaseException as error:
        # Without default SIGCHLD disposition, WNOWAIT cannot reserve the PID
        # through exit. Refuse all numeric process-group signals and all Popen
        # waits; ECHILD under an ignored/custom handler is not exit status.
        _ACTIVE_DISPATCH_PROCESS = None
        return ProcessCleanupResult(
            False, "unverified", None, "unverified",
            f"emergency PGID signal refused without wait ownership: {type(error).__name__}",
        )
    try:
        _leader_exit_status_unreaped(process)
    except BaseException as error:
        _ACTIVE_DISPATCH_PROCESS = None
        return ProcessCleanupResult(
            False, "unverified", None, "unverified",
            f"cannot verify unreaped runner ownership: {type(error).__name__}",
        )
    signal_error: str | None = None
    try:
        # start_new_session=True makes this Popen PID the group/session leader.
        # Re-observe ownership immediately before using its numeric group ID.
        _leader_exit_status_unreaped(process)
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except BaseException as error:
        if isinstance(error, ChronologyError) and "default SIGCHLD disposition" in str(error):
            _ACTIVE_DISPATCH_PROCESS = None
            return ProcessCleanupResult(
                False, "unverified", None, "unverified",
                f"emergency PGID signal refused without wait ownership: {type(error).__name__}",
            )
        signal_error = f"emergency SIGKILL failed: {type(error).__name__}"
    _ACTIVE_DISPATCH_PROCESS = None
    reaped = _bounded_owned_wait(process, DISPATCH_REAP_GRACE_SECONDS,
                                 "unverified", signal_error,
                                 "bounded emergency reap")
    return reaped


def _bounded_owned_wait(
    process: subprocess.Popen[bytes], timeout_seconds: float,
    group_status: str, prior_error: str | None, operation: str,
) -> ProcessCleanupResult:
    """Reap only while this caller still has verifiable default-SIGCHLD ownership."""
    try:
        _require_owned_child_wait_semantics()
        # Confirm this process still owns an unreaped child immediately before
        # Popen.wait. An ignored/custom SIGCHLD disposition can auto-reap the
        # child, and Popen.wait may translate ECHILD into a fabricated zero.
        _leader_exit_status_unreaped(process)
    except BaseException as error:
        return ProcessCleanupResult(
            False, "unverified", None, "unverified",
            ";".join(item for item in (
                prior_error,
                f"{operation} refused without verifiable child ownership: {type(error).__name__}",
            ) if item),
        )
    try:
        return_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as error:
        return ProcessCleanupResult(
            False, "not_reaped", None, group_status,
            ";".join(item for item in (
                prior_error,
                f"{operation} timed out: {type(error).__name__}",
            ) if item),
        )
    except BaseException as error:
        return ProcessCleanupResult(
            False, "unverified", None, "unverified",
            ";".join(item for item in (
                prior_error,
                f"{operation} failed without a verified wait status: {type(error).__name__}",
            ) if item),
        )
    if type(return_code) is not int:
        return ProcessCleanupResult(
            False, "unverified", None, "unverified",
            ";".join(item for item in (
                prior_error, f"{operation} returned a non-integer wait status",
            ) if item),
        )
    return ProcessCleanupResult(
        True, "owned_reaped", return_code, group_status, prior_error,
    )


def _terminate_process_group(
    process: subprocess.Popen[bytes],
) -> ProcessCleanupResult:
    """Return separate leader-reap and verified group-cleanup outcomes."""
    global _ACTIVE_DISPATCH_PROCESS
    try:
        _require_owned_child_wait_semantics()
        _leader_exit_status_unreaped(process)
        cleanup_deadline = time.monotonic() + DISPATCH_CLEANUP_TOTAL_SECONDS
        _signal_unreaped_owned_group(process, signal.SIGTERM)
        term_budget = min(DISPATCH_TERM_GRACE_SECONDS,
                          max(0.0, cleanup_deadline - time.monotonic()))
        group_quiescent = _wait_owned_group_quiescent(process, term_budget)
        if not group_quiescent:
            _signal_unreaped_owned_group(process, signal.SIGKILL)
            kill_budget = min(DISPATCH_KILL_GRACE_SECONDS,
                              max(0.0, cleanup_deadline - time.monotonic()))
            group_quiescent = _wait_owned_group_quiescent(process, kill_budget)
        _leader_exit_status_unreaped(process)
        group_members, escaped_members = _owned_session_members(process.pid)
        group_clean = group_quiescent and not group_members and not escaped_members
        cleanup_status = "clean" if group_clean else "unclean"
        if group_clean:
            error_message = None
        else:
            error_message = "owned session cleanup left live group or escaped session members"
        remaining = cleanup_deadline - time.monotonic()
        reap_timeout = (min(DISPATCH_REAP_GRACE_SECONDS, remaining)
                        if remaining > 0 else DISPATCH_REAP_GRACE_SECONDS)
        # This pointer is the only signal-time reference to the runner. Clear it
        # before wait() releases the PID that anchors the fresh PGID.
        _ACTIVE_DISPATCH_PROCESS = None
        return _bounded_owned_wait(
            process, reap_timeout, cleanup_status, error_message,
            "bounded direct-runner reap",
        )
    except BaseException as error:
        # Inspection/signaling errors cannot certify the session tree. Keep the
        # unreaped leader as the ownership boundary for one bounded SIGKILL and
        # reap attempt, then report the tree as unverified regardless of reap.
        fallback = _bounded_emergency_reap(process)
        message = f"{type(error).__name__}:{str(error)[:512]}"
        if fallback.error_message:
            message = f"{message};{fallback.error_message}"
        return fallback._replace(
            process_group_cleanup_status="unverified", error_message=message,
        )


_ACTIVE_DISPATCH_PROCESS: subprocess.Popen[bytes] | None = None
_PENDING_DISPATCH_SIGNAL: int | None = None


def _install_dispatch_signal_handlers() -> dict[int, Any]:
    global _PENDING_DISPATCH_SIGNAL
    _PENDING_DISPATCH_SIGNAL = None
    require(threading.current_thread() is threading.main_thread(),
            "bounded chronology launch must run on the main thread for signal cleanup")
    previous: dict[int, Any] = {}

    def handler(signum: int, _frame: Any) -> None:
        global _PENDING_DISPATCH_SIGNAL
        if _PENDING_DISPATCH_SIGNAL is None:
            _PENDING_DISPATCH_SIGNAL = signum

    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        previous[signum] = signal.signal(signum, handler)
    return previous


def _restore_dispatch_signal_handlers(previous: dict[int, Any]) -> None:
    for signum, handler in previous.items():
        signal.signal(signum, handler)


def _capture_output(path: Path) -> tuple[dict[str, str], bytes, int]:
    raw, info = _read_stable(path, "fixed pair-runner output", MAX_OUTPUT_BYTES)
    require(stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid(),
            "fixed pair-runner output is not a private mode-0600 regular file")
    pin = {"path": str(path), "sha256": sha256_bytes(raw)}
    return pin, raw, info.st_size


def _flush_close_streams(*streams: Any, ignore_errors: bool = False) -> None:
    first_error: BaseException | None = None
    for stream in streams:
        if stream is None or getattr(stream, "closed", False):
            continue
        try:
            stream.flush()
            os.fsync(stream.fileno())
        except BaseException as error:
            if first_error is None:
                first_error = error
        try:
            stream.close()
        except BaseException as error:
            if first_error is None:
                first_error = error
    if first_error is not None and not ignore_errors:
        raise first_error


def _cleanup_is_safe(cleanup: ProcessCleanupResult) -> bool:
    if cleanup.process_reap_status == "not_started":
        return (not cleanup.process_reaped and cleanup.return_code is None and
                cleanup.process_group_cleanup_status == "not_started")
    return (cleanup.process_reap_status == "owned_reaped" and cleanup.process_reaped and
            type(cleanup.return_code) is int and
            cleanup.process_group_cleanup_status == "clean")


def _cleanup_error_sha256(cleanup: ProcessCleanupResult) -> str | None:
    if _cleanup_is_safe(cleanup):
        return None
    message = cleanup.error_message or (
        f"process_reaped={cleanup.process_reaped};"
        f"process_reap_status={cleanup.process_reap_status};"
        f"return_code={cleanup.return_code};"
        f"process_group_cleanup_status={cleanup.process_group_cleanup_status}"
    )
    return sha256_bytes(message.encode("utf-8", "replace"))


def _failed_dispatch_details(authorization: dict[str, Any], pid: int | None,
                             error: BaseException, elapsed_ns: int,
                             cleanup: ProcessCleanupResult) -> dict[str, Any]:
    message = f"{type(error).__name__}:{str(error)[:1024]}"
    return {
        "authorization_id": authorization["authorization_id"],
        "job_run_id": authorization["job"]["run_id"],
        "member_role": "campaign_pair_runner", "pid": pid,
        "return_code": cleanup.return_code,
        "error_type": type(error).__name__, "error_sha256": sha256_bytes(message.encode("utf-8", "replace")),
        "elapsed_ns": max(0, elapsed_ns), "process_reaped": cleanup.process_reaped,
        "process_reap_status": cleanup.process_reap_status,
        "process_group_cleanup_status": cleanup.process_group_cleanup_status,
        "cleanup_error_sha256": _cleanup_error_sha256(cleanup),
        "capacity_registration_head": authorization["capacity_registration_head"],
        "qualification_eligible": False,
    }


def _interrupted_dispatch_details(authorization: dict[str, Any], pid: int | None,
                                  signum: int, elapsed_ns: int,
                                  cleanup: ProcessCleanupResult) -> dict[str, Any]:
    return {
        "authorization_id": authorization["authorization_id"],
        "job_run_id": authorization["job"]["run_id"],
        "member_role": "campaign_pair_runner", "pid": pid,
        "signal": signum, "return_code": cleanup.return_code,
        "elapsed_ns": max(0, elapsed_ns), "process_reaped": cleanup.process_reaped,
        "process_reap_status": cleanup.process_reap_status,
        "process_group_cleanup_status": cleanup.process_group_cleanup_status,
        "cleanup_error_sha256": _cleanup_error_sha256(cleanup),
        "capacity_registration_head": authorization["capacity_registration_head"],
        "qualification_eligible": False,
    }


def _timeout_dispatch_details(authorization: dict[str, Any], pid: int | None,
                              elapsed_ns: int,
                              cleanup: ProcessCleanupResult) -> dict[str, Any]:
    return {
        "authorization_id": authorization["authorization_id"],
        "job_run_id": authorization["job"]["run_id"],
        "member_role": "campaign_pair_runner", "pid": pid,
        "return_code": cleanup.return_code, "elapsed_ns": max(0, elapsed_ns),
        "effective_timeout_seconds": authorization["effective_timeout_seconds"],
        "process_reaped": cleanup.process_reaped,
        "process_reap_status": cleanup.process_reap_status,
        "process_group_cleanup_status": cleanup.process_group_cleanup_status,
        "cleanup_error_sha256": _cleanup_error_sha256(cleanup),
        "capacity_registration_head": authorization["capacity_registration_head"],
        "qualification_eligible": False,
    }


@_serialize_locked_api
def launch_authorized_locked(
    lock: CampaignHostLock, authorization: DispatchAuthorization,
) -> dict[str, Any]:
    """Popen one authorized original pair runner and durably bind/reap its direct process."""
    authorization = _consume_authorization(lock, authorization)
    prepared = authorization.prepared
    token_details = _json_copy(authorization.details)
    details = token_details
    start_ns = authorization.start_monotonic_ns
    deadline_ns = start_ns + token_details["effective_timeout_seconds"] * 1_000_000_000
    process: subprocess.Popen[bytes] | None = None
    process_reaped = False
    cleanup_result: ProcessCleanupResult | None = None
    bound: dict[str, Any] | None = None
    stdout_stream: Any = None
    stderr_stream: Any = None
    stdout_path = Path(token_details["stdout_path"])
    stderr_path = Path(token_details["stderr_path"])
    context: dict[str, Any] | None = None
    previous_handlers: dict[int, Any] = {}
    outcome: dict[str, Any] | None = None
    error: BaseException | None = None
    global _ACTIVE_DISPATCH_PROCESS, _PENDING_DISPATCH_SIGNAL
    try:
        previous_handlers = _install_dispatch_signal_handlers()
        context = _prepare_inputs(
            authorization.plan_pin, authorization.spec_pin, authorization.source_root,
            authorization.input_root, prepared["host_id"], authorization.observed_host_pin,
            prepared["output_root"],
        )
        _check_lock(lock, context["output_root"], context["campaign_id"], context["host_id"])
        require(context["original_pins"] == prepared["original_pins"],
                "original SourceV5/spec/plan/host pins changed after authorization")
        state = _read_journal(lock, context)
        registration = state["registration"]
        authorization_id = token_details["authorization_id"]
        prior = state["authorized"].get(authorization_id)
        require(state["pending"] == authorization_id and registration is not None and
                prior is not None,
                "one-use dispatch authorization is no longer the journal head")
        details = prior["details"]
        require(details == token_details,
                "dispatch token differs from its fsynced authorization record")
        capacity_details, _completion = _capacity_completion(
            context, authorization.capacity_output_root, authorization.completion_pin,
        )
        require(_registration_fields(capacity_details) == _registration_fields(registration),
                "capacity completion changed after dispatch authorization")
        spec = _validate_dispatch_authorization(
            details, context, registration, state["registration_head"],
        )
        require(time.monotonic_ns() < deadline_ns,
                "fixed confirmation outer deadline expired before direct Popen")
        _ensure_confirmation_host_directory(
            context, details["confirmation_owner_marker"],
            state["registration_head"],
        )
        runtime_pin = _write_runtime_binding_file(
            context["output_root"], Path(spec["runtime_bindings"]["path"]),
            spec["runtime_manifest_raw"],
        )
        require(runtime_pin == {
            "path": details["runtime_bindings"]["path"],
            "sha256": details["runtime_bindings"]["sha256"],
        }, "runtime binding output differs from the frozen authorization pin")
        _ensure_private_tree(context["output_root"], stdout_path.parent)
        stdout_fd = os.open(
            stdout_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
            getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600,
        )
        os.fchmod(stdout_fd, 0o600)
        stdout_stream = os.fdopen(stdout_fd, "wb", buffering=0)
        stderr_fd = os.open(
            stderr_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
            getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o600,
        )
        os.fchmod(stderr_fd, 0o600)
        stderr_stream = os.fdopen(stderr_fd, "wb", buffering=0)
        if _PENDING_DISPATCH_SIGNAL is not None:
            raise ChronologyError("dispatch was interrupted before direct Popen")
        _require_owned_child_wait_semantics()
        if time.monotonic_ns() >= deadline_ns:
            cleanup_result = ProcessCleanupResult(
                False, "not_started", None, "not_started", None,
            )
            outcome = _timeout_dispatch_details(
                authorization.details, None, time.monotonic_ns() - start_ns,
                cleanup_result,
            )
            _append_event(lock, context, "dispatch_timeout", outcome)
            return {"authorization_id": authorization.details["authorization_id"],
                    "job_run_id": authorization.details["job"]["run_id"],
                    "status": "timeout", "pid": None, "process_reaped": False,
                    "process_reap_status": cleanup_result.process_reap_status,
                    "return_code": cleanup_result.return_code,
                    "process_group_cleanup_status": "not_started",
                    "cleanup_error_sha256": None,
                    "qualification_eligible": False,
                    "controller_chronology_proven": False}
        try:
            process = subprocess.Popen(
                authorization.details["argv"], cwd=authorization.details["cwd"],
                env=authorization.details["environment"], stdin=subprocess.DEVNULL,
                stdout=stdout_stream, stderr=stderr_stream, close_fds=True,
                shell=False, start_new_session=True,
            )
        except OSError as launch_error:
            elapsed_ns = time.monotonic_ns() - start_ns
            _flush_close_streams(stdout_stream, stderr_stream, ignore_errors=True)
            stdout_stream = stderr_stream = None
            cleanup_result = ProcessCleanupResult(
                False, "not_started", None, "not_started", None,
            )
            failure = _failed_dispatch_details(
                authorization.details, None, launch_error, elapsed_ns,
                cleanup_result,
            )
            _append_event(lock, context, "dispatch_failed", failure)
            return {"authorization_id": authorization.details["authorization_id"],
                    "job_run_id": authorization.details["job"]["run_id"],
                    "status": "launch_failed", "pid": None, "process_reaped": False,
                    "process_reap_status": cleanup_result.process_reap_status,
                    "return_code": cleanup_result.return_code,
                    "process_group_cleanup_status": "not_started",
                    "cleanup_error_sha256": None,
                    "error_sha256": failure["error_sha256"],
                    "qualification_eligible": False,
                    "controller_chronology_proven": False}
        _ACTIVE_DISPATCH_PROCESS = process
        try:
            bound = _live_process_identity(
                process, context["stage"], authorization.details["shebang_interpreter"],
                authorization.details["cwd"],
                context["prepared"]["current_host"]["cpu_affinity"],
                context["prepared"]["current_host"]["network_namespace_inode"],
                authorization.details["environment"],
                timeout_seconds=max(0.01, min(1.0, (deadline_ns - time.monotonic_ns()) / 1e9)),
            )
        except BaseException as binding_error:
            error = binding_error
            raise
        environment_sha = authorization.details["environment_sha256"]
        bound_details = {
            "authorization_id": authorization.details["authorization_id"],
            "job_run_id": authorization.details["job"]["run_id"],
            "member_role": "campaign_pair_runner", "pid": bound["pid"],
            "start_ticks": bound["start_ticks"],
            "runner_path": authorization.details["runner"]["path"],
            "runner_sha256": authorization.details["runner"]["sha256"],
            "process_executable_path": bound["process_executable_path"],
            "process_executable_sha256": bound["process_executable_sha256"],
            "cwd": bound["cwd"], "cpu_affinity": bound["cpu_affinity"],
            "network_namespace_inode": bound["network_namespace_inode"],
            "environment": authorization.details["environment"],
            "environment_sha256": environment_sha,
            "actual_environment_sha256": sha256_bytes(canonical_bytes(bound["environment"])),
            "process_report_nonce": None,
            "member_report_nonces": [item["report_nonce"] for item in authorization.details["pair_members"]],
            "caller_role": "campaign_pair_runner",
            "pair_members_sha256": authorization.details["pair_members_sha256"],
            "capacity_registration_head": authorization.details["capacity_registration_head"],
            "qualification_eligible": False,
        }
        _validate_bound_details(bound_details, authorization.details, context)
        _append_event(lock, context, "dispatch_bound", bound_details)

        status = "completed"
        signum: int | None = None
        while _leader_exit_status_unreaped(process) is None:
            if _PENDING_DISPATCH_SIGNAL is not None:
                status = "interrupted"
                signum = _PENDING_DISPATCH_SIGNAL
                break
            if time.monotonic_ns() >= deadline_ns:
                status = "timeout"
                break
            stdout_info = os.fstat(stdout_stream.fileno())
            stderr_info = os.fstat(stderr_stream.fileno())
            require(stdout_info.st_size <= MAX_OUTPUT_BYTES and
                    stderr_info.st_size <= MAX_OUTPUT_BYTES,
                    "fixed pair-runner output exceeded its finite capture bound")
            time.sleep(min(0.02, max(0.0, (deadline_ns - time.monotonic_ns()) / 1e9)))
        if status == "completed" and time.monotonic_ns() >= deadline_ns:
            status = "timeout"
        if status == "completed" and _PENDING_DISPATCH_SIGNAL is not None:
            status = "interrupted"
            signum = _PENDING_DISPATCH_SIGNAL
        cleanup_result = _terminate_process_group(process)
        process_reaped = cleanup_result.process_reaped
        if status == "completed" and time.monotonic_ns() >= deadline_ns:
            status = "timeout"
        if status == "completed" and _PENDING_DISPATCH_SIGNAL is not None:
            status = "interrupted"
            signum = _PENDING_DISPATCH_SIGNAL
        return_code = cleanup_result.return_code
        _flush_close_streams(stdout_stream, stderr_stream)
        stdout_stream = stderr_stream = None
        elapsed_ns = max(0, time.monotonic_ns() - start_ns)
        if status == "timeout":
            terminal = _timeout_dispatch_details(
                authorization.details, bound["pid"], elapsed_ns,
                cleanup_result,
            )
            _append_event(lock, context, "dispatch_timeout", terminal)
            cleanup_safe = _cleanup_is_safe(cleanup_result)
            outcome = {"authorization_id": authorization.details["authorization_id"],
                       "job_run_id": authorization.details["job"]["run_id"],
                       "status": "timeout" if cleanup_safe else "cleanup_failed",
                       "dispatch_status": "timeout",
                       "pid": bound["pid"],
                       "process_reaped": process_reaped,
                       "process_reap_status": cleanup_result.process_reap_status,
                       "return_code": cleanup_result.return_code,
                       "process_group_cleanup_status": cleanup_result.process_group_cleanup_status,
                       "cleanup_error_sha256": terminal["cleanup_error_sha256"],
                       "qualification_eligible": False,
                       "controller_chronology_proven": False}
        elif status == "interrupted":
            terminal = _interrupted_dispatch_details(
                authorization.details, bound["pid"], signum or signal.SIGTERM,
                elapsed_ns, cleanup_result,
            )
            _append_event(lock, context, "dispatch_interrupted", terminal)
            cleanup_safe = _cleanup_is_safe(cleanup_result)
            outcome = {"authorization_id": authorization.details["authorization_id"],
                       "job_run_id": authorization.details["job"]["run_id"],
                       "status": "interrupted" if cleanup_safe else "cleanup_failed",
                       "dispatch_status": "interrupted",
                       "pid": bound["pid"],
                       "signal": signum, "process_reaped": process_reaped,
                       "process_reap_status": cleanup_result.process_reap_status,
                       "return_code": cleanup_result.return_code,
                       "process_group_cleanup_status": cleanup_result.process_group_cleanup_status,
                       "cleanup_error_sha256": terminal["cleanup_error_sha256"],
                       "qualification_eligible": False,
                       "controller_chronology_proven": False}
        elif not _cleanup_is_safe(cleanup_result):
            failure = ChronologyError(cleanup_result.error_message or
                                      "pair-runner group cleanup was not verified clean")
            terminal = _failed_dispatch_details(
                authorization.details, bound["pid"], failure, elapsed_ns,
                cleanup_result,
            )
            _append_event(lock, context, "dispatch_failed", terminal)
            outcome = {"authorization_id": authorization.details["authorization_id"],
                       "job_run_id": authorization.details["job"]["run_id"],
                       "status": "cleanup_failed", "pid": bound["pid"],
                       "process_reaped": process_reaped,
                       "process_reap_status": cleanup_result.process_reap_status,
                       "return_code": cleanup_result.return_code,
                       "process_group_cleanup_status": cleanup_result.process_group_cleanup_status,
                       "cleanup_error_sha256": terminal["cleanup_error_sha256"],
                       "error_sha256": terminal["error_sha256"],
                       "qualification_eligible": False,
                       "controller_chronology_proven": False}
        else:
            stdout_pin, stdout_raw, stdout_size = _capture_output(stdout_path)
            stderr_pin, stderr_raw, stderr_size = _capture_output(stderr_path)
            if return_code is not None and return_code < 0:
                exit_status = "signaled"
                exit_signal: int | None = -return_code
            else:
                exit_status = "completed"
                exit_signal = None
            terminal = {
                "authorization_id": authorization.details["authorization_id"],
                "job_run_id": authorization.details["job"]["run_id"],
                "member_role": "campaign_pair_runner", "pid": bound["pid"],
                "return_code": return_code, "status": exit_status,
                "signal": exit_signal, "elapsed_ns": elapsed_ns,
                "stdout": stdout_pin, "stderr": stderr_pin,
                "stdout_sha256": stdout_pin["sha256"],
                "stderr_sha256": stderr_pin["sha256"],
                "stdout_size": stdout_size, "stderr_size": stderr_size,
                "process_reaped": cleanup_result.process_reaped,
                "process_reap_status": cleanup_result.process_reap_status,
                "process_group_cleanup_status": cleanup_result.process_group_cleanup_status,
                "cleanup_error_sha256": _cleanup_error_sha256(cleanup_result),
                "capacity_registration_head": authorization.details["capacity_registration_head"],
                "qualification_eligible": False,
            }
            _append_event(lock, context, "dispatch_exited", terminal)
            outcome = {"authorization_id": authorization.details["authorization_id"],
                       "job_run_id": authorization.details["job"]["run_id"],
                       "status": exit_status, "return_code": return_code,
                       "pid": bound["pid"], "start_ticks": bound["start_ticks"],
                       "process_executable_path": bound["process_executable_path"],
                       "process_executable_sha256": bound["process_executable_sha256"],
                       "process_reaped": process_reaped,
                       "process_reap_status": cleanup_result.process_reap_status,
                       "process_group_cleanup_status": cleanup_result.process_group_cleanup_status,
                       "cleanup_error_sha256": _cleanup_error_sha256(cleanup_result),
                       "qualification_eligible": False,
                       "controller_chronology_proven": False}
    except BaseException as caught:
        error = caught
        elapsed_ns = max(0, time.monotonic_ns() - start_ns)
        pid = process.pid if process is not None else None
        if process is not None:
            if cleanup_result is None:
                cleanup_result = _terminate_process_group(process)
            process_reaped = cleanup_result.process_reaped
            return_code = cleanup_result.return_code
        else:
            process_reaped = False
            return_code = None
            cleanup_result = ProcessCleanupResult(
                False, "not_started", None, "not_started", None,
            )
        _flush_close_streams(stdout_stream, stderr_stream, ignore_errors=True)
        stdout_stream = stderr_stream = None
        signal_value = _PENDING_DISPATCH_SIGNAL
        cleanup_safe = _cleanup_is_safe(cleanup_result)
        transaction_context = context if context is not None else prepared
        try:
            current = _read_journal(lock, transaction_context)
            if current["pending"] == authorization.details["authorization_id"]:
                if signal_value is not None:
                    terminal = _interrupted_dispatch_details(
                        authorization.details, pid, signal_value, elapsed_ns,
                        cleanup_result,
                    )
                    _append_event(lock, transaction_context, "dispatch_interrupted", terminal)
                    outcome = {"authorization_id": authorization.details["authorization_id"],
                               "job_run_id": authorization.details["job"]["run_id"],
                               "status": "interrupted" if cleanup_safe else "cleanup_failed",
                               "dispatch_status": "interrupted",
                               "pid": pid, "signal": signal_value,
                               "process_reaped": process_reaped,
                               "process_reap_status": cleanup_result.process_reap_status,
                               "return_code": cleanup_result.return_code,
                               "process_group_cleanup_status": cleanup_result.process_group_cleanup_status,
                               "cleanup_error_sha256": terminal["cleanup_error_sha256"],
                               "qualification_eligible": False,
                               "controller_chronology_proven": False}
                elif time.monotonic_ns() >= deadline_ns:
                    terminal = _timeout_dispatch_details(
                        authorization.details, pid, elapsed_ns,
                        cleanup_result,
                    )
                    _append_event(lock, transaction_context, "dispatch_timeout", terminal)
                    outcome = {"authorization_id": authorization.details["authorization_id"],
                               "job_run_id": authorization.details["job"]["run_id"],
                               "status": "timeout" if cleanup_safe else "cleanup_failed",
                               "dispatch_status": "timeout", "pid": pid,
                               "process_reaped": process_reaped,
                               "process_reap_status": cleanup_result.process_reap_status,
                               "return_code": cleanup_result.return_code,
                               "process_group_cleanup_status": cleanup_result.process_group_cleanup_status,
                               "cleanup_error_sha256": terminal["cleanup_error_sha256"],
                               "qualification_eligible": False,
                               "controller_chronology_proven": False}
                else:
                    dispatch_error = caught if cleanup_safe else ChronologyError(
                        f"{type(caught).__name__}: dispatch cleanup is not verified safe"
                    )
                    terminal = _failed_dispatch_details(
                        authorization.details, pid, dispatch_error, elapsed_ns,
                        cleanup_result,
                    )
                    _append_event(lock, transaction_context, "dispatch_failed", terminal)
                    outcome = {"authorization_id": authorization.details["authorization_id"],
                               "job_run_id": authorization.details["job"]["run_id"],
                               "status": "launch_failed" if cleanup_safe else "cleanup_failed",
                               "dispatch_status": "launch_failed", "pid": pid,
                               "process_reaped": process_reaped,
                               "process_reap_status": cleanup_result.process_reap_status,
                               "return_code": cleanup_result.return_code,
                               "process_group_cleanup_status": cleanup_result.process_group_cleanup_status,
                               "cleanup_error_sha256": terminal["cleanup_error_sha256"],
                               "error_sha256": terminal["error_sha256"],
                               "qualification_eligible": False,
                               "controller_chronology_proven": False}
        except BaseException:
            raise
    finally:
        if stdout_stream is not None or stderr_stream is not None:
            _flush_close_streams(stdout_stream, stderr_stream, ignore_errors=True)
        if process is not None:
            _ACTIVE_DISPATCH_PROCESS = None
        if previous_handlers:
            _restore_dispatch_signal_handlers(previous_handlers)
        _PENDING_DISPATCH_SIGNAL = None
        with _AUTHORIZATION_TOKEN_LOCK:
            _AUTHORIZATION_TOKENS.pop(id(authorization), None)
    require(outcome is not None, "bounded launch ended without a durable terminal result")
    return outcome






def _check_lock(lock: object, output_root: Path, campaign_id: str, host_id: str) -> CampaignHostLock:
    require(_lock_token_is_live(lock),
            "locked chronology API requires its active fd-owned CampaignHostLock token")
    assert isinstance(lock, CampaignHostLock)
    require(lock.active and lock.campaign_id == campaign_id and
            lock.host_id == host_id and lock.output_root == output_root,
            "campaign/host lock token does not own these inputs")
    try:
        fd_info = os.fstat(lock.fd)
        path_info = lock.lock_path.lstat()
    except OSError as error:
        raise ChronologyError(f"campaign/host lock descriptor is no longer valid: {error}") from error
    require(stat.S_ISREG(fd_info.st_mode) and stat.S_ISREG(path_info.st_mode) and
            (fd_info.st_dev, fd_info.st_ino) == lock._fd_key == (path_info.st_dev, path_info.st_ino) and
            stat.S_IMODE(fd_info.st_mode) == stat.S_IMODE(path_info.st_mode) == 0o600 and
            fd_info.st_uid == path_info.st_uid == os.getuid(),
            "campaign/host lock must remain an owned regular O_NOFOLLOW file with mode 0600")
    return lock


def campaign_host_lock(
    output_root: Path, campaign_id: str, host_id: str, *,
    timeout_seconds: float | None = None,
) -> CampaignHostLock:
    """Open and hold the one private per-campaign/per-host flock context."""
    root = _safe_root(Path(output_root), "campaign chronology output root")
    require(stat.S_IMODE(root.stat().st_mode) == 0o700 and root.stat().st_uid == os.getuid(),
            "campaign chronology output root must be owned and mode 0700")
    campaign_id = _token(campaign_id, "campaign ID")
    host_id = _token(host_id, "host ID")
    campaign_dir = root / campaign_id
    _ensure_private_directory(campaign_dir)
    chronology_dir = campaign_dir / "chronology"
    _ensure_private_directory(chronology_dir)
    host_dir = chronology_dir / host_id
    _ensure_private_directory(host_dir)
    lock_path = host_dir / "campaign-host.lock"
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        fd = os.open(lock_path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
    except FileExistsError:
        fd = os.open(lock_path, flags)
    try:
        if created:
            os.fchmod(fd, 0o600)
        info = os.fstat(fd)
        path_info = lock_path.lstat()
        require(stat.S_ISREG(info.st_mode) and stat.S_ISREG(path_info.st_mode) and
                (info.st_dev, info.st_ino) == (path_info.st_dev, path_info.st_ino) and
                stat.S_IMODE(info.st_mode) == stat.S_IMODE(path_info.st_mode) == 0o600 and
                info.st_uid == path_info.st_uid == os.getuid(),
                "campaign/host lock must be an owned regular O_NOFOLLOW file with mode 0600")
        if timeout_seconds is None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        else:
            require(type(timeout_seconds) in (int, float) and 0 <= timeout_seconds <= 3600,
                    "lock acquisition timeout exceeds its finite bound")
            deadline = time.monotonic() + float(timeout_seconds)
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise ChronologyError("campaign/host flock acquisition timed out")
                    time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
        return CampaignHostLock(root, campaign_id, host_id, host_dir, lock_path, fd)
    except BaseException:
        os.close(fd)
        raise


def _safe_child(root: Path, value: object, label: str) -> Path:
    relative = _relative(value, label)
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        try:
            info = cursor.lstat()
        except OSError as error:
            raise ChronologyError(f"{label} is unavailable: {error}") from error
        require(not stat.S_ISLNK(info.st_mode), f"{label} traverses a symlink")
    try:
        resolved = cursor.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise ChronologyError(f"{label} is missing or escaped its pinned root") from error
    return resolved


def _source_file(source_root: Path, source: dict[str, Any], relative: str,
                 label: str, maximum: int = MAX_SOURCE_BYTES) -> tuple[bytes, str, dict[str, Any]]:
    files = source.get("source", {}).get("files")
    require(type(files) is list and files, "SourceV5 regular-file inventory is missing")
    matches = [item for item in files if type(item) is dict and item.get("path") == relative]
    require(len(matches) == 1, f"SourceV5 has no unique regular inventory entry for {relative}")
    record = _exact(matches[0], {"path", "kind", "mode", "sha256", "size"},
                    f"SourceV5 {label} inventory entry")
    require(record["kind"] == "file" and record["mode"] in ("100644", "100755"),
            f"SourceV5 {label} is not a regular file inventory entry")
    expected_sha = _digest(record["sha256"], f"SourceV5 {label} digest")
    size = _uint(record["size"], f"SourceV5 {label} size", maximum=maximum)
    path = _safe_child(source_root, relative, f"SourceV5 {label}")
    raw, info = _read_stable(path, f"SourceV5 {label}", maximum)
    mode = stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode)
    require(mode == int(record["mode"], 8) and len(raw) == size and sha256_bytes(raw) == expected_sha,
            f"SourceV5 {label} bytes, mode, or size differ from the typed inventory")
    return raw, expected_sha, record


def _load_module(raw: bytes, path: Path, label: str) -> types.ModuleType:
    module_name = f"chronology_{label}_{sha256_bytes(raw)}"
    module = types.ModuleType(module_name)
    module.__file__ = str(path)
    module.__package__ = ""
    prior = sys.modules.get(module_name)
    sys.modules[module_name] = module
    try:
        exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    except Exception as error:
        raise ChronologyError(f"captured SourceV5 {label} cannot be loaded: {error}") from error
    finally:
        if prior is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = prior
    return module


def _prepare_inputs(
    plan_pin: object, spec_pin: object, source_root_arg: Path, input_root_arg: Path,
    host_id: str, observed_host_pin: object, output_root: Path,
) -> dict[str, Any]:
    spec, spec_path, spec_raw, spec_raw_sha = _read_pin(spec_pin, "campaign spec", MAX_SPEC_BYTES)
    plan, plan_path, plan_raw, plan_raw_sha = _read_pin(plan_pin, "campaign plan", MAX_PLAN_BYTES)
    require(spec.get("schema") == SPEC_SCHEMA and plan.get("schema") == PLAN_SCHEMA,
            "chronology requires the pinned SourceV5 specV3 and planV3")
    require(spec.get("campaign_id") == plan.get("campaign_id"), "spec/plan campaign IDs differ")
    campaign_id = _token(spec.get("campaign_id"), "campaign ID")
    host_id = _token(host_id, "host ID")
    require(host_id in plan.get("host_ids", []), "selected host is absent from the frozen plan")
    source_root = _safe_root(Path(source_root_arg), "SourceV5 root")
    input_root = _safe_root(Path(input_root_arg), "campaign input root")
    output_root = _safe_root(Path(output_root), "campaign chronology output root")
    require(not _within(source_root, input_root) and not _within(source_root, output_root),
            "campaign inputs and transaction outputs must remain outside SourceV5")
    active_path = Path(__file__).resolve(strict=True)
    require(active_path == source_root / CHRONOLOGY_SOURCE_PATH,
            "active chronology module is not executing from the supplied SourceV5 root")

    refs = spec.get("source_manifests")
    require(type(refs) is list and len(refs) == 3,
            "SourceV5 spec must pin all three host source manifests")
    raw_refs: dict[str, dict[str, Any]] = {}
    sources: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(refs):
        ref = _exact(value, {"host_id", "relative_path", "sha256"},
                     f"SourceV5 manifest ref[{index}]")
        ref_host = _token(ref["host_id"], f"SourceV5 manifest host[{index}]")
        require(ref_host not in raw_refs, f"duplicate SourceV5 manifest host {ref_host}")
        relative = _relative(ref["relative_path"], f"SourceV5 manifest relative path[{index}]")
        manifest_path = spec_path.parent / relative
        raw, _info = _read_stable(manifest_path, f"SourceV5 manifest {ref_host}", MAX_MANIFEST_BYTES)
        raw_sha = sha256_bytes(raw)
        semantic_pin = _digest(ref["sha256"], f"SourceV5 semantic manifest pin {ref_host}")
        manifest = _parse_object(raw, f"SourceV5 manifest {ref_host}", MAX_MANIFEST_BYTES)
        require(manifest.get("schema") == SOURCE_SCHEMA and
                _digest(manifest.get("manifest_sha256"), f"SourceV5 semantic manifest {ref_host}") ==
                semantic_pin and
                hashlib.sha256(canonical_bytes({key: item for key, item in manifest.items()
                                                if key != "manifest_sha256"})).hexdigest() ==
                manifest["manifest_sha256"],
                f"SourceV5 semantic manifest pin is invalid for {ref_host}")
        raw_refs[ref_host] = {
            "host_id": ref_host, "path": str(manifest_path),
            "raw_sha256": raw_sha, "semantic_sha256": manifest["manifest_sha256"],
            "source_tree_sha256": manifest["source"]["source_tree_sha256"],
        }
        sources[ref_host] = manifest
    require(host_id in sources, "selected host has no SourceV5 source manifest")
    selected_source = sources[host_id]

    stage_raw, stage_sha, stage_record = _source_file(
        source_root, selected_source, CAPACITY_STAGE_SOURCE_PATH, "capacity-stage module",
        maximum=MAX_SCRIPT_BYTES,
    )
    chronology_raw, chronology_sha, chronology_record = _source_file(
        source_root, selected_source, CHRONOLOGY_SOURCE_PATH, "chronology module",
        maximum=MAX_SCRIPT_BYTES,
    )
    active_raw, active_info = _read_stable(active_path, "active chronology module", MAX_SCRIPT_BYTES)
    require(active_raw == chronology_raw and sha256_bytes(active_raw) == chronology_sha,
            "active chronology module differs from its exact regular SourceV5 inventory pin")
    require(active_info.st_mode & 0o111 == 0 or stat.S_IMODE(active_info.st_mode) in (0o644, 0o755),
            "active chronology module has an unsupported file mode")
    for other_host, source in sources.items():
        for rel, expected_sha in ((CAPACITY_STAGE_SOURCE_PATH, stage_sha),
                                  (CHRONOLOGY_SOURCE_PATH, chronology_sha)):
            _raw, other_sha, other_record = _source_file(source_root, source, rel,
                                                          f"{other_host} {rel}",
                                                          maximum=MAX_SCRIPT_BYTES)
            require(other_sha == expected_sha and other_record["mode"] ==
                    (stage_record if rel == CAPACITY_STAGE_SOURCE_PATH else chronology_record)["mode"],
                    f"SourceV5 host {other_host} captures a different {rel}")
    runner_raw, runner_sha, _runner_record = _source_file(
        source_root, selected_source, PAIR_RUNNER_SOURCE_PATH, "fixed pair runner",
        maximum=MAX_SCRIPT_BYTES,
    )
    require(runner_sha == spec.get("runner_sha256"),
            "fixed pair runner source entry differs from the unchanged spec hash")
    for other_host, source in sources.items():
        _other_raw, other_runner_sha, _other_record = _source_file(
            source_root, source, PAIR_RUNNER_SOURCE_PATH,
            f"{other_host} fixed pair runner", maximum=MAX_SCRIPT_BYTES,
        )
        require(other_runner_sha == runner_sha,
                f"SourceV5 host {other_host} captures a different fixed pair runner")
    stage_module = _load_module(stage_raw, source_root / CAPACITY_STAGE_SOURCE_PATH, "capacity_stage")
    require(callable(getattr(stage_module, "_prepare_pins", None)) and
            callable(getattr(stage_module, "run_capacity_stage", None)) and
            callable(getattr(stage_module, "verify_capacity_completion", None)),
            "captured capacity-stage API is unsupported")
    try:
        prepared = stage_module._prepare_pins(
            plan_pin, spec_pin, source_root, input_root, host_id, observed_host_pin,
        )
    except Exception as error:
        raise ChronologyError(f"captured SourceV5 stage rejected its original pins/host context: {error}") from error
    require(prepared["spec_raw_sha256"] == spec_raw_sha and
            prepared["plan_raw_sha256"] == plan_raw_sha and prepared["host_id"] == host_id,
            "captured stage returned a different original input context")
    controller = prepared["stack"]["controller"]
    refs_by_host = stage_module._source_manifest_refs(spec, spec_path)
    source_pins = []
    for ref in refs:
        ref_host = ref["host_id"]
        path, source, raw, raw_sha = refs_by_host[ref_host]
        source_pins.append({
            "host_id": ref_host, "path": str(path), "raw_sha256": raw_sha,
            "semantic_sha256": source["manifest_sha256"],
            "source_tree_sha256": source["source"]["source_tree_sha256"],
        })
    host_context_pin = _exact(observed_host_pin, {"path", "sha256"}, "observed host pin")
    original_pins = {
        "schema": CHRONOLOGY_SCHEMA,
        "campaign_id": campaign_id, "host_id": host_id,
        "spec": {"path": str(spec_path), "raw_sha256": spec_raw_sha,
                 "semantic_sha256": prepared["spec_semantic_sha256"]},
        "plan": {"path": str(plan_path), "raw_sha256": plan_raw_sha,
                 "semantic_sha256": prepared["plan_semantic_sha256"]},
        "source_manifests": source_pins,
        "observed_host": {
            "path": str(prepared["host_context_path"]),
            "raw_sha256": prepared["host_context_raw_sha256"],
            "boot_id_sha256": prepared["current_host"]["boot_id_sha256"],
            "controls_sha256": prepared["host"]["host_fingerprint_sha256"],
            "controls": prepared["host_context"]["controls"],
            "cpu_affinity": prepared["current_host"]["cpu_affinity"],
            "network_namespace_inode": prepared["current_host"]["network_namespace_inode"],
        },
        "capacity_stage": {"path": CAPACITY_STAGE_SOURCE_PATH, "sha256": stage_sha},
        "chronology_module": {"path": CHRONOLOGY_SOURCE_PATH, "sha256": chronology_sha},
        "pair_runner": {"path": PAIR_RUNNER_SOURCE_PATH, "sha256": runner_sha},
        "captured_modules": [
            {"role": "campaign_controller", "path": CONTROLLER_SOURCE_PATH,
             "sha256": prepared["stack"]["controller_sha256"]},
            {"role": "campaign_inputs", "path": "scripts/application-campaign-inputs.py",
             "sha256": prepared["stack"]["inputs_sha256"]},
            {"role": "feedback_reader", "path": "scripts/application-feedback-readback.py",
             "sha256": prepared["stack"]["feedback_reader_sha256"]},
            {"role": "capacity_producer", "path": "scripts/application-byte-capacity.py",
             "sha256": prepared["stack"]["capacity_producer_sha256"]},
        ],
    }
    require(host_context_pin["path"] == str(prepared["host_context_path"]) and
            host_context_pin["sha256"] == prepared["host_context_raw_sha256"],
            "observed host path/raw pin changed during SourceV5 preparation")
    require(controller is prepared["stack"]["controller"],
            "captured SourceV5 controller object changed during preparation")
    return {
        "campaign_id": campaign_id, "host_id": host_id,
        "spec_pin": {"path": str(spec_path), "sha256": spec_raw_sha},
        "plan_pin": {"path": str(plan_path), "sha256": plan_raw_sha},
        "source_root": source_root, "input_root": input_root, "output_root": output_root,
        "spec": spec, "plan": plan, "sources": sources,
        "source": selected_source, "source_manifest_raw_refs": raw_refs,
        "prepared": prepared, "stage": stage_module, "controller": controller,
        "original_pins": original_pins,
        "original_pins_sha256": sha256_bytes(canonical_bytes(original_pins)),
        "boot_id_sha256": prepared["current_host"]["boot_id_sha256"],
    }


def _journal_path(lock: CampaignHostLock) -> Path:
    return lock.directory / "dispatch-journal.jsonl"


def _empty_journal(original_pins: dict[str, Any]) -> dict[str, Any]:
    return {
        "original_pins": _json_copy(original_pins), "record_count": 0,
        "dispatch_event_count": 0, "head": "0" * 64,
        "journal_heads": ["0" * 64],
        "registration": None, "registration_head": None, "stage_completion": None,
        "stage_head": None,
        "prepared_capacity_registration": None,
        "authorized": {}, "finished": set(), "pending": None,
        "cleanup_blocked": False, "process_cleanup": [],
        "source5_authorized": {}, "source5_finished": {},
        "source5_seen_jobs": set(), "source5_analyses": {},
        "source5_pending": None, "source5_cleanup_blocked": False,
        "last_monotonic_ns": 0, "file_stat": None,
    }


def _auth_detail_identity(details: dict[str, Any]) -> tuple[str, str]:
    return details["authorization_id"], details["job"]["run_id"]


def _validate_process_cleanup_details(details: dict[str, Any]) -> bool:
    process_reaped = details.get("process_reaped")
    require(type(process_reaped) is bool,
            "dispatch terminal omitted the direct leader reap result")
    reap_status = details.get("process_reap_status")
    require(type(reap_status) is str and reap_status in PROCESS_REAP_STATUSES,
            "dispatch terminal has an unknown direct leader reap status")
    return_code = details.get("return_code")
    cleanup_status = details.get("process_group_cleanup_status")
    require(type(cleanup_status) is str and cleanup_status in PROCESS_GROUP_CLEANUP_STATES,
            "dispatch terminal has an unknown process-group cleanup status")
    pid = details.get("pid")
    if pid is None:
        require(reap_status == "not_started" and not process_reaped and
                return_code is None and cleanup_status == "not_started",
                "dispatch without a direct Popen has contradictory cleanup metadata")
    else:
        _uint(pid, "dispatch cleanup direct Popen PID", positive=True,
              maximum=(1 << 31) - 1)
        require(cleanup_status != "not_started",
                "dispatch with a direct Popen claims cleanup never started")
        if reap_status == "owned_reaped":
            require(process_reaped and type(return_code) is int,
                    "owned direct leader reap lacks its exact integer wait status")
        else:
            require(reap_status in {"not_reaped", "unverified"} and
                    not process_reaped and return_code is None,
                    "unreaped or unverified direct leader has contradictory reap metadata")
    safe = ((reap_status == "not_started" and pid is None and not process_reaped and
             return_code is None and cleanup_status == "not_started") or
            (reap_status == "owned_reaped" and process_reaped and
             type(return_code) is int and cleanup_status == "clean"))
    error_sha256 = details.get("cleanup_error_sha256")
    if safe:
        require(error_sha256 is None,
                "verified clean process cleanup has contradictory error metadata")
    else:
        _digest(error_sha256, "process-group cleanup failure digest")
    return safe


def _source5_proof_identity(value: object) -> tuple[int, int]:
    require(type(value) is dict, "Source5 APP callback proof is not an object")
    event = value
    proof = event.get("proof")
    require(type(proof) is dict, "Source5 APP callback omitted its direct launch proof")
    pid = proof.get("pid")
    start_ticks = proof.get("start_ticks")
    require(type(pid) is int and 0 < pid <= (1 << 31) - 1 and
            type(start_ticks) is int and start_ticks > 0,
            "Source5 APP callback proof lacks a positive PID/start identity")
    return pid, start_ticks


def _source5_cleanup_is_clean(value: object) -> bool:
    if type(value) is not dict:
        return False
    if value.get("cleanup_status") == "verified":
        return value.get("leader_reaped") is True and \
            value.get("group_signal_after_leader_reap_count", 0) == 0
    if value.get("status") == "verified":
        application = value.get("application_cleanup")
        return application is None or (
            type(application) is dict and application.get("status") == "verified"
        )
    return False


def _source5_reference(value: object, label: str) -> tuple[Path, bytes, str]:
    pin = _exact(value, {"path", "raw_sha256"}, f"{label} raw pin")
    path = Path(_path_text(Path(pin["path"]), f"{label} path"))
    require(path.is_absolute(), f"{label} path must be absolute")
    expected = _digest(pin["raw_sha256"], f"{label} raw SHA-256")
    raw, _info = _read_stable(path, label, MAX_PLAN_BYTES)
    actual = sha256_bytes(raw)
    require(actual == expected, f"{label} differs from its raw pin")
    return path, raw, actual


def _source5_input_body(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items()
            if key not in {"input_snapshot_sha256", "qualification_eligible"}}


def _source5_artifact_pin(value: object, label: str) -> dict[str, str]:
    reference = _exact(value, {"path", "raw_sha256"}, f"{label} artifact")
    path = Path(_path_text(Path(reference["path"]), f"{label} path"))
    require(path.is_absolute(), f"{label} path must be absolute")
    _digest(reference["raw_sha256"], f"{label} raw SHA-256")
    return {"path": str(path), "raw_sha256": reference["raw_sha256"]}


def _verify_source5_prepared_input_generation(
    manifest: dict[str, Any] | None, prepared: dict[str, Any],
    generation_value: object | None = None,
) -> dict[str, Any]:
    """Replay the additive prepared-input bridge bound by execution-manifest v2."""
    generation_source = (
        manifest.get("prepared_input_generation") if manifest is not None
        else generation_value
    )
    generation = _exact(generation_source, {
        "completion", "provenance",
    }, "Source5 prepared-input generation")
    completion_pin = _exact(generation["completion"], {
        "path", "raw_sha256", "semantic_sha256",
    }, "Source5 prepared-input completion pin")
    raw_pin = _source5_artifact_pin(
        {"path": completion_pin["path"],
         "raw_sha256": completion_pin["raw_sha256"]},
        "Source5 prepared-input completion",
    )
    semantic_sha = _digest(completion_pin["semantic_sha256"],
                           "prepared-input completion semantic digest")
    completion_path = Path(raw_pin["path"])
    require(completion_path == prepared["prepared"]["plan_path"].parent /
            "prepared-inputs-completion.json" and
            _within(prepared["input_root"], completion_path),
            "prepared-input completion is not beside the exact final PlanV3 inside the original input root")
    completion_raw, _completion_info = _read_stable(
        completion_path, "Source5 prepared-input completion", MAX_COMPLETION_BYTES,
    )
    completion_raw_sha = sha256_bytes(completion_raw)
    require(completion_raw_sha == raw_pin["raw_sha256"],
            "prepared-input completion differs from its raw pin")
    completion_value = _parse_object(
        completion_raw, "Source5 prepared-input completion", MAX_COMPLETION_BYTES,
    )
    bounded_completion = completion_value.get("schema") == \
        "allocatbelt.application-source5-preparation-completion.v2"
    require(completion_value.get("schema") in (
                "allocatbelt.application-source5-preparation-completion.v1",
                "allocatbelt.application-source5-preparation-completion.v2",
            ),
            "unsupported Source5 prepared-input completion version")
    if manifest is not None:
        expected_bounded = manifest.get("schema") == SOURCE5_EXECUTION_SCHEMA_V3
        require(bounded_completion == expected_bounded,
                "Source5 execution-manifest version differs from the prepared-input budget contract")
    require(completion_value.get("completion_sha256") == semantic_sha and
            completion_value.get("complete") is True and
            completion_value.get("qualification_eligible") is False,
            "prepared-input completion schema, semantic digest, or eligibility differs")
    provenance = _exact(generation["provenance"], {
        "schema", "preparation_pin", "final_spec_pin", "final_plan_pin",
    }, "Source5 prepared-input completion provenance")
    require(provenance["schema"] ==
            "allocatbelt.application-source5-prepared-inputs-provenance.v1",
            "unsupported Source5 prepared-input completion provenance")
    for name, field in (("final_spec_pin", "spec"),
                        ("final_plan_pin", "plan")):
        pin = _source5_artifact_pin(provenance[name],
                                   f"prepared-input {field} provenance")
        expected = prepared["prepared"][f"{field}_path"]
        expected_sha = prepared["prepared"][f"{field}_raw_sha256"]
        require(pin == {"path": str(expected), "raw_sha256": expected_sha},
                f"prepared-input {field} provenance differs from original campaign bytes")
    preparation_pin = _source5_artifact_pin(
        provenance["preparation_pin"], "Source5 preparation-intent provenance",
    )
    require(_within(prepared["input_root"], Path(preparation_pin["path"])),
            "Source5 preparation intent is outside the original private input root")
    # Every use replays the complete transitive evidence graph. A digest of
    # the completion body alone does not prove that referenced producer,
    # source, host-verification, calibration, pilot, or oracle bytes remain
    # available and unchanged since an earlier registration.
    helper_raw, helper_sha, _helper_record = _source_file(
        prepared["source_root"], prepared["source"],
        "scripts/application-source5-input-preparation.py",
        "Source5 prepared-input verifier", maximum=MAX_SOURCE_BYTES,
    )
    helper = _load_module(
        helper_raw,
        prepared["source_root"] / "scripts/application-source5-input-preparation.py",
        f"source5_prepared_input_verifier_{helper_sha}",
    )
    verify = getattr(helper, "verify_prepared_inputs_completion", None)
    require(callable(verify),
            "pinned Source5 preparation helper lacks the pure completion verifier")
    try:
        verified = verify(
            {**raw_pin, "semantic_sha256": semantic_sha}, provenance,
            prepared["source_root"], prepared["input_root"],
        )
    except Exception as error:
        raise ChronologyError(
            f"Source5 prepared-input completion full-generation replay failed: {error}"
        ) from error
    require(type(verified) is dict and
            canonical_bytes(verified) == canonical_bytes(completion_value),
            "Source5 prepared-input verifier returned a different canonical completion")

    spec = prepared["spec"]
    plan = prepared["plan"]
    require(bool(spec["rates"]) and bool(spec["oracles"]) and
            all(plan["jobs"][phase] ==
                prepared["controller"].build_jobs(spec, phase)
                for phase in ("exploration", "aa", "confirmation",
                              "pressure", "soak")),
            "prepared-input completion requires the exact frozen full original PlanV3 phase schedule")
    require(verified["campaign_id"] == prepared["campaign_id"] and
            verified["final_spec"] == {
                "path": str(prepared["prepared"]["spec_path"]),
                "raw_sha256": prepared["prepared"]["spec_raw_sha256"],
                "semantic_sha256": prepared["prepared"]["spec_semantic_sha256"],
                "preregistration_sha256": prepared["controller"].preregistration_digest(spec),
            } and
            verified["final_plan"] == {
                "path": str(prepared["prepared"]["plan_path"]),
                "raw_sha256": prepared["prepared"]["plan_raw_sha256"],
                "semantic_sha256": prepared["prepared"]["plan_semantic_sha256"],
            }, "prepared-input completion differs from the original final SpecV3/PlanV3")
    host_ids = [item["host_id"] for item in spec["hosts"]]
    sources = _exact(verified["source_manifests"], set(host_ids),
                     "prepared-input SourceV5 generation map")
    source_refs = {item["host_id"]: item for item in spec["source_manifests"]}
    for host_id in host_ids:
        item = _exact(sources[host_id], {
            "path", "raw_sha256", "semantic_sha256", "source_tree_sha256",
        }, f"prepared-input {host_id} source generation")
        source = prepared["sources"][host_id]
        expected_path = prepared["prepared"]["spec_path"].parent / source_refs[host_id]["relative_path"]
        expected_raw = prepared["source_manifest_raw_refs"][host_id]["raw_sha256"]
        require(item == {
                    "path": str(expected_path), "raw_sha256": expected_raw,
                    "semantic_sha256": source["manifest_sha256"],
                    "source_tree_sha256": source["source"]["source_tree_sha256"],
                }, f"prepared-input completion changed {host_id} SourceV5 raw/semantic/tree pins")
    capacity_rows = verified.get("capacity_preparations")
    require(type(capacity_rows) is list and len(capacity_rows) == len(host_ids),
            "prepared-input completion does not cover all three host capacity preparations")
    resource_budgets = None
    if bounded_completion:
        resource_budgets = _exact(verified.get("resource_budgets"), set(host_ids),
                                  "prepared-input bounded resource budget map")
    for index, host_id in enumerate(host_ids):
        row_fields = {
            "host_id", "completion", "host_verification", "evidence_path_map",
            "completion_sha256", "ledger", "capacity_preparation_templates_sha256", "entries",
        }
        if bounded_completion:
            row_fields |= {"resource_budget", "resource_monitor"}
        row = _exact(capacity_rows[index], row_fields,
                     f"prepared capacity completion[{index}]")
        require(row.get("host_id") == host_id,
                "prepared capacity completions changed the original host order")
        cap_pin = _source5_artifact_pin(row.get("completion"),
                                       f"{host_id} pre-Spec capacity completion")
        ledger = row.get("ledger")
        require(type(ledger) is dict and
                type(row.get("entries")) is list and len(row["entries"]) == 15,
                f"{host_id} capacity registration is not the exact verified pre-Spec 15-entry completion")
        cap_value, _cap_raw, _cap_raw_sha = _read_pin(
            {"path": cap_pin["path"], "sha256": cap_pin["raw_sha256"]},
            f"{host_id} pre-Spec capacity stage receipt", MAX_COMPLETION_BYTES,
        )
        expected_capacity_schema = (
            "allocatbelt.application-capacity-preparation-completion.v2" if bounded_completion
            else "allocatbelt.application-capacity-preparation-completion.v1"
        )
        require(cap_value.get("schema") == expected_capacity_schema and
                not {"spec", "plan", "final_spec", "final_plan"} & set(cap_value),
                f"{host_id} prepared capacity registration is not the original standalone stage receipt")
        if bounded_completion:
            budget_pin = _exact(row["resource_budget"],
                                {"path", "raw_sha256", "semantic_sha256"},
                                f"{host_id} prepared capacity budget pin")
            require(resource_budgets[host_id] == budget_pin and
                    cap_value.get("resource_budget") == budget_pin and
                    row["resource_monitor"] == cap_value.get("resource_monitor") and
                    row["resource_monitor"].get("report_count") == 30,
                    f"{host_id} prepared capacity completion lost its frozen budget or 30 monitor receipts")
    selected = prepared["host_id"]
    selected_index = host_ids.index(selected)
    selected_capacity = capacity_rows[selected_index]
    selected_pin = _source5_artifact_pin(
        selected_capacity["completion"],
        f"{selected} selected pre-Spec capacity completion",
    )
    selected_ledger = selected_capacity["ledger"]
    if manifest is not None:
        registration = _exact(manifest.get("prepared_capacity_registration"), {
            "completion", "host_completion", "host_verification", "ledger",
            "capacity_schedule_sha256", "registration_head",
        }, "Source5 selected prepared-capacity registration")
        full_completion = _exact(registration["completion"], {
            "path", "raw_sha256", "semantic_sha256",
        }, "Source5 prepared-capacity bridge completion pin")
        host_completion = _exact(registration["host_completion"], {
            "path", "raw_sha256", "semantic_sha256",
        }, "Source5 selected host preparation completion pin")
        host_verification = _exact(registration["host_verification"], {
            "path", "raw_sha256", "receipt_sha256",
        }, "Source5 prepared-capacity host-verification pin")
        ledger_pin = _exact(registration["ledger"], {
            "path", "raw_sha256", "terminal_head",
        }, "Source5 selected preparation ledger pin")
        require(full_completion == completion_pin and
                {key: host_completion[key] for key in ("path", "raw_sha256")} == selected_pin and
                host_completion["semantic_sha256"] ==
                    selected_capacity["completion_sha256"] and
                host_verification == selected_capacity["host_verification"] and
                ledger_pin == selected_ledger and
                registration["capacity_schedule_sha256"] ==
                    selected_capacity["capacity_preparation_templates_sha256"] and
                _digest(registration["registration_head"],
                        "prepared-capacity registration event head"),
                "selected prepared-capacity registration differs from its full cohort bridge/ledger")
    pressure_rows = verified.get("pressure_calibrations")
    require(type(pressure_rows) is list and len(pressure_rows) == 45,
            "prepared-input completion does not contain the closed 45-entry V2 pressure scope matrix")
    return verified


def _validate_source5_prepared_capacity_registration(
    details_value: object, prepared: dict[str, Any],
) -> dict[str, Any]:
    details = _exact(details_value,
        DETAIL_FIELDS["source5_prepared_capacity_registered"],
        "Source5 prepared-capacity registration event")
    require(details["campaign_id"] == prepared["campaign_id"] and
            details["host_id"] == prepared["host_id"] and
            details["qualification_eligible"] is False and
            details["controller_chronology_proven"] is False,
            "prepared-capacity registration identity or eligibility differs")
    completion = _exact(details["completion"], {
        "path", "raw_sha256", "semantic_sha256",
    }, "prepared-capacity bridge completion pin")
    provenance = _exact(details["provenance"], {
        "schema", "preparation_pin", "final_spec_pin", "final_plan_pin",
    }, "prepared-capacity completion provenance")
    verified = _verify_source5_prepared_input_generation(
        None, prepared,
        {"completion": completion, "provenance": provenance},
    )
    host_ids = [item["host_id"] for item in prepared["spec"]["hosts"]]
    selected_index = host_ids.index(prepared["host_id"])
    row = verified["capacity_preparations"][selected_index]
    host_completion = _exact(details["host_completion"], {
        "path", "raw_sha256", "semantic_sha256",
    }, "prepared-capacity host completion pin")
    host_verification = _exact(details["host_verification"], {
        "path", "raw_sha256", "receipt_sha256",
    }, "prepared-capacity host-verification receipt pin")
    ledger = _exact(details["capacity_ledger"], {
        "path", "raw_sha256", "terminal_head",
    }, "prepared-capacity sealed ledger")
    entries = details["entries"]
    require(type(entries) is list and entries == row["entries"] and
            {key: host_completion[key] for key in ("path", "raw_sha256")} ==
                row["completion"] and
            host_completion["semantic_sha256"] == row["completion_sha256"] and
            host_verification == row["host_verification"] and
            ledger == row["ledger"] and
            details["capacity_schedule_sha256"] ==
                row["capacity_preparation_templates_sha256"] and
            len(entries) == 15,
            "prepared-capacity registration differs from its complete original host receipt, ledger, or 15-entry schedule")
    _digest(details["capacity_schedule_sha256"],
            "prepared-capacity schedule SHA-256")
    _digest(host_verification["receipt_sha256"],
            "prepared-capacity host-verification semantic digest")
    _digest(ledger["raw_sha256"], "prepared-capacity ledger raw SHA-256")
    _digest(ledger["terminal_head"], "prepared-capacity ledger terminal head")
    return {
        "completion": completion,
        "provenance": provenance,
        "host_completion": host_completion,
        "host_verification": host_verification,
        "capacity_ledger": ledger,
        "capacity_schedule_sha256": details["capacity_schedule_sha256"],
        "entries": entries,
    }


def _validate_source5_manifest_value(
    manifest_value: object, raw: bytes, prepared: dict[str, Any], *,
    verify_selected_files: bool = False,
) -> dict[str, Any]:
    base_fields = {
        "schema", "campaign_id", "hosts", "original_inputs", "execution_sources",
        "modules", "observed_hosts", "artifact_root",
        "output_root", "phase_order", "protocol_sha256", "qualification_eligible",
        "manifest_sha256",
    }
    require(type(manifest_value) is dict,
            "Source5 execution-input manifest is not an object")
    schema = manifest_value.get("schema")
    if schema == SOURCE5_EXECUTION_SCHEMA:
        manifest = _exact(manifest_value, base_fields | {"capacity_completions"},
                           "Source5 execution-input manifest v1")
        prepared_v2 = False
    elif schema == SOURCE5_EXECUTION_SCHEMA_V2:
        manifest = _exact(manifest_value, base_fields | {
            "scope", "prepared_input_generation",
            "prepared_capacity_registration",
        }, "Source5 execution-input manifest v2")
        prepared_v2 = True
        require(manifest["scope"] == "final_prepared",
                "Source5 manifest v2 only accepts the closed final-prepared scope")
    elif schema == SOURCE5_EXECUTION_SCHEMA_V3:
        manifest = _exact(manifest_value, base_fields | {
            "scope", "prepared_input_generation",
            "prepared_capacity_registration",
        }, "Source5 execution-input manifest v3")
        prepared_v2 = True
        require(manifest["scope"] == "final_prepared_bounded",
                "Source5 manifest v3 only accepts the closed bounded final-prepared scope")
    else:
        raise ChronologyError("unsupported Source5 execution-input manifest schema")
    require(raw == canonical_bytes(manifest),
            "Source5 execution-input manifest bytes/schema are not canonical")
    body = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    require(manifest["manifest_sha256"] == sha256_bytes(canonical_bytes(body)),
            "Source5 execution-input manifest self digest is invalid")
    spec = prepared["spec"]
    plan = prepared["plan"]
    host_ids = [item["host_id"] for item in spec["hosts"]]
    require(manifest["campaign_id"] == prepared["campaign_id"] and
            manifest["hosts"] == host_ids == plan["host_ids"],
            "Source5 manifest changed the original three host IDs/order")
    require(manifest["qualification_eligible"] is False,
            "Source5 execution-input manifest cannot claim qualification eligibility")
    if prepared_v2:
        require(bool(spec["rates"]) and bool(spec["oracles"]),
                "Source5 final-prepared manifest requires the original complete rates and oracle maps")
        require(all(plan["jobs"][phase] ==
                    prepared["controller"].build_jobs(spec, phase)
                    for phase in ("exploration", "aa", "confirmation",
                                  "pressure", "soak")),
                "Source5 final-prepared PlanV3 differs from the exact unchanged full phase derivation")
    require(manifest["phase_order"] == [
        "exploration", "aa", "confirmation", "fixed_analysis", "pressure",
        "pressure_analysis", "soak", "final_analysis",
    ], "Source5 phase order differs from the original campaign protocol")
    _digest(manifest["protocol_sha256"], "Source5 original protocol digest")
    require(manifest["protocol_sha256"] == sha256_bytes(canonical_bytes(spec["protocol"])),
            "Source5 protocol digest differs from the immutable original SpecV3")
    original = _exact(manifest["original_inputs"], {
        "spec", "plan", "source_manifests", "campaign_artifacts_root",
    }, "Source5 original input pins")
    for name, semantic in (("spec", prepared["prepared"]["spec_semantic_sha256"]),
                           ("plan", prepared["prepared"]["plan_semantic_sha256"])):
        item = _exact(original[name], {"artifact", "semantic_sha256"},
                      f"Source5 original {name} pin")
        artifact = _source5_artifact_pin(item["artifact"], f"Source5 original {name}")
        expected_path = prepared["prepared"][f"{name}_path"]
        expected_raw_sha = prepared["prepared"][f"{name}_raw_sha256"]
        require(artifact == {"path": str(expected_path), "raw_sha256": expected_raw_sha} and
                item["semantic_sha256"] == semantic,
                f"Source5 original {name} raw/semantic pins differ from the frozen input")
    manifest_sources = original["source_manifests"]
    require(type(manifest_sources) is dict and set(manifest_sources) == set(host_ids),
            "Source5 source-manifest map does not cover the exact original hosts")
    refs = {item["host_id"]: item for item in spec["source_manifests"]}
    for host_id in host_ids:
        item = _exact(manifest_sources[host_id], {"artifact", "semantic_sha256"},
                      f"Source5 {host_id} source-manifest pin")
        artifact = _source5_artifact_pin(item["artifact"], f"Source5 {host_id} source manifest")
        source = prepared["sources"][host_id]
        expected_path = prepared["prepared"]["spec_path"].parent / refs[host_id]["relative_path"]
        expected_raw = prepared["source_manifest_raw_refs"][host_id]["raw_sha256"]
        require(artifact["path"] == str(expected_path) and
                artifact["raw_sha256"] == expected_raw and
                item["semantic_sha256"] == refs[host_id]["sha256"] ==
                source["manifest_sha256"],
                f"Source5 {host_id} source manifest differs from the original SpecV3 reference")
    artifact_root = _safe_root(Path(manifest["artifact_root"]), "Source5 private artifact root")
    output_root = _safe_root(Path(manifest["output_root"]), "Source5 private output root")
    require(artifact_root == Path(manifest["artifact_root"]) and
            output_root == prepared["output_root"] and
            stat.S_IMODE(artifact_root.stat().st_mode) == 0o700 and
            stat.S_IMODE(output_root.stat().st_mode) == 0o700 and
            artifact_root.stat().st_uid == output_root.stat().st_uid == os.getuid(),
            "Source5 artifact/output roots are not canonical owned private directories")
    require(not _within(prepared["source_root"], artifact_root) and
            not _within(prepared["source_root"], output_root) and
            not _within(prepared["input_root"], output_root),
            "Source5 private roots overlap SourceV5 or original campaign inputs")
    original_artifact_root = Path(original["campaign_artifacts_root"])
    require(original_artifact_root.is_absolute() and
            original_artifact_root.resolve(strict=True) == original_artifact_root and
            not _within(prepared["source_root"], original_artifact_root),
            "Source5 original campaign artifact root is not canonical or is inside SourceV5")
    sources = _exact(manifest["execution_sources"], set(host_ids),
                     "Source5 execution source snapshots")
    for host_id in host_ids:
        item = _exact(sources[host_id], {
            "source_root", "git_commit", "source_tree_sha256", "build_sha256",
        }, f"Source5 {host_id} execution source snapshot")
        source = prepared["sources"][host_id]
        _digest(item["source_tree_sha256"], f"Source5 {host_id} source-tree digest")
        _digest(item["build_sha256"], f"Source5 {host_id} build digest")
        require(type(item["source_root"]) is str and Path(item["source_root"]).is_absolute() and
                item["git_commit"] == source["source"]["git_commit"] and
                item["source_tree_sha256"] == source["source"]["source_tree_sha256"] and
                item["build_sha256"] == source["build"]["build_sha256"],
                f"Source5 {host_id} execution source differs from its original SourceV5 manifest")
        if host_id == prepared["host_id"]:
            require(Path(item["source_root"]).resolve(strict=True) == prepared["source_root"],
                    "Source5 selected source root differs from the active original source snapshot")
    module_map = _exact(manifest["modules"], set(host_ids), "Source5 module inventory map")
    for host_id in host_ids:
        source = prepared["sources"][host_id]
        records = module_map[host_id]
        require(type(records) is dict, f"Source5 {host_id} module inventory must be path-keyed")
        expected_paths = {
            item["path"] for item in source["source"]["files"]
            if item["kind"] == "file" and item["path"].startswith("scripts/")
            and PurePosixPath(item["path"]).suffix in {".py", ".sh"}
        }
        require(set(records) == expected_paths,
                f"Source5 {host_id} module pins do not cover all regular script dependencies")
        by_path = {item["path"]: item for item in source["source"]["files"]}
        for relative, value in records.items():
            pin = _exact(value, {"path", "sha256"}, f"Source5 {host_id} module pin {relative}")
            inventory = by_path[relative]
            require(pin == {"path": relative, "sha256": inventory["sha256"]},
                    f"Source5 {host_id} module pin differs from its typed inventory record")
            if verify_selected_files and host_id == prepared["host_id"]:
                source_path = _safe_child(prepared["source_root"], relative,
                                          f"Source5 module {relative}")
                module_raw, module_info = _read_stable(source_path, f"Source5 module {relative}", MAX_SOURCE_BYTES)
                mode = f"{stat.S_IFMT(module_info.st_mode) | stat.S_IMODE(module_info.st_mode):06o}"
                require(sha256_bytes(module_raw) == inventory["sha256"] and
                        len(module_raw) == inventory["size"] and mode == inventory["mode"],
                        f"Source5 module {relative} differs from its typed regular-file inventory")
    observed = _exact(manifest["observed_hosts"], set(host_ids),
                      "Source5 observed-host pins")
    for host_id in host_ids:
        item = _exact(observed[host_id], {
            "artifact", "host_fingerprint_sha256", "controls_sha256",
        }, f"Source5 {host_id} observed-host pin")
        _source5_artifact_pin(item["artifact"], f"Source5 {host_id} observed host")
        _digest(item["host_fingerprint_sha256"], f"Source5 {host_id} host fingerprint")
        _digest(item["controls_sha256"], f"Source5 {host_id} host controls")
        if host_id == prepared["host_id"]:
            require(item["artifact"] == {
                "path": str(prepared["prepared"]["host_context_path"]),
                "raw_sha256": prepared["prepared"]["host_context_raw_sha256"],
            } and item["host_fingerprint_sha256"] ==
            prepared["prepared"]["host"]["host_fingerprint_sha256"] and
            item["controls_sha256"] == sha256_bytes(canonical_bytes(
                prepared["prepared"]["host_context"]["controls"])),
                "Source5 selected observed-host pin differs from the original host contract")
    if prepared_v2:
        prepared["source5_execution_manifest"] = manifest
        prepared["source5_prepared_input_completion"] = \
            _verify_source5_prepared_input_generation(manifest, prepared)
    else:
        completions = _exact(manifest["capacity_completions"], set(host_ids),
                             "Source5 capacity completion map")
        for host_id in host_ids:
            item = _exact(completions[host_id], {
                "artifact", "schedule_sha256", "ledger_raw_sha256", "terminal_head",
                "registration_head",
            }, f"Source5 {host_id} capacity completion")
            _source5_artifact_pin(item["artifact"], f"Source5 {host_id} capacity completion")
            for field in ("schedule_sha256", "ledger_raw_sha256", "terminal_head", "registration_head"):
                _digest(item[field], f"Source5 {host_id} capacity {field}")
    return manifest


def _validate_source5_prerequisites(
    phase: str, value: object, state: dict[str, Any],
) -> list[dict[str, Any]]:
    required = {
        "exploration": (),
        "aa": ("exploration",),
        "confirmation": ("exploration", "aa"),
        "pressure": ("fixed_analysis",),
        "soak": ("pressure_analysis",),
    }[phase]
    require(type(value) is list and len(value) == len(required),
            f"Source5 {phase} helper has the wrong prerequisite count")
    results: list[dict[str, Any]] = []
    for index, required_phase in enumerate(required):
        item = _exact(value[index], {
            "phase", "analysis", "analysis_sha256", "event_head",
        }, f"Source5 {phase} prerequisite[{index}]")
        analysis = _source5_artifact_pin(item["analysis"],
                                         f"Source5 {required_phase} analysis")
        _digest(item["analysis_sha256"], f"Source5 {required_phase} analysis digest")
        _digest(item["event_head"], f"Source5 {required_phase} chronology head")
        prior = state["source5_analyses"].get(required_phase)
        require(item["phase"] == required_phase and prior is not None and
                prior["phase_gate_passed"] is True and
                prior["analysis"] == analysis and
                prior["analysis_sha256"] == item["analysis_sha256"] and
                prior["event_head"] == item["event_head"],
                f"Source5 {phase} lacks a verified passing {required_phase} analysis prerequisite")
        results.append(item)
    return results


def _verify_source5_record_evidence(
    record: dict[str, Any], prepared: dict[str, Any],
) -> None:
    """Re-read every content-addressed artifact named by a successful job record."""
    phase = record["job"]["phase"]
    common = {"execution_manifest", "helper_input", "helper_module"}
    if phase in {"exploration", "aa", "confirmation"}:
        actual = record["evidence"]
        if type(actual) is dict and set(actual) == common | {"overlay", "receipt"}:
            evidence = _exact(actual, common | {"overlay", "receipt"},
                              "Source5 fixed-pair record evidence")
        else:
            evidence = _exact(actual, common | {
                "kind", "overlay", "receipt", "processes", "runtime_bindings",
                "source_snapshot",
            }, "Source5 controller fixed-pair record evidence")
            require(evidence["kind"] == "source5_fixed_pair",
                    "Source5 fixed record evidence kind differs")
            for key, label in (("processes", "fixed process ledger"),
                               ("runtime_bindings", "fixed runtime bindings")):
                pin = _source5_artifact_pin(evidence[key], f"Source5 {label}")
                _source5_reference(pin, f"Source5 {label}")
            _validate_source5_source_snapshot(evidence["source_snapshot"], prepared)
        expected_helper = "scripts/application-fixed-pair.py"
        for key, label in (("overlay", "fixed-pair overlay"),
                           ("receipt", "fixed-pair receipt")):
            pin = _source5_artifact_pin(evidence[key], f"Source5 {label}")
            _source5_reference(pin, f"Source5 {label}")
    elif phase == "pressure":
        actual = record["evidence"]
        if type(actual) is dict and set(actual) == common | {"pressure", "recipe"}:
            evidence = _exact(actual, common | {"pressure", "recipe"},
                              "Source5 pressure record evidence")
        else:
            evidence = _exact(actual, common | {
                "kind", "recipe", "overlay", "readback", "processes",
                "fixed_predecessor", "source_snapshot",
            }, "Source5 controller pressure record evidence")
            require(evidence["kind"] == "source5_pressure_pair",
                    "Source5 pressure record evidence kind differs")
            for key, label in (("overlay", "pressure overlay"),
                               ("readback", "pressure readback"),
                               ("processes", "pressure process ledger"),
                               ("fixed_predecessor", "pressure fixed predecessor")):
                pin = _source5_artifact_pin(evidence[key], f"Source5 {label}")
                _source5_reference(pin, f"Source5 {label}")
            _validate_source5_source_snapshot(evidence["source_snapshot"], prepared)
        expected_helper = "scripts/application-pressure-pair.py"
        for key, label in (("pressure", "pressure readback"),
                           ("recipe", "pressure recipe")):
            pin = _source5_artifact_pin(evidence[key], f"Source5 {label}")
            _source5_reference(pin, f"Source5 {label}")
    elif phase == "soak":
        evidence = _exact(record["evidence"], common | {
            "kind", "soak_component",
        }, "Source5 Soak record evidence")
        require(evidence["kind"] == "source5_timed_soak",
                "Source5 Soak record evidence kind differs")
        expected_helper = "scripts/application-source5-soak.py"
        component_pin = _source5_artifact_pin(
            evidence["soak_component"], "Source5 Soak component",
        )
        _source5_reference(component_pin, "Source5 Soak component")
    else:
        raise ChronologyError("Source5 record evidence uses an unsupported phase")
    for key, label in (("execution_manifest", "execution manifest"),
                       ("helper_input", "helper input")):
        pin = _source5_artifact_pin(evidence[key], f"Source5 {label}")
        _source5_reference(pin, f"Source5 {label}")
    helper_module = _exact(evidence["helper_module"], {
        "path", "sha256", "size", "mode", "kind",
    }, "Source5 helper module evidence")
    require(helper_module["path"] == expected_helper,
            "Source5 recorded helper module does not match the original phase role")
    _raw, helper_sha, helper_record = _source_file(
        prepared["source_root"], prepared["source"], helper_module["path"],
        "Source5 recorded helper module", maximum=MAX_SCRIPT_BYTES,
    )
    require(helper_sha == helper_module["sha256"] and
            helper_record == helper_module,
            "Source5 recorded helper module no longer matches its typed source pin")


def _validate_source5_source_snapshot(
    value: object, prepared: dict[str, Any],
) -> None:
    snapshot = _exact(value, {
        "artifact", "semantic_sha256", "source_tree_sha256",
    }, "Source5 component source snapshot")
    artifact = _source5_artifact_pin(snapshot["artifact"],
                                     "Source5 component source manifest")
    expected_ref = _exact(
        prepared["source_manifest_raw_refs"][prepared["host_id"]],
        {"host_id", "path", "raw_sha256", "semantic_sha256",
         "source_tree_sha256"},
        "Source5 selected source-manifest generation pin",
    )
    require(expected_ref["host_id"] == prepared["host_id"] and
            artifact["path"] == expected_ref["path"] and
            artifact["raw_sha256"] == expected_ref["raw_sha256"] and
            snapshot["semantic_sha256"] == prepared["source"]["manifest_sha256"] and
            snapshot["semantic_sha256"] == expected_ref["semantic_sha256"] and
            snapshot["source_tree_sha256"] ==
                prepared["source"]["source"]["source_tree_sha256"] ==
                    expected_ref["source_tree_sha256"],
            "Source5 component source snapshot differs from the exact selected source generation")


def _source5_phase_records(
    prepared: dict[str, Any], state: dict[str, Any], phase: str,
) -> tuple[list[dict[str, Any]], str]:
    if phase == "soak":
        return _source5_soak_phase_records(prepared, state)
    host_id = prepared["host_id"]
    campaign_id = prepared["campaign_id"]
    expected_jobs = [job for job in prepared["plan"]["jobs"].get(phase, [])
                     if type(job) is dict and job.get("host_id") == host_id]
    require(expected_jobs, f"Source5 analysis has no original {phase} jobs")
    phase_root = (prepared["output_root"] / campaign_id / "source5" /
                  host_id / phase)
    ledger_path = phase_root / "controller-ledger.jsonl"
    ledger_raw, _ledger_info = _read_stable(
        ledger_path, f"Source5 {phase} analysis ledger", MAX_JOURNAL_BYTES,
    )
    require(ledger_raw.endswith(b"\n") and b"\r" not in ledger_raw,
            f"Source5 {phase} analysis ledger framing differs")
    try:
        ledger_records = [json.loads(line) for line in ledger_raw.splitlines()]
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ChronologyError(f"Source5 {phase} analysis ledger is malformed") from error
    require(len(ledger_records) == len(expected_jobs),
            f"Source5 {phase} analysis ledger is incomplete")
    records: list[dict[str, Any]] = []
    record_raw_hashes: list[str] = []
    for index, (record, job) in enumerate(zip(ledger_records, expected_jobs, strict=True)):
        record = _exact(record, {
            "schema", "state", "job", "pair_directory", "process_metrics",
            "evidence", "chronology", "qualification_eligible", "record_sha256",
        }, f"Source5 {phase} record[{index}]")
        body = {key: value for key, value in record.items() if key != "record_sha256"}
        require(record["schema"] == SOURCE5_JOB_RECORD_SCHEMA and
                record["state"] == "valid_pair" and
                record["qualification_eligible"] is False and
                record["job"] == job and
                record["record_sha256"] == sha256_bytes(canonical_bytes(body)),
                f"Source5 {phase} record[{index}] identity/state/digest differs")
        record_path = phase_root / "job-records" / f"{job['run_id']}.json"
        file_raw, _file_info = _read_stable(
            record_path, f"Source5 {phase} job record", MAX_EVENT_BYTES,
        )
        require(file_raw == canonical_bytes(record),
                f"Source5 {phase} record file differs from its canonical phase ledger line")
        file_sha = sha256_bytes(file_raw)
        finished = state["source5_finished"].get((phase, job["run_id"]))
        require(finished is not None and finished["state"] == "valid_pair",
                f"Source5 {phase} record[{index}] has no successful durable authorization")
        evidence = record["evidence"]
        details = finished["details"]
        require(evidence["execution_manifest"] == details["execution_manifest"] and
                evidence["helper_input"] == details["helper_input"] and
                evidence["helper_module"] == details["helper_module"],
                f"Source5 {phase} record[{index}] evidence differs from its authorized input pins")
        _verify_source5_record_evidence(record, prepared)
        _helper_input_path, helper_input_raw, _helper_input_sha = _source5_reference(
            evidence["helper_input"], f"Source5 {phase} authorized helper input",
        )
        helper_input = _parse_object(
            helper_input_raw, f"Source5 {phase} authorized helper input", MAX_PLAN_BYTES,
        )
        payload = helper_input.get("payload")
        require(type(payload) is dict,
                f"Source5 {phase} authorized helper input has no payload object")
        if phase in {"exploration", "aa", "confirmation"}:
            overlay_pin = _exact(payload.get("overlay_pin"), {"path", "sha256"},
                                 "Source5 authorized fixed-pair overlay pin")
            require(evidence["overlay"] == {
                "path": overlay_pin["path"], "raw_sha256": overlay_pin["sha256"],
            }, "Source5 record overlay differs from the original authorized helper input")
        elif phase == "pressure":
            recipe_pin = _exact(payload.get("recipe_pin"), {"path", "raw_sha256"},
                                "Source5 authorized pressure recipe pin")
            require(evidence["recipe"] == recipe_pin,
                    "Source5 record recipe differs from the original authorized helper input")
        else:
            component_pin = _source5_artifact_pin(
                evidence["soak_component"], "Source5 Soak component",
            )
            output_root = Path(payload["output_root"])
            require(component_pin["path"] ==
                    str(output_root / "source5-soak-component.json") and
                    record["pair_directory"] == str(output_root),
                    "Source5 Soak component is outside the exact authorized output directory")
            _component_path, component_raw, component_sha = _source5_reference(
                component_pin, "Source5 Soak component",
            )
            component = _parse_object(component_raw, "Source5 Soak component",
                                      MAX_EVENT_BYTES)
            helper_raw, _helper_sha, _helper_record = _source_file(
                prepared["source_root"], prepared["source"],
                "scripts/application-source5-soak.py",
                "Source5 Soak component verifier", maximum=MAX_SCRIPT_BYTES,
            )
            helper_module_value = _load_module(
                helper_raw,
                prepared["source_root"] / "scripts/application-source5-soak.py",
                "source5_soak_component_verifier",
            )
            readback_module = helper_module_value._load_readback_module(prepared)
            readback = helper_module_value.verify_source5_soak_component(
                component, prepared, record["job"], details, readback_module,
            )
            require(component_sha == component_pin["raw_sha256"] and
                    readback == component["readback"] ==
                    record["process_metrics"][0] and
                    component["passed"] is (record["state"] == "valid_soak"),
                    "Source5 Soak component did not freshly replay its exact one-APP numeric gate")
        chronology = _exact(record["chronology"], {
            "authorization_id", "authorization_head", "app_started_heads",
            "app_terminal_heads", "job_terminal_head", "component_sha256",
            "process_metrics_sha256", "app_start_events", "app_terminal_events",
            "member_processes",
        }, f"Source5 {phase} record chronology")
        metrics = record["process_metrics"]
        require(finished is not None and finished["state"] == "valid_pair" and
                finished["details"]["job"] == job and
                chronology["authorization_id"] == finished["authorization_id"] and
                chronology["authorization_head"] == finished["authorization_head"] and
                chronology["job_terminal_head"] == finished["record_sha256"] and
                chronology["component_sha256"] == finished["terminal"]["component_sha256"] and
                chronology["process_metrics_sha256"] ==
                    finished["terminal"]["process_metrics_sha256"] ==
                    sha256_bytes(canonical_bytes(metrics)) and
                chronology["app_started_heads"] ==
                    [item["event_head"] for item in finished["starts"]] and
                chronology["app_terminal_heads"] ==
                    [item["event_head"] for item in finished["terminals"]] and
                chronology["app_start_events"] ==
                    [item["proof"] for item in finished["starts"]],
                f"Source5 {phase} record[{index}] metrics or lifecycle differs from its durable journal chain")
        require(type(metrics) is list and len(metrics) == 2 and
                all(type(item) is dict for item in metrics),
                f"Source5 {phase} record[{index}] lacks two canonical process metrics")
        records.append(record)
        record_raw_hashes.append(file_sha)
    controller = prepared["controller"]
    controller.validate_phase_ledger(records, expected_jobs, phase, host_id)
    require(all(record["state"] == "valid_pair" for record in records),
            f"Source5 {phase} analysis has an invalid original ordinal")
    return records, sha256_bytes(canonical_bytes({
        "ledger_raw_sha256": sha256_bytes(ledger_raw),
        "record_raw_sha256": record_raw_hashes,
    }))


def _source5_soak_phase_records(
    prepared: dict[str, Any], state: dict[str, Any],
) -> tuple[list[dict[str, Any]], str]:
    host_id = prepared["host_id"]
    campaign_id = prepared["campaign_id"]
    expected_jobs = [job for job in prepared["plan"]["jobs"].get("soak", [])
                     if type(job) is dict and job.get("host_id") == host_id]
    require(len(expected_jobs) == 1,
            "Source5 Soak verifier requires exactly one original host job")
    phase_root = (prepared["output_root"] / campaign_id / "source5" /
                  host_id / "soak")
    ledger_path = phase_root / "controller-ledger.jsonl"
    ledger_raw, _ledger_info = _read_stable(
        ledger_path, "Source5 soak analysis ledger", MAX_JOURNAL_BYTES,
    )
    require(ledger_raw.endswith(b"\n") and b"\r" not in ledger_raw,
            "Source5 Soak analysis ledger framing differs")
    try:
        lines = ledger_raw.splitlines(keepends=True)
        records = [json.loads(line) for line in lines]
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ChronologyError("Source5 Soak analysis ledger is malformed") from error
    require(len(records) == len(expected_jobs) == 1,
            "Source5 Soak ledger does not contain exactly one original ordinal")
    record = _exact(records[0], {
        "schema", "state", "job", "pair_directory", "process_metrics",
        "evidence", "chronology", "qualification_eligible", "record_sha256",
    }, "Source5 Soak job record")
    body = {key: value for key, value in record.items() if key != "record_sha256"}
    require(lines[0] == canonical_bytes(record) and
            record["schema"] == SOURCE5_JOB_RECORD_SCHEMA and
            record["state"] in {"valid_soak", "invalid_soak"} and
            record["job"] == expected_jobs[0] and
            record["qualification_eligible"] is False and
            record["record_sha256"] == sha256_bytes(canonical_bytes(body)),
            "Source5 Soak job record differs from its original ordinal or digest")
    record_path = phase_root / "job-records" / f"{record['job']['run_id']}.json"
    record_raw, _record_info = _read_stable(
        record_path, "Source5 Soak job record", MAX_EVENT_BYTES,
    )
    require(record_raw == lines[0],
            "Source5 Soak record file differs from its one-line controller ledger")
    finished = state["source5_finished"].get(("soak", record["job"]["run_id"]))
    require(finished is not None and finished["state"] == record["state"] and
            finished["details"]["job"] == record["job"],
            "Source5 Soak record has no matching successful/invalid durable authorization")
    _validate_source5_authorization(finished["details"], prepared, state)
    _verify_source5_record_evidence(record, prepared)
    chronology = _exact(record["chronology"], {
        "authorization_id", "authorization_head", "app_started_heads",
        "app_terminal_heads", "job_terminal_head", "component_sha256",
        "process_metrics_sha256", "app_start_events", "app_terminal_events",
        "member_processes",
    }, "Source5 Soak chronology")
    metrics = record["process_metrics"]
    terminal = finished["terminals"][0]
    expected_terminal_event = {
        "campaign_id": prepared["campaign_id"],
        "host_id": host_id,
        "run_id": record["job"]["run_id"],
        "descriptor": terminal["descriptor"],
        "member_ordinal": 0,
        "pid": terminal["pid"],
        "status": terminal["status"],
        "child_return_code": terminal["child_return_code"],
        "signal": terminal["signal"],
        "cleanup": terminal["cleanup"],
        "terminal_monotonic_ns": terminal["terminal_monotonic_ns"],
    }
    require(type(metrics) is list and len(metrics) == 1 and
            type(metrics[0]) is dict and
            chronology["authorization_id"] == finished["authorization_id"] and
            chronology["authorization_head"] == finished["authorization_head"] and
            chronology["job_terminal_head"] == finished["record_sha256"] and
            chronology["component_sha256"] == finished["terminal"]["component_sha256"] and
            chronology["process_metrics_sha256"] ==
                finished["terminal"]["process_metrics_sha256"] ==
                sha256_bytes(canonical_bytes(metrics)) and
            chronology["app_started_heads"] ==
                [item["event_head"] for item in finished["starts"]] and
            chronology["app_terminal_heads"] ==
                [item["event_head"] for item in finished["terminals"]] and
            chronology["app_start_events"] ==
                [item["proof"] for item in finished["starts"]] and
            chronology["app_terminal_events"] == [expected_terminal_event] and
            chronology["member_processes"] == [{
                "descriptor": finished["starts"][0]["descriptor"],
                "pid": finished["starts"][0]["pid"],
                "start_ticks": finished["starts"][0]["start_ticks"],
                "member_index": 0,
            }],
            "Source5 Soak metrics or one-member callback chain differs from durable chronology")
    component_pin = record["evidence"]["soak_component"]
    component_path, component_raw, component_sha = _source5_reference(
        component_pin, "Source5 Soak component",
    )
    component = _parse_object(component_raw, "Source5 Soak component", MAX_EVENT_BYTES)
    helper_raw, _helper_sha, _helper_entry = _source_file(
        prepared["source_root"], prepared["source"],
        "scripts/application-source5-soak.py", "Source5 Soak component replay",
        maximum=MAX_SCRIPT_BYTES,
    )
    helper_module = _load_module(
        helper_raw, prepared["source_root"] / "scripts/application-source5-soak.py",
        "source5_soak_analysis_replay",
    )
    readback_module = helper_module._load_readback_module(prepared)
    replayed_readback = helper_module.verify_source5_soak_component(
        component, prepared, record["job"], finished["details"],
        readback_module,
    )
    require(component_path == Path(record["pair_directory"]) /
            "source5-soak-component.json" and
            component_sha == component_pin["raw_sha256"] and
            sha256_bytes(canonical_bytes(component)) ==
                chronology["component_sha256"] and
            replayed_readback == metrics[0] == component["readback"] and
            component["passed"] is (record["state"] == "valid_soak"),
            "Source5 Soak full artifact and readback replay differs from its durable record")
    return [record], sha256_bytes(canonical_bytes({
        "ledger_raw_sha256": sha256_bytes(ledger_raw),
        "record_raw_sha256": [sha256_bytes(record_raw)],
    }))


def _source5_comparable_analysis(value: object) -> object:
    normalized = json.loads(canonical_bytes(value))
    if type(normalized) is dict and type(normalized.get("bootstrap")) is dict:
        bootstrap = normalized["bootstrap"]
        # The Rust analyzer reports process-specific resource/timing metadata.
        # Its intervals, gates, input pins, and all other protocol fields remain
        # exact comparisons against an independent rerun.
        for name in ("analyzer_wall_seconds", "resident_peak_bytes", "output_sha256"):
            bootstrap.pop(name, None)
    return normalized


def _source5_analysis_matches_replay(
    phase: str, actual: object, expected: object,
) -> bool:
    if phase in {"fixed_analysis", "pressure_analysis"}:
        return _source5_comparable_analysis(actual) == \
            _source5_comparable_analysis(expected)
    return actual == expected


def _recompute_source5_analysis(
    analysis: dict[str, Any], prepared: dict[str, Any],
    state: dict[str, Any], details: dict[str, Any], analysis_sha: str,
) -> tuple[dict[str, Any], bool]:
    phase = analysis["phase"]
    require(phase in {
        "exploration", "aa", "fixed_analysis", "pressure_analysis",
        "soak", "final_analysis",
    }, "Source5 analysis phase is outside its closed original phase enum")
    source_phase = {"fixed_analysis": "confirmation",
                    "pressure_analysis": "pressure",
                    "soak": "soak", "final_analysis": "soak"}.get(phase, phase)
    records, records_sha = _source5_phase_records(prepared, state, source_phase)
    source5_controller_raw, source5_controller_sha, _source5_record = _source_file(
        prepared["source_root"], prepared["source"],
        "scripts/application-source5-campaign.py",
        "Source5 campaign analysis helper", maximum=MAX_SCRIPT_BYTES,
    )
    source5_controller = _load_module(
        source5_controller_raw,
        prepared["source_root"] / "scripts/application-source5-campaign.py",
        f"source5_analysis_{source5_controller_sha}",
    )
    if phase == "exploration":
        fixed_raw, _fixed_sha, _fixed_record = _source_file(
            prepared["source_root"], prepared["source"],
            "scripts/application-fixed-pair.py", "Source5 fixed-pair analysis verifier",
            maximum=MAX_SCRIPT_BYTES,
        )
        fixed_module = _load_module(
            fixed_raw, prepared["source_root"] / "scripts/application-fixed-pair.py",
            f"source5_capacity_analysis_{analysis_sha}",
        )
        phase_context = types.SimpleNamespace(
            campaign=prepared["controller"], fixed_pair=fixed_module,
            spec=prepared["spec"], plan=prepared["plan"],
            host_id=prepared["host_id"],
        )
        pilot = source5_controller._capacity_pilot(phase_context, records)
        pilot_ref = _source5_artifact_pin(
            analysis["analysis"]["pilot"], "Source5 exploration pilot",
        )
        pilot_path, pilot_raw, pilot_sha = _source5_reference(
            pilot_ref, "Source5 exploration pilot",
        )
        require(pilot_raw == canonical_bytes(pilot),
                "Source5 exploration pilot differs from the independently reconstructed six-pair export")
        frozen = prepared["controller"].freeze_rates(
            prepared["spec"], pilot, pilot_sha,
        )
        expected_rates = source5_controller._frozen_rate_rows(
            prepared["host_id"], frozen, pilot_sha,
        )
        existing = [row for row in prepared["spec"]["rates"]
                    if row["host_id"] == prepared["host_id"]]
        if prepared["spec"]["rates"] and prepared["spec"]["oracles"]:
            require(existing == expected_rates,
                    "retained exploration data do not reproduce the final frozen numeric/provenance rate rows")
            rate_status = "verified_against_final_frozen_spec"
        else:
            require(not prepared["spec"]["rates"] and not prepared["spec"]["oracles"],
                    "prospective exploration has only one of rates/oracles frozen")
            rate_status = "candidate_for_separate_final_freeze"
        candidate = {
            "schema": "allocatbelt.application-source5-rate-candidate.v1",
            "scope": "final_frozen" if existing else "prospective_exploration",
            "pilot": {"path": str(pilot_path), "raw_sha256": pilot_sha},
            "candidate_rates": expected_rates,
            "original_spec_rates": existing,
            "status": rate_status,
            "qualification_eligible": False,
        }
        candidate_ref = _source5_artifact_pin(
            analysis["analysis"]["rate_candidate"],
            "Source5 exploration rate candidate",
        )
        candidate_path, candidate_raw, candidate_sha = _source5_reference(
            candidate_ref, "Source5 exploration rate candidate",
        )
        expected_analysis = {
                    "schema": "allocatbelt.application-source5-exploration-analysis.v1",
                    "scope": candidate["scope"],
                    "pilot": {"path": str(pilot_path), "raw_sha256": pilot_sha},
                    "rate_candidate": {"path": str(candidate_path),
                                       "raw_sha256": candidate_sha},
                    "rate_status": rate_status,
                }
        require(candidate_raw == canonical_bytes(candidate) and
                details["numeric_gates_passed"] is True,
                "Source5 exploration rate candidate differs from its independent replay")
        numeric = True
    elif phase == "aa":
        expected_jobs = [job for job in prepared["plan"]["jobs"]["aa"]
                         if job["host_id"] == prepared["host_id"]]
        expected_analysis = prepared["controller"].validate_aa_records(
            records, expected_jobs, prepared["host_id"],
            prepared["spec"]["protocol"]["bootstrap_draws"],
            prepared["spec"]["protocol"]["bootstrap_seed"],
        )
        numeric = expected_analysis.get("passed") is True
    elif phase in {"fixed_analysis", "pressure_analysis"}:
        analyzer = prepared["source"].get("analysis_artifact")
        require(type(analyzer) is dict and set(analyzer) == {"path", "sha256"},
                "Source5 numeric analysis has no pinned Rust analyzer")
        _digest(analyzer["sha256"], "Source5 Rust paired-analysis binary SHA-256")
        analyzer_path = _safe_child(
            prepared["source_root"], analyzer["path"],
            "Source5 Rust paired-analysis binary",
        )
        analyzer_raw, analyzer_info = _read_stable(
            analyzer_path, "Source5 Rust paired-analysis binary", MAX_ANALYZER_BYTES,
        )
        analyzer_sha = sha256_bytes(analyzer_raw)
        require(analyzer_sha == analyzer["sha256"] and analyzer_info.st_mode & 0o111,
                "Source5 Rust paired-analysis binary differs from its SourceV5 pin")
        expected_analysis = prepared["controller"].analyze_confirmation_host_numeric(
            prepared["spec"], prepared["host_id"], records,
            prepared["output_root"], analyzer_path, analyzer_sha,
            phase="confirmation" if phase == "fixed_analysis" else "pressure",
        )
        numeric = expected_analysis.get("numeric_gates_passed") is True
    elif phase == "soak":
        record = records[0]
        readback = record["process_metrics"][0]
        expected_analysis = {
            "schema": "allocatbelt.application-source5-soak-analysis.v1",
            "component": record["evidence"]["soak_component"],
            "readback": readback,
            "record_sha256": record["record_sha256"],
        }
        numeric = readback.get("passed") is True
    else:
        required_phases = (
            "exploration", "aa", "fixed_analysis", "pressure_analysis", "soak",
        )
        prior_events = [state["source5_analyses"].get(name)
                        for name in required_phases]
        require(all(type(item) is dict for item in prior_events),
                "Source5 final analysis lacks each durable original phase event")
        phase_records = {
            name: _source5_phase_records(prepared, state, source_name)
            for name, source_name in (
                ("exploration", "exploration"),
                ("aa", "aa"),
                ("fixed_analysis", "confirmation"),
                ("pressure_analysis", "pressure"),
                ("soak", "soak"),
            )
        }
        fixed_raw, _fixed_sha, _fixed_record = _source_file(
            prepared["source_root"], prepared["source"],
            "scripts/application-fixed-pair.py",
            "Source5 final fixed-pair replay", maximum=MAX_SCRIPT_BYTES,
        )
        fixed_module = _load_module(
            fixed_raw, prepared["source_root"] / "scripts/application-fixed-pair.py",
            f"source5_final_capacity_{analysis_sha}",
        )
        phase_context = types.SimpleNamespace(
            campaign=prepared["controller"], fixed_pair=fixed_module,
            spec=prepared["spec"], plan=prepared["plan"],
            host_id=prepared["host_id"],
        )
        exploration_records = phase_records["exploration"][0]
        pilot = source5_controller._capacity_pilot(phase_context, exploration_records)
        exploration_analysis_pin = prior_events[0]["analysis"]
        _exploration_path, exploration_raw, _exploration_sha = _source5_reference(
            exploration_analysis_pin, "Source5 original exploration analysis",
        )
        exploration_value = _parse_object(
            exploration_raw, "Source5 original exploration analysis", MAX_EVENT_BYTES,
        )
        pilot_pin = _source5_artifact_pin(
            exploration_value["analysis"]["pilot"],
            "Source5 original frozen exploration pilot",
        )
        pilot_path, pilot_raw, pilot_sha = _source5_reference(
            pilot_pin, "Source5 original frozen exploration pilot",
        )
        require(pilot_raw == canonical_bytes(pilot),
                "Source5 final analysis pilot differs from fresh six-pair replay")
        frozen = prepared["controller"].freeze_rates(
            prepared["spec"], pilot, pilot_sha,
        )
        expected_rates = source5_controller._frozen_rate_rows(
            prepared["host_id"], frozen, pilot_sha,
        )
        existing_rates = [item for item in prepared["spec"]["rates"]
                          if item["host_id"] == prepared["host_id"]]
        gate_exploration = existing_rates == expected_rates
        aa_records = phase_records["aa"][0]
        aa_jobs = [job for job in prepared["plan"]["jobs"]["aa"]
                   if job["host_id"] == prepared["host_id"]]
        aa_result = prepared["controller"].validate_aa_records(
            aa_records, aa_jobs, prepared["host_id"],
            prepared["spec"]["protocol"]["bootstrap_draws"],
            prepared["spec"]["protocol"]["bootstrap_seed"],
        )
        analyzer = prepared["source"].get("analysis_artifact")
        require(type(analyzer) is dict and set(analyzer) == {"path", "sha256"},
                "Source5 final analysis has no pinned Rust paired analyzer")
        analyzer_path = _safe_child(
            prepared["source_root"], analyzer["path"],
            "Source5 final Rust paired-analysis binary",
        )
        analyzer_raw, analyzer_info = _read_stable(
            analyzer_path, "Source5 final Rust paired-analysis binary",
            MAX_ANALYZER_BYTES,
        )
        analyzer_sha = sha256_bytes(analyzer_raw)
        require(analyzer_sha == analyzer["sha256"] and analyzer_info.st_mode & 0o111,
                "Source5 final Rust analyzer differs from its SourceV5 pin")
        fixed_result = prepared["controller"].analyze_confirmation_host_numeric(
            prepared["spec"], prepared["host_id"],
            phase_records["fixed_analysis"][0], prepared["output_root"],
            analyzer_path, analyzer_sha, phase="confirmation",
        )
        pressure_result = prepared["controller"].analyze_confirmation_host_numeric(
            prepared["spec"], prepared["host_id"],
            phase_records["pressure_analysis"][0], prepared["output_root"],
            analyzer_path, analyzer_sha, phase="pressure",
        )
        soak_record = phase_records["soak"][0][0]
        gates = [
            gate_exploration,
            aa_result.get("passed") is True,
            fixed_result.get("numeric_gates_passed") is True,
            pressure_result.get("numeric_gates_passed") is True,
            soak_record["process_metrics"][0].get("passed") is True,
        ]
        for event, gate, required_phase in zip(
            prior_events, gates, required_phases, strict=True,
        ):
            require(event["phase_gate_passed"] is gate,
                    f"Source5 final {required_phase} gate differs from fresh numeric replay")
        record_digests = {
            name: value[1] for name, value in phase_records.items()
        }
        phase_results = [{
            "phase": name,
            "numeric_gates_passed": gate,
            "analysis_sha256": event["analysis_sha256"],
            "event_head": event["event_head"],
            "records_sha256": record_digests[name],
        } for name, gate, event in zip(required_phases, gates, prior_events, strict=True)]
        source_manifest_pins = {
            host: {"path": refs["path"], "raw_sha256": refs["raw_sha256"]}
            for host, refs in prepared["source_manifest_raw_refs"].items()
        }
        decision_context = types.SimpleNamespace(
            manifest=prepared["source5_execution_manifest"],
            host_id=prepared["host_id"],
            spec_pin={
                "path": prepared["prepared"]["spec_path"],
                "raw_sha256": prepared["prepared"]["spec_raw_sha256"],
            },
            plan_pin={
                "path": prepared["prepared"]["plan_path"],
                "raw_sha256": prepared["prepared"]["plan_raw_sha256"],
            },
            spec_semantic_sha256=prepared["prepared"]["spec_semantic_sha256"],
            plan_semantic_sha256=prepared["prepared"]["plan_semantic_sha256"],
            prepared_input_completion=prepared["source5_prepared_input_completion"],
            source_manifest_pins=source_manifest_pins,
            source=prepared["source"],
        )
        expected_analysis = source5_controller._source5_final_decision_value(
            decision_context, phase_results,
        )
        numeric = expected_analysis["numeric_gates_passed"] is True
    require(type(numeric) is bool and numeric is details["numeric_gates_passed"] and
            analysis["phase_gate_passed"] is numeric and
            analysis["campaign_qualification_eligible"] is False,
            f"Source5 {phase} phase gate differs from independently recomputed metrics")
    require(_source5_analysis_matches_replay(phase, analysis["analysis"], expected_analysis),
            f"Source5 {phase} analysis artifact differs from independently recomputed canonical analysis")
    return expected_analysis, numeric


def _validate_source5_analysis(
    details_value: object, prepared: dict[str, Any], state: dict[str, Any],
) -> dict[str, Any]:
    details = _exact(details_value, DETAIL_FIELDS["source5_analysis"],
                     "Source5 phase analysis event")
    phase = details["phase"]
    require(phase in {
        "exploration", "aa", "fixed_analysis", "pressure_analysis",
        "soak", "final_analysis",
    }, "Source5 phase analysis uses an unsupported original phase")
    analysis_path, analysis_raw, analysis_sha = _source5_reference(
        details["analysis"], "Source5 phase analysis artifact",
    )
    analysis = _parse_object(analysis_raw, "Source5 phase analysis artifact", MAX_EVENT_BYTES)
    analysis_material = {key: value for key, value in analysis.items()
                         if key != "analysis_sha256"}
    require(analysis_sha == details["analysis_sha256"] and
            analysis.get("schema") == "allocatbelt.application-source5-phase-analysis.v1" and
            analysis.get("analysis_sha256") ==
                sha256_bytes(canonical_bytes(analysis_material)) and
            analysis.get("campaign_id") == prepared["campaign_id"] and
            analysis.get("host_id") == prepared["host_id"] and
            analysis.get("phase") == phase and
            analysis.get("job_count") == details["job_count"] and
            analysis.get("job_set_sha256") == details["job_set_sha256"] and
            analysis.get("job_evidence_complete") == details["job_evidence_complete"] and
            analysis.get("numeric_gates_passed") == details["numeric_gates_passed"] and
            analysis.get("phase_gate_passed") == details["phase_gate_passed"] and
            analysis.get("campaign_qualification_eligible") == details["campaign_qualification_eligible"],
            "Source5 phase analysis artifact differs from its durable chronology event")
    require(details["job_evidence_complete"] is True and
            type(details["numeric_gates_passed"]) is bool and
            details["phase_gate_passed"] is details["numeric_gates_passed"] and
            details["campaign_qualification_eligible"] is False,
            "Source5 analysis did not separate numeric gates from false campaign eligibility")
    source_phase = {
        "fixed_analysis": "confirmation",
        "pressure_analysis": "pressure",
        "final_analysis": "soak",
    }.get(phase, phase)
    expected = [job for job in prepared["plan"]["jobs"].get(source_phase, [])
                if type(job) is dict and job.get("host_id") == prepared["host_id"]]
    expected_ids = [job["run_id"] for job in expected]
    expected_set_sha = sha256_bytes(canonical_bytes(expected_ids))
    require(details["job_count"] == len(expected_ids) and
            details["job_set_sha256"] == expected_set_sha,
            "Source5 phase analysis does not identify the exact original job set")
    if phase not in {"final_analysis"}:
        finished = [state["source5_finished"].get((source_phase, run_id))
                    for run_id in expected_ids]
        accepted_states = {"valid_soak", "invalid_soak"} if phase == "soak" else {"valid_pair"}
        require(all(item is not None and item["state"] in accepted_states for item in finished),
                f"Source5 {phase} analysis lacks the complete successful original phase horizon")
    if phase == "aa":
        prior = state["source5_analyses"].get("exploration")
        require(prior is not None and prior["phase_gate_passed"] is True,
                "Source5 A/A analysis lacks the completed exploration analysis")
    if phase == "fixed_analysis":
        _validate_source5_prerequisites("confirmation", [
            {"phase": key, "analysis": value["analysis"],
             "analysis_sha256": value["analysis_sha256"],
             "event_head": value["event_head"]}
            for key in ("exploration", "aa")
            for value in [state["source5_analyses"].get(key)]
            if value is not None
        ], state)
    if phase == "pressure_analysis":
        _validate_source5_prerequisites("pressure", [
            {"phase": key, "analysis": value["analysis"],
             "analysis_sha256": value["analysis_sha256"],
             "event_head": value["event_head"]}
            for key in ("fixed_analysis",)
            for value in [state["source5_analyses"].get(key)]
            if value is not None
        ], state)
    if phase == "soak":
        _validate_source5_prerequisites("soak", [
            {"phase": "pressure_analysis",
             "analysis": state["source5_analyses"]["pressure_analysis"]["analysis"],
             "analysis_sha256": state["source5_analyses"]["pressure_analysis"]["analysis_sha256"],
             "event_head": state["source5_analyses"]["pressure_analysis"]["event_head"]},
        ], state)
    if phase == "final_analysis":
        required_phases = (
            "exploration", "aa", "fixed_analysis", "pressure_analysis", "soak",
        )
        require(all(state["source5_analyses"].get(name) is not None
                    for name in required_phases),
                "Source5 final analysis lacks all original durable phase-analysis events")
    _recompute_source5_analysis(
        analysis, prepared, state, details, analysis_sha,
    )
    return {"path": analysis_path, "value": analysis}


def _verify_source5_probe_capture_bundle_v2(
    bundle_value: object, recipe: dict[str, Any],
    output_root_value: object, artifact_root_value: object,
) -> dict[str, Any]:
    """Check the raw locked two-member ProbeV2 bundle before pressure authorization."""
    bundle = _exact(bundle_value, {"schema", "members"},
                    "Source5 ProbeV2 capture bundle")
    capture_budget = _exact(recipe.get("probe_capture"), {
        "capture_timeout_ns", "storage_budget",
    }, "bounded Source5 pressure recipe ProbeV2 budget")
    _uint(capture_budget["capture_timeout_ns"],
          "bounded Source5 ProbeV2 capture timeout", positive=True,
          maximum=30_000_000_000)
    budget_value = _exact(capture_budget["storage_budget"], {
        "tmpdir_bytes", "tmpdir_inodes", "stdout_bytes", "stderr_bytes",
        "owner_result_bytes", "inventory_bytes", "failure_bytes",
        "receipt_bytes", "output_inodes",
    }, "bounded Source5 ProbeV2 capture storage budget")
    for name, budget_item in budget_value.items():
        _uint(budget_item, f"bounded Source5 ProbeV2 budget {name}",
              positive=True)
    output_root = Path(_path_text(Path(output_root_value),
                                  "Source5 ProbeV2 output root"))
    artifact_root = Path(_path_text(Path(artifact_root_value),
                                    "Source5 ProbeV2 artifact root"))
    require(bundle["schema"] == SOURCE5_PROBE_CAPTURE_BUNDLE_SCHEMA and
            recipe.get("schema") == SOURCE5_PRESSURE_RECIPE_SCHEMA_V2 and
            recipe.get("probe_capture") == capture_budget and
            type(bundle["members"]) is list and len(bundle["members"]) == 2 and
            type(recipe.get("members")) is list and len(recipe["members"]) == 2 and
            _within(artifact_root, output_root),
            "Source5 bounded pressure bundle/recipe has the wrong schema, count, or root")
    for index, row_value in enumerate(bundle["members"]):
        row = _exact(row_value, {
            "ordinal", "construction_probe", "capture_receipt", "capacity_bundle",
        }, f"Source5 ProbeV2 capture bundle member[{index}]")
        probe = _exact(row["construction_probe"], {
            "path", "raw_sha256", "allocator", "binary_sha256",
        }, f"Source5 ProbeV2 construction probe[{index}]")
        expected_probe = _exact(recipe["members"][index].get("construction_probe"), {
            "path", "raw_sha256", "allocator", "binary_sha256",
        }, f"Source5 pressure recipe construction probe[{index}]")
        for name in ("raw_sha256", "binary_sha256"):
            _digest(probe[name], f"Source5 ProbeV2 construction probe {name}[{index}]")
        capacity = _exact(row["capacity_bundle"], {
            "request", "artifact", "receipt",
        }, f"Source5 ProbeV2 capacity bundle[{index}]")
        for name, pin_value in capacity.items():
            pin = _exact(pin_value, {"path", "raw_sha256"},
                         f"Source5 ProbeV2 capacity {name}[{index}]")
            _digest(pin["raw_sha256"],
                    f"Source5 ProbeV2 capacity {name} digest[{index}]")
            require(Path(_path_text(Path(pin["path"]),
                                    f"Source5 ProbeV2 capacity {name} path")).is_absolute(),
                    f"Source5 ProbeV2 capacity {name} path[{index}] is not absolute")
        capture_pin = _exact(row["capture_receipt"], {
            "path", "raw_sha256", "receipt_sha256",
        }, f"Source5 ProbeV2 receipt pin[{index}]")
        _digest(capture_pin["raw_sha256"],
                f"Source5 ProbeV2 receipt raw digest[{index}]")
        _digest(capture_pin["receipt_sha256"],
                f"Source5 ProbeV2 receipt semantic digest[{index}]")
        capture_path, capture_raw, capture_sha = _source5_reference(
            {key: capture_pin[key] for key in ("path", "raw_sha256")},
            f"Source5 ProbeV2 receipt[{index}]",
        )
        require(type(row["ordinal"]) is int and row["ordinal"] == index and
                probe == expected_probe and capacity == recipe.get("capacity_bundle") and
                capture_sha == capture_pin["raw_sha256"] and
                _within(artifact_root, capture_path) and
                _within(output_root, capture_path),
                f"Source5 ProbeV2 bundle row[{index}] differs from its exact recipe/source/job binding")
        capture_value = _parse_object(
            capture_raw, f"Source5 ProbeV2 capture receipt[{index}]",
            MAX_PROBE_CAPTURE_RECEIPT_BYTES,
        )
        require(capture_raw == canonical_bytes(capture_value) and
                capture_value.get("schema") == SOURCE5_PROBE_CAPTURE_RECEIPT_SCHEMA and
                capture_value.get("receipt_sha256") == capture_pin["receipt_sha256"] ==
                    sha256_bytes(canonical_bytes({
                        key: value for key, value in capture_value.items()
                        if key != "receipt_sha256"
                    })) and
                capture_value.get("probe_pin") == probe and
                capture_value.get("capacity_bundle") == capacity and
                capture_value.get("capture_timeout_ns") ==
                    capture_budget["capture_timeout_ns"] and
                capture_value.get("storage_budget") == budget_value and
                capture_value.get("qualification_eligible") is False and
                capture_value.get("execution_ready") is False and
                capture_value.get("controller_chronology_proven") is False,
                f"Source5 ProbeV2 capture receipt[{index}] differs from its exact raw pins or budget")
    return bundle


def _validate_source5_authorization(
    details_value: object, prepared: dict[str, Any], state: dict[str, Any],
) -> dict[str, Any]:
    details = _exact(details_value, DETAIL_FIELDS["source5_authorized"],
                     "Source5 helper authorization")
    require(details["campaign_id"] == prepared["campaign_id"] and
            details["host_id"] == prepared["host_id"] and
            details["qualification_eligible"] is False,
            "Source5 authorization campaign, host, or eligibility differs")
    phase = details["phase"]
    require(phase in {"exploration", "aa", "confirmation", "pressure", "soak"},
            "Source5 authorization has an unsupported original phase")
    job_index = _uint(details["job_index"], "Source5 original job index")
    host_jobs = [job for job in prepared["plan"]["jobs"].get(phase, [])
                 if type(job) is dict and job.get("host_id") == prepared["host_id"]]
    require(job_index < len(host_jobs) and host_jobs[job_index] == details["job"],
            "Source5 authorization job/index differs from the exact original host plan order")
    job = _exact(details["job"], set(details["job"]), "Source5 original job")
    require(job.get("phase") == phase and job.get("host_id") == prepared["host_id"] and
            details["job_sha256"] == sha256_bytes(canonical_bytes(job)),
            "Source5 authorization job digest/phase/host differs")
    member_count = 1 if phase == "soak" else 2
    require(type(details["members"]) is list and len(details["members"]) == member_count,
            "Source5 authorization member count differs from its original phase")
    if phase == "soak":
        require(all(type(item) is dict and set(item) == {
                    "role", "allocator", "executor",
                } and item["role"] == "original_soak_app"
                for item in details["members"]),
                "Source5 Soak authorization is not one closed original APP role")
    else:
        require(all(type(item) is dict and set(item) == {"pair", "executor", "allocator"}
                    for item in details["members"]) and
                len({(item["pair"], item["executor"], item["allocator"])
                     for item in details["members"]}) == 2,
                "Source5 paired authorization descriptors are repeated or malformed")
    require(details["members_sha256"] ==
            sha256_bytes(canonical_bytes(details["members"])),
            "Source5 authorization member list has a different digest")
    manifest_path, manifest_raw, manifest_sha = _source5_reference(
        details["execution_manifest"], "Source5 execution manifest",
    )
    manifest = _parse_object(manifest_raw, "Source5 execution manifest", MAX_PLAN_BYTES)
    _validate_source5_manifest_value(manifest, manifest_raw, prepared)
    if manifest["schema"] == SOURCE5_EXECUTION_SCHEMA:
        registration = state.get("registration")
        require(registration is not None and
                details["capacity_registration_head"] == state.get("registration_head") and
                details["capacity_completion"] == {
                    "path": registration["capacity_completion"]["path"],
                    "raw_sha256": registration["capacity_completion"]["sha256"],
                } and
                details["capacity_ledger_raw_sha256"] == registration["capacity_ledger"]["raw_sha256"] and
                details["capacity_terminal_head"] == registration["capacity_ledger"]["terminal_head"] and
                details["capacity_schedule_sha256"] == registration["capacity_schedule_sha256"],
                "Source5 authorization is not descended from the currently registered legacy capacity head")
    else:
        registration = state.get("prepared_capacity_registration")
        capacity = manifest["prepared_capacity_registration"]
        require(registration is not None and
                details["capacity_registration_head"] == state.get("registration_head") and
                details["capacity_completion"] == capacity["host_completion"] ==
                    registration["host_completion"] and
                details["capacity_ledger_raw_sha256"] ==
                    capacity["ledger"]["raw_sha256"] ==
                    registration["capacity_ledger"]["raw_sha256"] and
                details["capacity_terminal_head"] ==
                    capacity["ledger"]["terminal_head"] ==
                    registration["capacity_ledger"]["terminal_head"] and
                details["capacity_schedule_sha256"] ==
                    capacity["capacity_schedule_sha256"] ==
                    registration["capacity_schedule_sha256"],
                "Source5 authorization is not descended from the prepared-capacity bridge registration")
    require(_within(Path(manifest["artifact_root"]), manifest_path),
            "Source5 execution manifest is outside its private artifact root")
    helper_path, helper_raw, helper_input_sha = _source5_reference(
        details["helper_input"], "Source5 helper input",
    )
    require(_within(Path(manifest["artifact_root"]), helper_path),
            "Source5 helper input is outside its private artifact root")
    helper_input = _parse_object(helper_raw, "Source5 helper input", MAX_PLAN_BYTES)
    _exact(helper_input, {
        "schema", "scope", "campaign_id", "host_id", "phase", "job_index", "job",
        "job_sha256", "members", "helper", "payload", "prerequisites",
        "outer_deadline_seconds", "effective_timeout_seconds",
        "input_snapshot_sha256", "qualification_eligible",
    }, "Source5 helper input")
    require(helper_input["schema"] == SOURCE5_HELPER_INPUT_SCHEMA and
            helper_input["scope"] in {"prospective_exploration", "final_frozen"} and
            helper_input["campaign_id"] == details["campaign_id"] and
            helper_input["host_id"] == details["host_id"] and
            helper_input["phase"] == phase and helper_input["job_index"] == job_index and
            helper_input["job"] == job and helper_input["job_sha256"] == details["job_sha256"] and
            helper_input["members"] == details["members"] and
            helper_input["outer_deadline_seconds"] == details["outer_deadline_seconds"] and
            helper_input["effective_timeout_seconds"] == details["effective_timeout_seconds"] and
            helper_input["qualification_eligible"] is False,
            "Source5 helper input differs from the durable authorization context")
    if helper_input["scope"] == "prospective_exploration":
        require(phase == "exploration" and not prepared["spec"]["rates"] and
                not prepared["spec"]["oracles"],
                "prospective Source5 scope is closed to exploration-only inputs")
    else:
        require(prepared["spec"]["rates"] and prepared["spec"]["oracles"],
                "final Source5 scope requires independently frozen original rates and oracles")
    helper = _exact(helper_input["helper"], {"path", "sha256", "entrypoint"},
                     "Source5 helper regular-file pin")
    helper_module = _exact(details["helper_module"],
                           {"path", "sha256", "size", "mode", "kind"},
                           "Source5 typed helper inventory pin")
    require(helper["path"] == helper_module["path"] and
            helper["sha256"] == helper_module["sha256"] and
            helper_module["kind"] == "file" and
            helper_module["mode"] in {"100644", "100755"},
            "Source5 helper source differs from its typed regular-file inventory pin")
    module_records = manifest["modules"].get(prepared["host_id"])
    require(type(module_records) is dict and
            module_records.get(helper_module["path"]) == {
                "path": helper_module["path"], "sha256": helper_module["sha256"],
            }, "Source5 helper is not in the selected host execution module inventory")
    source_record = next((item for item in prepared["source"]["source"]["files"]
                          if item.get("path") == helper_module["path"]), None)
    require(source_record == helper_module,
            "Source5 helper mode/size/kind/hash differs from the SourceV5 typed inventory")
    helper_roles = {
        "exploration": ("scripts/application-fixed-pair.py", "run_fixed_pair_overlay"),
        "aa": ("scripts/application-fixed-pair.py", "run_fixed_pair_overlay"),
        "confirmation": ("scripts/application-fixed-pair.py", "run_fixed_pair_overlay"),
        "pressure": ("scripts/application-pressure-pair.py", "run_pressure_pair_locked"),
        "soak": ("scripts/application-source5-soak.py", "run_source5_soak"),
    }
    helper_path_value, helper_entrypoint = helper_roles[phase]
    require(helper["path"] == helper_path_value and
            helper["entrypoint"] == helper_entrypoint,
            "Source5 phase uses an unapproved helper file/entrypoint")
    module_raw, module_sha, module_record = _source_file(
        prepared["source_root"], prepared["source"], helper_path_value,
        f"Source5 {phase} helper", maximum=MAX_SCRIPT_BYTES,
    )
    require(module_sha == helper_module["sha256"] and module_record == helper_module,
            "Source5 helper bytes differ from their typed inventory pin")
    helper_module_value = _load_module(
        module_raw, prepared["source_root"] / helper_path_value,
        f"source5_{phase}_helper",
    )
    if phase == "pressure":
        expected_members = helper_module_value.pressure_process_descriptors(job)
    elif phase == "soak":
        expected_members = [helper_module_value.soak_descriptor(job)]
    else:
        expected_members = helper_module_value._member_descriptors(
            job, prepared["controller"],
        )
    require(details["members"] == expected_members,
            "Source5 authorized member order differs from the captured helper's exact original descriptors")
    bounded_pressure = (phase == "pressure" and
                        manifest["schema"] == SOURCE5_EXECUTION_SCHEMA_V3)
    expected_payload_keys = (
        {"overlay_pin"} if phase in {"exploration", "aa", "confirmation"} else
        ({"schema", "recipe_pin", "output_root", "probe_capture_bundle"}
         if bounded_pressure else {"recipe_pin", "output_root"})
        if phase == "pressure" else
        {"materials_index", "output_root", "prepared_host_binding_sha256"}
    )
    require(type(helper_input["payload"]) is dict and
            set(helper_input["payload"]) == expected_payload_keys,
            "Source5 helper payload does not have its closed phase-specific shape")
    if phase == "pressure":
        if bounded_pressure:
            require(helper_input["payload"]["schema"] ==
                    SOURCE5_PRESSURE_HELPER_PAYLOAD_SCHEMA_V2,
                    "bounded Source5 pressure requires the exact helper-payload-v2 schema")
        recipe_pin = _exact(helper_input["payload"]["recipe_pin"],
                            {"path", "raw_sha256"}, "Source5 pressure recipe pin")
        recipe_path, recipe_raw, recipe_sha = _source5_reference(
            recipe_pin, "Source5 pressure recipe",
        )
        recipe = _parse_object(recipe_raw, "Source5 pressure recipe", MAX_PLAN_BYTES)
        require(recipe_raw == canonical_bytes(recipe) and
                recipe_sha == recipe_pin["raw_sha256"],
                "Source5 pressure recipe is not canonical or differs from its raw pin")
        require(helper_input["payload"]["output_root"] == details["output_root"],
                "Source5 pressure recipe output root differs from its authorization")
        if bounded_pressure:
            _verify_source5_probe_capture_bundle_v2(
                helper_input["payload"]["probe_capture_bundle"], recipe,
                helper_input["payload"]["output_root"],
                manifest["artifact_root"],
            )
    elif phase == "soak":
        materials_pin = _exact(helper_input["payload"]["materials_index"],
                               {"path", "raw_sha256"},
                               "Source5 Soak materials-index pin")
        _source5_reference(materials_pin, "Source5 Soak materials index")
        _digest(helper_input["payload"]["prepared_host_binding_sha256"],
                "Source5 Soak prepared-host binding digest")
        require(helper_input["payload"]["output_root"] == details["output_root"],
                "Source5 Soak output root differs from its authorization")
    else:
        overlay_pin = _exact(helper_input["payload"]["overlay_pin"],
                             {"path", "sha256"}, "Source5 fixed overlay pin")
        _digest(overlay_pin["sha256"], "Source5 fixed overlay SHA-256")
        require(Path(overlay_pin["path"]).is_absolute(),
                "Source5 fixed overlay path is not absolute")
        overlay_raw, _overlay_info = _read_stable(
            Path(overlay_pin["path"]), "Source5 fixed-pair overlay", MAX_PLAN_BYTES,
        )
        overlay = _parse_object(overlay_raw, "Source5 fixed-pair overlay", MAX_PLAN_BYTES)
        require(sha256_bytes(overlay_raw) == overlay_pin["sha256"] and
                overlay.get("output_root") == details["output_root"],
                "Source5 fixed overlay output root differs from its authorization")
    prerequisites = _validate_source5_prerequisites(phase, helper_input["prerequisites"], state)
    require(prerequisites == details["prerequisites"],
            "Source5 authorization prerequisite phase/analysis pins differ")
    outer_deadline = prepared["spec"]["deadlines"].get(
        "soak_outer_seconds" if phase == "soak" else "outer_seconds",
    )
    require(type(outer_deadline) is int and outer_deadline > 0 and
            helper_input["outer_deadline_seconds"] == outer_deadline and
            details["outer_deadline_seconds"] == outer_deadline,
            "Source5 helper changed the original finite phase deadline")
    effective = _uint(details["effective_timeout_seconds"],
                       "Source5 effective job deadline", positive=True,
                       maximum=MAX_TIMEOUT_SECONDS)
    require(effective <= outer_deadline, "Source5 effective job deadline exceeds the original job deadline")
    input_body = _source5_input_body(helper_input)
    input_sha = sha256_bytes(canonical_bytes(input_body))
    require(helper_input["input_snapshot_sha256"] == input_sha and
            details["input_snapshot_sha256"] == input_sha,
            "Source5 authorization input snapshot digest differs")
    require(details["authorization_id"] == "source5-" + sha256_bytes(canonical_bytes({
        key: value for key, value in details.items() if key != "authorization_id"
    }))[:48], "Source5 authorization ID is not derived from its closed durable details")
    output_root = Path(details["output_root"])
    require(output_root.is_absolute() and output_root.resolve(strict=True) == output_root and
            output_root.is_dir() and stat.S_IMODE(output_root.stat().st_mode) == 0o700 and
            output_root.stat().st_uid == os.getuid() and
            _within(Path(manifest["artifact_root"]), output_root) and
            not _within(prepared["source_root"], output_root) and
            not _within(prepared["input_root"], output_root),
            "Source5 job output root is not canonical private storage under its artifact root")
    selected_completion = _source5_capacity_manifest_record(
        manifest, prepared["host_id"],
    )
    require(selected_completion["artifact"] == details["capacity_completion"] and
            selected_completion["schedule_sha256"] == details["capacity_schedule_sha256"] and
            selected_completion["ledger_raw_sha256"] == details["capacity_ledger_raw_sha256"] and
            selected_completion["terminal_head"] == details["capacity_terminal_head"] and
            selected_completion["registration_head"] == details["capacity_registration_head"],
            "Source5 authorization capacity ancestry differs from its execution manifest")
    return {"manifest": manifest, "helper_input": helper_input,
            "helper_input_path": helper_path, "helper_input_sha256": helper_input_sha,
            "execution_manifest_path": manifest_path, "execution_manifest_sha256": manifest_sha}


def _check_event_semantics(
    state: dict[str, Any], event: str, details_value: object, record_sha: str,
    prepared: dict[str, Any], *, replay: bool, apply: bool = True,
) -> dict[str, Any]:
    details = _exact(details_value, DETAIL_FIELDS[event], f"chronology {event} details")
    if event == "capacity_stage_completed":
        require(state["stage_completion"] is None and state["registration"] is None and
                state["prepared_capacity_registration"] is None and
                not state["authorized"] and not state["source5_seen_jobs"],
                "capacity stage completion is not the first journal event")
        _validate_capacity_details(details, prepared)
        if apply:
            state["stage_completion"] = details
            state["stage_head"] = record_sha
    elif event == "capacity_registered":
        stage = state.get("stage_completion")
        require(stage is not None and state["registration"] is None and
                state["prepared_capacity_registration"] is None and
                not state["authorized"]
                and not state["source5_seen_jobs"],
                "capacity registration lacks one prior locked stage completion")
        _validate_capacity_details(details, prepared)
        require(details["capacity_stage_event_head"] == state.get("stage_head") and
                _registration_fields(details) == _registration_fields(stage),
                "capacity registration differs from the locked stage completion")
        if apply:
            state["registration"] = details
            state["registration_head"] = record_sha
    elif event == "source5_prepared_capacity_registered":
        require(state["record_count"] == 0 and
                state["stage_completion"] is None and
                state["registration"] is None and
                state["prepared_capacity_registration"] is None and
                not state["authorized"] and not state["source5_seen_jobs"],
                "prepared Source5 capacity registration must be the first journal event")
        _validate_source5_prepared_capacity_registration(details, prepared)
        if apply:
            state["prepared_capacity_registration"] = details
            state["registration_head"] = record_sha
    elif event == "source5_authorized":
        require(state.get("registration") is not None or
                state.get("prepared_capacity_registration") is not None,
                "Source5 helper authorization lacks the sealed 15-entry capacity registration")
        require(state.get("cleanup_blocked") is False and
                state.get("source5_cleanup_blocked") is False,
                "prior owned-process cleanup is unclean or unverified; Source5 launches are blocked")
        require(state.get("pending") is None and state.get("source5_pending") is None,
                "an earlier helper authorization remains unresolved")
        _validate_source5_authorization(details, prepared, state)
        authorization_id = details["authorization_id"]
        run_id = details["job"]["run_id"]
        key = (details["phase"], run_id)
        require(authorization_id not in state["source5_authorized"] and
                key not in state["source5_seen_jobs"],
                "original Source5 job authorization was already consumed and cannot be retried")
        if apply:
            state["source5_authorized"][authorization_id] = {
                "details": details, "authorization_head": record_sha,
                "starts": [], "terminals": [],
            }
            state["source5_pending"] = authorization_id
            state["source5_seen_jobs"].add(key)
    elif event == "source5_app_started":
        authorization_id = _token(details["authorization_id"], "Source5 authorization ID")
        prior = state["source5_authorized"].get(authorization_id)
        require(prior is not None and state.get("source5_pending") == authorization_id,
                "Source5 APP start has no active one-use helper authorization")
        index = _uint(details["member_index"], "Source5 APP member index")
        members = prior["details"]["members"]
        require(index == len(prior["starts"]) and index < len(members) and
                details["descriptor"] == members[index],
                "Source5 APP start is not the next exact authorized member")
        require(type(details["pid"]) is int and 0 < details["pid"] <= (1 << 31) - 1 and
                type(details["start_ticks"]) is int and details["start_ticks"] > 0,
                "Source5 APP start lacks its actual positive PID/start identity")
        _digest(details["proof_sha256"], "Source5 APP proof digest")
        require(details["proof_sha256"] == sha256_bytes(canonical_bytes(details["proof"])) and
                _source5_proof_identity(details["proof"]) ==
                (details["pid"], details["start_ticks"]),
                "Source5 APP start proof differs from its actual PID/start identity")
        require(details["qualification_eligible"] is False,
                "Source5 APP start claims campaign eligibility")
        if apply:
            prior["starts"].append({**details, "event_head": record_sha})
    elif event == "source5_app_terminal":
        authorization_id = _token(details["authorization_id"], "Source5 authorization ID")
        prior = state["source5_authorized"].get(authorization_id)
        require(prior is not None and state.get("source5_pending") == authorization_id,
                "Source5 APP terminal has no active one-use helper authorization")
        index = _uint(details["member_index"], "Source5 APP terminal member index")
        require(index < len(prior["starts"]) and index == len(prior["terminals"]),
                "Source5 APP terminal is missing or repeats its matching start")
        start = prior["starts"][index]
        require(details["descriptor"] == start["descriptor"] ==
                prior["details"]["members"][index] and
                details["pid"] == start["pid"],
                "Source5 APP terminal differs from the started member/PID")
        _uint(details["status"], "Source5 APP terminal status", maximum=255)
        raw_return = details["child_return_code"]
        signal_number = details["signal"]
        require(raw_return is None or (type(raw_return) is int and -127 <= raw_return <= 255),
                "Source5 APP terminal raw child return code is malformed")
        require(signal_number is None or
                (type(signal_number) is int and 1 <= signal_number <= 127),
                "Source5 APP terminal signal number is malformed")
        if raw_return is not None and raw_return < 0:
            require(signal_number == -raw_return and
                    (details["status"] in {125, 128 + signal_number} or
                     (details["status"] == 124 and
                      type(details["cleanup"]) is dict and
                      details["cleanup"].get("timed_out") is True)),
                    "Source5 APP signal terminal lost its raw code or normalized status")
        elif raw_return is not None:
            require(signal_number is None and
                    details["status"] in {raw_return, 124, 125},
                    "Source5 APP exit terminal status differs from its raw child code")
        else:
            require(signal_number is None and details["status"] == 125,
                    "Source5 APP terminal without a child code is not a normalized launch failure")
        _uint(details["terminal_monotonic_ns"], "Source5 APP terminal monotonic timestamp", positive=True)
        require(type(details["cleanup"]) is dict and
                details["qualification_eligible"] is False,
                "Source5 APP terminal cleanup/eligibility fields are malformed")
        if apply:
            prior["terminals"].append({**details, "event_head": record_sha})
            if not _source5_cleanup_is_clean(details["cleanup"]):
                state["source5_cleanup_blocked"] = True
    elif event == "source5_job_terminal":
        authorization_id = _token(details["authorization_id"], "Source5 authorization ID")
        prior = state["source5_authorized"].get(authorization_id)
        require(prior is not None and state.get("source5_pending") == authorization_id,
                "Source5 job terminal has no active one-use helper authorization")
        starts, terminals = prior["starts"], prior["terminals"]
        require(details["started_count"] == len(starts) and
                details["terminal_count"] == len(terminals) and
                len(terminals) <= len(starts) <= len(prior["details"]["members"]),
                "Source5 job terminal counts do not reconcile the recorded APP lifecycle prefix")
        require(details["state"] in {
                    "valid_pair", "invalid_pair", "valid_soak", "invalid_soak", "blocked",
                },
                "Source5 job terminal has an unknown disposition")
        require(details["blocked_reason"] is None or details["blocked_reason"] in {
            "deadline_watchdog_unverified", "effective_deadline_exceeded",
            "helper_preflight_failed",
            "incomplete_app_lifecycle", "owned_cleanup_unverified",
            "component_postflight_failed",
        }, "Source5 blocked terminal has an unknown retained failure reason")
        require((details["state"] == "blocked") ==
                (details["blocked_reason"] is not None),
                "Source5 blocked terminal state/reason fields disagree")
        _digest(details["component_sha256"], "Source5 component result digest")
        _digest(details["process_metrics_sha256"], "Source5 process metrics digest")
        require(details["qualification_eligible"] is False,
                "Source5 per-job terminal claims campaign eligibility")
        if details["state"] == "valid_pair":
            require(len(starts) == len(prior["details"]["members"]) == 2 and
                    len(terminals) == len(starts) == 2 and
                    all(item["status"] == 0 and _source5_cleanup_is_clean(item["cleanup"])
                        for item in terminals),
                    "valid Source5 pair lacks two clean successful actual APP lifecycles")
        elif details["state"] == "invalid_pair":
            require(len(starts) == len(terminals) == len(prior["details"]["members"]) == 2 and
                    all(_source5_cleanup_is_clean(item["cleanup"]) for item in terminals),
                    "invalid Source5 pair did not retain two completed clean APP lifecycles")
        elif details["state"] in {"valid_soak", "invalid_soak"}:
            require(prior["details"]["phase"] == "soak" and
                    len(starts) == len(terminals) == len(prior["details"]["members"]) == 1 and
                    terminals[0]["status"] == 0 and
                    _source5_cleanup_is_clean(terminals[0]["cleanup"]),
                    "completed Source5 Soak lacks its one clean original APP lifecycle")
        else:
            require(details["blocked_reason"] == "effective_deadline_exceeded" or
                    details["blocked_reason"] == "deadline_watchdog_unverified" or
                    (details["blocked_reason"] == "component_postflight_failed" and
                     prior["details"]["phase"] == "soak" and
                     len(terminals) == len(prior["details"]["members"]) == 1 and
                     all(_source5_cleanup_is_clean(item["cleanup"]) and
                         item["status"] == 0 for item in terminals)) or
                    len(terminals) < len(prior["details"]["members"]) or
                    any(not _source5_cleanup_is_clean(item["cleanup"]) or item["status"] != 0
                        for item in terminals),
                    "blocked Source5 terminal has no incomplete or failed lifecycle evidence")
        if apply:
            run_id = prior["details"]["job"]["run_id"]
            phase = prior["details"]["phase"]
            state["source5_finished"][(phase, run_id)] = {
                "authorization_id": authorization_id, "state": details["state"],
                "details": prior["details"], "starts": starts, "terminals": terminals,
                "terminal": details,
                "authorization_head": prior["authorization_head"],
                "record_sha256": record_sha,
            }
            state["source5_pending"] = None
            del state["source5_authorized"][authorization_id]
            if details["state"] == "blocked":
                state["source5_cleanup_blocked"] = True
    elif event == "source5_analysis":
        require(state.get("source5_pending") is None and
                state.get("source5_cleanup_blocked") is False,
                "Source5 analysis cannot proceed with a pending helper or unsafe cleanup")
        _validate_source5_analysis(details, prepared, state)
        phase = details["phase"]
        require(phase not in state["source5_analyses"],
                "Source5 phase analysis is immutable and already recorded")
        if apply:
            state["source5_analyses"][phase] = {
                **details, "event_head": record_sha,
            }
    elif event == "dispatch_authorized":
        registration = state.get("registration")
        require(registration is not None, "fixed confirmation dispatch lacks a capacity registration")
        require(not state["source5_seen_jobs"] and state["source5_pending"] is None,
                "legacy shell dispatch cannot follow Source5 helper execution")
        require(state.get("cleanup_blocked") is False,
                "prior pair-runner cleanup is unclean or unverified; later dispatch is blocked")
        require(state.get("pending") is None, "an earlier dispatch authorization remains unresolved")
        _validate_dispatch_authorization(details, prepared, registration,
                                         state["registration_head"])
        auth_id, run_id = _auth_detail_identity(details)
        require(auth_id not in state["authorized"] and run_id not in state["finished"],
                "original confirmation authorization was already consumed and cannot be retried")
        if apply:
            state["authorized"][auth_id] = {"details": details, "bound": None}
            state["pending"] = auth_id
    elif event.startswith("dispatch_"):
        authorization_id = _token(details.get("authorization_id"), "dispatch authorization ID")
        prior = state["authorized"].get(authorization_id)
        require(prior is not None and state.get("pending") == authorization_id,
                f"chronology {event} has no active one-use authorization")
        authorization = prior["details"]
        require(details["job_run_id"] == authorization["job"]["run_id"] and
                details["member_role"] == authorization["member_role"] and
                details["capacity_registration_head"] == state["registration_head"],
                f"chronology {event} differs from its original authorization")
        cleanup_safe = True
        if event == "dispatch_bound":
            require(prior["bound"] is None, "dispatch process was bound more than once")
            _validate_bound_details(details, authorization, prepared)
            if apply:
                prior["bound"] = details
        else:
            require(event in ("dispatch_exited", "dispatch_failed", "dispatch_interrupted", "dispatch_timeout"),
                    "unknown dispatch terminal event")
            cleanup_safe = _validate_process_cleanup_details(details)
            bound = prior["bound"]
            if event == "dispatch_exited":
                require(bound is not None, "dispatch exit lacks a durable post-Popen process binding")
                _validate_exit_details(details, bound, authorization, prepared)
            elif event in ("dispatch_interrupted", "dispatch_timeout"):
                if bound is not None:
                    require(details.get("pid") == bound["pid"],
                            f"{event} PID differs from the bound direct process")
                elif details.get("pid") is not None:
                    _uint(details.get("pid"), f"{event} direct Popen PID", positive=True,
                          maximum=(1 << 31) - 1)
                require(type(details.get("process_reaped")) is bool,
                        f"{event} lacks the direct process reap result")
                elapsed_ns = _uint(details.get("elapsed_ns"), f"{event} elapsed nanoseconds")
                require(elapsed_ns <= authorization["effective_timeout_seconds"] * 1_000_000_000 +
                        10_000_000_000,
                        f"{event} cleanup elapsed time exceeds its finite dispatch bound")
                if event == "dispatch_interrupted":
                    _uint(details.get("signal"), "dispatch interruption signal", positive=True,
                          maximum=255)
                    if details.get("pid") is None:
                        require(details.get("return_code") is None,
                                "interruption without a direct process has a fabricated exit code")
                    else:
                        require(details.get("return_code") is None or
                                type(details.get("return_code")) is int,
                                "interrupted direct process has a malformed wait status")
                else:
                    _uint(details.get("effective_timeout_seconds"),
                          "dispatch timeout effective bound", positive=True,
                          maximum=MAX_TIMEOUT_SECONDS)
                    require(details["effective_timeout_seconds"] ==
                            authorization["effective_timeout_seconds"],
                            "dispatch timeout differs from its authorized finite bound")
                    require(elapsed_ns >= authorization["effective_timeout_seconds"] * 1_000_000_000,
                            "dispatch timeout was recorded before its authorized deadline")
                    if details.get("pid") is None:
                        require(details.get("return_code") is None,
                                "timeout without a direct process has a fabricated exit code")
                    else:
                        require(details.get("return_code") is None or
                                type(details.get("return_code")) is int,
                                "timed-out direct process has a malformed wait status")
            else:
                if bound is None:
                    if details.get("pid") is None:
                        require(details.get("return_code") is None,
                                "failed dispatch without a direct process has an exit code")
                    else:
                        _uint(details.get("pid"), "failed direct Popen PID", positive=True,
                              maximum=(1 << 31) - 1)
                        require(details.get("return_code") is None or
                                type(details.get("return_code")) is int,
                                "failed direct process has a malformed wait status")
                    require(type(details.get("process_reaped")) is bool,
                            "failed direct Popen omitted its reap status")
                else:
                    require(details.get("pid") == bound["pid"] and
                            type(details.get("process_reaped")) is bool and
                            ((details["process_reaped"] and
                              type(details.get("return_code")) is int) or
                             (not details["process_reaped"] and
                              details.get("return_code") is None)),
                            "failed bound dispatch omitted its direct process reap status")
                _token(details.get("error_type"), "dispatch failure error type", maximum=128)
                elapsed_ns = _uint(details.get("elapsed_ns"), "failed dispatch elapsed nanoseconds")
                require(elapsed_ns <= authorization["effective_timeout_seconds"] * 1_000_000_000 +
                        10_000_000_000,
                        "failed dispatch cleanup elapsed time exceeds its finite bound")
                _digest(details.get("error_sha256"), "dispatch failure digest")
            if apply:
                state["pending"] = None
                state["finished"].add(authorization["job"]["run_id"])
                state["process_cleanup"].append({
                    "authorization_id": authorization_id,
                    "job_run_id": authorization["job"]["run_id"],
                    "process_reaped": details["process_reaped"],
                    "process_reap_status": details["process_reap_status"],
                    "return_code": details["return_code"],
                    "process_group_cleanup_status": details["process_group_cleanup_status"],
                    "cleanup_error_sha256": details["cleanup_error_sha256"],
                })
                if not cleanup_safe:
                    state["cleanup_blocked"] = True
                del state["authorized"][authorization_id]
    else:
        require(False, f"unknown chronology event {event}")
    return details


def _registration_fields(details: dict[str, Any]) -> dict[str, Any]:
    return {
        key: details[key] for key in (
            "capacity_completion", "capacity_ledger", "capacity_schedule_sha256",
            "entry_count", "entries", "qualification_eligible",
            "controller_chronology_proven",
        )
    }


def _validate_capacity_details(details: dict[str, Any], prepared: dict[str, Any]) -> None:
    completion = _exact(details["capacity_completion"], {"path", "sha256"},
                        "capacity completion raw pin")
    ledger = _exact(details["capacity_ledger"], {"path", "raw_sha256", "terminal_head"},
                    "capacity sealed ledger pin")
    _digest(completion["sha256"], "capacity completion raw SHA-256")
    _path_text(Path(completion["path"]), "capacity completion path")
    _digest(ledger["raw_sha256"], "capacity ledger raw SHA-256")
    _digest(ledger["terminal_head"], "capacity ledger terminal head")
    _path_text(Path(ledger["path"]), "capacity ledger path")
    _digest(details["capacity_schedule_sha256"], "capacity schedule SHA-256")
    require(details["entry_count"] == 15 and type(details["entry_count"]) is int and
            type(details["entries"]) is list and len(details["entries"]) == 15,
            "capacity registration must retain exactly 15 verified entries")
    require(details["qualification_eligible"] is False and
            details["controller_chronology_proven"] is False,
            "capacity registration cannot change eligibility or assert controller chronology")
    require(details["capacity_schedule_sha256"] ==
            prepared["plan"]["capacity_process_templates_sha256"],
            "capacity registration schedule differs from the original PlanV3 digest")


def _iter_journal_records_from_chunks(
    chunks: Any, original_pins: dict[str, Any], campaign_id: str, host_id: str,
    boot_id_sha256: str, stats: dict[str, Any], *,
    expected_byte_count: int | None = None,
    maximum_events: int = MAX_JOURNAL_EVENTS,
    maximum_bytes: int = MAX_JOURNAL_BYTES,
):
    """Yield journal records from bounded chunks, retaining at most one line."""
    _token(campaign_id, "journal campaign ID")
    _token(host_id, "journal host ID")
    _digest(boot_id_sha256, "journal boot identity")
    require(type(original_pins) is dict,
            "journal original input projection is not an object")
    try:
        _json_copy(original_pins)
    except ChronologyError as error:
        raise ChronologyError("journal original input projection is not canonical data") from error
    if expected_byte_count is not None:
        _uint(expected_byte_count, "captured journal byte count",
              maximum=maximum_bytes)
    _uint(maximum_events, "chronology journal event ceiling", positive=True,
          maximum=MAX_SOURCE5_JOURNAL_EVENTS)
    _uint(maximum_bytes, "chronology journal byte ceiling", positive=True,
          maximum=MAX_SOURCE5_JOURNAL_BYTES)
    previous = "0" * 64
    last_monotonic = 0
    sequence = 0
    total_bytes = 0
    pending = bytearray()
    hasher = hashlib.sha256()

    def parse_line(line: bytes) -> dict[str, Any]:
        nonlocal previous, last_monotonic, sequence
        sequence += 1
        require(sequence <= maximum_events and len(line) <= MAX_EVENT_BYTES and
                line.endswith(b"\n") and b"\r" not in line,
                "chronology journal framing or event count exceeds its finite bound")
        record_envelope = _parse_object(
            line, f"chronology journal line {sequence}", MAX_EVENT_BYTES,
        )
        envelope = _exact(record_envelope, {
            "previous_sha256", "record", "record_sha256",
        }, f"chronology journal envelope {sequence}")
        _digest(envelope["previous_sha256"], "journal previous SHA-256")
        record = _exact(envelope["record"], {
            "schema", "sequence", "monotonic_ns", "campaign_id", "host_id",
            "boot_id_sha256", "original_pins", "event", "details",
        }, f"chronology journal record {sequence}")
        require(record["schema"] == JOURNAL_SCHEMA and
                record["sequence"] == sequence and
                record["campaign_id"] == campaign_id and
                record["host_id"] == host_id and
                record["original_pins"] == original_pins and
                record["boot_id_sha256"] == boot_id_sha256,
                f"chronology journal record {sequence} changed campaign/source/host pins")
        monotonic_ns = _uint(
            record["monotonic_ns"], "journal monotonic timestamp", positive=True,
        )
        require(monotonic_ns > last_monotonic,
                f"chronology journal record {sequence} has invalid monotonic order")
        event = record["event"]
        require(type(event) is str and event in DETAIL_FIELDS,
                f"chronology journal record {sequence} has unknown event")
        details = _exact(
            record["details"], DETAIL_FIELDS[event],
            f"chronology {event} details at record {sequence}",
        )
        require(envelope["previous_sha256"] == previous,
                f"chronology journal chain breaks at record {sequence}")
        unsigned = {"previous_sha256": previous, "record": record}
        record_sha = sha256_bytes(canonical_bytes(unsigned))
        require(envelope["record_sha256"] == record_sha,
                f"chronology journal record digest is invalid at {sequence}")
        previous = record_sha
        last_monotonic = monotonic_ns
        return {
            "sequence": sequence, "previous_sha256": envelope["previous_sha256"],
            "record_sha256": record_sha, "record": record,
            "details": details,
        }

    for chunk in chunks:
        require(type(chunk) is bytes and 0 < len(chunk) <= 1024 * 1024,
                "captured chronology journal stream returned an invalid chunk")
        total_bytes += len(chunk)
        require(total_bytes <= maximum_bytes,
                "chronology journal exceeds its finite byte bound")
        hasher.update(chunk)
        pending.extend(chunk)
        while True:
            newline = pending.find(b"\n")
            if newline < 0:
                require(len(pending) <= MAX_EVENT_BYTES,
                        "chronology journal line exceeds its finite byte bound")
                break
            end = newline + 1
            line = bytes(pending[:end])
            del pending[:end]
            yield parse_line(line)
    require(not pending,
            "chronology journal framing has an unterminated record")
    require(expected_byte_count is None or total_bytes == expected_byte_count,
            "captured chronology journal stream byte count differs from its pin")
    stats.update({
        "raw_sha256": hasher.hexdigest(), "byte_count": total_bytes,
        "record_count": sequence, "terminal_head": previous,
        "last_monotonic_ns": last_monotonic,
    })


def _iter_journal_records(
    raw: bytes, original_pins: dict[str, Any], campaign_id: str, host_id: str,
    boot_id_sha256: str, *, maximum_events: int = MAX_JOURNAL_EVENTS,
    maximum_bytes: int = MAX_JOURNAL_BYTES,
):
    require(type(raw) is bytes and len(raw) <= maximum_bytes,
            "chronology journal exceeds its finite byte bound")
    chunks = (raw[offset:offset + 1024 * 1024]
              for offset in range(0, len(raw), 1024 * 1024))
    return _iter_journal_records_from_chunks(
        chunks, original_pins, campaign_id, host_id, boot_id_sha256, {},
        expected_byte_count=len(raw), maximum_events=maximum_events,
        maximum_bytes=maximum_bytes,
    )


def _iter_captured_journal_stream(
    stream: Any, byte_count: int, original_pins: dict[str, Any],
    campaign_id: str, host_id: str, boot_id_sha256: str,
    stats: dict[str, Any], *, maximum_events: int = MAX_JOURNAL_EVENTS,
    maximum_bytes: int = MAX_JOURNAL_BYTES,
):
    require(type(stream) is io.BufferedReader and
            type(stream.raw) is io.FileIO and stream.readable() and
            not stream.writable() and stream.seekable() and
            stream.raw.mode == "rb",
            "captured journal stream must be a read-only seekable regular byte stream")
    try:
        stream.seek(0)
        require(stream.tell() == 0,
                "captured journal stream did not rewind to its original byte origin")
        def chunks():
            remaining = byte_count
            while remaining:
                block = stream.read(min(1024 * 1024, remaining))
                require(type(block) is bytes and bool(block),
                        "captured journal stream ended before its pinned byte count")
                remaining -= len(block)
                yield block
            require(stream.read(1) == b"",
                    "captured journal stream exceeds its pinned byte count")
        yield from _iter_journal_records_from_chunks(
            chunks(), original_pins, campaign_id, host_id,
            boot_id_sha256, stats, expected_byte_count=byte_count,
            maximum_events=maximum_events, maximum_bytes=maximum_bytes,
        )
    except (OSError, ValueError) as error:
        raise ChronologyError(f"cannot consume captured journal stream: {error}") from error


def _journal_authorization_summary(details: dict[str, Any], record_sha: str) -> dict[str, Any]:
    job = details["job"]
    return {
        "authorization_id": details["authorization_id"],
        "phase": details["phase"], "job_index": details["job_index"],
        "job": job,
        "job_run_id": job.get("run_id"), "job_sha256": details["job_sha256"],
        "members_sha256": details["members_sha256"],
        "capacity_registration_head": details["capacity_registration_head"],
        "authorization_head": record_sha,
        "execution_manifest": details["execution_manifest"],
        "helper_input": details["helper_input"],
        "helper_module": details["helper_module"],
        "capacity_completion": details["capacity_completion"],
        "capacity_ledger_raw_sha256": details["capacity_ledger_raw_sha256"],
        "capacity_terminal_head": details["capacity_terminal_head"],
        "capacity_schedule_sha256": details["capacity_schedule_sha256"],
        "prerequisites": details["prerequisites"],
        "input_snapshot_sha256": details["input_snapshot_sha256"],
        "output_root": details["output_root"],
        "outer_deadline_seconds": details["outer_deadline_seconds"],
        "effective_timeout_seconds": details["effective_timeout_seconds"],
        "member_count": len(details["members"]),
        "members": details["members"],
        "starts": [], "terminals": [], "job_terminal": None,
    }


def _journal_structural_index(
    records: Any, campaign_id: str, host_id: str,
    original_pins_sha256: str,
) -> dict[str, Any]:
    """Build ancestry and one-use lifecycle structure; never certify job results."""
    registration_head: str | None = None
    stage_head: str | None = None
    registered_event: str | None = None
    used_authorizations: set[str] = set()
    used_source5_jobs: set[tuple[str, str]] = set()
    active_source5: dict[str, dict[str, Any]] = {}
    finished_source5: dict[tuple[str, str], dict[str, Any]] = {}
    active_dispatch: dict[str, dict[str, Any]] = {}
    finished_dispatch: set[str] = set()
    analyses: dict[str, dict[str, Any]] = {}
    cleanup_blocked = False
    source5_cleanup_blocked = False
    source5_pending: str | None = None
    dispatch_pending: str | None = None
    heads = ["0" * 64]
    event_index: list[dict[str, Any]] = []
    authorization_index: list[dict[str, Any]] = []
    registration_index: list[dict[str, Any]] = []
    record_count = 0
    terminal_head = "0" * 64
    last_monotonic_ns = 0
    stage_registration_fields: dict[str, Any] | None = None

    for item in records:
        record_count += 1
        terminal_head = item["record_sha256"]
        last_monotonic_ns = item["record"]["monotonic_ns"]
        record = item["record"]
        details = item["details"]
        event = record["event"]
        record_sha = item["record_sha256"]
        sequence = item["sequence"]
        row: dict[str, Any] = {
            "sequence": sequence, "event": event,
            "previous_sha256": item["previous_sha256"],
            "record_sha256": record_sha,
            "monotonic_ns": record["monotonic_ns"],
            "authorization_id": None, "job_run_id": None,
            "phase": None, "job_index": None, "member_index": None,
        }
        if event == "capacity_stage_completed":
            require(sequence == 1 and stage_head is None and registration_head is None,
                    "capacity stage completion is not the first journal event")
            require(details["entry_count"] == 15 and
                    type(details["entry_count"]) is int and
                    type(details["entries"]) is list and
                    len(details["entries"]) == 15 and
                    details["qualification_eligible"] is False and
                    details["controller_chronology_proven"] is False,
                    "capacity stage event does not retain the original false-ready 15-entry shape")
            _digest(details["capacity_schedule_sha256"],
                    "capacity stage schedule digest")
            stage_head = record_sha
            registered_event = event
            stage_registration_fields = _registration_fields(details)
            registration_index.append({
                "event": event, "sequence": sequence,
                "record_sha256": record_sha,
                "capacity_schedule_sha256": details["capacity_schedule_sha256"],
                "entry_count": details["entry_count"],
                "details": details,
                "producer_replay_pending": True,
            })
        elif event == "capacity_registered":
            require(stage_head is not None and registration_head is None and
                    details["capacity_stage_event_head"] == stage_head,
                    "capacity registration is not descended from its exact stage event")
            require(details["entry_count"] == 15 and
                    type(details["entry_count"]) is int and
                    type(details["entries"]) is list and
                    len(details["entries"]) == 15 and
                    details["qualification_eligible"] is False and
                    details["controller_chronology_proven"] is False,
                    "capacity registration does not retain the original false-ready 15-entry shape")
            _digest(details["capacity_schedule_sha256"],
                    "capacity registration schedule digest")
            stage_row = registration_index[0]
            require(stage_registration_fields is not None and
                    _registration_fields(details) == stage_registration_fields,
                    "capacity registration differs from the original stage record")
            registration_head = record_sha
            registered_event = event
            registration_index.append({
                "event": event, "sequence": sequence,
                "record_sha256": record_sha,
                "capacity_stage_event_head": stage_row["record_sha256"],
                "capacity_schedule_sha256": details["capacity_schedule_sha256"],
                "entry_count": details["entry_count"],
                "details": details,
                "producer_replay_pending": True,
            })
        elif event == "source5_prepared_capacity_registered":
            require(sequence == 1 and registration_head is None and stage_head is None,
                    "prepared-capacity registration must be the first journal event")
            require(details["campaign_id"] == campaign_id and
                    details["host_id"] == host_id and
                    type(details["entries"]) is list and
                    len(details["entries"]) == 15 and
                    details["qualification_eligible"] is False and
                    details["controller_chronology_proven"] is False,
                    "prepared-capacity registration does not bind the selected host's false-ready 15-entry bridge")
            _digest(details["capacity_schedule_sha256"],
                    "prepared-capacity schedule digest")
            completion = _exact(details["completion"], {
                "path", "raw_sha256", "semantic_sha256",
            }, "prepared-capacity completion pin")
            for digest_name in ("raw_sha256", "semantic_sha256"):
                _digest(completion[digest_name],
                        f"prepared-capacity completion {digest_name}")
            provenance = _exact(details["provenance"], {
                "schema", "preparation_pin", "final_spec_pin", "final_plan_pin",
            }, "prepared-capacity provenance")
            require(provenance["schema"] ==
                    "allocatbelt.application-source5-prepared-inputs-provenance.v1",
                    "prepared-capacity provenance schema differs")
            registration_head = record_sha
            registered_event = event
            registration_index.append({
                "event": event, "sequence": sequence,
                "record_sha256": record_sha,
                "capacity_schedule_sha256": details["capacity_schedule_sha256"],
                "entry_count": len(details["entries"]),
                "details": details,
                "producer_replay_pending": True,
            })
        elif event == "source5_authorized":
            require(registration_head is not None and
                    details["capacity_registration_head"] == registration_head and
                    not cleanup_blocked and not source5_cleanup_blocked and
                    dispatch_pending is None and source5_pending is None,
                    "Source5 authorization is not after one clean structural registration")
            require(details["campaign_id"] == campaign_id and
                    details["host_id"] == host_id and
                    details["qualification_eligible"] is False,
                    "Source5 authorization changed host/campaign identity or eligibility")
            phase = details["phase"]
            require(phase in {"exploration", "aa", "confirmation", "pressure", "soak"},
                    "Source5 authorization phase is outside the original campaign role table")
            authorization_id = _token(
                details["authorization_id"], "Source5 authorization ID",
            )
            job = details["job"]
            require(type(job) is dict and job.get("phase") == phase and
                    job.get("host_id") == host_id and
                    type(job.get("run_id")) is str and job.get("run_id"),
                    "Source5 authorization job identity is malformed")
            job_index = _uint(details["job_index"], "Source5 original job index")
            require(details["job_sha256"] == sha256_bytes(canonical_bytes(job)) and
                    details["members_sha256"] ==
                        sha256_bytes(canonical_bytes(details["members"])),
                    "Source5 authorization job/member digest differs")
            _digest(details["input_snapshot_sha256"],
                    "Source5 helper input snapshot digest")
            _digest(details["capacity_terminal_head"],
                    "Source5 authorization capacity terminal head")
            member_count = 1 if phase == "soak" else 2
            require(type(details["members"]) is list and
                    len(details["members"]) == member_count and
                    authorization_id not in used_authorizations and
                    (phase, job["run_id"]) not in used_source5_jobs,
                    "Source5 authorization repeats an ID/job or changes its original member count")
            if phase == "soak":
                require(all(type(member) is dict and set(member) == {
                            "role", "allocator", "executor",
                        } and member["role"] == "original_soak_app"
                        for member in details["members"]),
                        "Source5 Soak authorization is not the one original APP role")
            else:
                require(all(type(member) is dict and set(member) == {
                            "pair", "executor", "allocator",
                        } for member in details["members"]) and
                        len({(member["pair"], member["executor"], member["allocator"])
                             for member in details["members"]}) == 2,
                        "Source5 paired authorization member roles are malformed")
            for pin_name in ("execution_manifest", "helper_input"):
                pin = _exact(details[pin_name], {"path", "raw_sha256"},
                             f"Source5 {pin_name} pin")
                path = Path(_path_text(Path(pin["path"]),
                                       f"Source5 {pin_name} path"))
                require(path.is_absolute() and str(path) == pin["path"],
                        f"Source5 {pin_name} path is not canonical absolute text")
                _digest(pin["raw_sha256"], f"Source5 {pin_name} raw SHA-256")
            module_pin = _exact(details["helper_module"], {
                "path", "sha256", "size", "mode", "kind",
            }, "Source5 helper module pin")
            _relative(module_pin["path"], "Source5 helper module relative path")
            _digest(module_pin["sha256"], "Source5 helper module SHA-256")
            _uint(module_pin["size"], "Source5 helper module size",
                  maximum=MAX_SCRIPT_BYTES)
            require(module_pin["kind"] == "file" and
                    module_pin["mode"] in {"100644", "100755"},
                    "Source5 helper module is not a typed regular source file")
            for path_name in ("output_root",):
                value = details[path_name]
                path = Path(_path_text(Path(value), f"Source5 {path_name}"))
                require(path.is_absolute() and str(path) == value,
                        f"Source5 {path_name} is not canonical absolute text")
            _uint(details["outer_deadline_seconds"],
                  "Source5 outer deadline", positive=True, maximum=MAX_TIMEOUT_SECONDS)
            _uint(details["effective_timeout_seconds"],
                  "Source5 effective timeout", positive=True, maximum=MAX_TIMEOUT_SECONDS)
            require(details["effective_timeout_seconds"] <=
                    details["outer_deadline_seconds"],
                    "Source5 effective timeout exceeds the original outer deadline")
            require(authorization_id == "source5-" + sha256_bytes(canonical_bytes({
                key: value for key, value in details.items()
                if key != "authorization_id"
            }))[:48],
                    "Source5 authorization ID is not derived from its closed details")
            auth_row = _journal_authorization_summary(details, record_sha)
            auth_row["authorization_record_count"] = sequence
            active_source5[authorization_id] = auth_row
            authorization_index.append(auth_row)
            used_authorizations.add(authorization_id)
            used_source5_jobs.add((phase, job["run_id"]))
            source5_pending = authorization_id
            row.update({
                "authorization_id": authorization_id,
                "job_run_id": job["run_id"], "phase": phase,
                "job_index": job_index,
            })
        elif event == "source5_app_started":
            authorization_id = _token(
                details["authorization_id"], "Source5 authorization ID",
            )
            prior = active_source5.get(authorization_id)
            require(prior is not None and source5_pending == authorization_id,
                    "Source5 APP start has no active structural authorization")
            member_index = _uint(details["member_index"], "Source5 APP member index")
            require(member_index == len(prior["starts"]) and
                    member_index < prior["member_count"] and
                    details["descriptor"] == prior["members"][member_index],
                    "Source5 APP start is not the next exact authorized member")
            pid, start_ticks = _source5_proof_identity(details["proof"])
            require(details["pid"] == pid and details["start_ticks"] == start_ticks and
                    details["proof_sha256"] == sha256_bytes(canonical_bytes(details["proof"])) and
                    details["qualification_eligible"] is False,
                    "Source5 APP start proof differs from its recorded PID/start")
            prior["starts"].append({
                "member_index": member_index, "descriptor": details["descriptor"],
                "pid": pid, "start_ticks": start_ticks,
                "proof_sha256": details["proof_sha256"],
                "proof": details["proof"],
                "event_details": details,
                "event_head": record_sha,
            })
            row.update({"authorization_id": authorization_id,
                        "job_run_id": prior["job_run_id"],
                        "phase": prior["phase"], "member_index": member_index})
        elif event == "source5_app_terminal":
            authorization_id = _token(
                details["authorization_id"], "Source5 authorization ID",
            )
            prior = active_source5.get(authorization_id)
            require(prior is not None and source5_pending == authorization_id,
                    "Source5 APP terminal has no active structural authorization")
            member_index = _uint(details["member_index"], "Source5 APP member index")
            require(member_index == len(prior["terminals"]) and
                    member_index < len(prior["starts"]),
                    "Source5 APP terminal lacks its exact earlier start")
            start = prior["starts"][member_index]
            require(details["descriptor"] == start["descriptor"] ==
                    prior["members"][member_index] and
                    details["pid"] == start["pid"] and
                    details["qualification_eligible"] is False,
                    "Source5 APP terminal changed its started member identity")
            _uint(details["status"], "Source5 APP terminal normalized status", maximum=255)
            raw_return = details["child_return_code"]
            signal_number = details["signal"]
            require(raw_return is None or
                    (type(raw_return) is int and -127 <= raw_return <= 255),
                    "Source5 APP terminal raw child return code is malformed")
            require(signal_number is None or
                    (type(signal_number) is int and 1 <= signal_number <= 127),
                    "Source5 APP terminal signal number is malformed")
            if raw_return is not None and raw_return < 0:
                require(signal_number == -raw_return and
                        (details["status"] in {125, 128 + signal_number} or
                         (details["status"] == 124 and
                          type(details["cleanup"]) is dict and
                          details["cleanup"].get("timed_out") is True)),
                        "Source5 APP signal terminal lost its raw code or normalized status")
            elif raw_return is not None:
                require(signal_number is None and
                        details["status"] in {raw_return, 124, 125},
                        "Source5 APP exit terminal status differs from its raw child code")
            else:
                require(signal_number is None and details["status"] == 125,
                        "Source5 APP terminal without a child code is not a normalized launch failure")
            _uint(details["terminal_monotonic_ns"],
                  "Source5 APP terminal monotonic timestamp", positive=True)
            require(type(details["cleanup"]) is dict,
                    "Source5 APP terminal cleanup evidence is malformed")
            prior["terminals"].append({
                "member_index": member_index, "descriptor": details["descriptor"],
                "pid": details["pid"], "status": details["status"],
                "cleanup_sha256": sha256_bytes(canonical_bytes(details["cleanup"])),
                "cleanup_clean": _source5_cleanup_is_clean(details["cleanup"]),
                "child_return_code": details["child_return_code"],
                "signal": details["signal"],
                "cleanup": details["cleanup"],
                "terminal_monotonic_ns": details["terminal_monotonic_ns"],
                "event_details": details,
                "event_head": record_sha,
            })
            if not _source5_cleanup_is_clean(details["cleanup"]):
                source5_cleanup_blocked = True
            row.update({"authorization_id": authorization_id,
                        "job_run_id": prior["job_run_id"],
                        "phase": prior["phase"], "member_index": member_index})
        elif event == "source5_job_terminal":
            authorization_id = _token(
                details["authorization_id"], "Source5 authorization ID",
            )
            prior = active_source5.get(authorization_id)
            require(prior is not None and source5_pending == authorization_id,
                    "Source5 job terminal has no active structural authorization")
            require(details["started_count"] == len(prior["starts"]) and
                    details["terminal_count"] == len(prior["terminals"]) and
                    len(prior["terminals"]) <= len(prior["starts"]) <= prior["member_count"] and
                    details["qualification_eligible"] is False,
                    "Source5 terminal counts or eligibility differ from its recorded callbacks")
            require(details["state"] in {
                        "valid_pair", "invalid_pair", "valid_soak", "invalid_soak", "blocked",
                    } and
                    (details["blocked_reason"] is None or details["blocked_reason"] in {
                        "deadline_watchdog_unverified", "effective_deadline_exceeded",
                        "helper_preflight_failed", "incomplete_app_lifecycle",
                        "owned_cleanup_unverified", "component_postflight_failed",
                    }) and
                    (details["state"] == "blocked") ==
                        (details["blocked_reason"] is not None),
                    "Source5 job terminal disposition/reason shape differs")
            _digest(details["component_sha256"], "Source5 component digest")
            _digest(details["process_metrics_sha256"],
                    "Source5 process metrics digest")
            starts, terminals = prior["starts"], prior["terminals"]
            if details["state"] == "valid_pair":
                require(len(starts) == len(terminals) == prior["member_count"] == 2 and
                        all(item["status"] == 0 and item["cleanup_clean"]
                            for item in terminals),
                        "recorded valid Source5 pair lacks two clean successful APP lifecycles")
            elif details["state"] == "invalid_pair":
                require(len(starts) == len(terminals) == prior["member_count"] == 2 and
                        all(item["cleanup_clean"] for item in terminals),
                        "recorded invalid Source5 pair lacks two clean completed APP lifecycles")
            elif details["state"] in {"valid_soak", "invalid_soak"}:
                require(prior["phase"] == "soak" and
                        len(starts) == len(terminals) == prior["member_count"] == 1 and
                        terminals[0]["status"] == 0 and terminals[0]["cleanup_clean"],
                        "recorded Source5 Soak lacks its one clean successful APP lifecycle")
            else:
                require(details["blocked_reason"] in {
                            "effective_deadline_exceeded", "deadline_watchdog_unverified",
                        } or
                        (details["blocked_reason"] == "component_postflight_failed" and
                         prior["phase"] == "soak" and len(terminals) == 1 and
                         terminals[0]["status"] == 0 and terminals[0]["cleanup_clean"]) or
                        len(terminals) < prior["member_count"] or
                        any(item["status"] != 0 or not item["cleanup_clean"]
                            for item in terminals),
                        "recorded blocked Source5 job has no incomplete or failed APP lifecycle")
            prior["job_terminal"] = {
                "state_claim": details["state"],
                "blocked_reason": details["blocked_reason"],
                "started_count": details["started_count"],
                "terminal_count": details["terminal_count"],
                "component_sha256": details["component_sha256"],
                "process_metrics_sha256": details["process_metrics_sha256"],
                "event_head": record_sha,
                "component_replay_required": True,
            }
            prior["job_terminal"]["details"] = details
            finished_source5[(prior["phase"], prior["job_run_id"])] = prior
            del active_source5[authorization_id]
            source5_pending = None
            if details["state"] == "blocked":
                source5_cleanup_blocked = True
            row.update({"authorization_id": authorization_id,
                        "job_run_id": prior["job_run_id"],
                        "phase": prior["phase"]})
        elif event == "source5_analysis":
            phase = details["phase"]
            require(source5_pending is None and not source5_cleanup_blocked and
                    phase in {"exploration", "aa", "fixed_analysis", "pressure_analysis",
                              "soak", "final_analysis"} and
                    phase not in analyses,
                    "Source5 analysis is structurally out of order")
            # The stored booleans and analysis reference are claims only. They
            # are indexed for ancestry but never become a replayed gate result.
            for name in ("analysis_sha256", "job_set_sha256"):
                _digest(details[name], f"Source5 analysis {name}")
            require(type(details["numeric_gates_passed"]) is bool and
                    type(details["phase_gate_passed"]) is bool and
                    type(details["job_evidence_complete"]) is bool and
                    details["campaign_qualification_eligible"] is False,
                    "Source5 analysis claim fields are malformed or eligibility-bearing")
            analyses[phase] = {
                "event_head": record_sha,
                "analysis_sha256": details["analysis_sha256"],
                "job_set_sha256": details["job_set_sha256"],
                "job_count": details["job_count"],
                "analysis": details["analysis"],
                "numeric_gates_claimed": details["numeric_gates_passed"],
                "phase_gate_claimed": details["phase_gate_passed"],
                "replay_required": True,
            }
            row["phase"] = phase
            row["analysis_sha256"] = details["analysis_sha256"]
            row["analysis"] = details["analysis"]
        elif event == "dispatch_authorized":
            require(registration_head is not None and dispatch_pending is None and
                    source5_pending is None and not cleanup_blocked,
                    "legacy dispatch is structurally out of order")
            auth_id = _token(details["authorization_id"], "dispatch authorization ID")
            job = details["job"]
            require(type(job) is dict and type(job.get("run_id")) is str and
                    job.get("run_id") and details["capacity_registration_head"] == registration_head and
                    auth_id not in active_dispatch and auth_id not in finished_dispatch,
                    "legacy dispatch authorization changed run/registration identity")
            active_dispatch[auth_id] = {
                "authorization_id": auth_id, "job_run_id": job["run_id"],
                "authorization_head": record_sha, "bound": None,
            }
            dispatch_pending = auth_id
            row.update({"authorization_id": auth_id, "job_run_id": job["run_id"]})
        elif event == "dispatch_bound":
            auth_id = _token(details["authorization_id"], "dispatch authorization ID")
            prior = active_dispatch.get(auth_id)
            require(prior is not None and dispatch_pending == auth_id and
                    prior["bound"] is None and details["job_run_id"] == prior["job_run_id"] and
                    details["capacity_registration_head"] == registration_head,
                    "legacy dispatch bind has no exact prior authorization")
            prior["bound"] = {
                "event_head": record_sha, "pid": details["pid"],
                "start_ticks": details["start_ticks"],
            }
            row.update({"authorization_id": auth_id,
                        "job_run_id": prior["job_run_id"]})
        elif event.startswith("dispatch_"):
            auth_id = _token(details["authorization_id"], "dispatch authorization ID")
            prior = active_dispatch.get(auth_id)
            require(prior is not None and dispatch_pending == auth_id and
                    details["job_run_id"] == prior["job_run_id"] and
                    details["capacity_registration_head"] == registration_head,
                    f"legacy chronology {event} has no exact prior authorization")
            if event == "dispatch_exited":
                require(prior["bound"] is not None and
                        details["pid"] == prior["bound"]["pid"],
                        "legacy dispatch exit differs from its bound PID")
            if event in {"dispatch_exited", "dispatch_failed",
                         "dispatch_interrupted", "dispatch_timeout"}:
                cleanup_safe = _validate_process_cleanup_details(details)
                if not cleanup_safe:
                    cleanup_blocked = True
                finished_dispatch.add(auth_id)
                del active_dispatch[auth_id]
                dispatch_pending = None
            row.update({"authorization_id": auth_id,
                        "job_run_id": prior["job_run_id"]})

        heads.append(record_sha)
        event_index.append(row)

    return {
        "schema": SOURCE5_JOURNAL_ANCESTRY_SCHEMA_V1,
        "campaign_id": campaign_id, "host_id": host_id,
        "original_pins_sha256": original_pins_sha256,
        "record_count": record_count, "terminal_head": terminal_head,
        "head_by_record_count": heads,
        "events": event_index,
        "registrations": registration_index,
        "source5_authorizations": authorization_index,
        "source5_finished": [
            {
                "phase": phase, "job_run_id": run_id,
                "authorization_id": finished_source5[(phase, run_id)]["authorization_id"],
                "authorization_head": finished_source5[(phase, run_id)]["authorization_head"],
                "job_terminal": finished_source5[(phase, run_id)]["job_terminal"],
            }
            for phase, run_id in sorted(finished_source5)
        ],
        "source5_analyses": analyses,
        "pending_source5_authorization": source5_pending,
        "pending_dispatch_authorization": dispatch_pending,
        "cleanup_blocked": cleanup_blocked,
        "source5_cleanup_blocked": source5_cleanup_blocked,
        "analysis_results_replayed": False,
        "component_results_replayed": False,
    }


def replay_journal_bytes(
    raw: bytes, original_pins: dict[str, Any], campaign_id: str,
    host_id: str, boot_id_sha256: str, *,
    maximum_events: int = MAX_JOURNAL_EVENTS,
    maximum_bytes: int = MAX_JOURNAL_BYTES,
) -> dict[str, Any]:
    """Purely verify the exact v2 journal chain and index one-use ancestry.

    This is structural evidence only. It does not replay capacity producers,
    job components, APP output, analyses, or campaign gates.
    """
    original_sha = sha256_bytes(canonical_bytes(original_pins))
    result = _journal_structural_index(
        _iter_journal_records(raw, original_pins, campaign_id, host_id,
                              boot_id_sha256, maximum_events=maximum_events,
                              maximum_bytes=maximum_bytes),
        campaign_id, host_id, original_sha,
    )
    result.update({
        "journal_raw_sha256": sha256_bytes(raw),
        "journal_byte_count": len(raw),
        "journal_chain_replayed": True,
        "component_dispatch_pending": True,
        "qualification_eligible": False,
        "execution_ready": False,
    })
    return result


def _journal_ancestry_proof_from_index(
    ancestry: dict[str, Any], ancestor_head: str, ancestor_record_count: int,
    expected_event: str, authorization_id: str, run_id: str,
) -> dict[str, Any]:
    _digest(ancestor_head, "journal ancestor head")
    count = _uint(ancestor_record_count, "journal ancestor record count")
    require(count <= ancestry["record_count"] and
            ancestry["head_by_record_count"][count] == ancestor_head,
            "requested journal head/count is not an exact captured ancestor")
    matches = [row for row in ancestry["events"]
               if row["sequence"] == count and row["event"] == expected_event]
    require(len(matches) == 1,
            "requested journal ancestor is not the exact expected event")
    event_row = matches[0]
    require(event_row["authorization_id"] == authorization_id and
            event_row["job_run_id"] == run_id,
            "requested journal ancestor has a different authorization/job identity")
    return {
        "schema": SOURCE5_JOURNAL_ANCESTRY_SCHEMA_V1,
        "campaign_id": ancestry["campaign_id"], "host_id": ancestry["host_id"],
        "ancestor_head": ancestor_head, "ancestor_record_count": count,
        "event": expected_event, "authorization_id": authorization_id,
        "job_run_id": run_id, "journal_terminal_head": ancestry["terminal_head"],
        "journal_record_count": ancestry["record_count"],
        "structural_only": True, "qualification_eligible": False,
    }


def _journal_absolute_path(value: object, label: str) -> str:
    require(type(value) is str, f"{label} must be original absolute path text")
    path = Path(_path_text(Path(value), label))
    require(path.is_absolute() and str(path) == value,
            f"{label} is not normalized absolute path text")
    require(not value.startswith("//") and
            all(part not in ("", ".", "..") for part in path.parts[1:]),
            f"{label} contains a path alias component")
    return value


def _validate_chronology_original_pins(value: object) -> dict[str, Any]:
    pins = _exact(value, {
        "schema", "campaign_id", "host_id", "spec", "plan",
        "source_manifests", "observed_host", "capacity_stage",
        "chronology_module", "pair_runner", "captured_modules",
    }, "original chronology input projection")
    require(pins["schema"] == CHRONOLOGY_SCHEMA,
            "original chronology input projection schema differs")
    _token(pins["campaign_id"], "original campaign ID")
    _token(pins["host_id"], "original host ID")
    for role in ("spec", "plan"):
        pin = _exact(pins[role], {"path", "raw_sha256", "semantic_sha256"},
                     f"original {role} pin")
        _journal_absolute_path(pin["path"], f"original {role} path")
        _digest(pin["raw_sha256"], f"original {role} raw SHA-256")
        _digest(pin["semantic_sha256"], f"original {role} semantic SHA-256")
    source_rows = pins["source_manifests"]
    require(type(source_rows) is list and len(source_rows) == 3,
            "original source-manifest projection must retain exactly three hosts")
    source_hosts: list[str] = []
    for index, item in enumerate(source_rows):
        row = _exact(item, {
            "host_id", "path", "raw_sha256", "semantic_sha256",
            "source_tree_sha256",
        }, f"original source-manifest pin[{index}]")
        source_hosts.append(_token(row["host_id"], "source-manifest host ID"))
        _journal_absolute_path(row["path"], "source-manifest path")
        for name in ("raw_sha256", "semantic_sha256", "source_tree_sha256"):
            _digest(row[name], f"source-manifest {name}")
    require(len(set(source_hosts)) == 3 and pins["host_id"] in source_hosts,
            "original source-manifest projection repeats or omits a host")
    observed = _exact(pins["observed_host"], {
        "path", "raw_sha256", "boot_id_sha256", "controls_sha256", "controls",
        "cpu_affinity", "network_namespace_inode",
    }, "original observed-host projection")
    _journal_absolute_path(observed["path"], "observed-host path")
    for name in ("raw_sha256", "boot_id_sha256", "controls_sha256"):
        _digest(observed[name], f"observed-host {name}")
    require(type(observed["controls"]) is dict and
            observed["controls_sha256"] ==
                sha256_bytes(canonical_bytes(observed["controls"])),
            "original observed-host controls digest differs")
    require(type(observed["cpu_affinity"]) is list and
            observed["cpu_affinity"] == sorted(set(observed["cpu_affinity"])) and
            all(type(cpu) is int and 0 <= cpu <= 65535
                for cpu in observed["cpu_affinity"]),
            "original observed-host CPU affinity is malformed")
    _uint(observed["network_namespace_inode"],
          "original observed network namespace", positive=True)
    for role in ("capacity_stage", "chronology_module", "pair_runner"):
        item = _exact(pins[role], {"path", "sha256"},
                      f"original {role} module pin")
        require(type(item["path"]) is str and item["path"],
                f"original {role} module path is malformed")
        _digest(item["sha256"], f"original {role} module SHA-256")
    captured = pins["captured_modules"]
    expected_roles = {
        "campaign_controller": CONTROLLER_SOURCE_PATH,
        "campaign_inputs": "scripts/application-campaign-inputs.py",
        "feedback_reader": "scripts/application-feedback-readback.py",
        "capacity_producer": "scripts/application-byte-capacity.py",
    }
    require(type(captured) is list and len(captured) == len(expected_roles),
            "original captured-module projection is incomplete")
    seen_roles: set[str] = set()
    for index, item in enumerate(captured):
        row = _exact(item, {"role", "path", "sha256"},
                     f"original captured module[{index}]")
        role = row["role"]
        require(role in expected_roles and role not in seen_roles and
                row["path"] == expected_roles[role],
                "original captured-module role/path differs")
        seen_roles.add(role)
        _digest(row["sha256"], f"original {role} module SHA-256")
    require(seen_roles == set(expected_roles),
            "original captured-module role set differs")
    return pins


def _source5_journal_role_limit(role: str) -> int:
    return SOURCE5_JOURNAL_ROLE_LIMITS[role]


SOURCE5_JOURNAL_ROLE_LIMITS = {
    "evidence_index": MAX_SOURCE5_JOURNAL_INDEX_BYTES,
    "origin_receipt": MAX_COMPLETION_BYTES,
    "journal": MAX_SOURCE5_JOURNAL_BYTES,
    "execution_manifest": MAX_PLAN_BYTES,
    "preparation": MAX_COMPLETION_BYTES,
    "prepared_completion": MAX_COMPLETION_BYTES,
    "spec_v3": MAX_SPEC_BYTES,
    "plan_v3": MAX_PLAN_BYTES,
    "source_manifest": MAX_MANIFEST_BYTES,
    "observed_host": MAX_MANIFEST_BYTES,
    "typed_source_file": MAX_SOURCE_BYTES,
    "typed_source_symlink": MAX_SOURCE5_TYPED_SYMLINK_BYTES,
    "capacity_completion": MAX_COMPLETION_BYTES,
    "capacity_ledger": MAX_JOURNAL_BYTES,
    "capacity_request": MAX_PLAN_BYTES,
    "capacity_artifact": MAX_PLAN_BYTES,
    "capacity_receipt": MAX_PLAN_BYTES,
    "source5_helper_input": MAX_PLAN_BYTES,
    "source5_job_record": MAX_EVENT_BYTES,
    "capacity_host_receipt": MAX_COMPLETION_BYTES,
    "component_receipt": MAX_PLAN_BYTES,
    "fixed_pair_artifact": MAX_ANALYZER_BYTES,
    "pressure_pair_artifact": MAX_ANALYZER_BYTES,
    "source5_soak_artifact": MAX_ANALYZER_BYTES,
    "normal_app_output": MAX_ANALYZER_BYTES,
    "analysis_artifact": MAX_EVENT_BYTES,
    "opaque_trace": MAX_ANALYZER_BYTES,
}


def _validate_source5_journal_index_document(
    value: object, campaign_id: str, host_id: str,
    source_root: str, input_root: str, output_root: str,
) -> dict[str, Any]:
    index = _exact(value, {
        "schema", "campaign_id", "host_id", "source_root", "input_root",
        "output_root", "entries", "index_sha256",
    }, "Source5 journal evidence index")
    require(index["schema"] == SOURCE5_JOURNAL_EVIDENCE_INDEX_SCHEMA_V1 and
            index["campaign_id"] == campaign_id and index["host_id"] == host_id and
            index["source_root"] == source_root and index["input_root"] == input_root and
            index["output_root"] == output_root,
            "Source5 journal evidence-index identity/roots differ")
    body = {key: item for key, item in index.items() if key != "index_sha256"}
    _digest(index["index_sha256"], "Source5 journal evidence-index semantic digest")
    require(index["index_sha256"] == sha256_bytes(canonical_bytes(body)),
            "Source5 journal evidence-index self digest differs")
    entries = index["entries"]
    require(type(entries) is list and
            len(entries) <= MAX_SOURCE5_JOURNAL_EVIDENCE_ENTRIES,
            "Source5 journal evidence index is empty or exceeds its finite entry bound")
    previous = ""
    paths: set[str] = set()
    for position, item in enumerate(entries):
        row = _exact(item, {
            "role", "host_id", "origin_path", "local_path", "raw_sha256",
            "semantic_sha256", "byte_count",
        }, f"Source5 journal evidence index entry[{position}]")
        require(row["role"] in SOURCE5_JOURNAL_EVIDENCE_ROLES,
                f"Source5 evidence index entry[{position}] has an unknown typed role")
        origin = _journal_absolute_path(row["origin_path"],
                                        f"evidence origin path[{position}]")
        local = _journal_absolute_path(row["local_path"],
                                       f"evidence local path[{position}]")
        require(origin == local and origin > previous and origin not in paths,
                "Source5 journal evidence paths must be sorted, unique and identity-mapped")
        previous = origin
        paths.add(origin)
        if row["host_id"] is not None:
            _token(row["host_id"], "evidence entry host ID")
        _digest(row["raw_sha256"], "evidence entry raw SHA-256")
        semantic = row["semantic_sha256"]
        require(semantic is None or
                (type(semantic) is str and re.fullmatch(r"[0-9a-f]{64}", semantic) is not None),
                "evidence entry semantic digest is malformed")
        _uint(row["byte_count"], "evidence entry byte count",
              maximum=_source5_journal_role_limit(row["role"]))
    return index


def _source5_journal_index_entry(
    index: dict[str, Any], role: str, path: str, raw_sha256: str,
    *, host_id: str | None = None, semantic_sha256: str | None = None,
) -> dict[str, Any]:
    matches = [item for item in index["entries"]
               if item["role"] == role and item["origin_path"] == path]
    require(len(matches) == 1,
            f"Source5 journal evidence index lacks one exact {role} path")
    row = matches[0]
    require(row["raw_sha256"] == raw_sha256 and
            (host_id is None or row["host_id"] == host_id) and
            (semantic_sha256 is None or row["semantic_sha256"] == semantic_sha256),
            f"Source5 journal evidence index changed its {role} raw/semantic identity")
    return row


def _source5_live_origin_host_observation(
    prepared: dict[str, Any],
) -> dict[str, Any]:
    stage = prepared["stage"]
    stage_prepared = prepared["prepared"]
    verifier = getattr(stage, "_verify_observed_host", None)
    require(callable(verifier),
            "captured capacity stage lacks its strict origin-host verifier")
    try:
        observed = verifier(
            stage_prepared["host_context"], stage_prepared["host"],
            prepared["host_id"],
        )
    except Exception as error:
        raise ChronologyError(
            f"origin host observation no longer matches its pinned host context: {error}"
        ) from error
    value = {
        "boot_id_sha256": observed["boot_id_sha256"],
        "kernel_release": observed["kernel_release"],
        "cpu_model": observed["cpu_model"],
        "allowed_cpu_affinity": observed["cpu_affinity"],
        "network_namespace_inode": observed["network_namespace_inode"],
        "observed_monotonic_ns": time.monotonic_ns(),
    }
    return value


def _source5_origin_dependency_pins(prepared: dict[str, Any]) -> list[dict[str, Any]]:
    source_root = prepared["source_root"]
    host_sources = prepared["sources"]
    selected = prepared["source"]
    selected_raw = prepared["source_manifest_raw_refs"][prepared["host_id"]]
    result: list[dict[str, Any]] = []
    for role, relative in SOURCE5_JOURNAL_DEPENDENCY_ROLES:
        record = next((item for item in selected.get("source", {}).get("files", [])
                       if type(item) is dict and item.get("path") == relative), None)
        require(record is not None,
                f"Source5 typed source inventory lacks required {role} dependency")
        _raw, raw_sha, typed = _source_file(
            source_root, selected, relative, f"Source5 journal {role} dependency",
            maximum=MAX_SCRIPT_BYTES,
        )
        require(typed == record,
                f"Source5 journal {role} dependency differs from its typed inventory")
        for other_host, other_source in host_sources.items():
            _other_raw, other_sha, other_record = _source_file(
                source_root, other_source, relative,
                f"{other_host} Source5 journal {role} dependency",
                maximum=MAX_SCRIPT_BYTES,
            )
            require(other_sha == raw_sha and other_record["mode"] == typed["mode"] and
                    other_record["size"] == typed["size"],
                    f"SourceV5 host {other_host} captures another {relative} generation")
        result.append({
            "role": role, "path": relative, "raw_sha256": raw_sha,
            "mode": typed["mode"], "size": typed["size"],
            "source_manifest_raw_sha256": selected_raw["raw_sha256"],
            "source_manifest_semantic_sha256": selected_raw["semantic_sha256"],
            "source_tree_sha256": selected_raw["source_tree_sha256"],
        })
    result.sort(key=lambda item: item["path"])
    return result


def _validate_live_evidence_index_pin(
    pin_value: object, manifest: dict[str, Any], prepared: dict[str, Any],
    journal_summary: dict[str, Any], dependency_pins: list[dict[str, Any]],
    manifest_pin: dict[str, str], manifest_byte_count: int,
) -> tuple[dict[str, str], dict[str, Any]]:
    pin = _exact(pin_value, {"path", "raw_sha256", "semantic_sha256"},
                 "Source5 journal evidence-index pin")
    path_text = _journal_absolute_path(pin["path"],
                                       "Source5 journal evidence-index path")
    _digest(pin["raw_sha256"], "Source5 journal evidence-index raw SHA-256")
    _digest(pin["semantic_sha256"], "Source5 journal evidence-index semantic SHA-256")
    raw, info = _read_stable(Path(path_text), "Source5 journal evidence index",
                             MAX_SOURCE5_JOURNAL_INDEX_BYTES)
    require(stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid(),
            "Source5 journal evidence index must be an owned mode-0600 regular file")
    raw_sha = sha256_bytes(raw)
    require(raw_sha == pin["raw_sha256"],
            "Source5 journal evidence index raw bytes differ from their pin")
    value = _parse_object(raw, "Source5 journal evidence index",
                          MAX_SOURCE5_JOURNAL_INDEX_BYTES)
    index = _validate_source5_journal_index_document(
        value, prepared["campaign_id"], prepared["host_id"],
        str(prepared["source_root"]), str(prepared["input_root"]),
        str(prepared["output_root"]),
    )
    require(index["index_sha256"] == pin["semantic_sha256"],
            "Source5 evidence index semantic pin differs")
    journal_path = str(prepared["output_root"] / prepared["campaign_id"] /
                       "chronology" / prepared["host_id"] /
                       "dispatch-journal.jsonl")
    journal_row = _source5_journal_index_entry(
        index, "journal", journal_path, journal_summary["journal_raw_sha256"],
        host_id=prepared["host_id"],
    )
    require(journal_row["byte_count"] == journal_summary["journal_byte_count"] and
            journal_row["semantic_sha256"] is None,
            "Source5 evidence index journal size/semantic role differs")
    for role, pin_name in (("spec_v3", "spec"), ("plan_v3", "plan")):
        pin = prepared["original_pins"][pin_name]
        _source5_journal_index_entry(
            index, role, pin["path"], pin["raw_sha256"],
            semantic_sha256=pin["semantic_sha256"],
        )
    observed_pin = prepared["original_pins"]["observed_host"]
    _source5_journal_index_entry(
        index, "observed_host", observed_pin["path"], observed_pin["raw_sha256"],
        host_id=prepared["host_id"],
    )
    manifest_row = _source5_journal_index_entry(
        index, "execution_manifest", manifest_pin["path"],
        manifest_pin["sha256"], host_id=prepared["host_id"],
        semantic_sha256=manifest["manifest_sha256"],
    )
    require(manifest_row["byte_count"] == manifest_byte_count,
            "Source5 evidence index execution-manifest size differs")
    for source_host, ref in prepared["source_manifest_raw_refs"].items():
        _source5_journal_index_entry(
            index, "source_manifest", ref["path"], ref["raw_sha256"],
            host_id=source_host, semantic_sha256=ref["semantic_sha256"],
        )
    for item in dependency_pins:
        row = _source5_journal_index_entry(
            index, "typed_source_file",
            str(prepared["source_root"] / item["path"]), item["raw_sha256"],
            host_id=prepared["host_id"],
        )
        require(row["byte_count"] == item["size"] and
                row["semantic_sha256"] is None,
                f"Source5 evidence index typed module metadata differs for {item['path']}")
    return ({"path": path_text, "raw_sha256": raw_sha,
             "semantic_sha256": index["index_sha256"]}, index)


@_serialize_locked_api
def capture_source5_origin_journal_receipt_locked(
    lock: CampaignHostLock, execution_manifest_pin: object,
    evidence_index_pin: object, receipt_path: Path,
) -> dict[str, str]:
    """Capture one immutable origin-journal receipt while its live host lock is held."""
    manifest, prepared, state, manifest_pin = _prepare_source5_context(
        lock, execution_manifest_pin,
    )
    _check_lock(lock, prepared["output_root"], prepared["campaign_id"],
                prepared["host_id"])
    receipt_path = Path(receipt_path)
    require(receipt_path.is_absolute() and str(receipt_path) ==
            _path_text(receipt_path, "Source5 origin receipt path") and
            receipt_path.parent == lock.directory and
            receipt_path.name == "source5-origin-journal-receipt.json",
            "Source5 origin receipt path must be the fixed private host-lock child")
    dependency_pins = _source5_origin_dependency_pins(prepared)
    before = _source5_live_origin_host_observation(prepared)
    journal_path = _journal_path(lock)
    journal_max_events, journal_max_bytes = _journal_limits(prepared)
    try:
        journal_raw, journal_info = _read_stable(
            journal_path, "Source5 origin campaign journal", journal_max_bytes,
        )
        require(stat.S_IMODE(journal_info.st_mode) == 0o600 and
                journal_info.st_uid == os.getuid(),
                "Source5 origin journal must be an owned mode-0600 regular file")
    except ChronologyError as error:
        if not isinstance(error.__cause__, FileNotFoundError):
            raise
        journal_raw = b""
    journal_replay = replay_journal_bytes(
        journal_raw, prepared["original_pins"], prepared["campaign_id"],
        prepared["host_id"], prepared["boot_id_sha256"],
        maximum_events=journal_max_events, maximum_bytes=journal_max_bytes,
    )
    require(journal_replay["record_count"] == state["record_count"] and
            journal_replay["terminal_head"] == state["head"] and
            journal_replay["last_monotonic_ns"] == state["last_monotonic_ns"],
            "Source5 live semantic state differs from the exact stable journal snapshot")
    after = _source5_live_origin_host_observation(prepared)
    stable_fact_names = {
        "boot_id_sha256", "kernel_release", "cpu_model",
        "allowed_cpu_affinity", "network_namespace_inode",
    }
    require({key: before[key] for key in stable_fact_names} ==
            {key: after[key] for key in stable_fact_names},
            "Source5 origin host identity changed across the journal snapshot")
    original_host = prepared["original_pins"]["observed_host"]
    require(before["boot_id_sha256"] == original_host["boot_id_sha256"] and
            before["allowed_cpu_affinity"] == original_host["cpu_affinity"] and
            before["network_namespace_inode"] ==
                original_host["network_namespace_inode"],
            "Source5 origin observations differ from the pinned observed host")
    _check_lock(lock, prepared["output_root"], prepared["campaign_id"],
                prepared["host_id"])
    try:
        journal_after, _journal_after_info = _read_stable(
            journal_path, "Source5 origin campaign journal after host observation",
            journal_max_bytes,
        )
    except ChronologyError as error:
        if not isinstance(error.__cause__, FileNotFoundError):
            raise
        journal_after = b""
    require(sha256_bytes(journal_after) == sha256_bytes(journal_raw),
            "Source5 journal changed during origin receipt capture")
    captured_monotonic_ns = time.monotonic_ns()
    require(journal_replay["last_monotonic_ns"] <= captured_monotonic_ns and
            after["observed_monotonic_ns"] <= captured_monotonic_ns,
            "Source5 journal exceeds its actual origin capture monotonic bound")
    manifest_pin_value = {
        "path": manifest_pin["path"], "raw_sha256": manifest_pin["sha256"],
        "semantic_sha256": manifest["manifest_sha256"],
    }
    manifest_raw, _manifest_info = _read_stable(
        Path(manifest_pin["path"]), "Source5 origin execution manifest",
        MAX_PLAN_BYTES,
    )
    require(sha256_bytes(manifest_raw) == manifest_pin["sha256"],
            "Source5 execution manifest changed before origin receipt capture")
    index_pin, index = _validate_live_evidence_index_pin(
        evidence_index_pin, manifest, prepared,
        {**journal_replay, "journal_raw_sha256": sha256_bytes(journal_raw)},
        dependency_pins,
        {"path": manifest_pin["path"], "sha256": manifest_pin["sha256"]},
        len(manifest_raw),
    )
    origin_facts_body = {
        "schema": "allocatbelt.application-source5-origin-journal-facts.v1",
        "host_id": prepared["host_id"],
        "observed_host_pin": {
            "path": original_host["path"],
            "raw_sha256": original_host["raw_sha256"],
        },
        "boot_id_sha256": before["boot_id_sha256"],
        "kernel_release": before["kernel_release"],
        "cpu_model": before["cpu_model"],
        "allowed_cpu_affinity": before["allowed_cpu_affinity"],
        "network_namespace_inode": before["network_namespace_inode"],
        "controls_sha256": original_host["controls_sha256"],
        "controls": original_host["controls"],
        "before": before, "after": after,
    }
    origin_facts = {
        **origin_facts_body,
        "origin_facts_sha256": sha256_bytes(canonical_bytes(origin_facts_body)),
    }
    journal_record = {
        "path": str(journal_path),
        "raw_sha256": sha256_bytes(journal_raw),
        "byte_count": len(journal_raw),
        "record_count": journal_replay["record_count"],
        "terminal_head": journal_replay["terminal_head"],
        "last_monotonic_ns": journal_replay["last_monotonic_ns"],
    }
    body = {
        "schema": SOURCE5_ORIGIN_JOURNAL_RECEIPT_SCHEMA_V1,
        "campaign_id": prepared["campaign_id"],
        "host_id": prepared["host_id"],
        "original_pins": prepared["original_pins"],
        "execution_manifest": manifest_pin_value,
        "journal": journal_record,
        "origin_facts": origin_facts,
        "captured_monotonic_ns": captured_monotonic_ns,
        "dependency_pins": dependency_pins,
        "evidence_index": index_pin,
        "qualification_eligible": False,
        "execution_ready": False,
    }
    receipt = {**body, "receipt_sha256": sha256_bytes(canonical_bytes(body))}
    raw = canonical_bytes(receipt)
    require(len(raw) <= MAX_COMPLETION_BYTES,
            "Source5 origin journal receipt exceeds its finite byte bound")
    _write_exclusive(receipt_path, raw, 0o600)
    return {
        "path": str(receipt_path), "raw_sha256": sha256_bytes(raw),
        "semantic_sha256": receipt["receipt_sha256"],
    }


def _source5_evidence_chunks(value: object, byte_count: int, label: str):
    _uint(byte_count, f"{label} byte count", maximum=MAX_ANALYZER_BYTES)
    if type(value) is bytes:
        require(len(value) == byte_count,
                f"{label} byte length differs from its declared inventory")
        for offset in range(0, len(value), 1024 * 1024):
            yield value[offset:offset + 1024 * 1024]
        return
    require(type(value) is io.BufferedReader and
            type(value.raw) is io.FileIO and value.readable() and
            not value.writable() and value.seekable() and value.raw.mode == "rb",
            f"{label} must be immutable bytes or a bounded read-only stream")
    try:
        value.seek(0)
        require(value.tell() == 0,
                f"{label} stream did not start at its original byte origin")
        remaining = byte_count
        while remaining:
            block = value.read(min(1024 * 1024, remaining))
            require(type(block) is bytes and bool(block),
                    f"{label} stream ended before its pinned byte count")
            remaining -= len(block)
            yield block
        require(value.read(1) == b"",
                f"{label} stream contains bytes after its declared length")
    except (OSError, ValueError) as error:
        raise ChronologyError(f"cannot read captured {label}: {error}") from error


def _source5_evidence_bytes(
    entry: dict[str, Any], label: str, maximum: int,
) -> tuple[bytes, str]:
    require(entry["byte_count"] <= maximum,
            f"captured {label} exceeds its role-specific byte bound")
    chunks: list[bytes] = []
    hasher = hashlib.sha256()
    total = 0
    for block in _source5_evidence_chunks(
            entry["raw_bytes"], entry["byte_count"], label):
        total += len(block)
        require(total <= maximum,
                f"captured {label} exceeds its role-specific byte bound")
        hasher.update(block)
        chunks.append(block)
    require(total == entry["byte_count"] and
            hasher.hexdigest() == entry["raw_sha256"],
            f"captured {label} bytes differ from their original raw pin")
    return b"".join(chunks), hasher.hexdigest()


def _source5_verify_evidence_bytes(entry: dict[str, Any], label: str) -> str:
    hasher = hashlib.sha256()
    total = 0
    for block in _source5_evidence_chunks(
            entry["raw_bytes"], entry["byte_count"], label):
        total += len(block)
        require(total <= _source5_journal_role_limit(entry["role"]),
                f"captured {label} exceeds its role-specific byte bound")
        hasher.update(block)
    digest = hasher.hexdigest()
    require(total == entry["byte_count"] and digest == entry["raw_sha256"],
            f"captured {label} bytes differ from their original raw pin")
    return digest


def _source5_captured_evidence_store(value: object) -> dict[str, dict[str, Any]]:
    store = _exact(value, {"schema", "entries"}, "Source5 captured evidence store")
    require(store["schema"] == SOURCE5_CAPTURED_EVIDENCE_SCHEMA_V1,
            "unsupported Source5 captured evidence-store schema")
    entries = store["entries"]
    require(type(entries) is list and
            len(entries) <= MAX_SOURCE5_JOURNAL_EVIDENCE_ENTRIES,
            "Source5 captured evidence store is empty or exceeds its finite entry bound")
    result: dict[str, dict[str, Any]] = {}
    previous = ""
    for index, item in enumerate(entries):
        row = _exact(item, {
            "role", "host_id", "origin_path", "local_path", "raw_sha256",
            "semantic_sha256", "byte_count", "raw_bytes",
        }, f"Source5 captured evidence entry[{index}]")
        role = row["role"]
        require(role in SOURCE5_JOURNAL_EVIDENCE_ROLES,
                f"captured evidence entry[{index}] has an unknown typed role")
        origin = _journal_absolute_path(row["origin_path"],
                                        f"captured origin path[{index}]")
        local = _journal_absolute_path(row["local_path"],
                                       f"captured local path[{index}]")
        require(origin == local and origin > previous and origin not in result,
                "captured evidence entries must be unique sorted identity paths")
        previous = origin
        host_id = row["host_id"]
        if host_id is not None:
            _token(host_id, "captured evidence host ID")
        _digest(row["raw_sha256"], "captured evidence raw SHA-256")
        semantic = row["semantic_sha256"]
        require(semantic is None or
                (type(semantic) is str and
                 re.fullmatch(r"[0-9a-f]{64}", semantic) is not None),
                "captured evidence semantic digest is malformed")
        _uint(row["byte_count"], "captured evidence byte count",
              maximum=_source5_journal_role_limit(role))
        data = row["raw_bytes"]
        require(type(data) is bytes or
                (type(data) is io.BufferedReader and type(data.raw) is io.FileIO and
                 data.readable() and not data.writable() and data.seekable() and
                 data.raw.mode == "rb"),
                "captured evidence must be immutable bytes or a read-only stream")
        result[origin] = row
    return result


def _source5_index_role_map(index: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {row["origin_path"]: row for row in index["entries"]}


def _source5_verify_store_closure(
    store: dict[str, dict[str, Any]], index: dict[str, Any],
    index_pin: dict[str, str], receipt_pin: dict[str, str],
) -> None:
    rows = _source5_index_role_map(index)
    expected_paths = set(rows) | {index_pin["path"], receipt_pin["path"]}
    require(set(store) == expected_paths,
            "captured Source5 evidence members differ from the closed role index")
    for path, source_row in rows.items():
        captured = store[path]
        for name in ("role", "host_id", "origin_path", "local_path", "raw_sha256",
                     "semantic_sha256", "byte_count"):
            require(captured[name] == source_row[name],
                    f"captured Source5 evidence changes indexed {name} for {path}")
    index_entry = store[index_pin["path"]]
    require(index_entry["role"] == "evidence_index" and
            index_entry["raw_sha256"] == index_pin["raw_sha256"] and
            index_entry["semantic_sha256"] == index_pin["semantic_sha256"],
            "captured Source5 evidence index file differs from its external pin")
    receipt_entry = store[receipt_pin["path"]]
    require(receipt_entry["role"] == "origin_receipt" and
            receipt_entry["raw_sha256"] == receipt_pin["raw_sha256"] and
            receipt_entry["semantic_sha256"] == receipt_pin["semantic_sha256"],
            "captured Source5 origin receipt file differs from its external pin")


def _source5_read_canonical_evidence(
    store: dict[str, dict[str, Any]], path: str, label: str, maximum: int,
) -> tuple[dict[str, Any], bytes, str]:
    entry = store.get(path)
    require(entry is not None,
            f"captured Source5 evidence omits the direct {label} path")
    raw, actual = _source5_evidence_bytes(entry, label, maximum)
    value = _parse_object(raw, label, maximum)
    require(actual == entry["raw_sha256"],
            f"captured {label} raw bytes differ from their pin")
    return value, raw, actual


def _source5_source_manifest_document(
    store: dict[str, dict[str, Any]], row: dict[str, Any],
) -> dict[str, Any]:
    value, raw, actual = _source5_read_canonical_evidence(
        store, row["origin_path"], f"SourceV5 manifest {row['host_id']}",
        MAX_MANIFEST_BYTES,
    )
    value = _exact(value, {
        "schema", "source", "build", "artifacts", "soak_artifacts",
        "analysis_artifact", "fixed_runtime_policy",
        "runtime_readback_validator", "resource_domain_calibration",
        "qualification_harness", "feedback_policy", "manifest_sha256",
    }, "SourceV5 source manifest")
    require(row["role"] == "source_manifest" and
            row["host_id"] is not None and
            actual == row["raw_sha256"] and
            value.get("schema") == SOURCE_SCHEMA and
            value.get("manifest_sha256") == row["semantic_sha256"] and
            sha256_bytes(canonical_bytes({key: item for key, item in value.items()
                                          if key != "manifest_sha256"})) ==
                value.get("manifest_sha256"),
            "SourceV5 source-manifest raw/semantic roles differ")
    source = value.get("source")
    require(type(source) is dict and set(source) == {
        "git_commit", "source_tree_sha256", "cargo_lock_sha256", "files",
    }, "SourceV5 source-manifest typed inventory is malformed")
    entries = source["files"]
    require(type(entries) is list and
            0 < len(entries) <= MAX_SOURCE5_TYPED_SOURCE_FILES,
            "SourceV5 typed source inventory is sparse or oversized")
    normalized: list[dict[str, Any]] = []
    by_path: dict[str, dict[str, Any]] = {}
    previous_path_bytes: bytes | None = None
    total_bytes = 0
    for index, item in enumerate(entries):
        require(type(item) is dict,
                f"SourceV5 typed source entry[{index}] is not an object")
        kind = item.get("kind")
        fields = {"path", "kind", "mode", "sha256", "size"}
        if kind == "symlink":
            fields.add("target")
        record = _exact(item, fields,
                        f"SourceV5 typed source entry[{index}]")
        relative = _relative(record["path"], "SourceV5 typed source relative path")
        path_text = relative.as_posix()
        require("\n" not in path_text and "\r" not in path_text,
                "SourceV5 typed source path contains a forbidden newline")
        try:
            path_bytes = path_text.encode("utf-8", "strict")
        except UnicodeEncodeError as error:
            raise ChronologyError(
                "SourceV5 typed source path is not valid UTF-8 text",
            ) from error
        require(path_text not in by_path and
                (previous_path_bytes is None or path_bytes > previous_path_bytes),
                "SourceV5 typed source paths must be unique and UTF-8 byte sorted")
        previous_path_bytes = path_bytes
        _digest(record["sha256"], "SourceV5 typed source file digest")
        size = _uint(record["size"], "SourceV5 typed source file size",
                     maximum=(MAX_SOURCE_BYTES if kind == "file" else
                              MAX_SOURCE5_TYPED_SYMLINK_BYTES))
        if kind == "file":
            require(record["mode"] in {"100644", "100755"},
                    "SourceV5 regular source file has an invalid mode")
            canonical_record = {
                "path": path_text, "kind": "file", "mode": record["mode"],
                "sha256": record["sha256"], "size": size,
            }
        else:
            require(kind == "symlink" and record["mode"] == "120000",
                    "SourceV5 typed source entry has an invalid kind or mode")
            target = record["target"]
            require(type(target) is str,
                    "SourceV5 source symlink target is malformed")
            try:
                target_bytes = target.encode("utf-8", "strict")
            except UnicodeEncodeError as error:
                raise ChronologyError(
                    "SourceV5 source symlink target is not valid UTF-8 text",
                ) from error
            require(0 < len(target_bytes) <= MAX_SOURCE5_TYPED_SYMLINK_BYTES and
                    size == len(target_bytes) and
                    sha256_bytes(target_bytes) == record["sha256"],
                    "SourceV5 source symlink literal target hash or size differs")
            canonical_record = {
                "path": path_text, "kind": "symlink", "mode": "120000",
                "target": target, "sha256": record["sha256"], "size": size,
            }
        total_bytes += size
        require(total_bytes <= MAX_SOURCE5_TYPED_SOURCE_TOTAL_BYTES,
                "SourceV5 typed source inventory exceeds its finite total byte bound")
        by_path[path_text] = canonical_record
        normalized.append(canonical_record)

    symlink_paths = {
        path for path, item in by_path.items() if item["kind"] == "symlink"
    }
    for path, item in by_path.items():
        parts = path.split("/")
        for position in range(1, len(parts)):
            parent = "/".join(parts[:position])
            require(parent not in by_path and parent not in symlink_paths,
                    f"SourceV5 typed source inventory has a non-directory parent: {path}")
        if item["kind"] != "symlink":
            continue
        target = item["target"]
        require(target and not target.startswith("/") and "\\" not in target and
                "\n" not in target and "\r" not in target and "\x00" not in target,
                f"SourceV5 source symlink target is not bounded relative text: {path}")
        target_parts = target.split("/")
        require(all(target_parts),
                f"SourceV5 source symlink target is not normalized: {path}")
        resolved = path.split("/")[:-1]
        for position, part in enumerate(target_parts):
            if part == ".":
                continue
            if part == "..":
                require(bool(resolved),
                        f"SourceV5 source symlink target escapes the source tree: {path}")
                resolved.pop()
            else:
                resolved.append(part)
                if position < len(target_parts) - 1:
                    prefix = "/".join(resolved)
                    require(prefix not in by_path,
                            f"SourceV5 source symlink traverses a non-directory: {path}")
        require(bool(resolved),
                f"SourceV5 source symlink resolves to the source root: {path}")
        target_record = by_path.get("/".join(resolved))
        require(target_record is not None and target_record["kind"] == "file",
                f"SourceV5 source symlink does not target one regular inventory file: {path}")

    _digest(source["source_tree_sha256"], "SourceV5 source-tree digest")
    _digest(source["cargo_lock_sha256"], "SourceV5 Cargo.lock digest")
    require(type(source["git_commit"]) is str and bool(source["git_commit"]),
            "SourceV5 source commit identity is malformed")
    expected_tree_sha256 = sha256_bytes(canonical_bytes({
        "schema": SOURCE_INVENTORY_SCHEMA, "entries": normalized,
    }))
    require(source["source_tree_sha256"] == expected_tree_sha256,
            "SourceV5 typed source-tree digest does not bind its normalized inventory")
    _token(source["git_commit"], "SourceV5 source commit identity", 1024)
    return value


def _source5_manifest_artifact_pins(
    manifest: dict[str, Any],
) -> list[tuple[str, str, str]]:
    """Return every external SourceV5 artifact as a typed role/path/raw pin."""
    result: list[tuple[str, str, str]] = []
    allocators = {"allocatbelt", "mimalloc-secure", "mimalloc-standard", "system"}
    artifacts = _exact(manifest.get("artifacts"), allocators,
                       "SourceV5 four-allocator artifact map")
    declared_paths: set[str] = set()
    for allocator, item in artifacts.items():
        pin = _exact(item, {"path", "sha256"},
                     f"SourceV5 {allocator} application artifact")
        relative = _relative(pin["path"],
                             f"SourceV5 {allocator} artifact path")
        require(relative.as_posix() not in declared_paths,
                "SourceV5 four-allocator artifacts alias a frozen path")
        declared_paths.add(relative.as_posix())
        result.append(("normal_app_output", relative.as_posix(),
                       _digest(pin["sha256"],
                               f"SourceV5 {allocator} artifact digest")))

    soak_artifacts = manifest.get("soak_artifacts")
    require(type(soak_artifacts) is dict and
            "allocatbelt" in soak_artifacts and
            set(soak_artifacts).issubset(allocators),
            "SourceV5 Soak artifacts omit the candidate or name an unknown allocator")
    for allocator, item in soak_artifacts.items():
        pin = _exact(item, {"path", "sha256"},
                     f"SourceV5 {allocator} Soak artifact")
        relative = _relative(pin["path"],
                             f"SourceV5 {allocator} Soak artifact path")
        require(relative.as_posix() not in declared_paths,
                "SourceV5 Soak artifact aliases another declared build artifact")
        declared_paths.add(relative.as_posix())
        result.append(("source5_soak_artifact", relative.as_posix(),
                       _digest(pin["sha256"],
                               f"SourceV5 {allocator} Soak artifact digest")))

    analysis = _exact(manifest.get("analysis_artifact"), {"path", "sha256"},
                      "SourceV5 analyzer artifact")
    analysis_path = _relative(analysis["path"],
                              "SourceV5 analyzer artifact path").as_posix()
    require(analysis_path not in declared_paths,
            "SourceV5 analyzer aliases a treatment artifact")
    declared_paths.add(analysis_path)
    result.append(("analysis_artifact", analysis_path,
                   _digest(analysis["sha256"],
                           "SourceV5 analyzer artifact digest")))

    calibration = _exact(manifest.get("resource_domain_calibration"), {
        "binary", "output", "record", "source", "build", "build_sha256",
    }, "SourceV5 resource-domain calibration")
    for name in ("binary", "output"):
        pin = _exact(calibration[name], {"path", "sha256"},
                     f"SourceV5 calibration {name} artifact")
        calibration_path = _relative(
            pin["path"], f"SourceV5 calibration {name} path",
        ).as_posix()
        require(calibration_path not in declared_paths,
                "SourceV5 domain-calibration artifact aliases another artifact")
        declared_paths.add(calibration_path)
        result.append(("capacity_artifact", calibration_path,
                       _digest(pin["sha256"],
                               f"SourceV5 calibration {name} digest")))

    # The runtime validator is source code, so it must be covered by the
    # regular typed inventory rather than a second artifact role.
    validator = _exact(manifest.get("runtime_readback_validator"),
                       {"path", "sha256"},
                       "SourceV5 runtime-readback source pin")
    validator_path = _relative(validator["path"],
                               "SourceV5 runtime-readback source path").as_posix()
    source_rows = manifest.get("source", {}).get("files")
    matches = [item for item in source_rows
               if type(item) is dict and item.get("path") == validator_path]
    require(len(matches) == 1 and matches[0].get("kind") == "file" and
            matches[0].get("sha256") == validator["sha256"],
            "SourceV5 runtime-readback source is not one exact regular inventory pin")
    return result


def _source5_validate_full_source_index_closure(
    request: dict[str, Any], manifest: dict[str, Any],
    sources: dict[str, dict[str, Any]], host_ids: list[str],
    index: dict[str, Any], store: dict[str, dict[str, Any]],
) -> None:
    """Check complete typed source/artifact membership before consuming files."""
    execution_sources = _exact(manifest["execution_sources"], set(host_ids),
                               "Source5 source-root map for closure")
    for host in host_ids:
        source_root = _journal_absolute_path(
            execution_sources[host]["source_root"],
            f"Source5 {host} source root for typed closure",
        )
        require(source_root == request["source_root"],
                "Source5 peer source roots differ from the identity-mapped captured SourceRoot")

    selected_files = sources[host_ids[0]]["source"]["files"]
    for host in host_ids[1:]:
        require(sources[host]["source"]["files"] == selected_files,
                "Source5 host manifests do not preserve one identical typed source inventory")

    required: dict[str, tuple[str, str, int | None]] = {}

    def expect(path: str, role: str, raw_sha256: str,
               byte_count: int | None, label: str) -> None:
        _journal_absolute_path(path, f"{label} original path")
        _digest(raw_sha256, f"{label} raw SHA-256")
        wanted = (role, raw_sha256, byte_count)
        prior = required.get(path)
        require(prior is None or prior == wanted,
                f"Source5 typed closure aliases incompatible evidence roles at {path}")
        required[path] = wanted

    for record in selected_files:
        relative = _relative(record["path"], "Source5 typed source path")
        path = str(Path(request["source_root"]).joinpath(*relative.parts))
        role = ("typed_source_file" if record["kind"] == "file" else
                "typed_source_symlink")
        expect(path, role, record["sha256"], record["size"],
               f"Source5 typed source {record['path']}")

    for host in host_ids:
        for role, relative, raw_sha256 in _source5_manifest_artifact_pins(
                sources[host]):
            path = str(Path(request["source_root"]).joinpath(*
                            _relative(relative,
                                      "Source5 declared artifact path").parts))
            expect(path, role, raw_sha256, None,
                   f"Source5 {host} declared artifact {relative}")

    for path, (role, raw_sha256, size) in required.items():
        row = _source5_check_indexed_ref(
            store, index, role, path, raw_sha256,
            host_id=request["host_id"], semantic_sha256=None,
        )
        require(row["semantic_sha256"] is None,
                f"Source5 {role} row has an undeclared semantic digest: {path}")
        if size is not None:
            require(row["byte_count"] == size,
                    f"Source5 typed source size differs from its exact inventory: {path}")
        else:
            require(row["byte_count"] > 0,
                    f"Source5 declared artifact is empty: {path}")

    for record in selected_files:
        if record["kind"] != "symlink":
            continue
        symlink_path = str(Path(request["source_root"]).joinpath(*
                                _relative(record["path"],
                                          "Source5 symlink path").parts))
        literal, _literal_sha256 = _source5_evidence_bytes(
            store[symlink_path], "SourceV5 literal source symlink",
            MAX_SOURCE5_TYPED_SYMLINK_BYTES,
        )
        require(literal == record["target"].encode("utf-8"),
                "captured SourceV5 symlink bytes differ from its literal inventory target")

    # Only after every typed source and manifest-declared artifact has an exact
    # role/raw/size row may any indexed nested stream be consumed.
    for path in sorted(_source5_index_role_map(index)):
        entry = store[path]
        _source5_verify_evidence_bytes(
            entry, f"indexed Source5 {entry['role']} evidence",
        )


def _source5_journal_pin(value: object, fields: set[str], label: str) -> dict[str, Any]:
    pin = _exact(value, fields, label)
    _journal_absolute_path(pin["path"], f"{label} path")
    _digest(pin["raw_sha256"], f"{label} raw SHA-256")
    if "semantic_sha256" in fields:
        _digest(pin["semantic_sha256"], f"{label} semantic SHA-256")
    return pin


def _source5_journal_request(value: object) -> dict[str, Any]:
    request = _exact(value, {
        "schema", "scope", "campaign_id", "host_id", "source_root",
        "input_root", "output_root", "execution_manifest", "provenance",
        "journal", "origin_receipt", "evidence_index",
    }, "Source5 host-journal offline request")
    require(request["schema"] == SOURCE5_HOST_JOURNAL_REQUEST_SCHEMA_V1,
            "unsupported Source5 host-journal request schema")
    require(request["scope"] in {
        "prospective_exploration", "final_prepared", "final_prepared_bounded",
    }, "Source5 host-journal request has an unsupported frozen scope")
    _token(request["campaign_id"], "Source5 journal request campaign ID")
    _token(request["host_id"], "Source5 journal request host ID")
    for name in ("source_root", "input_root", "output_root"):
        _journal_absolute_path(request[name], f"Source5 journal request {name}")
    _source5_journal_pin(request["execution_manifest"], {
        "path", "raw_sha256", "semantic_sha256",
    }, "Source5 execution manifest pin")
    _source5_journal_pin(request["origin_receipt"], {
        "path", "raw_sha256", "semantic_sha256",
    }, "Source5 origin receipt pin")
    _source5_journal_pin(request["evidence_index"], {
        "path", "raw_sha256", "semantic_sha256",
    }, "Source5 evidence index pin")
    journal = _exact(request["journal"], {
        "path", "raw_sha256", "byte_count", "record_count", "terminal_head",
    }, "Source5 original journal pin")
    _journal_absolute_path(journal["path"], "Source5 journal path")
    _digest(journal["raw_sha256"], "Source5 journal raw SHA-256")
    _uint(journal["byte_count"], "Source5 journal byte count",
          maximum=(MAX_SOURCE5_JOURNAL_BYTES
                   if request["scope"] in {
                       "final_prepared", "final_prepared_bounded",
                   } else MAX_JOURNAL_BYTES))
    _uint(journal["record_count"], "Source5 journal record count",
          maximum=(MAX_SOURCE5_JOURNAL_EVENTS
                   if request["scope"] in {
                       "final_prepared", "final_prepared_bounded",
                   } else MAX_JOURNAL_EVENTS))
    _digest(journal["terminal_head"], "Source5 journal terminal head")
    chronology_dir = (Path(request["output_root"]) / request["campaign_id"] /
                      "chronology" / request["host_id"])
    require(journal["path"] == str(chronology_dir / "dispatch-journal.jsonl") and
            request["origin_receipt"]["path"] ==
                str(chronology_dir / "source5-origin-journal-receipt.json"),
            "Source5 journal/receipt paths differ from the exact locked host chronology directory")
    provenance = _exact(request["provenance"], {
        "schema", "preparation_pin", "final_spec_pin", "final_plan_pin",
    }, "Source5 journal original-generation provenance")
    require(provenance["schema"] == SOURCE5_JOURNAL_PROVENANCE_SCHEMA_V1,
            "Source5 journal provenance schema differs")
    for name in ("final_spec_pin", "final_plan_pin"):
        pin = _exact(provenance[name], {"path", "raw_sha256"},
                     f"Source5 journal provenance {name}")
        _journal_absolute_path(pin["path"], f"Source5 journal provenance {name} path")
        _digest(pin["raw_sha256"], f"Source5 journal provenance {name} raw SHA-256")
    preparation = provenance["preparation_pin"]
    if request["scope"] == "prospective_exploration":
        require(preparation is None,
                "prospective exploration request cannot bind a final preparation intent")
    else:
        preparation = _exact(preparation, {"path", "raw_sha256"},
                             "Source5 journal preparation provenance pin")
        _journal_absolute_path(preparation["path"],
                               "Source5 journal preparation provenance path")
        _digest(preparation["raw_sha256"],
                "Source5 journal preparation provenance raw SHA-256")
    return request


def _source5_journal_entry(
    store: dict[str, dict[str, Any]], path: str, role: str,
    host_id: str | None = None,
) -> dict[str, Any]:
    row = store.get(path)
    require(row is not None and row["role"] == role and
            (host_id is None or row["host_id"] == host_id),
            f"captured Source5 evidence omits the direct {role} role at {path}")
    return row


def _source5_semantic_document(
    row: dict[str, Any], store: dict[str, dict[str, Any]], label: str,
    maximum: int, self_field: str | None,
) -> tuple[dict[str, Any], bytes, str]:
    value, raw, raw_sha = _source5_read_canonical_evidence(
        store, row["origin_path"], label, maximum,
    )
    require(row["semantic_sha256"] is not None,
            f"captured {label} lacks its independently pinned semantic digest")
    semantic = (sha256_bytes(canonical_bytes({
        key: item for key, item in value.items() if key != self_field
    })) if self_field is not None else sha256_bytes(canonical_bytes(value)))
    require(semantic == row["semantic_sha256"],
            f"captured {label} semantic digest differs from its typed role")
    return value, raw, raw_sha


def _source5_execution_manifest_document(
    request: dict[str, Any], store: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], bytes, str]:
    pin = request["execution_manifest"]
    row = _source5_journal_entry(
        store, pin["path"], "execution_manifest", request["host_id"],
    )
    require(row["raw_sha256"] == pin["raw_sha256"] and
            row["semantic_sha256"] == pin["semantic_sha256"],
            "captured execution-manifest entry differs from its external pin")
    manifest, raw, raw_sha = _source5_read_canonical_evidence(
        store, pin["path"], "Source5 execution manifest", MAX_PLAN_BYTES,
    )
    base = {
        "schema", "campaign_id", "hosts", "original_inputs", "execution_sources",
        "modules", "observed_hosts", "artifact_root", "output_root", "phase_order",
        "protocol_sha256", "qualification_eligible", "manifest_sha256",
    }
    schema = manifest.get("schema")
    if schema == SOURCE5_EXECUTION_SCHEMA:
        _exact(manifest, base | {"capacity_completions"},
               "Source5 execution manifest v1")
        expected_scope = "prospective_exploration"
    elif schema == SOURCE5_EXECUTION_SCHEMA_V2:
        _exact(manifest, base | {
            "scope", "prepared_input_generation", "prepared_capacity_registration",
        }, "Source5 execution manifest v2")
        expected_scope = "final_prepared"
    elif schema == SOURCE5_EXECUTION_SCHEMA_V3:
        _exact(manifest, base | {
            "scope", "prepared_input_generation", "prepared_capacity_registration",
        }, "Source5 execution manifest v3")
        expected_scope = "final_prepared_bounded"
    else:
        raise ChronologyError("unsupported Source5 execution-manifest schema")
    semantic = sha256_bytes(canonical_bytes({
        key: value for key, value in manifest.items()
        if key != "manifest_sha256"
    }))
    require(raw_sha == pin["raw_sha256"] and
            manifest["manifest_sha256"] == pin["semantic_sha256"] == semantic and
            manifest["campaign_id"] == request["campaign_id"] and
            manifest["qualification_eligible"] is False and
            (schema == SOURCE5_EXECUTION_SCHEMA and
             request["scope"] == "prospective_exploration" or
             schema != SOURCE5_EXECUTION_SCHEMA and
             request["scope"] == expected_scope),
            "Source5 execution manifest raw/semantic/scope pins differ")
    _journal_absolute_path(manifest["artifact_root"],
                           "Source5 execution artifact root")
    _journal_absolute_path(manifest["output_root"],
                           "Source5 execution output root")
    require(manifest["output_root"] == request["output_root"] and
            manifest["phase_order"] == [
                "exploration", "aa", "confirmation", "fixed_analysis",
                "pressure", "pressure_analysis", "soak", "final_analysis",
            ], "Source5 execution manifest changed original roots/phase order")
    _digest(manifest["protocol_sha256"], "Source5 original protocol digest")
    return manifest, raw, raw_sha


def _source5_parse_cpu_set(value: object) -> list[int]:
    require(type(value) is str and value and " " not in value,
            "original CPU-set control is malformed")
    cpus: set[int] = set()
    for piece in value.split(","):
        parts = piece.split("-")
        require(len(parts) in {1, 2} and all(part.isdigit() for part in parts),
                "original CPU-set control has malformed ranges")
        start = int(parts[0])
        end = int(parts[-1])
        require(0 <= start <= end <= 65535 and end - start <= 65535,
                "original CPU-set range is outside its finite bound")
        cpus.update(range(start, end + 1))
    return sorted(cpus)


def _source5_rust_integer_constant(runtime_text: str, name: str) -> int:
    match = re.search(
        rf"\bconst\s+{re.escape(name)}\s*:\s*(?:u64|u32|u16|usize)\s*=\s*"
        rf"([0-9][0-9_]*(?:\s*\*\s*[0-9][0-9_]*)*)\s*;",
        runtime_text,
    )
    require(match is not None,
            f"typed SourceV5 runtime is missing capacity-floor numeric constant {name}")
    result = 1
    for piece in match.group(1).split("*"):
        value = piece.strip().replace("_", "")
        require(value.isdecimal(),
                f"typed SourceV5 capacity-floor constant {name} is not a literal product")
        result *= int(value)
    return result


def _source5_rust_string_constant(runtime_text: str, name: str) -> str:
    match = re.search(
        rf"\b(?:pub(?:\([^)]*\))?\s+)?const\s+{re.escape(name)}\s*:\s*&str\s*=\s*\"([^\"]+)\"\s*;",
        runtime_text,
    )
    require(match is not None,
            f"typed SourceV5 runtime is missing capacity-floor string constant {name}")
    return match.group(1)


def _source5_capacity_floor_descriptor(
    source: dict[str, Any], store: dict[str, dict[str, Any]],
    request: dict[str, Any],
) -> dict[str, Any]:
    relative = "bench/src/application/runtime_bindings.rs"
    records = source["source"]["files"]
    matches = [item for item in records
               if type(item) is dict and item.get("path") == relative]
    require(len(matches) == 1,
            "SourceV5 runtime inventory has no unique feedback policy source")
    record = _exact(matches[0], {
        "path", "kind", "mode", "sha256", "size",
    }, "SourceV5 runtime feedback policy source record")
    require(record["kind"] == "file" and record["mode"] in ("100644", "100755"),
            "SourceV5 runtime feedback policy source is not a regular file")
    path = str(Path(request["source_root"]).joinpath(*PurePosixPath(relative).parts))
    captured = _source5_journal_entry(
        store, path, "typed_source_file", request["host_id"],
    )
    require(captured["raw_sha256"] == record["sha256"] and
            captured["byte_count"] == record["size"] and
            captured["semantic_sha256"] is None,
            "captured runtime feedback policy source differs from its typed inventory")
    runtime_raw, _runtime_sha = _source5_evidence_bytes(
        captured, "SourceV5 runtime feedback policy source", MAX_SOURCE_BYTES,
    )
    try:
        runtime_text = runtime_raw.decode("utf-8", "strict")
    except UnicodeError as error:
        raise ChronologyError("SourceV5 runtime feedback policy source is not UTF-8") from error
    descriptor = {
        "capacity_divisor": _source5_rust_integer_constant(
            runtime_text, "CAPACITY_FLOOR_DIVISOR",
        ),
        "minimum_floor_bytes_per_second": _source5_rust_integer_constant(
            runtime_text, "CAPACITY_FLOOR_MINIMUM_BYTES_PER_SECOND",
        ),
        "policy_id": _source5_rust_string_constant(
            runtime_text, "CAPACITY_FLOOR_POLICY_ID",
        ),
        "probe_activation": _source5_rust_string_constant(
            runtime_text, "CAPACITY_FLOOR_PROBE_ACTIVATION",
        ),
        "rule": _source5_rust_string_constant(runtime_text, "CAPACITY_FLOOR_RULE"),
        "rule_version": _source5_rust_string_constant(
            runtime_text, "CAPACITY_FLOOR_RULE_VERSION",
        ),
        "runtime_activation": _source5_rust_string_constant(
            runtime_text, "CAPACITY_FLOOR_RUNTIME_ACTIVATION",
        ),
        "static_floor_bytes_per_second": _source5_rust_integer_constant(
            runtime_text, "FEEDBACK_RATE_FLOOR",
        ),
        "static_rate_roof_bytes_per_second": _source5_rust_integer_constant(
            runtime_text, "APPLICATION_RATE_CEILING_BYTES_PER_SECOND",
        ),
    }
    require(descriptor == {
        "capacity_divisor": 10,
        "minimum_floor_bytes_per_second": 1,
        "policy_id": CAPACITY_FLOOR_POLICY_ID,
        "probe_activation": "explicit_policy_id_and_capacity_artifact",
        "rule": "max_one_min_static_floor_capacity_div_ten",
        "rule_version": "application-feedback-capacity-resolution-v2",
        "runtime_activation": "explicit_pressure_qualification_and_policy_id_and_capacity_artifact",
        "static_floor_bytes_per_second": 64 * 1024 * 1024,
        "static_rate_roof_bytes_per_second": 16 * 1024**3,
    }, "SourceV5 Rust capacity-floor constants differ from the fixed source contract")
    return descriptor


def _source5_feedback_policy_artifact(
    source: dict[str, Any], selected_policy_id: str | None,
    floor_descriptor: dict[str, Any] | None, host_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    artifact = _exact(source.get("feedback_policy"), {
        "schema", "policy", "policy_sha256",
    }, f"SourceV5 {host_id} feedback policy artifact")
    body_keys = {
        "schema", "version", "reader_contract", "algorithm", "contexts", "source_pins",
    }
    if selected_policy_id is not None:
        body_keys.add("capacity_floor_policy")
    body = _exact(artifact["policy"], body_keys,
                  f"SourceV5 {host_id} feedback policy body")
    expected_schema = (
        SOURCE5_FEEDBACK_POLICY_ARTIFACT_SCHEMA_V2
        if selected_policy_id is not None else
        SOURCE5_FEEDBACK_POLICY_ARTIFACT_SCHEMA_V1
    )
    require(artifact["schema"] == body["schema"] == expected_schema and
            artifact["policy_sha256"] ==
                sha256_bytes(canonical_bytes(body)),
            f"SourceV5 {host_id} feedback policy schema or raw policy hash differs")
    require(body["version"] == "runtime-feedback-policy-v1",
            f"SourceV5 {host_id} feedback policy version differs")
    inventory = {item["path"]: item for item in source["source"]["files"]}
    source_pins = _exact(body["source_pins"], {
        "feedback_validator", "runtime_bindings", "runtime_policy", "runtime_sensor",
    }, f"SourceV5 {host_id} feedback policy source pins")
    expected_paths = {
        "feedback_validator": "scripts/application-feedback-readback.py",
        "runtime_bindings": "bench/src/application/runtime_bindings.rs",
        "runtime_policy": "crates/allocatbelt/src/runtime/resource_feedback_policy.rs",
        "runtime_sensor": "crates/allocatbelt/src/runtime/resource_feedback_sensor.rs",
    }
    harness = source.get("qualification_harness")
    require(type(harness) is dict,
            f"SourceV5 {host_id} feedback policy has no qualification harness")
    feedback_validator_pin = _exact(
        harness.get("feedback_validator"), {"path", "sha256"},
        f"SourceV5 {host_id} feedback validator harness pin",
    )
    for name, relative in expected_paths.items():
        pin = _exact(source_pins[name], {"path", "sha256"},
                     f"SourceV5 {host_id} feedback policy {name} pin")
        record = inventory.get(relative)
        require(pin["path"] == relative and type(record) is dict and
                record.get("kind") == "file" and record.get("sha256") ==
                    pin["sha256"],
                f"SourceV5 {host_id} feedback policy {name} pin differs from its typed source row")
    require(source_pins["feedback_validator"] == feedback_validator_pin,
            f"SourceV5 {host_id} feedback policy validator differs from its harness")
    if selected_policy_id is not None:
        descriptor = body["capacity_floor_policy"]
        require(type(floor_descriptor) is dict and descriptor == floor_descriptor and
                descriptor["policy_id"] == selected_policy_id ==
                    CAPACITY_FLOOR_POLICY_ID,
                f"SourceV5 {host_id} floor descriptor differs from its exact Rust constants/SpecV3 selector")
    else:
        require("capacity_floor_policy" not in body,
                f"SourceV5 {host_id} static policy unexpectedly publishes a selected floor")
    return artifact, body


def _source5_preparation_core_projection(
    spec: dict[str, Any], selected_policy_id: str | None,
) -> dict[str, Any]:
    keys = {
        "campaign_id", "runner_sha256", "hosts", "cells", "protocol",
        "runtime_binding", "phase_adapters", "aa_controls", "soak", "deadlines",
    }
    schema = (SOURCE5_PREPARATION_CORE_SCHEMA_V2
              if selected_policy_id is not None else
              SOURCE5_PREPARATION_CORE_SCHEMA_V1)
    require(selected_policy_id is None or
            selected_policy_id == CAPACITY_FLOOR_POLICY_ID,
            "SpecV3 selects an unknown capacity-floor policy ID")
    result = {"schema": schema, **{key: spec[key] for key in sorted(keys)}}
    if selected_policy_id is not None:
        result["capacity_floor_policy_id"] = selected_policy_id
    return result


def _source5_validate_selected_plan_templates(
    plan: dict[str, Any], source_documents: dict[str, dict[str, Any]],
    selected_policy_id: str, floor_descriptor: dict[str, Any],
) -> None:
    templates = plan.get("feedback_process_templates")
    host_ids = plan.get("host_ids")
    require(type(host_ids) is list and len(host_ids) == 3 and
            set(host_ids) == set(source_documents) and len(set(host_ids)) == 3,
            "selected PlanV3 host matrix differs from the three SourceV5 manifests")
    require(type(templates) is list and len(templates) == 720 and
            plan.get("feedback_process_templates_sha256") ==
                sha256_bytes(canonical_bytes(templates)),
            "selected SourceV5 PlanV3 feedback-template digest or matrix differs")
    capacity_templates = plan.get("capacity_process_templates")
    require(type(capacity_templates) is list and len(capacity_templates) == 45,
            "selected PlanV3 omits the original 45-entry capacity context matrix")
    capacity_bindings: dict[tuple[str, str, str], tuple[str, str]] = {}
    for index, value in enumerate(capacity_templates):
        key = _exact(value.get("capacity_key") if type(value) is dict else None, {
            "host_id", "workload", "profile", "calibration_id",
        }, f"selected PlanV3 capacity key[{index}]")
        host_id = _token(key["host_id"], f"selected PlanV3 capacity host[{index}]")
        matrix_key = (host_id, key["workload"], key["profile"])
        require(host_id in source_documents and matrix_key not in capacity_bindings,
                f"selected PlanV3 capacity context[{index}] is unknown or duplicated")
        condition_id = _token(value.get("pressure_condition_id"),
                              f"selected PlanV3 capacity pressure condition[{index}]")
        capacity_bindings[matrix_key] = (key["calibration_id"], condition_id)
    expected_contexts = {
        (workload, profile)
        for workload, profiles in (
            ("cpu", ("steady", "burst", "oversubscribed")),
            ("memory", ("steady", "burst", "oversubscribed")),
            ("http", ("steady", "burst", "oversubscribed")),
            ("disk", ("steady", "burst", "oversubscribed")),
            ("mixed", ("mixed", "burst", "oversubscribed")),
        )
        for profile in profiles
    }
    require(set(capacity_bindings) == {
        (host_id, workload, profile)
        for host_id in host_ids for workload, profile in expected_contexts
    }, "selected PlanV3 capacity contexts do not cover the original matrix")
    feedback_matrix: set[tuple[str, str, str, str, str, str]] = set()
    for index, value in enumerate(templates):
        item = _exact(value, {
            "identity", "nonce_scope", "nonce_instantiation_schema",
            "nonce_instantiation_rule", "policy", "required_proofs",
            "template_sha256",
        }, f"selected PlanV3 feedback template[{index}]")
        identity = _exact(item["identity"], {
            "campaign_id", "host_id", "workload", "profile",
            "comparison_family", "capacity_calibration_id",
            "pressure_condition_id", "allocator", "executor", "source_sha256",
            "binary_sha256", "fixed_policy_sha256", "feedback_policy_sha256",
            "context_policy_sha256", "prospective_nonce",
        }, f"selected PlanV3 feedback identity[{index}]")
        host_id = _token(identity["host_id"],
                         f"selected PlanV3 feedback host[{index}]")
        source = source_documents.get(host_id)
        require(source is not None,
                f"selected PlanV3 feedback template[{index}] names an unknown source host")
        require(identity["campaign_id"] == plan["campaign_id"] and
                identity["workload"] in {workload for workload, _profile in expected_contexts} and
                (identity["workload"], identity["profile"]) in expected_contexts and
                identity["allocator"] in (
                    "allocatbelt", "mimalloc-secure", "mimalloc-standard", "system",
                ) and identity["executor"] in ("allocatbelt", "tokio-1.53.1"),
                f"selected PlanV3 feedback template[{index}] identity is outside the original matrix")
        matrix_key = (host_id, identity["workload"], identity["profile"])
        require(matrix_key in capacity_bindings and
                identity["capacity_calibration_id"] == capacity_bindings[matrix_key][0],
                f"selected PlanV3 feedback template[{index}] does not bind its original capacity context")
        artifact = source["feedback_policy"]
        source_body = artifact["policy"]
        family = identity["comparison_family"]
        require(family in ("fixed_policy", "external_pressure"),
                f"selected PlanV3 feedback template[{index}] has an unknown family")
        if family == "fixed_policy":
            require(identity["pressure_condition_id"] is None,
                    f"selected PlanV3 fixed template[{index}] binds a pressure condition")
        else:
            require(identity["pressure_condition_id"] == capacity_bindings[matrix_key][1],
                    f"selected PlanV3 pressure template[{index}] changed its original pressure condition")
        policy_keys = {
            "version", "reader_contract", "algorithm", "context", "source_pins",
        }
        is_selected_pressure = family == "external_pressure"
        if is_selected_pressure:
            policy_keys.update({"capacity_floor_policy", "capacity_floor_policy_id"})
        policy = _exact(item["policy"], policy_keys,
                        f"selected PlanV3 feedback policy[{index}]")
        context_key = f"{identity['workload']}/{identity['profile']}"
        contexts = source_body.get("contexts")
        require(type(contexts) is dict and context_key in contexts,
                f"selected PlanV3 feedback template[{index}] has no SourceV5 context")
        expected_policy = {
            "version": source_body["version"],
            "reader_contract": source_body["reader_contract"],
            "algorithm": source_body["algorithm"],
            "context": contexts[context_key],
            "source_pins": source_body["source_pins"],
        }
        if is_selected_pressure:
            expected_policy["capacity_floor_policy"] = floor_descriptor
            expected_policy["capacity_floor_policy_id"] = selected_policy_id
        require(policy == expected_policy,
                f"selected PlanV3 feedback template[{index}] policy projection differs from SourceV5")
        expected_binary = source["artifacts"].get(identity["allocator"])
        require(type(expected_binary) is dict and
                identity["source_sha256"] == source["source"]["source_tree_sha256"] and
                identity["binary_sha256"] == expected_binary["sha256"] and
                identity["feedback_policy_sha256"] == artifact["policy_sha256"] and
                identity["fixed_policy_sha256"] == source["fixed_runtime_policy"]["policy_sha256"],
                f"selected PlanV3 feedback template[{index}] source/binary/policy pins differ")
        require(identity["context_policy_sha256"] ==
                sha256_bytes(canonical_bytes(expected_policy)),
                f"selected PlanV3 feedback template[{index}] context policy digest differs")
        feedback_matrix_key = (
            host_id, identity["workload"], identity["profile"], family,
            identity["allocator"], identity["executor"],
        )
        require(feedback_matrix_key not in feedback_matrix,
                f"selected PlanV3 feedback template[{index}] repeats an original process role")
        feedback_matrix.add(feedback_matrix_key)
        body = {key: child for key, child in item.items()
                if key != "template_sha256"}
        require(item["template_sha256"] ==
                sha256_bytes(canonical_bytes(body)),
                f"selected PlanV3 feedback template[{index}] self digest differs")
    expected_feedback_matrix = {
        (host_id, workload, profile, family, allocator, executor)
        for host_id in host_ids
        for workload, profile in expected_contexts
        for family in ("fixed_policy", "external_pressure")
        for allocator in ("allocatbelt", "mimalloc-secure", "mimalloc-standard", "system")
        for executor in ("allocatbelt", "tokio-1.53.1")
    }
    require(feedback_matrix == expected_feedback_matrix,
            "selected PlanV3 feedback templates do not cover the exact source/condition/allocator/executor matrix")


def _source5_validate_source_provenance(
    request: dict[str, Any], store: dict[str, dict[str, Any]],
    manifest: dict[str, Any], index: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, dict[str, Any]],
           dict[str, dict[str, Any]], dict[str, Any], dict[str, Any]]:
    provenance = request["provenance"]
    original = _exact(manifest.get("original_inputs"), {
        "spec", "plan", "source_manifests", "campaign_artifacts_root",
    }, "Source5 original execution inputs")
    spec_ref = _exact(original["spec"], {"artifact", "semantic_sha256"},
                      "Source5 original SpecV3 reference")
    plan_ref = _exact(original["plan"], {"artifact", "semantic_sha256"},
                      "Source5 original PlanV3 reference")
    spec_artifact = _exact(spec_ref["artifact"], {"path", "raw_sha256"},
                           "Source5 SpecV3 raw artifact pin")
    plan_artifact = _exact(plan_ref["artifact"], {"path", "raw_sha256"},
                           "Source5 PlanV3 raw artifact pin")
    _journal_absolute_path(spec_artifact["path"], "Source5 SpecV3 path")
    _journal_absolute_path(plan_artifact["path"], "Source5 PlanV3 path")
    for pin in (spec_artifact, plan_artifact):
        _digest(pin["raw_sha256"], "Source5 original SpecV3/PlanV3 raw SHA-256")
    require(provenance["final_spec_pin"] == spec_artifact and
            provenance["final_plan_pin"] == plan_artifact,
            "Source5 request provenance changed original SpecV3/PlanV3 raw pins")
    spec_row = _source5_journal_entry(
        store, spec_artifact["path"], "spec_v3",
    )
    plan_row = _source5_journal_entry(
        store, plan_artifact["path"], "plan_v3",
    )
    require(spec_row["raw_sha256"] == spec_artifact["raw_sha256"] and
            spec_row["semantic_sha256"] == spec_ref["semantic_sha256"] and
            plan_row["raw_sha256"] == plan_artifact["raw_sha256"],
            "captured SpecV3/PlanV3 evidence roles differ from execution-manifest pins")
    spec, spec_raw, spec_raw_sha = _source5_semantic_document(
        spec_row, store, "original SpecV3", MAX_SPEC_BYTES, None,
    )
    spec_semantic = sha256_bytes(canonical_bytes(spec))
    require(spec_raw_sha == spec_artifact["raw_sha256"] and
            spec_ref["semantic_sha256"] == spec_semantic and
            spec.get("schema") == SPEC_SCHEMA and
            spec.get("campaign_id") == request["campaign_id"] and
            spec.get("runner_sha256") is not None,
            "captured SpecV3 differs from its original raw/semantic/campaign pins")
    selected_floor_policy_id = spec.get("capacity_floor_policy_id")
    _exact(spec, {
        "schema", "campaign_id", "source_manifests", "runner_sha256", "hosts",
        "cells", "rates", "oracles", "protocol", "runtime_binding",
        "phase_adapters", "aa_controls", "soak", "deadlines",
        "qualification_inputs",
    } | ({"capacity_floor_policy_id"}
         if "capacity_floor_policy_id" in spec else set()),
       "captured original SpecV3")
    require(selected_floor_policy_id is None or
            selected_floor_policy_id == CAPACITY_FLOOR_POLICY_ID,
            "captured original SpecV3 selects an unknown capacity-floor policy ID")
    plan, plan_raw, plan_raw_sha = _source5_semantic_document(
        plan_row, store, "original PlanV3", MAX_PLAN_BYTES, "plan_sha256",
    )
    plan_semantic = plan_row["semantic_sha256"]
    require(plan_raw_sha == plan_artifact["raw_sha256"] and
            plan_ref["semantic_sha256"] == plan_semantic and
            plan.get("schema") == PLAN_SCHEMA and
            plan.get("campaign_id") == request["campaign_id"] and
            plan.get("spec_sha256") == spec_semantic and
            plan.get("plan_sha256") == plan_semantic and
            plan.get("execution_ready") is False and
            plan.get("full_gate_ready") is False,
            "captured PlanV3 differs from its original false-ready raw/semantic generation")
    _exact(plan, {
        "schema", "campaign_id", "spec_sha256", "source_manifests", "protocol",
        "runtime_binding", "execution_ready", "full_gate_ready", "full_gate_gaps",
        "host_ids", "cell_count", "jobs", "runtime_process_bindings",
        "capacity_process_templates", "capacity_process_templates_sha256",
        "feedback_process_templates", "feedback_process_templates_sha256",
        "campaign_inputs_module_sha256", "plan_sha256",
    }, "captured original PlanV3")
    require(Path(spec_artifact["path"]).parent == Path(request["input_root"]) and
            Path(plan_artifact["path"]).parent == Path(request["input_root"]),
            "Source5 request input root differs from the original SpecV3/PlanV3 generation")
    host_rows = spec.get("hosts")
    require(type(host_rows) is list and len(host_rows) == 3,
            "captured SpecV3 does not preserve the original three host order")
    host_ids = [item.get("host_id") for item in host_rows
                if type(item) is dict]
    require(len(host_ids) == 3 and all(type(item) is str for item in host_ids) and
            len(set(host_ids)) == 3 and host_ids == plan.get("host_ids") and
            host_ids == manifest.get("hosts") and request["host_id"] in host_ids,
            "captured SpecV3/PlanV3/manifest host order or selected host differs")
    require(manifest["phase_order"] == [
        "exploration", "aa", "confirmation", "fixed_analysis", "pressure",
        "pressure_analysis", "soak", "final_analysis",
    ] and manifest["protocol_sha256"] ==
        sha256_bytes(canonical_bytes(spec["protocol"])),
        "Source5 execution manifest changed the original phase/protocol generation")
    execution_sources = _exact(manifest["execution_sources"], set(host_ids),
                               "Source5 execution source map")
    for source_host in host_ids:
        source_snapshot = _exact(execution_sources[source_host], {
            "source_root", "git_commit", "source_tree_sha256", "build_sha256",
        }, f"Source5 {source_host} execution source snapshot")
        _journal_absolute_path(source_snapshot["source_root"],
                               f"Source5 {source_host} original source root")
        _digest(source_snapshot["source_tree_sha256"],
                f"Source5 {source_host} original source tree")
        _digest(source_snapshot["build_sha256"],
                f"Source5 {source_host} original build identity")
    require(execution_sources[request["host_id"]]["source_root"] ==
            request["source_root"],
            "Source5 request changes the selected host's original source-root identity")

    refs = spec.get("source_manifests")
    require(type(refs) is list and len(refs) == 3,
            "captured SpecV3 does not contain exactly three source-manifest pins")
    manifest_sources = _exact(original["source_manifests"], set(host_ids),
                              "Source5 original source-manifest map")
    source_documents: dict[str, dict[str, Any]] = {}
    source_raw_refs: dict[str, dict[str, Any]] = {}
    for position, ref_value in enumerate(refs):
        ref = _exact(ref_value, {"host_id", "relative_path", "sha256"},
                     f"SpecV3 source-manifest reference[{position}]")
        ref_host = _token(ref["host_id"], "SourceV5 manifest host ID")
        require(ref_host == host_ids[position],
                "SpecV3 source-manifest references changed original host order")
        relative = _relative(ref["relative_path"],
                             "SourceV5 source-manifest relative path")
        expected_path = str(Path(spec_artifact["path"]).parent.joinpath(*relative.parts))
        original_ref = _exact(manifest_sources[ref_host], {
            "artifact", "semantic_sha256",
        }, f"Source5 {ref_host} original source-manifest reference")
        original_artifact = _exact(original_ref["artifact"], {
            "path", "raw_sha256",
        }, f"Source5 {ref_host} source-manifest raw pin")
        require(original_artifact["path"] == expected_path and
                original_ref["semantic_sha256"] == ref["sha256"],
                f"Source5 {ref_host} manifest path/semantic pin differs from SpecV3")
        source_pin_row = _source5_journal_entry(
            store, expected_path, "source_manifest", ref_host,
        )
        require(source_pin_row["raw_sha256"] == original_artifact["raw_sha256"] and
                source_pin_row["semantic_sha256"] == original_ref["semantic_sha256"],
                f"captured SourceV5 {ref_host} manifest differs from execution provenance")
        source = _source5_source_manifest_document(store, source_pin_row)
        require(source["manifest_sha256"] == ref["sha256"],
                f"SourceV5 {ref_host} semantic manifest differs from SpecV3")
        source_documents[ref_host] = source
        source_raw_refs[ref_host] = {
            "host_id": ref_host, "path": expected_path,
            "raw_sha256": source_pin_row["raw_sha256"],
            "semantic_sha256": source["manifest_sha256"],
            "source_tree_sha256": source["source"]["source_tree_sha256"],
        }
    trees = {item["source_tree_sha256"] for item in source_raw_refs.values()}
    require(len(trees) == 1,
            "three SourceV5 host manifests do not bind one common source tree")
    _source5_validate_full_source_index_closure(
        request, manifest, source_documents, host_ids, index, store,
    )
    floor_descriptor = None
    if selected_floor_policy_id is not None:
        floor_descriptor = _source5_capacity_floor_descriptor(
            source_documents[request["host_id"]], store, request,
        )
    feedback_policy_hashes: set[str] = set()
    fixed_policy_hashes: set[str] = set()
    for source_host in host_ids:
        feedback_artifact, _feedback_body = _source5_feedback_policy_artifact(
            source_documents[source_host], selected_floor_policy_id,
            floor_descriptor, source_host,
        )
        feedback_policy_hashes.add(feedback_artifact["policy_sha256"])
        fixed_artifact = _exact(source_documents[source_host]["fixed_runtime_policy"], {
            "schema", "policy", "policy_sha256",
        }, f"SourceV5 {source_host} fixed runtime policy artifact")
        fixed_policy_hashes.add(_digest(
            fixed_artifact["policy_sha256"],
            f"SourceV5 {source_host} fixed runtime policy digest",
        ))
    require(len(feedback_policy_hashes) == len(fixed_policy_hashes) == 1,
            "SourceV5 host manifests do not share exact fixed and feedback policy hashes")
    runtime_binding = _exact(spec["runtime_binding"], {
        "resource_domain", "resource_policy_sha256", "feedback_policy_sha256",
        "feedback_match", "source_state",
    }, "original SpecV3 runtime policy binding")
    require(runtime_binding["feedback_policy_sha256"] ==
            next(iter(feedback_policy_hashes)) and
            runtime_binding["resource_policy_sha256"] ==
                next(iter(fixed_policy_hashes)),
            "SpecV3 runtime policy hashes do not bind the three SourceV5 policy artifacts")
    if selected_floor_policy_id is not None:
        _source5_validate_selected_plan_templates(
            plan, source_documents, selected_floor_policy_id, floor_descriptor,
        )
    plan_sources = plan.get("source_manifests")
    require(type(plan_sources) is dict and set(plan_sources) == set(host_ids) and
            all(plan_sources[host] == source_raw_refs[host]["semantic_sha256"]
                for host in host_ids),
            "PlanV3 SourceV5 semantic map differs from original manifests")

    source_root = request["source_root"]
    typed_by_host: dict[str, dict[str, dict[str, Any]]] = {}
    for ref_host in host_ids:
        typed_by_host[ref_host] = {
            item["path"]: item for item in source_documents[ref_host]["source"]["files"]
        }
    selected_rows = typed_by_host[request["host_id"]]
    expected_modules = {
        item["path"] for item in selected_rows.values()
        if item["kind"] == "file" and
        item["path"].startswith("scripts/") and
        PurePosixPath(item["path"]).suffix in {".py", ".sh"}
    }
    module_map = _exact(manifest["modules"], set(host_ids),
                        "Source5 execution module map")
    for source_host in host_ids:
        host_records = _exact(module_map[source_host], expected_modules,
                              f"Source5 {source_host} execution module pins")
        inventory_by_path = typed_by_host[source_host]
        for relative in expected_modules:
            pin = _exact(host_records[relative], {"path", "sha256"},
                         f"Source5 {source_host} module pin {relative}")
            require(pin == {"path": relative,
                            "sha256": inventory_by_path[relative]["sha256"]},
                    f"Source5 {source_host} module pin differs from typed inventory for {relative}")
    dependency_pins: list[dict[str, Any]] = []
    for role, relative in SOURCE5_JOURNAL_DEPENDENCY_ROLES:
        record = selected_rows.get(relative)
        require(record is not None,
                f"selected SourceV5 typed inventory lacks {role}")
        capture_path = str(Path(source_root).joinpath(*PurePosixPath(relative).parts))
        captured = _source5_journal_entry(
            store, capture_path, "typed_source_file", request["host_id"],
        )
        require(captured["raw_sha256"] == record["sha256"] and
                captured["byte_count"] == record["size"] and
                captured["semantic_sha256"] is None,
                f"captured SourceV5 {role} bytes differ from the selected typed inventory")
        for ref_host in host_ids:
            peer = typed_by_host[ref_host].get(relative)
            require(peer is not None and
                    (peer["sha256"], peer["mode"], peer["size"]) ==
                        (record["sha256"], record["mode"], record["size"]),
                    f"SourceV5 host {ref_host} captures a different {relative} generation")
        selected_module_map = module_map[request["host_id"]]
        require(selected_module_map.get(relative) == {
                    "path": relative, "sha256": record["sha256"],
                }, f"Source5 execution manifest module pin differs for {relative}")
        dependency_pins.append({
            "role": role, "path": relative, "raw_sha256": record["sha256"],
            "mode": record["mode"], "size": record["size"],
            "source_manifest_raw_sha256":
                source_raw_refs[request["host_id"]]["raw_sha256"],
            "source_manifest_semantic_sha256":
                source_raw_refs[request["host_id"]]["semantic_sha256"],
            "source_tree_sha256":
                source_raw_refs[request["host_id"]]["source_tree_sha256"],
        })
    dependency_pins.sort(key=lambda item: item["path"])

    observed_map = _exact(manifest["observed_hosts"], set(host_ids),
                          "Source5 observed-host map")
    observed_ref = _exact(observed_map[request["host_id"]], {"artifact"},
                          "Source5 selected observed-host reference")
    observed_pin = _exact(observed_ref["artifact"], {"path", "raw_sha256"},
                          "Source5 selected observed-host raw pin")
    observed_row = _source5_journal_entry(
        store, observed_pin["path"], "observed_host", request["host_id"],
    )
    require(observed_row["raw_sha256"] == observed_pin["raw_sha256"] and
            observed_row["semantic_sha256"] is None,
            "captured observed-host raw pin differs from the execution manifest")
    observed, observed_raw, observed_raw_sha = _source5_read_canonical_evidence(
        store, observed_pin["path"], "original observed host", MAX_MANIFEST_BYTES,
    )
    host_spec = next(item for item in host_rows
                     if item["host_id"] == request["host_id"])
    controls = _exact(host_spec.get("controls"), {
        "cpu_model", "microcode_sha256", "kernel_release", "governor",
        "frequency_policy", "boost_policy", "cpu_set", "numa_policy",
        "cgroup_policy_sha256", "background_load_policy_sha256",
        "x86_64_v3_capability_sha256", "target_triple", "target_cpu",
    }, "original SpecV3 selected-host controls")
    control_sha = sha256_bytes(canonical_bytes(controls))
    observed = _exact(observed, {
        "schema", "host_id", "boot_id_sha256", "controls_sha256", "controls",
        "kernel_release", "cpu_model", "cpu_affinity",
        "network_namespace_inode",
    }, "observed SourceV5 host context")
    require(observed_raw_sha == observed_pin["raw_sha256"] and
            observed["schema"] == "allocatbelt.application-capacity-host-context.v1" and
            observed["host_id"] == request["host_id"] and
            observed["controls"] == controls and
            observed["controls_sha256"] == control_sha ==
                host_spec.get("host_fingerprint_sha256") and
            observed["kernel_release"] == controls["kernel_release"] and
            observed["cpu_model"] == controls["cpu_model"],
            "observed SourceV5 host bytes differ from the original SpecV3 controls")
    _digest(observed["boot_id_sha256"], "observed SourceV5 boot identity")
    affinity = observed["cpu_affinity"]
    require(type(affinity) is list and 1 <= len(affinity) <= 4096 and
            affinity == sorted(set(affinity)) and
            all(type(cpu) is int and 0 <= cpu <= 65535 for cpu in affinity) and
            affinity == _source5_parse_cpu_set(controls["cpu_set"]),
            "observed SourceV5 host affinity differs from the original host controls")
    network_namespace = _uint(
        observed["network_namespace_inode"],
        "observed SourceV5 network namespace", positive=True,
    )
    observed_original = {
        "path": observed_pin["path"], "raw_sha256": observed_raw_sha,
        "boot_id_sha256": observed["boot_id_sha256"],
        "controls_sha256": observed["controls_sha256"],
        "controls": observed["controls"], "cpu_affinity": affinity,
        "network_namespace_inode": network_namespace,
    }
    pair_runner_record = selected_rows.get(PAIR_RUNNER_SOURCE_PATH)
    require(pair_runner_record is not None and
            spec.get("runner_sha256") == pair_runner_record["sha256"],
            "SpecV3 runner digest differs from its selected typed SourceV5 inventory")
    module_role_rows = []
    for role, relative in (
        ("campaign_controller", CONTROLLER_SOURCE_PATH),
        ("campaign_inputs", "scripts/application-campaign-inputs.py"),
        ("feedback_reader", "scripts/application-feedback-readback.py"),
        ("capacity_producer", "scripts/application-byte-capacity.py"),
    ):
        record = selected_rows.get(relative)
        require(record is not None,
                f"selected SourceV5 typed inventory lacks {role}")
        module_role_rows.append({"role": role, "path": relative,
                                 "sha256": record["sha256"]})

    original_pins = _validate_chronology_original_pins({
        "schema": CHRONOLOGY_SCHEMA,
        "campaign_id": request["campaign_id"],
        "host_id": request["host_id"],
        "spec": {"path": spec_artifact["path"], "raw_sha256": spec_raw_sha,
                 "semantic_sha256": spec_semantic},
        "plan": {"path": plan_artifact["path"], "raw_sha256": plan_raw_sha,
                 "semantic_sha256": plan_semantic},
        "source_manifests": [source_raw_refs[host] for host in host_ids],
        "observed_host": observed_original,
        "capacity_stage": {
            "path": CAPACITY_STAGE_SOURCE_PATH,
            "sha256": selected_rows[CAPACITY_STAGE_SOURCE_PATH]["sha256"],
        },
        "chronology_module": {
            "path": CHRONOLOGY_SOURCE_PATH,
            "sha256": selected_rows[CHRONOLOGY_SOURCE_PATH]["sha256"],
        },
        "pair_runner": {
            "path": PAIR_RUNNER_SOURCE_PATH,
            "sha256": pair_runner_record["sha256"],
        },
        "captured_modules": module_role_rows,
    })
    campaign_path = Path(source_root) / CONTROLLER_SOURCE_PATH
    campaign_entry = _source5_journal_entry(
        store, str(campaign_path), "typed_source_file", request["host_id"],
    )
    _campaign_raw, _campaign_sha = _source5_evidence_bytes(
        campaign_entry, "captured campaign controller module", MAX_SCRIPT_BYTES,
    )
    require(type(plan.get("jobs")) is dict,
            "original PlanV3 job schedule is malformed")

    # Validate the exact execution-manifest version/scope and its provenance.
    manifest_schema = manifest["schema"]
    if manifest_schema == SOURCE5_EXECUTION_SCHEMA:
        require(request["scope"] == "prospective_exploration" and
                provenance["preparation_pin"] is None and
                not spec.get("rates") and not spec.get("oracles"),
                "execution-manifest v1 is restricted to prospective exploration inputs")
    else:
        expected_generation_scope = (
            "final_prepared" if manifest_schema == SOURCE5_EXECUTION_SCHEMA_V2
            else "final_prepared_bounded"
        )
        require(manifest.get("scope") == expected_generation_scope and
                request["scope"] == expected_generation_scope and
                spec.get("rates") and spec.get("oracles"),
                "prepared Source5 execution manifest changed its exact frozen scope")
        generation = _exact(manifest["prepared_input_generation"], {
            "completion", "provenance",
        }, "Source5 prepared-input generation")
        generation_provenance = _exact(generation["provenance"], {
            "schema", "preparation_pin", "final_spec_pin", "final_plan_pin",
        }, "Source5 prepared-input generation provenance")
        require(generation_provenance["schema"] ==
                "allocatbelt.application-source5-prepared-inputs-provenance.v1" and
                provenance["preparation_pin"] == generation_provenance["preparation_pin"] and
                provenance["final_spec_pin"] == generation_provenance["final_spec_pin"] and
                provenance["final_plan_pin"] == generation_provenance["final_plan_pin"],
                "Source5 request provenance differs from its execution-manifest generation")
        completion_pin = _exact(generation["completion"], {
            "path", "raw_sha256", "semantic_sha256",
        }, "Source5 prepared-input completion pin")
        completion_row = _source5_journal_entry(
            store, completion_pin["path"], "prepared_completion",
        )
        require(completion_row["raw_sha256"] == completion_pin["raw_sha256"] and
                completion_row["semantic_sha256"] == completion_pin["semantic_sha256"],
                "captured prepared-input completion differs from its generation pin")
        completion, _completion_raw, completion_sha = _source5_semantic_document(
            completion_row, store, "Source5 prepared-input completion",
            MAX_COMPLETION_BYTES, "completion_sha256",
        )
        expected_completion_schema = (
            "allocatbelt.application-source5-preparation-completion.v2"
            if manifest_schema == SOURCE5_EXECUTION_SCHEMA_V3 else
            "allocatbelt.application-source5-preparation-completion.v1"
        )
        require(completion_sha == completion_pin["raw_sha256"] and
                completion["schema"] == expected_completion_schema and
                completion["complete"] is True and
                completion["qualification_eligible"] is False and
                completion["campaign_id"] == request["campaign_id"] and
                completion["completion_sha256"] == completion_pin["semantic_sha256"] and
                completion["final_spec"]["path"] == spec_artifact["path"] and
                completion["final_spec"]["raw_sha256"] == spec_artifact["raw_sha256"] and
                completion["final_spec"]["semantic_sha256"] == spec_semantic and
                completion["final_plan"]["path"] == plan_artifact["path"] and
                completion["final_plan"]["raw_sha256"] == plan_artifact["raw_sha256"] and
                completion["final_plan"]["semantic_sha256"] == plan_semantic,
                "prepared-input completion differs from its original final SpecV3/PlanV3")
        prep_pin = _exact(provenance["preparation_pin"], {
            "path", "raw_sha256",
        }, "Source5 preparation intent provenance")
        require(completion["preparation"]["path"] == prep_pin["path"] and
                completion["preparation"]["raw_sha256"] == prep_pin["raw_sha256"],
                "prepared-input completion changed its original preparation intent")
        prep_row = _source5_journal_entry(store, prep_pin["path"], "preparation")
        preparation, _preparation_raw, preparation_sha = \
            _source5_semantic_document(
                prep_row, store, "Source5 preparation intent",
                MAX_COMPLETION_BYTES, "preparation_sha256",
            )
        preparation = _exact(preparation, {
            "schema", "core", "source_pins", "observed_hosts",
            "capacity_templates", "condition_intensities", "deferred",
            "eligibility", "preparation_sha256",
        }, "Source5 original preparation intent")
        require(preparation_sha == prep_pin["raw_sha256"] and
                preparation["schema"] == SOURCE5_PREPARATION_SCHEMA_V1 and
                preparation["preparation_sha256"] ==
                    completion["preparation"]["semantic_sha256"] and
                preparation["eligibility"] == {
                    "capacity_evidence_complete": False,
                    "pressure_calibration_complete": False,
                    "rates_frozen": False, "oracles_frozen": False,
                    "confirmation_ready": False, "qualification_eligible": False,
                },
                "Source5 preparation raw/semantic/readiness differs from its completion")
        expected_preparation_core = _source5_preparation_core_projection(
            spec, selected_floor_policy_id,
        )
        require(preparation["core"] == expected_preparation_core,
                "Source5 preparation core differs from the exact final SpecV3 projection")
        preparation_source_pins = _exact(
            preparation["source_pins"], set(host_ids),
            "Source5 preparation source-manifest map",
        )
        spec_source_refs = {
            ref["host_id"]: ref for ref in spec["source_manifests"]
        }
        for source_host in host_ids:
            prep_source = _exact(preparation_source_pins[source_host], {
                "manifest", "modules", "artifacts",
            }, f"Source5 preparation {source_host} source pin")
            prep_manifest = _exact(prep_source["manifest"], {
                "relative_path", "raw_sha256", "semantic_sha256",
                "source_tree_sha256",
            }, f"Source5 preparation {source_host} manifest pin")
            source_ref = spec_source_refs[source_host]
            source_ref_record = source_raw_refs[source_host]
            require(prep_manifest == {
                "relative_path": source_ref["relative_path"],
                "raw_sha256": source_ref_record["raw_sha256"],
                "semantic_sha256": source_ref_record["semantic_sha256"],
                "source_tree_sha256": source_ref_record["source_tree_sha256"],
            }, f"Source5 preparation {source_host} pin differs from final SpecV3")
        if manifest_schema == SOURCE5_EXECUTION_SCHEMA_V3:
            require(type(completion.get("resource_budgets")) is dict and
                    set(completion["resource_budgets"]) == set(host_ids),
                    "bounded prepared-input completion omits its original per-host budgets")

    # The full component callback remains a later dispatcher responsibility.
    return (spec, plan, source_documents, source_raw_refs, observed_original,
            {"dependency_pins": dependency_pins, "original_pins": original_pins,
             "manifest": manifest})


def _source5_check_indexed_ref(
    store: dict[str, dict[str, Any]], index: dict[str, Any], role: str,
    path: str, raw_sha256: str, *, host_id: str | None = None,
    semantic_sha256: str | None = None,
) -> dict[str, Any]:
    row = _source5_journal_index_entry(
        index, role, path, raw_sha256, host_id=host_id,
        semantic_sha256=semantic_sha256,
    )
    captured = _source5_journal_entry(store, path, role, host_id)
    require(captured["raw_sha256"] == row["raw_sha256"] and
            captured["semantic_sha256"] == row["semantic_sha256"] and
            captured["byte_count"] == row["byte_count"],
            f"captured Source5 {role} evidence differs from its indexed path row")
    return row


def _source5_validate_origin_journal_receipt(
    request: dict[str, Any], index: dict[str, Any],
    store: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], bytes]:
    pin = request["origin_receipt"]
    require(pin["path"] not in _source5_index_role_map(index),
            "Source5 origin receipt cannot recursively appear inside its own evidence index")
    row = _source5_journal_entry(store, pin["path"], "origin_receipt",
                                 request["host_id"])
    require(row["raw_sha256"] == pin["raw_sha256"] and
            row["semantic_sha256"] == pin["semantic_sha256"],
            "Source5 origin receipt store row differs from its external pin")
    receipt, raw, raw_sha = _source5_read_canonical_evidence(
        store, pin["path"], "Source5 origin journal receipt", MAX_COMPLETION_BYTES,
    )
    fields = {
        "schema", "campaign_id", "host_id", "original_pins",
        "execution_manifest", "journal", "origin_facts",
        "captured_monotonic_ns", "dependency_pins", "evidence_index",
        "qualification_eligible", "execution_ready", "receipt_sha256",
    }
    _exact(receipt, fields, "Source5 origin journal receipt")
    body = {key: value for key, value in receipt.items()
            if key != "receipt_sha256"}
    semantic = sha256_bytes(canonical_bytes(body))
    require(receipt["schema"] == SOURCE5_ORIGIN_JOURNAL_RECEIPT_SCHEMA_V1 and
            receipt["campaign_id"] == request["campaign_id"] and
            receipt["host_id"] == request["host_id"] and
            receipt["qualification_eligible"] is False and
            receipt["execution_ready"] is False and
            receipt["receipt_sha256"] == pin["semantic_sha256"] == semantic and
            raw_sha == pin["raw_sha256"],
            "Source5 origin journal receipt schema, identity, digest, or eligibility differs")
    require(receipt["execution_manifest"] == request["execution_manifest"] and
            receipt["evidence_index"] == request["evidence_index"],
            "Source5 origin receipt changed execution-manifest or evidence-index raw/semantic pins")
    journal = _exact(receipt["journal"], {
        "path", "raw_sha256", "byte_count", "record_count", "terminal_head",
        "last_monotonic_ns",
    }, "Source5 origin receipt journal snapshot")
    expected_journal = request["journal"]
    require({key: journal[key] for key in (
                "path", "raw_sha256", "byte_count", "record_count", "terminal_head",
            )} == expected_journal,
            "Source5 origin receipt journal snapshot differs from the exact request pin")
    _uint(journal["last_monotonic_ns"],
          "Source5 origin last journal timestamp")
    captured_ns = _uint(receipt["captured_monotonic_ns"],
                        "Source5 origin receipt capture timestamp", positive=True)
    require(journal["last_monotonic_ns"] <= captured_ns,
            "Source5 origin journal timestamp exceeds the captured same-boot time ceiling")
    origin = _exact(receipt["origin_facts"], {
        "schema", "host_id", "observed_host_pin", "boot_id_sha256",
        "kernel_release", "cpu_model", "allowed_cpu_affinity",
        "network_namespace_inode", "controls_sha256", "controls", "before",
        "after", "origin_facts_sha256",
    }, "Source5 original host facts")
    origin_body = {key: value for key, value in origin.items()
                   if key != "origin_facts_sha256"}
    require(origin["schema"] ==
            "allocatbelt.application-source5-origin-journal-facts.v1" and
            origin["host_id"] == request["host_id"] and
            origin["origin_facts_sha256"] ==
                sha256_bytes(canonical_bytes(origin_body)),
            "Source5 origin host-facts schema or self-digest differs")
    _digest(origin["boot_id_sha256"], "Source5 origin boot ID digest")
    _digest(origin["controls_sha256"], "Source5 origin controls digest")
    _uint(origin["network_namespace_inode"],
          "Source5 origin network namespace inode", positive=True)
    require(type(origin["kernel_release"]) is str and origin["kernel_release"] and
            type(origin["cpu_model"]) is str and origin["cpu_model"] and
            type(origin["controls"]) is dict,
            "Source5 origin host controls or platform facts are malformed")
    affinity = origin["allowed_cpu_affinity"]
    require(type(affinity) is list and 1 <= len(affinity) <= 4096 and
            affinity == sorted(set(affinity)) and
            all(type(cpu) is int and 0 <= cpu <= 65535 for cpu in affinity),
            "Source5 origin affinity is malformed")
    for label in ("before", "after"):
        fact = _exact(origin[label], {
            "boot_id_sha256", "kernel_release", "cpu_model",
            "allowed_cpu_affinity", "network_namespace_inode",
            "observed_monotonic_ns",
        }, f"Source5 origin host {label} observation")
        require(fact["boot_id_sha256"] == origin["boot_id_sha256"] and
                fact["kernel_release"] == origin["kernel_release"] and
                fact["cpu_model"] == origin["cpu_model"] and
                fact["allowed_cpu_affinity"] == affinity and
                fact["network_namespace_inode"] == origin["network_namespace_inode"],
                f"Source5 origin host {label} observation changed its boot/platform identity")
        observed_ns = _uint(fact["observed_monotonic_ns"],
                            f"Source5 origin {label} monotonic time", positive=True)
        require(observed_ns <= captured_ns,
                f"Source5 origin {label} time exceeds its exact same-boot receipt bound")
    observed_pin = _exact(origin["observed_host_pin"], {
        "path", "raw_sha256",
    }, "Source5 origin observed-host pin")
    _journal_absolute_path(observed_pin["path"],
                           "Source5 origin observed-host path")
    _digest(observed_pin["raw_sha256"],
            "Source5 origin observed-host raw SHA-256")
    return receipt, raw


def _source5_validate_indexed_component_receipts(
    index: dict[str, Any], store: dict[str, dict[str, Any]], host_id: str,
) -> list[dict[str, str]]:
    accepted = {
        "allocatbelt.application-fixed-pair-host-verification.v1",
        "allocatbelt.application-pressure-pair-host-verification.v1",
        "allocatbelt.application-source5-soak-host-verification.v2",
    }
    result: list[dict[str, str]] = []
    for row in index["entries"]:
        if row["role"] != "component_receipt":
            continue
        require(row["host_id"] == host_id and
                row["semantic_sha256"] is not None,
                "Source5 strict component receipt lacks its exact selected-host semantic role")
        value, _raw, raw_sha = _source5_read_canonical_evidence(
            store, row["origin_path"], "Source5 strict component host receipt",
            MAX_PLAN_BYTES,
        )
        require(value.get("schema") in accepted and
                value.get("qualification_eligible") is False and
                value.get("execution_ready") is False and
                raw_sha == row["raw_sha256"],
                "Source5 strict component receipt has an unsupported schema, readiness claim, or raw digest")
        if value["schema"] == "allocatbelt.application-fixed-pair-host-verification.v1":
            _exact(value, {
                "schema", "strict_verified", "qualification_eligible",
                "execution_ready", "campaign_chronology_complete",
                "overlay_raw_sha256", "execution_receipt_raw_sha256",
                "execution_receipt_sha256", "status", "run_id",
                "host_verification", "receipt_sha256",
            }, "fixed-pair origin host receipt")
            digest_field = "receipt_sha256"
            require(value["strict_verified"] is True and
                    value["campaign_chronology_complete"] is False,
                    "fixed-pair origin receipt claims a non-source5 status")
            host_identity = _exact(value["host_verification"], {
                "schema", "host_id", "observed_host_raw_sha256",
                "process_affinity", "network_namespace_inode", "output_mount",
                "host_verification_sha256",
            }, "fixed-pair origin host identity")
            identity_body = {key: item for key, item in host_identity.items()
                             if key != "host_verification_sha256"}
            require(host_identity["schema"] ==
                    "allocatbelt.application-fixed-pair-host-verification-identity.v1" and
                    host_identity["host_id"] == host_id and
                    host_identity["host_verification_sha256"] ==
                        sha256_bytes(canonical_bytes(identity_body)),
                    "fixed-pair origin identity schema/host/self digest differs")
        elif value["schema"] == "allocatbelt.application-pressure-pair-host-verification.v1":
            _exact(value, {
                "schema", "campaign_id", "host_id", "job", "recipe",
                "readback", "source_manifest", "spec", "plan",
                "execution_manifest", "authorization_id", "journal_head",
                "registration_head", "observed_host", "origin_facts",
                "dependency_pins", "member_facts", "strict_result_sha256",
                "qualification_eligible", "execution_ready", "receipt_sha256",
            }, "pressure-pair origin host receipt")
            digest_field = "receipt_sha256"
            require(value["host_id"] == host_id and
                    type(value["member_facts"]) is list and
                    len(value["member_facts"]) == 2,
                    "pressure-pair origin receipt changes selected host/member count")
        else:
            _exact(value, {
                "schema", "campaign_id", "host_id", "run_id",
                "component_sha256", "component_pins", "generation",
                "prepared_host_context_pin", "fixed_spec_host_pin",
                "observed_host_pin", "prepared_host_binding_sha256",
                "helper_input_pin", "construction_probe", "pressure_origin",
                "origin_host", "process_absence", "tree_roots",
                "evidence_inventory", "evidence_bases", "readback_sha256",
                "bounded_execution_ready", "bounded_blockers",
                "qualification_eligible", "execution_ready", "receipt_sha256",
            }, "Source5 Soak origin host receipt")
            require(value["host_id"] == host_id and
                    type(value["run_id"]) is str and
                    type(value["component_pins"]) is dict and
                    value["bounded_execution_ready"] is False,
                    "Source5 Soak origin receipt changes selected host/run or bounded readiness")
            digest_field = "receipt_sha256"
        body = {key: item for key, item in value.items()
                if key != digest_field}
        semantic = sha256_bytes(canonical_bytes(body))
        require(value.get(digest_field) == row["semantic_sha256"] == semantic,
                "Source5 strict component host receipt semantic digest differs from its indexed role")
        result.append({
            "schema": "allocatbelt.application-source5-indexed-component-receipt.v1",
            "path": row["origin_path"], "raw_sha256": raw_sha,
            "semantic_sha256": semantic, "component_schema": value["schema"],
            "host_id": host_id, "run_id": value.get("run_id") or
                value.get("job", {}).get("run_id"),
        })
    return result


def _source5_validate_capacity_host_receipts(
    index: dict[str, Any], store: dict[str, dict[str, Any]], host_id: str,
) -> list[dict[str, str]]:
    schemas = {
        "allocatbelt.application-capacity-preparation-verification.v1",
        "allocatbelt.application-capacity-preparation-verification.v2",
    }
    result: list[dict[str, str]] = []
    for row in index["entries"]:
        if row["role"] != "capacity_host_receipt":
            continue
        require(row["host_id"] == host_id and row["semantic_sha256"] is not None,
                "capacity host-receipt index row lacks selected-host/raw-semantic identity")
        value, _raw, raw_sha = _source5_read_canonical_evidence(
            store, row["origin_path"], "Source5 capacity origin-host receipt",
            MAX_COMPLETION_BYTES,
        )
        require(value.get("schema") in schemas and
                value.get("host_id") == host_id and value.get("complete") is True and
                value.get("qualification_eligible") is False and
                value.get("controller_chronology_proven") is False and
                raw_sha == row["raw_sha256"],
                "Source5 capacity host receipt changed schema, host, readiness, or raw bytes")
        body = {key: item for key, item in value.items()
                if key != "receipt_sha256"}
        semantic = sha256_bytes(canonical_bytes(body))
        require(value.get("receipt_sha256") == row["semantic_sha256"] == semantic,
                "Source5 capacity host receipt semantic digest differs from its indexed role")
        result.append({
            "path": row["origin_path"], "raw_sha256": raw_sha,
            "semantic_sha256": semantic, "schema": value["schema"],
            "host_id": host_id,
        })
    return result


def _source5_validate_indexed_job_records(
    index: dict[str, Any], store: dict[str, dict[str, Any]],
    manifest: dict[str, Any], request: dict[str, Any],
    structural: dict[str, Any],
) -> list[dict[str, Any]]:
    by_job = {
        (row["phase"], row["job_run_id"]): row
        for row in structural["source5_finished"]
    }
    auth_by_job = {
        (row["phase"], row["job_run_id"]): row
        for row in structural["source5_authorizations"]
    }
    output_root = manifest["output_root"]
    result: list[dict[str, Any]] = []
    seen_jobs: set[tuple[str, str]] = set()
    for index_row in index["entries"]:
        if index_row["role"] != "source5_job_record":
            continue
        require(index_row["host_id"] == request["host_id"],
                "Source5 job-record index row belongs to another host")
        value, _raw, raw_sha = _source5_read_canonical_evidence(
            store, index_row["origin_path"], "Source5 immutable job record",
            MAX_EVENT_BYTES,
        )
        _exact(value, {
            "schema", "state", "job", "pair_directory", "process_metrics",
            "evidence", "chronology", "qualification_eligible", "record_sha256",
        }, "Source5 immutable job record")
        key = (value["job"].get("phase"), value["job"].get("run_id"))
        finished = by_job.get(key)
        authorization = auth_by_job.get(key)
        expected_path = str(Path(output_root) / request["campaign_id"] / "source5" /
                            request["host_id"] / key[0] / "job-records" /
                            f"{key[1]}.json") if all(type(item) is str and item
                            for item in key) else ""
        body = {field: item for field, item in value.items()
                if field != "record_sha256"}
        semantic = sha256_bytes(canonical_bytes(body))
        require(value["schema"] == SOURCE5_JOB_RECORD_SCHEMA and
                raw_sha == index_row["raw_sha256"] and
                semantic == value["record_sha256"] == index_row["semantic_sha256"] and
                value["qualification_eligible"] is False and
                key[0] in {"exploration", "aa", "confirmation", "pressure", "soak"} and
                finished is not None and authorization is not None and
                value["job"] == authorization["job"] and
                value["state"] == finished["job_terminal"]["state_claim"] and
                expected_path == index_row["origin_path"] and
                key not in seen_jobs,
                "Source5 job record differs from its unique original journal authorization/terminal/path")
        chronology = _exact(value["chronology"], {
            "authorization_id", "authorization_head", "app_started_heads",
            "app_terminal_heads", "job_terminal_head", "component_sha256",
            "process_metrics_sha256", "app_start_events", "app_terminal_events",
            "member_processes",
        }, "Source5 job record chronology projection")
        require(chronology["authorization_id"] == authorization["authorization_id"] and
                chronology["authorization_head"] == authorization["authorization_head"] and
                chronology["app_started_heads"] ==
                    [item["event_head"] for item in authorization["starts"]] and
                chronology["app_terminal_heads"] ==
                    [item["event_head"] for item in authorization["terminals"]] and
                chronology["app_start_events"] ==
                    [item["event_details"] for item in authorization["starts"]] and
                chronology["app_terminal_events"] ==
                    [item["event_details"] for item in authorization["terminals"]] and
                chronology["job_terminal_head"] == finished["job_terminal"]["event_head"] and
                chronology["component_sha256"] ==
                    finished["job_terminal"]["details"]["component_sha256"] and
                chronology["process_metrics_sha256"] ==
                    finished["job_terminal"]["details"]["process_metrics_sha256"] and
                finished["job_terminal"]["details"]["process_metrics_sha256"] ==
                    sha256_bytes(canonical_bytes(value["process_metrics"])) and
                value["process_metrics"] is not None and
                chronology["member_processes"] == [
                    {"descriptor": item["descriptor"], "pid": item["proof"]["pid"],
                     "start_ticks": item["proof"]["start_ticks"],
                     "member_index": index}
                    for index, item in enumerate(authorization["starts"])
                ],
                "Source5 immutable job record differs from its exact authorization callbacks/terminal metrics")
        result.append({
            "path": index_row["origin_path"], "raw_sha256": raw_sha,
            "semantic_sha256": semantic, "phase": key[0], "job_run_id": key[1],
            "job_index": authorization["job_index"],
            "authorization_id": authorization["authorization_id"],
            "authorization_head": authorization["authorization_head"],
            "job_terminal_head": finished["job_terminal"]["event_head"],
            "component_sha256": finished["job_terminal"]["details"]["component_sha256"],
            "process_metrics_sha256": finished["job_terminal"]["details"]["process_metrics_sha256"],
            "record": value,
        })
        seen_jobs.add(key)
    return result


def _source5_replay_journal_entry(
    row: dict[str, Any], original_pins: dict[str, Any], request: dict[str, Any],
    boot_id_sha256: str, *, maximum_events: int, maximum_bytes: int,
) -> dict[str, Any]:
    require(row["role"] == "journal" and
            row["origin_path"] == request["journal"]["path"] and
            row["raw_sha256"] == request["journal"]["raw_sha256"] and
            row["byte_count"] == request["journal"]["byte_count"],
            "Source5 captured journal row differs from the exact host request pin")
    stats: dict[str, Any] = {}
    records = _iter_captured_journal_stream(
        row["raw_bytes"], row["byte_count"], original_pins,
        request["campaign_id"], request["host_id"], boot_id_sha256, stats,
        maximum_events=maximum_events, maximum_bytes=maximum_bytes,
    ) if type(row["raw_bytes"]) is not bytes else _iter_journal_records_from_chunks(
        (row["raw_bytes"][offset:offset + 1024 * 1024]
         for offset in range(0, len(row["raw_bytes"]), 1024 * 1024)),
        original_pins, request["campaign_id"], request["host_id"],
        boot_id_sha256, stats, expected_byte_count=row["byte_count"],
        maximum_events=maximum_events, maximum_bytes=maximum_bytes,
    )
    structural = _journal_structural_index(
        records, request["campaign_id"], request["host_id"],
        sha256_bytes(canonical_bytes(original_pins)),
    )
    require(stats.get("raw_sha256") == request["journal"]["raw_sha256"] and
            stats.get("byte_count") == request["journal"]["byte_count"] and
            stats.get("record_count") == request["journal"]["record_count"] and
            stats.get("terminal_head") == request["journal"]["terminal_head"],
            "Source5 raw journal bytes do not replay to the exact pinned count/head")
    structural.update({
        "journal_raw_sha256": stats["raw_sha256"],
        "journal_byte_count": stats["byte_count"],
        "last_monotonic_ns": stats["last_monotonic_ns"],
        "journal_chain_replayed": True,
        "component_dispatch_pending": True,
        "qualification_eligible": False,
        "execution_ready": False,
        "analysis_results_replayed": False,
        "component_results_replayed": False,
    })
    return structural


def _source5_validate_authorization_inputs(
    request: dict[str, Any], manifest: dict[str, Any],
    spec: dict[str, Any], plan: dict[str, Any],
    source_documents: dict[str, dict[str, Any]],
    structural: dict[str, Any], index: dict[str, Any],
    store: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Bind each journal authorization to the exact frozen plan/helper input."""
    source_rows = {
        item["path"]: item
        for item in source_documents[request["host_id"]]["source"]["files"]
    }
    module_map = manifest["modules"][request["host_id"]]
    helper_roles = {
        "exploration": ("scripts/application-fixed-pair.py", "run_fixed_pair_overlay"),
        "aa": ("scripts/application-fixed-pair.py", "run_fixed_pair_overlay"),
        "confirmation": ("scripts/application-fixed-pair.py", "run_fixed_pair_overlay"),
        "pressure": ("scripts/application-pressure-pair.py", "run_pressure_pair_locked"),
        "soak": ("scripts/application-source5-soak.py", "run_source5_soak"),
    }
    required_prerequisites = {
        "exploration": (),
        "aa": ("exploration",),
        "confirmation": ("exploration", "aa"),
        "pressure": ("fixed_analysis",),
        "soak": ("pressure_analysis",),
    }
    registration_rows = structural["registrations"]
    registration = next((row for row in reversed(registration_rows)
                         if row["event"] in {
                             "capacity_registered",
                             "source5_prepared_capacity_registered",
                         }), None)
    require(registration is not None,
            "Source5 authorization journal has no completed 15-entry registration")
    registration_details = registration["details"]
    result: list[dict[str, Any]] = []
    for auth in structural["source5_authorizations"]:
        phase = auth["phase"]
        host_jobs = [job for job in plan["jobs"].get(phase, [])
                     if type(job) is dict and job.get("host_id") == request["host_id"]]
        require(auth["job_index"] < len(host_jobs) and
                host_jobs[auth["job_index"]] == auth["job"],
                "Source5 authorization does not match the exact original host job index/order")
        require(auth["job_sha256"] ==
                sha256_bytes(canonical_bytes(auth["job"])) and
                auth["members_sha256"] ==
                sha256_bytes(canonical_bytes(auth["members"])) and
                auth["execution_manifest"] == {
                    "path": request["execution_manifest"]["path"],
                    "raw_sha256": request["execution_manifest"]["raw_sha256"],
                },
                "Source5 authorization job/member/manifest pins differ from original inputs")
        helper_pin = _exact(auth["helper_input"], {"path", "raw_sha256"},
                            "Source5 authorized helper-input pin")
        _journal_absolute_path(helper_pin["path"],
                               "Source5 authorized helper-input path")
        _digest(helper_pin["raw_sha256"],
                "Source5 authorized helper-input raw SHA-256")
        _source5_check_indexed_ref(
            store, index, "source5_helper_input", helper_pin["path"],
            helper_pin["raw_sha256"], host_id=request["host_id"],
            semantic_sha256=None,
        )
        helper_entry = _source5_journal_entry(
            store, helper_pin["path"], "source5_helper_input", request["host_id"],
        )
        helper_raw, helper_raw_sha = _source5_evidence_bytes(
            helper_entry, "authorized Source5 helper input", MAX_PLAN_BYTES,
        )
        helper_input = _parse_object(
            helper_raw, "authorized Source5 helper input", MAX_PLAN_BYTES,
        )
        _exact(helper_input, {
            "schema", "scope", "campaign_id", "host_id", "phase", "job_index",
            "job", "job_sha256", "members", "helper", "payload",
            "prerequisites", "outer_deadline_seconds",
            "effective_timeout_seconds", "input_snapshot_sha256",
            "qualification_eligible",
        }, "Source5 authorized helper input")
        input_body = _source5_input_body(helper_input)
        input_sha = sha256_bytes(canonical_bytes(input_body))
        expected_scope = ("prospective_exploration" if request["scope"] ==
                          "prospective_exploration" else "final_frozen")
        require(helper_raw_sha == helper_pin["raw_sha256"] and
                helper_input["schema"] == SOURCE5_HELPER_INPUT_SCHEMA and
                helper_input["scope"] == expected_scope and
                helper_input["campaign_id"] == request["campaign_id"] and
                helper_input["host_id"] == request["host_id"] and
                helper_input["phase"] == phase and
                helper_input["job_index"] == auth["job_index"] and
                helper_input["job"] == auth["job"] and
                helper_input["job_sha256"] == auth["job_sha256"] and
                helper_input["members"] == auth["members"] and
                helper_input["prerequisites"] == auth["prerequisites"] and
                helper_input["outer_deadline_seconds"] == auth["outer_deadline_seconds"] and
                helper_input["effective_timeout_seconds"] == auth["effective_timeout_seconds"] and
                helper_input["input_snapshot_sha256"] == auth["input_snapshot_sha256"] ==
                    input_sha and
                helper_input["qualification_eligible"] is False,
                "Source5 helper input differs from its exact durable authorization projection")
        require(Path(helper_pin["path"]).is_relative_to(Path(manifest["artifact_root"])),
                "Source5 authorized helper input is outside its original artifact root")
        if expected_scope == "prospective_exploration":
            require(phase == "exploration" and not spec.get("rates") and
                    not spec.get("oracles"),
                    "prospective Source5 scope is not exploration-only")
        else:
            require(spec.get("rates") and spec.get("oracles"),
                    "final Source5 scope lost original rates/oracles")
        expected_helper_path, expected_entrypoint = helper_roles[phase]
        helper_ref = _exact(helper_input["helper"], {
            "path", "sha256", "entrypoint",
        }, "Source5 helper module reference")
        helper_module = _exact(auth["helper_module"], {
            "path", "sha256", "size", "mode", "kind",
        }, "Source5 authorized typed helper module")
        typed_helper = source_rows.get(expected_helper_path)
        require(helper_ref["path"] == helper_module["path"] == expected_helper_path and
                helper_ref["sha256"] == helper_module["sha256"] and
                helper_ref["entrypoint"] == expected_entrypoint and
                typed_helper == helper_module and
                helper_module["kind"] == "file" and
                helper_module["mode"] in {"100644", "100755"} and
                module_map.get(expected_helper_path) == {
                    "path": expected_helper_path,
                    "sha256": helper_module["sha256"],
                },
                "Source5 authorization helper path/entrypoint differs from its typed source role")
        deadline_name = "soak_outer_seconds" if phase == "soak" else "outer_seconds"
        outer_deadline = spec["deadlines"].get(deadline_name)
        require(type(outer_deadline) is int and outer_deadline > 0 and
                auth["outer_deadline_seconds"] == outer_deadline and
                0 < auth["effective_timeout_seconds"] <= outer_deadline,
                "Source5 authorization exceeds or changes the original phase deadline")
        expected_prereq = required_prerequisites[phase]
        require(type(auth["prerequisites"]) is list and
                len(auth["prerequisites"]) == len(expected_prereq),
                "Source5 authorization prerequisite list has a wrong phase count")
        for position, (prerequisite, expected_phase) in enumerate(zip(
                auth["prerequisites"], expected_prereq, strict=True)):
            pin = _exact(prerequisite, {
                "phase", "analysis", "analysis_sha256", "event_head",
            }, f"Source5 authorization prerequisite[{position}]")
            analysis_pin = _exact(pin["analysis"], {"path", "raw_sha256"},
                                  "Source5 prerequisite analysis raw pin")
            analysis_event = structural["source5_analyses"].get(expected_phase)
            analysis_rows = [event for event in structural["events"]
                             if event["event"] == "source5_analysis" and
                             event["phase"] == expected_phase]
            require(pin["phase"] == expected_phase and
                    analysis_event is not None and len(analysis_rows) == 1 and
                    analysis_event["analysis"] == analysis_pin and
                    analysis_event["analysis_sha256"] == pin["analysis_sha256"] and
                    analysis_event["event_head"] == pin["event_head"] and
                    analysis_event["phase_gate_claimed"] is True and
                    analysis_event["numeric_gates_claimed"] is True and
                    analysis_rows[0]["sequence"] < auth["authorization_record_count"],
                    "Source5 authorization prerequisite is not the exact earlier claimed analysis event")

        output_path = _journal_absolute_path(auth["output_root"],
                                             "Source5 authorized job output root")
        artifact_root = Path(manifest["artifact_root"])
        output_root = Path(output_path)
        require(output_root.is_relative_to(artifact_root) and
                not output_root.is_relative_to(Path(request["source_root"])) and
                not output_root.is_relative_to(Path(request["input_root"])),
                "Source5 authorized output root is outside the original artifact boundary")
        payload = helper_input["payload"]
        require(type(payload) is dict,
                "Source5 authorization helper payload is not a closed object")
        references: list[dict[str, Any]] = []

        def payload_ref(role: str, pin_value: object, raw_name: str,
                        label: str, semantic_name: str | None = None,
                        allowed_roots: tuple[Path, ...] | None = None) -> dict[str, Any]:
            fields = {"path", raw_name}
            if semantic_name is not None:
                fields.add(semantic_name)
            pin = _exact(pin_value, fields, label)
            path = _journal_absolute_path(pin["path"], f"{label} path")
            raw_sha = _digest(pin[raw_name], f"{label} raw SHA-256")
            semantic_sha = (_digest(pin[semantic_name], f"{label} semantic SHA-256")
                            if semantic_name is not None else None)
            roots = allowed_roots or (artifact_root,)
            require(any(Path(path).is_relative_to(root) for root in roots),
                    f"{label} path is outside its original private evidence roots")
            references.append({
                "role": role, "path": path, "raw_sha256": raw_sha,
                "semantic_sha256": semantic_sha,
                "host_id": request["host_id"],
            })
            return pin

        if phase in {"exploration", "aa", "confirmation"}:
            _exact(payload, {"overlay_pin"},
                   "Source5 fixed helper payload")
            overlay_pin = payload_ref(
                "fixed_pair_artifact", payload["overlay_pin"],
                "sha256", "Source5 fixed overlay pin",
            )
            overlay_entry = _source5_journal_entry(
                store, overlay_pin["path"], "fixed_pair_artifact",
                request["host_id"],
            )
            overlay_raw, _overlay_raw_sha = _source5_evidence_bytes(
                overlay_entry, "Source5 authorized fixed overlay", MAX_PLAN_BYTES,
            )
            overlay = _parse_object(overlay_raw,
                                    "Source5 authorized fixed overlay",
                                    MAX_PLAN_BYTES)
            overlay_material = {key: value for key, value in overlay.items()
                                if key != "overlay_sha256"}
            overlay_semantic = sha256_bytes(canonical_bytes(overlay_material))
            require(overlay.get("overlay_sha256") == overlay_semantic,
                    "Source5 fixed overlay semantic digest differs from its original bytes")
            references[-1]["semantic_sha256"] = overlay_semantic
        elif phase == "pressure":
            bounded_pressure = manifest["schema"] == SOURCE5_EXECUTION_SCHEMA_V3
            expected_keys = ({"schema", "recipe_pin", "output_root",
                              "probe_capture_bundle"} if bounded_pressure else
                             {"recipe_pin", "output_root"})
            _exact(payload, expected_keys, "Source5 pressure helper payload")
            require(payload["output_root"] == output_path,
                    "Source5 pressure payload output root differs from its authorization")
            recipe_pin = payload_ref(
                "pressure_pair_artifact", payload["recipe_pin"],
                "raw_sha256", "Source5 pressure recipe pin",
            )
            recipe_entry = _source5_journal_entry(
                store, recipe_pin["path"], "pressure_pair_artifact",
                request["host_id"],
            )
            require(recipe_entry["raw_sha256"] == recipe_pin["raw_sha256"],
                    "Source5 pressure recipe indexed raw digest differs")
            recipe_raw, _recipe_raw_sha = _source5_evidence_bytes(
                recipe_entry, "Source5 pressure recipe", MAX_PLAN_BYTES,
            )
            recipe = _parse_object(recipe_raw, "Source5 pressure recipe",
                                    MAX_PLAN_BYTES)
            recipe_body = {key: value for key, value in recipe.items()
                           if key != "recipe_sha256"}
            recipe_semantic = sha256_bytes(canonical_bytes(recipe_body))
            require(recipe.get("recipe_sha256") == recipe_semantic,
                    "Source5 pressure recipe semantic digest differs from its original bytes")
            references[-1]["semantic_sha256"] = recipe_semantic
            if bounded_pressure:
                require(payload["schema"] == SOURCE5_PRESSURE_HELPER_PAYLOAD_SCHEMA_V2 and
                        recipe.get("schema") == SOURCE5_PRESSURE_RECIPE_SCHEMA_V2,
                        "bounded pressure authorization changed its exact v2 schemas")
                bundle = _exact(payload["probe_capture_bundle"], {
                    "schema", "members",
                }, "Source5 ProbeV2 capture bundle")
                require(bundle["schema"] == SOURCE5_PROBE_CAPTURE_BUNDLE_SCHEMA and
                        type(bundle["members"]) is list and
                        len(bundle["members"]) == 2 and
                        type(recipe.get("members")) is list and
                        len(recipe["members"]) == 2,
                        "Source5 bounded pressure bundle/recipe does not retain its two original members")
                for ordinal, bundle_member_value in enumerate(bundle["members"]):
                    member = _exact(bundle_member_value, {
                        "ordinal", "construction_probe", "capture_receipt",
                        "capacity_bundle",
                    }, f"Source5 ProbeV2 capture member[{ordinal}]")
                    require(member["ordinal"] == ordinal,
                            "Source5 ProbeV2 capture bundle reordered its original pair")
                    probe = _exact(member["construction_probe"], {
                        "path", "raw_sha256", "allocator", "binary_sha256",
                    }, f"Source5 ProbeV2 construction probe[{ordinal}]")
                    expected_probe = _exact(
                        recipe["members"][ordinal].get("construction_probe"), {
                            "path", "raw_sha256", "allocator", "binary_sha256",
                        }, f"Source5 pressure recipe construction probe[{ordinal}]",
                    )
                    require(probe == expected_probe,
                            "Source5 ProbeV2 construction probe differs from its exact recipe member")
                    payload_ref("pressure_pair_artifact", {
                                    "path": probe["path"],
                                    "raw_sha256": probe["raw_sha256"],
                                },
                                "raw_sha256",
                                f"Source5 ProbeV2 construction probe[{ordinal}]",
                                allowed_roots=(artifact_root, output_root))
                    capture_pin = payload_ref(
                        "pressure_pair_artifact", member["capture_receipt"],
                        "raw_sha256",
                        f"Source5 ProbeV2 capture receipt[{ordinal}]",
                        semantic_name="receipt_sha256",
                        allowed_roots=(artifact_root, output_root),
                    )
                    capacity_bundle = _exact(member["capacity_bundle"], {
                        "request", "artifact", "receipt",
                    }, f"Source5 ProbeV2 capacity bundle[{ordinal}]")
                    require(capacity_bundle == recipe.get("capacity_bundle"),
                            "Source5 ProbeV2 capacity bundle differs from its exact recipe family")
                    for name in ("request", "artifact", "receipt"):
                        payload_ref(
                            f"capacity_{name}", capacity_bundle[name],
                            "raw_sha256", f"Source5 ProbeV2 capacity {name}[{ordinal}]",
                            allowed_roots=(artifact_root, Path(request["input_root"]),
                                           Path(request["output_root"])),
                        )
            else:
                require(payload["output_root"] == output_path,
                        "Source5 pressure output root differs from the exact authorization")
        else:
            _exact(payload, {
                "materials_index", "output_root", "prepared_host_binding_sha256",
            }, "Source5 Soak helper payload")
            require(payload["output_root"] == output_path,
                    "Source5 Soak output root differs from the exact authorization")
            materials_pin = payload_ref(
                "source5_soak_artifact", payload["materials_index"],
                "raw_sha256", "Source5 Soak materials-index pin",
            )
            materials_entry = _source5_journal_entry(
                store, materials_pin["path"], "source5_soak_artifact",
                request["host_id"],
            )
            materials_raw, _materials_raw_sha = _source5_evidence_bytes(
                materials_entry, "Source5 Soak materials index", MAX_PLAN_BYTES,
            )
            materials = _parse_object(
                materials_raw, "Source5 Soak materials index", MAX_PLAN_BYTES,
            )
            materials_body = {key: value for key, value in materials.items()
                              if key != "materials_sha256"}
            materials_semantic = sha256_bytes(canonical_bytes(materials_body))
            _exact(materials, {
                "schema", "campaign_id", "host_id", "job", "job_sha256",
                "parent_recipe", "build_receipt",
                "prepared_host_binding_sha256", "materials_sha256",
            }, "Source5 Soak materials index")
            require(materials["schema"] ==
                    "allocatbelt.application-source5-soak-materials-index.v1" and
                    materials["campaign_id"] == request["campaign_id"] and
                    materials["host_id"] == request["host_id"] and
                    materials["job"] == auth["job"] and
                    materials["job_sha256"] == auth["job_sha256"] and
                    materials["prepared_host_binding_sha256"] ==
                        payload["prepared_host_binding_sha256"] and
                    materials["materials_sha256"] == materials_semantic,
                    "Source5 Soak materials index does not bind its exact original authorization")
            references[-1]["semantic_sha256"] = materials_semantic
            payload_ref("source5_soak_artifact", materials["parent_recipe"],
                        "raw_sha256", "Source5 Soak parent recipe pin")
            parent_pin = materials["parent_recipe"]
            parent_entry = _source5_journal_entry(
                store, parent_pin["path"], "source5_soak_artifact",
                request["host_id"],
            )
            parent_raw, _parent_raw_sha = _source5_evidence_bytes(
                parent_entry, "Source5 Soak parent recipe", MAX_PLAN_BYTES,
            )
            parent_recipe = _parse_object(
                parent_raw, "Source5 Soak parent recipe", MAX_PLAN_BYTES,
            )
            parent_semantic = sha256_bytes(canonical_bytes({
                key: value for key, value in parent_recipe.items()
                if key != "recipe_sha256"
            }))
            require(parent_recipe.get("recipe_sha256") == parent_semantic,
                    "Source5 Soak parent recipe semantic digest differs from its original bytes")
            references[-1]["semantic_sha256"] = parent_semantic
            payload_ref("source5_soak_artifact", materials["build_receipt"],
                        "raw_sha256", "Source5 Soak recipe-build receipt pin")

        if manifest["schema"] == SOURCE5_EXECUTION_SCHEMA:
            registration_capacity = manifest["capacity_completions"][request["host_id"]]
            require(registration["event"] == "capacity_registered" and
                    auth["capacity_completion"] == {
                        "path": registration_details["capacity_completion"]["path"],
                        "raw_sha256": registration_details["capacity_completion"]["sha256"],
                    } == registration_capacity["artifact"] and
                    auth["capacity_ledger_raw_sha256"] ==
                        registration_details["capacity_ledger"]["raw_sha256"] ==
                        registration_capacity["ledger_raw_sha256"] and
                    auth["capacity_terminal_head"] ==
                        registration_details["capacity_ledger"]["terminal_head"] ==
                        registration_capacity["terminal_head"] and
                    auth["capacity_schedule_sha256"] ==
                        registration_details["capacity_schedule_sha256"] ==
                        registration_capacity["schedule_sha256"] and
                    auth["capacity_registration_head"] ==
                        registration["record_sha256"] ==
                        registration_capacity["registration_head"],
                    "Source5 authorization changed its exact legacy 15-entry registration")
        else:
            capacity = _exact(manifest["prepared_capacity_registration"], {
                "completion", "host_completion", "host_verification", "ledger",
                "capacity_schedule_sha256", "registration_head",
            }, "Source5 prepared-capacity manifest registration")
            require(registration["event"] == "source5_prepared_capacity_registered" and
                    auth["capacity_completion"] ==
                        capacity["host_completion"] ==
                        registration_details["host_completion"] and
                    auth["capacity_ledger_raw_sha256"] ==
                        capacity["ledger"]["raw_sha256"] ==
                        registration_details["capacity_ledger"]["raw_sha256"] and
                    auth["capacity_terminal_head"] ==
                        capacity["ledger"]["terminal_head"] ==
                        registration_details["capacity_ledger"]["terminal_head"] and
                    auth["capacity_schedule_sha256"] ==
                        capacity["capacity_schedule_sha256"] ==
                        registration_details["capacity_schedule_sha256"] and
                    auth["capacity_registration_head"] ==
                        capacity["registration_head"] == registration["record_sha256"],
                    "Source5 authorization changed its exact prepared 15-entry registration")
        result.append({
            "authorization_id": auth["authorization_id"],
            "phase": phase, "job_run_id": auth["job_run_id"],
            "job_index": auth["job_index"], "input_snapshot_sha256": input_sha,
            "helper_input": helper_input,
            "payload_references": references,
        })
    return result


def _source5_plan_event_ceiling(
    plan: dict[str, Any], request: dict[str, Any], manifest: dict[str, Any],
) -> int:
    return _source5_plan_event_projection(
        plan, request, manifest,
    )["maximum_callback_events"]


def _source5_plan_event_projection(
    plan: dict[str, Any], request: dict[str, Any], manifest: dict[str, Any],
) -> dict[str, Any]:
    """Derive the maximum Source5 callback horizon from the frozen host plan."""
    if request["scope"] == "prospective_exploration":
        phases = ("exploration",)
        analyses = 1
    else:
        phases = ("exploration", "aa", "confirmation", "pressure", "soak")
        analyses = 6
    counts: dict[str, int] = {}
    all_phases = ("exploration", "aa", "confirmation", "pressure", "soak")
    for phase in all_phases:
        jobs = plan["jobs"].get(phase)
        require(type(jobs) is list,
                f"Source5 frozen PlanV3 {phase} jobs are not a list")
        counts[phase] = sum(
            1 for job in jobs
            if type(job) is dict and job.get("host_id") == request["host_id"]
        )
    pair_jobs = sum(counts.get(phase, 0) for phase in phases
                    if phase != "soak")
    soak_jobs = counts.get("soak", 0)
    registration_events = 2 if manifest["schema"] == SOURCE5_EXECUTION_SCHEMA else 1
    ceiling = registration_events + analyses + 6 * pair_jobs + 4 * soak_jobs
    maximum_bytes = (
        _source5_plan_journal_byte_ceiling(ceiling)
        if manifest["schema"] in {
            SOURCE5_EXECUTION_SCHEMA_V2, SOURCE5_EXECUTION_SCHEMA_V3,
        } else MAX_JOURNAL_BYTES
    )
    require(ceiling <= (MAX_SOURCE5_JOURNAL_EVENTS
                        if manifest["schema"] in {
                            SOURCE5_EXECUTION_SCHEMA_V2,
                            SOURCE5_EXECUTION_SCHEMA_V3,
                        } else MAX_JOURNAL_EVENTS),
            "original Source5 PlanV3 callback horizon exceeds its versioned chronology journal event cap")
    return {
        "schema": "allocatbelt.application-source5-journal-plan-ceiling.v1",
        "scope": request["scope"], "host_id": request["host_id"],
        "execution_manifest_schema": manifest["schema"],
        "job_counts": counts,
        "counted_phases": list(phases),
        "paired_job_event_count": 6 * pair_jobs,
        "soak_job_event_count": 4 * soak_jobs,
        "registration_event_count": registration_events,
        "analysis_event_count": analyses,
        "maximum_callback_events": ceiling,
        "maximum_event_bytes": MAX_EVENT_BYTES,
        "maximum_journal_bytes": maximum_bytes,
        "component_gate_claim": False,
    }


def _source5_plan_journal_byte_ceiling(event_ceiling: int) -> int:
    events = _uint(event_ceiling, "plan-derived Source5 event ceiling",
                   positive=True, maximum=MAX_SOURCE5_JOURNAL_EVENTS)
    # The event line cap is already part of the closed v2 record protocol; the
    # one-GiB ceiling is the existing finite analyzer/artifact byte bound.
    return min(MAX_SOURCE5_JOURNAL_BYTES, events * MAX_EVENT_BYTES)


def _source5_validate_direct_index_closure(
    request: dict[str, Any], manifest: dict[str, Any],
    provenance_result: tuple[Any, ...], receipt: dict[str, Any],
    structural: dict[str, Any], index: dict[str, Any],
    store: dict[str, dict[str, Any]], authorization_inputs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    spec, plan, sources, source_refs, observed, detail = provenance_result
    original_pins = detail["original_pins"]
    checks: dict[tuple[str, str, str | None], dict[str, Any]] = {}

    def check(role: str, path: str, raw_sha: str, host: str | None = None,
              semantic_sha: str | None = None, *,
              semantic_is_null: bool = False) -> None:
        row = _source5_check_indexed_ref(
            store, index, role, path, raw_sha, host_id=host,
            semantic_sha256=semantic_sha,
        )
        if semantic_is_null:
            require(row["semantic_sha256"] is None,
                    f"Source5 {role} row invents a semantic digest outside its schema")
        checked = {"role": role, "path": path, "host_id": host,
                   "raw_sha256": raw_sha,
                   "semantic_sha256": semantic_sha,
                   "byte_count": row["byte_count"]}
        key = (role, path, host)
        prior = checks.get(key)
        require(prior is None or prior == checked,
                f"Source5 direct index closure aliases incompatible pins at {path}")
        checks[key] = checked

    journal = request["journal"]
    check("journal", journal["path"], journal["raw_sha256"],
          request["host_id"], semantic_is_null=True)
    check("execution_manifest", request["execution_manifest"]["path"],
          request["execution_manifest"]["raw_sha256"], request["host_id"],
          request["execution_manifest"]["semantic_sha256"])
    for name, role in (("spec", "spec_v3"), ("plan", "plan_v3")):
        pin = original_pins[name]
        check(role, pin["path"], pin["raw_sha256"],
              semantic_sha=pin["semantic_sha256"])
    for source_host, pin in source_refs.items():
        check("source_manifest", pin["path"], pin["raw_sha256"], source_host,
              pin["semantic_sha256"])
    for source_host, source_value in sources.items():
        for inventory_item in source_value["source"]["files"]:
            relative = _relative(inventory_item["path"],
                                 "Source5 indexed typed source path")
            source_path = str(Path(request["source_root"]).joinpath(
                *relative.parts,
            ))
            source_role = ("typed_source_file"
                           if inventory_item["kind"] == "file" else
                           "typed_source_symlink")
            check(source_role, source_path, inventory_item["sha256"],
                  request["host_id"], semantic_is_null=True)
            source_indexed = _source5_check_indexed_ref(
                store, index, source_role, source_path,
                inventory_item["sha256"], host_id=request["host_id"],
                semantic_sha256=None,
            )
            require(source_indexed["byte_count"] == inventory_item["size"],
                    "Source5 typed source index size differs from its manifest")
        for artifact_role, artifact_relative, artifact_sha in \
                _source5_manifest_artifact_pins(source_value):
            artifact_path = str(Path(request["source_root"]).joinpath(
                *_relative(artifact_relative,
                           "Source5 indexed artifact path").parts,
            ))
            check(artifact_role, artifact_path, artifact_sha,
                  request["host_id"], semantic_is_null=True)
            artifact_indexed = _source5_check_indexed_ref(
                store, index, artifact_role, artifact_path, artifact_sha,
                host_id=request["host_id"], semantic_sha256=None,
            )
            require(artifact_indexed["byte_count"] > 0,
                    "Source5 declared artifact index row is empty")
    check("observed_host", observed["path"], observed["raw_sha256"],
          request["host_id"], semantic_is_null=True)
    for item in detail["dependency_pins"]:
        path = str(Path(request["source_root"]) / item["path"])
        check("typed_source_file", path, item["raw_sha256"],
              request["host_id"], semantic_is_null=True)
    manifest_schema = manifest["schema"]
    if manifest_schema != SOURCE5_EXECUTION_SCHEMA:
        generation = manifest["prepared_input_generation"]
        completion = generation["completion"]
        check("prepared_completion", completion["path"],
              completion["raw_sha256"], semantic_sha=completion["semantic_sha256"])
        preparation = request["provenance"]["preparation_pin"]
        preparation_row = _source5_journal_entry(
            store, preparation["path"], "preparation",
        )
        preparation_value, _preparation_raw, _preparation_raw_sha = \
            _source5_semantic_document(
                preparation_row, store, "Source5 preparation intent",
                MAX_COMPLETION_BYTES, "preparation_sha256",
            )
        check("preparation", preparation["path"], preparation["raw_sha256"],
                  semantic_sha=preparation_value["preparation_sha256"])

    for registration in structural["registrations"]:
        details_value = registration["details"]
        if registration["event"] in {"capacity_stage_completed", "capacity_registered"}:
            completion = details_value["capacity_completion"]
            ledger = details_value["capacity_ledger"]
            check("capacity_completion", completion["path"], completion["sha256"],
                  request["host_id"])
            check("capacity_ledger", ledger["path"], ledger["raw_sha256"],
                  request["host_id"])
        else:
            completion = details_value["completion"]
            check("prepared_completion", completion["path"],
                  completion["raw_sha256"], semantic_sha=completion["semantic_sha256"])
            prep = details_value["provenance"]["preparation_pin"]
            prep_row = _source5_journal_entry(store, prep["path"], "preparation")
            prep_value, _prep_raw, _prep_raw_sha = _source5_semantic_document(
                prep_row, store, "Source5 preparation intent",
                MAX_COMPLETION_BYTES, "preparation_sha256",
            )
            check("preparation", prep["path"], prep["raw_sha256"],
                  semantic_sha=prep_value["preparation_sha256"])
            host_completion = details_value["host_completion"]
            check("capacity_completion", host_completion["path"],
                  host_completion["raw_sha256"], request["host_id"],
                  host_completion["semantic_sha256"])
            host_receipt = details_value["host_verification"]
            check("capacity_host_receipt", host_receipt["path"],
                  host_receipt["raw_sha256"], request["host_id"],
                  host_receipt["receipt_sha256"])
            capacity_ledger = details_value["capacity_ledger"]
            check("capacity_ledger", capacity_ledger["path"],
                  capacity_ledger["raw_sha256"], request["host_id"],
                  semantic_is_null=True)

    for authorization in structural["source5_authorizations"]:
        helper = authorization["helper_input"]
        check("source5_helper_input", helper["path"], helper["raw_sha256"],
              request["host_id"], semantic_is_null=True)
        check("typed_source_file", str(Path(request["source_root"]) /
              authorization["helper_module"]["path"]),
              authorization["helper_module"]["sha256"], request["host_id"])
        for prerequisite in authorization["prerequisites"]:
            pin = prerequisite["analysis"]
            check("analysis_artifact", pin["path"], pin["raw_sha256"],
                  request["host_id"], prerequisite["analysis_sha256"])
    for authorization in authorization_inputs:
        for reference in authorization["payload_references"]:
            check(
                reference["role"], reference["path"],
                reference["raw_sha256"], reference["host_id"],
                reference["semantic_sha256"],
                semantic_is_null=reference["semantic_sha256"] is None,
            )
    for analysis in structural["source5_analyses"].values():
        pin = analysis["analysis"]
        check("analysis_artifact", pin["path"], pin["raw_sha256"],
              request["host_id"], analysis["analysis_sha256"])

    require(receipt["original_pins"] == original_pins and
            receipt["dependency_pins"] == detail["dependency_pins"],
            "Source5 origin receipt changed original pins or captured dependency identity")
    receipt_origin = receipt["origin_facts"]
    require(receipt_origin["observed_host_pin"] == {
                "path": observed["path"], "raw_sha256": observed["raw_sha256"],
            } and
            receipt_origin["boot_id_sha256"] == observed["boot_id_sha256"] and
            receipt_origin["controls_sha256"] == observed["controls_sha256"] and
            receipt_origin["allowed_cpu_affinity"] == observed["cpu_affinity"] and
            receipt_origin["network_namespace_inode"] ==
                observed["network_namespace_inode"],
            "Source5 origin receipt host observations differ from the original observed-host bytes")
    return sorted(checks.values(),
                  key=lambda item: (item["path"], item["role"],
                                    item["host_id"] or ""))


def verify_source5_host_journal_offline(
    request_value: object, captured_evidence_value: object,
) -> dict[str, Any]:
    """Purely reconstruct one host's exact input generation and journal ancestry.

    This API never reads a path, clock, process table, lock, signal state, or
    storage mount. It returns only structural Source5 authorization facts;
    component, capacity-producer, analysis, and campaign gates remain pending.
    """
    request = _source5_journal_request(request_value)
    store = _source5_captured_evidence_store(captured_evidence_value)
    index_pin = request["evidence_index"]
    require(index_pin["path"] not in store or
            store[index_pin["path"]]["role"] == "evidence_index",
            "Source5 evidence-index external path conflicts with another evidence role")
    require(request["origin_receipt"]["path"] != index_pin["path"],
            "Source5 origin receipt and evidence index cannot share one original path")
    index_row = _source5_journal_entry(store, index_pin["path"], "evidence_index",
                                       request["host_id"])
    require(index_row["raw_sha256"] == index_pin["raw_sha256"] and
            index_row["semantic_sha256"] == index_pin["semantic_sha256"],
            "captured Source5 evidence-index row differs from the request's external pin")
    index_value, index_raw, actual_index_raw_sha = _source5_read_canonical_evidence(
        store, index_pin["path"], "Source5 journal evidence index",
        MAX_SOURCE5_JOURNAL_INDEX_BYTES,
    )
    require(actual_index_raw_sha == index_pin["raw_sha256"],
            "Source5 evidence-index raw digest differs")
    index = _validate_source5_journal_index_document(
        index_value, request["campaign_id"], request["host_id"],
        request["source_root"], request["input_root"], request["output_root"],
    )
    require(index["index_sha256"] == index_pin["semantic_sha256"] and
            index_pin["semantic_sha256"] == sha256_bytes(canonical_bytes({
                key: value for key, value in index.items() if key != "index_sha256"
            })),
            "Source5 evidence-index semantic digest differs")
    index_paths = _source5_index_role_map(index)
    require(index_pin["path"] not in index_paths and
            request["origin_receipt"]["path"] not in index_paths,
            "Source5 evidence index cannot recursively index itself or its origin receipt")
    expected_store_paths = set(index_paths) | {
        index_pin["path"], request["origin_receipt"]["path"],
    }
    require(set(store) == expected_store_paths,
            "captured Source5 evidence members differ from the closed index and its two external records")
    for path, indexed in index_paths.items():
        captured = store[path]
        require(all(captured[name] == indexed[name] for name in (
                    "role", "host_id", "origin_path", "local_path",
                    "raw_sha256", "semantic_sha256", "byte_count",
                )),
                f"captured Source5 evidence differs from the index row for {path}")
    require(store[index_pin["path"]]["raw_sha256"] == index_pin["raw_sha256"] and
            store[index_pin["path"]]["semantic_sha256"] == index_pin["semantic_sha256"] and
            store[request["origin_receipt"]["path"]]["raw_sha256"] ==
                request["origin_receipt"]["raw_sha256"] and
            store[request["origin_receipt"]["path"]]["semantic_sha256"] ==
                request["origin_receipt"]["semantic_sha256"],
            "captured Source5 index/receipt external rows differ from their exact pins")
    receipt, receipt_raw = _source5_validate_origin_journal_receipt(
        request, index, store,
    )
    manifest, manifest_raw, manifest_raw_sha = _source5_execution_manifest_document(
        request, store,
    )
    require(manifest_raw_sha == request["execution_manifest"]["raw_sha256"] and
            manifest["output_root"] == request["output_root"],
            "Source5 execution manifest changed its exact original host/output roots")
    _journal_absolute_path(manifest["artifact_root"],
                           "Source5 campaign artifact root")
    original, _plan = None, None
    provenance_result = _source5_validate_source_provenance(
        request, store, manifest, index,
    )
    spec, plan, _sources, source_refs, observed, detail = provenance_result
    plan_event_projection = _source5_plan_event_projection(
        plan, request, manifest,
    )
    plan_event_ceiling = plan_event_projection["maximum_callback_events"]
    plan_byte_ceiling = plan_event_projection["maximum_journal_bytes"]
    require(request["journal"]["byte_count"] <= plan_byte_ceiling,
            "Source5 journal raw bytes exceed the exact plan/schema-derived receipt budget")
    original = detail["original_pins"]
    require(request["input_root"] == str(Path(original["spec"]["path"]).parent) and
            request["source_root"] == manifest["execution_sources"][request["host_id"]]["source_root"],
            "Source5 replay roots differ from the exact original input/source roots")
    host_ids = [host["host_id"] for host in spec["hosts"]]
    require(host_ids == manifest["hosts"] and len(host_ids) == 3 and
            len(set(host_ids)) == 3 and host_ids == plan["host_ids"],
            "Source5 original three-host order differs across SpecV3/PlanV3/manifest")
    require(all(manifest["execution_sources"][host]["source_tree_sha256"] ==
                source_refs[host]["source_tree_sha256"] and
                manifest["execution_sources"][host]["git_commit"] ==
                _source5_source_manifest_document(
                    store, _source5_journal_entry(
                        store, source_refs[host]["path"], "source_manifest", host,
                    ),
                )["source"]["git_commit"]
                for host in host_ids),
            "Source5 execution source snapshots differ from the three exact SourceV5 manifests")
    _source5_check_indexed_ref(
        store, index, "journal", request["journal"]["path"],
        request["journal"]["raw_sha256"], host_id=request["host_id"],
    )
    structural = _source5_replay_journal_entry(
        store[request["journal"]["path"]], original, request,
        observed["boot_id_sha256"],
        maximum_events=(plan_event_ceiling
                        if manifest["schema"] in {
                            SOURCE5_EXECUTION_SCHEMA_V2,
                            SOURCE5_EXECUTION_SCHEMA_V3,
                        } else MAX_JOURNAL_EVENTS),
        maximum_bytes=plan_byte_ceiling,
    )
    require(structural["record_count"] <= plan_event_ceiling,
            "Source5 journal contains more events than the exact original PlanV3 callback horizon")
    require(structural["terminal_head"] == receipt["journal"]["terminal_head"] and
            structural["record_count"] == receipt["journal"]["record_count"] and
            structural["journal_raw_sha256"] == receipt["journal"]["raw_sha256"] and
            structural["last_monotonic_ns"] == receipt["journal"]["last_monotonic_ns"] and
            structural["last_monotonic_ns"] <= receipt["captured_monotonic_ns"],
            "Source5 exact journal replay differs from its origin receipt/time ceiling")
    authorization_inputs = _source5_validate_authorization_inputs(
        request, manifest, spec, plan, _sources, structural, index, store,
    )
    indexed_refs = _source5_validate_direct_index_closure(
        request, manifest, provenance_result, receipt, structural, index, store,
        authorization_inputs,
    )
    indexed_receipts = _source5_validate_indexed_component_receipts(
        index, store, request["host_id"],
    )
    indexed_capacity_receipts = _source5_validate_capacity_host_receipts(
        index, store, request["host_id"],
    )
    indexed_records = _source5_validate_indexed_job_records(
        index, store, manifest, request, structural,
    )
    require(receipt["execution_manifest"] == request["execution_manifest"] and
            receipt["evidence_index"] == request["evidence_index"] and
            receipt["original_pins"] == original and
            receipt["dependency_pins"] == detail["dependency_pins"],
            "Source5 strict origin receipt differs from the independently reconstructed source/input generation")
    return {
        "schema": SOURCE5_JOURNAL_REPLAY_SCHEMA_V1,
        "scope": request["scope"], "campaign_id": request["campaign_id"],
        "host_id": request["host_id"], "source_root": request["source_root"],
        "input_root": request["input_root"], "output_root": request["output_root"],
        "execution_manifest": request["execution_manifest"],
        "origin_receipt": request["origin_receipt"],
        "evidence_index": request["evidence_index"],
        "journal": {
            "path": request["journal"]["path"],
            "raw_sha256": structural["journal_raw_sha256"],
            "byte_count": structural["journal_byte_count"],
            "record_count": structural["record_count"],
            "terminal_head": structural["terminal_head"],
            "last_monotonic_ns": structural["last_monotonic_ns"],
        },
        "planned_source5_event_ceiling": plan_event_ceiling,
        "planned_source5_byte_ceiling": plan_byte_ceiling,
        "planned_source5_event_projection": plan_event_projection,
        "original_pins": original,
        "source_manifest_refs": source_refs,
        "dependency_pins": detail["dependency_pins"],
        "prepared_capacity_registration": next((row["details"]
            for row in structural["registrations"]
            if row["event"] == "source5_prepared_capacity_registered"), None),
        "registration_index": structural["registrations"],
        "source5_authorizations": structural["source5_authorizations"],
        "authorization_input_projections": authorization_inputs,
        "source5_finished": structural["source5_finished"],
        "source5_analyses": structural["source5_analyses"],
        "events": structural["events"],
        "head_by_record_count": structural["head_by_record_count"],
        "ancestry_index": structural,
        "indexed_direct_refs": indexed_refs,
        "indexed_job_records": indexed_records,
        "indexed_component_receipts": indexed_receipts,
        "indexed_capacity_host_receipts": indexed_capacity_receipts,
        "analysis_results_replayed": False,
        "component_results_replayed": False,
        "capacity_producer_replayed": False,
        "component_dispatch_pending": True,
        "qualification_eligible": False,
        "execution_ready": False,
        "receipt_raw_sha256": sha256_bytes(receipt_raw),
        "manifest_raw_sha256": manifest_raw_sha,
    }


def verify_source5_journal_ancestry(
    request_value: object, captured_evidence_value: object, *,
    authorization_head: str, authorization_record_count: int,
    authorization_id: str, job_run_id: str, phase: str,
    historical_head: str | None = None,
    historical_record_count: int | None = None,
) -> dict[str, Any]:
    """Rebuild the host journal and prove one original authorization ancestor."""
    host = verify_source5_host_journal_offline(
        request_value, captured_evidence_value,
    )
    _digest(authorization_head, "Source5 authorization ancestor head")
    count = _uint(authorization_record_count,
                  "Source5 authorization ancestor record count")
    authorization_id = _token(authorization_id, "Source5 authorization ID")
    job_run_id = _token(job_run_id, "Source5 authorization job run ID")
    require(phase in {"exploration", "aa", "confirmation", "pressure", "soak"},
            "Source5 ancestry phase is not an original campaign phase")
    matches = [row for row in host["source5_authorizations"]
               if row["authorization_id"] == authorization_id]
    require(len(matches) == 1,
            "Source5 requested authorization is not unique in the full captured host journal")
    row = matches[0]
    require(row["phase"] == phase and row["job_run_id"] == job_run_id and
            row["authorization_head"] == authorization_head and
            row["authorization_record_count"] == count,
            "Source5 requested authorization/head/count differs from its exact original journal row")
    proof = _journal_ancestry_proof_from_index(
        host["ancestry_index"], authorization_head, count,
        "source5_authorized", authorization_id, job_run_id,
    )
    require(row["capacity_registration_head"] in
            host["head_by_record_count"][:count],
            "Source5 authorization is not descended from its exact captured capacity registration")
    require((historical_head is None) == (historical_record_count is None),
            "Source5 historical head and record count must be supplied together")
    historical_proof = None
    if historical_head is not None:
        _digest(historical_head, "Source5 historical journal snapshot head")
        historical_count = _uint(
            historical_record_count,
            "Source5 historical journal snapshot record count",
        )
        require(historical_count <= count and
                host["head_by_record_count"][historical_count] == historical_head and
                row["capacity_registration_head"] in
                    host["head_by_record_count"][:historical_count + 1],
                "Source5 historical head/count is not the exact registration-descended predecessor of this authorization")
        historical_proof = {
            "head": historical_head, "record_count": historical_count,
            "registration_head": row["capacity_registration_head"],
            "authorization_head": authorization_head,
            "authorization_record_count": count,
            "structural_only": True,
        }
    finished = next((item for item in host["source5_finished"]
                     if item["phase"] == phase and item["job_run_id"] == job_run_id), None)
    if finished is not None:
        require(finished["authorization_id"] == authorization_id and
                finished["authorization_head"] == authorization_head,
                "Source5 completed authorization differs from its captured terminal lineage")
    fixed_predecessor = None
    if phase == "pressure":
        predecessor_ids = row["job"].get("predecessor_run_ids")
        require(type(predecessor_ids) is list and len(predecessor_ids) == 1 and
                type(predecessor_ids[0]) is str and
                predecessor_ids[0] != job_run_id,
                "original pressure job does not name exactly one distinct fixed predecessor")
        predecessor_run_id = _token(
            predecessor_ids[0], "original fixed predecessor run ID",
        )
        predecessor_auths = [item for item in host["source5_authorizations"]
                             if item["phase"] == "confirmation" and
                             item["job_run_id"] == predecessor_run_id]
        predecessor_finished = [item for item in host["source5_finished"]
                                if item["phase"] == "confirmation" and
                                item["job_run_id"] == predecessor_run_id]
        require(len(predecessor_auths) == len(predecessor_finished) == 1,
                "original pressure job lacks one exact fixed predecessor authorization and terminal")
        prior_authorization = predecessor_auths[0]
        prior_finished = predecessor_finished[0]
        terminal_rows = [item for item in host["events"]
                         if item["record_sha256"] ==
                            prior_finished["job_terminal"]["event_head"] and
                         item["event"] == "source5_job_terminal"]
        require(prior_finished["authorization_id"] ==
                    prior_authorization["authorization_id"] and
                prior_finished["authorization_head"] ==
                    prior_authorization["authorization_head"] and
                prior_finished["job_terminal"]["state_claim"] == "valid_pair" and
                prior_authorization["authorization_record_count"] < count and
                len(terminal_rows) == 1 and terminal_rows[0]["sequence"] < count,
                "original pressure fixed predecessor is not an earlier structurally successful terminal")
        fixed_predecessor = {
            "run_id": predecessor_run_id,
            "authorization": prior_authorization,
            "finished": prior_finished,
            "terminal_record_count": terminal_rows[0]["sequence"],
            "component_replay_required": True,
            "qualification_eligible": False,
        }
    return {
        **proof, "phase": phase,
        "job_index": row["job_index"], "job_sha256": row["job_sha256"],
        "members_sha256": row["members_sha256"],
        "capacity_registration_head": row["capacity_registration_head"],
        "authorization": row,
        "completed": finished is not None,
        "historical_ancestor": historical_proof,
        "fixed_predecessor": fixed_predecessor,
        "component_replayed": False,
        "qualification_eligible": False,
    }


def _read_journal(lock: CampaignHostLock, prepared: dict[str, Any]) -> dict[str, Any]:
    _check_lock(lock, prepared["output_root"], prepared["campaign_id"], prepared["host_id"])
    maximum_events, maximum_bytes = _journal_limits(prepared)
    replay_context = (
        prepared.get("source5_execution_schema"),
        prepared.get("source5_execution_manifest_raw_sha256"),
        maximum_events, maximum_bytes,
    )
    path = _journal_path(lock)
    state_cached = _cached_lock_state(lock)
    try:
        info = path.lstat()
    except FileNotFoundError:
        require(state_cached is None or state_cached["file_stat"] is None,
                "chronology journal disappeared while its lock was held")
        state = state_cached or _empty_journal(prepared["original_pins"])
        require(state["original_pins"] == prepared["original_pins"],
                "chronology journal original pins changed")
        state["_replay_context"] = replay_context
        _set_cached_lock_state(lock, state)
        return state
    except OSError as error:
        raise ChronologyError(f"cannot inspect chronology journal: {error}") from error
    require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and
            info.st_uid == os.getuid(),
            "chronology journal must be an owned mode-0600 regular file")
    key = (info.st_dev, info.st_ino, info.st_mode, info.st_size,
           info.st_mtime_ns, info.st_ctime_ns)
    if state_cached is not None and state_cached["file_stat"] == key:
        require(state_cached["original_pins"] == prepared["original_pins"],
                "chronology journal is already bound to different original pins")
        if state_cached.get("_replay_context") == replay_context:
            return state_cached
    raw, read_info = _read_stable(path, "campaign dispatch journal", maximum_bytes)
    require(stat.S_IMODE(read_info.st_mode) == 0o600 and read_info.st_uid == os.getuid(),
            "chronology journal permissions changed while reading")
    state = _empty_journal(prepared["original_pins"])
    state["_replay_context"] = replay_context
    for item in _iter_journal_records(
            raw, prepared["original_pins"], prepared["campaign_id"],
            prepared["host_id"], prepared["boot_id_sha256"],
            maximum_events=maximum_events, maximum_bytes=maximum_bytes):
        sequence = item["sequence"]
        record = item["record"]
        record_sha = item["record_sha256"]
        event = record["event"]
        monotonic_ns = record["monotonic_ns"]
        require(monotonic_ns <= time.monotonic_ns() + 1_000_000_000,
                f"chronology journal record {sequence} has invalid monotonic order")
        _check_event_semantics(state, event, record["details"], record_sha,
                               prepared, replay=True)
        state["record_count"] += 1
        if event.startswith("dispatch_"):
            state["dispatch_event_count"] += 1
        state["head"] = record_sha
        state["journal_heads"].append(record_sha)
        state["last_monotonic_ns"] = monotonic_ns
    after = path.lstat()
    after_key = (after.st_dev, after.st_ino, after.st_mode, after.st_size,
                 after.st_mtime_ns, after.st_ctime_ns)
    require(after_key == key, "chronology journal changed during chain replay")
    state["file_stat"] = key
    _set_cached_lock_state(lock, state)
    return state


def _journal_limits(prepared: dict[str, Any]) -> tuple[int, int]:
    schema = prepared.get("source5_execution_schema")
    if schema in {SOURCE5_EXECUTION_SCHEMA_V2, SOURCE5_EXECUTION_SCHEMA_V3}:
        events = prepared.get("source5_journal_event_ceiling")
        byte_count = prepared.get("source5_journal_byte_ceiling")
        _uint(events, "plan-derived Source5 journal event ceiling", positive=True,
              maximum=MAX_SOURCE5_JOURNAL_EVENTS)
        _uint(byte_count, "plan-derived Source5 journal byte ceiling", positive=True,
              maximum=MAX_SOURCE5_JOURNAL_BYTES)
        return events, byte_count
    return MAX_JOURNAL_EVENTS, MAX_JOURNAL_BYTES


def _append_event(lock: CampaignHostLock, prepared: dict[str, Any], event: str,
                  details: dict[str, Any]) -> dict[str, Any]:
    _check_lock(lock, prepared["output_root"], prepared["campaign_id"], prepared["host_id"])
    state = _read_journal(lock, prepared)
    maximum_events, maximum_bytes = _journal_limits(prepared)
    require(state["record_count"] < maximum_events,
            "original Source5 PlanV3 callback horizon is exhausted")
    require(event in DETAIL_FIELDS, f"unknown chronology event {event}")
    record = {
        "schema": JOURNAL_SCHEMA, "sequence": state["record_count"] + 1,
        "monotonic_ns": max(time.monotonic_ns(), state["last_monotonic_ns"] + 1),
        "campaign_id": prepared["campaign_id"], "host_id": prepared["host_id"],
        "boot_id_sha256": prepared["boot_id_sha256"],
        "original_pins": _json_copy(prepared["original_pins"]), "event": event,
        "details": _json_copy(details),
    }
    unsigned = {"previous_sha256": state["head"], "record": record}
    record_sha = sha256_bytes(canonical_bytes(unsigned))
    _check_event_semantics(state, event, record["details"], record_sha,
                           prepared, replay=False, apply=False)
    line = canonical_bytes({**unsigned, "record_sha256": record_sha})
    require(len(line) <= MAX_EVENT_BYTES, f"chronology {event} record exceeds its finite line bound")
    path = _journal_path(lock)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        descriptor = os.open(path, flags | os.O_EXCL, 0o600)
        created = True
    except FileExistsError:
        descriptor = os.open(
            path, os.O_WRONLY | os.O_APPEND | getattr(os, "O_CLOEXEC", 0) |
            getattr(os, "O_NOFOLLOW", 0),
        )
    try:
        if created:
            os.fchmod(descriptor, 0o600)
        info = os.fstat(descriptor)
        path_info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and stat.S_ISREG(path_info.st_mode) and
                (info.st_dev, info.st_ino) == (path_info.st_dev, path_info.st_ino) and
                info.st_uid == path_info.st_uid == os.getuid() and
                stat.S_IMODE(info.st_mode) == stat.S_IMODE(path_info.st_mode) == 0o600,
                "chronology journal must remain an owned mode-0600 regular file")
        require(info.st_size + len(line) <= maximum_bytes,
                "chronology journal exceeds its finite byte bound")
        offset = 0
        while offset < len(line):
            offset += os.write(descriptor, line[offset:])
        os.fsync(descriptor)
        after_info = os.fstat(descriptor)
        require(stat.S_ISREG(after_info.st_mode) and
                (after_info.st_dev, after_info.st_ino) == (info.st_dev, info.st_ino) and
                after_info.st_uid == os.getuid() and stat.S_IMODE(after_info.st_mode) == 0o600 and
                after_info.st_size == info.st_size + len(line),
                "chronology journal metadata changed during durable append")
    finally:
        os.close(descriptor)
    if created:
        _fsync_directory(path.parent)
    after_path = path.lstat()
    require((after_path.st_dev, after_path.st_ino, after_path.st_size) ==
            (after_info.st_dev, after_info.st_ino, after_info.st_size),
            "chronology journal path changed after its durable append")
    _check_event_semantics(state, event, record["details"], record_sha,
                           prepared, replay=False)
    state["record_count"] += 1
    if event.startswith("dispatch_"):
        state["dispatch_event_count"] += 1
    state["head"] = record_sha
    state["journal_heads"].append(record_sha)
    state["last_monotonic_ns"] = record["monotonic_ns"]
    state["file_stat"] = (
        after_path.st_dev, after_path.st_ino, after_path.st_mode, after_path.st_size,
        after_path.st_mtime_ns, after_path.st_ctime_ns,
    )
    _set_cached_lock_state(lock, state)
    return {**record, "record_sha256": record_sha}


def _capacity_completion(
    prepared: dict[str, Any], capacity_output_root: Path, completion_pin: object,
) -> tuple[dict[str, Any], dict[str, Any]]:
    capacity_output_root = _safe_root(Path(capacity_output_root), "capacity evidence output root")
    require(not _within(prepared["source_root"], capacity_output_root),
            "capacity evidence output root must be outside SourceV5")
    completion_pin_value = _exact(completion_pin, {"path", "sha256"}, "capacity completion pin")
    completion_path = Path(completion_pin_value["path"])
    completion_sha = _digest(completion_pin_value["sha256"], "capacity completion raw SHA-256")
    try:
        verification = prepared["stage"].verify_capacity_completion(
            prepared["plan_pin"], prepared["spec_pin"], prepared["source_root"],
            prepared["input_root"], prepared["host_id"],
            {"path": str(prepared["prepared"]["host_context_path"]),
             "sha256": prepared["prepared"]["host_context_raw_sha256"]},
            capacity_output_root, {"path": str(completion_path), "sha256": completion_sha},
        )
    except Exception as error:
        raise ChronologyError(f"captured full capacity completion verifier rejected registration: {error}") from error
    verification = _exact(verification, {
        "completion_raw_sha256", "ledger_raw_sha256", "terminal_head", "complete",
        "qualification_eligible", "controller_chronology_proven", "entry_count",
        "capacity_process_templates_sha256",
    }, "captured capacity verifier result")
    require(verification["complete"] is True and
            verification["qualification_eligible"] is False and
            verification["controller_chronology_proven"] is False and
            verification["entry_count"] == 15 and type(verification["entry_count"]) is int and
            verification["capacity_process_templates_sha256"] ==
            prepared["plan"]["capacity_process_templates_sha256"],
            "captured capacity verifier result does not prove the exact ineligible 15-entry replay")
    raw, completion_stat = _read_stable(completion_path, "capacity completion overlay", MAX_COMPLETION_BYTES)
    require(stat.S_IMODE(completion_stat.st_mode) == 0o600 and completion_stat.st_uid == os.getuid(),
            "capacity completion overlay must remain an owned mode-0600 file")
    require(sha256_bytes(raw) == completion_sha == verification["completion_raw_sha256"],
            "capacity completion changed during full replay")
    completion = _parse_object(raw, "capacity completion overlay", MAX_COMPLETION_BYTES)
    _exact(completion, {
        "schema", "complete", "qualification_eligible", "controller_chronology_proven",
        "campaign_id", "host_id", "spec", "plan", "source", "observed_host", "stage",
        "controller", "inputs", "feedback_reader", "capacity_producer",
        "capacity_process_templates_sha256", "stage_directory", "ledger", "entries",
    }, "capacity completion overlay")
    require(completion["schema"] == CAPACITY_COMPLETION_SCHEMA and completion["complete"] is True and
            completion["qualification_eligible"] is False and
            completion["controller_chronology_proven"] is False and
            completion["campaign_id"] == prepared["campaign_id"] and
            completion["host_id"] == prepared["host_id"] and
            type(completion["entries"]) is list and len(completion["entries"]) == 15,
            "capacity completion must be complete for 15 entries and remain ineligible")
    require(completion["spec"] == {
        "path": str(prepared["prepared"]["spec_path"]),
        "raw_sha256": prepared["prepared"]["spec_raw_sha256"],
        "semantic_sha256": prepared["prepared"]["spec_semantic_sha256"],
    } and completion["plan"] == {
        "path": str(prepared["prepared"]["plan_path"]),
        "raw_sha256": prepared["prepared"]["plan_raw_sha256"],
        "semantic_sha256": prepared["prepared"]["plan_semantic_sha256"],
    }, "capacity completion original raw/semantic spec/plan pins differ")
    require(completion["capacity_process_templates_sha256"] ==
            prepared["plan"]["capacity_process_templates_sha256"],
            "capacity completion schedule differs from original PlanV3")
    ledger_value = _exact(completion["ledger"], {"path", "raw_sha256", "terminal_head"},
                          "capacity sealed ledger")
    ledger = {
        "path": _path_text(Path(ledger_value["path"]), "capacity ledger path"),
        "raw_sha256": _digest(ledger_value["raw_sha256"], "capacity ledger raw SHA-256"),
        "terminal_head": _digest(ledger_value["terminal_head"], "capacity ledger terminal head"),
    }
    require(ledger["raw_sha256"] == verification["ledger_raw_sha256"] and
            ledger["terminal_head"] == verification["terminal_head"],
            "capacity registration ledger pins differ from the full replay result")
    details = {
        "capacity_completion": {"path": str(completion_path), "sha256": completion_sha},
        "capacity_ledger": ledger,
        "capacity_schedule_sha256": completion["capacity_process_templates_sha256"],
        "entry_count": len(completion["entries"]), "entries": completion["entries"],
        "qualification_eligible": False, "controller_chronology_proven": False,
    }
    return details, completion


def _phase_directory(prepared: dict[str, Any]) -> Path:
    return (prepared["output_root"] / prepared["campaign_id"] / "confirmation" /
            prepared["host_id"])


def _require_no_legacy_confirmation(prepared: dict[str, Any]) -> None:
    phase_dir = _phase_directory(prepared)
    require(not phase_dir.exists() and not phase_dir.is_symlink(),
            "an existing original confirmation host directory blocks chronology registration")
    legacy_journal = phase_dir / "controller-ledger.jsonl"
    require(not legacy_journal.exists() and not legacy_journal.is_symlink(),
            "an existing original confirmation ledger blocks chronology registration")


@_serialize_locked_api
def run_capacity_stage_locked(
    lock: CampaignHostLock, plan_pin: object, spec_pin: object, source_root: Path,
    input_root: Path, host_id: str, observed_host_pin: object, output_root: Path,
) -> dict[str, Any]:
    """Invoke the captured stage while the same private campaign/host flock is held."""
    prepared = _prepare_inputs(plan_pin, spec_pin, source_root, input_root, host_id,
                               observed_host_pin, output_root)
    lock = _check_lock(lock, prepared["output_root"], prepared["campaign_id"], host_id)
    state = _read_journal(lock, prepared)
    require(state["record_count"] == 0 and state["pending"] is None,
            "capacity stage invocation must precede every chronology registration/dispatch")
    _require_no_legacy_confirmation(prepared)
    try:
        result = prepared["stage"].run_capacity_stage(
            prepared["plan_pin"], prepared["spec_pin"], prepared["source_root"],
            prepared["input_root"], prepared["host_id"],
            {"path": str(prepared["prepared"]["host_context_path"]),
             "sha256": prepared["prepared"]["host_context_raw_sha256"]},
            prepared["output_root"],
        )
    except Exception as error:
        raise ChronologyError(f"captured capacity stage failed under the campaign/host lock: {error}") from error
    result = _exact(result, {
        "completion", "ledger", "complete", "qualification_eligible",
        "entry_count", "controller_chronology_proven",
    }, "captured capacity stage result")
    require(result["complete"] is True and result["qualification_eligible"] is False and
            result["controller_chronology_proven"] is False and
            result["entry_count"] == 15 and type(result["entry_count"]) is int,
            "captured capacity stage did not return its exact ineligible 15-entry completion")
    details, completion = _capacity_completion(
        prepared, prepared["output_root"], result.get("completion"),
    )
    stage_completion_pin = _exact(result["completion"], {"path", "sha256"},
                                  "captured capacity stage completion pin")
    stage_ledger_pin = _exact(result["ledger"], {"path", "raw_sha256", "terminal_head"},
                              "captured capacity stage sealed ledger pin")
    require(stage_completion_pin == details["capacity_completion"] and
            stage_ledger_pin == completion["ledger"],
            "captured capacity stage result disagrees with its full completion replay")
    _append_event(lock, prepared, "capacity_stage_completed", details)
    return {
        **result, "capacity_stage_verified": True,
        "capacity_schedule_sha256": details["capacity_schedule_sha256"],
        "entry_count": 15, "qualification_eligible": False,
        "controller_chronology_proven": False,
    }


@_serialize_locked_api
def register_capacity_completion_locked(
    lock: CampaignHostLock, plan_pin: object, spec_pin: object, source_root: Path,
    input_root: Path, host_id: str, observed_host_pin: object, output_root: Path,
    completion_pin: object, *, capacity_output_root: Path | None = None,
) -> dict[str, Any]:
    """Fully replay the 15-entry completion and seal its head before any confirmation directory exists."""
    prepared = _prepare_inputs(plan_pin, spec_pin, source_root, input_root, host_id,
                               observed_host_pin, output_root)
    lock = _check_lock(lock, prepared["output_root"], prepared["campaign_id"], host_id)
    state = _read_journal(lock, prepared)
    require(state["stage_completion"] is not None,
            "capacity completion must be produced by run_capacity_stage_locked under this same lock")
    require(not state["authorized"] and state["pending"] is None,
            "capacity registration is too late because a confirmation dispatch was already authorized")
    _require_no_legacy_confirmation(prepared)
    evidence_root = Path(capacity_output_root) if capacity_output_root is not None else prepared["output_root"]
    details, completion = _capacity_completion(prepared, evidence_root, completion_pin)
    require(_registration_fields(details) ==
            _registration_fields(state["stage_completion"]),
            "capacity registration differs from the locked stage completion")
    if state["registration"] is not None:
        require(details == _registration_fields(state["registration"]),
                "conflicting capacity completion registration already exists")
        return {
            "registered": True, "registration_head": state["registration_head"],
            "capacity_ledger_raw_sha256": details["capacity_ledger"]["raw_sha256"],
            "capacity_ledger_terminal_head": details["capacity_ledger"]["terminal_head"],
            "entry_count": 15, "qualification_eligible": False,
            "controller_chronology_proven": False,
            "api_transaction_order_proven": True,
        }
    _require_no_legacy_confirmation(prepared)
    details["capacity_stage_event_head"] = state["stage_head"]
    record = _append_event(lock, prepared, "capacity_registered", details)
    return {
        "registered": True, "registration_head": record["record_sha256"],
        "capacity_ledger_raw_sha256": details["capacity_ledger"]["raw_sha256"],
        "capacity_ledger_terminal_head": details["capacity_ledger"]["terminal_head"],
        "entry_count": 15, "qualification_eligible": False,
        "controller_chronology_proven": False,
        "api_transaction_order_proven": True,
    }


@_serialize_locked_api
def register_source5_prepared_capacity_locked(
    lock: CampaignHostLock, plan_pin: object, spec_pin: object,
    source_root: Path, input_root: Path, host_id: str,
    observed_host_pin: object, output_root: Path,
    completion_pin: object, provenance_pin: object,
) -> dict[str, Any]:
    """Replay/register the actual standalone pre-Spec capacity preparation receipt."""
    prepared = _prepare_inputs(
        plan_pin, spec_pin, source_root, input_root, host_id,
        observed_host_pin, output_root,
    )
    lock = _check_lock(lock, prepared["output_root"], prepared["campaign_id"], host_id)
    require(bool(prepared["spec"].get("rates")) and
            bool(prepared["spec"].get("oracles")),
            "prepared-capacity registration requires the separately frozen final SpecV3")
    pin = _exact(completion_pin, {
        "path", "raw_sha256", "semantic_sha256",
    }, "prepared-input bridge completion pin")
    provenance = _exact(provenance_pin, {
        "schema", "preparation_pin", "final_spec_pin", "final_plan_pin",
    }, "prepared-input bridge provenance")
    state = _read_journal(lock, prepared)
    require(state["record_count"] == 0 and state["stage_completion"] is None and
            state["registration"] is None and
            state["prepared_capacity_registration"] is None and
            state["pending"] is None and state["source5_pending"] is None and
            not state["authorized"] and not state["source5_seen_jobs"],
            "prepared-capacity registration must precede every campaign execution event")
    _require_no_legacy_confirmation(prepared)
    generation = {"completion": pin, "provenance": provenance}
    verified = _verify_source5_prepared_input_generation(
        None, prepared, generation,
    )
    host_ids = [item["host_id"] for item in prepared["spec"]["hosts"]]
    row = verified["capacity_preparations"][host_ids.index(host_id)]
    details = {
        "campaign_id": prepared["campaign_id"], "host_id": host_id,
        "completion": pin, "provenance": provenance,
        "host_completion": {
            **row["completion"],
            "semantic_sha256": row["completion_sha256"],
        },
        "host_verification": row["host_verification"],
        "capacity_ledger": row["ledger"],
        "capacity_schedule_sha256":
            row["capacity_preparation_templates_sha256"],
        "entries": row["entries"],
        "qualification_eligible": False,
        "controller_chronology_proven": False,
    }
    record = _append_event(
        lock, prepared, "source5_prepared_capacity_registered", details,
    )
    return {
        "registered": True,
        "completion": pin,
        "host_completion": {
            **row["completion"],
            "semantic_sha256": row["completion_sha256"],
        },
        "host_verification": row["host_verification"],
        "ledger": row["ledger"],
        "capacity_schedule_sha256":
            row["capacity_preparation_templates_sha256"],
        "registration_head": record["record_sha256"],
        "entry_count": len(row["entries"]),
        "qualification_eligible": False,
        "controller_chronology_proven": False,
    }


def _inventory_runner_pin(prepared: dict[str, Any], runner_path_arg: Path) -> dict[str, str]:
    source_root = prepared["source_root"]
    expected_path = source_root / PAIR_RUNNER_SOURCE_PATH
    runner_path = Path(runner_path_arg)
    _path_text(runner_path, "fixed pair-runner path")
    require(runner_path.is_absolute() and runner_path == expected_path,
            "fixed confirmation must execute the original SourceV5 pair-runner path")
    raw, raw_sha, record = _source_file(
        source_root, prepared["source"], PAIR_RUNNER_SOURCE_PATH, "fixed pair runner",
        maximum=MAX_SCRIPT_BYTES,
    )
    require(record["mode"] == "100755" and os.access(runner_path, os.X_OK) and
            raw_sha == prepared["spec"]["runner_sha256"],
            "pair-runner executable differs from its original SourceV5 inventory/spec pin")
    return {"path": str(runner_path), "sha256": raw_sha}


def _pinned_binary(prepared: dict[str, Any], allocator: object, label: str) -> tuple[Path, str]:
    name = _token(allocator, f"{label} allocator")
    artifacts = prepared["source"].get("artifacts")
    require(type(artifacts) is dict and name in artifacts,
            f"SourceV5 has no {label} application artifact for {name}")
    artifact = _exact(artifacts[name], {"path", "sha256"}, f"{label} SourceV5 artifact")
    relative = _relative(artifact["path"], f"{label} SourceV5 binary path")
    path = _safe_child(prepared["source_root"], relative.as_posix(), f"{label} SourceV5 binary")
    info = path.stat(follow_symlinks=False)
    require(stat.S_ISREG(info.st_mode) and info.st_mode & 0o111 != 0,
            f"{label} SourceV5 binary is not executable")
    raw, _info = _read_stable(path, f"{label} SourceV5 binary", 1024 * 1024 * 1024)
    raw_sha = sha256_bytes(raw)
    expected_sha = _digest(artifact["sha256"], f"{label} SourceV5 binary SHA-256")
    require(raw_sha == expected_sha, f"{label} binary changed after SourceV5 capture")
    return path, expected_sha


def _oracle_pin(controller: types.ModuleType, job: dict[str, Any], allocator: str,
                artifacts_root: Path | None) -> tuple[Path, str] | None:
    if job["mode"] != "open_loop":
        return None
    require(artifacts_root is not None,
            "original fixed open-loop dispatch requires its frozen campaign artifact root")
    oracle_map = controller.oracle_map_for_job(job)
    oracle = oracle_map.get(allocator)
    require(type(oracle) is dict, f"original plan has no {allocator} oracle for {job['run_id']}")
    relative = _relative(oracle.get("relative_path"), "fixed confirmation oracle path")
    path = _safe_child(artifacts_root, relative.as_posix(), "fixed confirmation oracle")
    raw, _info = _read_stable(path, "fixed confirmation oracle", 16 * 1024 * 1024)
    expected = _digest(oracle.get("sha256"), "fixed confirmation oracle SHA-256")
    require(sha256_bytes(raw) == expected, "fixed confirmation oracle differs from its frozen plan pin")
    return path, expected


def _job_for_authorization(prepared: dict[str, Any], exact_job: object) -> tuple[int, dict[str, Any], list[dict[str, Any]]]:
    jobs = prepared["plan"]["jobs"]["confirmation"]
    host_jobs = [(index, job) for index, job in enumerate(
        item for item in jobs if item["host_id"] == prepared["host_id"]
    )]
    matches = [(index, job) for index, job in host_jobs
               if canonical_bytes(job) == canonical_bytes(exact_job)]
    if not matches:
        pressure_jobs = prepared["plan"].get("jobs", {}).get("pressure", [])
        is_pressure = any(
            type(item) is dict and item.get("host_id") == prepared["host_id"] and
            canonical_bytes(item) == canonical_bytes(exact_job)
            for item in pressure_jobs
        )
        require(not is_pressure,
                "pressure dispatch is explicitly unsupported by the fixed confirmation journal")
    require(len(matches) == 1,
            "dispatch must name exactly one original PlanV3 fixed-confirmation job")
    index, job = matches[0]
    require(job.get("phase") == "confirmation" and
            job.get("comparison_family") == "fixed_policy" and
            job.get("host_id") == prepared["host_id"],
            "pressure or foreign jobs are not enabled by the fixed confirmation journal")
    controller = prepared["controller"]
    descriptors = controller.process_descriptors(job)
    require(type(descriptors) is list and len(descriptors) == 2,
            "fixed pair runner must preserve the two original plan members")
    bindings = prepared["plan"]["runtime_process_bindings"].get(job["run_id"])
    require(type(bindings) is list and len(bindings) == 2 and
            controller.build_runtime_process_bindings(job, prepared["spec"], prepared["source"]) == bindings,
            "fixed confirmation runtime recipes differ from the original PlanV3")
    for descriptor, binding in zip(descriptors, bindings, strict=True):
        require(all(binding.get(key) == value for key, value in descriptor.items()),
                "fixed runner member differs from its original process descriptor")
    return index, job, bindings


def _expected_shebang_interpreter(runner_raw: bytes, environment: dict[str, str]) -> dict[str, str]:
    first_line = runner_raw.splitlines()[0] if runner_raw else b""
    require(first_line == b"#!/usr/bin/env bash",
            "fixed pair runner interpreter line differs from the pinned shell contract")
    path_text = environment.get("PATH")
    require(type(path_text) is str and path_text,
            "fixed runner environment must pin a nonempty PATH")
    found = shutil.which("bash", path=path_text)
    require(found is not None, "fixed runner's pinned PATH cannot resolve bash")
    path = Path(found).resolve(strict=True)
    raw, _info = _read_stable(path, "fixed pair-runner interpreter", 256 * 1024 * 1024)
    return {"path": str(path), "sha256": sha256_bytes(raw)}


def _environment_snapshot(environment: dict[str, str]) -> tuple[dict[str, str], str]:
    require(type(environment) is dict and environment,
            "fixed pair-runner environment must be a nonempty mapping")
    for key, value in environment.items():
        require(type(key) is str and type(value) is str and key and "=" not in key and
                "\x00" not in key and "\x00" not in value,
                "fixed pair-runner environment contains an invalid key/value")
        require(key not in {"BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS"} and
                not key.startswith("BASH_FUNC_"),
                "fixed pair-runner environment contains an unpinned Bash startup or function import control")
        try:
            key.encode("ascii", "strict")
            value.encode("utf-8", "strict")
        except UnicodeError as error:
            raise ChronologyError("fixed pair-runner environment key/value encoding is unsupported") from error
    raw = canonical_bytes(environment)
    require(len(raw) <= MAX_ENVIRONMENT_BYTES,
            "fixed pair-runner environment exceeds its finite byte bound")
    return environment, sha256_bytes(raw)


def _owner_marker(prepared: dict[str, Any], registration_head: str) -> dict[str, Any]:
    body = {
        "schema": "allocatbelt.application-campaign-chronology-owner.v1",
        "campaign_id": prepared["campaign_id"], "host_id": prepared["host_id"],
        "original_pins_sha256": prepared["original_pins_sha256"],
        "registration_head": registration_head,
        "qualification_eligible": False,
    }
    return {"path": str(_phase_directory(prepared) / ".chronology-owner.json"),
            "sha256": sha256_bytes(canonical_bytes(body))}


def _launch_spec(
    prepared: dict[str, Any], job_index: int, job: dict[str, Any],
    bindings: list[dict[str, Any]], runner_pin: dict[str, str],
    campaign_artifacts_root_arg: Path | None, environment: dict[str, str],
    registration_head: str,
) -> dict[str, Any]:
    environment, environment_sha = _environment_snapshot(environment)
    runner_path = Path(runner_pin["path"])
    require(runner_path == prepared["source_root"] / PAIR_RUNNER_SOURCE_PATH,
            "fixed pair runner path differs from the regular SourceV5 path")
    runner_raw, runner_sha, runner_record = _source_file(
        prepared["source_root"], prepared["source"], PAIR_RUNNER_SOURCE_PATH,
        "fixed pair runner", maximum=MAX_SCRIPT_BYTES,
    )
    require(runner_record["mode"] == "100755" and os.access(runner_path, os.X_OK) and
            runner_sha == runner_pin["sha256"] == prepared["spec"]["runner_sha256"],
            "fixed pair runner pin differs from the original spec/source files")
    interpreter = _expected_shebang_interpreter(runner_raw, environment)
    artifacts_root = None
    if job["mode"] == "open_loop":
        require(campaign_artifacts_root_arg is not None,
                "original fixed open-loop dispatch requires its campaign artifact root")
        artifacts_root = _safe_root(Path(campaign_artifacts_root_arg), "campaign artifact root")
        require(not _within(prepared["source_root"], artifacts_root),
                "campaign oracle artifacts must remain outside SourceV5")
    else:
        require(campaign_artifacts_root_arg is None,
                "capacity-mode fixed dispatch does not consume a campaign artifact root")

    binary, _binary_sha = _pinned_binary(prepared, job["allocator"], "candidate")
    candidate_oracle = _oracle_pin(prepared["controller"], job, job["allocator"], artifacts_root)
    baseline_binary: Path | None = None
    baseline_allocator: str | None = None
    baseline_oracle: tuple[Path, str] | None = None
    if job.get("comparison_kind") == "allocator":
        baseline_allocator = _token(job.get("baseline_allocator"), "fixed baseline allocator")
        baseline_binary, _baseline_sha = _pinned_binary(prepared, baseline_allocator, "baseline")
        if job["mode"] == "open_loop":
            baseline_oracle = _oracle_pin(prepared["controller"], job, baseline_allocator, artifacts_root)

    output_root = prepared["output_root"]
    phase_dir = _phase_directory(prepared)
    control = _token(job.get("control_id", job["family"]), "fixed confirmation control")
    profile = _token(job["profile"], "fixed confirmation profile")
    mode = _token(job["mode"], "fixed confirmation mode")
    allocator = _token(job["allocator"], "fixed confirmation allocator")
    runner_output = phase_dir / "pairs" / control / profile / mode / allocator
    binding_path = runner_output / ".runtime-bindings" / f"{job['run_id']}.json"
    controller = prepared["controller"]
    manifest = controller.runtime_binding_manifest_value(bindings, job, prepared["spec"],
                                                         prepared["source"])
    manifest_raw = canonical_bytes(manifest)
    manifest_sha = sha256_bytes(manifest_raw)
    validator_pin = _exact(prepared["source"]["runtime_readback_validator"],
                           {"path", "sha256"}, "SourceV5 fixed runtime validator pin")
    validator_path = _safe_child(prepared["source_root"], validator_pin["path"],
                                 "SourceV5 fixed runtime validator")
    validator_raw, _validator_info = _read_stable(validator_path, "SourceV5 runtime validator",
                                                  MAX_SOURCE_BYTES)
    validator_sha = _digest(validator_pin["sha256"], "SourceV5 runtime validator SHA-256")
    require(sha256_bytes(validator_raw) == validator_sha,
            "SourceV5 runtime validator differs from its pin")
    control_baseline = _uint(
        prepared["source"]["resource_domain_calibration"]["record"]["fixed_global_control_baseline"],
        "fixed global control baseline", positive=True,
    )
    argv = controller.build_pair_runner_argv(
        runner_path, binary, job, prepared["prepared"]["host"]["controls"]["cpu_set"], runner_output,
        prepared["spec"]["deadlines"], job.get("arrivals") or 5000,
        candidate_oracle, baseline_binary, baseline_allocator, baseline_oracle,
        binding_path, manifest_sha, validator_path, validator_sha, control_baseline,
    )
    require(type(argv) is list and len(argv) <= 64 and all(
        type(item) is str and "\x00" not in item and len(item.encode("utf-8")) <= MAX_PATH_BYTES
        for item in argv
    ), "fixed pair runner argv exceeds its finite string/argument bounds")
    require(argv[0] == str(runner_path) and Path(argv[0]).is_absolute(),
            "fixed runner argv[0] differs from the pinned executable script")
    deadline = _uint(prepared["spec"]["deadlines"]["outer_seconds"],
                     "original fixed job outer deadline", positive=True,
                     maximum=MAX_TIMEOUT_SECONDS)
    phase_jobs = [item for item in prepared["plan"]["jobs"]["confirmation"]
                  if item["host_id"] == prepared["host_id"]]
    require(0 <= job_index < len(phase_jobs) and phase_jobs[job_index] == job,
            "fixed dispatch index differs from the original host job order")
    run_id = _token(job["run_id"], "fixed confirmation run ID")
    stdout_path = phase_dir / f"{job_index:06d}-{run_id}.stdout.log"
    stderr_path = phase_dir / f"{job_index:06d}-{run_id}.stderr.log"
    owner = _owner_marker(prepared, registration_head)
    return {
        "job_index": job_index, "job": job,
        "job_sha256": sha256_bytes(canonical_bytes(job)),
        "member_role": "campaign_pair_runner",
        "pair_members": bindings,
        "pair_members_sha256": sha256_bytes(canonical_bytes(bindings)),
        "runner": runner_pin,
        "argv": argv, "cwd": str(prepared["source_root"]),
        "environment": environment, "environment_sha256": environment_sha,
        "runner_output": str(runner_output),
        "runtime_bindings": {"path": str(binding_path), "sha256": manifest_sha,
                             "size": len(manifest_raw)},
        "runtime_manifest_raw": manifest_raw,
        "runtime_validator": {"path": str(validator_path), "sha256": validator_sha},
        "fixed_global_control_baseline": control_baseline,
        "outer_deadline_seconds": deadline,
        "campaign_artifacts_root": str(artifacts_root) if artifacts_root is not None else None,
        "shebang_interpreter": interpreter,
        "stdout_path": str(stdout_path), "stderr_path": str(stderr_path),
        "confirmation_owner_marker": owner,
        "phase_directory": str(phase_dir),
        "source_manifest_raw_sha256": prepared["prepared"]["source_raw_sha256"],
        "spec_raw_sha256": prepared["prepared"]["spec_raw_sha256"],
        "plan_raw_sha256": prepared["prepared"]["plan_raw_sha256"],
        "registration_head": registration_head,
        "qualification_eligible": False,
    }


def _owner_body(prepared: dict[str, Any], registration_head: str) -> dict[str, Any]:
    return {
        "schema": "allocatbelt.application-campaign-chronology-owner.v1",
        "campaign_id": prepared["campaign_id"], "host_id": prepared["host_id"],
        "original_pins_sha256": prepared["original_pins_sha256"],
        "registration_head": registration_head,
        "qualification_eligible": False,
    }


def _ensure_confirmation_directory(
    prepared: dict[str, Any], owner_pin: dict[str, str], registration_head: str,
) -> None:
    phase_dir = _phase_directory(prepared)
    campaign_dir = phase_dir.parent.parent
    _ensure_private_directory(campaign_dir)
    confirmation_parent = phase_dir.parent
    _ensure_private_directory(confirmation_parent)
    if phase_dir.exists() or phase_dir.is_symlink():
        info = phase_dir.lstat()
        require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and
                info.st_uid == os.getuid() and phase_dir.resolve(strict=True) == phase_dir,
                "confirmation host directory is not the private directory owned by this transaction")
    else:
        phase_dir.mkdir(mode=0o700)
        info = phase_dir.lstat()
        require(stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid(),
                "cannot establish private confirmation host directory")
        _fsync_directory(confirmation_parent)
    marker_path = Path(owner_pin["path"])
    require(marker_path == phase_dir / ".chronology-owner.json",
            "confirmation ownership marker escaped its host directory")
    expected_raw = canonical_bytes(_owner_body(prepared, registration_head))
    expected_sha = sha256_bytes(expected_raw)
    require(owner_pin["sha256"] == expected_sha, "confirmation ownership marker digest changed")
    if marker_path.exists() or marker_path.is_symlink():
        raw, info = _read_stable(marker_path, "confirmation chronology owner marker", 64 * 1024)
        require(stat.S_IMODE(info.st_mode) == 0o400 and info.st_uid == os.getuid() and
                raw == expected_raw and sha256_bytes(raw) == expected_sha,
                "confirmation directory is owned by a different chronology registration")
    else:
        _write_exclusive(marker_path, expected_raw, 0o400)


def _validate_dispatch_authorization(
    details_value: object, prepared: dict[str, Any], registration: dict[str, Any],
    registration_head: str,
) -> dict[str, Any]:
    details = _exact(details_value, DETAIL_FIELDS["dispatch_authorized"],
                     "authorized fixed confirmation dispatch")
    job_index = _uint(details["job_index"], "fixed confirmation job index")
    index, job, bindings = _job_for_authorization(prepared, details["job"])
    require(index == job_index and details["job_sha256"] ==
            sha256_bytes(canonical_bytes(job)),
            "dispatch job bytes/index differ from the exact original PlanV3 job")
    runner_pin = _exact(details["runner"], {"path", "sha256"},
                        "fixed confirmation runner pin")
    environment, environment_sha = _environment_snapshot(details["environment"])
    artifacts_root_value = details["campaign_artifacts_root"]
    artifacts_root = None if artifacts_root_value is None else Path(artifacts_root_value)
    spec = _launch_spec(
        prepared, index, job, bindings, runner_pin, artifacts_root, environment,
        registration_head,
    )
    expected_auth_material = {
        "campaign_id": prepared["campaign_id"], "host_id": prepared["host_id"],
        "run_id": job["run_id"], "job_sha256": spec["job_sha256"],
        "capacity_registration_head": registration_head,
    }
    expected_auth_id = "dispatch-" + sha256_bytes(canonical_bytes(expected_auth_material))[:48]
    outer_deadline = _uint(details["outer_deadline_seconds"],
                           "fixed confirmation outer deadline", positive=True,
                           maximum=MAX_TIMEOUT_SECONDS)
    effective_timeout = _uint(details["effective_timeout_seconds"],
                              "effective fixed dispatch timeout", positive=True,
                              maximum=MAX_TIMEOUT_SECONDS)
    require(effective_timeout <= outer_deadline == spec["outer_deadline_seconds"],
            "dispatch timeout exceeds its original fixed job deadline")
    require(details["authorization_id"] == expected_auth_id and
            details["member_role"] == "campaign_pair_runner" and
            details["pair_members"] == bindings and
            details["pair_members_sha256"] == spec["pair_members_sha256"] and
            details["capacity_registration_head"] == registration_head and
            details["capacity_completion_raw_sha256"] == registration["capacity_completion"]["sha256"] and
            details["capacity_ledger_raw_sha256"] == registration["capacity_ledger"]["raw_sha256"] and
            details["capacity_ledger_terminal_head"] == registration["capacity_ledger"]["terminal_head"] and
            details["capacity_schedule_sha256"] == registration["capacity_schedule_sha256"] and
            details["argv"] == spec["argv"] and details["cwd"] == spec["cwd"] and
            details["environment"] == environment and details["environment_sha256"] == environment_sha and
            details["runner_output"] == spec["runner_output"] and
            details["runtime_bindings"] == spec["runtime_bindings"] and
            details["runtime_validator"] == spec["runtime_validator"] and
            details["fixed_global_control_baseline"] == spec["fixed_global_control_baseline"] and
            details["outer_deadline_seconds"] == spec["outer_deadline_seconds"] and
            details["stdout_path"] == spec["stdout_path"] and
            details["stderr_path"] == spec["stderr_path"] and
            details["campaign_artifacts_root"] == spec["campaign_artifacts_root"] and
            details["shebang_interpreter"] == spec["shebang_interpreter"] and
            details["confirmation_owner_marker"] == spec["confirmation_owner_marker"] and
            details["qualification_eligible"] is False,
            "dispatch authorization differs from the original fixed job/capacity/source/runtime roles")
    return spec


@_serialize_locked_api
def authorize_dispatch_locked(
    lock: CampaignHostLock, plan_pin: object, spec_pin: object, source_root: Path,
    input_root: Path, host_id: str, observed_host_pin: object, output_root: Path,
    completion_pin: object, exact_job: object, pair_runner_path: Path,
    *, campaign_artifacts_root: Path | None = None,
    capacity_output_root: Path | None = None,
    effective_timeout_seconds: int | None = None,
) -> DispatchAuthorization:
    """Record/fsync one unique original fixed-pair authorization before Popen."""
    _require_owned_child_wait_semantics()
    # Reject inherited shell startup/import controls before source capture or
    # other expensive authorization validation. Freeze the environment that
    # this transaction will bind to its original fixed runner.
    environment, environment_sha = _environment_snapshot(dict(os.environ))
    prepared = _prepare_inputs(plan_pin, spec_pin, source_root, input_root, host_id,
                               observed_host_pin, output_root)
    lock = _check_lock(lock, prepared["output_root"], prepared["campaign_id"], host_id)
    state = _read_journal(lock, prepared)
    registration = state["registration"]
    require(registration is not None and state["pending"] is None,
            "fixed confirmation authorization requires one sealed capacity registration")
    require(state.get("cleanup_blocked") is False,
            "prior pair-runner cleanup is unclean or unverified; later dispatch is blocked")
    capacity_output = _safe_root(Path(capacity_output_root), "capacity evidence output root") \
        if capacity_output_root is not None else prepared["output_root"]
    capacity_details, _completion = _capacity_completion(prepared, capacity_output, completion_pin)
    require(_registration_fields(capacity_details) == _registration_fields(registration),
            "capacity completion changed after its locked registration")
    job_index, job, bindings = _job_for_authorization(prepared, exact_job)
    runner_pin = _inventory_runner_pin(prepared, pair_runner_path)
    _require_owned_child_wait_semantics()
    artifacts_root = Path(campaign_artifacts_root) if campaign_artifacts_root is not None else None
    dispatch = _launch_spec(
        prepared, job_index, job, bindings, runner_pin, artifacts_root, environment,
        state["registration_head"],
    )
    effective_timeout = dispatch["outer_deadline_seconds"] if effective_timeout_seconds is None else _uint(
        effective_timeout_seconds, "effective fixed dispatch timeout", positive=True,
        maximum=MAX_TIMEOUT_SECONDS,
    )
    require(effective_timeout <= dispatch["outer_deadline_seconds"],
            "effective dispatch timeout cannot exceed the original fixed job deadline")
    phase_dir = _phase_directory(prepared)
    if phase_dir.exists() or phase_dir.is_symlink():
        _verify_owner_marker(prepared, dispatch["confirmation_owner_marker"],
                             state["registration_head"], create=False)
    else:
        _require_no_legacy_confirmation(prepared)
    require(not Path(dispatch["runtime_bindings"]["path"]).exists() and
            not Path(dispatch["runtime_bindings"]["path"]).is_symlink() and
            not Path(dispatch["stdout_path"]).exists() and not Path(dispatch["stdout_path"]).is_symlink() and
            not Path(dispatch["stderr_path"]).exists() and not Path(dispatch["stderr_path"]).is_symlink(),
            "original confirmation job output already exists and cannot be retried")
    auth_material = {
        "campaign_id": prepared["campaign_id"], "host_id": host_id,
        "run_id": job["run_id"], "job_sha256": dispatch["job_sha256"],
        "capacity_registration_head": state["registration_head"],
    }
    authorization_id = "dispatch-" + sha256_bytes(canonical_bytes(auth_material))[:48]
    details = {
        "authorization_id": authorization_id,
        "job_index": job_index, "job": job, "job_sha256": dispatch["job_sha256"],
        "member_role": "campaign_pair_runner",
        "pair_members": bindings, "pair_members_sha256": dispatch["pair_members_sha256"],
        "capacity_registration_head": state["registration_head"],
        "capacity_completion_raw_sha256": registration["capacity_completion"]["sha256"],
        "capacity_ledger_raw_sha256": registration["capacity_ledger"]["raw_sha256"],
        "capacity_ledger_terminal_head": registration["capacity_ledger"]["terminal_head"],
        "capacity_schedule_sha256": registration["capacity_schedule_sha256"],
        "runner": runner_pin, "argv": dispatch["argv"], "cwd": dispatch["cwd"],
        "environment": environment, "environment_sha256": environment_sha,
        "runner_output": dispatch["runner_output"],
        "campaign_artifacts_root": dispatch["campaign_artifacts_root"],
        "shebang_interpreter": dispatch["shebang_interpreter"],
        "runtime_bindings": dispatch["runtime_bindings"],
        "runtime_validator": dispatch["runtime_validator"],
        "fixed_global_control_baseline": dispatch["fixed_global_control_baseline"],
        "outer_deadline_seconds": dispatch["outer_deadline_seconds"],
        "effective_timeout_seconds": effective_timeout,
        "stdout_path": dispatch["stdout_path"], "stderr_path": dispatch["stderr_path"],
        "confirmation_owner_marker": dispatch["confirmation_owner_marker"],
        "qualification_eligible": False,
    }
    _validate_dispatch_authorization(details, prepared, registration,
                                     state["registration_head"])
    record = _append_event(lock, prepared, "dispatch_authorized", details)
    return DispatchAuthorization(
        lock, prepared, prepared["plan_pin"], prepared["spec_pin"],
        prepared["source_root"], prepared["input_root"],
        {"path": str(prepared["prepared"]["host_context_path"]),
         "sha256": prepared["prepared"]["host_context_raw_sha256"]},
        capacity_output, capacity_details["capacity_completion"],
        details, record["monotonic_ns"],
    )


def _validate_bound_details(
    details_value: object, authorization: dict[str, Any], prepared: dict[str, Any],
) -> dict[str, Any]:
    details = _exact(details_value, DETAIL_FIELDS["dispatch_bound"],
                     "fixed pair-runner process binding")
    _verify_owner_marker(prepared, authorization["confirmation_owner_marker"],
                         authorization["capacity_registration_head"], create=False)
    pid = _uint(details["pid"], "actual pair-runner PID", positive=True,
                maximum=(1 << 31) - 1)
    start_ticks = _uint(details["start_ticks"], "actual pair-runner start ticks", positive=True)
    expected_interpreter = authorization["shebang_interpreter"]
    environment, environment_sha = _environment_snapshot(authorization["environment"])
    expected_members = [item["report_nonce"] for item in authorization["pair_members"]]
    runtime_manifest = prepared["controller"].runtime_binding_manifest_value(
        authorization["pair_members"], authorization["job"], prepared["spec"],
        prepared["source"],
    )
    runtime_raw = canonical_bytes(runtime_manifest)
    _verify_runtime_binding_file(authorization["runtime_bindings"], runtime_raw,
                                 prepared["output_root"])
    require(details["authorization_id"] == authorization["authorization_id"] and
            details["job_run_id"] == authorization["job"]["run_id"] and
            details["member_role"] == "campaign_pair_runner" and
            details["runner_path"] == authorization["runner"]["path"] and
            details["runner_sha256"] == authorization["runner"]["sha256"] and
            details["process_executable_path"] == expected_interpreter["path"] and
            details["process_executable_sha256"] == expected_interpreter["sha256"] and
            details["cwd"] == authorization["cwd"] and
            details["cpu_affinity"] == prepared["prepared"]["current_host"]["cpu_affinity"] and
            details["network_namespace_inode"] == prepared["prepared"]["current_host"]["network_namespace_inode"] and
            details["environment"] == environment and details["environment_sha256"] == environment_sha and
            details["actual_environment_sha256"] == environment_sha and
            details["process_report_nonce"] is None and
            details["member_report_nonces"] == expected_members and
            details["caller_role"] == "campaign_pair_runner" and
            details["pair_members_sha256"] == authorization["pair_members_sha256"] and
            details["capacity_registration_head"] == authorization["capacity_registration_head"] and
            details["qualification_eligible"] is False,
            "actual pair-runner PID/start/executable/cwd/affinity/environment binding differs from dispatch")
    return details


def _validate_exit_details(
    details_value: object, bound: dict[str, Any], authorization: dict[str, Any],
    prepared: dict[str, Any],
) -> dict[str, Any]:
    details = _exact(details_value, DETAIL_FIELDS["dispatch_exited"],
                     "fixed pair-runner exit record")
    pid = _uint(details["pid"], "pair-runner exit PID", positive=True,
                maximum=(1 << 31) - 1)
    return_code = details["return_code"]
    require(type(return_code) is int and pid == bound["pid"] and
            details["authorization_id"] == authorization["authorization_id"] and
            details["job_run_id"] == authorization["job"]["run_id"] and
            details["member_role"] == "campaign_pair_runner" and
            details["process_reaped"] is True and
            details["process_reap_status"] == "owned_reaped" and
            details["process_group_cleanup_status"] == "clean" and
            details["cleanup_error_sha256"] is None and
            details["capacity_registration_head"] == authorization["capacity_registration_head"] and
            details["qualification_eligible"] is False,
            "pair-runner exit differs from the actual bound process")
    elapsed_ns = _uint(details["elapsed_ns"], "pair-runner elapsed nanoseconds")
    require(elapsed_ns <= authorization["effective_timeout_seconds"] * 1_000_000_000,
            "pair-runner exit exceeded its authorized finite deadline")
    if return_code >= 0:
        require(details["status"] == "completed" and details["signal"] is None,
                "normally exited pair runner has contradictory signal metadata")
    else:
        require(details["status"] == "signaled" and details["signal"] == -return_code,
                "signaled pair runner has contradictory wait status")
    phase_dir = _phase_directory(prepared)
    expected = {
        "stdout": Path(authorization["stdout_path"]),
        "stderr": Path(authorization["stderr_path"]),
    }
    for name in ("stdout", "stderr"):
        pin = _exact(details[name], {"path", "sha256"}, f"pair-runner {name} pin")
        path = Path(pin["path"])
        require(path == expected[name] and _within(phase_dir, path),
                f"pair-runner {name} path escaped its host output")
        raw, info = _read_stable(path, f"pair-runner {name}", MAX_OUTPUT_BYTES)
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600 and
                sha256_bytes(raw) == _digest(pin["sha256"], f"pair-runner {name} SHA-256") and
                details[f"{name}_sha256"] == pin["sha256"] and
                len(raw) == details[f"{name}_size"] == _uint(
                    details[f"{name}_size"], f"pair-runner {name} size", maximum=MAX_OUTPUT_BYTES),
                f"pair-runner {name} bytes differ from the durable exit capture")
    return details


@_serialize_locked_api
def verify_campaign_chronology_locked(
    lock: CampaignHostLock, plan_pin: object, spec_pin: object, source_root: Path,
    input_root: Path, host_id: str, observed_host_pin: object, output_root: Path,
    completion_pin: object, *, capacity_output_root: Path | None = None,
) -> dict[str, Any]:
    """Replay the private transaction journal and reverify the registered capacity completion."""
    prepared = _prepare_inputs(plan_pin, spec_pin, source_root, input_root, host_id,
                               observed_host_pin, output_root)
    _check_lock(lock, prepared["output_root"], prepared["campaign_id"], host_id)
    state = _read_journal(lock, prepared)
    registration = state["registration"]
    require(registration is not None, "chronology journal has no sealed capacity registration")
    evidence_root = Path(capacity_output_root) if capacity_output_root is not None else prepared["output_root"]
    details, _completion = _capacity_completion(prepared, evidence_root, completion_pin)
    require(_registration_fields(details) == _registration_fields(registration),
            "chronology registration differs from a fresh full 15-entry capacity replay")
    pending = state["pending"]
    return {
        "schema": CHRONOLOGY_SCHEMA,
        "campaign_id": prepared["campaign_id"], "host_id": prepared["host_id"],
        "journal_path": str(_journal_path(lock)), "journal_head": state["head"],
        "journal_record_count": state["record_count"],
        "registration_head": state["registration_head"],
        "capacity_completion_raw_sha256": details["capacity_completion"]["sha256"],
        "capacity_ledger_raw_sha256": details["capacity_ledger"]["raw_sha256"],
        "capacity_ledger_terminal_head": details["capacity_ledger"]["terminal_head"],
        "capacity_schedule_sha256": details["capacity_schedule_sha256"],
        "entry_count": 15,
        "dispatch_event_count": state["dispatch_event_count"],
        "pending_authorization": pending is not None,
        "cleanup_blocked": state["cleanup_blocked"],
        "terminal_process_cleanup": state["process_cleanup"],
        "qualification_eligible": False,
        "execution_ready": False,
        "controller_chronology_proven": False,
        "api_transaction_order_proven": True,
    }


_SOURCE5_AUTH_OWNER = object()
_SOURCE5_AUTHORIZATION_TOKENS: dict[int, dict[str, Any]] = {}


class Source5JobAuthorization:
    """One-use capability for an inventory-pinned Source5 in-process helper."""

    __slots__ = (
        "lock", "prepared", "manifest_pin", "helper_input_pin", "helper_input",
        "helper_module", "helper_module_path", "details_value", "authorization_head",
        "start_monotonic_ns", "used", "_owner",
    )

    def __init__(
        self, lock: CampaignHostLock, prepared: dict[str, Any],
        manifest_pin: dict[str, str], helper_input_pin: dict[str, str],
        helper_input: dict[str, Any], helper_module: types.ModuleType,
        helper_module_path: Path, details_value: dict[str, Any],
        authorization_head: str, start_monotonic_ns: int,
    ):
        self.lock = lock
        self.prepared = prepared
        self.manifest_pin = dict(manifest_pin)
        self.helper_input_pin = dict(helper_input_pin)
        self.helper_input = _json_copy(helper_input)
        self.helper_module = helper_module
        self.helper_module_path = helper_module_path
        self.details_value = _json_copy(details_value)
        self.authorization_head = authorization_head
        self.start_monotonic_ns = start_monotonic_ns
        self.used = False
        self._owner = _SOURCE5_AUTH_OWNER
        with _AUTHORIZATION_TOKEN_LOCK:
            _SOURCE5_AUTHORIZATION_TOKENS[id(self)] = {
                "object": self, "lock": lock,
                "snapshot": _source5_authorization_snapshot(self),
                "consumed": False,
            }

    @property
    def details(self) -> dict[str, Any]:
        return _json_copy(self.details_value)


def _source5_authorization_snapshot(authorization: Source5JobAuthorization) -> bytes:
    return canonical_bytes({
        "lock": {
            "output_root": str(authorization.lock.output_root),
            "campaign_id": authorization.lock.campaign_id,
            "host_id": authorization.lock.host_id,
            "fd": authorization.lock.fd,
            "fd_key": list(authorization.lock._fd_key),
        },
        "manifest_pin": authorization.manifest_pin,
        "helper_input_pin": authorization.helper_input_pin,
        "helper_input": authorization.helper_input,
        "helper_module_path": str(authorization.helper_module_path),
        "helper_module_sha256": authorization.details_value["helper_module"]["sha256"],
        "helper_module_object_id": id(authorization.helper_module),
        "helper_entrypoint": authorization.helper_input["helper"]["entrypoint"],
        "helper_entrypoint_object_id": id(getattr(
            authorization.helper_module,
            authorization.helper_input["helper"]["entrypoint"], None,
        )),
        "details": authorization.details_value,
        "authorization_head": authorization.authorization_head,
        "start_monotonic_ns": authorization.start_monotonic_ns,
    })


def _consume_source5_authorization(
    lock: CampaignHostLock, authorization: object,
) -> Source5JobAuthorization:
    require(type(authorization) is Source5JobAuthorization and
            getattr(authorization, "_owner", None) is _SOURCE5_AUTH_OWNER,
            "Source5 helper launch requires a module-issued one-use authorization")
    with _AUTHORIZATION_TOKEN_LOCK:
        token = _SOURCE5_AUTHORIZATION_TOKENS.get(id(authorization))
        require(token is not None and token["object"] is authorization and
                token["lock"] is lock and not token["consumed"] and
                not authorization.used,
                "Source5 authorization is foreign, belongs to another lock, or was already consumed")
        require(token["snapshot"] == _source5_authorization_snapshot(authorization),
                "Source5 authorization changed after its durable journal event")
        token["consumed"] = True
        authorization.used = True
    return authorization


def _source5_capacity_manifest_record(
    manifest: dict[str, Any], host_id: str,
) -> dict[str, Any]:
    if manifest["schema"] == SOURCE5_EXECUTION_SCHEMA:
        return manifest["capacity_completions"][host_id]
    registration = manifest["prepared_capacity_registration"]
    return {
        "artifact": {
            "path": registration["host_completion"]["path"],
            "raw_sha256": registration["host_completion"]["raw_sha256"],
        },
        "schedule_sha256": registration["capacity_schedule_sha256"],
        "ledger_raw_sha256": registration["ledger"]["raw_sha256"],
        "terminal_head": registration["ledger"]["terminal_head"],
        "registration_head": registration["registration_head"],
    }


def _prepare_source5_context(
    lock: CampaignHostLock, execution_manifest_pin: object,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, str]]:
    pin = _exact(execution_manifest_pin, {"path", "sha256"},
                 "Source5 execution manifest pin")
    manifest, manifest_path, manifest_raw, manifest_sha = _read_pin(
        pin, "Source5 execution manifest", MAX_PLAN_BYTES,
    )
    info = manifest_path.stat(follow_symlinks=False)
    require(stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid(),
            "Source5 execution manifest must be an owned mode-0600 file")
    selected_host = lock.host_id
    original = _exact(manifest.get("original_inputs"), {
        "spec", "plan", "source_manifests", "campaign_artifacts_root",
    }, "Source5 original input pins")
    spec_ref = _exact(original["spec"], {"artifact", "semantic_sha256"},
                      "Source5 spec pin")
    plan_ref = _exact(original["plan"], {"artifact", "semantic_sha256"},
                      "Source5 plan pin")
    spec_artifact = _source5_artifact_pin(spec_ref["artifact"], "Source5 spec")
    plan_artifact = _source5_artifact_pin(plan_ref["artifact"], "Source5 plan")
    source_value = _exact(manifest.get("execution_sources"),
                          set(manifest.get("hosts", [])),
                          "Source5 execution source map")[selected_host]
    source_root = _safe_root(Path(source_value["source_root"]), "Source5 selected source root")
    observed_value = _exact(manifest.get("observed_hosts"),
                            set(manifest.get("hosts", [])),
                            "Source5 observed-host map")[selected_host]
    observed_artifact = _source5_artifact_pin(observed_value["artifact"],
                                               "Source5 selected observed host")
    output_root = _safe_root(Path(manifest["output_root"]), "Source5 output root")
    _check_lock(lock, output_root, manifest["campaign_id"], selected_host)
    prepared = _prepare_inputs(
        {"path": plan_artifact["path"], "sha256": plan_artifact["raw_sha256"]},
        {"path": spec_artifact["path"], "sha256": spec_artifact["raw_sha256"]},
        source_root, Path(spec_artifact["path"]).parent, selected_host,
        {"path": observed_artifact["path"], "sha256": observed_artifact["raw_sha256"]},
        output_root,
    )
    manifest = _validate_source5_manifest_value(manifest, manifest_raw, prepared)
    require(prepared["campaign_id"] == lock.campaign_id and
            prepared["host_id"] == selected_host,
            "Source5 manifest differs from the active chronology lock identity")
    prepared["source5_execution_schema"] = manifest["schema"]
    prepared["source5_execution_manifest_raw_sha256"] = manifest_sha
    scope = ("prospective_exploration" if
             manifest["schema"] == SOURCE5_EXECUTION_SCHEMA else
             manifest["scope"])
    prepared["source5_journal_event_projection"] = _source5_plan_event_projection(
        prepared["plan"], {"host_id": selected_host, "scope": scope}, manifest,
    )
    prepared["source5_journal_event_ceiling"] = \
        prepared["source5_journal_event_projection"]["maximum_callback_events"]
    prepared["source5_journal_byte_ceiling"] = \
        prepared["source5_journal_event_projection"]["maximum_journal_bytes"]
    state = _read_journal(lock, prepared)
    if manifest["schema"] == SOURCE5_EXECUTION_SCHEMA:
        registration = state["registration"]
        require(registration is not None,
                "Source5 v1 execution requires its unchanged 15-entry stage-v1 registration")
        capacity = manifest["capacity_completions"][selected_host]
        require(capacity["artifact"] == {
                    "path": registration["capacity_completion"]["path"],
                    "raw_sha256": registration["capacity_completion"]["sha256"],
                } and capacity["schedule_sha256"] == registration["capacity_schedule_sha256"] and
                capacity["ledger_raw_sha256"] == registration["capacity_ledger"]["raw_sha256"] and
                capacity["terminal_head"] == registration["capacity_ledger"]["terminal_head"] and
                capacity["registration_head"] == state["registration_head"],
                "Source5 selected capacity completion differs from the sealed full 15-entry journal replay")
    else:
        registration = state["prepared_capacity_registration"]
        manifest_registration = manifest["prepared_capacity_registration"]
        require(registration is not None and
                state["registration"] is None and
                manifest_registration["registration_head"] ==
                    state["registration_head"] and
                manifest_registration["completion"] ==
                    registration["completion"] and
                manifest_registration["host_completion"] ==
                    registration["host_completion"] and
                manifest_registration["host_verification"] ==
                    registration["host_verification"] and
                manifest_registration["ledger"] ==
                    registration["capacity_ledger"] and
                manifest_registration["capacity_schedule_sha256"] ==
                    registration["capacity_schedule_sha256"],
                "Source5 v2 selected host lacks the exact registered prepared-capacity bridge/ledger")
    manifest_pin = {"path": str(manifest_path), "sha256": manifest_sha}
    prepared["source5_execution_manifest_pin"] = {
        "path": str(manifest_path), "raw_sha256": manifest_sha,
    }
    return manifest, prepared, state, manifest_pin


@_serialize_locked_api
def authorize_source5_job_locked(
    lock: CampaignHostLock, execution_manifest_pin: object,
    exact_job: object, helper_input_pin: object, *,
    effective_timeout_seconds: int | None = None,
) -> Source5JobAuthorization:
    """Fsync one unique original Source5 job authorization before helper work."""
    manifest, prepared, state, manifest_pin = _prepare_source5_context(
        lock, execution_manifest_pin,
    )
    helper_pin = _source5_artifact_pin(helper_input_pin, "Source5 helper input")
    helper_path, helper_raw, helper_input_sha = _source5_reference(
        helper_pin, "Source5 helper input",
    )
    helper_info = helper_path.stat(follow_symlinks=False)
    require(stat.S_IMODE(helper_info.st_mode) == 0o600 and
            helper_info.st_uid == os.getuid(),
            "Source5 helper input must be an owned mode-0600 file")
    helper_input = _parse_object(helper_raw, "Source5 helper input", MAX_PLAN_BYTES)
    require(helper_input.get("schema") == SOURCE5_HELPER_INPUT_SCHEMA,
            "unsupported Source5 helper input schema")
    phase = helper_input.get("phase")
    require(type(exact_job) is dict and helper_input.get("job") == exact_job,
            "Source5 exact_job differs from the canonical helper input")
    host_jobs = [job for job in prepared["plan"]["jobs"].get(phase, [])
                 if type(job) is dict and job.get("host_id") == prepared["host_id"]]
    matches = [index for index, job in enumerate(host_jobs) if job == exact_job]
    require(len(matches) == 1 and helper_input.get("job_index") == matches[0],
            "Source5 helper input job/index is not the exact unique original host-plan entry")
    if effective_timeout_seconds is not None:
        requested_timeout = _uint(
            effective_timeout_seconds, "Source5 effective job timeout",
            positive=True, maximum=MAX_TIMEOUT_SECONDS,
        )
        require(requested_timeout == helper_input.get("effective_timeout_seconds"),
                "Source5 effective timeout must be frozen in the canonical helper input")
    if phase in {"pressure", "soak"}:
        job_output_root = Path(helper_input["payload"]["output_root"])
    else:
        overlay_pin = helper_input["payload"]["overlay_pin"]
        overlay_raw, overlay_info = _read_stable(
            Path(overlay_pin["path"]), "Source5 fixed-pair overlay", MAX_PLAN_BYTES,
        )
        require(stat.S_IMODE(overlay_info.st_mode) == 0o600 and
                overlay_info.st_uid == os.getuid(),
                "Source5 fixed-pair overlay must remain an owned private file")
        overlay_value = _parse_object(overlay_raw, "Source5 fixed-pair overlay", MAX_PLAN_BYTES)
        require(sha256_bytes(overlay_raw) == overlay_pin["sha256"],
                "Source5 fixed-pair overlay differs from its raw pin")
        job_output_root = Path(overlay_value.get("output_root", ""))
    details_base = {
        "campaign_id": prepared["campaign_id"], "host_id": prepared["host_id"],
        "phase": phase, "job_index": matches[0], "job": exact_job,
        "job_sha256": sha256_bytes(canonical_bytes(exact_job)),
        "members": helper_input.get("members"),
        "members_sha256": sha256_bytes(canonical_bytes(helper_input.get("members"))),
        "execution_manifest": {"path": manifest_pin["path"],
                               "raw_sha256": manifest_pin["sha256"]},
        "helper_input": {"path": str(helper_path),
                          "raw_sha256": helper_input_sha},
        "capacity_registration_head": state["registration_head"],
        "capacity_completion": _source5_capacity_manifest_record(
            manifest, prepared["host_id"],
        )["artifact"],
        "capacity_ledger_raw_sha256": _source5_capacity_manifest_record(
            manifest, prepared["host_id"],
        )["ledger_raw_sha256"],
        "capacity_terminal_head": _source5_capacity_manifest_record(
            manifest, prepared["host_id"],
        )["terminal_head"],
        "capacity_schedule_sha256": _source5_capacity_manifest_record(
            manifest, prepared["host_id"],
        )["schedule_sha256"],
        "prerequisites": helper_input.get("prerequisites"),
        "outer_deadline_seconds": helper_input.get("outer_deadline_seconds"),
        "effective_timeout_seconds": helper_input.get("effective_timeout_seconds"),
        "input_snapshot_sha256": helper_input.get("input_snapshot_sha256"),
        "output_root": str(job_output_root),
        "qualification_eligible": False,
    }
    helper = _exact(helper_input.get("helper"), {"path", "sha256", "entrypoint"},
                     "Source5 helper pin")
    helper_relative = _relative(helper["path"], "Source5 helper module path").as_posix()
    _raw, helper_sha, helper_inventory = _source_file(
        prepared["source_root"], prepared["source"], helper_relative,
        "Source5 helper module", maximum=MAX_SCRIPT_BYTES,
    )
    module_pin = manifest["modules"][prepared["host_id"]][helper_relative]
    require(module_pin == {"path": helper_relative, "sha256": helper_sha},
            "Source5 helper module differs from the closed execution manifest pin")
    details_base["helper_module"] = {
        "path": helper_relative, "sha256": helper_sha,
        "size": helper_inventory["size"], "mode": helper_inventory["mode"],
        "kind": helper_inventory["kind"],
    }
    _validate_source5_prerequisites(phase, helper_input.get("prerequisites"), state)
    details = {
        **details_base,
        "authorization_id": "source5-" + sha256_bytes(canonical_bytes(details_base))[:48],
    }
    _validate_source5_authorization(details, prepared, state)
    helper_raw, helper_sha, _helper_record = _source_file(
        prepared["source_root"], prepared["source"], helper_relative,
        "Source5 executable helper", maximum=MAX_SCRIPT_BYTES,
    )
    helper_module = _load_module(
        helper_raw, prepared["source_root"] / helper_relative,
        f"source5_{phase}_helper",
    )
    authorization_record = _append_event(
        lock, prepared, "source5_authorized", details,
    )
    return Source5JobAuthorization(
        lock, prepared, manifest_pin,
        {"path": str(helper_path), "raw_sha256": helper_input_sha},
        helper_input, helper_module, prepared["source_root"] / helper_relative,
        details, authorization_record["record_sha256"], time.monotonic_ns(),
    )


@_serialize_locked_api
def source5_chronology_snapshot_locked(
    lock: CampaignHostLock, execution_manifest_pin: object,
) -> dict[str, Any]:
    """Seal the current registered capacity/job heads before one pressure recipe."""
    manifest, prepared, state, manifest_pin = _prepare_source5_context(
        lock, execution_manifest_pin,
    )
    require(state["pending"] is None and state["source5_pending"] is None and
            state["cleanup_blocked"] is False and
            state["source5_cleanup_blocked"] is False,
            "Source5 chronology snapshot is blocked by an unresolved or unsafe job")
    capacity = _source5_capacity_manifest_record(manifest, prepared["host_id"])
    return {
        "schema": "allocatbelt.application-source5-chronology-snapshot.v1",
        "campaign_id": prepared["campaign_id"],
        "host_id": prepared["host_id"],
        "execution_manifest": {"path": manifest_pin["path"],
                               "raw_sha256": manifest_pin["sha256"]},
        "observed_host": manifest["observed_hosts"][prepared["host_id"]]["artifact"],
        "output_root": str(prepared["output_root"]),
        "capacity_output_root": str(prepared["output_root"]),
        "journal_head": state["head"],
        "journal_record_count": state["record_count"],
        "registration_head": state["registration_head"],
        "dispatch_event_count": state["dispatch_event_count"],
        "capacity_completion": capacity["artifact"],
        "capacity_schedule_sha256": capacity["schedule_sha256"],
        "capacity_ledger_raw_sha256": capacity["ledger_raw_sha256"],
        "capacity_terminal_head": capacity["terminal_head"],
        "qualification_eligible": False,
    }


def _source5_append_app_started(
    lock: CampaignHostLock, prepared: dict[str, Any], authorization_id: str,
    event: object,
) -> dict[str, Any]:
    require(type(event) is dict, "Source5 helper APP-start callback is not an object")
    state = _read_journal(lock, prepared)
    prior = state["source5_authorized"].get(authorization_id)
    require(prior is not None and state["source5_pending"] == authorization_id,
            "Source5 APP-start callback has no pending durable authorization")
    index = len(prior["starts"])
    require(index < len(prior["details"]["members"]),
            "Source5 helper reported more APP starts than authorized members")
    descriptor = prior["details"]["members"][index]
    require(event.get("campaign_id") == prepared["campaign_id"] and
            event.get("host_id") == prepared["host_id"] and
            event.get("run_id") == prior["details"]["job"]["run_id"] and
            event.get("descriptor") == descriptor and
            event.get("member_ordinal") == index,
            "Source5 helper APP-start callback differs from the next authorized member")
    pid, start_ticks = _source5_proof_identity(event)
    require(all((item["pid"], item["start_ticks"]) != (pid, start_ticks)
                for item in prior["starts"]),
            "Source5 APP-start callback repeats a PID/start identity")
    details = {
        "authorization_id": authorization_id, "member_index": index,
        "descriptor": descriptor, "pid": pid, "start_ticks": start_ticks,
        "proof_sha256": sha256_bytes(canonical_bytes(event)), "proof": event,
        "qualification_eligible": False,
    }
    return _append_event(lock, prepared, "source5_app_started", details)


def _source5_append_app_terminal(
    lock: CampaignHostLock, prepared: dict[str, Any], authorization_id: str,
    event: object,
) -> dict[str, Any]:
    require(type(event) is dict, "Source5 helper APP-terminal callback is not an object")
    state = _read_journal(lock, prepared)
    prior = state["source5_authorized"].get(authorization_id)
    require(prior is not None and state["source5_pending"] == authorization_id,
            "Source5 APP-terminal callback has no pending durable authorization")
    index = len(prior["terminals"])
    require(index < len(prior["starts"]),
            "Source5 helper reported an APP terminal before an actual APP start")
    start = prior["starts"][index]
    require(event.get("campaign_id") == prepared["campaign_id"] and
            event.get("host_id") == prepared["host_id"] and
            event.get("run_id") == prior["details"]["job"]["run_id"] and
            event.get("member_ordinal") == index and
            event.get("descriptor") == start["descriptor"] and
            event.get("pid") == start["pid"],
            "Source5 helper APP-terminal callback differs from the actual started member")
    status = event.get("status")
    require(type(status) is int and 0 <= status <= 255,
            "Source5 APP terminal status is malformed")
    cleanup = event.get("cleanup")
    require(type(cleanup) is dict,
            "Source5 APP terminal omitted direct supervisor cleanup evidence")
    raw_return = event.get("child_return_code")
    if raw_return is None:
        raw_return = cleanup.get("child_return_code", cleanup.get("return_code"))
    signal_number = event.get("signal")
    if signal_number is None:
        observed_signal = cleanup.get("received_signal")
        if type(observed_signal) is int:
            signal_number = observed_signal
        elif type(raw_return) is int and raw_return < 0:
            signal_number = -raw_return
    if type(raw_return) is int and raw_return < 0:
        require(signal_number == -raw_return and (
                    status in {125, 128 + signal_number} or
                    (status == 124 and cleanup.get("timed_out") is True)
                ),
                "Source5 signal terminal did not retain the raw child code and normalized status")
    elif raw_return is None:
        require(signal_number is None and status == 125,
                "Source5 terminal without a raw child result must use normalized launch-failure status")
    else:
        require(type(raw_return) is int and 0 <= raw_return <= 255 and
                signal_number is None and status in {raw_return, 124, 125},
                "Source5 normal terminal status differs from its raw child result")
    terminal_ns = event.get("terminal_monotonic_ns")
    _uint(terminal_ns, "Source5 APP terminal monotonic timestamp", positive=True)
    details = {
        "authorization_id": authorization_id, "member_index": index,
        "descriptor": start["descriptor"], "pid": start["pid"],
        "status": status, "child_return_code": raw_return,
        "signal": signal_number, "cleanup": cleanup,
        "terminal_monotonic_ns": terminal_ns,
        "qualification_eligible": False,
    }
    return _append_event(lock, prepared, "source5_app_terminal", details)


def _preflight_authorized_source5_helper(
    lock: CampaignHostLock, authorization: Source5JobAuthorization,
) -> dict[str, Any] | None:
    """Reconstruct the exact authorized payload before any execution helper can launch APPs."""
    prepared = authorization.prepared
    details = authorization.details
    helper_input = authorization.helper_input
    module = authorization.helper_module
    payload = helper_input["payload"]
    job = details["job"]
    if details["phase"] in {"exploration", "aa", "confirmation"}:
        overlay_pin = payload["overlay_pin"]
        overlay, raw, overlay_sha, overlay_context, reconstructed = module._read_overlay(
            overlay_pin,
        )
        require(overlay_sha == overlay_pin["sha256"] and
                overlay["job"]["value"] == job and
                overlay["job"]["sha256"] == details["job_sha256"] and
                overlay["campaign_id"] == prepared["campaign_id"] and
                overlay["host_id"] == prepared["host_id"] and
                overlay_context["job"] == job and
                reconstructed["job"] == overlay["job"],
                "Source5 fixed overlay reconstructs a different authorized original job")
        original = prepared["original_pins"]
        require(overlay["spec"]["pin"] == {
                    "path": original["spec"]["path"],
                    "sha256": original["spec"]["raw_sha256"],
                } and overlay["spec"]["semantic_sha256"] == original["spec"]["semantic_sha256"] and
                overlay["plan"]["pin"] == {
                    "path": original["plan"]["path"],
                    "sha256": original["plan"]["raw_sha256"],
                } and overlay["plan"]["semantic_sha256"] == original["plan"]["semantic_sha256"],
                "Source5 fixed overlay SpecV3/PlanV3 pins differ from its authorization")
        expected_manifests = {
            item["host_id"]: {
                "pin": {"path": item["path"], "sha256": item["raw_sha256"]},
                "manifest_sha256": item["semantic_sha256"],
            }
            for item in original["source_manifests"]
        }
        require(overlay["sources"]["manifests"] == expected_manifests and
                overlay["sources"]["selected"]["root"] == str(prepared["source_root"]) and
                overlay["sources"]["selected"]["host_id"] == prepared["host_id"] and
                overlay["sources"]["observed_host"]["pin"] == {
                    "path": original["observed_host"]["path"],
                    "sha256": original["observed_host"]["raw_sha256"],
                } and
                overlay["output_root"] == details["output_root"],
                "Source5 fixed overlay source/host/output pins differ from its authorization")
        descriptors = [member["descriptor"] for member in overlay["members"]]
        require(descriptors == details["members"] and len(descriptors) == 2,
                "Source5 fixed overlay member order differs from its durable authorization")
        del raw
        return None

    if details["phase"] == "soak":
        source_module = sys.modules.get(__name__)
        require(source_module is not None,
                "Source5 Soak preflight requires the original loaded chronology module")
        preflight = module.prepare_source5_soak(
            helper_input, prepared, details,
        )
        require(type(preflight) is dict and
                preflight.get("schema") ==
                "allocatbelt.application-source5-soak-preflight.v1" and
                preflight.get("readback_module") is not None,
                "Source5 Soak adapter did not return its same-source prelaunch audit")
        return preflight

    require(details["phase"] == "pressure",
            "Source5 execution helper has no preflight adapter for this phase")
    recipe_path, recipe_raw, recipe_sha = _source5_reference(
        payload["recipe_pin"], "Source5 pressure recipe",
    )
    require(recipe_sha == payload["recipe_pin"]["raw_sha256"],
            "Source5 pressure recipe changed after authorization")
    recipe = _parse_object(recipe_raw, "Source5 pressure recipe", MAX_PLAN_BYTES)
    source_module = sys.modules.get(__name__)
    require(source_module is not None,
            "Source5 pressure preflight requires the original loaded chronology module")
    module._prepare_prerequisites(
        recipe, Path(payload["output_root"]),
        chronology_module=source_module, lock=lock,
        authorization_context=details,
    )
    del recipe_path
    return None


def _retain_source5_soak_failure_sidecars(
    output_root: Path, authorization_id: str, error_sha256: str,
    started: list[dict[str, Any]], terminal: list[dict[str, Any]],
) -> tuple[dict[str, str] | None, str | None]:
    names = (
        "soak-preflight.json", "soak-launch.json", "soak-postflight.json",
        "soak-readback.json", "soak-receipt.json",
        "soak-supervisor-interruption.json", "source5-soak-supervisor.json",
    )
    retained: list[dict[str, str]] = []
    failures: list[dict[str, str]] = []
    for name in names:
        path = output_root / name
        if not path.exists() and not path.is_symlink():
            continue
        try:
            raw, raw_sha, _info = _read_stable(
                path, f"Source5 failed Soak sidecar {name}", MAX_PLAN_BYTES,
            )
            del raw
            retained.append({"path": str(path), "raw_sha256": raw_sha})
        except BaseException as error:
            failures.append({
                "path": str(path),
                "error_sha256": sha256_bytes(
                    f"{type(error).__name__}:{error}".encode("utf-8", "replace"),
                ),
            })
    failure = {
        "schema": "allocatbelt.application-source5-soak-failure.v1",
        "authorization_id": authorization_id,
        "error_sha256": error_sha256,
        "app_start_events": [item["event"] for item in started],
        "app_terminal_events": [item["event"] for item in terminal],
        "retained_sidecars": retained,
        "sidecar_read_failures": failures,
        "qualification_eligible": False,
    }
    path = output_root / "source5-soak-failure.json"
    raw = canonical_bytes(failure)
    try:
        _write_exclusive(path, raw, 0o600)
        return {"path": str(path), "raw_sha256": sha256_bytes(raw)}, None
    except BaseException as error:
        return None, sha256_bytes(
            f"{type(error).__name__}:{error}".encode("utf-8", "replace"),
        )


@_serialize_locked_api
def run_authorized_source5_job_locked(
    lock: CampaignHostLock, authorization: Source5JobAuthorization,
) -> dict[str, Any]:
    """Consume one Source5 capability and run its exact pinned helper once."""
    authorization = _consume_source5_authorization(lock, authorization)
    prepared = authorization.prepared
    details = authorization.details
    job = details["job"]
    deadline_ns = authorization.start_monotonic_ns + \
        details["effective_timeout_seconds"] * 1_000_000_000
    watchdog = _Source5DeadlineWatchdog(deadline_ns)
    start_events: list[dict[str, Any]] = []
    terminal_events: list[dict[str, Any]] = []

    def on_app_started(event: dict[str, Any]) -> None:
        with watchdog.defer_during_journal_append():
            recorded = _source5_append_app_started(
                lock, prepared, details["authorization_id"], event,
            )
        start_events.append({"event": _json_copy(event),
                             "journal_head": recorded["record_sha256"]})

    def on_app_terminal(event: dict[str, Any]) -> None:
        with watchdog.defer_during_journal_append():
            recorded = _source5_append_app_terminal(
                lock, prepared, details["authorization_id"], event,
            )
        terminal_events.append({"event": _json_copy(event),
                                "journal_head": recorded["record_sha256"]})

    helper_input = authorization.helper_input
    payload = helper_input["payload"]
    module = authorization.helper_module
    result: dict[str, Any] | None = None
    soak_component_pin: dict[str, str] | None = None
    process_metrics: list[dict[str, Any]] = []
    status = "blocked"
    error_sha256: str | None = None
    helper_preflight_succeeded = False
    try:
        with watchdog:
            soak_preflight = _preflight_authorized_source5_helper(lock, authorization)
            helper_preflight_succeeded = True
            if details["phase"] in {"exploration", "aa", "confirmation"}:
                receipt_pin = module.run_fixed_pair_overlay(
                    payload["overlay_pin"], on_app_started, on_app_terminal,
                )
                verification = module.verify_fixed_pair_overlay(
                    payload["overlay_pin"], receipt_pin,
                )
                receipt_path, receipt_raw, receipt_sha = _source5_reference(
                    {"path": receipt_pin["path"], "raw_sha256": receipt_pin["sha256"]},
                    "verified fixed-pair receipt",
                )
                receipt = _parse_object(receipt_raw, "verified fixed-pair receipt",
                                        module.MAX_RECEIPT_BYTES)
                require(verification.get("verified") is True and
                        verification.get("status") == receipt.get("status") and
                        verification.get("receipt_sha256") == receipt_sha and
                        receipt.get("qualification_eligible") is False and
                        receipt.get("inputs_unchanged") is True,
                        "fixed-pair component receipt did not freshly verify its pinned immutable inputs")
                process_metrics = receipt.get("process_metrics", [])
                require(type(process_metrics) is list,
                        "fixed-pair receipt process metrics are malformed")
                component = {
                    "schema": "allocatbelt.application-source5-fixed-component.v1",
                    "overlay": {"path": payload["overlay_pin"]["path"],
                                "raw_sha256": payload["overlay_pin"]["sha256"]},
                    "receipt": {"path": str(receipt_path), "raw_sha256": receipt_sha},
                    "verification": verification,
                }
                status = "valid_pair" if verification["status"] == "valid_pair" else "invalid_pair"
            elif details["phase"] == "pressure":
                recipe_path, _recipe_raw, recipe_sha = _source5_reference(
                    payload["recipe_pin"], "Source5 pressure recipe",
                )
                chronology_module = sys.modules.get(__name__)
                require(chronology_module is not None,
                        "Source5 pressure helper requires the same loaded chronology module instance")
                result = module.run_pressure_pair_locked(
                    recipe_path, recipe_sha, Path(payload["output_root"]),
                    chronology_module=chronology_module,
                    lock=lock, authorization_context=details,
                    on_app_started=on_app_started, on_app_terminal=on_app_terminal,
                )
                require(type(result) is dict and result.get("validated") is True and
                        result.get("qualification_eligible") is False,
                        "locked pressure helper did not return an independently validated component receipt")
                process_metrics = result.get("pressure_metrics", [])
                require(type(process_metrics) is list,
                        "locked pressure helper returned malformed process metrics")
                component = result
                status = "valid_pair" if len(process_metrics) == 2 else "invalid_pair"
            elif details["phase"] == "soak":
                require(type(soak_preflight) is dict,
                        "Source5 Soak locked preflight did not return its captured context")
                component = module.run_source5_soak(
                    soak_preflight, on_app_started, on_app_terminal,
                )
                require(type(component) is dict and
                        component.get("schema") ==
                        "allocatbelt.application-source5-soak-component.v1" and
                        component.get("validated") is True and
                        component.get("qualification_eligible") is False and
                        component.get("launch_enabled") is True and
                        type(component.get("passed")) is bool and
                        component.get("prepared_host_binding_sha256") ==
                            payload["prepared_host_binding_sha256"] and
                        component.get("application_cleanup", {}).get("status") ==
                            "verified" and component.get("pressure_cleanup") ==
                            "verified",
                        "Source5 Soak failed its exact full-horizon postflight or cleanup replay")
                process_metrics = [component["readback"]]
                require(type(component["readback"]) is dict and
                        component["readback"].get("validated") is True and
                        component["readback"].get("qualification_eligible") is True and
                        component["readback"].get("passed") is component["passed"],
                        "Source5 Soak component does not retain its exact passing raw component gate")
                component_path = Path(details["output_root"]) / "source5-soak-component.json"
                component_raw = canonical_bytes(component)
                _write_exclusive(component_path, component_raw, 0o600)
                soak_component_pin = {
                    "path": str(component_path),
                    "raw_sha256": sha256_bytes(component_raw),
                }
                status = "valid_soak" if component["passed"] else "invalid_soak"
            else:
                raise ChronologyError("Source5 helper phase has no locked adapter")
            callback_count = 1 if details["phase"] == "soak" else 2
            require(len(start_events) == len(terminal_events) == callback_count,
                    "Source5 helper returned without the exact actual APP callback count")
            require(all(
                item["event"]["status"] == 0 and
                _source5_cleanup_is_clean(item["event"].get("cleanup"))
                for item in terminal_events
            ), "Source5 APP lifecycle did not finish successfully with verified cleanup")
            expected_metrics = 1 if details["phase"] == "soak" else 2
            require(len(process_metrics) == expected_metrics and
                    all(type(item) is dict for item in process_metrics),
                    "Source5 component process-metric count differs from its original phase")
    except BaseException as error:
        if isinstance(error, KeyboardInterrupt):
            watchdog._fail_lifecycle("authorization_interrupted", error)
        error_sha256 = sha256_bytes(
            f"{type(error).__name__}:{error}".encode("utf-8", "replace"),
        )
        component = {
            "schema": "allocatbelt.application-source5-component-failure.v1",
            "error_type": type(error).__name__, "error_sha256": error_sha256,
        }
        if details["phase"] == "soak":
            soak_component_pin, retention_error_sha256 = _retain_source5_soak_failure_sidecars(
                Path(details["output_root"]), details["authorization_id"],
                error_sha256, start_events, terminal_events,
            )
            if soak_component_pin is not None:
                component["retained_failure"] = soak_component_pin
            if retention_error_sha256 is not None:
                component["retention_error_sha256"] = retention_error_sha256
        if watchdog.lifecycle_failed or watchdog.expired:
            status = "blocked"
        elif (details["phase"] != "soak" and len(start_events) == 2 and
              len(terminal_events) == 2 and all(
            _source5_cleanup_is_clean(item["event"].get("cleanup"))
            for item in terminal_events
        )):
            status = "invalid_pair"
        else:
            status = "blocked"
        process_metrics = []
    component_sha256 = sha256_bytes(canonical_bytes(component))
    metrics_sha256 = sha256_bytes(canonical_bytes(process_metrics))
    state = _read_journal(lock, prepared)
    prior = state["source5_authorized"].get(details["authorization_id"])
    require(prior is not None and state["source5_pending"] == details["authorization_id"],
            "Source5 authorization changed during component execution")
    start_head = state["head"]
    if status != "blocked":
        blocked_reason = None
    elif watchdog.lifecycle_failed:
        blocked_reason = "deadline_watchdog_unverified"
    elif watchdog.expired:
        blocked_reason = "effective_deadline_exceeded"
    elif len(prior["terminals"]) < len(prior["starts"]):
        blocked_reason = "incomplete_app_lifecycle"
    elif any(not _source5_cleanup_is_clean(item["cleanup"])
             for item in prior["terminals"]):
        blocked_reason = "owned_cleanup_unverified"
    elif details["phase"] == "soak" and helper_preflight_succeeded:
        blocked_reason = "component_postflight_failed"
    else:
        blocked_reason = "helper_preflight_failed"
    job_terminal = {
        "authorization_id": details["authorization_id"],
        "state": status, "blocked_reason": blocked_reason,
        "component_sha256": component_sha256,
        "process_metrics_sha256": metrics_sha256,
        "started_count": len(prior["starts"]),
        "terminal_count": len(prior["terminals"]),
        "qualification_eligible": False,
    }
    terminal_record = _append_event(
        lock, prepared, "source5_job_terminal", job_terminal,
    )
    output = {
        "schema": "allocatbelt.application-source5-verified-job.v1",
        "state": status, "job": job, "job_sha256": details["job_sha256"],
        "component": component, "component_sha256": component_sha256,
        "process_metrics": process_metrics,
        "process_metrics_sha256": metrics_sha256,
        "evidence": {
            "execution_manifest": details["execution_manifest"],
            "helper_input": details["helper_input"],
            "helper_module": details["helper_module"],
            **({"overlay": component["overlay"], "receipt": component["receipt"]}
               if details["phase"] != "pressure" and
               type(component) is dict and "overlay" in component and
               "receipt" in component else {}),
            **({"pressure": component.get("readback"),
                "recipe": payload.get("recipe_pin")}
               if details["phase"] == "pressure" and type(component) is dict else {}),
            **({"soak_component": soak_component_pin}
               if details["phase"] == "soak" and soak_component_pin is not None else {}),
        },
        "chronology": {
            "authorization_id": details["authorization_id"],
            "authorization_head": authorization.authorization_head,
            "app_started_heads": [item["journal_head"] for item in start_events],
            "app_terminal_heads": [item["journal_head"] for item in terminal_events],
            "job_terminal_head": terminal_record["record_sha256"],
            "head_before_job_terminal": start_head,
            "app_start_events": [item["event"] for item in start_events],
            "app_terminal_events": [item["event"] for item in terminal_events],
        },
        "error_sha256": error_sha256,
        "qualification_eligible": False,
    }
    return output


@_serialize_locked_api
def record_source5_analysis_locked(
    lock: CampaignHostLock, execution_manifest_pin: object,
    analysis_pin: object,
) -> dict[str, Any]:
    """Seal one fresh per-host phase analysis for later prerequisite checks."""
    manifest, prepared, state, _manifest_pin = _prepare_source5_context(
        lock, execution_manifest_pin,
    )
    analysis_artifact = _source5_artifact_pin(analysis_pin, "Source5 analysis")
    _, analysis_raw, analysis_sha = _source5_reference(
        analysis_artifact, "Source5 analysis",
    )
    analysis = _parse_object(analysis_raw, "Source5 phase analysis", MAX_EVENT_BYTES)
    require(analysis.get("schema") == "allocatbelt.application-source5-phase-analysis.v1" and
            analysis.get("campaign_id") == prepared["campaign_id"] and
            analysis.get("host_id") == prepared["host_id"],
            "Source5 analysis artifact is not bound to this campaign/host")
    phase = analysis.get("phase")
    source_phase = {"fixed_analysis": "confirmation",
                    "pressure_analysis": "pressure",
                    "final_analysis": "soak"}.get(phase, phase)
    expected_jobs = [job for job in prepared["plan"]["jobs"].get(source_phase, [])
                     if type(job) is dict and job.get("host_id") == prepared["host_id"]]
    expected_ids = [job["run_id"] for job in expected_jobs]
    details = {
        "phase": phase,
        "analysis": analysis_artifact,
        "analysis_sha256": analysis_sha,
        "job_count": len(expected_ids),
        "job_set_sha256": sha256_bytes(canonical_bytes(expected_ids)),
        "job_evidence_complete": analysis.get("job_evidence_complete"),
        "numeric_gates_passed": analysis.get("numeric_gates_passed"),
        "phase_gate_passed": analysis.get("phase_gate_passed"),
        "campaign_qualification_eligible": analysis.get("campaign_qualification_eligible"),
    }
    _validate_source5_analysis(details, prepared, state)
    record = _append_event(lock, prepared, "source5_analysis", details)
    return {
        "recorded": True, "phase": phase,
        "analysis_sha256": analysis_sha,
        "event_head": record["record_sha256"],
        "phase_gate_passed": details["phase_gate_passed"],
        "campaign_qualification_eligible": False,
    }


def verify_source5_capacity_ancestor_locked(
    lock: CampaignHostLock, execution_manifest_pin: object,
    authorization_context: object, *, historical_journal_head: str,
    historical_registration_head: str,
) -> dict[str, Any]:
    """Verify a historical Source5 authorization under an already-held API operation."""
    require(_lock_token_is_live(lock),
            "Source5 ancestor verification requires the active fd-owned lock token")
    details_value = _exact(authorization_context, DETAIL_FIELDS["source5_authorized"],
                           "Source5 historical authorization context")
    manifest, prepared, state, _pin = _prepare_source5_context(lock, execution_manifest_pin)
    authorization_id = details_value["authorization_id"]
    completed = state["source5_finished"].get(
        (details_value["phase"], details_value["job"]["run_id"]),
    )
    pending = state["source5_authorized"].get(authorization_id)
    is_pending = pending is not None and state["source5_pending"] == authorization_id
    is_finished = completed is not None and completed["authorization_id"] == authorization_id
    require((is_pending and pending["details"] == details_value) or
            (is_finished and completed["details"] == details_value),
            "Source5 overlay does not bind a durable pending or completed helper authorization")
    _validate_source5_authorization(details_value, prepared, state)
    _digest(historical_journal_head, "Source5 overlay historical chronology head")
    _digest(historical_registration_head, "Source5 overlay capacity registration head")
    require(historical_journal_head in state["journal_heads"] and
            historical_registration_head == state["registration_head"] and
            historical_registration_head in state["journal_heads"] and
            state["journal_heads"].index(historical_registration_head) <=
            state["journal_heads"].index(historical_journal_head),
            "Source5 overlay chronology/capacity heads are not ancestors of the current journal")
    if is_finished:
        require(completed["details"] == details_value,
                "Source5 historical authorization differs from its durable terminal chain")
    return {
        "authorization_id": authorization_id,
        "authorization_state": "pending" if is_pending else completed["state"],
        "registration_head": state["registration_head"],
        "capacity_completion_raw_sha256": _source5_capacity_manifest_record(
            manifest, prepared["host_id"],
        )["artifact"]["raw_sha256"],
        "capacity_schedule_sha256": _source5_capacity_manifest_record(
            manifest, prepared["host_id"],
        )["schedule_sha256"],
        "capacity_ledger_raw_sha256": _source5_capacity_manifest_record(
            manifest, prepared["host_id"],
        )["ledger_raw_sha256"],
        "capacity_terminal_head": _source5_capacity_manifest_record(
            manifest, prepared["host_id"],
        )["terminal_head"],
        "entry_count": 15,
        "dispatch_event_count": state["dispatch_event_count"],
        "output_root": str(prepared["output_root"]),
        "journal_head": state["head"],
        "historical_journal_head": historical_journal_head,
        "historical_journal_record_count": state["journal_heads"].index(historical_journal_head),
        "pending_authorization": state["source5_pending"] is not None,
        "cleanup_blocked": state["source5_cleanup_blocked"],
        "qualification_eligible": False,
    }


def source5_authorization_context_locked(
    lock: CampaignHostLock, execution_manifest_pin: object,
    authorization_id: str,
) -> dict[str, Any]:
    """Return an authorization only after locating its pending/completed journal event."""
    require(_lock_token_is_live(lock),
            "Source5 authorization lookup requires the live campaign lock token")
    manifest, prepared, state, _manifest_pin = _prepare_source5_context(
        lock, execution_manifest_pin,
    )
    del manifest
    if state["source5_pending"] == authorization_id:
        pending = state["source5_authorized"].get(authorization_id)
        require(pending is not None,
                "Source5 pending authorization ID has no replayed authorization event")
        details = pending["details"]
    else:
        matches = [item for item in state["source5_finished"].values()
                   if item["authorization_id"] == authorization_id]
        require(len(matches) == 1,
                "Source5 authorization ID is absent or duplicated in the replayed journal")
        details = matches[0]["details"]
    _validate_source5_authorization(details, prepared, state)
    return _json_copy(details)


def _verify_source5_completed_job_locked_impl(
    lock: CampaignHostLock, execution_manifest_pin: object,
    active_authorization_context: object | None, record_pin: object,
    *, fixed_phase_allowlist: set[str], allow_pressure: bool,
) -> dict[str, Any]:
    """Replay a completed fixed job's record against its journal lifecycle chain."""
    require(_lock_token_is_live(lock),
            "Source5 fixed predecessor replay requires the live campaign lock token")
    active = None if active_authorization_context is None else _exact(
        active_authorization_context, DETAIL_FIELDS["source5_authorized"],
        "active Source5 authorization",
    )
    record_path, record_raw, record_raw_sha = _source5_reference(
        record_pin, "Source5 completed job record",
    )
    record = _parse_object(record_raw, "Source5 completed job record", MAX_EVENT_BYTES)
    exact_record = _exact(record, {
        "schema", "state", "job", "pair_directory", "process_metrics", "evidence",
        "chronology", "qualification_eligible", "record_sha256",
    }, "Source5 completed job record")
    material = {key: value for key, value in exact_record.items()
                if key != "record_sha256"}
    require(exact_record["schema"] == SOURCE5_JOB_RECORD_SCHEMA and
            exact_record["record_sha256"] == sha256_bytes(canonical_bytes(material)) and
            exact_record["qualification_eligible"] is False and
            exact_record["state"] == "valid_pair",
            "Source5 predecessor record digest, state, or eligibility differs")
    metrics = exact_record["process_metrics"]
    require(type(metrics) is list and len(metrics) == 2 and
            all(type(item) is dict for item in metrics),
            "Source5 predecessor record lacks its two validated process metrics")
    chronology = _exact(exact_record["chronology"], {
        "authorization_id", "authorization_head", "app_started_heads",
        "app_terminal_heads", "job_terminal_head", "component_sha256",
        "process_metrics_sha256", "app_start_events", "app_terminal_events",
        "member_processes",
    }, "Source5 predecessor chronology")
    _digest(chronology["authorization_head"], "Source5 predecessor authorization head")
    _digest(chronology["job_terminal_head"], "Source5 predecessor terminal head")
    _digest(chronology["component_sha256"], "Source5 predecessor component digest")
    _digest(chronology["process_metrics_sha256"], "Source5 predecessor metrics digest")
    require(chronology["process_metrics_sha256"] == sha256_bytes(canonical_bytes(metrics)),
            "Source5 predecessor chronology metrics digest differs")
    require(type(chronology["app_started_heads"]) is list and
            type(chronology["app_terminal_heads"]) is list and
            len(chronology["app_started_heads"]) == len(chronology["app_terminal_heads"]) == 2 and
            type(chronology["app_start_events"]) is list and
            type(chronology["app_terminal_events"]) is list and
            len(chronology["app_start_events"]) == len(chronology["app_terminal_events"]) == 2,
            "Source5 predecessor chronology does not retain both actual APP lifecycle callbacks")
    for value in (*chronology["app_started_heads"], *chronology["app_terminal_heads"]):
        _digest(value, "Source5 predecessor APP lifecycle head")
    manifest, prepared, state, _manifest_pin = _prepare_source5_context(
        lock, execution_manifest_pin,
    )
    if active is not None:
        active_id = active["authorization_id"]
        pending = state["source5_authorized"].get(active_id)
        active_finished = state["source5_finished"].get(
            (active["phase"], active["job"]["run_id"]),
        )
        active_pending = pending is not None and state["source5_pending"] == active_id and \
            pending["details"] == active
        active_complete = active_finished is not None and \
            active_finished["authorization_id"] == active_id and \
            active_finished["details"] == active
        require(active_pending or active_complete,
                "Source5 predecessor replay does not have a journal-bound pressure authorization")
        _validate_source5_authorization(active, prepared, state)
    job = exact_record["job"]
    allowed_phases = fixed_phase_allowlist | ({"pressure"} if allow_pressure else set())
    require(type(job) is dict and job.get("host_id") == prepared["host_id"] and
            job.get("phase") in allowed_phases and
            (active is None or (
                active["phase"] == "pressure" and
                active["job"].get("run_id") == job.get("run_id") or
                active["phase"] == "pressure" and
                job.get("run_id") in active["job"].get("predecessor_run_ids", [])
            )),
            "Source5 completed record is outside its original job/predecessor scope")
    phase = job["phase"]
    finished = state["source5_finished"].get((phase, job.get("run_id")))
    require(finished is not None and finished["state"] == "valid_pair" and
            finished["authorization_id"] == chronology["authorization_id"] and
            finished["details"]["job"] == job and
            finished["authorization_head"] == chronology["authorization_head"] and
            finished["terminal"]["component_sha256"] == chronology["component_sha256"] and
            finished["terminal"]["process_metrics_sha256"] == chronology["process_metrics_sha256"] and
            finished["record_sha256"] == chronology["job_terminal_head"] and
            [item["event_head"] for item in finished["starts"]] == chronology["app_started_heads"] and
            [item["event_head"] for item in finished["terminals"]] == chronology["app_terminal_heads"] and
            [item["proof"] for item in finished["starts"]] == chronology["app_start_events"] and
            [item["cleanup"] for item in finished["terminals"]] == [
                item.get("cleanup") for item in chronology["app_terminal_events"]
            ] and chronology["member_processes"] == [
                {"descriptor": item["descriptor"], "pid": item["pid"],
                 "start_ticks": item["start_ticks"], "member_index": index}
                for index, item in enumerate(finished["starts"])
            ],
            "Source5 record differs from the exact completed APP lifecycle chain")
    auth_details = finished["details"]
    helper_path, helper_raw, helper_sha = _source5_reference(
        auth_details["helper_input"], "Source5 completed helper input",
    )
    helper_input = _parse_object(helper_raw, "Source5 completed helper input", MAX_PLAN_BYTES)
    common_evidence_keys = {
        "execution_manifest", "helper_input", "helper_module",
    }
    if phase in fixed_phase_allowlist:
        require(active is None or job["run_id"] in active["job"].get("predecessor_run_ids", []),
                "Source5 fixed record is not the exact declared pressure predecessor")
        fixed_evidence_keys = {
            "kind", "overlay", "receipt", "processes", "runtime_bindings",
            "source_snapshot",
        }
        if set(exact_record["evidence"]) == fixed_evidence_keys:
            evidence = _exact(exact_record["evidence"], fixed_evidence_keys,
                              "Source5 fixed predecessor evidence")
        else:
            evidence = _exact(exact_record["evidence"],
                              fixed_evidence_keys | common_evidence_keys,
                              "Source5 controller fixed predecessor evidence")
            require(evidence["execution_manifest"] == auth_details["execution_manifest"] and
                    evidence["helper_input"] == auth_details["helper_input"] and
                    evidence["helper_module"] == auth_details["helper_module"],
                    "Source5 fixed predecessor authorization pins differ from its record")
        require(evidence["kind"] == "source5_fixed_pair",
                "Source5 pressure predecessor evidence kind is not fixed-pair")
        overlay_pin = helper_input["payload"]["overlay_pin"]
        require(evidence["overlay"] == {
            "path": overlay_pin["path"], "raw_sha256": overlay_pin["sha256"],
        }, "Source5 predecessor overlay pin differs from its durable helper input")
        fixed_raw, fixed_sha, _fixed_record = _source_file(
            prepared["source_root"], prepared["source"],
            "scripts/application-fixed-pair.py", "Source5 fixed-pair verifier",
            maximum=MAX_SCRIPT_BYTES,
        )
        fixed_module = _load_module(
            fixed_raw, prepared["source_root"] / "scripts/application-fixed-pair.py",
            "source5_fixed_predecessor_verifier",
        )
        require(fixed_sha == auth_details["helper_module"]["sha256"],
                "Source5 fixed predecessor verifier differs from its authorization helper pin")
        receipt_path, receipt_raw, receipt_sha = _source5_reference(
            evidence["receipt"], "Source5 fixed predecessor receipt",
        )
        receipt = _parse_object(receipt_raw, "Source5 fixed predecessor receipt",
                                fixed_module.MAX_RECEIPT_BYTES)
        verified = fixed_module.verify_fixed_pair_overlay(
            {"path": overlay_pin["path"], "sha256": overlay_pin["sha256"]},
            {"path": str(receipt_path), "sha256": receipt_sha},
        )
        overlay, _overlay_raw, _overlay_sha, _fixed_context, _reconstructed = \
            fixed_module._read_overlay(
                {"path": overlay_pin["path"], "sha256": overlay_pin["sha256"]},
            )
        require(verified.get("verified") is True and
                verified.get("status") == "valid_pair" and
                receipt.get("process_metrics") == metrics and
                receipt.get("process_validation_errors") == [None, None] and
                receipt.get("inputs_unchanged") is True,
                "Source5 fixed predecessor receipt did not freshly replay to its canonical metrics")
        component = {
            "schema": "allocatbelt.application-source5-fixed-component.v1",
            "overlay": {"path": overlay_pin["path"],
                        "raw_sha256": overlay_pin["sha256"]},
            "receipt": {"path": str(receipt_path),
                        "raw_sha256": receipt_sha},
            "verification": verified,
        }
        require(sha256_bytes(canonical_bytes(component)) == chronology["component_sha256"],
                "Source5 fixed component digest differs from its source record")
        expected_processes = {
            "path": str(Path(overlay["output_root"]) / "processes.tsv"),
            "raw_sha256": receipt["processes_sha256"],
        }
        runtime_pin = overlay["runtime_bindings"]["pin"]
        expected_runtime = {"path": runtime_pin["path"], "raw_sha256": runtime_pin["sha256"]}
        selected_manifest = overlay["sources"]["manifests"][prepared["host_id"]]
        expected_source = {
            "artifact": {"path": selected_manifest["pin"]["path"],
                         "raw_sha256": selected_manifest["pin"]["sha256"]},
            "semantic_sha256": selected_manifest["manifest_sha256"],
            "source_tree_sha256": overlay["sources"]["selected"]["source_tree_sha256"],
        }
        require(evidence["processes"] == expected_processes and
                evidence["runtime_bindings"] == expected_runtime and
                evidence["source_snapshot"] == expected_source,
                "Source5 fixed predecessor raw artifact pins differ from its freshly replayed overlay")
    else:
        require(active is None and job["phase"] == "pressure",
                "Source5 pressure record replay must use its completed authorization context")
        pressure_evidence_keys = {
            "kind", "recipe", "overlay", "readback", "processes",
            "fixed_predecessor", "source_snapshot",
        }
        if set(exact_record["evidence"]) == pressure_evidence_keys:
            evidence = _exact(exact_record["evidence"], pressure_evidence_keys,
                              "Source5 pressure record evidence")
        else:
            evidence = _exact(exact_record["evidence"],
                              pressure_evidence_keys | common_evidence_keys,
                              "Source5 controller pressure record evidence")
            require(evidence["execution_manifest"] == auth_details["execution_manifest"] and
                    evidence["helper_input"] == auth_details["helper_input"] and
                    evidence["helper_module"] == auth_details["helper_module"],
                    "Source5 pressure authorization pins differ from its record")
        payload_recipe = helper_input["payload"]["recipe_pin"]
        recipe, _recipe_raw, _recipe_sha = _source5_reference(
            payload_recipe, "Source5 pressure recipe",
        )
        require(evidence["kind"] == "source5_pressure_pair" and
                evidence["recipe"] == payload_recipe and
                evidence["overlay"] == recipe["execution_overlay"]["artifact"],
                "Source5 pressure record changed its authorized recipe/overlay pins")
        pair_root = Path(exact_record["pair_directory"])
        require(pair_root.is_absolute() and pair_root.resolve(strict=True) == pair_root and
                evidence["readback"] == {
                    "path": str(pair_root / "pressure-pair-readback.json"),
                    "raw_sha256": evidence["readback"]["raw_sha256"],
                } and evidence["processes"] == {
                    "path": str(pair_root / "processes.tsv"),
                    "raw_sha256": evidence["processes"]["raw_sha256"],
                } and evidence["fixed_predecessor"] == {
                    "path": str(pair_root / "preflight" / "fixed-pressure-predecessor.json"),
                    "raw_sha256": evidence["fixed_predecessor"]["raw_sha256"],
                }, "Source5 pressure record sidecar pins differ from its private job layout")
        source_ref = recipe["source_manifest"]
        expected_source = {
            "artifact": source_ref["artifact"],
            "semantic_sha256": source_ref["semantic_sha256"],
            "source_tree_sha256": prepared["source"]["source"]["source_tree_sha256"],
        }
        require(evidence["source_snapshot"] == expected_source,
                "Source5 pressure source snapshot differs from its recipe")
        component = {
            "schema": "allocatbelt.application-source5-pressure-component.v1",
            "validated": True,
            "qualification_eligible": False,
            "recipe": evidence["recipe"], "overlay": evidence["overlay"],
            "readback": evidence["readback"], "processes": evidence["processes"],
            "pressure_metrics": metrics,
        }
        require(sha256_bytes(canonical_bytes(component)) == chronology["component_sha256"],
                "Source5 pressure component digest differs from its source record")
    del helper_path, helper_sha, manifest
    return {
        "record": {"path": str(record_path), "raw_sha256": record_raw_sha},
        "authorization_id": chronology["authorization_id"],
        "authorization_head": chronology["authorization_head"],
        "job_terminal_head": chronology["job_terminal_head"],
        "record_sha256": exact_record["record_sha256"],
        "metrics_sha256": chronology["process_metrics_sha256"],
        "process_metrics": metrics,
    }


def verify_source5_completed_job_locked(
    lock: CampaignHostLock, execution_manifest_pin: object,
    active_authorization_context: object | None, record_pin: object,
) -> dict[str, Any]:
    """Replay only a confirmation predecessor or an active pressure record."""
    return _verify_source5_completed_job_locked_impl(
        lock, execution_manifest_pin, active_authorization_context, record_pin,
        fixed_phase_allowlist={"confirmation"}, allow_pressure=True,
    )


def verify_source5_completed_fixed_phase_locked(
    lock: CampaignHostLock, execution_manifest_pin: object,
    record_pin: object,
) -> dict[str, Any]:
    """Replay exploration/AA/confirmation fixed records without pressure authority."""
    require(_lock_token_is_live(lock),
            "Source5 fixed-phase replay requires the live campaign lock token")
    return _verify_source5_completed_job_locked_impl(
        lock, execution_manifest_pin, None, record_pin,
        fixed_phase_allowlist={"exploration", "aa", "confirmation"}, allow_pressure=False,
    )


@_serialize_locked_api
def verify_source5_completed_soak_job_locked(
    lock: CampaignHostLock, execution_manifest_pin: object,
    record_pin: object,
) -> dict[str, Any]:
    """Freshly replay one original single-APP Soak record under its host lock."""
    manifest, prepared, state, _manifest_pin = _prepare_source5_context(
        lock, execution_manifest_pin,
    )
    require(manifest["schema"] in (SOURCE5_EXECUTION_SCHEMA_V2,
                                     SOURCE5_EXECUTION_SCHEMA_V3),
            "Source5 Soak replay requires the prepared final execution generation")
    selected = _source5_artifact_pin(record_pin, "Source5 Soak record")
    record_path, record_raw, record_sha = _source5_reference(
        selected, "Source5 Soak record",
    )
    records, records_sha = _source5_soak_phase_records(prepared, state)
    record = records[0]
    expected_raw = canonical_bytes(record)
    expected_path = (prepared["output_root"] / prepared["campaign_id"] /
                     "source5" / prepared["host_id"] / "soak" /
                     "job-records" / f"{record['job']['run_id']}.json")
    require(record_path == expected_path and
            record_sha == sha256_bytes(expected_raw),
            "Source5 Soak record pin differs from the freshly replayed original ordinal")
    require(record_raw == expected_raw and record_sha == sha256_bytes(expected_raw),
            "Source5 Soak record bytes differ from the fresh per-host chronology/artifact replay")
    return {
        "verified": True,
        "status": record["state"],
        "run_id": record["job"]["run_id"],
        "record_sha256": record_sha,
        "phase_records_sha256": records_sha,
        "component_sha256": record["chronology"]["component_sha256"],
        "process_metrics": record["process_metrics"],
        "started_count": len(record["chronology"]["app_start_events"]),
        "terminal_count": len(record["chronology"]["app_terminal_events"]),
        "qualification_eligible": False,
    }


def _cli_pin(path: Path, raw_sha256: str) -> dict[str, str]:
    return {"path": str(path), "sha256": raw_sha256}


def _parser() -> Any:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "register", "launch", "verify"):
        command = commands.add_parser(name)
        command.add_argument("--plan", type=Path, required=True)
        command.add_argument("--plan-sha256", required=True)
        command.add_argument("--spec", type=Path, required=True)
        command.add_argument("--spec-sha256", required=True)
        command.add_argument("--source-root", type=Path, required=True)
        command.add_argument("--input-root", type=Path, required=True)
        command.add_argument("--host-id", required=True)
        command.add_argument("--observed-host", type=Path, required=True)
        command.add_argument("--observed-host-sha256", required=True)
        command.add_argument("--output-root", type=Path, required=True)
        if name != "run":
            command.add_argument("--capacity-output-root", type=Path)
        command.add_argument("--lock-timeout-seconds", type=float, default=30.0)
        if name != "run":
            command.add_argument("--completion", type=Path, required=True)
            command.add_argument("--completion-sha256", required=True)
        if name == "launch":
            command.add_argument("--job-run-id", required=True)
            command.add_argument("--pair-runner", type=Path, required=True)
            command.add_argument("--campaign-artifacts-root", type=Path)
            command.add_argument("--effective-timeout-seconds", type=int)
    prepared = commands.add_parser(
        "register-prepared-capacity",
        help="replay and register the separate pre-Spec preparation generation",
    )
    prepared.add_argument("--plan", type=Path, required=True)
    prepared.add_argument("--plan-sha256", required=True)
    prepared.add_argument("--spec", type=Path, required=True)
    prepared.add_argument("--spec-sha256", required=True)
    prepared.add_argument("--source-root", type=Path, required=True)
    prepared.add_argument("--input-root", type=Path, required=True)
    prepared.add_argument("--host-id", required=True)
    prepared.add_argument("--observed-host", type=Path, required=True)
    prepared.add_argument("--observed-host-sha256", required=True)
    prepared.add_argument("--output-root", type=Path, required=True)
    prepared.add_argument("--completion", type=Path, required=True)
    prepared.add_argument("--completion-raw-sha256", required=True)
    prepared.add_argument("--completion-semantic-sha256", required=True)
    prepared.add_argument("--preparation", type=Path, required=True)
    prepared.add_argument("--preparation-sha256", required=True)
    prepared.add_argument("--final-spec", type=Path, required=True)
    prepared.add_argument("--final-spec-sha256", required=True)
    prepared.add_argument("--final-plan", type=Path, required=True)
    prepared.add_argument("--final-plan-sha256", required=True)
    prepared.add_argument("--lock-timeout-seconds", type=float, default=30.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        plan_pin = _cli_pin(args.plan, args.plan_sha256)
        spec_pin = _cli_pin(args.spec, args.spec_sha256)
        observed_pin = _cli_pin(args.observed_host, args.observed_host_sha256)
        spec, _spec_path, _spec_raw, _spec_sha = _read_pin(
            spec_pin, "campaign spec", MAX_SPEC_BYTES,
        )
        campaign_id = _token(spec.get("campaign_id"), "campaign ID")
        source_root = _safe_root(args.source_root, "SourceV5 root")
        input_root = _safe_root(args.input_root, "campaign input root")
        output_root = _safe_root(args.output_root, "campaign chronology output root")
        require(not _within(source_root, input_root) and
                not _within(source_root, output_root),
                "campaign inputs and transaction outputs must remain outside SourceV5")
        if args.command == "register-prepared-capacity":
            completion_pin = {
                "path": str(args.completion),
                "raw_sha256": args.completion_raw_sha256,
                "semantic_sha256": args.completion_semantic_sha256,
            }
            provenance_pin = {
                "schema": "allocatbelt.application-source5-prepared-inputs-provenance.v1",
                "preparation_pin": _cli_pin(args.preparation,
                                             args.preparation_sha256),
                "final_spec_pin": _cli_pin(args.final_spec,
                                            args.final_spec_sha256),
                "final_plan_pin": _cli_pin(args.final_plan,
                                            args.final_plan_sha256),
            }
        else:
            completion_pin = None if args.command == "run" else _cli_pin(
                args.completion, args.completion_sha256,
            )
        with campaign_host_lock(
            output_root, campaign_id, args.host_id,
            timeout_seconds=args.lock_timeout_seconds,
        ) as lock:
            if args.command == "run":
                result = run_capacity_stage_locked(
                    lock, plan_pin, spec_pin, source_root, input_root,
                    args.host_id, observed_pin, output_root,
                )
            elif args.command == "register-prepared-capacity":
                assert completion_pin is not None
                result = register_source5_prepared_capacity_locked(
                    lock, plan_pin, spec_pin, source_root, input_root,
                    args.host_id, observed_pin, output_root,
                    completion_pin, provenance_pin,
                )
            elif args.command == "register":
                assert completion_pin is not None
                result = register_capacity_completion_locked(
                    lock, plan_pin, spec_pin, source_root, input_root,
                    args.host_id, observed_pin, output_root, completion_pin,
                    capacity_output_root=args.capacity_output_root,
                )
            elif args.command == "verify":
                assert completion_pin is not None
                result = verify_campaign_chronology_locked(
                    lock, plan_pin, spec_pin, source_root, input_root,
                    args.host_id, observed_pin, output_root, completion_pin,
                    capacity_output_root=args.capacity_output_root,
                )
            else:
                assert completion_pin is not None
                plan, _plan_path, _plan_raw, _plan_sha = _read_pin(
                    plan_pin, "campaign plan", MAX_PLAN_BYTES,
                )
                host_jobs = [job for job in plan.get("jobs", {}).get("confirmation", [])
                             if type(job) is dict and job.get("host_id") == args.host_id]
                matches = [job for job in host_jobs if job.get("run_id") == args.job_run_id]
                if not matches:
                    pressure_jobs = [job for job in plan.get("jobs", {}).get("pressure", [])
                                     if type(job) is dict and job.get("host_id") == args.host_id and
                                     job.get("run_id") == args.job_run_id]
                    require(not pressure_jobs,
                            "pressure dispatch is explicitly unsupported by the fixed confirmation journal")
                require(len(matches) == 1,
                        "CLI dispatch run ID is not unique in the original host confirmation plan")
                authorization = authorize_dispatch_locked(
                    lock, plan_pin, spec_pin, source_root, input_root,
                    args.host_id, observed_pin, output_root, completion_pin,
                    matches[0], args.pair_runner,
                    campaign_artifacts_root=args.campaign_artifacts_root,
                    capacity_output_root=args.capacity_output_root,
                    effective_timeout_seconds=args.effective_timeout_seconds,
                )
                result = launch_authorized_locked(lock, authorization)
            sys.stdout.buffer.write(canonical_bytes(result))
        return 0
    except (ChronologyError, OSError, subprocess.SubprocessError, ValueError,
            TypeError, KeyError, UnicodeError, AssertionError) as error:
        print(f"application campaign chronology: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
