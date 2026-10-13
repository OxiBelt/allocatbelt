#!/usr/bin/env python3
"""Native Linux regressions for bounded feedback-probe process cleanup."""
from __future__ import annotations

import importlib.util
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch


SCRIPT_DIR = Path(__file__).resolve().parent
READER_PATH = SCRIPT_DIR / "application-feedback-readback.py"


def _load_reader() -> Any:
    spec = importlib.util.spec_from_file_location("feedback_process_ownership_target", READER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {READER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


reader = _load_reader()


@unittest.skipUnless(sys.platform == "linux" and Path("/proc").is_dir(), "requires native Linux procfs")
class ProcessOwnershipCleanupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="feedback-process-ownership-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def _capture(self, code: str, *, timeout: float = 0.6) -> tuple[int, bytes, bytes]:
        return reader._capture_bounded_process(
            [sys.executable, "-c", code], self.root, "ownership fixture",
            timeout_seconds=timeout,
        )

    def _instrument_processes(self) -> tuple[dict[str, Any], Any]:
        real_popen = reader.subprocess.Popen
        state: dict[str, Any] = {
            "process": None, "waited": False, "wait_calls": 0, "actual_wait": None,
            "signals": [], "scans": 0,
        }

        def launch(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
            process = real_popen(*args, **kwargs)
            state["process"] = process
            real_wait = process.wait
            state["actual_wait"] = real_wait

            def tracked_wait(timeout: float | None = None) -> int:
                state["wait_calls"] += 1
                result = real_wait(timeout=timeout)
                state["waited"] = True
                return result

            process.wait = tracked_wait  # type: ignore[method-assign]
            return process

        return state, launch

    def _reap_fixture_after_restoring_sigchld(self, state: dict[str, Any], timeout: float = 2.0) -> int | None:
        process = state["process"]
        deadline = time.monotonic() + timeout
        while True:
            try:
                observed = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            except ChildProcessError:
                # SIGCHLD ignore may already have auto-reaped this fixture.
                return None
            if observed is not None and observed.si_pid == process.pid:
                if observed.si_code == os.CLD_EXITED:
                    expected = observed.si_status
                else:
                    expected = -observed.si_status
                actual = state["actual_wait"](timeout=max(0.0, deadline - time.monotonic()))
                self.assertEqual(actual, expected)
                state["waited"] = True
                return actual
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.fail("fixture child did not exit under restored SIGCHLD disposition")
            time.sleep(min(0.01, remaining))

    def _assert_no_process_group_operation_after_reap(self, state: dict[str, Any]) -> tuple[Any, Any]:
        real_scan = reader._owned_session_members
        real_killpg = reader.os.killpg

        def scan(session_id: int) -> tuple[list[int], list[int]]:
            process = state["process"]
            self.assertFalse(state["waited"], "procfs was scanned after the leader was reaped")
            self.assertIsNotNone(process)
            self.assertIsNone(process.returncode)
            state["scans"] += 1
            return real_scan(session_id)

        def killpg(process_group_id: int, signum: int) -> None:
            process = state["process"]
            self.assertFalse(state["waited"], "a process group was signaled after the leader was reaped")
            self.assertIsNotNone(process)
            self.assertIsNone(process.returncode)
            self.assertEqual(process_group_id, process.pid)
            state["signals"].append(signum)
            real_killpg(process_group_id, signum)

        return patch.object(reader, "_owned_session_members", scan), patch.object(reader.os, "killpg", killpg)

    def _assert_not_running(self, pid: int, timeout: float = 2.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
            except FileNotFoundError:
                return
            closing = fields.rfind(")")
            self.assertGreaterEqual(closing, 0)
            state = fields[closing + 1 :].split()[0]
            if state in {"Z", "X"}:
                return
            time.sleep(0.01)
        self.fail(f"owned fixture process {pid} remained live")

    def test_normal_exit_reaps_once_without_signaling(self) -> None:
        state, launch = self._instrument_processes()
        scan_patch, kill_patch = self._assert_no_process_group_operation_after_reap(state)
        with patch.object(reader.subprocess, "Popen", launch), scan_patch, kill_patch:
            result = self._capture("import sys; sys.stdout.write('ok'); sys.stderr.write('err')")
        self.assertEqual(result, (0, b"ok", b"err"))
        self.assertEqual(state["wait_calls"], 1)
        self.assertEqual(state["signals"], [])
        self.assertGreater(state["scans"], 0)

    def test_timeout_ignoring_term_uses_kill_before_one_reap(self) -> None:
        state, launch = self._instrument_processes()
        scan_patch, kill_patch = self._assert_no_process_group_operation_after_reap(state)
        code = "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print('ready', flush=True); time.sleep(30)"
        with patch.object(reader.subprocess, "Popen", launch), scan_patch, kill_patch:
            with self.assertRaisesRegex(reader.ValidationError, "exceeded its 0.6-second deadline"):
                self._capture(code)
        self.assertEqual(state["signals"], [signal.SIGTERM, signal.SIGKILL])
        self.assertEqual(state["wait_calls"], 1)
        self.assertEqual(state["process"].returncode, -signal.SIGKILL)

    def test_same_group_pipe_holder_is_terminated_after_leader_exit(self) -> None:
        pid_path = self.root / "pipe-holder.pid"
        code = f"""import os
import time
pid_path = {str(pid_path)!r}
pid = os.fork()
if pid == 0:
    with open(pid_path, "w", encoding="ascii") as handle:
        handle.write(str(os.getpid()))
    time.sleep(30)
    os._exit(0)
print("leader exited", flush=True)
os._exit(0)
"""
        state, launch = self._instrument_processes()
        scan_patch, kill_patch = self._assert_no_process_group_operation_after_reap(state)
        with patch.object(reader.subprocess, "Popen", launch), scan_patch, kill_patch:
            with self.assertRaisesRegex(reader.ValidationError, "exceeded its 0.6-second deadline"):
                self._capture(code)
        self.assertEqual(state["wait_calls"], 1)
        self.assertEqual(state["signals"], [signal.SIGTERM])
        self.assertTrue(pid_path.exists())
        self._assert_not_running(int(pid_path.read_text(encoding="ascii")))

    def test_selector_setup_failure_still_cleans_child_and_closes_both_pipes(self) -> None:
        state, launch = self._instrument_processes()
        scan_patch, kill_patch = self._assert_no_process_group_operation_after_reap(state)

        def selector_failure() -> Any:
            raise OSError("injected selector setup failure")

        with patch.object(reader.subprocess, "Popen", launch), patch.object(
            reader.selectors, "DefaultSelector", selector_failure,
        ), scan_patch, kill_patch:
            with self.assertRaisesRegex(OSError, "injected selector setup failure"):
                self._capture("import time; time.sleep(30)")
        self.assertEqual(state["wait_calls"], 1)
        self.assertEqual(state["signals"], [signal.SIGTERM])
        self.assertTrue(state["process"].stdout.closed)
        self.assertTrue(state["process"].stderr.closed)

    def test_live_descendant_in_another_group_is_reported_and_not_signaled(self) -> None:
        pid_path = self.root / "escaped-group.pid"
        code = f"""import os
import time
pid_path = {str(pid_path)!r}
pid = os.fork()
if pid == 0:
    os.setpgid(0, 0)
    with open(pid_path, "w", encoding="ascii") as handle:
        handle.write(str(os.getpid()))
    time.sleep(2)
    os._exit(0)
print("leader exited", flush=True)
os._exit(0)
"""
        state, launch = self._instrument_processes()
        scan_patch, kill_patch = self._assert_no_process_group_operation_after_reap(state)
        with patch.object(reader.subprocess, "Popen", launch), scan_patch, kill_patch:
            with self.assertRaisesRegex(reader.ValidationError, "outside its owned process group"):
                self._capture(code)
        self.assertEqual(state["wait_calls"], 1)
        self.assertEqual(state["signals"], [])
        self.assertTrue(pid_path.exists())
        escaped_pid = int(pid_path.read_text(encoding="ascii"))
        stat_line = Path(f"/proc/{escaped_pid}/stat").read_text(encoding="ascii")
        fields = stat_line[stat_line.rfind(")") + 1 :].split()
        self.assertNotEqual(int(fields[2]), state["process"].pid)
        self.assertEqual(int(fields[3]), state["process"].pid)
        os.kill(escaped_pid, signal.SIGTERM)
        self._assert_not_running(escaped_pid)

    def test_persistent_proc_scan_failure_emergency_kills_and_reaps_but_fails(self) -> None:
        state, launch = self._instrument_processes()
        events: list[tuple[Any, ...]] = []
        real_waitid = reader.os.waitid
        real_killpg = reader.os.killpg

        def audited_waitid(idtype: int, process_id: int, options: int) -> Any:
            result = real_waitid(idtype, process_id, options)
            events.append(("waitid", idtype, process_id, options, signal.getsignal(signal.SIGCHLD)))
            return result

        def audited_killpg(process_group_id: int, signum: int) -> None:
            process = state["process"]
            self.assertFalse(state["waited"])
            self.assertIsNone(process.returncode)
            self.assertEqual(process_group_id, process.pid)
            self.assertTrue(events, "fallback signal had no preceding wait ownership check")
            kind, idtype, process_id, options, disposition = events[-1]
            self.assertEqual(kind, "waitid", "fallback signal did not immediately follow its ownership check")
            self.assertEqual(idtype, reader.os.P_PID)
            self.assertEqual(process_id, process.pid)
            self.assertTrue(options & reader.os.WNOWAIT)
            self.assertEqual(disposition, signal.SIG_DFL)
            state["signals"].append(signum)
            events.append(("killpg", process_group_id, signum))
            real_killpg(process_group_id, signum)

        def scanner_failure(_session_id: int) -> tuple[list[int], list[int]]:
            process = state["process"]
            self.assertFalse(state["waited"])
            self.assertIsNone(process.returncode)
            events.append(("scan-failure",))
            raise reader.ValidationError("injected persistent procfs failure")

        code = "import time; print('ready', flush=True); time.sleep(30)"
        with patch.object(reader.subprocess, "Popen", launch), patch.object(
            reader, "_owned_session_members", scanner_failure,
        ), patch.object(reader.os, "waitid", audited_waitid), patch.object(reader.os, "killpg", audited_killpg):
            with self.assertRaisesRegex(reader.ValidationError, "cleanup is unverified.*injected persistent procfs failure") as caught:
                self._capture(code)
        self.assertRegex(str(caught.exception.__cause__), "exceeded its 0.6-second deadline")
        self.assertEqual(state["signals"], [signal.SIGTERM, signal.SIGKILL])
        self.assertEqual(state["wait_calls"], 1)
        self.assertIn(state["process"].returncode, {-signal.SIGTERM, -signal.SIGKILL})
        self.assertTrue(state["process"].stdout.closed)
        self.assertTrue(state["process"].stderr.closed)
        fallback_signals = [event for event in events if event[0] == "killpg"]
        self.assertEqual([event[2] for event in fallback_signals], [signal.SIGTERM, signal.SIGKILL])

    def test_kill_failure_is_propagated_after_bounded_final_reap(self) -> None:
        state, launch = self._instrument_processes()
        signal_attempts: list[int] = []

        def denied_killpg(_process_group_id: int, signum: int) -> None:
            process = state["process"]
            self.assertFalse(state["waited"])
            self.assertIsNone(process.returncode)
            signal_attempts.append(signum)
            raise PermissionError("injected killpg failure")

        code = "import time; print('ready', flush=True); time.sleep(0.15)"
        with patch.object(reader.subprocess, "Popen", launch), patch.object(reader.os, "killpg", denied_killpg):
            with self.assertRaisesRegex(reader.ValidationError, "cleanup is unverified.*injected killpg failure"):
                self._capture(code, timeout=0.05)
        self.assertEqual(signal_attempts, [signal.SIGTERM, signal.SIGTERM, signal.SIGKILL])
        self.assertEqual(state["wait_calls"], 1)
        self.assertIsNotNone(state["process"].returncode)

    def test_nondefault_sigchld_refuses_launch_before_popen(self) -> None:
        old_handler = signal.getsignal(signal.SIGCHLD)
        launched = False

        def unexpected_launch(*_args: Any, **_kwargs: Any) -> subprocess.Popen[bytes]:
            nonlocal launched
            launched = True
            raise AssertionError("Popen ran despite unsupported SIGCHLD")

        try:
            signal.signal(signal.SIGCHLD, signal.SIG_IGN)
            with patch.object(reader.subprocess, "Popen", unexpected_launch):
                with self.assertRaisesRegex(reader.ValidationError, "default SIGCHLD"):
                    self._capture("pass")
        finally:
            signal.signal(signal.SIGCHLD, old_handler)
        self.assertFalse(launched)

    def test_sigchld_changed_during_failure_prevents_numeric_fallback_signals(self) -> None:
        old_handler = signal.getsignal(signal.SIGCHLD)
        ready_path = self.root / "sigchld-child-ready"
        code = f"import pathlib,time; pathlib.Path({str(ready_path)!r}).write_text('ready'); time.sleep(0.4)"
        state, launch = self._instrument_processes()
        signal_attempts: list[int] = []
        real_selector = reader.selectors.DefaultSelector

        def rejecting_killpg(_process_group_id: int, signum: int) -> None:
            signal_attempts.append(signum)
            raise AssertionError("numeric process-group signal under nondefault SIGCHLD")

        class FaultingSelector:
            def __init__(self) -> None:
                self.inner = real_selector()

            def register(self, *args: Any, **kwargs: Any) -> Any:
                return self.inner.register(*args, **kwargs)

            def get_map(self) -> Any:
                return self.inner.get_map()

            def select(self, _timeout: float | None = None) -> Any:
                deadline = time.monotonic() + 1.0
                while not ready_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.005)
                if not ready_path.exists():
                    raise AssertionError("fixture child did not become active")
                signal.signal(signal.SIGCHLD, signal.SIG_IGN)
                raise OSError("injected active-capture failure")

            def close(self) -> None:
                self.inner.close()

        try:
            with patch.object(reader.subprocess, "Popen", launch), patch.object(
                reader.selectors, "DefaultSelector", FaultingSelector,
            ), patch.object(reader.os, "killpg", rejecting_killpg):
                with self.assertRaisesRegex(reader.ValidationError, "cleanup is unverified.*default SIGCHLD"):
                    self._capture(code, timeout=1.0)
        finally:
            signal.signal(signal.SIGCHLD, old_handler)
        self.assertEqual(signal_attempts, [])
        self.assertEqual(state["wait_calls"], 0)
        self.assertIsNone(state["process"].returncode)
        self.assertTrue(state["process"].stdout.closed)
        self.assertTrue(state["process"].stderr.closed)
        self._reap_fixture_after_restoring_sigchld(state)

    def test_success_scan_lost_ownership_cannot_return_zero_with_captured_stdout(self) -> None:
        marker = self.root / "nonzero-child-wrote-stdout"
        code = (
            "import pathlib,sys; "
            "sys.stdout.write('valid-looking-output'); sys.stdout.flush(); "
            f"pathlib.Path({str(marker)!r}).write_text('stdout-written'); "
            "raise SystemExit(23)"
        )
        state, launch = self._instrument_processes()
        _scan_patch, kill_patch = self._assert_no_process_group_operation_after_reap(state)
        actual_scans = 0
        real_scan = reader._owned_session_members

        def externally_reaping_scan(session_id: int) -> tuple[list[int], list[int]]:
            nonlocal actual_scans
            self.assertFalse(state["waited"], "process ownership was scanned after external reap")
            result = real_scan(session_id)
            actual_scans += 1
            self.assertEqual(result, ([], []))
            process = state["process"]
            self.assertIsNone(process.returncode)
            pid, wait_status = os.waitpid(process.pid, 0)
            self.assertEqual(pid, process.pid)
            state["externally_observed_exit_code"] = os.waitstatus_to_exitcode(wait_status)
            state["waited"] = True
            return result

        with patch.object(reader.subprocess, "Popen", launch), patch.object(
            reader, "_owned_session_members", externally_reaping_scan,
        ), kill_patch:
            with self.assertRaisesRegex(reader.ValidationError, "ownership was lost"):
                self._capture(code)
        self.assertEqual(actual_scans, 1)
        self.assertEqual(state["externally_observed_exit_code"], 23)
        self.assertTrue(marker.is_file())
        self.assertEqual(marker.read_text(encoding="ascii"), "stdout-written")
        self.assertEqual(state["wait_calls"], 0)
        self.assertEqual(state["signals"], [])
        self.assertIsNone(state["process"].returncode)
        self.assertTrue(state["process"].stdout.closed)
        self.assertTrue(state["process"].stderr.closed)


if __name__ == "__main__":
    unittest.main()
