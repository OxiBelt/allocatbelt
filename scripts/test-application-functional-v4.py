#!/usr/bin/env python3
"""Read-only tests for the SourceSchemaV4 functional integration inputs."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import re
import shutil
import signal
import sys
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "scripts" / "test-application-pair-functional-e2e.py"
RUNNER_PATH = ROOT / "scripts" / "run-application-pair.sh"
HELPER_SPEC = importlib.util.spec_from_file_location("functional_v4_helper_tests", HELPER_PATH)
assert HELPER_SPEC is not None and HELPER_SPEC.loader is not None
HELPER = importlib.util.module_from_spec(HELPER_SPEC)
HELPER_SPEC.loader.exec_module(HELPER)


class SourceSchemaV4FunctionalInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        source_root = os.environ.get("ALLOCATBELT_V4_TEST_SOURCE_ROOT")
        source_manifest = os.environ.get("ALLOCATBELT_V4_TEST_SOURCE_MANIFEST")
        source_manifest_sha = os.environ.get("ALLOCATBELT_V4_TEST_SOURCE_MANIFEST_SHA256")
        signer_fingerprint = os.environ.get("ALLOCATBELT_V4_TEST_SIGNER_FINGERPRINT")
        if not source_root or not source_manifest or not source_manifest_sha or not signer_fingerprint:
            raise unittest.SkipTest("set the SourceSchemaV4 root, manifest, raw SHA, and signer fingerprint variables on the designated remote host")
        cls.source_root = Path(source_root).resolve(strict=True)
        cls.source_manifest_path = Path(source_manifest).resolve(strict=True)
        cls.source, cls.source_manifest_raw, cls.source_manifest_file_sha = HELPER.load_source_manifest_v4(
            cls.source_root, cls.source_manifest_path, source_manifest_sha, signer_fingerprint,
        )

    def _sentinel_bootstrap_fixture(self, failure: str) -> tuple[Path, Path, str, str, Path, list[str], Any]:
        temporary = tempfile.TemporaryDirectory(prefix="source-v4-bootstrap-")
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        source_root = base / "source"
        scripts = source_root / "scripts"
        scripts.mkdir(parents=True)
        marker = base / "controller-executed"
        sentinel = (
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('executed', encoding='ascii')\n"
            "raise RuntimeError('sentinel controller executed')\n"
        ).encode("utf-8")
        committed_controller = b"# signed controller fixture\n"
        working_controller = sentinel
        controller_path = scripts / "application-campaign.py"
        controller_path.write_bytes(working_controller)
        controller_path.chmod(0o644)
        engine_raw = (ROOT / "scripts" / "application-source-inventory.py").read_bytes()
        engine_path = scripts / "application-source-inventory.py"
        engine_path.write_bytes(engine_raw)
        engine_path.chmod(0o644)
        committed_records = []
        for relative, raw in (
            ("scripts/application-campaign.py", committed_controller),
            ("scripts/application-source-inventory.py", engine_raw),
        ):
            committed_records.append({
                "path": relative,
                "kind": "file",
                "mode": "100644",
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
            })
        committed_records.sort(key=lambda item: item["path"].encode("utf-8"))
        source_identity = {
            "git_commit": "a" * 40,
            "source_tree_sha256": hashlib.sha256(HELPER.canonical_stdlib({
                "schema": "allocatbelt.application-source-inventory.v1",
                "entries": committed_records,
            })).hexdigest(),
            "files": committed_records,
        }
        unsigned: dict[str, Any] = {
            "schema": "allocatbelt.application-source-manifest.v4",
            "source": source_identity,
        }
        manifest = {
            **unsigned,
            "manifest_sha256": hashlib.sha256(HELPER.canonical_stdlib(unsigned)).hexdigest(),
        }
        raw_manifest = HELPER.canonical_stdlib(manifest)
        manifest_path = base / "source-manifest.json"
        manifest_path.write_bytes(raw_manifest)
        expected_sha = hashlib.sha256(raw_manifest).hexdigest()
        expected_signer = os.environ["ALLOCATBELT_V4_TEST_SIGNER_FINGERPRINT"]
        calls: list[str] = []

        def fake_git(arguments: list[str], cwd: Path, timeout_seconds: int = 60) -> subprocess.CompletedProcess[bytes]:
            calls.append(" ".join(arguments))
            if arguments[:2] == ["rev-parse", "HEAD"]:
                return subprocess.CompletedProcess(arguments, 0, b"a" * 40 + b"\n", b"")
            if arguments[:2] == ["rev-parse", "--show-toplevel"]:
                return subprocess.CompletedProcess(arguments, 0, str(source_root).encode() + b"\n", b"")
            if arguments[:1] == ["verify-commit"]:
                signer = "0" * 40 if failure == "signer" else expected_signer
                status = (
                    f"[GNUPG:] VALIDSIG {signer} 20261013 1791878400 0 4 0 22 8 00 {signer}\n"
                    f"[GNUPG:] GOODSIG {signer} caller UID contains {expected_signer}\n"
                ).encode("ascii")
                return subprocess.CompletedProcess(arguments, 0, b"", status)
            if arguments[:2] in (["ls-tree", "-r"], ["ls-files", "--stage"]):
                rows = []
                for record in committed_records:
                    raw = committed_controller if record["path"].endswith("application-campaign.py") else engine_raw
                    object_id = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
                    if arguments[0] == "ls-tree":
                        rows.append(f"{record['mode']} blob {object_id}\t{record['path']}\0".encode("utf-8"))
                    else:
                        rows.append(f"{record['mode']} {object_id} 0\t{record['path']}\0".encode("utf-8"))
                return subprocess.CompletedProcess(arguments, 0, b"".join(rows), b"")
            if arguments[:2] == ["ls-files", "--others"]:
                return subprocess.CompletedProcess(arguments, 0, b"", b"")
            if arguments[:2] == ["cat-file", "blob"]:
                return subprocess.CompletedProcess(arguments, 0, committed_controller, b"")
            raise AssertionError(f"unexpected bootstrap Git command: {arguments}")

        return source_root, manifest_path, expected_sha, expected_signer, marker, calls, fake_git

    def test_real_manifest_and_all_application_inputs_are_verified(self) -> None:
        self.assertEqual(self.source["schema"], "allocatbelt.application-source-manifest.v4")
        live_head = HELPER.run_checked(["git", "rev-parse", "HEAD"], self.source_root).decode("ascii").strip()
        self.assertEqual(self.source["source"]["git_commit"], live_head)
        self.assertEqual(
            set(self.source["artifacts"]),
            {"allocatbelt", "mimalloc-secure", "mimalloc-standard", "system"},
        )
        self.assertIn("allocatbelt", self.source["soak_artifacts"])
        self.assertTrue(self.source["analysis_artifact"]["sha256"])
        self.assertTrue(self.source["resource_domain_calibration"]["binary"]["sha256"])
        self.assertTrue(self.source["resource_domain_calibration"]["output"]["sha256"])
        artifacts = HELPER.source_v4_pinned_artifacts(self.source_root, self.source)
        self.assertTrue({"allocatbelt", "mimalloc-secure", "mimalloc-standard", "system"}.issubset(artifacts))
        self.assertEqual(artifacts["allocatbelt"][1], self.source["artifacts"]["allocatbelt"]["sha256"])
        self.assertEqual(
            self.source_manifest_file_sha,
            __import__("hashlib").sha256(self.source_manifest_raw).hexdigest(),
        )

    def test_embedded_runner_v4_preflight_verifies_real_signed_inputs_without_launching_a_pair(self) -> None:
        runner_source = RUNNER_PATH.read_text(encoding="utf-8")
        function_start = runner_source.index("verify_functional_v4_overlay() {")
        function_end = runner_source.index("\n}\n\nverify_functional_overlay()", function_start)
        embedded = re.search(
            r"<<'PY'\n(.*?)\nPY",
            runner_source[function_start:function_end],
            flags=re.DOTALL,
        )
        self.assertIsNotNone(embedded, "could not extract the actual embedded SourceSchemaV4 preflight")

        context = HELPER.validate_source_v4_context(
            workload="cpu", profile="steady", mode="capacity", pair_kind="aa-bounded",
            baseline_allocator=None, rate_per_second=None, arrivals=None,
            trace_deadline_seconds=30, drain_deadline_seconds=10, shutdown_deadline_seconds=5,
            process_deadline_seconds=180, pair_deadline_seconds=360,
        )
        run_id = "functional-v4-preflight-probe-01"
        binding_manifest, bindings = HELPER.source_v4_runtime_bindings(self.source, context, run_id)
        source_runner_record = next(
            record for record in self.source["source"]["files"]
            if record["path"] == "scripts/run-application-pair.sh"
        )
        source_runner_path = self.source_root / "scripts" / "run-application-pair.sh"
        candidate_sha256 = self.source["artifacts"]["allocatbelt"]["sha256"]

        with tempfile.TemporaryDirectory(
            prefix="source-v4-embedded-preflight-",
            dir=os.environ["ALLOCATBELT_V4_TEST_OUTPUT_ROOT"],
        ) as temporary:
            raw_root = Path(temporary) / "raw"
            input_root = raw_root / ".functional-inputs"
            tmp_root = raw_root / ".functional-tmp"
            raw_root.mkdir(mode=0o700)
            input_root.mkdir(mode=0o700)
            tmp_root.mkdir(mode=0o700)
            manifest_path = input_root / "source-manifest.json"
            manifest_path.write_bytes(self.source_manifest_raw)
            manifest_path.chmod(0o600)
            binding_path = input_root / f"{run_id}.runtime-bindings.json"
            binding_raw = HELPER._CAMPAIGN.canonical_bytes(binding_manifest)
            binding_path.write_bytes(binding_raw)
            binding_path.chmod(0o600)
            storage_context = HELPER.require_rootfs_storage_context(raw_root, tmp_root)
            overlay = HELPER.functional_pair_overlay_v4(
                self.source, context, run_id, source_runner_record["sha256"],
                hashlib.sha256(binding_raw).hexdigest(), bindings,
                ".functional-inputs/source-manifest.json", self.source_manifest_file_sha,
                candidate_sha256, None, None, None, storage_context, ".functional-tmp",
                os.environ["ALLOCATBELT_V4_TEST_SIGNER_FINGERPRINT"],
            )
            overlay_path = input_root / f"{run_id}.functional-overlay.json"
            overlay_raw = HELPER._CAMPAIGN.canonical_bytes(overlay)
            overlay_path.write_bytes(overlay_raw)
            overlay_path.chmod(0o600)

            arguments = [
                str(overlay_path), hashlib.sha256(overlay_raw).hexdigest(),
                str(binding_path), hashlib.sha256(binding_raw).hexdigest(),
                source_runner_record["sha256"], self.source["source"]["source_tree_sha256"],
                self.source["source"]["git_commit"], run_id, context["pair_kind"], "allocatbelt", "",
                context["workload"], context["profile"], context["mode"], "-", "5000",
                candidate_sha256, "", "", "",
                self.source["runtime_readback_validator"]["sha256"],
                HELPER.SOURCE_INVENTORY_MODULE_SHA256, str(self.source_root), str(raw_root), str(tmp_root),
            ]
            real_popen = subprocess.Popen
            launched_commands: list[tuple[str, ...]] = []

            def verification_only_popen(command: Any, *args: Any, **kwargs: Any) -> Any:
                vector = tuple(str(item) for item in command)
                executable = Path(vector[0]).name if vector else ""
                self.assertIn(
                    executable, {"git", "cargo", "rustc"},
                    f"embedded preflight attempted to launch a non-verification executable: {vector}",
                )
                launched_commands.append(vector)
                return real_popen(command, *args, **kwargs)

            original_argv = sys.argv
            namespace = {"__file__": str(source_runner_path), "__name__": "source_v4_preflight_test"}
            try:
                sys.argv = ["verify_functional_v4_overlay", *arguments]
                with patch.dict(os.environ, {"TMPDIR": str(tmp_root)}):
                    with patch("subprocess.Popen", new=verification_only_popen):
                        exec(compile(embedded.group(1), str(RUNNER_PATH), "exec", dont_inherit=True), namespace)
            finally:
                sys.argv = original_argv

            self.assertTrue(
                any("verify-commit" in command and "--raw" in command for command in launched_commands),
                "embedded preflight did not verify the pinned commit signature",
            )
            self.assertTrue(
                any(
                    "cat-file" in command
                    and f"{self.source['source']['git_commit']}:scripts/application-campaign.py" in command
                    for command in launched_commands
                ),
                "embedded preflight did not bind the captured controller to the signed commit blob",
            )
            self.assertFalse(
                any(candidate_sha256 in command for command in launched_commands),
                "embedded preflight attempted to launch a pinned application binary",
            )

    def test_bad_raw_file_pin_is_rejected_before_any_execution(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "raw manifest SHA-256"):
            HELPER.load_source_manifest_v4(
                self.source_root, self.source_manifest_path, "0" * 64,
                os.environ["ALLOCATBELT_V4_TEST_SIGNER_FINGERPRINT"],
            )

    def test_wrong_raw_pin_rejects_sentinel_before_any_git_or_controller_execution(self) -> None:
        source_root, manifest, _sha, signer, marker, calls, fake_git = self._sentinel_bootstrap_fixture("valid")
        with patch.object(HELPER, "_run_trusted_git", side_effect=fake_git):
            with self.assertRaisesRegex(RuntimeError, "raw manifest SHA-256"):
                HELPER.load_source_manifest_v4(source_root, manifest, "0" * 64, signer)
        self.assertEqual(calls, [])
        self.assertFalse(marker.exists())

    def test_dirty_source_rejects_sentinel_before_controller_execution(self) -> None:
        source_root, manifest, sha, signer, marker, _calls, fake_git = self._sentinel_bootstrap_fixture("dirty")
        with patch.object(HELPER, "_run_trusted_git", side_effect=fake_git):
            with self.assertRaisesRegex(RuntimeError, "differs from signed record"):
                HELPER.load_source_manifest_v4(source_root, manifest, sha, signer)
        self.assertFalse(marker.exists())

    def test_wrong_validsig_rejects_sentinel_even_when_uid_mentions_pinned_fingerprint(self) -> None:
        source_root, manifest, sha, signer, marker, _calls, fake_git = self._sentinel_bootstrap_fixture("signer")
        with patch.object(HELPER, "_run_trusted_git", side_effect=fake_git):
            with self.assertRaisesRegex(RuntimeError, "VALIDSIG signing/primary fingerprint"):
                HELPER.load_source_manifest_v4(source_root, manifest, sha, signer)
        self.assertFalse(marker.exists())

    def test_wrong_signer_fingerprint_is_rejected(self) -> None:
        pinned = os.environ["ALLOCATBELT_V4_TEST_SIGNER_FINGERPRINT"]
        wrong = ("0" if pinned[0] != "0" else "1") + pinned[1:]
        with self.assertRaisesRegex(RuntimeError, "caller-pinned signer"):
            HELPER.verify_signed_source_commit(
                self.source_root, self.source["source"]["git_commit"], wrong,
            )

    def test_trusted_git_environment_is_fully_restored_on_success_and_exception(self) -> None:
        variables = {
            "PATH": "/caller/bin:/usr/bin",
            "LC_ALL": "C.UTF-8",
            "PAGER": "caller-pager",
            "GNUPGHOME": "/caller/private-gnupg",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.fsmonitor",
            "GIT_CONFIG_VALUE_0": "caller-helper",
            "GIT_TRACE": "caller-trace-file",
        }
        with patch.dict(os.environ, variables, clear=False):
            before = {key: (key in os.environ, os.environ.get(key)) for key in variables}
            with HELPER._trusted_git_environment():
                self.assertEqual(os.environ["PATH"], HELPER.TRUSTED_TOOL_PATH)
                self.assertEqual(os.environ["GIT_CONFIG_COUNT"], "8")
                self.assertEqual(os.environ["GIT_CONFIG_VALUE_0"], "false")
                self.assertNotIn("GIT_TRACE", os.environ)
            self.assertEqual(
                {key: (key in os.environ, os.environ.get(key)) for key in variables}, before,
            )
            with self.assertRaisesRegex(ValueError, "fixture exception"):
                with HELPER._trusted_git_environment():
                    raise ValueError("fixture exception")
            self.assertEqual(
                {key: (key in os.environ, os.environ.get(key)) for key in variables}, before,
            )

    def test_bootstrap_rejections_never_execute_a_sentinel_controller(self) -> None:
        pinned = os.environ["ALLOCATBELT_V4_TEST_SIGNER_FINGERPRINT"]
        cases = (
            ("wrong-raw", "valid", "raw manifest SHA-256"),
            ("dirty", "dirty", "differs from signed record"),
            ("wrong-signer", "signer", "VALIDSIG signing/primary fingerprint"),
        )
        for _label, failure, expected_error in cases:
            with self.subTest(failure=failure):
                source_root, manifest, sha, signer, marker, calls, fake_git = self._sentinel_bootstrap_fixture(failure)
                with patch.object(HELPER, "_run_trusted_git", side_effect=fake_git):
                    raw_pin = "0" * 64 if failure == "valid" else sha
                    with self.assertRaisesRegex(RuntimeError, expected_error):
                        HELPER.load_source_manifest_v4(source_root, manifest, raw_pin, signer or pinned)
                self.assertFalse(marker.exists(), "rejected bootstrap executed the source-selected sentinel controller")
                if failure == "valid":
                    self.assertEqual(calls, [])

    def test_signature_parser_uses_validsig_fingerprint_fields_only(self) -> None:
        pinned = os.environ["ALLOCATBELT_V4_TEST_SIGNER_FINGERPRINT"]
        other = ("0" if pinned[0] != "0" else "1") + pinned[1:]
        valid_line = f"[GNUPG:] VALIDSIG {other} 20261013 1791878400 0 4 0 22 8 00 {other}\n"
        uid_line = f"[GNUPG:] GOODSIG {other} UID contains {pinned}\n"
        result = subprocess.CompletedProcess(
            ["git", "verify-commit"], 0, b"", (valid_line + uid_line).encode("ascii"),
        )
        with patch.object(HELPER, "_run_trusted_git", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "VALIDSIG signing/primary fingerprint"):
                HELPER.verify_signed_source_commit(self.source_root, self.source["source"]["git_commit"], pinned)

    def test_nonblocking_stable_read_rejects_fifo_without_waiting(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="functional-v4-fifo-", dir=os.environ["ALLOCATBELT_V4_TEST_OUTPUT_ROOT"],
        ) as temporary:
            fifo = Path(temporary) / "source.fifo"
            os.mkfifo(fifo)
            started = time.monotonic()
            with self.assertRaisesRegex(RuntimeError, "not a regular file"):
                HELPER.read_stable(fifo, "FIFO race fixture", 1024)
            self.assertLess(time.monotonic() - started, 1.0)

    def test_preflight_capture_timeout_and_signals_clean_the_entire_process_group(self) -> None:
        temporary = tempfile.TemporaryDirectory(
            prefix="functional-v4-groups-", dir=os.environ["ALLOCATBELT_V4_TEST_OUTPUT_ROOT"],
        )
        self.addCleanup(temporary.cleanup)
        temporary_root = Path(temporary.name)
        pid_file = temporary_root / "timeout-grandchild.pid"
        child_code = (
            "import os,signal,subprocess,sys,time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "grand=subprocess.Popen([sys.executable,'-c',\"import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)\"]); "
            "open(sys.argv[1],'w').write(str(grand.pid)); print('ready',flush=True); time.sleep(60)"
        )
        with self.assertRaisesRegex(RuntimeError, "finite deadline"):
            HELPER.run_capture_bounded(
                [sys.executable, "-c", child_code, str(pid_file)], self.source_root,
                timeout_seconds=1, max_stdout_bytes=1024,
            )
        self._assert_pid_stopped(int(pid_file.read_text(encoding="ascii")))

        output_error = None
        try:
            HELPER.run_capture_bounded(
                [sys.executable, "-c", "import sys; sys.stdout.write('x'*4096)"],
                self.source_root, timeout_seconds=5, max_stdout_bytes=128,
            )
        except RuntimeError as error:
            output_error = error
        self.assertIsNotNone(output_error)
        self.assertIn("capture ceiling", str(output_error))

        for signum in (__import__("signal").SIGHUP, __import__("signal").SIGINT, __import__("signal").SIGTERM):
            with self.subTest(signal=signum):
                signal_pid_file = temporary_root / f"signal-grandchild-{signum}.pid"
                wrapper = (
                    "import importlib.util,sys\nfrom pathlib import Path\n"
                    f"spec=importlib.util.spec_from_file_location('signal_helper', {str(HELPER_PATH)!r})\n"
                    "helper=importlib.util.module_from_spec(spec)\nspec.loader.exec_module(helper)\n"
                    f"child={child_code!r}\n"
                    "try:\n"
                    "    helper.run_capture_bounded([sys.executable,'-c',child,sys.argv[1]],Path.cwd(),timeout_seconds=20)\n"
                    "except RuntimeError as error:\n"
                    "    print(str(error))\n"
                    "    raise SystemExit(23)\n"
                    "raise SystemExit(0)\n"
                )
                wrapper_process = subprocess.Popen(
                    [sys.executable, "-c", wrapper, str(signal_pid_file)],
                    cwd=self.source_root, stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
                    env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                )
                try:
                    deadline = time.monotonic() + 5
                    while not signal_pid_file.exists() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue(signal_pid_file.exists(), "signal fixture child did not become live")
                    os.kill(wrapper_process.pid, signum)
                    self.assertEqual(wrapper_process.wait(timeout=5), 23)
                    self._assert_pid_stopped(int(signal_pid_file.read_text(encoding="ascii")))
                finally:
                    if wrapper_process.poll() is None:
                        wrapper_process.kill()
                        wrapper_process.wait(timeout=2)

        # The command leader exits successfully, but its child keeps the capture
        # pipes open. Deliver HUP only after the leader has been reaped so this
        # exercises the normal-exit cleanup window rather than command startup.
        cleanup_pid_file = temporary_root / "cleanup-window-pids"
        cleanup_child = (
            "import os,subprocess,sys; from pathlib import Path; "
            "grand=subprocess.Popen([sys.executable,'-c',"
            "\"import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)\"]); "
            "temporary=Path(sys.argv[1]+'.tmp'); "
            "temporary.write_text(f'{os.getpid()} {grand.pid}',encoding='ascii'); "
            "os.replace(temporary,sys.argv[1])"
        )
        cleanup_wrapper = (
            "import importlib.util,os,signal,sys,threading,time\nfrom pathlib import Path\n"
            f"spec=importlib.util.spec_from_file_location('cleanup_signal_helper', {str(HELPER_PATH)!r})\n"
            "helper=importlib.util.module_from_spec(spec)\nspec.loader.exec_module(helper)\n"
            f"child={cleanup_child!r}\n"
            "def interrupt_after_leader_exit():\n"
            "    deadline=time.monotonic()+5\n"
            "    while not Path(sys.argv[1]).exists() and time.monotonic()<deadline: time.sleep(0.005)\n"
            "    if not Path(sys.argv[1]).exists(): return\n"
            "    leader=int(Path(sys.argv[1]).read_text().split()[0])\n"
            "    while Path(f'/proc/{leader}').exists() and time.monotonic()<deadline: time.sleep(0.005)\n"
            "    os.kill(os.getpid(),signal.SIGHUP)\n"
            "threading.Thread(target=interrupt_after_leader_exit,daemon=True).start()\n"
            "try:\n"
            "    helper.run_capture_bounded([sys.executable,'-c',child,sys.argv[1]],Path.cwd(),timeout_seconds=10)\n"
            "except RuntimeError as error:\n"
            "    Path(sys.argv[2]).write_text(str(error),encoding='utf-8')\n"
            "    raise SystemExit(23)\n"
            "raise SystemExit(0)\n"
        )
        cleanup_error_path = temporary_root / "cleanup-window-error"
        cleanup_process = subprocess.Popen(
            [sys.executable, "-c", cleanup_wrapper, str(cleanup_pid_file), str(cleanup_error_path)],
            cwd=self.source_root, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
        try:
            self.assertEqual(cleanup_process.wait(timeout=5), 23)
            _leader_pid, grandchild_pid = map(int, cleanup_pid_file.read_text(encoding="ascii").split())
            self.assertIn("interrupted by signal", cleanup_error_path.read_text(encoding="utf-8"))
            self._assert_pid_stopped(grandchild_pid)
        finally:
            if cleanup_process.poll() is None:
                cleanup_process.kill()
                cleanup_process.wait(timeout=2)

    def _assert_pid_stopped(self, pid: int) -> None:
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            try:
                status = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").rsplit(")", 1)[1].split()[0]
            except FileNotFoundError:
                return
            if status == "Z":
                return
            time.sleep(0.02)
        self.fail(f"process group descendant {pid} remained live after bounded cleanup")

    def test_capacity_liveness_requires_real_horizon_work_and_all_mixed_families(self) -> None:
        helper = HELPER.validate_v4_capacity_liveness
        helper("cpu", 30_000_000_000, 1, 31)
        with self.assertRaisesRegex(RuntimeError, "30-to-31-second"):
            helper("cpu", 29_999_999_999, 1, 31)
        with self.assertRaisesRegex(RuntimeError, "no completed work"):
            helper("cpu", 30_000_000_000, 0, 31)
        all_families = {"cpu": 1, "memory": 1, "http": 1, "disk": 1}
        helper("mixed", 30_000_000_000, 4, 31, all_families)
        empty_family = {**all_families, "disk": 0}
        with self.assertRaisesRegex(RuntimeError, "every family"):
            helper("mixed", 30_000_000_000, 3, 31, empty_family)

    def test_file_size_limit_is_an_exact_soft_and_hard_bound_and_tree_watch_is_live(self) -> None:
        temporary = tempfile.TemporaryDirectory(
            prefix="functional-v4-budgets-", dir=os.environ["ALLOCATBELT_V4_TEST_OUTPUT_ROOT"],
        )
        self.addCleanup(temporary.cleanup)
        temporary_root = Path(temporary.name)
        stdout = temporary_root / "rlimit.stdout"
        stderr = temporary_root / "rlimit.stderr"
        status = HELPER.run_bounded(
            [sys.executable, "-c",
             "import resource; print(*resource.getrlimit(resource.RLIMIT_FSIZE))"],
            self.source_root, stdout, stderr, 5, file_size_limit_bytes=16 * 1024 * 1024,
        )
        self.assertEqual(status, 0)
        self.assertEqual(
            tuple(map(int, stdout.read_text(encoding="ascii").split())),
            (16 * 1024 * 1024, 16 * 1024 * 1024),
        )

        tree = temporary_root / "watch-root"
        tree.mkdir(mode=0o700)
        self.addCleanup(lambda: shutil.rmtree(tree, ignore_errors=True))
        entry_root = temporary_root / "entry-root"
        (entry_root / "one" / "two").mkdir(parents=True)
        with self.assertRaisesRegex(RuntimeError, "directory-count budget"):
            HELPER.functional_tree_usage(
                entry_root, max_files=512, max_bytes=1024,
                max_directories=1, max_entries=1024,
            )
        limits = dict(HELPER.SOURCE_V4_FUNCTIONAL_LIMITS)
        try:
            HELPER.SOURCE_V4_FUNCTIONAL_LIMITS["max_output_bytes"] = 64
            HELPER.SOURCE_V4_FUNCTIONAL_LIMITS["minimum_free_bytes"] = 0
            writer = (
                "from pathlib import Path; import time; "
                f"Path({str(tree / 'oversized.bin')!r}).write_bytes(b'x'*256); time.sleep(60)"
            )
            with self.assertRaisesRegex(RuntimeError, "output budget exceeded"):
                HELPER.run_bounded(
                    [sys.executable, "-c", writer], self.source_root,
                    tree / "runner.stdout", tree / "runner.stderr", 5,
                    file_size_limit_bytes=16 * 1024 * 1024, watch_root=tree,
                )
        finally:
            HELPER.SOURCE_V4_FUNCTIONAL_LIMITS.update(limits)

    def test_report_records_the_caller_pinned_signer(self) -> None:
        source_manifest_sha = os.environ["ALLOCATBELT_V4_TEST_SOURCE_MANIFEST_SHA256"]
        self.assertRegex(source_manifest_sha, r"^[0-9a-f]{64}$")
        self.assertEqual(
            self.source_manifest_file_sha,
            __import__("hashlib").sha256(self.source_manifest_raw).hexdigest(),
        )
        self.assertIn(
            '"signer_fingerprint": args.signer_fingerprint',
            HELPER_PATH.read_text(encoding="utf-8"),
        )
        self.assertNotIn("SOURCE_GIT_SIGNING_FINGERPRINT", vars(HELPER))

    def test_selectable_contexts_are_exactly_the_original_fifteen(self) -> None:
        expected = {
            *((workload, profile) for workload in ("cpu", "memory", "http", "disk")
              for profile in ("steady", "burst", "oversubscribed")),
            *(('mixed', profile) for profile in ('mixed', 'burst', 'oversubscribed')),
        }
        self.assertEqual(set(HELPER.SOURCE_V4_CELLS), expected)
        self.assertEqual(len(HELPER.SOURCE_V4_CELLS), 15)
        self.assertNotIn(("cpu", "safety_overload"), HELPER.SOURCE_V4_CELLS)

    def test_binding_builder_uses_manifest_identity_without_campaign_or_phase_labels(self) -> None:
        context = HELPER.validate_source_v4_context(
            workload="mixed", profile="burst", mode="open_loop", pair_kind="matched",
            baseline_allocator=None, rate_per_second=100, arrivals=1000,
            trace_deadline_seconds=10, drain_deadline_seconds=10, shutdown_deadline_seconds=5,
            process_deadline_seconds=180, pair_deadline_seconds=360,
        )
        run_id = "functional-v4-inputs-mixed-burst-open_loop-matched-01"
        binding_manifest, bindings = HELPER.source_v4_runtime_bindings(self.source, context, run_id)
        self.assertEqual(binding_manifest["source_manifest_sha256"], self.source["manifest_sha256"])
        self.assertNotIn("campaign_id", binding_manifest)
        self.assertNotIn("phase", binding_manifest)
        self.assertEqual(
            {(item["pair"], item["executor"], item["allocator"]) for item in bindings},
            {("bounded", "bounded", "allocatbelt"), ("tokio", "tokio", "allocatbelt")},
        )
        for binding in bindings:
            self.assertEqual(binding["recipe"]["identity"]["source_sha256"], self.source["source"]["source_tree_sha256"])
            self.assertEqual(binding["recipe"]["identity"]["run_id"], run_id)
            self.assertEqual(binding["recipe"]["run"]["workload"], "mixed")
            self.assertEqual(binding["recipe"]["run"]["profile"], "burst")
            self.assertEqual(binding["recipe"]["run"]["mode"], "open_loop")
            self.assertEqual(binding["recipe"]["run"]["arrivals"], 1000)

    def test_allocator_baselines_are_only_actual_manifest_artifacts(self) -> None:
        for baseline in ("mimalloc-secure", "mimalloc-standard", "system"):
            context = HELPER.validate_source_v4_context(
                workload="disk", profile="oversubscribed", mode="open_loop", pair_kind="allocator-match",
                baseline_allocator=baseline, rate_per_second=100, arrivals=1000,
                trace_deadline_seconds=10, drain_deadline_seconds=10, shutdown_deadline_seconds=5,
                process_deadline_seconds=150, pair_deadline_seconds=360,
            )
            _manifest, bindings = HELPER.source_v4_runtime_bindings(
                self.source, context, f"functional-v4-inputs-disk-oversubscribed-{baseline}-01",
            )
            descriptors = {(item["pair"], item["allocator"]) for item in bindings}
            self.assertEqual(descriptors, {("candidate", "allocatbelt"), ("baseline", baseline)})
            baseline_binding = next(item for item in bindings if item["pair"] == "baseline")
            self.assertEqual(baseline_binding["recipe"]["identity"]["binary_sha256"], self.source["artifacts"][baseline]["sha256"])

    def test_capacity_recipe_keeps_exact_thirty_second_horizon_and_no_rate(self) -> None:
        context = HELPER.validate_source_v4_context(
            workload="mixed", profile="mixed", mode="capacity", pair_kind="aa-bounded",
            baseline_allocator=None, rate_per_second=None, arrivals=None,
            trace_deadline_seconds=30, drain_deadline_seconds=10, shutdown_deadline_seconds=5,
            process_deadline_seconds=300, pair_deadline_seconds=600,
        )
        _manifest, bindings = HELPER.source_v4_runtime_bindings(
            self.source, context, "functional-v4-inputs-mixed-capacity-aa-bounded-01",
        )
        validator = HELPER._CAMPAIGN.runtime_readback_module(self.source["runtime_readback_validator"]["sha256"])
        for binding in bindings:
            self.assertIsNone(binding["recipe"]["run"]["rate_per_second"])
            self.assertEqual(binding["recipe"]["run"]["arrivals"], 5000)
            expected = validator.build_fixed_expectation(binding["recipe"])
            self.assertEqual(expected["contract"]["configuration"]["trace_duration_ns"], "30000000000")
        with self.assertRaisesRegex(RuntimeError, "exact 30-second horizon"):
            HELPER.validate_source_v4_context(
                workload="mixed", profile="mixed", mode="capacity", pair_kind="aa-bounded",
                baseline_allocator=None, rate_per_second=None, arrivals=None,
                trace_deadline_seconds=29, drain_deadline_seconds=10, shutdown_deadline_seconds=5,
                process_deadline_seconds=300, pair_deadline_seconds=600,
            )

    def test_tmpdir_context_is_a_private_nonsymlink_directory_on_the_output_filesystem(self) -> None:
        transfer_root = os.environ.get("ALLOCATBELT_V4_TEST_OUTPUT_ROOT")
        if not transfer_root:
            self.skipTest("set ALLOCATBELT_V4_TEST_OUTPUT_ROOT to a private directory on the root filesystem")
        with tempfile.TemporaryDirectory(prefix="functional-v4-storage-", dir=transfer_root) as temporary:
            output_root = Path(temporary).resolve(strict=True)
            tmpdir_root = output_root / "tmp"
            tmpdir_root.mkdir(mode=0o700)
            record = HELPER.require_rootfs_storage_context(output_root, tmpdir_root)
            self.assertEqual(record["output_root"]["st_dev"], record["tmpdir_root"]["st_dev"])
            self.assertNotIn(record["tmpdir_root"]["filesystem_type"], ("tmpfs", "ramfs"))


if __name__ == "__main__":
    unittest.main()
