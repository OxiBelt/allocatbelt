#!/usr/bin/env python3
"""Focused tests for typed, bounded Git source inventories."""

from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from typing import Any
from unittest import mock


SCRIPT = Path(__file__).with_name("application-source-inventory.py")
LOADER = importlib.machinery.SourceFileLoader("application_source_inventory", str(SCRIPT))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
assert SPEC is not None
inventory_module = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(inventory_module)


class SourceInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="application-source-inventory-")
        self.root = Path(self.temporary.name) / "source"
        self.root.mkdir()
        self.git("init", "-q")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *arguments: str) -> None:
        subprocess.run(["git", *arguments], cwd=self.root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def add(self, *paths: str) -> None:
        self.git("add", "--", *paths)

    def write(self, relative: str, value: bytes, mode: int = 0o644) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        path.chmod(mode)
        return path

    def link(self, relative: str, target: str) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(target)
        return path

    def test_tracks_license_symlink_as_literal_target_and_file_identity(self) -> None:
        self.write("LICENSE", b"license contents\n")
        self.link("crates/allocatbelt/LICENSE", "../../LICENSE")
        self.add("LICENSE", "crates/allocatbelt/LICENSE")

        value = inventory_module.inventory(self.root)
        self.assertEqual(value["schema"], inventory_module.SCHEMA)
        self.assertEqual(
            value["entries"],
            [
                {
                    "path": "LICENSE",
                    "kind": "file",
                    "mode": "100644",
                    "sha256": hashlib.sha256(b"license contents\n").hexdigest(),
                    "size": len(b"license contents\n"),
                },
                {
                    "path": "crates/allocatbelt/LICENSE",
                    "kind": "symlink",
                    "mode": "120000",
                    "target": "../../LICENSE",
                    "sha256": hashlib.sha256(b"../../LICENSE").hexdigest(),
                    "size": len(b"../../LICENSE"),
                },
            ],
        )
        digest = inventory_module.digest_inventory(value)
        self.assertEqual(inventory_module.source_tree_digest(self.root), digest)
        self.assertEqual(inventory_module.verify_source_tree(self.root, digest, value["entries"]), value)

    def test_same_content_retarget_changes_typed_identity(self) -> None:
        self.write("a", b"same")
        self.write("b", b"same")
        link = self.link("current", "a")
        self.add("a", "b", "current")
        first = inventory_module.inventory(self.root)
        first_digest = inventory_module.digest_inventory(first)

        link.unlink()
        link.symlink_to("b")
        self.git("add", "--", "current")
        second = inventory_module.inventory(self.root)
        self.assertNotEqual(first_digest, inventory_module.digest_inventory(second))
        with self.assertRaisesRegex(inventory_module.InventoryError, "differs from the frozen"):
            inventory_module.verify_source_tree(self.root, first_digest, first["entries"])

    def test_untracked_chmod_and_content_race_serialize_one_stable_snapshot(self) -> None:
        path = self.write("draft", b"before", 0o644)
        original_read_regular = inventory_module._read_regular

        def race_before_stable_open(root_fd, root_path, root_identity, raw_path, expected_mode):
            self.assertEqual(raw_path, b"draft")
            path.write_bytes(b"after-chmod-race")
            path.chmod(0o755)
            return original_read_regular(root_fd, root_path, root_identity, raw_path, expected_mode)

        with mock.patch.object(inventory_module, "_read_regular", side_effect=race_before_stable_open):
            value = inventory_module.inventory(self.root)
        self.assertEqual(
            value["entries"],
            [{
                "path": "draft",
                "kind": "file",
                "mode": "100755",
                "sha256": hashlib.sha256(b"after-chmod-race").hexdigest(),
                "size": len(b"after-chmod-race"),
            }],
        )

    def test_regular_to_fifo_swap_is_nonblocking_and_rejected(self) -> None:
        self.write("victim", b"regular file")
        self.add("victim")
        program = (
            "import os,runpy,sys\n"
            "module=runpy.run_path(sys.argv[1])\n"
            "real_open=os.open\n"
            "def racing_open(path,flags,*args,**kwargs):\n"
            " if path==b'victim' and kwargs.get('dir_fd') is not None:\n"
            "  directory=kwargs['dir_fd']\n"
            "  os.unlink(path,dir_fd=directory)\n"
            "  os.mkfifo(path,0o600,dir_fd=directory)\n"
            " return real_open(path,flags,*args,**kwargs)\n"
            "os.open=racing_open\n"
            "try: module['inventory'](sys.argv[2])\n"
            "except module['InventoryError'] as error: print(str(error))\n"
            "else: raise SystemExit('FIFO was accepted')\n"
        )
        try:
            result = subprocess.run(
                [sys.executable, "-B", "-c", program, str(SCRIPT), str(self.root)],
                check=False,
                capture_output=True,
                text=True,
                timeout=4,
            )
        except subprocess.TimeoutExpired:
            self.fail("opening a regular-to-FIFO replacement blocked instead of rejecting it")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("changed to a non-regular file", result.stdout)

    def test_untracked_regular_file_is_included_but_untracked_symlink_is_rejected(self) -> None:
        self.write("tracked", b"tracked")
        self.add("tracked")
        self.write("draft", b"draft")
        value = inventory_module.inventory(self.root)
        self.assertEqual([entry["path"] for entry in value["entries"]], ["draft", "tracked"])
        self.link("extra-link", "tracked")
        with self.assertRaisesRegex(inventory_module.InventoryError, "untracked or incorrectly-modeled symlink"):
            inventory_module.inventory(self.root)

    def test_untracked_only_source_tree_is_included(self) -> None:
        self.write("draft", b"untracked source")
        value = inventory_module.inventory(self.root)
        self.assertEqual([entry["path"] for entry in value["entries"]], ["draft"])
        self.assertEqual(value["entries"][0]["kind"], "file")

    def test_rejects_untracked_terminal_link_and_symlinked_parent(self) -> None:
        self.write("tracked", b"tracked")
        self.add("tracked")
        self.link("extra", "tracked")
        with self.assertRaisesRegex(inventory_module.InventoryError, "untracked or incorrectly-modeled symlink"):
            inventory_module.inventory(self.root)

        (self.root / "extra").unlink()
        self.write(".gitignore", b"/parent\n")
        self.write("real/file", b"body")
        self.write("parent/file", b"body")
        self.git("add", "-f", "--", ".gitignore", "real/file", "parent/file")
        (self.root / "parent/file").unlink()
        (self.root / "parent").rmdir()
        (self.root / "parent").symlink_to("real", target_is_directory=True)
        with self.assertRaisesRegex(inventory_module.InventoryError, "parent is missing, non-directory, or symlinked"):
            inventory_module.inventory(self.root)

    def test_rejects_escaping_dangling_directory_and_chained_targets(self) -> None:
        cases = (
            ("escape", "../outside", {"regular": b"body"}),
            ("dangling", "missing", {"regular": b"body"}),
            ("directory", "folder", {"folder/file": b"body"}),
            ("file-parent", "regular/../target", {"regular": b"body", "target": b"body"}),
            ("file-dot", "regular/.", {"regular": b"body"}),
            ("chain", "first", {"regular": b"body", "first": "regular"}),
        )
        for link_name, target, files in cases:
            with self.subTest(link=link_name):
                with tempfile.TemporaryDirectory(prefix="application-source-link-case-") as temporary:
                    root = Path(temporary) / "source"
                    root.mkdir()
                    subprocess.run(["git", "init", "-q"], cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    paths: list[str] = []
                    for name, contents in files.items():
                        path = root / name
                        path.parent.mkdir(parents=True, exist_ok=True)
                        if isinstance(contents, str):
                            path.symlink_to(contents)
                        else:
                            path.write_bytes(contents)
                        paths.append(name)
                    symlink_path = root / link_name
                    symlink_path.symlink_to(target)
                    paths.append(link_name)
                    subprocess.run(["git", "add", "--", *paths], cwd=root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    with self.assertRaises(inventory_module.InventoryError):
                        inventory_module.inventory(root)

    def test_actual_git_mode_is_checked_and_serialized(self) -> None:
        executable = self.write("tool", b"#!/bin/sh\n", 0o755)
        self.add("tool")
        value = inventory_module.inventory(self.root)
        self.assertEqual(value["entries"][0]["mode"], "100755")
        executable.chmod(0o644)
        with self.assertRaisesRegex(inventory_module.InventoryError, "tracked Git mode differs"):
            inventory_module.inventory(self.root)

    def test_tracked_symlink_cannot_be_replaced_by_a_regular_file(self) -> None:
        self.write("target", b"body")
        link = self.link("link", "target")
        self.add("target", "link")
        link.unlink()
        self.write("link", b"target")
        with self.assertRaisesRegex(inventory_module.InventoryError, "tracked symlink mode differs"):
            inventory_module.inventory(self.root)

    def test_record_validation_rejects_bad_link_hash_order_modes_and_bounds(self) -> None:
        file_record = {
            "path": "LICENSE",
            "kind": "file",
            "mode": "100644",
            "sha256": "a" * 64,
            "size": 1,
        }
        valid_link = {
            "path": "crate/LICENSE",
            "kind": "symlink",
            "mode": "120000",
            "target": "../LICENSE",
            "sha256": hashlib.sha256(b"../LICENSE").hexdigest(),
            "size": len(b"../LICENSE"),
        }
        valid = {"schema": inventory_module.SCHEMA, "entries": [file_record, valid_link]}
        self.assertEqual(inventory_module.validate_records(valid), valid["entries"])
        mutations: list[dict[str, Any]] = []
        bad_hash = {**valid_link, "sha256": "b" * 64}
        mutations.append({"schema": inventory_module.SCHEMA, "entries": [file_record, bad_hash]})
        bad_order = {"schema": inventory_module.SCHEMA, "entries": [valid_link, file_record]}
        mutations.append(bad_order)
        bad_mode = {"schema": inventory_module.SCHEMA, "entries": [{**file_record, "mode": "120000"}]}
        mutations.append(bad_mode)
        too_large = {"schema": inventory_module.SCHEMA, "entries": [{**file_record, "size": inventory_module.MAX_FILE_BYTES + 1}]}
        mutations.append(too_large)
        long_target = "a" * (inventory_module.MAX_SYMLINK_BYTES + 1)
        oversized_link = {
            **valid_link,
            "target": long_target,
            "sha256": hashlib.sha256(long_target.encode("utf-8")).hexdigest(),
            "size": len(long_target.encode("utf-8")),
        }
        mutations.append({"schema": inventory_module.SCHEMA, "entries": [file_record, oversized_link]})
        too_many_bytes = {
            "schema": inventory_module.SCHEMA,
            "entries": [
                {**file_record, "path": f"file-{index:02d}", "size": inventory_module.MAX_FILE_BYTES}
                for index in range(33)
            ],
        }
        mutations.append(too_many_bytes)
        prefix_file = {**file_record, "path": "crate/file"}
        terminal_file = {**file_record, "path": "crate/LICENSE"}
        for target in ("file/../LICENSE", "LICENSE/.", "LICENSE/"):
            invalid_target = {
                **valid_link,
                "target": target,
                "sha256": hashlib.sha256(target.encode("utf-8")).hexdigest(),
                "size": len(target.encode("utf-8")),
            }
            records = [terminal_file, prefix_file, {**invalid_target, "path": "crate/link"}]
            mutations.append({"schema": inventory_module.SCHEMA, "entries": records})
        for value in mutations:
            with self.subTest(value=value), self.assertRaises(inventory_module.InventoryError):
                inventory_module.validate_records(value)

    def test_git_capture_limit_is_enforced(self) -> None:
        self.write("one", b"1")
        self.write("two", b"2")
        self.add("one", "two")
        original = inventory_module.MAX_GIT_CAPTURE_BYTES
        inventory_module.MAX_GIT_CAPTURE_BYTES = 4
        try:
            with self.assertRaisesRegex(inventory_module.InventoryError, "capture bound"):
                inventory_module.inventory(self.root)
        finally:
            inventory_module.MAX_GIT_CAPTURE_BYTES = original

    def test_git_timeout_kills_descendant_after_leader_exits(self) -> None:
        pid_path = Path(self.temporary.name) / "timeout-descendant.pid"
        child_program = (
            "import os,signal,sys,time\n"
            "child=os.fork()\n"
            "if child==0:\n"
            " signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            " open(sys.argv[1],'w').write(str(os.getpid()))\n"
            " time.sleep(30)\n"
            " os._exit(0)\n"
            "os._exit(0)\n"
        )
        started = time.monotonic()
        with self.assertRaisesRegex(inventory_module.InventoryError, "finite deadline"):
            inventory_module._checked_capture([sys.executable, "-c", child_program, str(pid_path)], self.root, 0.2)
        self.assertLess(time.monotonic() - started, 3.0)
        self.assertTrue(pid_path.is_file(), "child process did not start before the bounded timeout")
        self.assert_process_stopped(int(pid_path.read_text(encoding="ascii")))

    def test_successful_capture_reaps_detached_descendant_after_leader_exit(self) -> None:
        pid_path = Path(self.temporary.name) / "success-descendant.pid"
        child_program = (
            "import os,signal,sys,time\n"
            "child=os.fork()\n"
            "if child==0:\n"
            " signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            " sink=os.open(os.devnull,os.O_WRONLY)\n"
            " os.dup2(sink,1)\n"
            " os.dup2(sink,2)\n"
            " open(sys.argv[1],'w').write(str(os.getpid()))\n"
            " time.sleep(30)\n"
            " os._exit(0)\n"
            "os.write(1,b'captured\\0')\n"
            "os._exit(0)\n"
        )
        started = time.monotonic()
        captured = inventory_module._checked_capture(
            [sys.executable, "-c", child_program, str(pid_path)], self.root, 2.0
        )
        self.assertEqual(captured, b"captured\0")
        self.assertLess(time.monotonic() - started, 3.0)
        self.assertTrue(pid_path.is_file(), "detached child process did not start")
        self.assert_process_stopped(int(pid_path.read_text(encoding="ascii")))

    def test_interrupt_during_success_cleanup_refuses_capture_success(self) -> None:
        pid_path = Path(self.temporary.name) / "cleanup-window-descendant.pid"
        cleanup_marker = Path(self.temporary.name) / "cleanup-window.started"
        child_program = (
            "import os,signal,sys,time\n"
            "child=os.fork()\n"
            "if child==0:\n"
            " signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            " sink=os.open(os.devnull,os.O_WRONLY)\n"
            " os.dup2(sink,1)\n"
            " os.dup2(sink,2)\n"
            " open(sys.argv[1],'w').write(str(os.getpid()))\n"
            " time.sleep(30)\n"
            " os._exit(0)\n"
            "os.write(1,b'captured\\0')\n"
            "os._exit(0)\n"
        )
        outer_program = (
            "import os,runpy,sys,time\nfrom pathlib import Path\n"
            "module=runpy.run_path(sys.argv[1])\n"
            "real_stop=module['_stop_process_group']\n"
            "def notify_stop(process,**kwargs):\n"
            " Path(sys.argv[4]).write_text(str(os.getpid()))\n"
            " time.sleep(0.3)\n"
            " return real_stop(process,**kwargs)\n"
            "module['_checked_capture'].__globals__['_stop_process_group']=notify_stop\n"
            "try:\n"
            " module['_checked_capture']([sys.executable,'-c',sys.argv[3],sys.argv[5]],Path(sys.argv[2]),60)\n"
            "except module['InventoryError'] as error:\n"
            " print(str(error))\n"
            " raise SystemExit(0)\n"
            "raise SystemExit('capture unexpectedly succeeded')\n"
        )
        process = subprocess.Popen(
            [sys.executable, "-B", "-c", outer_program, str(SCRIPT), str(self.root), child_program, str(cleanup_marker), str(pid_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        descendant = None
        try:
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline and not cleanup_marker.exists():
                if process.poll() is not None:
                    break
                time.sleep(0.01)
            if not cleanup_marker.is_file():
                if process.poll() is not None:
                    try:
                        early_stdout, early_stderr = process.communicate(timeout=0.5)
                    except subprocess.TimeoutExpired:
                        early_stdout, early_stderr = b"", b""
                    self.fail(
                        "capture exited before its successful cleanup window: "
                        f"status={process.returncode}, stdout={early_stdout!r}, stderr={early_stderr!r}"
                    )
                self.fail("capture did not enter its successful cleanup window")
            descendant = int(pid_path.read_text(encoding="ascii"))
            os.kill(process.pid, signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=4.0)
            self.assertEqual(process.returncode, 0, stderr.decode(errors="replace"))
            self.assertIn("during capture cleanup", stdout.decode(errors="replace"))
            self.assert_process_stopped(descendant)
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=2.0)
            if descendant is not None:
                self.kill_process(descendant)

    def test_sighup_is_forwarded_and_capture_group_is_cleaned(self) -> None:
        pid_path = Path(self.temporary.name) / "hup-descendant.pid"
        hup_marker = Path(self.temporary.name) / "hup-forwarded"
        child_program = (
            "import os,signal,sys,time\n"
            "child=os.fork()\n"
            "if child==0:\n"
            " signal.signal(signal.SIGHUP,lambda *_: open(sys.argv[2],'w').write('hup'))\n"
            " signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            " open(sys.argv[1],'w').write(str(os.getpid()))\n"
            " time.sleep(30)\n"
            " os._exit(0)\n"
            "os._exit(0)\n"
        )
        outer_program = (
            "import runpy,sys\nfrom pathlib import Path\n"
            "module=runpy.run_path(sys.argv[1])\n"
            "try:\n"
            " module['_checked_capture']([sys.executable,'-c',sys.argv[3],sys.argv[4],sys.argv[5]],Path(sys.argv[2]),60)\n"
            "except module['InventoryError'] as error:\n"
            " print(str(error))\n"
            " raise SystemExit(0)\n"
            "raise SystemExit('capture unexpectedly returned')\n"
        )
        process = subprocess.Popen(
            [sys.executable, "-B", "-c", outer_program, str(SCRIPT), str(self.root), child_program, str(pid_path), str(hup_marker)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        descendant = None
        try:
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline and not pid_path.exists():
                if process.poll() is not None:
                    break
                time.sleep(0.01)
            self.assertTrue(pid_path.is_file(), "capture child did not establish its SIGHUP handler")
            descendant = int(pid_path.read_text(encoding="ascii"))
            os.kill(process.pid, signal.SIGHUP)
            stdout, stderr = process.communicate(timeout=4.0)
            self.assertEqual(process.returncode, 0, stderr.decode(errors="replace"))
            self.assertIn("interrupted by signal", stdout.decode(errors="replace"))
            self.assertEqual(hup_marker.read_text(encoding="ascii"), "hup")
            self.assert_process_stopped(descendant)
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=2.0)
            if descendant is not None:
                self.kill_process(descendant)

    def test_sigterm_is_forwarded_to_capture_group_and_cleanup_is_bounded(self) -> None:
        pid_path = Path(self.temporary.name) / "signal-descendant.pid"
        child_program = (
            "import os,signal,sys,time\n"
            "child=os.fork()\n"
            "if child==0:\n"
            " signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
            " open(sys.argv[1],'w').write(str(os.getpid()))\n"
            " time.sleep(30)\n"
            " os._exit(0)\n"
            "os._exit(0)\n"
        )
        outer_program = (
            "import runpy,sys\nfrom pathlib import Path\n"
            "module=runpy.run_path(sys.argv[1])\n"
            "try:\n"
            " module['_checked_capture']([sys.executable,'-c',sys.argv[3],sys.argv[4]],Path(sys.argv[2]),60)\n"
            "except module['InventoryError'] as error:\n"
            " print(str(error))\n"
            " raise SystemExit(0)\n"
            "raise SystemExit('capture unexpectedly returned')\n"
        )
        process = subprocess.Popen(
            [sys.executable, "-B", "-c", outer_program, str(SCRIPT), str(self.root), child_program, str(pid_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        descendant = None
        try:
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline and not pid_path.exists():
                if process.poll() is not None:
                    break
                time.sleep(0.01)
            self.assertTrue(pid_path.is_file(), "capture child did not establish its signal handler")
            descendant = int(pid_path.read_text(encoding="ascii"))
            started = time.monotonic()
            os.kill(process.pid, signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=4.0)
            self.assertEqual(process.returncode, 0, stderr.decode(errors="replace"))
            self.assertIn("interrupted by signal", stdout.decode(errors="replace"))
            self.assertLess(time.monotonic() - started, 4.0)
            self.assert_process_stopped(descendant)
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=2.0)
            if descendant is not None:
                self.kill_process(descendant)

    def assert_process_stopped(self, pid: int) -> None:
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            try:
                state = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").rsplit(")", 1)[1].split()[0]
            except FileNotFoundError:
                return
            if state == "Z":
                return
            time.sleep(0.01)
        self.fail(f"capture left descendant {pid} running")

    def kill_process(self, pid: int) -> None:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def test_file_count_bound_and_digest_cli(self) -> None:
        self.write("one", b"1")
        self.write("two", b"2")
        self.add("one", "two")
        original = inventory_module.MAX_FILES
        inventory_module.MAX_FILES = 1
        try:
            with self.assertRaisesRegex(inventory_module.InventoryError, "file-count bound"):
                inventory_module.inventory(self.root)
        finally:
            inventory_module.MAX_FILES = original

        expected = inventory_module.source_tree_digest(self.root)
        output = StringIO()
        with redirect_stdout(output):
            result = inventory_module.main(["digest", "--root", str(self.root)])
        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), expected + "\n")


if __name__ == "__main__":
    unittest.main()
