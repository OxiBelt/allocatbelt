#!/usr/bin/env python3
"""Native real-filesystem tests for the non-authorizing lineage capture IO."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SOURCE = Path(__file__).with_name("application-source5-lineage-capture.py")
SPEC = importlib.util.spec_from_file_location("source5_lineage_capture_tests", SOURCE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Source-pinned lineage capture IO target")
capture = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = capture
SPEC.loader.exec_module(capture)


def pin_for(origin: str, raw: bytes) -> dict[str, str]:
    return {"path": origin, "raw_sha256": hashlib.sha256(raw).hexdigest()}


def declaration_and_manifest(contents: dict[str, bytes]):
    objects = []
    captured = []
    for index, (relative, raw) in enumerate(sorted(contents.items())):
        pin = pin_for(f"/retained/source5/{index:04d}.json", raw)
        objects.append({
            "origin_pin": pin, "role": "preparation", "host_id": "host-kvm-a",
            "maximum_bytes": max(1, len(raw) + 10), "byte_count": len(raw),
            "phase": None, "run_id": None, "row_index": None, "job_sha256": None,
        })
        captured.append({
            "origin_pin": pin, "local_relative_path": relative,
            "byte_count": len(raw),
        })
    declaration = {
        "schema": capture.DECLARATION_SCHEMA,
        "cohort_host_ids": ["host-kvm-a", "host-kvm-b"],
        "objects": objects,
    }
    manifest = {"schema": capture.CAPTURE_MANIFEST_SCHEMA, "objects": captured}
    return declaration, manifest


def make_stage(root: Path, contents: dict[str, bytes]) -> Path:
    stage = root / "capture"
    stage.mkdir(mode=0o700)
    os.chmod(stage, 0o700)
    for relative, raw in contents.items():
        target = stage / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        for parent in (target.parent, *target.parent.parents):
            if parent == stage:
                break
            if stage in parent.parents:
                os.chmod(parent, 0o700)
        target.write_bytes(raw)
        os.chmod(target, 0o400)
    return stage


class PreparedExplorationLineageCaptureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="lineage-capture-test-")
        self.root = Path(self.temp.name)
        self.contents = {
            "header.json": b'{"schema":"header-v1"}\n',
            "objects/record-0001.json": b'{"schema":"record-v1"}\n',
        }
        self.declaration, self.manifest = declaration_and_manifest(self.contents)
        self.stage = make_stage(self.root, self.contents)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _reader(self, declaration=None, manifest=None, stage=None):
        return capture.PreparedExplorationLineageCaptureReaderV1(
            self.declaration if declaration is None else declaration,
            self.manifest if manifest is None else manifest,
            str(self.stage if stage is None else stage),
        )

    def test_reads_exact_local_bytes_and_reports_actual_physical_usage(self) -> None:
        with self._reader() as reader:
            first = self.declaration["objects"][0]["origin_pin"]
            second = self.declaration["objects"][1]["origin_pin"]
            self.assertEqual(reader(first, 1024), self.contents["header.json"])
            self.assertEqual(reader.read(second, 1024), self.contents["objects/record-0001.json"])
            usage = reader.storage_usage()
            self.assertEqual(usage, {
                "schema": capture.STORAGE_USAGE_SCHEMA,
                "file_count": 2, "directory_count": 1, "inode_count": 4,
                "byte_count": sum(map(len, self.contents.values())),
                "allocated_byte_count": sum(
                    path.stat().st_blocks * 512 for path in
                    (self.stage, self.stage / "objects", self.stage / "header.json",
                     self.stage / "objects/record-0001.json")
                ),
            })
            with self.assertRaises(capture.PreparedExplorationLineageCaptureError):
                reader({"path": "/retained/unlisted.json",
                        "raw_sha256": hashlib.sha256(b"ambient").hexdigest()}, 1024)
        with self.assertRaises(capture.PreparedExplorationLineageCaptureError):
            reader(first, 1024)

    def test_rejects_unknown_pins_bad_caps_and_local_path_aliases(self) -> None:
        bad = copy.deepcopy(self.manifest)
        bad["objects"][0]["origin_pin"]["path"] = "/retained/unknown.json"
        with self.assertRaises(capture.PreparedExplorationLineageCaptureError):
            self._reader(manifest=bad)

        bad = copy.deepcopy(self.manifest)
        bad["objects"][0]["origin_pin"]["raw_sha256"] = "0" * 64
        with self.assertRaises(capture.PreparedExplorationLineageCaptureError):
            self._reader(manifest=bad)

        bad = copy.deepcopy(self.manifest)
        bad["objects"][0]["local_relative_path"] = "../escape.json"
        with self.assertRaises(capture.PreparedExplorationLineageCaptureError):
            self._reader(manifest=bad)

        bad = copy.deepcopy(self.manifest)
        bad["objects"][1]["local_relative_path"] = bad["objects"][0]["local_relative_path"]
        with self.assertRaises(capture.PreparedExplorationLineageCaptureError):
            self._reader(manifest=bad)

        bad = copy.deepcopy(self.manifest)
        bad["objects"][0]["byte_count"] -= 1
        with self.assertRaises(capture.PreparedExplorationLineageCaptureError):
            self._reader(manifest=bad)

        bad = copy.deepcopy(self.declaration)
        bad["objects"][0]["maximum_bytes"] = len(self.contents["header.json"]) - 1
        with self.assertRaises(capture.PreparedExplorationLineageCaptureError):
            self._reader(declaration=bad)

    def test_rejects_symlink_hardlink_wrong_mode_and_changed_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lineage-capture-link-") as temp:
            root = Path(temp)
            stage = make_stage(root, self.contents)
            target = stage / "objects/record-0001.json"
            saved = target.with_suffix(".saved")
            target.rename(saved)
            target.symlink_to(saved.name)
            with self.assertRaises(capture.PreparedExplorationLineageCaptureError):
                self._reader(stage=stage)

        with tempfile.TemporaryDirectory(prefix="lineage-capture-hardlink-") as temp:
            root = Path(temp)
            stage = make_stage(root, self.contents)
            os.link(stage / "header.json", stage / "extra.json")
            with self.assertRaises(capture.PreparedExplorationLineageCaptureError):
                self._reader(stage=stage)

        with tempfile.TemporaryDirectory(prefix="lineage-capture-mode-") as temp:
            root = Path(temp)
            stage = make_stage(root, self.contents)
            os.chmod(stage / "header.json", 0o600)
            with self.assertRaises(capture.PreparedExplorationLineageCaptureError):
                self._reader(stage=stage)

        with tempfile.TemporaryDirectory(prefix="lineage-capture-bytes-") as temp:
            root = Path(temp)
            stage = make_stage(root, self.contents)
            target = stage / "header.json"
            os.chmod(target, 0o600)
            target.write_bytes(b"X" * len(self.contents["header.json"]))
            os.chmod(target, 0o400)
            with self.assertRaises(capture.PreparedExplorationLineageCaptureError):
                self._reader(stage=stage)

    def test_detects_replaced_file_directory_and_root_after_custody(self) -> None:
        reader = self._reader()
        try:
            target = self.stage / "header.json"
            replacement = self.stage / "replacement"
            replacement.write_bytes(self.contents["header.json"])
            os.chmod(replacement, 0o400)
            os.replace(replacement, target)
            with self.assertRaises(capture.PreparedExplorationLineageCaptureError):
                reader(self.declaration["objects"][0]["origin_pin"], 1024)
        finally:
            reader.close()

        with tempfile.TemporaryDirectory(prefix="lineage-capture-dir-") as temp:
            root = Path(temp)
            stage = make_stage(root, self.contents)
            reader = self._reader(stage=stage)
            try:
                old = stage / "objects"
                moved = stage / "objects-old"
                old.rename(moved)
                old.mkdir(mode=0o700)
                replacement = old / "record-0001.json"
                replacement.write_bytes(self.contents["objects/record-0001.json"])
                os.chmod(replacement, 0o400)
                with self.assertRaises(capture.PreparedExplorationLineageCaptureError):
                    reader(self.declaration["objects"][1]["origin_pin"], 1024)
            finally:
                reader.close()

        with tempfile.TemporaryDirectory(prefix="lineage-capture-root-") as temp:
            root = Path(temp)
            stage = make_stage(root, self.contents)
            reader = self._reader(stage=stage)
            try:
                moved = root / "capture-old"
                stage.rename(moved)
                stage.mkdir(mode=0o700)
                os.chmod(stage, 0o700)
                with self.assertRaises((capture.PreparedExplorationLineageCaptureError,
                                        OSError)):
                    reader(self.declaration["objects"][0]["origin_pin"], 1024)
            finally:
                reader.close()

    def test_caller_and_source_caps_are_independent_bounds_on_actual_bytes(self) -> None:
        first = self.declaration["objects"][0]["origin_pin"]
        size = len(self.contents["header.json"])
        with self._reader() as reader:
            self.assertEqual(reader(first, size), self.contents["header.json"])
            self.assertEqual(reader(first, 1 << 30), self.contents["header.json"])
            for maximum in (size - 1, 0, -1, True, 1.0):
                with self.subTest(maximum=maximum), self.assertRaises(
                        capture.PreparedExplorationLineageCaptureError):
                    reader(first, maximum)
        bad = copy.deepcopy(self.declaration)
        bad["objects"][0]["byte_count"] = None
        bad["objects"][0]["maximum_bytes"] = size - 1
        with self.assertRaises(capture.PreparedExplorationLineageCaptureError):
            self._reader(declaration=bad)

    def test_undeclared_subtree_is_rejected_before_it_is_opened(self) -> None:
        extra = self.stage / "undeclared"
        extra.mkdir(mode=0o700)
        for index in range(24):
            extra = extra / str(index)
            extra.mkdir(mode=0o700)
        real_open = os.open
        attempted = []

        def observe(path, flags, *args, **kwargs):
            if path == "undeclared":
                attempted.append(path)
            return real_open(path, flags, *args, **kwargs)

        with patch.object(capture.os, "open", side_effect=observe):
            with self.assertRaises(capture.PreparedExplorationLineageCaptureError):
                self._reader()
        self.assertEqual(attempted, [])

    def test_fifo_swap_at_open_is_nonblocking_and_rejected(self) -> None:
        first = self.declaration["objects"][0]["origin_pin"]
        with self._reader() as reader:
            real_open = os.open
            swapped = False

            def swap(path, flags, *args, **kwargs):
                nonlocal swapped
                if path == "header.json" and not swapped:
                    swapped = True
                    target = self.stage / "header.json"
                    target.unlink()
                    os.mkfifo(target, 0o400)
                    self.assertTrue(flags & os.O_NONBLOCK)
                return real_open(path, flags, *args, **kwargs)

            with patch.object(capture.os, "open", side_effect=swap):
                with self.assertRaises(capture.PreparedExplorationLineageCaptureError):
                    reader(first, 1024)
            self.assertTrue(swapped)

    def test_parent_directory_swap_during_actual_read_is_rejected(self) -> None:
        second = self.declaration["objects"][1]["origin_pin"]
        with self._reader() as reader:
            real_read = os.read
            swapped = False

            def swap(descriptor, maximum):
                nonlocal swapped
                raw = real_read(descriptor, maximum)
                if raw and not swapped:
                    swapped = True
                    original = self.stage / "objects"
                    original.rename(self.root / "detached-objects")
                    original.mkdir(mode=0o700)
                    target = original / "record-0001.json"
                    target.write_bytes(self.contents["objects/record-0001.json"])
                    target.chmod(0o400)
                return raw

            with patch.object(capture.os, "read", side_effect=swap):
                with self.assertRaises(capture.PreparedExplorationLineageCaptureError):
                    reader(second, 1024)
            self.assertTrue(swapped)

    def test_rejects_extra_or_missing_files_and_nonprivate_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lineage-capture-extra-") as temp:
            stage = make_stage(Path(temp), self.contents)
            extra = stage / "extra.json"
            extra.write_bytes(b"extra\n")
            os.chmod(extra, 0o400)
            with self.assertRaises(capture.PreparedExplorationLineageCaptureError):
                self._reader(stage=stage)

        with tempfile.TemporaryDirectory(prefix="lineage-capture-missing-") as temp:
            stage = make_stage(Path(temp), self.contents)
            (stage / "header.json").unlink()
            with self.assertRaises(capture.PreparedExplorationLineageCaptureError):
                self._reader(stage=stage)

        with tempfile.TemporaryDirectory(prefix="lineage-capture-root-mode-") as temp:
            stage = make_stage(Path(temp), self.contents)
            os.chmod(stage, 0o755)
            with self.assertRaises(capture.PreparedExplorationLineageCaptureError):
                self._reader(stage=stage)


if __name__ == "__main__":
    unittest.main()
