#!/usr/bin/env python3
"""Focused contract tests for the separate construction read I/O ports."""
from __future__ import annotations

import ast
import importlib.util
import inspect
import types
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent


def load_sibling(filename: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, filename)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load test dependency {filename.name}")
    module = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


campaign = load_sibling(
    SCRIPT_DIR / "application-source5-campaign.py",
    "source5_construction_read_campaign_tests",
)
archive = load_sibling(
    SCRIPT_DIR / "application-source5-evidence-archive.py",
    "source5_construction_read_archive_tests",
)


class ConstructionReadPortTests(unittest.TestCase):
    def test_construction_dispatch_uses_only_construction_apis(self) -> None:
        ordinary = lambda *args, **kwargs: "ordinary"
        construction = lambda *args, **kwargs: "construction"
        module = types.SimpleNamespace(
            validate_recorded_preparation_read_window_v2=ordinary,
            validate_prepared_input_construction_read_window_v1=construction,
        )
        self.assertIs(
            campaign._source5_recorded_read_plan_member(
                module, "validate_window",
            ), ordinary,
        )
        self.assertIs(
            campaign._source5_recorded_read_plan_member(
                module, "validate_window", construction=True,
            ), construction,
        )
        self.assertIs(
            archive._recorded_read_plan_member(module, "validate_window"),
            ordinary,
        )
        self.assertIs(
            archive._recorded_read_plan_member(
                module, "validate_window", construction=True,
            ), construction,
        )

    def test_missing_construction_api_does_not_fall_back_to_replay(self) -> None:
        module = types.SimpleNamespace(
            validate_recorded_preparation_read_window_v2=lambda *args: None,
        )
        with self.assertRaises(campaign.Source5CampaignError):
            campaign._source5_recorded_read_plan_member(
                module, "validate_window", construction=True,
            )
        with self.assertRaises(archive.EvidenceArchiveError):
            archive._recorded_read_plan_member(
                module, "validate_window", construction=True,
            )

    def test_public_ports_have_fixed_protocol_signatures(self) -> None:
        public_ports = (
            campaign.source5_prepared_input_construction_read_client_v1,
            campaign.publish_source5_prepared_input_construction_readback_v1,
            archive.serve_source5_prepared_input_construction_read_window_v1,
            archive.release_source5_prepared_input_construction_read_root_output_v1,
        )
        for port in public_ports:
            with self.subTest(port=port.__name__):
                self.assertNotIn("construction", inspect.signature(port).parameters)

    def test_ordinary_h_loader_rejects_construction_basis(self) -> None:
        basis = {
            "schema": campaign.SOURCE5_PREPARED_INPUT_CONSTRUCTION_BASIS_SCHEMA,
        }
        with self.assertRaises(campaign.Source5CampaignError):
            campaign._source5_recorded_read_plan_module(basis, b"")

    def test_ordinary_root_closure_keeps_current_width_finalization(self) -> None:
        graph = {"reader": types.SimpleNamespace(close=lambda: None)}
        with mock.patch.object(
            archive, "_recorded_pre_manifest_source_graph", return_value=graph,
        ), mock.patch.object(
            archive, "_recorded_pre_manifest_source_current_width",
            return_value={"validated": True},
        ) as finalize_width:
            result = archive._recorded_pre_manifest_source_closure(
                {}, {}, b"", b"", "", "", None,
            )
        finalize_width.assert_called_once()
        self.assertEqual(result["width"], {"validated": True})

    def test_construction_root_closure_has_no_current_width_finalizer(self) -> None:
        graph = {"reader": types.SimpleNamespace(close=lambda: None)}
        with mock.patch.object(
            archive, "_recorded_pre_manifest_source_graph", return_value=graph,
        ), mock.patch.object(
            archive, "_recorded_pre_manifest_source_current_width",
        ) as finalize_width:
            result = archive._recorded_pre_manifest_source_construction_closure(
                {"construction_inputs": {}}, {}, b"", b"", "", "", None,
            )
        finalize_width.assert_not_called()
        self.assertNotIn("width", result)

    def test_h_payload_yield_keeps_the_exact_three_fields(self) -> None:
        tree = ast.parse(
            (SCRIPT_DIR / "application-source5-campaign.py").read_text(),
        )
        client = next(
            node for node in tree.body
            if isinstance(node, ast.ClassDef) and
            node.name == "_Source5RecordedPreparationReadClient"
        )
        open_view = next(
            node for node in client.body
            if isinstance(node, ast.FunctionDef) and node.name == "open_view"
        )
        yields = [node for node in ast.walk(open_view)
                  if isinstance(node, ast.Yield) and
                  isinstance(node.value, ast.Dict)]
        self.assertEqual(len(yields), 1)
        keys = [item.value for item in yields[0].value.keys
                if isinstance(item, ast.Constant)]
        self.assertEqual(keys, [
            "payload_view", "objects_by_origin", "stage_root",
        ])



class ConstructionPhysicalAdmissionTests(unittest.TestCase):
    """Exercise the actual output-directory guard without creating a payload."""

    def setUp(self) -> None:
        import os
        import tempfile
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.output = self.root / "completion"
        self.output.mkdir(mode=0o700)
        self.scratch = self.root / "scratch"
        self.scratch.mkdir(mode=0o700)
        space = os.statvfs(self.scratch)
        self.block = space.f_frsize or space.f_bsize
        required = ((64 * 1024 * 1024 + self.block - 1) // self.block) * self.block + self.block
        self.plan = {
            "completion_output_reservation": {
                "schema": "allocatbelt.application-source5-prepared-input-completion-reservation.v1",
                "path": str(self.output / "prepared-inputs-completion.json"),
                "device_id": self.output.stat().st_dev,
                "allocation_block_bytes": self.block,
                "maximum_file_bytes": 64 * 1024 * 1024,
                "directory_growth_reserve_bytes": self.block,
                "required_bytes": required, "required_inodes": 1,
                "declared_reserved_bytes": required,
                "declared_reserved_inodes": 1,
                "same_device_as_scratch": True,
                "same_device_required_bytes": required + self.block,
                "same_device_required_inodes": 2,
            },
            "scratch_declaration": {
                "root": str(self.scratch),
                "device_id": self.scratch.stat().st_dev,
                "allocation_block_bytes": self.block,
            },
            "resource_projection": {
                "required_bytes": self.block, "required_inodes": 1,
            },
        }

    def check(self) -> None:
        campaign._source5_prepared_input_construction_check_resources(
            self.plan, self.block, 1, require_output_absent=True,
        )

    def available(self, byte_count: int, inode_count: int):
        import os
        values = list(os.statvfs(self.scratch))
        values[4] = byte_count // self.block
        values[7] = inode_count
        return os.statvfs_result(values)

    def test_real_private_directories_and_space_are_admitted(self) -> None:
        self.check()
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_existing_completion_is_retained_and_rejected(self) -> None:
        path = Path(self.plan["completion_output_reservation"]["path"])
        path.write_bytes(b"existing receipt")
        inode = path.stat().st_ino
        with self.assertRaisesRegex(campaign.Source5CampaignError, "already exists"):
            self.check()
        self.assertEqual(path.stat().st_ino, inode)
        self.assertEqual(path.read_bytes(), b"existing receipt")

    def test_shared_device_exact_boundary_and_one_block_short(self) -> None:
        total = self.plan["completion_output_reservation"]["same_device_required_bytes"]
        with mock.patch.object(campaign.os, "statvfs", return_value=self.available(total, 2)):
            self.check()
        with mock.patch.object(campaign.os, "statvfs", return_value=self.available(total - self.block, 2)):
            with self.assertRaisesRegex(campaign.Source5CampaignError, "shared device"):
                self.check()

    def test_shared_device_one_inode_short(self) -> None:
        total = self.plan["completion_output_reservation"]["same_device_required_bytes"]
        with mock.patch.object(campaign.os, "statvfs", return_value=self.available(total, 1)):
            with self.assertRaisesRegex(campaign.Source5CampaignError, "shared device"):
                self.check()

    def test_wrong_output_device_and_block_are_rejected(self) -> None:
        output = self.plan["completion_output_reservation"]
        for key, value in (("device_id", output["device_id"] + 1),
                           ("allocation_block_bytes", self.block * 2)):
            with self.subTest(field=key), mock.patch.dict(output, {key: value}):
                with self.assertRaisesRegex(campaign.Source5CampaignError, "device or finite reservation"):
                    self.check()

    def test_output_mode_and_symlink_are_rejected(self) -> None:
        self.output.chmod(0o755)
        with self.assertRaisesRegex(campaign.Source5CampaignError, "canonical private storage"):
            self.check()
        self.output.chmod(0o700)
        link = self.root / "output-link"
        link.symlink_to(self.output, target_is_directory=True)
        self.plan["completion_output_reservation"]["path"] = str(link / "prepared-inputs-completion.json")
        with self.assertRaisesRegex(campaign.Source5CampaignError, "canonical private storage"):
            self.check()

    def test_output_parent_replacement_between_lstat_and_open_is_rejected(self) -> None:
        original_open = campaign.os.open
        moved = self.root / "original-completion"
        def replacing_open(path, flags, *args, **kwargs):
            if Path(path) == self.output:
                self.output.rename(moved)
                self.output.mkdir(mode=0o700)
            return original_open(path, flags, *args, **kwargs)
        with mock.patch.object(campaign.os, "open", side_effect=replacing_open):
            with self.assertRaisesRegex(campaign.Source5CampaignError, "device or finite reservation"):
                self.check()
        self.assertTrue(moved.is_dir())
        self.assertEqual(list(self.output.iterdir()), [])

    def test_output_parent_descriptor_closes_on_success_and_failure(self) -> None:
        import os
        original_open = os.open
        opened = []
        def tracked_open(*args, **kwargs):
            fd = original_open(*args, **kwargs)
            opened.append(fd)
            return fd
        with mock.patch.object(campaign.os, "open", side_effect=tracked_open):
            self.check()
            self.plan["completion_output_reservation"]["device_id"] += 1
            with self.assertRaises(campaign.Source5CampaignError):
                self.check()
        self.assertEqual(len(opened), 2)
        for fd in opened:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_separate_real_filesystems_enforce_output_bytes_and_inodes(self) -> None:
        import os
        import tempfile
        # Linux qualification guests provide /dev/shm as a distinct tmpfs.
        with tempfile.TemporaryDirectory(dir="/dev/shm") as directory:
            scratch = Path(directory).resolve()
            self.assertNotEqual(scratch.stat().st_dev, self.output.stat().st_dev)
            fs = os.statvfs(scratch)
            block = fs.f_frsize or fs.f_bsize
            self.plan["scratch_declaration"] = {
                "root": str(scratch), "device_id": scratch.stat().st_dev,
                "allocation_block_bytes": block,
            }
            output = self.plan["completion_output_reservation"]
            output.update(same_device_as_scratch=False,
                          same_device_required_bytes=0,
                          same_device_required_inodes=0)
            self.check()
            original_space = os.fstatvfs
            output_fd = os.open(self.output, os.O_RDONLY | os.O_DIRECTORY)
            try:
                actual = original_space(output_fd)
            finally:
                os.close(output_fd)
            # Keep actual directories/devices; inject only finite free-space observations.
            for byte_short, inode_short in ((True, False), (False, True)):
                values = list(actual)
                values[4] = (output["required_bytes"] - self.block) // self.block if byte_short else output["required_bytes"] // self.block
                values[7] = 0 if inode_short else 1
                with self.subTest(bytes_short=byte_short, inodes_short=inode_short), mock.patch.object(campaign.os, "fstatvfs", return_value=os.statvfs_result(values)):
                    with self.assertRaisesRegex(campaign.Source5CampaignError, "separate device resources"):
                        self.check()


class ConstructionLeaseEntryTests(unittest.TestCase):
    def client(self, *, cancelled=False, expired=False):
        import threading
        import time
        client = object.__new__(campaign._Source5RecordedPreparationReadClient)
        client._construction = True
        client._provider_lock = threading.Lock()
        client.cancel_event = threading.Event()
        if cancelled:
            client.cancel_event.set()
        client._operation_deadline_ns = time.monotonic_ns() + (-1 if expired else 10_000_000_000)
        client.plan = {"timeout_declaration": {"maximum_io_window_seconds": 5}}
        return client

    def test_cancelled_construction_entry_releases_lease_without_io(self) -> None:
        client = self.client(cancelled=True)
        with mock.patch.object(campaign, "_source5_recorded_read_check_scratch") as scratch:
            with self.assertRaises(campaign.Source5CampaignError):
                with client.open_view(0):
                    self.fail("cancelled lease yielded")
        scratch.assert_not_called()
        self.assertTrue(client._provider_lock.acquire(blocking=False))
        client._provider_lock.release()

    def test_expired_construction_entry_releases_lease_without_io(self) -> None:
        client = self.client(expired=True)
        with mock.patch.object(campaign, "_source5_recorded_read_check_scratch") as scratch:
            with self.assertRaises(campaign.Source5CampaignError):
                with client.open_view(0):
                    self.fail("expired lease yielded")
        scratch.assert_not_called()
        self.assertTrue(client._provider_lock.acquire(blocking=False))
        client._provider_lock.release()

    def test_overlapping_construction_entry_preserves_existing_lease(self) -> None:
        client = self.client()
        self.assertTrue(client._provider_lock.acquire(blocking=False))
        try:
            with self.assertRaises(campaign.Source5CampaignError):
                with client.open_view(0):
                    self.fail("overlapping lease yielded")
            self.assertFalse(client._provider_lock.acquire(blocking=False))
        finally:
            client._provider_lock.release()


if __name__ == "__main__":
    unittest.main()
