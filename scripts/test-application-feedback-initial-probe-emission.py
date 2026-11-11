"""Emitter DTO contracts and a non-APP direct-owner component check.

The `/usr/bin/true` fast-exit case exercises the actual Fixed owner and actual
PID/start/cleanup values only; it does not establish SourceV5 or ProbeV2 authority.
"""
from __future__ import annotations

import copy
import importlib.util
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parent


def _load_component(name: str, filename: str):
    module_spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    assert module_spec is not None and module_spec.loader is not None
    module = importlib.util.module_from_spec(module_spec)
    sys.modules[module_spec.name] = module
    module_spec.loader.exec_module(module)
    return module


composition = _load_component(
    "initial_probe_emission_composition_component",
    "application-feedback-composition.py",
)


def _request() -> dict[str, object]:
    return {
        "schema": composition.INITIAL_PROBE_REQUEST_SCHEMA,
        "source_root": str(composition.SOURCE_ROOT),
        "source_manifest": {
            "path": "/private/source-manifest.json", "raw_sha256": "a" * 64,
        },
        "context": {
            "host_id": "fixture-kvm-host-a",
            "workload": "cpu", "profile": "steady", "calibration_id": "capacity-cpu",
        },
        "allocator": "allocatbelt",
        "capacity_bundle": {
            "request": {"path": "/private/capacity-request.json", "raw_sha256": "b" * 64},
            "artifact": {"path": "/private/capacity.tsv", "raw_sha256": "c" * 64},
            "receipt": {"path": "/private/capacity-receipt.json", "raw_sha256": "d" * 64},
        },
        "observed_host": {"path": "/private/observed-host.json", "raw_sha256": "e" * 64},
        "output_root": "/private/probe-output",
        "emission_id": "f" * 32,
        "timeout_ns": 30_000_000_000,
        "storage_budget": {
            "tmpdir_bytes": 1024 * 1024 * 1024,
            "tmpdir_inodes": 4096,
            "stdout_bytes": 512 * 1024,
            "stderr_bytes": 64 * 1024,
            "owner_result_bytes": composition.MAX_PROBE_OWNER_RESULT_BYTES,
            "inventory_bytes": composition.MAX_PROBE_TMPDIR_INVENTORY_BYTES,
            "failure_bytes": composition.MAX_PROBE_CAPTURE_FAILURE_BYTES,
            "receipt_bytes": composition.MAX_PROBE_CAPTURE_RECEIPT_BYTES,
            "output_inodes": 4096,
        },
    }


def _receipt_body() -> dict[str, object]:
    body = {
        key: None for key in
        composition.INITIAL_PROBE_EMISSION_RECEIPT_FIELDS - {"receipt_sha256"}
    }
    body.update({
        "schema": composition.INITIAL_PROBE_EMISSION_SCHEMA,
        "role": composition.INITIAL_PROBE_EMISSION_ROLE,
        "verification_scope": "origin_host_resident_paths",
        "request_pin": {"path": "/private/request.json", "raw_sha256": "a" * 64},
        "owner_result_pin": {
            "path": "/private/owner.json", "raw_sha256": "b" * 64,
            "owner_result_sha256": "c" * 64,
        },
        "start_callback_count": 1,
        "start_callback_proof": {
            "pid": 321, "start_ticks": 456,
            "requested_argv": ["/source/bin", "--emit-feedback-policy-only"],
            "requested_argv_sha256": "d" * 64,
            "environment_sha256": "e" * 64,
        },
        "owner_supervision_sha256": "f" * 64,
        "stdout": {"path": "/private/stdout.bin", "raw_sha256": "1" * 64,
                   "byte_count": 128},
        "stderr": {"path": "/private/stderr.bin", "raw_sha256": "2" * 64,
                   "byte_count": 0},
        "construction_probe": {
            "path": "/private/stdout.bin", "raw_sha256": "1" * 64,
            "allocator": "allocatbelt", "binary_sha256": "3" * 64,
        },
        "binary": {
            "path": "/source/bin", "source_relative_path": "bin/allocatbelt",
            "raw_sha256": "3" * 64, "device": 11, "inode": 22, "size": 4096,
        },
        "output_mount_initial": {"available_bytes": 100000, "available_inodes": 10000},
        "output_mount_final": {"available_bytes": 90000, "available_inodes": 9990},
        "tmpdir_initial": {"available_bytes": 100000, "available_inodes": 10000},
        "tmpdir_final": {
            "device": 11, "inode": 23, "bytes_used": 0,
            "file_count": 0, "directory_count": 0,
            "available_bytes": 90000, "available_inodes": 9990,
        },
        "tmpdir_inventory_pin": {
            "path": "/private/inventory.json", "raw_sha256": "4" * 64,
            "inventory_sha256": "5" * 64,
        },
        "storage_budget": _request()["storage_budget"],
        "exit_status": 0,
        "qualification_eligible": False, "execution_ready": False,
        "controller_chronology_proven": False,
    })
    return body


def _write_success_layout(root: Path, *, include_receipt: bool) -> None:
    root.mkdir(mode=0o700)
    (root / "tmp").mkdir(mode=0o700)
    names = ["stdout.bin", "stderr.bin", "owner-result.json", "tmpdir-inventory.json"]
    if include_receipt:
        names.append("emission-receipt.json")
    for name in names:
        path = root / name
        path.write_bytes(b"")
        os.chmod(path, 0o600)


class InitialProbeEmissionRequestTests(unittest.TestCase):
    def test_source_selected_host_request_and_fixed_storage_budget_are_accepted(self) -> None:
        value = _request()
        self.assertEqual(composition._validate_initial_probe_request(value), value)
        value["context"]["host_id"] = "fixture-kvm-host-b"
        self.assertEqual(composition._validate_initial_probe_request(value), value)

    def test_malformed_host_and_probe_input_are_rejected_before_source_loading(self) -> None:
        malformed_host = _request()
        malformed_host["context"]["host_id"] = "host/alias"
        with self.assertRaises(composition.CompositionError):
            composition._validate_initial_probe_request(malformed_host)

        already_has_probe = _request()
        already_has_probe["construction_probe"] = {
            "path": "/private/fake-probe.json", "raw_sha256": "1" * 64,
            "allocator": "allocatbelt", "binary_sha256": "2" * 64,
        }
        with self.assertRaises(composition.CompositionError):
            composition._validate_initial_probe_request(already_has_probe)

    def test_emit_rejects_malformed_request_before_source_loader_or_owner(self) -> None:
        value = _request()
        value["context"]["host_id"] = "host/alias"
        raw = composition.canonical(value)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "initial-probe-request.json"
            path.write_bytes(raw)
            os.chmod(path, 0o600)
            original_loader = composition._load_initial_probe_source_stack

            def unexpected_source_load(_request):
                raise AssertionError("invalid request reached Source preflight")

            composition._load_initial_probe_source_stack = unexpected_source_load
            try:
                with self.assertRaises(composition.CompositionError):
                    composition.emit_initial_calibrated_probe_v2({
                        "path": str(path), "raw_sha256": composition.sha256(raw),
                    })
            finally:
                composition._load_initial_probe_source_stack = original_loader

    def test_floor_selector_and_storage_caps_are_closed(self) -> None:
        selected = _request()
        selected["capacity_floor_policy_id"] = composition.CAPACITY_FLOOR_POLICY_ID
        self.assertEqual(composition._validate_initial_probe_request(selected), selected)
        unknown_floor = _request()
        unknown_floor["capacity_floor_policy_id"] = "caller-chosen-floor"
        with self.assertRaises(composition.CompositionError):
            composition._validate_initial_probe_request(unknown_floor)
        oversized_stdout = _request()
        oversized_stdout["storage_budget"]["stdout_bytes"] += 1
        with self.assertRaises(composition.CompositionError):
            composition._validate_initial_probe_request(oversized_stdout)

    def test_initial_emission_receipt_has_a_distinct_ineligible_schema(self) -> None:
        body = {
            key: None for key in
            composition.INITIAL_PROBE_EMISSION_RECEIPT_FIELDS - {"receipt_sha256"}
        }
        body.update({
            "schema": composition.INITIAL_PROBE_EMISSION_SCHEMA,
            "role": composition.INITIAL_PROBE_EMISSION_ROLE,
            "verification_scope": "origin_host_resident_paths",
            "qualification_eligible": False,
            "execution_ready": False,
            "controller_chronology_proven": False,
        })
        receipt, raw = composition._seal_initial_probe_emission_receipt(body)
        self.assertEqual(receipt["schema"], composition.INITIAL_PROBE_EMISSION_SCHEMA)
        self.assertNotEqual(receipt["schema"], composition.PROBE_CAPTURE_RECEIPT_SCHEMA)
        self.assertEqual(receipt["receipt_sha256"], composition.sha256(
            composition.canonical(body),
        ))
        self.assertEqual(raw, composition.canonical(receipt))

    def test_resealed_start_and_binary_dtos_reject_boolean_zero_and_negative_fields(self) -> None:
        argv = ["/source/bin", "--emit-feedback-policy-only"]
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                       "TMPDIR": "/private/tmp"}
        body = _receipt_body()
        body["start_callback_proof"].update({
            "requested_argv": argv,
            "requested_argv_sha256": composition.sha256(composition.canonical(argv)),
            "environment_sha256": composition.sha256(composition.canonical(environment)),
        })
        base_receipt, _raw = composition._seal_initial_probe_emission_receipt(body)
        self.assertTrue(composition._validate_initial_probe_start_proof(
            base_receipt["start_callback_proof"], argv, environment,
        ))
        expected_descriptor = {"device": 11, "inode": 22, "size": 4096}
        binary_kwargs = {
            "expected_path": Path("/source/bin"),
            "source_relative_path": "bin/allocatbelt",
            "expected_sha256": "3" * 64,
            "expected_descriptor": expected_descriptor,
            "maximum_size": 512 * 1024 * 1024,
        }
        self.assertEqual(composition._validate_initial_probe_binary_identity(
            base_receipt["binary"], **binary_kwargs,
        ), expected_descriptor)
        start_invalids = {
            "pid": (True, 0, -1, 1 << 31),
            "start_ticks": (True, 0, -1, 1 << 64),
        }
        for field, invalid_values in start_invalids.items():
            for malformed in invalid_values:
                with self.subTest(field=field, malformed=malformed):
                    resealed_body = copy.deepcopy({
                        key: value for key, value in base_receipt.items()
                        if key != "receipt_sha256"
                    })
                    resealed_body["start_callback_proof"][field] = malformed
                    resealed, raw = composition._seal_initial_probe_emission_receipt(
                        resealed_body,
                    )
                    self.assertEqual(resealed["receipt_sha256"],
                                     composition.sha256(composition.canonical(resealed_body)))
                    self.assertEqual(raw, composition.canonical(resealed))
                    with self.assertRaises(composition.CompositionError):
                        composition._validate_initial_probe_start_proof(
                            resealed["start_callback_proof"], argv, environment,
                        )

        binary_invalids = {
            "device": (True, 0, -1, 1 << 64),
            "inode": (True, 0, -1, 1 << 64),
            "size": (True, 0, -1, 512 * 1024 * 1024 + 1),
        }
        for field, invalid_values in binary_invalids.items():
            for malformed in invalid_values:
                with self.subTest(field=field, malformed=malformed):
                    resealed_body = copy.deepcopy({
                        key: value for key, value in base_receipt.items()
                        if key != "receipt_sha256"
                    })
                    resealed_body["binary"][field] = malformed
                    resealed, raw = composition._seal_initial_probe_emission_receipt(
                        resealed_body,
                    )
                    self.assertEqual(raw, composition.canonical(resealed))
                    with self.assertRaises(composition.CompositionError):
                        composition._validate_initial_probe_binary_identity(
                            resealed["binary"], **binary_kwargs,
                        )
                    direct = {
                        "binary_path": "/source/bin", "binary_sha256": "3" * 64,
                        "binary_device": 11, "binary_inode": 22, "binary_size": 4096,
                    }
                    direct_field = {
                        "device": "binary_device", "inode": "binary_inode",
                        "size": "binary_size",
                    }[field]
                    direct[direct_field] = malformed
                    with self.assertRaises(composition.CompositionError):
                        composition._validate_initial_probe_direct_binary(
                            direct, expected_path=Path("/source/bin"),
                            expected_sha256="3" * 64,
                            expected_descriptor=expected_descriptor,
                            maximum_size=512 * 1024 * 1024,
                        )

    def test_resealed_receipt_must_fit_actual_and_template_request_reservations(self) -> None:
        body = _receipt_body()
        receipt, raw = composition._seal_initial_probe_emission_receipt(body)
        budget = body["storage_budget"]
        self.assertTrue(composition._validate_initial_probe_receipt_budget(
            receipt, raw, budget,
        ))

        actual_length_budget = dict(budget)
        actual_length_budget["receipt_bytes"] = 1
        actual_body = copy.deepcopy({
            key: value for key, value in receipt.items() if key != "receipt_sha256"
        })
        actual_body["storage_budget"] = actual_length_budget
        actual_receipt, actual_raw = composition._seal_initial_probe_emission_receipt(
            actual_body,
        )
        with self.assertRaises(composition.CompositionError):
            composition._validate_initial_probe_receipt_budget(
                actual_receipt, actual_raw, actual_length_budget,
            )

        template_budget = dict(budget)
        template_budget["receipt_bytes"] = len(raw) + 1
        template_body = copy.deepcopy({
            key: value for key, value in receipt.items() if key != "receipt_sha256"
        })
        template_body["storage_budget"] = template_budget
        template_receipt, template_raw = composition._seal_initial_probe_emission_receipt(
            template_body,
        )
        self.assertLessEqual(len(template_raw), template_budget["receipt_bytes"])
        self.assertGreater(composition._initial_probe_receipt_template_size(
            template_receipt,
        ), template_budget["receipt_bytes"])
        with self.assertRaises(composition.CompositionError):
            composition._validate_initial_probe_receipt_budget(
                template_receipt, template_raw, template_budget,
            )

    def test_success_layout_is_exact_streamed_and_charges_unknown_children(self) -> None:
        budget = _request()["storage_budget"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "emission"
            _write_success_layout(root, include_receipt=False)
            usage = composition._verify_initial_probe_success_layout(
                root, budget, include_receipt=False,
            )
            self.assertEqual(usage["inode_count"], 5)
            (root / "emission-receipt.json").write_bytes(b"")
            os.chmod(root / "emission-receipt.json", 0o600)
            self.assertEqual(
                composition._verify_initial_probe_success_layout(
                    root, budget, include_receipt=True,
                )["inode_count"],
                6,
            )
            (root / "unexpected.bin").write_bytes(b"extra")
            os.chmod(root / "unexpected.bin", 0o600)
            with self.assertRaises(composition.CompositionError):
                composition._verify_initial_probe_success_layout(
                    root, budget, include_receipt=True,
                )

            (root / "unexpected.bin").unlink()
            (root / "capture-failure.json").write_bytes(b"failure")
            os.chmod(root / "capture-failure.json", 0o600)
            with self.assertRaises(composition.CompositionError):
                composition._verify_initial_probe_success_layout(
                    root, budget, include_receipt=True,
                )

    def test_real_fast_exit_fixed_owner_return_join_component(self) -> None:
        # This runs the real Fixed owner on a system utility, not an APP; its
        # PID/start/supervision values are actual process facts, but this test
        # does not establish any SourceV5 or calibrated-Probe authority.
        binary_text = shutil.which("true")
        if binary_text is None:
            self.skipTest("no system true binary for the direct-owner component check")
        binary = Path(binary_text).resolve(strict=True)
        binary_info = binary.stat(follow_symlinks=False)
        if not stat.S_ISREG(binary_info.st_mode) or not (binary_info.st_mode & 0o111):
            self.skipTest("the located true executable is not a regular executable")
        binary_sha = composition.sha256(binary.read_bytes())
        descriptor = {
            "device": binary_info.st_dev, "inode": binary_info.st_ino,
            "size": binary_info.st_size,
        }
        fixed = _load_component("initial_probe_emission_fixed_component",
                                "application-fixed-pair.py")
        helper = _load_component("initial_probe_emission_identity_component",
                                 "application-soak-readback.py")
        capacity_stage = _load_component(
            "initial_probe_emission_capacity_stage_component",
            "application-capacity-stage.py",
        )
        affinity = sorted(os.sched_getaffinity(0))
        netns = os.stat("/proc/self/ns/net").st_ino
        argv = [str(binary)]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            try:
                fixed._mount_identity(root)
            except fixed.FixedPairError as error:
                self.skipTest(f"temporary filesystem cannot host direct-owner capture: {error}")
            run_dir = root / "run"
            run_dir.mkdir(mode=0o700)
            tmpdir = run_dir / "tmp"
            fixed._prepare_member_tmpdir(
                tmpdir, run_dir,
                {"tmpdir_bytes": 1024 * 1024, "tmpdir_inodes": 128},
            )
            environment = {
                "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                "TMPDIR": str(tmpdir),
            }
            fixed._require_waitable_sigchld()
            started = []
            direct = fixed._run_direct_process(
                argv, binary, binary_sha, Path(composition.SOURCE_ROOT), environment,
                affinity, run_dir / "stdout.bin", run_dir / "stderr.bin",
                4096, 4096, 2.0, helper, expected_tmpdir=tmpdir,
                expected_network_inode=netns,
                on_started=lambda proof: started.append(proof),
                capture_identity=False,
            )
            start, actual_descriptor = composition._validate_initial_probe_owner_return(
                direct, started, argv=argv, environment=environment,
                cwd=Path(composition.SOURCE_ROOT), affinity=affinity,
                network_namespace_inode=netns, binary=binary,
                binary_sha256=binary_sha, binary_descriptor=descriptor,
                maximum_binary_size=512 * 1024 * 1024,
                fixed=fixed, capacity_stage=capacity_stage,
            )
            owner_result, owner_raw = composition._probe_owner_result(direct, started)
            self.assertEqual(actual_descriptor, descriptor)
            self.assertGreater(start["pid"], 0)
            self.assertGreater(start["start_ticks"], 0)
            owner_body = {
                key: value for key, value in owner_result.items()
                if key != "owner_result_sha256"
            }
            self.assertEqual(owner_result["owner_result_sha256"],
                             composition.sha256(composition.canonical(owner_body)))
            self.assertEqual(owner_raw, composition.canonical(owner_result))
            owner_path = run_dir / "owner-result.json"
            composition._write_exclusive(owner_path, owner_raw)
            stored_owner, stored_sha = composition._read_stable(
                owner_path, "test persisted Fixed owner result",
                composition.MAX_PROBE_OWNER_RESULT_BYTES,
            )
            self.assertEqual(stored_owner, owner_raw)
            self.assertEqual(stored_sha, composition.sha256(owner_raw))


if __name__ == "__main__":
    unittest.main()
