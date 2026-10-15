#!/usr/bin/env python3
"""Focused invariants for the Source5 checkpoint/archive coordinator."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
ARCHIVE_PATH = SCRIPT_DIR / "application-source5-evidence-archive.py"


def load_target():
    spec = importlib.util.spec_from_file_location(
        "source5_evidence_archive_test_target", ARCHIVE_PATH,
    )
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load production target {ARCHIVE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


archive = load_target()


def canonical(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def private(path: Path) -> Path:
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)
    return path


def pinned(path: Path, raw: bytes, semantic: str | None = None) -> dict[str, str]:
    return {
        "path": str(path), "raw_sha256": sha(raw),
        "semantic_sha256": sha(raw) if semantic is None else semantic,
    }


def source5_fixture(root: Path, *, state: str = "failed_or_invalid"):
    job = {
        "host_id": "host-a", "phase": "aa", "ordinal": 1,
        "run_id": "campaign-host-a-aa-01", "predecessor_run_ids": [],
    }
    plan_body = {
        "schema": "allocatbelt.application-campaign-plan.v3",
        "campaign_id": "campaign-a", "jobs": {"aa": [job]},
    }
    plan = {**plan_body, "plan_sha256": sha(canonical(plan_body))}
    plan_raw = canonical(plan)
    plan_path = root / "inputs" / "plan-v3.json"
    record_path = root / "source5" / "host-a" / "aa" / "job-records" / f"{job['run_id']}.json"
    metrics = []
    chronology = {
        "authorization_id": "source5-auth-01",
        "authorization_head": "a" * 64,
        "app_started_heads": [], "app_terminal_heads": [],
        "job_terminal_head": "b" * 64,
        "component_sha256": "c" * 64,
        "process_metrics_sha256": sha(canonical(metrics)),
        "app_start_events": [], "app_terminal_events": [],
        "member_processes": [],
    }
    record_body = {
        "schema": "allocatbelt.application-source5-job-record.v1",
        "state": state, "job": job, "pair_directory": str(root / "pair"),
        "process_metrics": metrics, "evidence": {},
        "chronology": chronology, "qualification_eligible": False,
    }
    record = {**record_body, "record_sha256": sha(canonical(record_body))}
    record_raw = canonical(record)
    return {
        "job": job, "plan": plan, "plan_raw": plan_raw,
        "plan_pin": {
            "path": str(plan_path), "raw_sha256": sha(plan_raw),
            "semantic_sha256": plan["plan_sha256"],
        },
        "record": record, "record_raw": record_raw,
        "job_record_pin": {
            "path": str(record_path), "raw_sha256": sha(record_raw),
        },
    }


def context_for(root: Path, fixture: dict) -> dict:
    return {
        "schema": archive.CONTEXT_SCHEMA_V1,
        "campaign_id": "campaign-a", "host_id": "host-a", "phase": "aa",
        "job_index": 0,
        "source_manifest_pin": pinned(root / "source.json", b"source"),
        "execution_manifest_pin": pinned(root / "execution.json", b"execution"),
        "plan_pin": fixture["plan_pin"],
        "resource_budget_pin": pinned(root / "host-budget.json", b"budget"),
        "predecessor_ack_pin": None,
        "authorized_signer_fingerprint": "A" * 40,
    }


class ArchiveCliTests(unittest.TestCase):
    def test_caught_input_failure_reaches_the_process_exit(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-cli-exit-") as tmp:
            missing = str(Path(tmp) / "absent")
            options = (
                "request", "request-pin", "job-record", "catalogue-chunk-map",
                "catalogue-cache-root", "dependency-local-map",
                "dependency-cache-root", "staging-root", "archive-root",
                "stage-map-path", "gpg-executable", "gpg-homedir",
            )
            argv = [sys.executable, "-B", str(ARCHIVE_PATH)]
            for option in options:
                argv.extend(["--" + option, missing])
            argv.extend(["--signer-fingerprint", "A" * 40])
            result = subprocess.run(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, check=False, timeout=10,
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, b"")
            self.assertIn(b"Source5 evidence archive failed:", result.stderr)

    def test_plan_ceiling_does_not_expand_general_metadata(self) -> None:
        raw = canonical({"value": "x" * 1024})
        with self.assertRaises(archive.EvidenceArchiveError):
            archive._parse_canonical(raw, "small metadata", maximum_bytes=512)
        self.assertEqual(
            archive._parse_canonical(raw, "PlanV3", maximum_bytes=2048),
            {"value": "x" * 1024},
        )
        self.assertEqual(archive.MAX_PLAN_BYTES, 256 * 1024 * 1024)
        self.assertEqual(archive.MAX_JSON_BYTES, 32 * 1024 * 1024)


class CheckpointRequestTests(unittest.TestCase):
    def test_request_binds_raw_plan_record_original_index_and_rows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-request-test-") as tmp:
            root = Path(tmp)
            output = private(root / "output")
            fixture = source5_fixture(root)
            context = context_for(root, fixture)
            row = {
                "origin_path": str(root / "source5" / "host-a" / "aa" /
                                    "outputs" / "result.bin"),
                "role": "normal_app_output", "byte_count": 4,
                "raw_sha256": sha(b"data"), "semantic_sha256": None,
            }
            request, request_pin = archive.build_checkpoint_request(
                context, fixture["job_record_pin"], fixture["record_raw"],
                fixture["plan_raw"], [row], {}, output / "checkpoint-request.json",
            )
            self.assertEqual(request["entries"], [row])
            self.assertNotIn(fixture["job_record_pin"]["path"],
                             [entry["origin_path"] for entry in request["entries"]])
            self.assertEqual(request["request_sha256"],
                             sha(canonical({key: value for key, value in request.items()
                                            if key != "request_sha256"})))
            self.assertEqual(request_pin["raw_sha256"],
                             sha((output / "checkpoint-request.json").read_bytes()))
            self.assertEqual(request_pin["semantic_sha256"],
                             request["request_sha256"])

    def test_filtered_plan_index_mismatch_fails_before_request_write(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-index-mismatch-") as tmp:
            root = Path(tmp)
            output = private(root / "output")
            fixture = source5_fixture(root)
            context = context_for(root, fixture)
            context["job_index"] = 1
            row = {
                "origin_path": str(root / "source5" / "host-a" / "aa" /
                                    "outputs" / "result.bin"),
                "role": "normal_app_output", "byte_count": 4,
                "raw_sha256": sha(b"data"), "semantic_sha256": None,
            }
            with self.assertRaises(archive.EvidenceArchiveError):
                archive.build_checkpoint_request(
                    context, fixture["job_record_pin"], fixture["record_raw"],
                    fixture["plan_raw"], [row], {},
                    output / "should-not-exist.json",
                )
            self.assertFalse((output / "should-not-exist.json").exists())

    def test_job_record_cannot_enter_reclaimable_request_rows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-local-job-record-") as tmp:
            root = Path(tmp)
            output = private(root / "output")
            fixture = source5_fixture(root)
            row = {
                "origin_path": fixture["job_record_pin"]["path"],
                "role": "source5_job_record",
                "byte_count": len(fixture["record_raw"]),
                "raw_sha256": sha(fixture["record_raw"]),
                "semantic_sha256": fixture["record"]["record_sha256"],
            }
            with self.assertRaises(archive.EvidenceArchiveError):
                archive.build_checkpoint_request(
                    context_for(root, fixture), fixture["job_record_pin"],
                    fixture["record_raw"], fixture["plan_raw"], [row], {},
                    output / "must-not-exist.json",
                )
            self.assertFalse((output / "must-not-exist.json").exists())

    def test_job_disposition_is_also_nonexportable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-local-disposition-") as tmp:
            root = Path(tmp)
            output = private(root / "output")
            fixture = source5_fixture(root)
            disposition_path = str(
                root / "source5" / "host-a" / "aa" / "job-records" /
                f"{fixture['job']['run_id']}.disposition.json"
            )
            raw = b"failure disposition remains local"
            row = {
                "origin_path": disposition_path,
                "role": "source5_job_disposition",
                "byte_count": len(raw), "raw_sha256": sha(raw),
                "semantic_sha256": None,
            }
            with self.assertRaises(archive.EvidenceArchiveError):
                archive.build_checkpoint_request(
                    context_for(root, fixture), fixture["job_record_pin"],
                    fixture["record_raw"], fixture["plan_raw"], [row], {},
                    output / "must-not-exist.json",
                )
            self.assertFalse((output / "must-not-exist.json").exists())

    def test_success_request_requires_both_raw_owner_zero_usage_facts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-tmp-proof-") as tmp:
            root = Path(tmp)
            output = private(root / "output")
            fixture = source5_fixture(root, state="valid_pair")
            context = context_for(root, fixture)
            receipt_path = str(root / "fixed-pair-execution-receipt.json")
            mount = {
                "mount_id": 41, "major_minor": "8:1", "mount_root": "/",
                "mount_point": "/tmp", "filesystem_type": "ext4",
                "mount_source": "/dev/test", "device": 8,
            }

            def final_tmp(ordinal: int) -> dict:
                return {
                    "path": str(root / f"member-{ordinal}-tmp"), "device": 8,
                    "inode": 100 + ordinal, "mode": 0o700,
                    "mount": mount, "bytes_used": 0, "file_count": 0,
                    "directory_count": 0, "bytes_limit": 1024,
                    "inode_limit": 64, "available_bytes": 4096,
                    "available_inodes": 128,
                }

            receipt_body = {
                "schema": "allocatbelt.application-fixed-pair-execution-receipt.v1",
                "campaign_id": "campaign-a", "host_id": "host-a",
                "run_id": fixture["job"]["run_id"], "status": "valid_pair",
                "member_attempts": [
                    {"ordinal": 0, "tmpdir_final": final_tmp(0)},
                    {"ordinal": 1, "tmpdir_final": final_tmp(1)},
                ],
            }
            receipt = {
                **receipt_body, "receipt_sha256": sha(canonical(receipt_body)),
            }
            receipt_raw = canonical(receipt)
            receipt_pin = {
                "path": receipt_path, "raw_sha256": sha(receipt_raw),
                "semantic_sha256": receipt["receipt_sha256"],
            }
            rows = [{
                "origin_path": receipt_path, "role": "component_receipt",
                "byte_count": len(receipt_raw), "raw_sha256": sha(receipt_raw),
                "semantic_sha256": receipt["receipt_sha256"],
            }]
            request, _pin = archive.build_checkpoint_request(
                context, fixture["job_record_pin"], fixture["record_raw"],
                fixture["plan_raw"], rows, {receipt_path: receipt_raw},
                output / "checkpoint-request.json",
            )
            self.assertEqual(
                [proof["member_ordinal"] for proof in request["empty_tmp_proofs"]],
                [0, 1],
            )
            self.assertTrue(all(proof["owner_receipt_pin"] == receipt_pin
                                for proof in request["empty_tmp_proofs"]))

            bad_receipt = dict(receipt_body)
            bad_receipt["member_attempts"] = [
                {"ordinal": 0, "tmpdir_final": final_tmp(0)},
                {"ordinal": 1, "tmpdir_final": {
                    **final_tmp(1), "bytes_used": 1,
                }},
            ]
            bad_receipt["receipt_sha256"] = sha(canonical(bad_receipt))
            bad_raw = canonical(bad_receipt)
            bad_rows = [dict(rows[0], byte_count=len(bad_raw),
                             raw_sha256=sha(bad_raw),
                             semantic_sha256=bad_receipt["receipt_sha256"])]
            with self.assertRaises(archive.EvidenceArchiveError):
                archive.build_checkpoint_request(
                    context, fixture["job_record_pin"], fixture["record_raw"],
                    fixture["plan_raw"], bad_rows, {receipt_path: bad_raw},
                    output / "bad-request.json",
                )
            self.assertFalse((output / "bad-request.json").exists())


class ExecutionManifestSignerBindingTests(unittest.TestCase):
    def test_signer_context_must_match_the_execution_manifest_host_entry(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-signer-context-") as tmp:
            root = Path(tmp)
            fixture = source5_fixture(root)
            context = context_for(root, fixture)
            signer_pin = {
                "path": str(root / "private-signer-context.json"),
                "raw_sha256": "a" * 64,
                "semantic_sha256": "b" * 64,
            }
            host_contexts = {
                "host-a": {
                    "artifact": {
                        "path": signer_pin["path"],
                        "raw_sha256": signer_pin["raw_sha256"],
                    },
                    "semantic_sha256": signer_pin["semantic_sha256"],
                },
                "host-b": {
                    "artifact": {
                        "path": str(root / "host-b-signer-context.json"),
                        "raw_sha256": "c" * 64,
                    },
                    "semantic_sha256": "d" * 64,
                },
            }
            body = {
                "schema": "allocatbelt.application-source5-campaign-execution.v4",
                "campaign_id": "campaign-a", "hosts": ["host-a", "host-b"],
                "original_inputs": {}, "execution_sources": {},
                "modules": {}, "observed_hosts": {},
                "artifact_root": "/private/artifacts",
                "output_root": "/private/output", "phase_order": ["aa"],
                "protocol_sha256": "e" * 64,
                "qualification_eligible": False,
                "scope": "final_prepared_bounded",
                "prepared_input_generation": {},
                "prepared_capacity_registration": {},
                "archive_signer_contexts": host_contexts,
            }
            execution = {
                **body, "manifest_sha256": sha(canonical(body)),
            }
            execution_raw = canonical(execution)
            execution_pin = {
                "path": str(root / "execution-manifest.json"),
                "raw_sha256": sha(execution_raw),
                "semantic_sha256": execution["manifest_sha256"],
            }
            context["execution_manifest_pin"] = execution_pin
            self.assertEqual(
                archive._validate_execution_manifest_signer_context(
                    execution_raw, execution_pin, signer_pin, context,
                ),
                execution_pin,
            )
            with self.assertRaises(archive.EvidenceArchiveError):
                archive._validate_execution_manifest_signer_context(
                    execution_raw, execution_pin,
                    {**signer_pin, "raw_sha256": "f" * 64}, context,
                )


class ObjectCopyTests(unittest.TestCase):
    def test_stream_copy_reopens_content_addressed_object_and_literal_link(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-object-copy-") as tmp:
            root = Path(tmp)
            staging = private(root / "staging")
            archive_root = private(root / "archive")
            regular_path = staging / "regular.bin"
            regular_raw = b"already-fsynced source object\x00with bytes"
            regular_path.write_bytes(regular_raw)
            os.chmod(regular_path, 0o600)
            link_path = staging / "literal-link"
            os.symlink("target-that-is-not-followed", link_path)
            fd = archive._open_dir_path(str(archive_root),
                                        "test archive", private_final=True)
            try:
                regular_row = {
                    "origin_path": "/origin/regular.bin",
                    "role": "normal_app_output",
                    "byte_count": len(regular_raw),
                    "raw_sha256": sha(regular_raw),
                    "semantic_sha256": None,
                }
                object_id = archive._object_identity(
                    regular_row["origin_path"], regular_row["raw_sha256"],
                )
                first_pin, first_source = archive._copy_object(
                    fd, object_id, str(regular_path), str(staging), regular_row,
                )
                object_path = archive_root / "objects" / object_id
                self.assertEqual(object_path.read_bytes(), regular_raw)
                self.assertEqual(stat_mode(object_path), 0o600)
                self.assertEqual(os.stat(object_path).st_nlink, 1)
                again_pin, _again_source = archive._copy_object(
                    fd, object_id, str(regular_path), str(staging), regular_row,
                )
                self.assertEqual(first_pin, again_pin)
                self.assertEqual(first_source["kind"], "regular")

                link_raw = b"target-that-is-not-followed"
                link_row = {
                    "origin_path": "/origin/literal-link",
                    "role": "normal_app_output",
                    "byte_count": len(link_raw),
                    "raw_sha256": sha(link_raw),
                    "semantic_sha256": None,
                }
                link_object = archive._object_identity(
                    link_row["origin_path"], link_row["raw_sha256"],
                )
                archive._copy_object(
                    fd, link_object, str(link_path), str(staging), link_row,
                )
                self.assertEqual(
                    (archive_root / "objects" / link_object).read_bytes(),
                    link_raw,
                )
                self.assertTrue(link_path.is_symlink())
            finally:
                os.close(fd)

    def test_stage_path_escape_and_changed_inode_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-stage-identity-") as tmp:
            root = Path(tmp)
            stage = private(root / "stage")
            original = stage / "object.bin"
            original.write_bytes(b"pinned")
            os.chmod(original, 0o600)
            row = {"byte_count": 6, "raw_sha256": sha(b"pinned")}
            descriptor, _literal = archive._staged_descriptor(
                str(original), str(stage), row,
            )
            replacement = stage / "replacement.bin"
            replacement.write_bytes(b"pinned")
            os.chmod(replacement, 0o600)
            replacement.replace(original)
            with self.assertRaises(archive.EvidenceArchiveError):
                archive._unlink_stage_file(str(original), str(stage), descriptor)
            outside_root = private(root / "outside")
            outside = outside_root / "escape.bin"
            outside.write_bytes(b"pinned")
            os.chmod(outside, 0o600)
            with self.assertRaises(archive.EvidenceArchiveError):
                archive._staged_descriptor(str(outside), str(stage), row)


def stat_mode(path: Path) -> int:
    import stat
    return stat.S_IMODE(path.stat().st_mode)


class GpgIdentityTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("gpg") and shutil.which("gpgv") and
                         shutil.which("gpgconf"),
                         "GPG, GPGV and GPGConf are required for detached signature verification")
    def test_detached_ack_signature_uses_the_pinned_primary_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-test-key-") as tmp:
            with ExitStack() as cleanup:
                root = Path(tmp)
                home = private(root / "gnupg")
                cleanup.callback(lambda: subprocess.run(
                    ["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, check=False, timeout=30,
                ))
                key = subprocess.run(
                    ["gpg", "--batch", "--quiet", "--homedir", str(home),
                     "--pinentry-mode", "loopback", "--passphrase", "",
                     "--quick-generate-key",
                     "Source5 archive test <source5-archive@example.invalid>",
                     "ed25519", "sign", "0"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, check=False, timeout=60,
                )
                self.assertEqual(key.returncode, 0, key.stderr.decode(errors="replace"))
                listed = subprocess.run(
                    ["gpg", "--batch", "--with-colons", "--fingerprint",
                     "--list-secret-keys"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    check=False, timeout=30, env={
                        "GNUPGHOME": str(home), "LC_ALL": "C", "LANG": "C",
                    },
                )
                self.assertEqual(listed.returncode, 0, listed.stderr.decode(errors="replace"))
                fingerprints = [
                    line.split(":")[9] for line in listed.stdout.decode().splitlines()
                    if line.startswith("fpr:")
                ]
                self.assertEqual(len(fingerprints), 1)
                fingerprint = fingerprints[0]
                exported = subprocess.run(
                    ["gpg", "--batch", "--quiet", "--homedir", str(home),
                     "--export", fingerprint],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    check=False, timeout=30,
                )
                self.assertEqual(exported.returncode, 0)
                keyring = root / "trusted.gpg"
                keyring.write_bytes(exported.stdout)
                os.chmod(keyring, 0o600)
                gpgv = shutil.which("gpgv")
                gpgv_path = Path(gpgv).resolve(strict=True)
                gpgv_raw = gpgv_path.read_bytes()
                ack = canonical({"schema": "test", "durable": "all bytes reopened"})
                signature = archive._gpg_sign(ack, {
                    "gpg_executable": shutil.which("gpg"),
                    "gpg_homedir": str(home),
                    "primary_fingerprint": fingerprint,
                    "maximum_signature_bytes": 4096,
                })
                primary = archive._verify_detached_signature(ack, signature, {
                    "fingerprint": fingerprint,
                    "keyring_pin": {
                        "path": str(keyring), "raw_sha256": sha(keyring.read_bytes()),
                    },
                    "gpgv_pin": {
                        "path": str(gpgv_path),
                        "raw_sha256": sha(gpgv_raw),
                    },
                })
                self.assertEqual(primary, fingerprint)
                with self.assertRaises(archive.EvidenceArchiveError):
                    archive._verify_detached_signature(ack + b"forged", signature, {
                        "fingerprint": fingerprint,
                        "keyring_pin": {
                            "path": str(keyring),
                            "raw_sha256": sha(keyring.read_bytes()),
                        },
                        "gpgv_pin": {
                            "path": str(gpgv_path),
                            "raw_sha256": sha(gpgv_raw),
                        },
                    })
                with self.assertRaises(archive.EvidenceArchiveError):
                    archive._gpg_sign(ack, {
                        "gpg_executable": shutil.which("gpg"),
                        "gpg_homedir": str(home),
                        "primary_fingerprint": fingerprint,
                        "maximum_signature_bytes": 1,
                    })


if __name__ == "__main__":
    unittest.main(verbosity=2)
