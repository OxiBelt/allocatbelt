#!/usr/bin/env python3
"""No-link bounded Source5 request, packet, offer, and ACK-bundle witnesses."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import inspect
import json
import os
import shutil
import subprocess
import stat
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
ARCHIVE_PATH = SCRIPT_DIR / "application-source5-evidence-archive.py"
PACKET_PATH = SCRIPT_DIR / "application-source5-evidence-transfer-packet.py"
BUDGET_TEST_PATH = SCRIPT_DIR / "test-application-source5-evidence-budget.py"
CAMPAIGN_CONTROLLER_PATH = SCRIPT_DIR / "application-campaign.py"


def load_target(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load production target {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


archive = load_target("source5_archive_packet_test_archive", ARCHIVE_PATH)
packet = load_target("source5_archive_packet_test_target", PACKET_PATH)
budget_tests = load_target("source5_archive_packet_test_budget", BUDGET_TEST_PATH)
budget_producer = budget_tests.budget
analysis_campaign = load_target(
    "source5_archive_packet_test_campaign", CAMPAIGN_CONTROLLER_PATH,
)


def canonical(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def private(path: Path) -> Path:
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)
    return path


def pin(path: Path, raw: bytes, semantic: str | None = None):
    return {
        "path": str(path), "raw_sha256": sha(raw),
        "semantic_sha256": sha(raw) if semantic is None else semantic,
    }


def selected_budget_source_fixture():
    relative = packet.SOURCE5_BUDGET_VALIDATOR_PATH
    module_path = SCRIPT_DIR / "application-source5-evidence-budget.py"
    module_raw = module_path.read_bytes()
    info = module_path.stat(follow_symlinks=False)
    mode = f"{stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode):06o}"
    module_sha = sha(module_raw)
    files = [{
        "path": relative, "kind": "file", "mode": mode,
        "sha256": module_sha, "size": len(module_raw),
    }]
    source_body = {
        "git_commit": "1" * 40,
        "source_tree_sha256": sha(canonical({
            "schema": packet.SOURCE_INVENTORY_SCHEMA_V1,
            "entries": files,
        })),
        "files": files,
    }
    source = {
        "schema": packet.SOURCE_MANIFEST_SCHEMA_V5,
        "source": source_body,
        "build": {"build_sha256": "2" * 64},
    }
    source["manifest_sha256"] = sha(canonical(source))
    source_raw = canonical(source)
    source_pin = {
        "path": "/inputs/source-manifest.json",
        "raw_sha256": sha(source_raw),
        "semantic_sha256": source["manifest_sha256"],
    }
    execution_body = {
        "schema": packet.EXECUTION_SCHEMA_V4,
        "campaign_id": "campaign-a", "hosts": ["host-a"],
        "original_inputs": {"source_manifests": {
            "host-a": {
                "artifact": {
                    "path": source_pin["path"],
                    "raw_sha256": source_pin["raw_sha256"],
                },
                "semantic_sha256": source_pin["semantic_sha256"],
            },
        }},
        "execution_sources": {"host-a": {
            "source_root": "/not-opened/source",
            "git_commit": source_body["git_commit"],
            "source_tree_sha256": source_body["source_tree_sha256"],
            "build_sha256": sha(canonical(source["build"])),
        }},
        "modules": {"host-a": {relative: {
            "path": relative, "sha256": module_sha,
        }}},
    }
    execution = {
        **execution_body,
        "manifest_sha256": sha(canonical(execution_body)),
    }
    execution_raw = canonical(execution)
    context = {
        "campaign_id": "campaign-a", "host_id": "host-a",
        "source_manifest_pin": source_pin,
        "execution_manifest_pin": {
            "path": "/inputs/execution-manifest.json",
            "raw_sha256": sha(execution_raw),
            "semantic_sha256": execution["manifest_sha256"],
        },
    }
    return source, context, execution


def make_test_signer(root: Path, cleanup: ExitStack, maximum_signature_bytes: int):
    gpg = shutil.which("gpg")
    gpgv = shutil.which("gpgv")
    gpgconf = shutil.which("gpgconf")
    if not (gpg and gpgv and gpgconf):
        raise AssertionError("GPG, GPGV and GPGConf are required for the full archive roundtrip")
    home = private(root / "gnupg")
    cleanup.callback(lambda: subprocess.run(
        [gpgconf, "--homedir", str(home), "--kill", "gpg-agent"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False, timeout=30,
    ))
    generated = subprocess.run(
        [gpg, "--batch", "--quiet", "--homedir", str(home),
         "--pinentry-mode", "loopback", "--passphrase", "",
         "--quick-generate-key", "Source5 archive test <archive@example.invalid>",
         "ed25519", "sign", "0"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False, timeout=60,
    )
    if generated.returncode != 0:
        raise AssertionError(generated.stderr.decode(errors="replace"))
    listed = subprocess.run(
        [gpg, "--batch", "--homedir", str(home), "--with-colons",
         "--fingerprint", "--list-secret-keys"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False, timeout=30,
    )
    if listed.returncode != 0:
        raise AssertionError(listed.stderr.decode(errors="replace"))
    fingerprints = [
        line.split(":")[9]
        for line in listed.stdout.decode().splitlines()
        if line.startswith("fpr:")
    ]
    if len(fingerprints) != 1:
        raise AssertionError("test GPG home did not produce one signing key")
    fingerprint = fingerprints[0]
    exported = subprocess.run(
        [gpg, "--batch", "--quiet", "--homedir", str(home),
         "--export", fingerprint],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False, timeout=30,
    )
    if exported.returncode != 0 or not exported.stdout:
        raise AssertionError(exported.stderr.decode(errors="replace"))
    keyring = root / "archive-keyring.gpg"
    keyring.write_bytes(exported.stdout)
    os.chmod(keyring, 0o600)
    gpgv_path = Path(gpgv).resolve(strict=True)
    gpgv_raw = gpgv_path.read_bytes()
    return {
        "gpg_executable": str(Path(gpg).resolve(strict=True)),
        "gpg_homedir": str(home), "fingerprint": fingerprint,
        "keyring_pin": {
            "path": str(keyring), "raw_sha256": sha(exported.stdout),
        },
        "gpgv_pin": {
            "path": str(gpgv_path), "raw_sha256": sha(gpgv_raw),
        },
        "maximum_signature_bytes": maximum_signature_bytes,
    }


def attach_test_signer_context(source_inputs, host_id: str, signer: dict):
    body = {
        "schema": packet.ARCHIVE_SIGNER_CONTEXT_SCHEMA,
        "campaign_id": source_inputs["execution"]["campaign_id"],
        "host_id": host_id,
        "authorized_primary_fingerprint": signer["fingerprint"],
        "maximum_signature_bytes": signer["maximum_signature_bytes"],
        "keyring_pin": signer["keyring_pin"],
        "gpgv_pin": signer["gpgv_pin"],
        "signature_format": "binary_detached_primary_sha256_v1",
    }
    value = {
        **body, "signer_context_sha256": sha(canonical(body)),
    }
    raw = canonical(value)
    path = Path(signer["keyring_pin"]["path"]).parent / "archive-signer-context.json"
    path.write_bytes(raw)
    os.chmod(path, 0o600)
    context_pin = {
        "path": str(path), "raw_sha256": sha(raw),
        "semantic_sha256": value["signer_context_sha256"],
    }
    source_inputs["signer_artifacts"][host_id] = {
        "raw": raw, "pin": context_pin, "context": value,
    }
    execution_body = {
        key: item for key, item in source_inputs["execution"].items()
        if key != "manifest_sha256"
    }
    contexts = dict(execution_body["archive_signer_contexts"])
    contexts[host_id] = {
        "artifact": {
            "path": context_pin["path"],
            "raw_sha256": context_pin["raw_sha256"],
        },
        "semantic_sha256": context_pin["semantic_sha256"],
    }
    execution_body["archive_signer_contexts"] = contexts
    execution = budget_tests.sealed(execution_body, "manifest_sha256")
    execution_raw = canonical(execution)
    source_inputs["execution"] = execution
    source_inputs["execution_raw"] = execution_raw
    source_inputs["pins"]["execution_manifest"] = {
        "path": source_inputs["pins"]["execution_manifest"]["path"],
        "raw_sha256": sha(execution_raw),
        "semantic_sha256": execution["manifest_sha256"],
    }
    return source_inputs


class PacketRoundTripTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        source_inputs = budget_tests.fixture()
        # Match the real campaign producer's positive exploration ordinals.
        ordinals = {}
        for job in source_inputs["plan"]["jobs"]["exploration"]:
            host = job["host_id"]
            ordinals[host] = ordinals.get(host, 0) + 1
            job["ordinal"] = ordinals[host]
        budget_tests.repin_plan_case(source_inputs)
        signer_artifacts = {}
        signer_contexts = {}
        signature_quota = budget_producer.ARCHIVE_SIGNATURE_QUOTA_BYTES
        for host_id in source_inputs["execution"]["hosts"]:
            context_body = {
                "schema": packet.ARCHIVE_SIGNER_CONTEXT_SCHEMA,
                "campaign_id": source_inputs["execution"]["campaign_id"],
                "host_id": host_id,
                "authorized_primary_fingerprint": "A" * 40,
                "maximum_signature_bytes": signature_quota,
                "keyring_pin": {
                    "path": f"/private/{host_id}/archive-keyring.gpg",
                    "raw_sha256": "a" * 64,
                },
                "gpgv_pin": {
                    "path": f"/private/{host_id}/gpgv",
                    "raw_sha256": "b" * 64,
                },
                "signature_format": "binary_detached_primary_sha256_v1",
            }
            signer_context = {
                **context_body,
                "signer_context_sha256": sha(canonical(context_body)),
            }
            signer_raw = canonical(signer_context)
            signer_pin = {
                "path": f"/private/{host_id}/archive-signer-context.json",
                "raw_sha256": sha(signer_raw),
                "semantic_sha256": signer_context["signer_context_sha256"],
            }
            signer_contexts[host_id] = {
                "artifact": {
                    "path": signer_pin["path"],
                    "raw_sha256": signer_pin["raw_sha256"],
                },
                "semantic_sha256": signer_pin["semantic_sha256"],
            }
            signer_artifacts[host_id] = {
                "raw": signer_raw, "pin": signer_pin,
            }
        execution_body = {
            key: value for key, value in source_inputs["execution"].items()
            if key != "manifest_sha256"
        }
        execution_body.update({
            "modules": {}, "observed_hosts": {},
            "artifact_root": "/private/campaign-artifacts",
            "output_root": "/private/campaign-output",
            "phase_order": [
                "exploration", "aa", "confirmation", "pressure", "soak",
            ],
            "protocol_sha256": "c" * 64,
            "scope": "final_prepared_bounded",
            "prepared_input_generation": {
                "completion": {}, "provenance": {},
            },
            "prepared_capacity_registration": {
                "completion": {}, "host_completion": {},
                "host_verification": {}, "ledger": {},
                "capacity_schedule_sha256": "d" * 64,
                "registration_head": "e" * 64,
            },
        })
        execution_body["schema"] = (
            "allocatbelt.application-source5-campaign-execution.v4"
        )
        execution_body["archive_signer_contexts"] = signer_contexts
        execution = budget_tests.sealed(execution_body, "manifest_sha256")
        execution_raw = canonical(execution)
        source_inputs["execution"] = execution
        source_inputs["pins"]["execution_manifest"] = {
            "path": source_inputs["pins"]["execution_manifest"]["path"],
            "raw_sha256": sha(execution_raw),
            "semantic_sha256": execution["manifest_sha256"],
        }
        source_inputs["execution_raw"] = execution_raw
        source_inputs["signer_artifacts"] = signer_artifacts
        audit = budget_producer.build_host_evidence_budget_plan(
            source_inputs["spec"], source_inputs["plan"],
            source_inputs["sources"], source_inputs["execution"],
            source_inputs["host_id"], pins_value=source_inputs["pins"],
        )
        audit = copy.deepcopy(audit)
        audit["schedule"]["job_counts"] = {
            "exploration": 1, "aa": 0, "confirmation": 0,
            "pressure": 0, "soak": 0,
        }
        audit["schedule"]["fixed_job_count"] = 1
        audit["schedule"]["pressure_job_count"] = 0
        audit["schedule"]["total_job_count"] = 1
        audit["schedule"]["maximum_callback_events"] = 13
        audit["schedule"]["worst_case_journal_bytes"] = (
            13 * budget_producer.MAX_EVENT_BYTES
        )
        cls.audit = budget_tests.sealed(
            {key: value for key, value in audit.items()
             if key != "budget_plan_sha256"},
            "budget_plan_sha256",
        )
        source_digest = cls.audit["original_pins"]["source_manifests"][
            cls.audit["host_id"]
        ]["semantic_sha256"]
        contract_body = {
            "schema": "allocatbelt.application-source5-owner-evidence-catalogue.v1",
            "source_manifest_sha256": source_digest,
            "owner_source_pins": {}, "fixed_pair": {}, "pressure_pair": {},
            "soak": {}, "transport_caps": {
                "chronology": {"MAX_COMPLETION_BYTES": 16 * 1024 * 1024},
            },
            "role_ceiling_conflicts": {},
            "exact_full_path_catalogue_complete": True,
            "execution_ready": False, "qualification_eligible": False,
        }
        cls.owner_contract = {
            **contract_body,
            "owner_contract_sha256": sha(canonical(contract_body)),
        }
        cls.source_inputs = source_inputs

    def test_budget_parser_uses_actual_nonready_producer_schema(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-real-budget-") as tmp:
            fixture = self._fixture(Path(tmp))
            self.assertIn("execution_blockers", fixture["budget"])
            self.assertFalse(fixture["budget"]["readiness"]["execution_ready"])
            self.assertFalse(
                fixture["budget"]["readiness"]["qualification_eligible"],
            )
            limits = packet._budget_limits(
                fixture["budget_raw"], fixture["budget_pin"],
                "campaign-a", "host-a",
            )
            self.assertEqual(
                limits[0],
                fixture["budget"]["path_catalogue"]["retention_policy"][
                    "maximum_transfer_packet_bytes"
                ],
            )

    def test_failure_disposition_cannot_enter_transfer_request(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-disposition-request-") as tmp:
            fixture = self._fixture(Path(tmp))
            body = dict(fixture["request"])
            entries = [dict(row) for row in fixture["rows"]]
            entries[0]["role"] = "source5_job_disposition"
            body["entries"] = entries
            body["request_sha256"] = ""
            request = {
                **body,
                "request_sha256": sha(canonical({
                    key: value for key, value in body.items()
                    if key != "request_sha256"
                })),
            }
            with self.assertRaises(packet.TransferPacketError):
                packet._validate_request(request)

    def test_analyzer_scratch_role_cannot_enter_archive_payload_closure(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-analyzer-spool-export-") as tmp:
            fixture = self._fixture(Path(tmp))
            body = dict(fixture["request"])
            entries = [dict(row) for row in fixture["rows"]]
            entries[0]["role"] = packet.SOURCE5_ANALYZER_SPOOL_ROLE
            body["entries"] = entries
            body["request_sha256"] = ""
            request = {
                **body,
                "request_sha256": sha(canonical({
                    key: value for key, value in body.items()
                    if key != "request_sha256"
                })),
            }
            with self.assertRaisesRegex(
                    packet.TransferPacketError, "non-exportable"):
                packet._validate_request(request)
            with self.assertRaisesRegex(
                    archive.EvidenceArchiveError, "non-exportable"):
                archive._validate_rows([{
                    "origin_path": str(fixture["scratch_root"] /
                                       "analyzer-spool"),
                    "role": packet.SOURCE5_ANALYZER_SPOOL_ROLE,
                    "byte_count": 0, "raw_sha256": "0" * 64,
                    "semantic_sha256": None,
                }])
            with self.assertRaisesRegex(
                    archive.EvidenceArchiveError, "non-exportable"):
                archive._validate_rows([{
                    "origin_path": "/private/scratch/campaign/host/analyzer-spool",
                    "role": packet.SOURCE5_ANALYZER_SPOOL_ROLE,
                    "byte_count": 0, "raw_sha256": "0" * 64,
                    "semantic_sha256": None,
                }])

    def _fixture(
        self, root: Path, *, packet_cap: int = 1 << 20,
        source_inputs=None, audit=None, owner_contract=None,
        original_job=None, authorized_signer_fingerprint: str | None = None,
    ):
        source_inputs = self.source_inputs if source_inputs is None else source_inputs
        audit = self.audit if audit is None else audit
        owner_contract = (self.owner_contract if owner_contract is None
                          else owner_contract)
        source_root = private(root / "source")
        output_root = private(root / "output")
        scratch_root = private(root / "scratch")
        if original_job is None:
            phase = "aa"
            run_id = "campaign-host-a-aa-" + "x" * 128
        else:
            phase = original_job["phase"]
            run_id = original_job["run_id"]
        payload = source_root / "payload.bin"
        payload_raw = b"checkpointed payload bytes\x00\xff"
        payload.write_bytes(payload_raw)
        os.chmod(payload, 0o600)
        link = source_root / "literal-link"
        os.symlink("unfollowed-target", link)
        link_raw = os.fsencode(os.readlink(link))
        job_path = source_root / "job-records" / f"{run_id}.json"
        job_path.parent.mkdir(mode=0o700)
        os.chmod(job_path.parent, 0o700)
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
        job_body = {
            "schema": "allocatbelt.application-source5-job-record.v1",
            "state": "failed", "pair_directory": str(root / "pair"),
            "process_metrics": metrics, "evidence": {},
            "chronology": chronology, "qualification_eligible": False,
        }
        if original_job is not None:
            job_body["job"] = original_job
        job_raw = canonical({
            **job_body, "record_sha256": sha(canonical(job_body)),
        })
        job_path.write_bytes(job_raw)
        os.chmod(job_path, 0o600)

        request_path = output_root / "checkpoint-request.json"
        packet_path = scratch_root / "job.tar"
        offer_path = output_root / "transfer-offer.json"
        receiver_path = output_root / "ack-bundle.tar"
        incoming_path = Path(str(receiver_path) + ".incoming")
        def catalogue_row(path: Path, role: str, maximum: int,
                          storage_root: Path) -> dict:
            row = budget_tests.Source5PathCatalogueTests.row(
                str(path), role=role, maximum=maximum,
            )
            row.update({
                "host_id": "host-a", "phase": phase, "run_id": run_id,
                "storage_root": str(storage_root),
                "owner": "archive_packet_test",
            })
            return row

        core_rows = [
            catalogue_row(job_path, "source5_job_record", len(job_raw),
                          source_root),
            catalogue_row(payload, "normal_app_output", len(payload_raw),
                          source_root),
            catalogue_row(link, "normal_app_output", len(link_raw),
                          source_root),
        ]
        job_caps = budget_producer.project_archive_job_caps(core_rows)[
            (phase, run_id)
        ]
        transport_paths = {
            "source5_checkpoint_request": request_path,
            "source5_transfer_offer": offer_path,
            "source5_transfer_packet": packet_path,
            "source5_ack_bundle": receiver_path,
            "source5_ack_bundle_incoming": incoming_path,
            "source5_checkpoint": output_root / "checkpoint.json",
            "source5_object_manifest": output_root / "object-manifest.json",
            "source5_archive_ack": output_root / "archive-ack.json",
            "source5_archive_signature": output_root / "archive-ack.sig",
            "source5_stage_map": output_root / "stage-map.json",
        }
        transport_caps = (
            ("source5_checkpoint_request", "checkpoint_request_bytes", output_root),
            ("source5_transfer_offer", "transfer_offer_bytes", output_root),
            ("source5_transfer_packet", "transfer_packet_bytes", scratch_root),
            ("source5_ack_bundle", "ack_bundle_bytes", output_root),
            ("source5_ack_bundle_incoming", "ack_bundle_bytes", output_root),
            ("source5_checkpoint", "checkpoint_bytes", output_root),
            ("source5_object_manifest", "object_manifest_bytes", output_root),
            ("source5_archive_ack", "archive_ack_bytes", output_root),
            ("source5_archive_signature", "signature_bytes", output_root),
            ("source5_stage_map", "stage_map_bytes", output_root),
        )
        catalogue_rows = list(core_rows)
        for role, cap_field, storage_root in transport_caps:
            catalogue_rows.append(catalogue_row(
                transport_paths[role], role, job_caps[cap_field], storage_root,
            ))
        chunk_dir = private(root / "catalogue")
        catalogue = budget_producer.write_path_catalogue_chunks(
            catalogue_rows, chunk_dir,
        )
        budget_path = root / "host-evidence-budget.json"
        store_root = private(root / "store")
        reservation_roots = [
            {"path": str(source_root), "role": "artifact",
             "reserved_bytes": budget_producer.MAX_U64,
             "reserved_inodes": budget_producer.MAX_U64,
             "filesystem_id": "1"},
            {"path": str(output_root), "role": "output",
             "reserved_bytes": budget_producer.MAX_U64,
             "reserved_inodes": budget_producer.MAX_U64,
             "filesystem_id": "2"},
            {"path": str(scratch_root), "role": "scratch",
             "reserved_bytes": budget_producer.MAX_U64,
             "reserved_inodes": budget_producer.MAX_U64,
             "filesystem_id": "3"},
            {"path": str(store_root), "role": "evidence_store",
             "reserved_bytes": budget_producer.MAX_U64,
             "reserved_inodes": budget_producer.MAX_U64,
             "filesystem_id": "4"},
        ]
        reservation = budget_producer.build_storage_reservation_value(
            "campaign-a", "host-a", reservation_roots,
        )
        reservation_raw = canonical(reservation)
        reservation_pin = {
            "path": str(root / "storage-reservation.json"),
            "raw_sha256": sha(reservation_raw),
            "semantic_sha256": reservation["reservation_sha256"],
            "byte_count": len(reservation_raw),
        }
        budget = budget_producer.build_host_evidence_budget_v2(
            audit, owner_contract, catalogue, reservation,
            reservation_pin,
        )
        budget = budget_producer.validate_host_evidence_budget_v2(budget)
        budget_raw = canonical(budget)
        budget_path.write_bytes(budget_raw)
        os.chmod(budget_path, 0o600)
        budget_pin = pin(budget_path, budget_raw, budget["budget_sha256"])

        rows = [
            {
                "origin_path": str(payload), "role": "normal_app_output",
                "byte_count": len(payload_raw), "raw_sha256": sha(payload_raw),
                "semantic_sha256": None,
            },
            {
                "origin_path": str(link), "role": "normal_app_output",
                "byte_count": len(link_raw), "raw_sha256": sha(link_raw),
                "semantic_sha256": None,
            },
        ]
        rows.sort(key=lambda row: row["origin_path"])
        context = {
            "schema": archive.CONTEXT_SCHEMA_V1,
            "campaign_id": "campaign-a", "host_id": "host-a",
            "phase": phase, "job_index": 0,
            "source_manifest_pin": source_inputs["pins"][
                "source_manifests"]["host-a"
            ],
            "execution_manifest_pin": source_inputs["pins"][
                "execution_manifest"
            ],
            "plan_pin": source_inputs["pins"]["plan"],
            "resource_budget_pin": budget_pin,
            "predecessor_ack_pin": None,
            "authorized_signer_fingerprint": (
                authorized_signer_fingerprint or "A" * 40
            ),
        }
        authorization = {
            "authorization_id": chronology["authorization_id"],
            "authorization_head": chronology["authorization_head"],
            "terminal_head": chronology["job_terminal_head"],
            "component_sha256": chronology["component_sha256"],
            "process_metrics_sha256": chronology["process_metrics_sha256"],
        }
        request_body = {
            "schema": archive.REQUEST_SCHEMA_V1,
            "context": context,
            "job_record_pin": {
                "path": str(job_path), "raw_sha256": sha(job_raw),
            },
            "authorization": authorization,
            "predecessor_ack_pin": None,
            "owner_receipt_pins": {},
            "empty_tmp_proofs": [], "entries": rows,
            "request_sha256": "",
        }
        if original_job is None:
            request_sha = sha(canonical({
                key: value for key, value in request_body.items()
                if key != "request_sha256"
            }))
            request = {**request_body, "request_sha256": request_sha}
            request_raw = canonical(request)
            request_path.write_bytes(request_raw)
            os.chmod(request_path, 0o600)
            request_pin = pin(request_path, request_raw, request_sha)
        else:
            request, request_pin = archive.build_checkpoint_request(
                context, request_body["job_record_pin"], job_raw,
                canonical(source_inputs["plan"]), rows, {}, request_path,
            )
            request_raw = canonical(request)
        return {
            "root": root, "source_root": source_root, "output_root": output_root,
            "scratch_root": scratch_root, "payload": payload, "payload_raw": payload_raw,
            "link": link, "link_raw": link_raw, "job_path": job_path,
            "run_id": run_id,
            "catalogue_chunk_paths": [
                item["path"] for item in catalogue["chunks"]
            ],
            "job_raw": job_raw, "request": request, "request_raw": request_raw,
            "request_pin": request_pin, "request_path": request_path,
            "packet_path": packet_path, "offer_path": offer_path,
            "receiver_path": receiver_path, "budget": budget,
            "incoming_path": incoming_path,
            "budget_raw": budget_raw, "budget_pin": budget_pin,
            "budget_path": budget_path,
            "plan_raw": canonical(source_inputs["plan"]),
            "source_manifest_raw": canonical(
                source_inputs["sources"]["host-a"]
            ),
            "execution_manifest_raw": source_inputs["execution_raw"],
            "execution_manifest_pin": source_inputs["pins"][
                "execution_manifest"
            ],
            "signer_context_raw": source_inputs["signer_artifacts"][
                "host-a"
            ]["raw"],
            "signer_context_pin": source_inputs["signer_artifacts"][
                "host-a"
            ]["pin"],
            "rows": rows,
        }

    def _offer(self, fixture):
        result = packet.export_transfer_packet(
            fixture["request_raw"], fixture["request_pin"],
            str(fixture["budget_pin"]["path"]), str(fixture["packet_path"]),
            str(fixture["offer_path"]), str(fixture["receiver_path"]),
        )
        packet_pin = {
            "path": result["path"], "raw_sha256": result["raw_sha256"],
            "byte_count": result["byte_count"],
        }
        offer, offer_pin = packet.publish_transfer_offer(
            fixture["request_raw"], fixture["request_pin"], packet_pin,
            fixture["budget_raw"], fixture["budget_pin"],
            fixture["offer_path"], fixture["receiver_path"],
        )
        return packet_pin, offer, offer_pin

    def _capture_catalogue_map(self, fixture, root: Path,
                               *, remove_origins: bool = False):
        cache = private(root / "root-catalogue-cache")
        rows = []
        for index, origin_path in enumerate(fixture["catalogue_chunk_paths"]):
            local_path = cache / f"captured-{index:04d}.jsonl"
            local_path.write_bytes(Path(origin_path).read_bytes())
            os.chmod(local_path, 0o600)
            rows.append({
                "origin_path": origin_path, "local_path": str(local_path),
            })
        body = {
            "schema": packet.CATALOGUE_LOCAL_MAP_SCHEMA,
            "campaign_id": fixture["request"]["context"]["campaign_id"],
            "host_id": fixture["request"]["context"]["host_id"],
            "resource_budget_pin": fixture["budget_pin"],
            "chunks": rows,
        }
        raw = canonical({**body, "map_sha256": sha(canonical(body))})
        paths = packet._parse_catalogue_local_map(
            raw, body["campaign_id"], body["host_id"],
            fixture["budget_pin"],
        )
        if remove_origins:
            for origin_path in fixture["catalogue_chunk_paths"]:
                Path(origin_path).unlink()
        return paths, str(cache)

    @unittest.skipUnless(shutil.which("gpg") and shutil.which("gpgv") and
                         shutil.which("gpgconf"),
                         "GPG, GPGV and GPGConf are required for a full archive roundtrip")
    def test_disjoint_full_archive_ack_verify_and_reclaim_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-full-archive-") as tmp:
            root = Path(tmp)
            with ExitStack() as cleanup:
                signer = make_test_signer(
                    root, cleanup, budget_producer.ARCHIVE_SIGNATURE_QUOTA_BYTES,
                )
                source_inputs = attach_test_signer_context(
                    copy.deepcopy(self.source_inputs), "host-a", signer,
                )
                audit = budget_producer.build_host_evidence_budget_plan(
                    source_inputs["spec"], source_inputs["plan"],
                    source_inputs["sources"], source_inputs["execution"],
                    source_inputs["host_id"], pins_value=source_inputs["pins"],
                )
                audit = copy.deepcopy(audit)
                audit["schedule"]["job_counts"] = {
                    "exploration": 1, "aa": 0, "confirmation": 0,
                    "pressure": 0, "soak": 0,
                }
                audit["schedule"]["fixed_job_count"] = 1
                audit["schedule"]["pressure_job_count"] = 0
                audit["schedule"]["total_job_count"] = 1
                audit["schedule"]["maximum_callback_events"] = 13
                audit["schedule"]["worst_case_journal_bytes"] = (
                    13 * budget_producer.MAX_EVENT_BYTES
                )
                audit = budget_tests.sealed(
                    {key: value for key, value in audit.items()
                     if key != "budget_plan_sha256"},
                    "budget_plan_sha256",
                )
                original_jobs = [
                    job for job in source_inputs["plan"]["jobs"]["exploration"]
                    if job["host_id"] == "host-a"
                ]
                self.assertTrue(original_jobs)
                fixture = self._fixture(
                    root, source_inputs=source_inputs, audit=audit,
                    owner_contract=self.owner_contract,
                    original_job=original_jobs[0],
                    authorized_signer_fingerprint=signer["fingerprint"],
                )
                packet_pin, offer, offer_pin = self._offer(fixture)
                catalogue_map, catalogue_cache = self._capture_catalogue_map(
                    fixture, root, remove_origins=True,
                )
                self.assertTrue(all(not Path(path).exists()
                                    for path in fixture["catalogue_chunk_paths"]))

                coordinator_stage = private(root / "coordinator-stage")
                imported = packet.import_transfer_packet(
                    fixture["packet_path"], fixture["budget_raw"],
                    fixture["budget_pin"], canonical(offer), offer_pin,
                    coordinator_stage, catalogue_map, catalogue_cache,
                )
                self.assertEqual(imported["packet_raw_sha256"],
                                 packet_pin["raw_sha256"])
                dependency_cache = private(root / "coordinator-dependencies")
                dependency_paths = {}
                dependencies = (
                    (fixture["request"]["context"]["source_manifest_pin"],
                     fixture["source_manifest_raw"], "source-manifest.json"),
                    (fixture["request"]["context"]["plan_pin"],
                     fixture["plan_raw"], "plan.json"),
                    (fixture["budget_pin"], fixture["budget_raw"],
                     "host-evidence-budget.json"),
                )
                for dependency_pin, raw, name in dependencies:
                    local = dependency_cache / name
                    local.write_bytes(raw)
                    os.chmod(local, 0o600)
                    dependency_paths[dependency_pin["path"]] = str(local)

                archive_root = private(root / "private-archive")
                archive_result = archive.archive_job_checkpoint(
                    fixture["request_pin"], fixture["request_raw"],
                    fixture["request"]["context"],
                    fixture["request"]["job_record_pin"], fixture["job_raw"],
                    fixture["plan_raw"], fixture["budget_raw"],
                    dependency_paths, str(dependency_cache),
                    catalogue_map, catalogue_cache,
                    fixture["rows"], {}, imported["staged_files"],
                    imported["staging_root"], str(archive_root),
                    str(root / "coordinator-stage-map.json"), {
                        "gpg_executable": signer["gpg_executable"],
                        "gpg_homedir": signer["gpg_homedir"],
                        "primary_fingerprint": signer["fingerprint"],
                        "maximum_signature_bytes":
                            signer["maximum_signature_bytes"],
                    },
                )
                checkpoint_raw = canonical(archive_result["checkpoint"])
                manifest_raw = canonical(archive_result["object_manifest"])
                ack_raw = canonical(archive_result["ack"])
                signature_raw = Path(
                    archive_result["signature_pin"]["path"],
                ).read_bytes()
                response_path = root / "coordinator-ack-bundle.tar"
                response_pin = packet.build_ack_bundle(
                    checkpoint_raw, manifest_raw, ack_raw, signature_raw,
                    fixture["budget_raw"], fixture["budget_pin"], response_path,
                )
                # Root completed import, durable copy and signing while host
                # origins were absent. Re-enter the simulated host namespace.
                for descriptor in fixture["budget"]["path_catalogue"]["chunks"]:
                    origin = Path(descriptor["path"])
                    self.assertFalse(origin.exists())
                    raw = Path(catalogue_map[str(origin)]).read_bytes()
                    self.assertEqual(len(raw), descriptor["byte_count"])
                    self.assertEqual(sha(raw), descriptor["raw_sha256"])
                    origin.write_bytes(raw)
                    os.chmod(origin, 0o600)
                fixture["incoming_path"].write_bytes(response_path.read_bytes())
                os.chmod(fixture["incoming_path"], 0o600)
                host_bundle_pin = {
                    "path": str(fixture["receiver_path"]),
                    "raw_sha256": response_pin["raw_sha256"],
                    "byte_count": response_pin["byte_count"],
                }
                published = subprocess.run(
                    [sys.executable, "-B", str(PACKET_PATH), "publish-ack",
                     "--incoming", str(fixture["incoming_path"]),
                     "--budget", fixture["budget_pin"]["path"],
                     "--offer", str(fixture["offer_path"]),
                     "--budget-pin-json", canonical(fixture["budget_pin"]).decode().rstrip("\n"),
                     "--offer-pin-json", canonical(offer_pin).decode().rstrip("\n"),
                     "--bundle-pin-json", canonical(host_bundle_pin).decode().rstrip("\n")],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, check=False, timeout=10,
                )
                self.assertEqual(published.returncode, 0, published.stderr.decode())
                transferred = packet.read_ack_bundle(
                    fixture["receiver_path"], fixture["budget_raw"],
                    fixture["budget_pin"], canonical(offer), offer_pin,
                    host_bundle_pin, fixture["signer_context_raw"],
                    fixture["signer_context_pin"],
                    fixture["execution_manifest_raw"],
                    fixture["execution_manifest_pin"],
                )

                manifest_rows = {
                    row["origin_path"]: row
                    for row in transferred["manifest"]["objects"]
                }
                host_rows = []
                for entry in transferred["checkpoint"]["entries"]:
                    local, _literal = archive._staged_descriptor(
                        entry["origin_path"], str(fixture["source_root"]), entry,
                    )
                    manifest_row = manifest_rows[entry["origin_path"]]
                    host_rows.append({
                        "origin_path": entry["origin_path"],
                        "object_id": manifest_row["object_id"],
                        "remote_object_pin": manifest_row["object_pin"],
                        "local_staged_file": local,
                    })
                stage_map_body = {
                    "schema": archive.STAGE_MAP_SCHEMA_V1,
                    "checkpoint_pin": transferred["checkpoint_pin"],
                    "object_manifest_pin": transferred["manifest_pin"],
                    "rows": host_rows, "stage_map_sha256": "",
                }
                stage_map = {
                    **stage_map_body,
                    "stage_map_sha256": sha(canonical({
                        key: value for key, value in stage_map_body.items()
                        if key != "stage_map_sha256"
                    })),
                }
                stage_map_raw = canonical(stage_map)
                stage_map_path = fixture["output_root"] / "stage-map.json"
                stage_map_path.write_bytes(stage_map_raw)
                os.chmod(stage_map_path, 0o600)
                stage_map_pin = {
                    "path": str(stage_map_path),
                    "raw_sha256": sha(stage_map_raw),
                    "semantic_sha256": stage_map["stage_map_sha256"],
                }
                verified = archive.verify_durable_ack(
                    transferred["checkpoint_pin"], transferred["checkpoint"],
                    transferred["checkpoint_raw"], fixture["request_raw"],
                    fixture["budget_raw"],
                    fixture["request"]["job_record_pin"], fixture["job_raw"],
                    fixture["plan_raw"], transferred["manifest_pin"],
                    transferred["manifest"], transferred["manifest_raw"],
                    transferred["ack_pin"], transferred["ack"],
                    transferred["ack_raw"], transferred["signature_pin"],
                    transferred["signature_raw"], fixture["signer_context_pin"],
                    fixture["signer_context_raw"],
                    fixture["execution_manifest_pin"],
                    fixture["execution_manifest_raw"], stage_map_pin,
                    stage_map, str(fixture["source_root"]), None,
                )
                removed = archive.reclaim_acknowledged_local_paths(
                    transferred["checkpoint"], verified, stage_map,
                    str(fixture["source_root"]),
                    checkpoint_raw=transferred["checkpoint_raw"],
                    request_raw=fixture["request_raw"],
                    host_budget_raw=fixture["budget_raw"],
                    job_record_bytes=fixture["job_raw"],
                    plan_bytes=fixture["plan_raw"],
                    object_manifest=transferred["manifest"],
                    manifest_raw=transferred["manifest_raw"],
                    ack=transferred["ack"], ack_raw=transferred["ack_raw"],
                    signature_raw=transferred["signature_raw"],
                    signer_context_pin=fixture["signer_context_pin"],
                    signer_context_raw=fixture["signer_context_raw"],
                    execution_manifest_pin=fixture["execution_manifest_pin"],
                    execution_manifest_raw=fixture["execution_manifest_raw"],
                )
                self.assertEqual(
                    set(removed), {row["origin_path"] for row in fixture["rows"]},
                )
                self.assertTrue(all(not Path(row["origin_path"]).exists()
                                    for row in fixture["rows"]))
                self.assertTrue(fixture["job_path"].is_file())

    def test_one_packet_roundtrip_preserves_literal_symlink_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-transfer-roundtrip-") as tmp:
            root = Path(tmp)
            fixture = self._fixture(root)
            packet_pin, offer, offer_pin = self._offer(fixture)
            catalogue_map, catalogue_cache = self._capture_catalogue_map(
                fixture, root, remove_origins=True,
            )
            stage = private(root / "private-stage")
            result = packet.import_transfer_packet(
                fixture["packet_path"], fixture["budget_raw"],
                fixture["budget_pin"], canonical(offer), offer_pin, stage,
                catalogue_map, catalogue_cache,
            )
            self.assertTrue(all(not Path(path).exists()
                                for path in fixture["catalogue_chunk_paths"]))
            self.assertEqual(result["request"], fixture["request"])
            self.assertEqual(result["packet_raw_sha256"],
                             packet_pin["raw_sha256"])
            job_staged = Path(result["job_record_path"])
            self.assertEqual(job_staged.read_bytes(), fixture["job_raw"])
            self.assertFalse(job_staged.is_symlink())
            self.assertEqual(job_staged.stat().st_nlink, 1)
            self.assertEqual(job_staged.stat().st_mode & 0o777, 0o600)
            for row in fixture["rows"]:
                staged = Path(result["staged_files"][row["origin_path"]])
                self.assertTrue(staged.is_file())
                self.assertFalse(staged.is_symlink())
                self.assertEqual(staged.read_bytes(),
                                 fixture["payload_raw"] if row["origin_path"] ==
                                 str(fixture["payload"]) else
                                 fixture["link_raw"])
                self.assertEqual(staged.stat().st_nlink, 1)
                self.assertEqual(staged.stat().st_mode & 0o777, 0o600)

    def test_tampered_payload_is_rejected_before_stage_creation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-transfer-tamper-") as tmp:
            root = Path(tmp)
            fixture = self._fixture(root)
            _packet_pin, offer, offer_pin = self._offer(fixture)
            catalogue_map, catalogue_cache = self._capture_catalogue_map(
                fixture, root, remove_origins=True,
            )
            packet_bytes = fixture["packet_path"].read_bytes()
            # The first object follows the request and separate local record.
            request_size = len(fixture["request_raw"])
            job_size = len(fixture["job_raw"])
            object_data_offset = (
                512 + ((request_size + 511) // 512) * 512 + 512 +
                ((job_size + 511) // 512) * 512 + 512
            )
            mutated = bytearray(packet_bytes)
            mutated[object_data_offset] ^= 0x01
            bad_packet = fixture["scratch_root"] / "bad.tar"
            bad_packet.write_bytes(mutated)
            os.chmod(bad_packet, 0o600)
            stage = private(root / "bad-stage")
            with self.assertRaises(packet.TransferPacketError):
                packet.import_transfer_packet(
                    bad_packet, fixture["budget_raw"], fixture["budget_pin"],
                    canonical(offer), offer_pin, stage,
                    catalogue_map, catalogue_cache,
                )
            self.assertEqual(list(stage.iterdir()), [])

    def test_missing_object_member_is_rejected_before_stage_creation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-transfer-missing-") as tmp:
            root = Path(tmp)
            fixture = self._fixture(root)
            _packet_pin, offer, offer_pin = self._offer(fixture)
            catalogue_map, catalogue_cache = self._capture_catalogue_map(
                fixture, root, remove_origins=True,
            )
            parts = []
            for name, raw in (
                ("checkpoint-request.json", fixture["request_raw"]),
                ("validation/job-record.json", fixture["job_raw"]),
            ):
                parts.append(packet._tar_header(name, len(raw)))
                parts.append(raw)
                parts.append(b"\x00" * ((-len(raw)) % packet.TAR_BLOCK_BYTES))
            parts.append(b"\x00" * 1024)
            missing = root / "missing-object.tar"
            missing.write_bytes(b"".join(parts))
            os.chmod(missing, 0o600)
            fd = os.open(missing, os.O_RDONLY)
            try:
                with self.assertRaises(packet.TransferPacketError):
                    packet._scan_packet(
                        fd, os.fstat(fd), offer["checkpoint_request_pin"],
                        fixture["budget"], catalogue_map, catalogue_cache,
                    )
            finally:
                os.close(fd)
            stage = private(root / "missing-stage")
            # The importer verifies its external packet pin before any stage
            # writes, even when the malicious packet is given a fresh offer.
            forged_offer_body = {
                **offer,
                "transfer_packet_pin": {
                    "path": offer["transfer_packet_pin"]["path"],
                    "raw_sha256": sha(missing.read_bytes()),
                    "byte_count": missing.stat().st_size,
                },
            }
            forged_offer = {
                **forged_offer_body,
                "offer_sha256": sha(canonical({
                    key: value for key, value in forged_offer_body.items()
                    if key != "offer_sha256"
                })),
            }
            forged_offer_pin = {
                "path": offer_pin["path"],
                "raw_sha256": sha(canonical(forged_offer)),
                "semantic_sha256": forged_offer["offer_sha256"],
            }
            with self.assertRaises(packet.TransferPacketError):
                packet.import_transfer_packet(
                    missing, fixture["budget_raw"], fixture["budget_pin"],
                    canonical(forged_offer), forged_offer_pin, stage,
                    catalogue_map, catalogue_cache,
                )
            self.assertEqual(list(stage.iterdir()), [])

    def test_offer_is_bound_to_one_catalogued_ack_receiver_and_quota(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-transfer-offer-") as tmp:
            root = Path(tmp)
            fixture = self._fixture(root)
            packet_pin, offer, offer_pin = self._offer(fixture)
            checked, checked_pin, limits = packet.validate_transfer_offer(
                canonical(offer), offer_pin,
                fixture["budget_raw"], fixture["budget_pin"],
            )
            self.assertEqual(checked, offer)
            self.assertEqual(checked_pin, offer_pin)
            self.assertEqual(
                checked["acknowledgement_receiver"]["maximum_bytes"],
                limits[-2],
            )
            self.assertEqual(
                checked["transfer_packet_pin"]["raw_sha256"],
                packet_pin["raw_sha256"],
            )

    def test_row_over_catalogue_ceiling_fails_before_packet_creation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-transfer-cap-") as tmp:
            root = Path(tmp)
            fixture = self._fixture(root)
            first = dict(fixture["rows"][0])
            first["byte_count"] += 1
            bad_entries = [first, fixture["rows"][1]]
            bad_body = {**fixture["request"], "entries": bad_entries,
                        "request_sha256": ""}
            bad_request = {
                **bad_body,
                "request_sha256": sha(canonical({
                    key: value for key, value in bad_body.items()
                    if key != "request_sha256"
                })),
            }
            raw = canonical(bad_request)
            packet_path = fixture["scratch_root"] / "over-cap.tar"
            with self.assertRaises(packet.TransferPacketError):
                packet.export_transfer_packet(
                    raw,
                    {
                        "path": fixture["request_pin"]["path"],
                        "raw_sha256": sha(raw),
                        "semantic_sha256": bad_request["request_sha256"],
                    },
                    fixture["budget_path"], packet_path,
                    fixture["offer_path"], fixture["receiver_path"],
                )
            self.assertFalse(packet_path.exists())

    def test_archive_replays_exact_object_and_local_record_catalogue_caps(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-archive-catalogue-") as tmp:
            root = Path(tmp)
            fixture = self._fixture(root)
            cache = private(root / "coordinator-catalogue-cache")
            catalogue_map_rows = []
            for index, origin_path in enumerate(fixture["catalogue_chunk_paths"]):
                captured_chunk = cache / f"captured-chunk-{index:04d}.jsonl"
                captured_chunk.write_bytes(Path(origin_path).read_bytes())
                os.chmod(captured_chunk, 0o600)
                catalogue_map_rows.append({
                    "origin_path": origin_path,
                    "local_path": str(captured_chunk),
                })
            catalogue_map_body = {
                "schema": archive.CATALOGUE_LOCAL_MAP_SCHEMA_V1,
                "campaign_id": "campaign-a", "host_id": "host-a",
                "resource_budget_pin": fixture["budget_pin"],
                "chunks": catalogue_map_rows,
            }
            catalogue_map_raw = canonical({
                **catalogue_map_body,
                "map_sha256": sha(canonical(catalogue_map_body)),
            })
            chunk_map = archive._parse_catalogue_local_map(
                catalogue_map_raw, fixture["request"]["context"],
            )
            dependency_cache = private(root / "coordinator-dependency-cache")
            dependency_values = {
                "source": (fixture["request"]["context"]["source_manifest_pin"],
                           fixture["source_manifest_raw"]),
                "plan": (fixture["request"]["context"]["plan_pin"],
                         fixture["plan_raw"]),
                "budget": (fixture["budget_pin"], fixture["budget_raw"]),
            }
            dependency_entries = []
            for name, (origin_pin, raw) in dependency_values.items():
                local_path = dependency_cache / f"captured-{name}.json"
                local_path.write_bytes(raw)
                os.chmod(local_path, 0o600)
                dependency_entries.append({
                    "origin_pin": origin_pin, "local_path": str(local_path),
                })
            dependency_entries.sort(key=lambda row: row["origin_pin"]["path"])
            dependency_map_body = {
                "schema": archive.DEPENDENCY_LOCAL_MAP_SCHEMA_V1,
                "campaign_id": "campaign-a", "host_id": "host-a",
                "entries": dependency_entries,
            }
            dependency_map_raw = canonical({
                **dependency_map_body,
                "map_sha256": sha(canonical(dependency_map_body)),
            })
            dependency_map = archive._parse_dependency_local_map(
                dependency_map_raw, fixture["request"]["context"],
            )
            archive._validate_local_dependencies(
                dependency_map, str(dependency_cache),
                fixture["request"]["context"], fixture["plan_raw"],
                fixture["budget_raw"],
            )
            job_document = json.loads(fixture["job_raw"])
            identity = {"run_id": fixture["run_id"]}
            archive._validate_host_budget_object_rows(
                fixture["budget_raw"], fixture["request"]["context"],
                identity, fixture["rows"],
                fixture["request"]["job_record_pin"],
                len(fixture["job_raw"]), job_document["record_sha256"],
                chunk_map, str(cache),
            )
            oversized = [dict(fixture["rows"][0],
                              byte_count=fixture["rows"][0]["byte_count"] + 1),
                         fixture["rows"][1]]
            with self.assertRaises(archive.EvidenceArchiveError):
                archive._validate_host_budget_object_rows(
                    fixture["budget_raw"], fixture["request"]["context"],
                    identity, oversized,
                    fixture["request"]["job_record_pin"],
                    len(fixture["job_raw"]), job_document["record_sha256"],
                    chunk_map, str(cache),
                )

    def test_catalogue_metadata_caps_reject_before_any_chunk_read(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-catalogue-pre-read-") as tmp:
            fixture = self._fixture(Path(tmp))
            for value in (True, 0, packet.MAX_CATALOGUE_CHUNK_BYTES + 1,
                          (1 << 64) - 1):
                budget = copy.deepcopy(fixture["budget"])
                catalogue = budget["path_catalogue"]
                catalogue["chunk_bytes"] = value
                catalogue["semantic_sha256"] = sha(canonical({
                    key: item for key, item in catalogue.items()
                    if key != "semantic_sha256"
                }))
                budget_tests.sealed(budget, "budget_sha256")
                with mock.patch.object(packet, "_read_regular_absolute") as reader:
                    with self.assertRaises(packet.TransferPacketError):
                        packet._catalogue_rows_for_paths(
                            budget, set(), "host-a", None, None,
                        )
                    reader.assert_not_called()
            for field in ("byte_count", "row_count"):
                budget = copy.deepcopy(fixture["budget"])
                catalogue = budget["path_catalogue"]
                catalogue["chunks"][0][field] = (1 << 64) - 1
                catalogue["semantic_sha256"] = sha(canonical({
                    key: item for key, item in catalogue.items()
                    if key != "semantic_sha256"
                }))
                budget_tests.sealed(budget, "budget_sha256")
                with mock.patch.object(packet, "_read_regular_absolute") as reader:
                    with self.assertRaises(packet.TransferPacketError):
                        packet._catalogue_rows_for_paths(
                            budget, set(), "host-a", None, None,
                        )
                    reader.assert_not_called()

    def test_huge_pax_header_is_rejected_before_reading_declared_body(self) -> None:
        fake_fd = os.open(os.devnull, os.O_RDONLY)
        header = {
            "name": "PaxHeaders/size", "typeflag": b"x", "mode": 0o600,
            "uid": 0, "gid": 0, "mtime": 0, "linkname": b"",
            "size": packet.MAX_PAX_HEADER_BYTES + 1, "offset": 0,
        }
        try:
            with self.assertRaises(packet.TransferPacketError):
                packet._parse_pax_size(fake_fd, header, 1 << 50)
        finally:
            os.close(fake_fd)

    def test_ack_bundle_is_a_bounded_exact_four_member_closure(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-ack-bundle-") as tmp:
            root = Path(tmp)
            fixture = self._fixture(root)
            _packet_pin, offer, offer_pin = self._offer(fixture)
            source5_root = (
                root / "private" / "campaign-a" / "host-a" / "source5"
            )
            job_sha = "e" * 64
            job_leaf = f"000001-{job_sha}.json"
            manifest_objects = []
            for row in fixture["rows"]:
                origin_name = sha(row["origin_path"].encode("utf-8"))
                object_id = (
                    f"{origin_name[:2]}/{origin_name}-"
                    f"{row['raw_sha256']}.bin"
                )
                manifest_objects.append({
                    "origin_path": row["origin_path"],
                    "role": row["role"], "object_id": object_id,
                    "byte_count": row["byte_count"],
                    "raw_sha256": row["raw_sha256"],
                    "semantic_sha256": row["semantic_sha256"],
                    "object_pin": {
                        "path": str(source5_root / "objects" / object_id),
                        "raw_sha256": row["raw_sha256"],
                        "semantic_sha256": row["raw_sha256"],
                        "byte_count": row["byte_count"],
                    },
                })
            manifest_body = {
                "schema": "allocatbelt.application-source5-evidence-object-manifest.v1",
                "campaign_id": "campaign-a", "host_id": "host-a",
                "phase": "aa", "job_index": 0, "job_ordinal": 1,
                "job_sha256": job_sha,
                "run_id": fixture["run_id"],
                "job_record_raw_sha256": sha(fixture["job_raw"]),
                "predecessor_ack_pin": None, "objects": manifest_objects,
                "object_count": len(fixture["rows"]),
                "payload_bytes": sum(row["byte_count"] for row in fixture["rows"]),
            }
            manifest = {
                **manifest_body,
                "manifest_sha256": sha(canonical(manifest_body)),
            }
            manifest_raw = canonical(manifest)
            manifest_pin = {
                "path": str(source5_root / "objects" / "manifests" / "aa" /
                            job_leaf),
                "raw_sha256": sha(manifest_raw),
                "semantic_sha256": manifest["manifest_sha256"],
            }
            checkpoint_body = {
                "schema": "allocatbelt.application-source5-evidence-job-checkpoint.v1",
                "request_pin": fixture["request_pin"],
                "context": fixture["request"]["context"],
                "job_record_pin": fixture["request"]["job_record_pin"],
                "authorization": fixture["request"]["authorization"],
                "predecessor_ack_pin": None, "owner_receipt_pins": {},
                "empty_tmp_proofs": [], "object_manifest_pin": manifest_pin,
                "entries": fixture["rows"],
            }
            checkpoint = {
                **checkpoint_body,
                "checkpoint_sha256": sha(canonical(checkpoint_body)),
            }
            checkpoint_raw = canonical(checkpoint)
            checkpoint_pin = {
                "path": str(source5_root / "checkpoints" / "aa" / job_leaf),
                "raw_sha256": sha(checkpoint_raw),
                "semantic_sha256": checkpoint["checkpoint_sha256"],
            }
            validation = {
                "path": str(source5_root / "validation" / "job-records" / "aa" /
                            job_leaf),
                "origin_path": fixture["job_path"].as_posix(),
                "raw_sha256": sha(fixture["job_raw"]),
                "semantic_sha256": json.loads(fixture["job_raw"])["record_sha256"],
                "byte_count": len(fixture["job_raw"]),
            }
            durable = {
                "commit_id": "1" * 64,
                "archive_source5_directory": {
                    "path": str(source5_root),
                    "device": 1, "inode": 2, "mode": 0o700,
                },
                "checkpoint_pin": checkpoint_pin,
                "object_manifest_pin": manifest_pin,
                "object_reopen_sha256": "2" * 64,
                "object_count": len(fixture["rows"]),
                "payload_bytes": sum(row["byte_count"] for row in fixture["rows"]),
                "job_record_validation": validation,
            }
            ack_body = {
                "schema": "allocatbelt.application-source5-evidence-durable-ack.v1",
                "checkpoint_pin": checkpoint_pin,
                "object_manifest_pin": manifest_pin,
                "predecessor_ack_pin": None,
                "signer_fingerprint": "A" * 40,
                "durable_commit": durable,
            }
            ack = {**ack_body, "ack_sha256": sha(canonical(ack_body))}
            ack_raw = canonical(ack)
            signature = b"bounded-test-signature"
            coordinator_bundle = root / "coordinator-ack-bundle.tar"
            coordinator_pin = packet.build_ack_bundle(
                checkpoint_raw, manifest_raw, ack_raw, signature,
                fixture["budget_raw"], fixture["budget_pin"],
                coordinator_bundle,
            )
            incoming_bytes = coordinator_bundle.read_bytes()
            fixture["incoming_path"].write_bytes(incoming_bytes)
            os.chmod(fixture["incoming_path"], 0o600)
            bundle_pin = {
                "path": str(fixture["receiver_path"]),
                "raw_sha256": coordinator_pin["raw_sha256"],
                "byte_count": coordinator_pin["byte_count"],
            }
            signer_context_raw = fixture["signer_context_raw"]
            signer_context_pin = fixture["signer_context_pin"]
            published = packet.publish_ack_bundle(
                fixture["incoming_path"], fixture["budget_raw"],
                fixture["budget_pin"], canonical(offer), offer_pin,
                bundle_pin,
            )
            self.assertEqual(published, bundle_pin)
            self.assertFalse(fixture["incoming_path"].exists())
            imported = packet.read_ack_bundle(
                fixture["receiver_path"], fixture["budget_raw"],
                fixture["budget_pin"], canonical(offer), offer_pin,
                bundle_pin, signer_context_raw, signer_context_pin,
                fixture["execution_manifest_raw"],
                fixture["execution_manifest_pin"],
            )
            self.assertEqual(imported["checkpoint_raw"], checkpoint_raw)
            self.assertEqual(imported["manifest_raw"], manifest_raw)
            self.assertEqual(imported["ack_raw"], ack_raw)
            self.assertEqual(imported["signature_raw"], signature)
            self.assertEqual(imported["bundle_pin"], bundle_pin)
            self.assertEqual(imported["checkpoint_pin"], checkpoint_pin)
            self.assertEqual(imported["manifest_pin"], manifest_pin)
            self.assertEqual(imported["ack_pin"]["raw_sha256"], sha(ack_raw))
            self.assertEqual(imported["signature_pin"]["raw_sha256"],
                             sha(signature))
            tampered_context = json.loads(signer_context_raw)
            tampered_body = {
                key: value for key, value in tampered_context.items()
                if key != "signer_context_sha256"
            }
            tampered_body["keyring_pin"] = {
                **tampered_body["keyring_pin"], "raw_sha256": "c" * 64,
            }
            tampered_context = {
                **tampered_body,
                "signer_context_sha256": sha(canonical(tampered_body)),
            }
            tampered_raw = canonical(tampered_context)
            tampered_pin = {
                "path": signer_context_pin["path"],
                "raw_sha256": sha(tampered_raw),
                "semantic_sha256": tampered_context[
                    "signer_context_sha256"
                ],
            }
            with self.assertRaises(packet.TransferPacketError):
                packet.read_ack_bundle(
                    fixture["receiver_path"], fixture["budget_raw"],
                    fixture["budget_pin"], canonical(offer), offer_pin,
                    bundle_pin, tampered_raw, tampered_pin,
                    fixture["execution_manifest_raw"],
                    fixture["execution_manifest_pin"],
                )

    def test_fixed_v3_read_ack_checks_the_actual_offered_request_pin(self) -> None:
        """Structural profile witness; this does not establish GPG authority."""
        with tempfile.TemporaryDirectory(prefix="source5-fixed-v3-read-ack-") as tmp:
            root = Path(tmp)
            fixture = self._fixture(root)
            owner_directory = private(root / "fixed-owner-receipts")
            owner_pins = {}
            owner_rows = []
            for role in ("component_receipt", "fixed_pair_host_receipt"):
                receipt_body = {
                    "schema": "allocatbelt.test-source5-owner-receipt.v1",
                    "role": role, "structural_fixture": True,
                }
                receipt_semantic = sha(canonical(receipt_body))
                raw = canonical({
                    **receipt_body, "receipt_sha256": receipt_semantic,
                })
                origin = owner_directory / f"{role}.json"
                origin.write_bytes(raw)
                os.chmod(origin, 0o600)
                receipt_pin = {
                    "path": str(origin), "raw_sha256": sha(raw),
                    "semantic_sha256": receipt_semantic,
                }
                owner_pins[role] = receipt_pin
                owner_rows.append({
                    "origin_path": str(origin), "role": role,
                    "byte_count": len(raw), "raw_sha256": sha(raw),
                    "semantic_sha256": receipt_semantic,
                })
            mount = {
                "mount_id": 1, "major_minor": "0:1",
                "mount_root": "/", "mount_point": "/",
                "filesystem_type": "ext4", "mount_source": "test",
                "device": 1,
            }
            proofs = []
            for ordinal in (0, 1):
                for domain in ("", "probe_tmpdir"):
                    proof = {
                        "role": "component_receipt",
                        "path": str(root / "tmp-facts" /
                                    f"{ordinal}-{domain or 'member'}"),
                        "owner_receipt_pin": owner_pins["component_receipt"],
                        "member_ordinal": ordinal, "device": 1,
                        "inode": 100 + len(proofs), "mode": 0o700,
                        "bytes_used": 0, "file_count": 0,
                        "directory_count": 0, "bytes_limit": 1024,
                        "inode_limit": 16, "mount": mount,
                    }
                    if domain:
                        proof["domain"] = domain
                    proofs.append(proof)
            context = fixture["request"]["context"]
            request_body = {
                "schema": packet.REQUEST_SCHEMA_V3,
                "context": context,
                "job_record_pin": fixture["request"]["job_record_pin"],
                "authorization": fixture["request"]["authorization"],
                "predecessor_ack_pin": context["predecessor_ack_pin"],
                "owner_receipt_pins": owner_pins,
                "empty_tmp_proofs": proofs,
                "entries": sorted(owner_rows,
                                  key=lambda row: row["origin_path"]),
                "request_sha256": "",
            }
            request = {
                **request_body,
                "request_sha256": sha(canonical({
                    key: value for key, value in request_body.items()
                    if key != "request_sha256"
                })),
            }
            self.assertEqual(packet._validate_request(request), request)
            request_raw = canonical(request)
            request_path = fixture["request_path"]
            request_path.write_bytes(request_raw)
            os.chmod(request_path, 0o600)
            request_pin = {
                "path": str(request_path), "raw_sha256": sha(request_raw),
                "semantic_sha256": request["request_sha256"],
            }

            source5_root = (
                root / "private" / context["campaign_id"] /
                context["host_id"] / "source5"
            )
            job_sha = "e" * 64
            job_leaf = f"000001-{job_sha}.json"
            objects = []
            for row in request["entries"]:
                object_id = packet._object_identity(
                    row["origin_path"], row["raw_sha256"],
                )
                objects.append({
                    **row, "object_id": object_id,
                    "object_pin": {
                        "path": str(source5_root / "objects" / object_id),
                        "raw_sha256": row["raw_sha256"],
                        "semantic_sha256": row["raw_sha256"],
                        "byte_count": row["byte_count"],
                    },
                })
            manifest_body = {
                "schema": "allocatbelt.application-source5-evidence-object-manifest.v1",
                "campaign_id": context["campaign_id"],
                "host_id": context["host_id"], "phase": context["phase"],
                "job_index": context["job_index"], "job_ordinal": 1,
                "job_sha256": job_sha, "run_id": fixture["run_id"],
                "job_record_raw_sha256":
                    request["job_record_pin"]["raw_sha256"],
                "predecessor_ack_pin": request["predecessor_ack_pin"],
                "objects": objects, "object_count": len(objects),
                "payload_bytes": sum(row["byte_count"]
                                     for row in request["entries"]),
            }
            manifest = {
                **manifest_body,
                "manifest_sha256": sha(canonical(manifest_body)),
            }
            manifest_raw = canonical(manifest)
            manifest_pin = {
                "path": str(source5_root / "objects" / "manifests" /
                            context["phase"] / job_leaf),
                "raw_sha256": sha(manifest_raw),
                "semantic_sha256": manifest["manifest_sha256"],
            }
            checkpoint_body = {
                "schema": packet.CHECKPOINT_SCHEMA_V3,
                "request_pin": request_pin, "context": context,
                "job_record_pin": request["job_record_pin"],
                "authorization": request["authorization"],
                "predecessor_ack_pin": request["predecessor_ack_pin"],
                "owner_receipt_pins": owner_pins,
                "empty_tmp_proofs": proofs,
                "object_manifest_pin": manifest_pin,
                "entries": request["entries"],
            }
            checkpoint = {
                **checkpoint_body,
                "checkpoint_sha256": sha(canonical(checkpoint_body)),
            }
            checkpoint_raw = canonical(checkpoint)
            checkpoint_pin = {
                "path": str(source5_root / "checkpoints" /
                            context["phase"] / job_leaf),
                "raw_sha256": sha(checkpoint_raw),
                "semantic_sha256": checkpoint["checkpoint_sha256"],
            }
            job_document = json.loads(fixture["job_raw"])
            validation = {
                "path": str(source5_root / "validation" / "job-records" /
                            context["phase"] / job_leaf),
                "origin_path": request["job_record_pin"]["path"],
                "raw_sha256": request["job_record_pin"]["raw_sha256"],
                "semantic_sha256": job_document["record_sha256"],
                "byte_count": len(fixture["job_raw"]),
            }
            durable = {
                "commit_id": "1" * 64,
                "archive_source5_directory": {
                    "path": str(source5_root), "device": 1, "inode": 2,
                    "mode": 0o700,
                },
                "checkpoint_pin": checkpoint_pin,
                "object_manifest_pin": manifest_pin,
                "object_reopen_sha256": "2" * 64,
                "object_count": len(objects),
                "payload_bytes": manifest["payload_bytes"],
                "job_record_validation": validation,
            }
            ack_body = {
                "schema": "allocatbelt.application-source5-evidence-durable-ack.v1",
                "checkpoint_pin": checkpoint_pin,
                "object_manifest_pin": manifest_pin,
                "predecessor_ack_pin": request["predecessor_ack_pin"],
                "signer_fingerprint": context["authorized_signer_fingerprint"],
                "durable_commit": durable,
            }
            ack = {**ack_body, "ack_sha256": sha(canonical(ack_body))}
            signature = b"structural-test-signature"
            members = [
                ("checkpoint.json", checkpoint_raw),
                ("object-manifest.json", manifest_raw),
                ("ack.json", canonical(ack)),
                ("ack.sig", signature),
            ]
            bundle_raw = b"".join(
                packet._tar_header(name, len(raw)) + raw +
                b"\x00" * ((-len(raw)) % packet.TAR_BLOCK_BYTES)
                for name, raw in members
            )
            bundle_raw += b"\x00" * 1024
            bundle_raw += b"\x00" * ((-len(bundle_raw)) % packet.TAR_RECORD_BYTES)
            self.assertEqual(
                len(bundle_raw),
                packet._tar_size((name, len(raw)) for name, raw in members),
            )
            receiver_path = fixture["receiver_path"]
            receiver_path.write_bytes(bundle_raw)
            os.chmod(receiver_path, 0o600)
            bundle_pin = {
                "path": str(receiver_path), "raw_sha256": sha(bundle_raw),
                "byte_count": len(bundle_raw),
            }
            retention = fixture["budget"]["path_catalogue"][
                "retention_policy"
            ]
            maximum_ack_bytes = retention["maximum_ack_bundle_bytes"]
            maximum_signature_bytes = retention["maximum_signature_bytes"]
            limits = (1 << 20, 1, 1 << 20, 16,
                      [str(fixture["source_root"])],
                      str(fixture["scratch_root"]), maximum_ack_bytes,
                      maximum_signature_bytes)

            def offer_for(pin_value):
                offer = packet._offer_body(
                    pin_value, str(fixture["packet_path"]), "b" * 64, 512,
                    str(receiver_path), maximum_ack_bytes,
                )
                raw = canonical(offer)
                offer_pin = {
                    "path": str(fixture["offer_path"]),
                    "raw_sha256": sha(raw),
                    "semantic_sha256": offer["offer_sha256"],
                }
                return offer, raw, offer_pin

            def read_with_profile(pin_value):
                offer, offer_raw, offer_pin = offer_for(pin_value)
                with mock.patch.object(
                    packet, "_validate_transfer_offer_with_profile",
                    return_value=(offer, offer_pin, limits, {
                        "required_request_schema": packet.REQUEST_SCHEMA_V3,
                    }),
                ):
                    return packet.read_ack_bundle(
                        receiver_path, fixture["budget_raw"],
                        fixture["budget_pin"], offer_raw, offer_pin,
                        bundle_pin, fixture["signer_context_raw"],
                        fixture["signer_context_pin"],
                        fixture["execution_manifest_raw"],
                        fixture["execution_manifest_pin"],
                        budget_context=context,
                    )

            imported = read_with_profile(request_pin)
            self.assertEqual(imported["checkpoint_raw"], checkpoint_raw)
            self.assertEqual(imported["checkpoint"]["schema"],
                             packet.CHECKPOINT_SCHEMA_V3)

            legacy_body = dict(request)
            legacy_body["schema"] = packet.REQUEST_SCHEMA
            legacy_body["empty_tmp_proofs"] = [
                proof for proof in proofs if "domain" not in proof
            ]
            legacy_body["request_sha256"] = ""
            legacy = {
                **legacy_body,
                "request_sha256": sha(canonical({
                    key: value for key, value in legacy_body.items()
                    if key != "request_sha256"
                })),
            }
            legacy_raw = canonical(legacy)
            request_path.write_bytes(legacy_raw)
            os.chmod(request_path, 0o600)
            legacy_pin = {
                "path": str(request_path), "raw_sha256": sha(legacy_raw),
                "semantic_sha256": legacy["request_sha256"],
            }
            with self.assertRaisesRegex(
                    packet.TransferPacketError,
                    "actual checkpoint request schema"):
                read_with_profile(legacy_pin)

            request_path.unlink()
            with self.assertRaises(OSError):
                read_with_profile(request_pin)

            request_path.write_bytes(request_raw)
            os.chmod(request_path, 0o600)
            request_path.write_bytes(b"changed request bytes\n")
            os.chmod(request_path, 0o600)
            with self.assertRaisesRegex(packet.TransferPacketError,
                                        "request bytes differ from their offer pin"):
                read_with_profile(request_pin)

            request_path.write_bytes(request_raw)
            os.chmod(request_path, 0o600)
            bad_semantic_pin = {
                "path": str(request_path),
                "raw_sha256": request_pin["raw_sha256"],
                "semantic_sha256": "f" * 64,
            }
            with self.assertRaisesRegex(packet.TransferPacketError,
                                        "request semantic pin differs"):
                read_with_profile(bad_semantic_pin)

    def test_inline_pin_rejects_noncanonical_or_unbounded_input_before_read(self) -> None:
        invalid = (
            "{}\n", '{"x":1,"x":1}', '{ "x":1}',
            "x" * packet.MAX_INLINE_PIN_BYTES, '{"x":"é"}',
        )
        for value in invalid:
            with self.subTest(value=value[:40]):
                with mock.patch.object(packet, "_read_regular_absolute") as reader:
                    with self.assertRaises((packet.TransferPacketError, UnicodeError)):
                        packet._cli_pin_document(None, value, "test pin")
                    reader.assert_not_called()

    def test_publish_cli_preserves_legacy_file_pins(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-publish-legacy-pins-") as tmp:
            root = Path(tmp)
            fixture = self._fixture(root)
            _packet_pin, _offer, offer_pin = self._offer(fixture)
            raw = b"publication checks bytes; the separate host reader checks the ACK"
            fixture["incoming_path"].write_bytes(raw)
            os.chmod(fixture["incoming_path"], 0o600)
            bundle_pin = {"path": str(fixture["receiver_path"]),
                          "raw_sha256": sha(raw), "byte_count": len(raw)}
            argv = [sys.executable, "-B", str(PACKET_PATH), "publish-ack",
                    "--incoming", str(fixture["incoming_path"]),
                    "--budget", fixture["budget_pin"]["path"],
                    "--offer", str(fixture["offer_path"])]
            for name, value in (("budget", fixture["budget_pin"]),
                                ("offer", offer_pin), ("bundle", bundle_pin)):
                path = root / f"{name}-pin.json"
                path.write_bytes(canonical(value))
                os.chmod(path, 0o600)
                argv.extend([f"--{name}-pin", str(path)])
            result = subprocess.run(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, check=False, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(fixture["receiver_path"].read_bytes(), raw)
            self.assertFalse(fixture["incoming_path"].exists())

    def test_publish_cli_rejects_tampered_inline_bundle_pin_without_rename(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-publish-bad-inline-pin-") as tmp:
            fixture = self._fixture(Path(tmp))
            _packet_pin, _offer, offer_pin = self._offer(fixture)
            raw = b"unchanged unacknowledged incoming bytes"
            fixture["incoming_path"].write_bytes(raw)
            os.chmod(fixture["incoming_path"], 0o600)
            bundle_pin = {"path": str(fixture["receiver_path"]),
                          "raw_sha256": "0" * 64, "byte_count": len(raw)}
            argv = [sys.executable, "-B", str(PACKET_PATH), "publish-ack",
                    "--incoming", str(fixture["incoming_path"]),
                    "--budget", fixture["budget_pin"]["path"],
                    "--offer", str(fixture["offer_path"])]
            for name, value in (("budget", fixture["budget_pin"]),
                                ("offer", offer_pin), ("bundle", bundle_pin)):
                argv.extend([f"--{name}-pin-json",
                             canonical(value).decode().rstrip("\n")])
            result = subprocess.run(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, check=False, timeout=10,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn(b"Source5 transfer packet failed:", result.stderr)
            self.assertFalse(fixture["receiver_path"].exists())
            self.assertEqual(fixture["incoming_path"].read_bytes(), raw)

    def test_ack_publisher_refuses_to_replace_a_final_receiver(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-ack-no-replace-") as tmp:
            root = Path(tmp)
            fixture = self._fixture(root)
            _packet_pin, offer, offer_pin = self._offer(fixture)
            incoming_raw = b"completed but intentionally invalid ACK envelope"
            final_raw = b"existing immutable receiver bytes"
            fixture["incoming_path"].write_bytes(incoming_raw)
            os.chmod(fixture["incoming_path"], 0o600)
            fixture["receiver_path"].write_bytes(final_raw)
            os.chmod(fixture["receiver_path"], 0o600)
            with self.assertRaises(packet.TransferPacketError):
                packet.publish_ack_bundle(
                    fixture["incoming_path"], fixture["budget_raw"],
                    fixture["budget_pin"], canonical(offer), offer_pin,
                    {
                        "path": str(fixture["receiver_path"]),
                        "raw_sha256": sha(incoming_raw),
                        "byte_count": len(incoming_raw),
                    },
                )
            self.assertEqual(fixture["receiver_path"].read_bytes(), final_raw)
            self.assertEqual(fixture["incoming_path"].read_bytes(), incoming_raw)


class HostBudgetR6SchemaTests(unittest.TestCase):
    def _fixture(self, *, width_bound: bool):
        campaign = "campaign-a"
        host = "host-a"
        plan_pin = pin(Path("/private/inputs/plan.json"), b"plan")
        source_pin = pin(Path("/private/inputs/source.json"), b"source")
        signer_contexts = {
            item: {
                "artifact": {
                    "path": f"/private/inputs/{item}-signer.json",
                    "raw_sha256": sha(item.encode()),
                },
                "semantic_sha256": sha((item + "-semantic").encode()),
            } for item in ("host-a", "host-b", "host-c")
        }
        width_body = {
            "schema": packet.JOURNAL_WIDTH_CONTRACT_SCHEMA,
            "campaign_id": campaign, "host_id": host,
            "original_pins_sha256": "1" * 64,
            "plan_pin": plan_pin, "source_manifest_pin": source_pin,
            "owner_pins": {}, "job_rows": [], "phase_totals": [],
            "fixed_event_widths": [], "total_event_count": 1,
            "total_event_bytes": 1,
            "failed_owner_window": {"phase": "exploration"},
        }
        width_contract = {
            **width_body, "contract_sha256": sha(canonical(width_body)),
        }
        width_raw = canonical(width_contract)
        width_pin = {
            "path": "/private/artifacts/campaign-a/source5/host-a/"
                    "prepared-input/journal-width-contract.json",
            "raw_sha256": sha(width_raw),
            "semantic_sha256": width_contract["contract_sha256"],
        }
        hosts = ["host-a", "host-b", "host-c"]
        execution_body = {
            "schema": packet.EXECUTION_SCHEMA_V4,
            "campaign_id": campaign, "hosts": hosts,
            "original_inputs": {}, "execution_sources": {},
            "modules": {}, "observed_hosts": {},
            "artifact_root": "/private/artifacts",
            "output_root": "/private/output", "phase_order": [],
            "protocol_sha256": "2" * 64,
            "qualification_eligible": False,
            "scope": "final_prepared_bounded",
            "prepared_input_generation": {"completion": {}, "provenance": {}},
            "prepared_capacity_registration": {},
            "archive_signer_contexts": signer_contexts,
            "journal_width_contracts": {
                item: ({"artifact": {"path": width_pin["path"],
                                      "raw_sha256": width_pin["raw_sha256"]},
                        "semantic_sha256": width_pin["semantic_sha256"]}
                       if item == host else {
                           "artifact": {
                               "path": f"/private/inputs/{item}-width.json",
                               "raw_sha256": sha((item + "-width").encode()),
                           },
                           "semantic_sha256": sha((item + "-width-sem").encode()),
                       }) for item in hosts
            },
        }
        if not width_bound:
            del execution_body["journal_width_contracts"]
        execution = {
            **execution_body,
            "manifest_sha256": sha(canonical(execution_body)),
        }
        execution_raw = canonical(execution)
        execution_pin = {
            "path": "/private/inputs/execution.json",
            "raw_sha256": sha(execution_raw),
            "semantic_sha256": execution["manifest_sha256"],
        }
        context = {
            "campaign_id": campaign, "host_id": host,
            "plan_pin": plan_pin, "source_manifest_pin": source_pin,
            "execution_manifest_pin": execution_pin,
            "resource_budget_pin": pin(
                Path("/private/inputs/host-budget.json"), b"budget",
            ),
        }
        original = {
            "spec": pin(Path("/private/inputs/spec.json"), b"spec"),
            "plan": plan_pin, "execution_manifest": execution_pin,
            "source_manifests": {host: source_pin},
            "source_tree_sha256": "3" * 64,
        }
        legacy_body = {
            "schema": packet.HOST_BUDGET_SCHEMA,
            "campaign_id": campaign, "host_id": host,
            "original_pins": original, "schedule": {}, "owner_contract": {},
            "path_catalogue": {"retention_policy": {
                "maximum_signature_bytes": 4096,
                "always_local_roles": sorted(
                    packet.ALWAYS_LOCAL_EVIDENCE_ROLES_LEGACY |
                    ({"journal_width_contract"} if width_bound else set()),
                ),
            }},
            "storage_reservation": {}, "role_byte_reservations": {},
            "transport": {},
            "execution_blockers": [
                "verified_between_pair_archive_ack_reclaim_not_integrated",
            ] if width_bound else [
                "source_derived_journal_width_not_bound",
                "verified_between_pair_archive_ack_reclaim_not_integrated",
            ],
            "readiness": {
                "budget_complete": False, "execution_ready": False,
                "component_gate_ready": False, "qualification_eligible": False,
            },
        }
        body = dict(legacy_body)
        if width_bound:
            body["execution_manifest_schema"] = packet.EXECUTION_SCHEMA_V4
            body["journal_width_contract_pin"] = width_pin
        budget = {**body, "budget_sha256": sha(canonical(body))}
        return context, budget, execution_raw, width_raw, width_pin

    def test_legacy_v2_field_set_keeps_signer_only_v4_nonready(self) -> None:
        context, budget, execution_raw, _width_raw, _width_pin = self._fixture(
            width_bound=False,
        )
        self.assertEqual(set(budget), packet.HOST_BUDGET_FIELDS_LEGACY)
        parsed, is_r6 = packet._exact_host_budget(budget, "legacy budget")
        self.assertFalse(is_r6)
        self.assertFalse(parsed["readiness"]["execution_ready"])
        self.assertFalse(packet._validate_host_budget_revision(
            parsed, context["campaign_id"], context["host_id"],
            context=context, execution_manifest_raw=execution_raw,
            require_manifest_binding=False,
        ))
        hybrid = {**budget, "journal_width_contract_pin": None}
        with self.assertRaises(packet.TransferPacketError):
            packet._exact_host_budget(hybrid, "unknown hybrid budget")

    def test_r6_v4_width_pin_matches_manifest_and_raw_contract(self) -> None:
        context, budget, execution_raw, width_raw, width_pin = self._fixture(
            width_bound=True,
        )
        parsed, is_r6 = packet._exact_host_budget(budget, "R6 budget")
        self.assertTrue(is_r6)
        self.assertTrue(packet._validate_host_budget_revision(
            parsed, context["campaign_id"], context["host_id"],
            context=context, execution_manifest_raw=execution_raw,
            journal_width_contract_raw=width_raw,
            require_manifest_binding=True,
        ))
        changed = {**parsed,
                   "journal_width_contract_pin": {
                       **width_pin, "path": "/private/other-width.json",
                   }}
        with self.assertRaisesRegex(packet.TransferPacketError,
                                    "width pin differs"):
            packet._validate_host_budget_revision(
                changed, context["campaign_id"], context["host_id"],
                context=context, execution_manifest_raw=execution_raw,
                journal_width_contract_raw=width_raw,
                require_manifest_binding=True,
            )
        with self.assertRaises(packet.TransferPacketError):
            packet._validate_host_budget_revision(
                parsed, context["campaign_id"], context["host_id"],
                context=context, execution_manifest_raw=execution_raw,
                require_manifest_binding=True,
            )

    def test_width_extension_cannot_claim_a_legacy_manifest_schema(self) -> None:
        context, budget, _execution_raw, _width_raw, _pin = self._fixture(
            width_bound=True,
        )
        changed = {**budget,
                   "execution_manifest_schema": packet.EXECUTION_SCHEMA_V3}
        with self.assertRaisesRegex(packet.TransferPacketError,
                                    "reserved for execution manifest v4"):
            packet._validate_host_budget_revision(
                changed, context["campaign_id"], context["host_id"],
                context=context,
            )


class H15ArchiveReadbackProducerTests(unittest.TestCase):
    """Exercise the exact H15 budget producer through both archive readers."""

    def test_h15_budget_producer_readback_catalogue_closes_both_readers(self) -> None:
        source_inputs = budget_tests.fixture()
        ordinals: dict[str, int] = {}
        for job in source_inputs["plan"]["jobs"]["exploration"]:
            host = job["host_id"]
            ordinals[host] = ordinals.get(host, 0) + 1
            job["ordinal"] = ordinals[host]
        budget_tests.repin_plan_case(source_inputs)
        host_id = source_inputs["host_id"]
        campaign_id = source_inputs["spec"]["campaign_id"]
        job = next(item for item in source_inputs["plan"]["jobs"]["exploration"]
                   if item["host_id"] == host_id)
        run_id = job["run_id"]
        job_sha = sha(canonical(job))
        source = source_inputs["sources"][host_id]
        source_rows = {row["path"]: row for row in source["source"]["files"]}

        catalogue_owner_paths = {
            "fixed_pair": "scripts/application-fixed-pair.py",
            "pressure_pair": "scripts/application-pressure-pair.py",
            "source5_controller": "scripts/application-source5-campaign.py",
            "source5_soak": "scripts/application-source5-soak.py",
            "soak_reader": "scripts/application-soak-readback.py",
            "offline_dispatcher": "scripts/application-source5-offline-dispatch.py",
            "chronology": "scripts/application-campaign-chronology.py",
            "evidence_transport": "scripts/application-source5-evidence-transport-v3.py",
        }
        budget_owner_paths = {
            "feedback_composer": "scripts/application-feedback-composition.py",
            "feedback_reader": "scripts/application-feedback-readback.py",
            "pressure_reader": "scripts/application-pressure-readback.py",
        }

        def owner_pin(role: str, path: str) -> dict[str, Any]:
            record = source_rows[path]
            return {"path": path, "raw_sha256": record["sha256"],
                    "byte_count": record["size"]}

        catalogue_owner_pins = {
            role: owner_pin(role, path)
            for role, path in catalogue_owner_paths.items()
        }
        budget_owner_pins = budget_producer._owner_schema_pins(source)
        width_owner_pins = dict(catalogue_owner_pins)
        for role, record in budget_owner_pins.items():
            normalized = {"path": record["path"],
                          "raw_sha256": record["sha256"],
                          "byte_count": record["size"]}
            self.assertIn(role, catalogue_owner_paths | budget_owner_paths)
            if role in width_owner_pins:
                self.assertEqual(width_owner_pins[role], normalized)
            width_owner_pins[role] = normalized

        plan_pin = source_inputs["pins"]["plan"]
        source_pin = source_inputs["pins"]["source_manifests"][host_id]
        counts = {
            "source5_authorized": 1,
            "source5_app_started": 2,
            "source5_app_terminal": 2,
            "source5_job_terminal": 1,
        }
        widths = {name: 1024 for name in counts}
        success_job_bytes = sum(counts[name] * widths[name] for name in counts)
        row = {
            "phase": "exploration", "job_index": 0,
            "ordinal": job["ordinal"], "run_id": run_id,
            "job_sha256": job_sha, "event_counts": dict(counts),
            "maximum_event_bytes_by_kind": dict(widths),
            "failed_event_counts": dict(counts),
            "failed_event_bytes_by_kind": dict(widths),
            "success_job_bytes": success_job_bytes,
            "failed_window_bytes": success_job_bytes,
            "failed_event_count": sum(counts.values()),
            "failed_event_count_uplift": 0, "byte_uplift": 0,
        }
        phases = budget_producer.PHASES
        phase_totals = []
        for phase in phases:
            count = 1 if phase == "exploration" else 0
            event_count = sum(counts.values()) if count else 0
            phase_totals.append({
                "phase": phase, "job_count": count,
                "event_count": event_count,
                "success_event_bytes": success_job_bytes if count else 0,
            })
        fixed_identities = [
            ("source5_prepared_capacity_registered", "registration"),
            *(("source5_analysis", phase) for phase in (
                "exploration", "aa", "fixed_analysis", "pressure_analysis",
                "soak", "final_analysis",
            )),
        ]
        fixed_widths = [{
            "event": event, "phase": phase,
            "count": 1, "maximum_line_bytes": 1024,
        } for event, phase in fixed_identities]
        failed_owner_window = {
            "phase": row["phase"], "job_index": row["job_index"],
            "ordinal": row["ordinal"], "run_id": row["run_id"],
            "job_sha256": row["job_sha256"],
            "failed_event_count": row["failed_event_count"],
            "failed_event_count_uplift": row["failed_event_count_uplift"],
            "failed_window_bytes": row["failed_window_bytes"],
            "success_job_bytes": row["success_job_bytes"],
            "byte_uplift": row["byte_uplift"],
        }
        width_body = {
            "schema": packet.JOURNAL_WIDTH_CONTRACT_SCHEMA,
            "campaign_id": campaign_id, "host_id": host_id,
            "original_pins_sha256": sha(canonical({
                "plan": plan_pin, "source_manifest": source_pin,
            })),
            "plan_pin": plan_pin, "source_manifest_pin": source_pin,
            "owner_pins": {role: width_owner_pins[role]
                           for role in sorted(width_owner_pins)},
            "job_rows": [row], "phase_totals": phase_totals,
            "fixed_event_widths": fixed_widths,
            "total_event_count": 13,
            "total_event_bytes": 13 * 1024,
            "failed_owner_window": failed_owner_window,
        }
        width_contract = {
            **width_body,
            "contract_sha256": sha(canonical(width_body)),
        }
        width_raw = canonical(width_contract)
        width_path = (
            f"/private/artifacts/{campaign_id}/source5/{host_id}/"
            "prepared-input/journal-width-contract.json"
        )
        width_pin = {
            "path": width_path, "raw_sha256": sha(width_raw),
            "semantic_sha256": width_contract["contract_sha256"],
        }

        execution_body = {
            key: value for key, value in source_inputs["execution"].items()
            if key != "manifest_sha256"
        }
        execution_body.update({
            "schema": packet.EXECUTION_SCHEMA_V4,
            "scope": "final_prepared_bounded",
            "prepared_input_generation": {"completion": {}, "provenance": {}},
            "prepared_capacity_registration": {},
            "modules": {}, "observed_hosts": {},
            "artifact_root": "/private/artifacts",
            "output_root": "/private/output", "phase_order": [],
            "protocol_sha256": "3" * 64,
            "archive_signer_contexts": {},
            "journal_width_contracts": {},
        })
        for host in execution_body["hosts"]:
            execution_body["archive_signer_contexts"][host] = {
                "artifact": {
                    "path": f"/private/inputs/{host}-signer-context.json",
                    "raw_sha256": sha((host + "-signer-raw").encode()),
                },
                "semantic_sha256": sha((host + "-signer-semantic").encode()),
            }
            if host == host_id:
                execution_body["journal_width_contracts"][host] = {
                    "artifact": {"path": width_path,
                                 "raw_sha256": width_pin["raw_sha256"]},
                    "semantic_sha256": width_pin["semantic_sha256"],
                }
            else:
                execution_body["journal_width_contracts"][host] = {
                    "artifact": {
                        "path": f"/private/inputs/{host}-width-contract.json",
                        "raw_sha256": sha((host + "-width-raw").encode()),
                    },
                    "semantic_sha256": sha((host + "-width-semantic").encode()),
                }
        execution = budget_tests.sealed(execution_body, "manifest_sha256")
        execution_raw = canonical(execution)
        execution_pin = {
            "path": "/private/output/execution-manifest.json",
            "raw_sha256": sha(execution_raw),
            "semantic_sha256": execution["manifest_sha256"],
        }
        source_inputs["execution"] = execution
        source_inputs["pins"]["execution_manifest"] = execution_pin

        audit = budget_producer.build_host_evidence_budget_plan(
            source_inputs["spec"], source_inputs["plan"],
            source_inputs["sources"], execution, host_id,
            pins_value=source_inputs["pins"],
        )
        audit = copy.deepcopy(audit)
        audit["schedule"]["job_counts"] = {
            phase: (1 if phase == "exploration" else 0)
            for phase in phases
        }
        audit["schedule"]["fixed_job_count"] = 1
        audit["schedule"]["pressure_job_count"] = 0
        audit["schedule"]["total_job_count"] = 1
        audit["schedule"]["maximum_callback_events"] = 13
        audit["schedule"]["maximum_callback_event_bytes"] = 1024
        audit["schedule"]["worst_case_journal_bytes"] = 13 * 1024
        audit = budget_tests.sealed(
            {key: value for key, value in audit.items()
             if key != "budget_plan_sha256"}, "budget_plan_sha256",
        )
        source_digest = source_pin["semantic_sha256"]
        cleanup = budget_producer._cleanup_source_shape(
            budget_producer.SOURCE5_CLEANUP_SESSION_MEMBER_LIMIT,
        )
        owner_cleanup_fields = {
            "maximum_session_members_per_snapshot",
            "maximum_pidfd_signal_entries_per_snapshot",
            "maximum_signal_snapshots", "maximum_cleanup_errors",
            "maximum_error_text_bytes", "normal_cleanup_poll_count",
            "emergency_cleanup_poll_count", "term_grace_seconds",
            "kill_reap_seconds", "cleanup_poll_interval_seconds",
        }
        owner_contract = {
            "schema": "allocatbelt.application-source5-owner-evidence-catalogue.v1",
            "source_manifest_sha256": source_digest,
            "owner_source_pins": catalogue_owner_pins,
            "fixed_pair": {}, "pressure_pair": {}, "soak": {},
            "transport_caps": {"chronology": {
                "MAX_COMPLETION_BYTES": 16 * 1024 * 1024,
            }},
            "role_ceiling_conflicts": {},
            "exact_full_path_catalogue_complete": True,
            "execution_ready": False, "qualification_eligible": False,
            "cleanup_source_shape": {
                key: cleanup[key] for key in owner_cleanup_fields
            },
        }

        row_factory = budget_tests.Source5PathCatalogueTests.row

        def catalogue_row(
            path: str, role: str, maximum: int, storage_root: str, *,
            owner: str = "source5_controller", phase: str | None = "exploration",
            run: str | None = run_id, kind: str = "file",
            file_maximum: int | None = None, inodes: int = 1,
            member_index: int | None = None,
            origin_pin: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            value = row_factory(
                path, role=role, kind=kind, maximum=maximum,
                file_maximum=maximum if file_maximum is None else file_maximum,
                inodes=inodes,
            )
            value.update({
                "host_id": host_id, "storage_root": storage_root,
                "owner": owner, "phase": phase, "run_id": run,
                "member_index": member_index,
                "aggregate_id": None, "aggregate_max_bytes": None,
                "origin_pin": origin_pin,
            })
            return value

        output_root = "/private/output"
        artifact_root = "/private/artifacts"
        scratch_root = "/private/scratch"
        payload = b"archive readback fixture"
        payload_sha = sha(payload)
        object_path = (
            f"{artifact_root}/{campaign_id}/source5/{host_id}/exploration/"
            f"{job['ordinal']:06d}-{job_sha}/stdout.tsv"
        )
        record_path = (
            f"{output_root}/{campaign_id}/source5/{host_id}/exploration/"
            f"job-records/{job['ordinal']:06d}-{job_sha}.json"
        )
        record_sha = sha(b"synthetic canonical job record")
        record_pin = {"path": record_path, "raw_sha256": record_sha}
        core_rows = [
            catalogue_row(
                object_path, "fixed_pair_artifact", 4096, artifact_root,
                owner="fixed_pair", origin_pin={
                    "raw_sha256": payload_sha, "semantic_sha256": None,
                },
            ),
            catalogue_row(
                record_path, "source5_job_record", 128 * 1024, output_root,
                origin_pin={"raw_sha256": record_sha,
                            "semantic_sha256": record_sha},
            ),
        ]
        archive_caps = budget_producer.project_archive_job_caps(core_rows)[
            ("exploration", run_id)
        ]
        transport_specs = (
            ("source5_checkpoint_request", "checkpoint_request_bytes", output_root),
            ("source5_transfer_offer", "transfer_offer_bytes", output_root),
            ("source5_transfer_packet", "transfer_packet_bytes", scratch_root),
            ("source5_ack_bundle", "ack_bundle_bytes", output_root),
            ("source5_ack_bundle_incoming", "ack_bundle_bytes", output_root),
            ("source5_checkpoint", "checkpoint_bytes", output_root),
            ("source5_object_manifest", "object_manifest_bytes", output_root),
            ("source5_archive_ack", "archive_ack_bytes", output_root),
            ("source5_archive_signature", "signature_bytes", output_root),
            ("source5_stage_map", "stage_map_bytes", output_root),
        )
        transport_rows = [catalogue_row(
            f"{root}/evidence/{role}.json", role, archive_caps[field], root,
        ) for role, field, root in transport_specs]
        readback = budget_producer.project_archive_readback_caps(core_rows)[
            ("exploration", run_id)
        ]
        analyzer_projection = analysis_campaign.analyzer_scratch_projection(
            {
                "cells": [
                    {"family": family, "profile": profile}
                    for family, _workload, profile in
                    analysis_campaign.expected_profile_cells()
                ],
                "protocol": {
                    "confirmation_pairs": 36,
                    "bootstrap_block_arrivals": 1000,
                },
            },
            analysis_campaign.MAX_TRACE_ARTIFACT_BYTES,
        )
        readback_root = f"{scratch_root}/{campaign_id}/{host_id}/archive-readback"
        readback_rows = [
            catalogue_row(
                f"{output_root}/{campaign_id}/source5/{host_id}/"
                "archive-read-control.jsonl",
                budget_producer.SOURCE5_ARCHIVE_READ_CONTROL_ROLE,
                64 * 1024, output_root, phase=None, run=None,
            ),
            catalogue_row(f"{readback_root}/request.json",
                          "source5_archive_read_request_slot",
                          readback["maximum_request_bytes"], scratch_root,
                          phase=None, run=None),
            catalogue_row(f"{readback_root}/response.json",
                          "source5_archive_read_response_slot",
                          readback["maximum_response_bytes"], scratch_root,
                          phase=None, run=None),
            catalogue_row(f"{readback_root}/response.json.incoming",
                          "source5_archive_read_response_incoming",
                          readback["maximum_response_bytes"], scratch_root,
                          phase=None, run=None),
            catalogue_row(f"{readback_root}/response.tar",
                          "source5_archive_read_bundle",
                          readback["maximum_bundle_bytes"], scratch_root,
                          phase=None, run=None),
            catalogue_row(f"{readback_root}/response.tar.incoming",
                          "source5_archive_read_bundle_incoming",
                          readback["maximum_bundle_bytes"], scratch_root,
                          phase=None, run=None),
            catalogue_row(f"{readback_root}/stage",
                          "source5_archive_read_stage",
                          readback["maximum_stage_bytes"], scratch_root,
                          phase=None, run=None,
                          kind="tree",
                          file_maximum=readback["maximum_object_bytes"],
                          inodes=readback["maximum_stage_inodes"]),
            catalogue_row(
                f"{scratch_root}/{campaign_id}/{host_id}/analyzer-spool",
                packet.SOURCE5_ANALYZER_SPOOL_ROLE,
                analyzer_projection["maximum_bytes"], scratch_root,
                phase=None, run=None, kind="tree",
                file_maximum=analyzer_projection["maximum_file_bytes"],
                inodes=analyzer_projection["maximum_inodes"],
            ),
            catalogue_row(width_path, "journal_width_contract", len(width_raw),
                          artifact_root, phase=None, run=None,
                          origin_pin={"raw_sha256": width_pin["raw_sha256"],
                                      "semantic_sha256": width_pin["semantic_sha256"]}),
        ]
        sidecar_rows = []
        for member in (0, 1):
            sidecar_rows.extend([
                catalogue_row(
                    f"{output_root}/{campaign_id}/source5/{host_id}/exploration/"
                    f"cleanup-sidecars/{job['ordinal']:06d}-{job_sha}-member{member}.json",
                    "source5_cleanup_sidecar", cleanup["admission_maximum_bytes"],
                    output_root, owner="fixed_pair", member_index=member,
                ),
                catalogue_row(
                    f"{output_root}/{campaign_id}/source5/{host_id}/exploration/"
                    f"cleanup-sidecars/{job['ordinal']:06d}-{job_sha}-member{member}.json.refusal.json",
                    "source5_cleanup_sidecar_refusal",
                    cleanup["refusal_file_bytes"], output_root,
                    owner="fixed_pair", member_index=member,
                ),
            ])

        with tempfile.TemporaryDirectory(prefix="source5-h15-readback-budget-") as tmp:
            root = Path(tmp)
            catalogue_directory = root / "catalogue"
            catalogue_directory.mkdir(mode=0o700)
            os.chmod(catalogue_directory, 0o700)
            catalogue = budget_producer.write_path_catalogue_chunks(
                [*core_rows, *transport_rows, *readback_rows, *sidecar_rows],
                catalogue_directory,
            )
            roots = [
                {"path": artifact_root, "role": "artifact",
                 "reserved_bytes": budget_producer.MAX_U64,
                 "reserved_inodes": budget_producer.MAX_U64,
                 "filesystem_id": "1"},
                {"path": output_root, "role": "output",
                 "reserved_bytes": budget_producer.MAX_U64,
                 "reserved_inodes": budget_producer.MAX_U64,
                 "filesystem_id": "2"},
                {"path": scratch_root, "role": "scratch",
                 "reserved_bytes": budget_producer.MAX_U64,
                 "reserved_inodes": budget_producer.MAX_U64,
                 "filesystem_id": "3"},
                {"path": "/private/store", "role": "evidence_store",
                 "reserved_bytes": budget_producer.MAX_U64,
                 "reserved_inodes": budget_producer.MAX_U64,
                 "filesystem_id": "4"},
            ]
            reservation = budget_producer.build_storage_reservation_value(
                campaign_id, host_id, roots,
            )
            reservation_raw = canonical(reservation)
            reservation_pin = {
                "path": "/private/artifacts/storage-reservation.json",
                "raw_sha256": sha(reservation_raw),
                "semantic_sha256": reservation["reservation_sha256"],
                "byte_count": len(reservation_raw),
            }
            produced_budget = budget_producer.build_host_evidence_budget_v2(
                audit, owner_contract, catalogue, reservation,
                reservation_pin,
                journal_width_contract_value=width_contract,
                journal_width_contract_pin_value=width_pin,
                journal_width_contract_raw=width_raw,
            )
            checked_budget = budget_producer.validate_host_evidence_budget_v2(
                produced_budget, journal_width_contract_raw=width_raw,
            )
            self.assertEqual(checked_budget, produced_budget)
            self.assertEqual(produced_budget["readiness"], {
                "budget_complete": False, "execution_ready": False,
                "component_gate_ready": False,
                "qualification_eligible": False,
            })
            self.assertEqual(produced_budget["execution_blockers"], [
                "verified_between_pair_archive_ack_reclaim_not_integrated",
            ])
            self.assertIn(
                budget_producer.SOURCE5_ARCHIVE_READ_CONTROL_ROLE,
                produced_budget["path_catalogue"]["role_byte_bounds"],
            )
            all_catalogue_rows = list(budget_producer.iter_path_catalogue_rows(
                produced_budget["path_catalogue"],
            ))
            role_byte_sums: dict[str, int] = {}
            for catalogue_row_value in all_catalogue_rows:
                role = catalogue_row_value["role"]
                role_byte_sums[role] = (
                    role_byte_sums.get(role, 0) +
                    catalogue_row_value["max_bytes"]
                )
            readback_rows = [
                catalogue_row_value for catalogue_row_value in all_catalogue_rows
                if catalogue_row_value["role"] in packet.SOURCE5_ARCHIVE_READ_ROLES
            ]
            analyzer_rows = [
                catalogue_row_value for catalogue_row_value in all_catalogue_rows
                if catalogue_row_value["role"] ==
                    packet.SOURCE5_ANALYZER_SPOOL_ROLE
            ]
            self.assertEqual(len(analyzer_rows), 1)
            self.assertTrue(packet._validate_h15_archive_readback_profile(
                produced_budget, host_id, readback_rows, role_byte_sums,
                analyzer_rows,
            ))
            self.assertTrue(archive._validate_h15_archive_readback_profile(
                produced_budget, host_id, readback_rows, role_byte_sums,
                analyzer_rows,
            ))
            with self.assertRaisesRegex(
                    packet.TransferPacketError, "exactly one analyzer"):
                packet._validate_h15_archive_readback_profile(
                    produced_budget, host_id, readback_rows, role_byte_sums,
                )
            swapped_analyzer = copy.deepcopy(analyzer_rows)
            swapped_analyzer[0]["path"] = (
                f"{scratch_root}/{campaign_id}/{host_id}/wrong-spool"
            )
            with self.assertRaisesRegex(
                    packet.TransferPacketError, "path or role-byte projection"):
                packet._validate_h15_archive_readback_profile(
                    produced_budget, host_id, readback_rows, role_byte_sums,
                    swapped_analyzer,
                )
            malformed_catalogue = copy.deepcopy(
                produced_budget["path_catalogue"],
            )
            malformed_catalogue["role_byte_bounds"][
                "source5_archive_read_unreviewed"
            ] = 1
            with self.assertRaisesRegex(packet.TransferPacketError,
                                        "partial or unknown"):
                packet._has_h15_archive_readback_roles(malformed_catalogue)

            oversized_role = "source5_archive_read_request_slot"
            oversized = packet.MAX_ARCHIVE_READ_METADATA_BYTES + 1
            malformed_budget = copy.deepcopy(produced_budget)
            catalogue_body = {
                key: value for key, value in
                malformed_budget["path_catalogue"].items()
                if key != "semantic_sha256"
            }
            catalogue_body["role_byte_bounds"][oversized_role] = oversized
            malformed_budget["path_catalogue"] = {
                **catalogue_body,
                "semantic_sha256": sha(canonical(catalogue_body)),
            }
            malformed_rows = copy.deepcopy(readback_rows)
            request_row = next(item for item in malformed_rows
                               if item["role"] == oversized_role)
            request_row["max_bytes"] = oversized
            request_row["max_file_bytes"] = oversized
            malformed_sums = dict(role_byte_sums)
            malformed_sums[oversized_role] = oversized
            with self.assertRaisesRegex(packet.TransferPacketError,
                                        "parser ceiling"):
                packet._validate_h15_archive_readback_profile(
                    malformed_budget, host_id, malformed_rows, malformed_sums,
                    analyzer_rows,
                )
            with self.assertRaisesRegex(archive.EvidenceArchiveError,
                                        "parser ceiling"):
                archive._validate_h15_archive_readback_profile(
                    malformed_budget, host_id, malformed_rows, malformed_sums,
                    analyzer_rows,
                )

            budget_raw = canonical(produced_budget)
            context = {
                "campaign_id": campaign_id, "host_id": host_id,
                "plan_pin": plan_pin, "source_manifest_pin": source_pin,
                "execution_manifest_pin": execution_pin,
                "resource_budget_pin": {
                    "path": f"/private/artifacts/{campaign_id}/source5/{host_id}/"
                            "host-evidence-budget-v2.json",
                    "raw_sha256": sha(budget_raw),
                    "semantic_sha256": produced_budget["budget_sha256"],
                },
                "phase": "exploration", "job_index": 0,
            }
            self.assertTrue(archive._validate_host_budget_revision(
                produced_budget, context, execution_manifest_raw=execution_raw,
                journal_width_contract_raw=width_raw,
                require_v4_manifest=True,
            ))
            self.assertTrue(packet._validate_host_budget_revision(
                produced_budget, campaign_id, host_id, context=context,
                execution_manifest_raw=execution_raw,
                journal_width_contract_raw=width_raw,
                require_manifest_binding=True,
            ))

            cache_root = root / "root-local-cache"
            cache_root.mkdir(mode=0o700)
            os.chmod(cache_root, 0o700)
            captured_chunks = {}
            for descriptor in produced_budget["path_catalogue"]["chunks"]:
                origin = descriptor["path"]
                captured = cache_root / Path(origin).name
                shutil.copyfile(origin, captured)
                os.chmod(captured, 0o600)
                captured_chunks[origin] = str(captured)
            self.assertTrue(all(origin != local
                                for origin, local in captured_chunks.items()))
            catalogue_rows = packet._catalogue_rows_for_paths(
                produced_budget, {object_path}, host_id, "exploration", run_id,
                catalogue_chunk_paths=captured_chunks,
                catalogue_cache_root=str(cache_root),
            )
            self.assertEqual(catalogue_rows[object_path]["role"],
                             "fixed_pair_artifact")
            archive_entries = [{
                "origin_path": object_path, "role": "fixed_pair_artifact",
                "byte_count": len(payload), "raw_sha256": payload_sha,
                "semantic_sha256": None,
            }]
            archive._validate_host_budget_object_rows(
                budget_raw, context,
                {"run_id": run_id, "job_sha256": job_sha},
                archive_entries, record_pin, 128 * 1024, record_sha,
                captured_chunks, str(cache_root),
                execution_manifest_raw=execution_raw,
                journal_width_contract_raw=width_raw,
            )


class TypedTreeInventoryPacketTests(unittest.TestCase):
    def _sample(self):
        root = "/private/job/opaque-trace"
        directory = root + "/nested"
        child = directory + "/trace.bin"
        inventory_path = "/private/job/probe-capture-inventory.json"
        receipt_path = "/private/job/probe-capture-receipt.json"
        raw_child = b"probe bytes"
        entries = [
            {"path": directory, "kind": "directory", "uid": 1000,
             "mode": 0o700, "size": None, "raw_sha256": None},
            {"path": child, "kind": "file", "uid": 1000,
             "mode": 0o600, "size": len(raw_child),
             "raw_sha256": sha(raw_child)},
        ]
        inventory_body = {
            "schema": "allocatbelt.application-feedback-probe-tmpdir-inventory.v1",
            "entries": entries,
        }
        inventory_sha = sha(canonical(inventory_body))
        inventory_raw = canonical({**inventory_body,
                                   "inventory_sha256": inventory_sha})
        inventory_pin = {
            "path": inventory_path, "raw_sha256": sha(inventory_raw),
            "semantic_sha256": inventory_sha,
        }
        receipt_pin = {
            "path": receipt_path, "raw_sha256": "a" * 64,
            "semantic_sha256": "b" * 64,
        }
        owner_pins = {"probe_capture_receipt_member0": receipt_pin}
        rows = [
            {"origin_path": inventory_path,
             "role": "probe_capture_inventory_member0",
             "byte_count": len(inventory_raw),
             "raw_sha256": sha(inventory_raw),
             "semantic_sha256": inventory_sha},
            {"origin_path": receipt_path,
             "role": "probe_capture_receipt_member0",
             "byte_count": 1, "raw_sha256": receipt_pin["raw_sha256"],
             "semantic_sha256": receipt_pin["semantic_sha256"]},
            {"origin_path": child, "role": "opaque_trace",
             "byte_count": len(raw_child), "raw_sha256": sha(raw_child),
             "semantic_sha256": None},
        ]
        rows.sort(key=lambda item: item["origin_path"])
        tree = {
            "owner_job_sha256": "c" * 64, "root_path": root,
            "role": "opaque_trace", "owner_receipt_pin": receipt_pin,
            "inventory_pin": inventory_pin,
            "inventory_sha256": inventory_sha,
            "entry_count": len(entries), "byte_count": len(raw_child),
            "entries": entries,
        }
        return tree, rows, owner_pins

    def test_nested_directory_and_file_close_over_exact_rows(self) -> None:
        tree, rows, owner_pins = self._sample()
        checked, file_paths = packet._validate_tree_inventories(
            [tree], rows, owner_pins,
        )
        self.assertEqual(checked, [tree])
        self.assertEqual(file_paths, {tree["entries"][1]["path"]})

    def test_v2_request_accepts_only_its_exact_additive_field(self) -> None:
        tree, rows, owner_pins = self._sample()
        context = {
            "schema": "allocatbelt.application-source5-evidence-archive-context.v1",
            "campaign_id": "campaign-a", "host_id": "host-a",
            "phase": "soak", "job_index": 0,
            "source_manifest_pin": pin(Path("/inputs/source.json"), b"source"),
            "execution_manifest_pin": pin(Path("/inputs/execution.json"), b"execution"),
            "plan_pin": pin(Path("/inputs/plan.json"), b"plan"),
            "resource_budget_pin": pin(Path("/inputs/budget.json"), b"budget"),
            "predecessor_ack_pin": None,
            "authorized_signer_fingerprint": "A" * 40,
        }
        body = {
            "schema": packet.REQUEST_SCHEMA_V2, "context": context,
            "job_record_pin": {
                "path": "/source5/host-a/soak/job-records/run.json",
                "raw_sha256": "d" * 64,
            },
            "authorization": {
                "authorization_id": "authorization-1",
                "authorization_head": "e" * 64,
                "terminal_head": "f" * 64,
                "component_sha256": "1" * 64,
                "process_metrics_sha256": "2" * 64,
            },
            "predecessor_ack_pin": None,
            "owner_receipt_pins": owner_pins,
            "empty_tmp_proofs": [], "entries": rows,
            "tree_inventories": [tree],
        }
        request = {**body, "request_sha256": sha(canonical(body))}
        self.assertEqual(packet._validate_request(request), request)
        empty_body = {**body, "tree_inventories": []}
        empty_request = {**empty_body,
                         "request_sha256": sha(canonical(empty_body))}
        with self.assertRaisesRegex(packet.TransferPacketError,
                                    "at least one exact tree declaration"):
            packet._validate_request(empty_request)
        changed = {**request, "unreviewed": True}
        changed_body = {key: value for key, value in changed.items()
                        if key != "request_sha256"}
        changed["request_sha256"] = sha(canonical(changed_body))
        with self.assertRaisesRegex(packet.TransferPacketError,
                                    "unexpected field set"):
            packet._validate_request(changed)

    def test_nested_tree_roots_are_not_disjoint_catalogue_declarations(self) -> None:
        tree, rows, owner_pins = self._sample()
        nested = {**tree, "root_path": tree["root_path"] + "/nested"}
        with self.assertRaisesRegex(packet.TransferPacketError,
                                    "disjoint opaque-trace"):
            packet._validate_tree_inventories([tree, nested], rows, owner_pins)

    def test_declared_opaque_tree_cannot_be_omitted_from_request(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-tree-catalogue-") as tmp:
            root = Path(tmp)
            tree_path = str(root / "opaque-trace")
            row = {
                "path": tree_path, "kind": "tree", "role": "opaque_trace",
                "host_id": "host-a", "max_bytes": 4096,
                "max_file_bytes": 2048, "max_inodes": 33,
                "storage_root": str(root), "owner": "probe_capture",
                "phase": "soak", "run_id": "run-a", "member_index": 0,
                "aggregate_id": None, "aggregate_max_bytes": None,
                "origin_pin": None,
            }
            chunk_raw = canonical(row)
            chunk_path = root / "catalogue.jsonl"
            chunk_path.write_bytes(chunk_raw)
            os.chmod(chunk_path, 0o600)
            chunk_pin = sha(chunk_raw)
            catalogue_body = {
                "schema": "allocatbelt.application-source5-host-path-catalogue.v2",
                "chunks": [{
                    "path": str(chunk_path), "raw_sha256": chunk_pin,
                    "semantic_sha256": chunk_pin,
                    "byte_count": len(chunk_raw), "row_count": 1,
                    "first_path": tree_path, "last_path": tree_path,
                }],
                "entry_count": 1, "chunk_bytes": len(chunk_raw),
            }
            budget = {"path_catalogue": {
                **catalogue_body,
                "semantic_sha256": sha(canonical(catalogue_body)),
            }}
            with self.assertRaisesRegex(packet.TransferPacketError,
                                        "omit or add an opaque-trace"):
                packet._catalogue_rows_for_paths(
                    budget, set(), "host-a", "soak", "run-a",
                    tree_paths=set(), require_tree_closure=True,
                )
            rows = packet._catalogue_rows_for_paths(
                budget, {tree_path}, "host-a", "soak", "run-a",
                tree_paths={tree_path}, require_tree_closure=True,
            )
            self.assertEqual(rows[tree_path]["kind"], "tree")

    def test_probe_inventory_cannot_relabel_a_link_as_a_regular_file(self) -> None:
        tree, rows, owner_pins = self._sample()
        changed = copy.deepcopy(tree)
        changed["entries"][1]["kind"] = "symlink"
        changed["entries"][1]["size"] = len(b"probe bytes")
        changed["entries"][1]["raw_sha256"] = sha(b"probe bytes")
        with self.assertRaisesRegex(packet.TransferPacketError,
                                    "only regular files and directories"):
            packet._validate_tree_inventories([changed], rows, owner_pins)


class BudgetV3SourceSelectionTests(unittest.TestCase):
    def test_validator_module_is_loaded_from_the_selected_source_row(self) -> None:
        source, context, execution = selected_budget_source_fixture()
        namespace = packet._read_source_budget_module(
            canonical(source), context, canonical(execution),
        )
        self.assertTrue(callable(
            namespace["validate_host_evidence_budget_v3"],
        ))
        self.assertEqual(
            namespace["HOST_BUDGET_SCHEMA_V3"],
            "allocatbelt.application-source5-host-evidence-budget.v3",
        )

    def test_typed_source_size_is_checked_before_module_execution(self) -> None:
        source, context, execution = selected_budget_source_fixture()
        source["source"]["files"][0]["size"] += 1
        source["source"]["source_tree_sha256"] = sha(canonical({
            "schema": packet.SOURCE_INVENTORY_SCHEMA_V1,
            "entries": source["source"]["files"],
        }))
        source.pop("manifest_sha256")
        source["manifest_sha256"] = sha(canonical(source))
        source_raw = canonical(source)
        source_pin = context["source_manifest_pin"]
        source_pin.update({
            "raw_sha256": sha(source_raw),
            "semantic_sha256": source["manifest_sha256"],
        })
        wrapper = execution["original_inputs"]["source_manifests"]["host-a"]
        wrapper["artifact"]["raw_sha256"] = source_pin["raw_sha256"]
        wrapper["semantic_sha256"] = source_pin["semantic_sha256"]
        execution["execution_sources"]["host-a"]["source_tree_sha256"] = source["source"]["source_tree_sha256"]
        execution.pop("manifest_sha256")
        execution["manifest_sha256"] = sha(canonical(execution))
        execution_raw = canonical(execution)
        context["execution_manifest_pin"].update({
            "raw_sha256": sha(execution_raw),
            "semantic_sha256": execution["manifest_sha256"],
        })
        with self.assertRaisesRegex(
                packet.TransferPacketError,
                "mode/size differs from typed SourceV5"):
            packet._read_source_budget_module(
                source_raw, context, execution_raw,
            )

    def test_root_catalogue_reader_uses_the_captured_copy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-packet-row-io-") as tmp:
            root = Path(tmp)
            cache = private(root / "cache")
            captured = private(cache / "captured")
            local = captured / "chunk.jsonl"
            raw = b"pinned captured catalogue bytes\n"
            local.write_bytes(raw)
            os.chmod(local, 0o600)
            origin_dir = private(root / "origin")
            origin = origin_dir / "chunk.jsonl"
            origin.write_bytes(b"different origin bytes")
            os.chmod(origin, 0o600)
            digest = sha(raw)
            budget = {"path_catalogue": {"chunks": [{
                "path": str(origin), "raw_sha256": digest,
                "semantic_sha256": digest, "byte_count": len(raw),
                "row_count": 1, "first_path": "/x", "last_path": "/x",
            }]}}
            reader = packet._source_budget_catalogue_reader(
                budget, {str(origin): str(local)}, str(cache), root_local=True,
            )
            self.assertEqual(reader(str(origin), len(raw)), raw)



class BudgetSchemaFieldsetCorrelationTests(unittest.TestCase):
    @staticmethod
    def _reseal(budget):
        body = {key: value for key, value in budget.items()
                if key != "budget_sha256"}
        return {**body, "budget_sha256": sha(canonical(body))}

    @classmethod
    def _ready_v3(cls, budget):
        body = {key: value for key, value in budget.items()
                if key != "budget_sha256"}
        body.update({
            "schema": packet.HOST_BUDGET_SCHEMA_V3,
            "admission_profile": packet.HOST_BUDGET_V3_ADMISSION_PROFILE,
            "execution_blockers": [],
            "readiness": {
                "budget_complete": True, "execution_ready": True,
                "component_gate_ready": False,
                "qualification_eligible": False,
            },
        })
        return cls._reseal(body)

    @staticmethod
    def _context_for(context, budget):
        result = copy.deepcopy(context)
        raw = canonical(budget)
        result["resource_budget_pin"] = pin(
            Path("/private/inputs/host-budget.json"), raw,
            budget["budget_sha256"],
        )
        return result

    def test_budget_context_rejects_crossed_schema_fieldsets(self) -> None:
        fixture = HostBudgetR6SchemaTests.__new__(HostBudgetR6SchemaTests)
        legacy_context, legacy, *_ = fixture._fixture(width_bound=False)
        width_context, width, *_ = fixture._fixture(width_bound=True)
        v3 = self._ready_v3(width)
        crossed = [
            ("legacy fields with v3 schema", {
                **legacy, "schema": packet.HOST_BUDGET_SCHEMA_V3,
            }, legacy_context),
            ("width-v2 fields with v3 schema", {
                **width, "schema": packet.HOST_BUDGET_SCHEMA_V3,
            }, width_context),
            ("v3 fields with v2 schema", {
                **v3, "schema": packet.HOST_BUDGET_SCHEMA,
            }, width_context),
            ("v3 fields with wrong profile", {
                **v3, "admission_profile": "other_profile",
            }, width_context),
        ]
        for label, candidate, context in crossed:
            with self.subTest(label=label):
                candidate = self._reseal(candidate)
                bound_context = self._context_for(context, candidate)
                with self.assertRaisesRegex(
                        packet.TransferPacketError, "schema|profile"):
                    packet._validate_budget_context(candidate, bound_context)

    def test_legacy_v2_context_keeps_its_closed_false_ready_path(self) -> None:
        fixture = HostBudgetR6SchemaTests.__new__(HostBudgetR6SchemaTests)
        context, legacy, *_ = fixture._fixture(width_bound=False)
        bound_context = self._context_for(context, legacy)
        parsed, width_bound = packet._exact_host_budget(legacy, "legacy budget")
        self.assertFalse(width_bound)
        self.assertFalse(parsed["readiness"]["execution_ready"])
        packet._validate_budget_context(legacy, bound_context)

    def test_v3_context_requires_captured_source_and_width_dependencies(self) -> None:
        fixture = HostBudgetR6SchemaTests.__new__(HostBudgetR6SchemaTests)
        context, width, *_ = fixture._fixture(width_bound=True)
        v3 = self._ready_v3(width)
        bound_context = self._context_for(context, v3)
        parsed, width_bound = packet._exact_host_budget(v3, "v3 budget")
        self.assertTrue(width_bound)
        self.assertEqual(parsed["admission_profile"],
                         packet.HOST_BUDGET_V3_ADMISSION_PROFILE)
        with self.assertRaisesRegex(
                packet.TransferPacketError, "requires its raw-pinned execution manifest"):
            packet._validate_budget_context(v3, bound_context)


class LegacyPacketImportContextRegressionTests(unittest.TestCase):
    def test_legacy_packet_import_keeps_context_distinct_from_budget(self) -> None:
        if not hasattr(PacketRoundTripTests, "source_inputs"):
            PacketRoundTripTests.setUpClass()
        helper = PacketRoundTripTests.__new__(PacketRoundTripTests)
        with tempfile.TemporaryDirectory(prefix="source5-legacy-import-context-") as tmp:
            root = Path(tmp)
            fixture = helper._fixture(root)
            packet_pin, offer, offer_pin = helper._offer(fixture)
            catalogue_map, catalogue_cache = helper._capture_catalogue_map(
                fixture, root, remove_origins=True,
            )
            staging = private(root / "packet-stage")
            imported = packet.import_transfer_packet(
                fixture["packet_path"], fixture["budget_raw"],
                fixture["budget_pin"], canonical(offer), offer_pin,
                staging, catalogue_map, catalogue_cache,
            )
            self.assertEqual(imported["packet_raw_sha256"],
                             packet_pin["raw_sha256"])
            self.assertEqual(imported["request"], fixture["request"])
            self.assertEqual(Path(imported["job_record_path"]).read_bytes(),
                             fixture["job_raw"])
            for row in fixture["rows"]:
                staged = Path(imported["staged_files"][row["origin_path"]])
                self.assertEqual(staged.stat().st_mode & 0o777, 0o600)
                if row["role"] == "normal_app_output":
                    self.assertEqual(staged.read_bytes(),
                                     fixture["payload_raw"] if row["origin_path"] ==
                                     str(fixture["payload"]) else fixture["link_raw"])

class PreparatoryTypedConsumerSelectionTests(unittest.TestCase):
    """Keep the new 360-job profile distinct and Source-selected."""

    def _fixture(self, root: Path):
        prep_path = "scripts/application-source5-preparatory-budget.py"
        source_paths = [
            archive.SOURCE5_BUDGET_VALIDATOR_PATH,
            archive.PREPARATORY_OWNER_CATALOGUE_PATH,
            archive.PREPARATORY_BUDGET_VALIDATOR_PATH,
            archive.PREPARATORY_CAMPAIGN_SOURCE_PATH,
            archive.PREPARATORY_INPUT_PREPARATION_SOURCE_PATH,
            "scripts/application-source5-evidence-archive.py",
            "scripts/application-source5-evidence-transfer-packet.py",
        ]
        files = []
        module_pins = {}
        for relative in source_paths:
            source_path = SCRIPT_DIR / Path(relative).name
            raw = source_path.read_bytes()
            destination = root / relative
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            destination.write_bytes(raw)
            destination.chmod(0o644)
            info = destination.stat(follow_symlinks=False)
            mode = f"{stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode):06o}"
            digest = sha(raw)
            files.append({
                "path": relative, "kind": "file", "mode": mode,
                "sha256": digest, "size": len(raw),
            })
            module_pins[relative] = {"path": relative, "sha256": digest}
        files.sort(key=lambda row: row["path"])
        source_body = {
            "git_commit": "a" * 40,
            "source_tree_sha256": sha(canonical({
                "schema": archive.SOURCE_INVENTORY_SCHEMA_V1,
                "entries": files,
            })),
            "files": files,
        }
        source_manifest = {
            "schema": archive.SOURCE_MANIFEST_SCHEMA_V5,
            "source": source_body,
            "build": {"build_sha256": "b" * 64},
        }
        source_manifest["manifest_sha256"] = sha(canonical(source_manifest))
        source_raw = canonical(source_manifest)
        host = "host-a"
        hosts = [host, "host-b", "host-c"]
        source_pin = {
            "path": "/inputs/host-a-source.json",
            "raw_sha256": sha(source_raw),
            "semantic_sha256": source_manifest["manifest_sha256"],
        }
        source_wrappers = {
            selected: {
                "artifact": {
                    "path": source_pin["path"] if selected == host else
                        f"/inputs/{selected}-source.json",
                    "raw_sha256": source_pin["raw_sha256"] if selected == host else
                        ("c" if selected == "host-b" else "d") * 64,
                },
                "semantic_sha256": source_pin["semantic_sha256"] if selected == host else
                    ("e" if selected == "host-b" else "f") * 64,
            }
            for selected in hosts
        }
        spec_pin = {
            "path": "/inputs/initial-spec.json", "raw_sha256": "1" * 64,
        }
        plan_pin = {
            "path": "/inputs/initial-plan.json", "raw_sha256": "2" * 64,
        }
        initial_spec = {
            "artifact": spec_pin, "semantic_sha256": "3" * 64,
        }
        initial_plan = {
            "artifact": plan_pin, "semantic_sha256": "4" * 64,
        }
        signer_wrapper = {
            "artifact": {
                "path": "/private/host-a-archive-signer.json",
                "raw_sha256": "5" * 64,
            },
            "semantic_sha256": "6" * 64,
        }
        generation = {
            "completion": {
                "path": "/inputs/prepared-generation.json",
                "raw_sha256": "7" * 64, "semantic_sha256": "8" * 64,
            },
            "provenance": {
                "schema": "allocatbelt.application-source5-preparatory-capacity-provenance.v1",
                "preparation_pin": {
                    "path": "/inputs/preparation.json", "raw_sha256": "9" * 64,
                },
                "initial_spec_pin": spec_pin,
                "initial_plan_pin": plan_pin,
            },
        }
        registration = {
            "completion": generation["completion"],
            "host_completion": {
                "path": "/inputs/capacity-host.json",
                "raw_sha256": "a" * 64, "semantic_sha256": "b" * 64,
            },
            "host_verification": {
                "path": "/inputs/capacity-host-receipt.json",
                "raw_sha256": "c" * 64, "receipt_sha256": "d" * 64,
            },
            "ledger": {
                "path": "/output/capacity.jsonl", "raw_sha256": "e" * 64,
                "terminal_head": "f" * 64,
            },
            "capacity_schedule_sha256": "1" * 64,
            "registration_head": "2" * 64,
        }
        execution_sources = {
            selected: {
                "source_root": f"/source/{selected}",
                "git_commit": source_body["git_commit"] if selected == host else
                    ("1" if selected == "host-b" else "2") * 40,
                "source_tree_sha256": source_body["source_tree_sha256"] if selected == host else
                    ("3" if selected == "host-b" else "4") * 64,
                "build_sha256": sha(canonical(source_manifest["build"])) if selected == host else
                    ("5" if selected == "host-b" else "6") * 64,
            }
            for selected in hosts
        }
        observed_hosts = {
            selected: {
                "artifact": {
                    "path": f"/inputs/{selected}-observed.json",
                    "raw_sha256": ("7" if selected == host else
                                   "8" if selected == "host-b" else "9") * 64,
                },
                "semantic_sha256": ("a" if selected == host else
                                    "b" if selected == "host-b" else "c") * 64,
            }
            for selected in hosts
        }
        budget_path = (
            "/artifact/campaign-prep/source5/host-a/evidence-budget/"
            "host-evidence-budget-preparatory-v1.json"
        )
        width_path = (
            "/artifact/campaign-prep/source5/host-a/evidence-budget/"
            "preparatory-journal-width-v1.json"
        )
        core = {
            "schema": archive.PREPARATORY_EXECUTION_SCHEMA_V1,
            "campaign_id": "campaign-prep", "host_id": host,
            "hosts": hosts,
            "original_inputs": {
                "spec": initial_spec, "plan": initial_plan,
                "source_manifests": source_wrappers,
                "campaign_artifacts_root": "/artifact/campaign-prep",
            },
            "execution_sources": execution_sources,
            "modules": {selected: module_pins for selected in hosts},
            "observed_hosts": observed_hosts,
            "artifact_root": "/artifact", "output_root": "/output",
            "scope": "preparatory_exploration",
            "phase_order": ["exploration"],
            "protocol_sha256": "d" * 64,
            "preparatory_capacity_generation": generation,
            "preparatory_capacity_registration": registration,
            "archive_signer_contexts": {host: signer_wrapper},
            "qualification_eligible": False,
        }
        prep_spec = importlib.util.spec_from_file_location(
            "source5_prep_budget_consumer_fixture",
            root / prep_path,
        )
        self.assertIsNotNone(prep_spec)
        self.assertIsNotNone(prep_spec.loader)
        prep = importlib.util.module_from_spec(prep_spec)
        prep_spec.loader.exec_module(prep)
        body = {
            **core,
            "preparatory_journal_width_contracts": {host: {
                "artifact": {"path": width_path, "raw_sha256": "8" * 64},
                "semantic_sha256": "9" * 64,
            }},
            "preparatory_host_budgets": {host: {
                "artifact": {"path": budget_path, "raw_sha256": "a" * 64},
                "semantic_sha256": "b" * 64,
            }},
        }
        body["preparatory_execution_basis_sha256"] = \
            prep.build_execution_basis(core)
        execution = prep.seal_execution_manifest(body)
        execution_raw = canonical(execution)
        context = {
            "schema": archive.CONTEXT_SCHEMA_V1,
            "campaign_id": "campaign-prep", "host_id": host,
            "phase": "exploration", "job_index": 0,
            "source_manifest_pin": source_pin,
            "execution_manifest_pin": {
                "path": "/inputs/preparatory-execution.json",
                "raw_sha256": sha(execution_raw),
                "semantic_sha256": execution["manifest_sha256"],
            },
            "plan_pin": {
                **plan_pin, "semantic_sha256": initial_plan["semantic_sha256"],
            },
            "resource_budget_pin": {
                "path": budget_path, "raw_sha256": "a" * 64,
                "semantic_sha256": "b" * 64,
            },
            "predecessor_ack_pin": None,
            "authorized_signer_fingerprint": "A" * 40,
        }
        return prep, source_raw, source_pin, execution_raw, context, module_pins

    def test_preparatory_source_and_archive_validators_load_only_typed_modules(self):
        with tempfile.TemporaryDirectory(prefix="prep-typed-module-consumer-") as tmp:
            root = Path(tmp)
            scripts_root = root / "scripts"
            scripts_root.mkdir(mode=0o700)
            prep, source_raw, _source_pin, execution_raw, context, pins = \
                self._fixture(root)
            with mock.patch.object(
                    archive, "__file__",
                    str(scripts_root / "application-source5-evidence-archive.py")), \
                 mock.patch.object(
                    packet, "__file__",
                    str(scripts_root / "application-source5-evidence-transfer-packet.py")):
                namespace, _source, _execution = archive._read_source_typed_module(
                    source_raw, execution_raw, context,
                    archive.PREPARATORY_BUDGET_VALIDATOR_PATH,
                    archive.PREPARATORY_EXECUTION_SCHEMA_V1,
                    namespace_name="test_selected_prep_budget_module",
                )
                self.assertEqual(
                    namespace["PREPARATORY_BUDGET_SCHEMA"],
                    archive.PREPARATORY_BUDGET_SCHEMA_V1,
                )
                original_pins = archive._preparatory_original_pins(
                    json.loads(execution_raw),
                )
                _budget_namespace, selected_budget, owner_catalogue = \
                    archive._load_preparatory_catalogue_modules(
                        source_raw, execution_raw, context, original_pins,
                    )
                selected_campaign, selected_input_preparation = \
                    archive._load_preparatory_capacity_modules(
                        source_raw, execution_raw, context, original_pins,
                    )
                self.assertEqual(
                    owner_catalogue.__source5_typed_pin__,
                    original_pins["typed_modules"][
                        archive.PREPARATORY_OWNER_CATALOGUE_PATH
                    ],
                )
                self.assertEqual(
                    set(owner_catalogue.OWNER_PATHS),
                    {
                        "fixed_pair", "pressure_pair", "source5_controller",
                        "source5_soak", "soak_reader", "offline_dispatcher",
                        "chronology", "evidence_transport",
                    },
                )
                self.assertEqual(
                    selected_budget.__source5_typed_pin__,
                    original_pins["typed_modules"][
                        archive.SOURCE5_BUDGET_VALIDATOR_PATH
                    ],
                )
                self.assertEqual(
                    selected_campaign.__source5_typed_pin__,
                    original_pins["typed_modules"][
                        archive.PREPARATORY_CAMPAIGN_SOURCE_PATH
                    ],
                )
                self.assertEqual(
                    selected_input_preparation.__source5_typed_pin__,
                    original_pins["typed_modules"][
                        archive.PREPARATORY_INPUT_PREPARATION_SOURCE_PATH
                    ],
                )
                self.assertIn(
                    "owner_catalogue_module",
                    inspect.signature(
                        namespace["validate_host_evidence_budget_v1"],
                    ).parameters,
                )
                self.assertTrue({
                    "campaign_module", "input_preparation_module", "spec_raw",
                }.issubset(inspect.signature(
                    namespace["validate_host_evidence_budget_v1"],
                ).parameters))
                selected_archive = packet._read_source_archive_preparatory_validator(
                    source_raw, execution_raw, context,
                )
                self.assertTrue(callable(
                    selected_archive["validate_preparatory_budget_profile_v1"],
                ))

                bad_context = copy.deepcopy(context)
                bad_manifest = json.loads(execution_raw)
                bad_manifest["modules"][context["host_id"]][
                    archive.PREPARATORY_BUDGET_VALIDATOR_PATH
                ]["sha256"] = "0" * 64
                bad_body = {key: value for key, value in bad_manifest.items()
                            if key != "manifest_sha256"}
                bad_manifest["preparatory_execution_basis_sha256"] = \
                    prep.build_execution_basis(bad_body)
                bad_manifest = prep.seal_execution_manifest({
                    key: value for key, value in bad_manifest.items()
                    if key != "manifest_sha256"
                })
                bad_raw = canonical(bad_manifest)
                bad_context["execution_manifest_pin"] = {
                    "path": context["execution_manifest_pin"]["path"],
                    "raw_sha256": sha(bad_raw),
                    "semantic_sha256": bad_manifest["manifest_sha256"],
                }
                with self.assertRaisesRegex(
                        archive.EvidenceArchiveError,
                        "typed module differs from the execution-manifest module pin"):
                    archive._read_source_typed_module(
                        source_raw, bad_raw, bad_context,
                        archive.PREPARATORY_BUDGET_VALIDATOR_PATH,
                        archive.PREPARATORY_EXECUTION_SCHEMA_V1,
                        namespace_name="test_rejected_prep_budget_module",
                    )

                bad_owner_manifest = json.loads(execution_raw)
                bad_owner_manifest["modules"][context["host_id"]][
                    archive.PREPARATORY_OWNER_CATALOGUE_PATH
                ]["sha256"] = "1" * 64
                bad_owner_body = {
                    key: value for key, value in bad_owner_manifest.items()
                    if key != "manifest_sha256"
                }
                bad_owner_manifest["preparatory_execution_basis_sha256"] = \
                    prep.build_execution_basis(bad_owner_body)
                bad_owner_manifest = prep.seal_execution_manifest({
                    key: value for key, value in bad_owner_manifest.items()
                    if key != "manifest_sha256"
                })
                bad_owner_raw = canonical(bad_owner_manifest)
                bad_owner_context = copy.deepcopy(context)
                bad_owner_context["execution_manifest_pin"] = {
                    "path": context["execution_manifest_pin"]["path"],
                    "raw_sha256": sha(bad_owner_raw),
                    "semantic_sha256": bad_owner_manifest["manifest_sha256"],
                }
                with self.assertRaisesRegex(
                        archive.EvidenceArchiveError,
                        "typed module differs from the execution-manifest module pin"):
                    archive._load_preparatory_catalogue_modules(
                        source_raw, bad_owner_raw, bad_owner_context,
                        archive._preparatory_original_pins(bad_owner_manifest),
                    )

    def test_prep_schema_does_not_alias_final_v2_or_v3_budget_readers(self):
        body = {"schema": archive.PREPARATORY_BUDGET_SCHEMA_V1}
        with self.assertRaises(packet.TransferPacketError):
            packet._exact_host_budget(body, "prep budget is not final v2/v3")
        with self.assertRaises(archive.EvidenceArchiveError):
            archive._parse_host_budget_value(
                canonical(body), "prep budget is not final v2/v3",
            )


class PreparatoryBudgetCanonicalCeilingTests(unittest.TestCase):
    def test_self_hash_uses_128_mib_only_for_prep_schema(self):
        payload = "x" * 160
        prep_body = {
            "schema": archive.PREPARATORY_BUDGET_SCHEMA_V1,
            "payload": payload,
        }
        final_body = {
            "schema": archive.HOST_BUDGET_SCHEMA_V2,
            "payload": payload,
        }
        with mock.patch.object(archive, "MAX_JSON_BYTES", 128), \
             mock.patch.object(archive, "PREPARATORY_MAX_BUDGET_BYTES", 512), \
             mock.patch.object(packet, "MAX_JSON_BYTES", 128), \
             mock.patch.object(packet, "PREPARATORY_MAX_BUDGET_BYTES", 512):
            prep_size = len(archive._canonical(prep_body, maximum_bytes=512))
            self.assertGreater(prep_size, archive.MAX_JSON_BYTES)
            expected = sha(archive._canonical(prep_body, maximum_bytes=512))
            prep_value = {**prep_body, "budget_sha256": expected}
            self.assertEqual(
                archive._budget_body_semantic_sha256(prep_value), expected,
            )
            self.assertEqual(
                packet._budget_body_semantic_sha256(prep_value), expected,
            )
            with self.assertRaises(archive.EvidenceArchiveError):
                archive._budget_body_semantic_sha256(final_body)
            with self.assertRaises(packet.TransferPacketError):
                packet._budget_body_semantic_sha256(final_body)


class PreparatorySixDependencyMapTests(unittest.TestCase):
    """Prep adds one cached Spec pin while legacy/final map widths stay closed."""

    def _fixture(self, root: Path, *, change_execution_spec: bool = False):
        cache = root / "dependency-cache"
        cache.mkdir(mode=0o700)
        campaign_id, host_id = "prep-campaign", "host-a"
        spec_pin_path = "/input/original-spec.json"
        spec_raw = canonical({
            "schema": "allocatbelt.application-campaign-spec.v3",
            "campaign_id": campaign_id,
            "rates": [], "oracles": [],
        })
        spec_pin = {
            "path": spec_pin_path, "raw_sha256": sha(spec_raw),
            "semantic_sha256": "1" * 64,
        }
        source_raw = canonical({"source": "captured"})
        plan_raw = canonical({"plan": "captured"})
        width_raw = canonical({"width": "captured"})
        paths = {
            "source": "/input/source-v5.json",
            "plan": "/input/plan-v3.json",
            "budget": "/input/host-budget.json",
            "execution": "/input/execution.json",
            "width": "/input/journal-width.json",
            "spec": spec_pin_path,
        }
        source_pin = {
            "path": paths["source"], "raw_sha256": sha(source_raw),
            "semantic_sha256": "2" * 64,
        }
        plan_pin = {
            "path": paths["plan"], "raw_sha256": sha(plan_raw),
            "semantic_sha256": "3" * 64,
        }
        width_pin = {
            "path": paths["width"], "raw_sha256": sha(width_raw),
            "semantic_sha256": "4" * 64,
        }
        execution_spec_pin = dict(spec_pin)
        if change_execution_spec:
            execution_spec_pin["semantic_sha256"] = "5" * 64
        execution = {
            "original_inputs": {
                "spec": {
                    "artifact": {
                        "path": execution_spec_pin["path"],
                        "raw_sha256": execution_spec_pin["raw_sha256"],
                    },
                    "semantic_sha256": execution_spec_pin["semantic_sha256"],
                },
                "plan": {"artifact": {
                    "path": plan_pin["path"],
                    "raw_sha256": plan_pin["raw_sha256"],
                }, "semantic_sha256": plan_pin["semantic_sha256"]},
                "source_manifests": {},
                "campaign_artifacts_root": "/artifact/prep-campaign",
            },
        }
        execution_raw = canonical(execution)
        execution_pin = {
            "path": paths["execution"], "raw_sha256": sha(execution_raw),
            "semantic_sha256": "6" * 64,
        }
        budget_body = {
            "schema": archive.PREPARATORY_BUDGET_SCHEMA_V1,
            "campaign_id": campaign_id, "host_id": host_id,
            "profile": archive.PREPARATORY_PROFILE_V1,
            "execution_basis_sha256": "7" * 64,
            "original_pins": {"initial_spec": spec_pin},
            "owner_contract": {}, "schedule": {}, "read_schedule": [],
            "journal_width_contract_pin": width_pin,
            "path_catalogue": {}, "archive_transport": {},
            "retention_policy": {}, "storage_reservation": {},
            "readiness": {}, "budget_sha256": "",
        }
        budget_body["budget_sha256"] = sha(canonical({
            key: value for key, value in budget_body.items()
            if key != "budget_sha256"
        }))
        budget_raw = canonical(budget_body)
        budget_pin = {
            "path": paths["budget"], "raw_sha256": sha(budget_raw),
            "semantic_sha256": budget_body["budget_sha256"],
        }
        context = {
            "schema": archive.CONTEXT_SCHEMA_V1,
            "campaign_id": campaign_id, "host_id": host_id,
            "phase": "exploration", "job_index": 0,
            "source_manifest_pin": source_pin,
            "plan_pin": plan_pin,
            "execution_manifest_pin": execution_pin,
            "resource_budget_pin": budget_pin,
            "predecessor_ack_pin": None,
            "authorized_signer_fingerprint": "A" * 40,
        }
        raw_by_kind = {
            "source": source_raw, "plan": plan_raw,
            "budget": budget_raw, "execution": execution_raw,
            "width": width_raw, "spec": spec_raw,
        }
        pin_by_kind = {
            "source": source_pin, "plan": plan_pin,
            "budget": budget_pin, "execution": execution_pin,
            "width": width_pin, "spec": spec_pin,
        }
        local_paths = {}
        entries = []
        for index, kind in enumerate((
                "source", "plan", "budget", "execution", "width", "spec")):
            local = cache / f"dependency-{index}.json"
            fd = os.open(local, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(raw_by_kind[kind])
                    stream.flush()
                    os.fsync(fd)
            finally:
                os.close(fd)
            local_paths[paths[kind]] = str(local)
            entries.append({"origin_pin": pin_by_kind[kind],
                            "local_path": str(local)})
        map_body = {"schema": archive.DEPENDENCY_LOCAL_MAP_SCHEMA_V1,
                    "campaign_id": campaign_id, "host_id": host_id,
                    "entries": entries}
        map_value = {**map_body,
                     "map_sha256": sha(canonical(map_body))}
        return {
            "cache": cache, "context": context, "budget": budget_body,
            "budget_raw": budget_raw, "budget_pin": budget_pin,
            "source_raw": source_raw, "plan_raw": plan_raw,
            "execution_raw": execution_raw, "width_raw": width_raw,
            "spec_raw": spec_raw, "spec_pin": spec_pin,
            "local_paths": local_paths,
            "dependency_pins": {
                path: _pin for path, _pin in zip(
                    [pin_by_kind[kind]["path"] for kind in (
                        "source", "plan", "budget", "execution", "width", "spec")],
                    [pin_by_kind[kind] for kind in (
                        "source", "plan", "budget", "execution", "width", "spec")],
                        strict=True,
                    )
            },
            "map_raw": canonical(map_value), "map_value": map_value,
        }

    def test_sixth_spec_copy_is_raw_pinned_and_source_manifest_remains_unmapped(self):
        with tempfile.TemporaryDirectory(prefix="prep-six-dependency-map-") as tmp:
            fixture = self._fixture(Path(tmp))
            paths, pins = archive._parse_dependency_local_map_details(
                fixture["map_raw"], fixture["context"],
            )
            self.assertEqual(len(paths), 6)
            self.assertEqual(paths[fixture["spec_pin"]["path"]],
                             fixture["local_paths"][fixture["spec_pin"]["path"]])
            source_raw, execution_raw, width_raw = archive._validate_local_dependencies(
                paths, str(fixture["cache"]), fixture["context"],
                fixture["plan_raw"], fixture["budget_raw"], pins,
            )
            self.assertEqual(source_raw, fixture["source_raw"])
            self.assertEqual(execution_raw, fixture["execution_raw"])
            self.assertEqual(width_raw, fixture["width_raw"])
            self.assertEqual(
                archive._read_root_preparatory_spec(
                    paths, str(fixture["cache"]), fixture["budget_raw"],
                ),
                fixture["spec_raw"],
            )
            _context, packet_source, packet_plan, packet_exec, packet_width, packet_spec = \
                packet._read_root_preparatory_dependencies(
                    fixture["budget"], fixture["budget_raw"],
                    fixture["budget_pin"], fixture["context"],
                    fixture["map_raw"], str(fixture["cache"]),
                )
            self.assertEqual((packet_source, packet_plan, packet_exec,
                              packet_width, packet_spec),
                             (fixture["source_raw"], fixture["plan_raw"],
                              fixture["execution_raw"], fixture["width_raw"],
                              fixture["spec_raw"]))

    def test_prep_root_readers_reject_legacy_five_row_map(self):
        with tempfile.TemporaryDirectory(prefix="prep-five-row-rejected-") as tmp:
            fixture = self._fixture(Path(tmp))
            body = dict(fixture["map_value"])
            entries = list(body["entries"][:5])
            map_body = {"schema": body["schema"],
                        "campaign_id": body["campaign_id"],
                        "host_id": body["host_id"], "entries": entries}
            legacy_five = canonical({**map_body,
                                     "map_sha256": sha(canonical(map_body))})
            paths, pins = archive._parse_dependency_local_map_details(
                legacy_five, fixture["context"],
            )
            with self.assertRaises(archive.EvidenceArchiveError):
                archive._validate_local_dependencies(
                    paths, str(fixture["cache"]), fixture["context"],
                    fixture["plan_raw"], fixture["budget_raw"], pins,
                )
            with self.assertRaises(packet.TransferPacketError):
                packet._read_root_preparatory_dependencies(
                    fixture["budget"], fixture["budget_raw"],
                    fixture["budget_pin"], fixture["context"],
                    legacy_five, str(fixture["cache"]),
                )

    def test_prep_root_readers_reject_swapped_width_and_spec_rows(self):
        with tempfile.TemporaryDirectory(prefix="prep-six-order-rejected-") as tmp:
            fixture = self._fixture(Path(tmp))
            body = dict(fixture["map_value"])
            entries = list(body["entries"])
            entries[4], entries[5] = entries[5], entries[4]
            map_body = {"schema": body["schema"],
                        "campaign_id": body["campaign_id"],
                        "host_id": body["host_id"], "entries": entries}
            swapped = canonical({**map_body,
                                 "map_sha256": sha(canonical(map_body))})
            paths, pins = archive._parse_dependency_local_map_details(
                swapped, fixture["context"],
            )
            with self.assertRaises(archive.EvidenceArchiveError):
                archive._validate_local_dependencies(
                    paths, str(fixture["cache"]), fixture["context"],
                    fixture["plan_raw"], fixture["budget_raw"], pins,
                )
            with self.assertRaises(packet.TransferPacketError):
                packet._read_root_preparatory_dependencies(
                    fixture["budget"], fixture["budget_raw"],
                    fixture["budget_pin"], fixture["context"],
                    swapped, str(fixture["cache"]),
                )

    def test_packet_rejects_spec_dependency_not_matching_execution_original(self):
        with tempfile.TemporaryDirectory(prefix="prep-spec-crosslink-reject-") as tmp:
            fixture = self._fixture(Path(tmp), change_execution_spec=True)
            with self.assertRaisesRegex(
                    packet.TransferPacketError,
                    "sixth Root prep dependency does not match both original Spec pin sets"):
                packet._read_root_preparatory_dependencies(
                    fixture["budget"], fixture["budget_raw"],
                    fixture["budget_pin"], fixture["context"],
                    fixture["map_raw"], str(fixture["cache"]),
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
