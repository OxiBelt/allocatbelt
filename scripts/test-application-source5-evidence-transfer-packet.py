#!/usr/bin/env python3
"""No-link bounded Source5 request, packet, offer, and ACK-bundle witnesses."""
from __future__ import annotations

import copy
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
from unittest import mock


SCRIPT_DIR = Path(__file__).resolve().parent
ARCHIVE_PATH = SCRIPT_DIR / "application-source5-evidence-archive.py"
PACKET_PATH = SCRIPT_DIR / "application-source5-evidence-transfer-packet.py"
BUDGET_TEST_PATH = SCRIPT_DIR / "test-application-source5-evidence-budget.py"


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
                packet.publish_ack_bundle(
                    fixture["incoming_path"], fixture["budget_raw"],
                    fixture["budget_pin"], canonical(offer), offer_pin,
                    host_bundle_pin,
                )
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
