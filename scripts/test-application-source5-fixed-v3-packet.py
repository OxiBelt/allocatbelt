#!/usr/bin/env python3
"""Structural V3 wire witnesses; no APP or signature qualification claim."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


path = Path(__file__).with_name("application-source5-evidence-transfer-packet.py")
spec = importlib.util.spec_from_file_location("fixed_v3_packet", path)
packet = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = packet
spec.loader.exec_module(packet)


def pin(path):
    return {"path": path, "raw_sha256": "a" * 64,
            "semantic_sha256": "b" * 64}


def request_fixture():
    owners = {role: pin("/component/" + role + ".json") for role in
              ("component_receipt", "fixed_pair_host_receipt")}
    proofs = []
    for ordinal in (0, 1):
        for domain in ("", "probe_tmpdir"):
            proof = {
                "role": "component_receipt", "path": f"/tmp/component-{ordinal}-{domain}",
                "owner_receipt_pin": owners["component_receipt"],
                "member_ordinal": ordinal, "device": 1, "inode": 20 + len(proofs),
                "mode": 0o700, "bytes_used": 0, "file_count": 0,
                "directory_count": 0, "bytes_limit": 1024, "inode_limit": 16,
                "mount": {"mount_id": 1, "major_minor": "0:1", "mount_root": "/",
                          "mount_point": "/", "filesystem_type": "ext4",
                          "mount_source": "component", "device": 1},
            }
            if domain:
                proof["domain"] = domain
            proofs.append(proof)
    context = {
        "schema": "allocatbelt.application-source5-evidence-archive-context.v1",
        "campaign_id": "component", "host_id": "host-a", "phase": "aa",
        "job_index": 0, "predecessor_ack_pin": None,
        "authorized_signer_fingerprint": "A" * 40,
        **{name: pin("/inputs/" + name + ".json") for name in
           ("source_manifest_pin", "execution_manifest_pin", "plan_pin", "resource_budget_pin")},
    }
    return {
        "schema": packet.REQUEST_SCHEMA_V3, "context": context,
        "job_record_pin": {"path": "/component/local-record.json", "raw_sha256": "c" * 64},
        "authorization": {"authorization_id": "authorization-1",
                          **{name: "d" * 64 for name in
                             ("authorization_head", "terminal_head", "component_sha256", "process_metrics_sha256")}},
        "predecessor_ack_pin": None, "owner_receipt_pins": owners,
        "empty_tmp_proofs": proofs,
        "entries": sorted([{"origin_path": value["path"], "role": role, "byte_count": 1,
                             "raw_sha256": value["raw_sha256"], "semantic_sha256": value["semantic_sha256"]}
                            for role, value in owners.items()], key=lambda row: row["origin_path"]),
    }


def legacy_request_fixture():
    request = request_fixture()
    request["schema"] = packet.REQUEST_SCHEMA
    request["empty_tmp_proofs"] = [
        proof for proof in request["empty_tmp_proofs"]
        if "domain" not in proof
    ]
    return request


def signed_request(body):
    return {**body, "request_sha256": digest(canonical(body))}


def bundle_documents(request):
    """Build structural document bindings, without asserting real durability."""
    context = request["context"]
    objects = []
    for row in request["entries"]:
        name = digest(row["origin_path"].encode())
        object_id = f"{name[:2]}/{name}-{row['raw_sha256']}.bin"
        objects.append({**row, "object_id": object_id, "object_pin": {
            "path": "/archive/objects/" + object_id,
            "raw_sha256": row["raw_sha256"],
            "semantic_sha256": row["raw_sha256"], "byte_count": row["byte_count"],
        }})
    manifest = {
        "schema": "allocatbelt.application-source5-evidence-object-manifest.v1",
        **{key: context[key] for key in ("campaign_id", "host_id", "phase", "job_index")},
        "job_ordinal": 1, "job_sha256": "e" * 64, "run_id": "component-run",
        "job_record_raw_sha256": request["job_record_pin"]["raw_sha256"],
        "predecessor_ack_pin": None, "objects": objects,
        "object_count": len(objects), "payload_bytes": sum(r["byte_count"] for r in objects),
    }
    manifest["manifest_sha256"] = digest(canonical(manifest))
    manifest_pin = {"path": "/archive/manifest.json", "raw_sha256": digest(canonical(manifest)),
                    "semantic_sha256": manifest["manifest_sha256"]}
    checkpoint_schema = {
        packet.REQUEST_SCHEMA:
            "allocatbelt.application-source5-evidence-job-checkpoint.v1",
        packet.REQUEST_SCHEMA_V2:
            "allocatbelt.application-source5-evidence-job-checkpoint.v2",
        packet.REQUEST_SCHEMA_V3:
            "allocatbelt.application-source5-evidence-job-checkpoint.v3",
    }[request["schema"]]
    checkpoint = {
        **{key: value for key, value in request.items() if key not in ("schema", "request_sha256")},
        "schema": checkpoint_schema,
        "request_pin": {"path": "/component/request.json", "raw_sha256": digest(canonical(request)),
                        "semantic_sha256": request["request_sha256"]},
        "object_manifest_pin": manifest_pin,
    }
    checkpoint["checkpoint_sha256"] = digest(canonical(checkpoint))
    checkpoint_pin = {"path": "/archive/checkpoint.json", "raw_sha256": digest(canonical(checkpoint)),
                      "semantic_sha256": checkpoint["checkpoint_sha256"]}
    durable = {
        "commit_id": "1" * 64,
        "archive_source5_directory": {"path": "/archive", "device": 1, "inode": 2, "mode": 0o700},
        "checkpoint_pin": checkpoint_pin, "object_manifest_pin": manifest_pin,
        "object_reopen_sha256": "2" * 64, "object_count": len(objects),
        "payload_bytes": manifest["payload_bytes"], "job_record_validation": {
            "path": "/archive/validation.json", "origin_path": request["job_record_pin"]["path"],
            "raw_sha256": request["job_record_pin"]["raw_sha256"],
            "semantic_sha256": "3" * 64, "byte_count": 1,
        },
    }
    ack = {
        "schema": "allocatbelt.application-source5-evidence-durable-ack.v1",
        "checkpoint_pin": checkpoint_pin, "object_manifest_pin": manifest_pin,
        "predecessor_ack_pin": None, "signer_fingerprint": context["authorized_signer_fingerprint"],
        "durable_commit": durable,
    }
    ack["ack_sha256"] = digest(canonical(ack))
    return checkpoint, manifest, ack


def make_ack_bundle(documents):
    names = ("checkpoint.json", "object-manifest.json", "ack.json", "ack.sig")
    members = list(zip(names, [canonical(value) for value in documents[:3]] +
                       [b"signature"], strict=True))
    raw = bytearray()
    for name, member in members:
        raw.extend(packet._tar_header(name, len(member)))
        raw.extend(member)
        raw.extend(b"\x00" * ((-len(member)) % packet.TAR_BLOCK_BYTES))
    raw.extend(b"\x00" * 1024)
    raw.extend(b"\x00" * ((-len(raw)) % packet.TAR_RECORD_BYTES))
    return bytes(raw)


class FixedV3PacketTests(unittest.TestCase):
    def test_source_profile_request_schema_is_exact_and_legacy_default_is_unchanged(self):
        profile = {"required_request_schema": packet.REQUEST_SCHEMA_V3}
        packet._require_profile_request_schema(profile, packet.REQUEST_SCHEMA_V3)
        for schema in (packet.REQUEST_SCHEMA, packet.REQUEST_SCHEMA_V2):
            with self.subTest(schema=schema):
                with self.assertRaisesRegex(
                        packet.TransferPacketError, "selected Source profile"):
                    packet._require_profile_request_schema(profile, schema)
        for schema in (packet.REQUEST_SCHEMA, packet.REQUEST_SCHEMA_V2):
            packet._require_profile_request_schema({}, schema)
        with self.assertRaisesRegex(
                packet.TransferPacketError, "unknown request schema"):
            packet._profile_required_request_schema({
                "required_request_schema": packet.REQUEST_SCHEMA_V2,
            })
        self.assertEqual(
            packet._request_schema_for_checkpoint_schema(
                packet.CHECKPOINT_SCHEMA_V3,
            ),
            packet.REQUEST_SCHEMA_V3,
        )

    def test_ack_publication_checks_profile_against_actual_checkpoint_before_rename(self):
        scenarios = (
            ({"required_request_schema": packet.REQUEST_SCHEMA_V3},
             request_fixture(), None, True),
            ({"required_request_schema": packet.REQUEST_SCHEMA_V3},
             legacy_request_fixture(), None, False),
            ({}, legacy_request_fixture(), None, True),
            ({}, None,
             b"publication checks bytes; the separate host reader checks the ACK",
             True),
        )
        for source_profile, request_body, raw_bundle, should_publish in scenarios:
            request_label = (request_body["schema"] if request_body is not None
                             else "legacy raw upload")
            with self.subTest(required=source_profile, request=request_label), \
                    tempfile.TemporaryDirectory(prefix="fixed-v3-packet-ack-profile-") as tmp:
                root = Path(tmp)
                os.chmod(root, 0o700)
                budget_raw = b"{}\n"
                budget_pin = {
                    "path": str(root / "budget.json"),
                    "raw_sha256": digest(budget_raw),
                    "semantic_sha256": "a" * 64,
                }
                if raw_bundle is None:
                    request = copy.deepcopy(request_body)
                    request["context"]["resource_budget_pin"] = budget_pin
                    request = signed_request(request)
                    documents = bundle_documents(request)
                    bundle_raw = make_ack_bundle(documents)
                    request_raw = canonical(request)
                    request_pin = {
                        "path": "/component/request.json",
                        "raw_sha256": digest(request_raw),
                        "semantic_sha256": request["request_sha256"],
                    }
                else:
                    bundle_raw = raw_bundle
                    request_pin = {
                        "path": "/component/request.json",
                        "raw_sha256": "a" * 64,
                        "semantic_sha256": "b" * 64,
                    }
                final_path = root / "ack.bundle"
                offer = packet._offer_body(
                    request_pin, "/component/packet.tar", "b" * 64, 512,
                    str(final_path), 1 << 20,
                )
                offer_raw = canonical(offer)
                offer_pin = {
                    "path": str(root / "offer.json"),
                    "raw_sha256": digest(offer_raw),
                    "semantic_sha256": offer["offer_sha256"],
                }
                incoming_path = Path(str(final_path) + ".incoming")
                incoming_path.write_bytes(bundle_raw)
                incoming_path.chmod(0o600)
                bundle_pin = {
                    "path": str(final_path),
                    "raw_sha256": digest(bundle_raw),
                    "byte_count": len(bundle_raw),
                }
                limits = (1 << 20, 1, 1 << 20, 16,
                          [str(root)], str(root), 1 << 20, 4096)
                with mock.patch.object(
                    packet, "_validate_transfer_offer_with_profile",
                    return_value=(offer, offer_pin, limits, source_profile),
                ):
                    if should_publish:
                        result = packet.publish_ack_bundle(
                            incoming_path, budget_raw, budget_pin, offer_raw,
                            offer_pin, bundle_pin,
                        )
                        self.assertEqual(result["path"], str(final_path))
                        self.assertEqual(final_path.read_bytes(), bundle_raw)
                    else:
                        with self.assertRaisesRegex(
                                packet.TransferPacketError,
                                "actual checkpoint request schema"):
                            packet.publish_ack_bundle(
                                incoming_path, budget_raw, budget_pin,
                                offer_raw, offer_pin, bundle_pin,
                            )
                        self.assertTrue(incoming_path.is_file())
                        self.assertFalse(final_path.exists())

    def test_exact_four_proof_fixed_request_and_finite_metadata_limit(self):
        request = signed_request(request_fixture())
        self.assertEqual(packet._validate_request(request), request)
        self.assertEqual(packet._checkpoint_metadata_limit(request), packet.MAX_JSON_BYTES)
        self.assertEqual(packet._checkpoint_metadata_limit({"schema": packet.REQUEST_SCHEMA_V2}),
                         packet.MAX_ARCHIVE_REQUEST_CHECKPOINT_BYTES)

    def test_resigned_invalid_profiles_and_proofs_refuse(self):
        changes = [
            lambda r: r["empty_tmp_proofs"].pop(),
            lambda r: r["empty_tmp_proofs"].append(copy.deepcopy(r["empty_tmp_proofs"][0])),
            lambda r: r["empty_tmp_proofs"].reverse(),
            lambda r: r["empty_tmp_proofs"][1].update(domain="application_tmpdir"),
            lambda r: r["empty_tmp_proofs"][1].update(member_ordinal=0),
            lambda r: r["empty_tmp_proofs"][0].update(bytes_used=True),
            lambda r: r["empty_tmp_proofs"][0].update(bytes_used=1),
            lambda r: r["empty_tmp_proofs"][0]["owner_receipt_pin"].update(raw_sha256="e" * 64),
            lambda r: r["context"].update(phase="pressure"),
            lambda r: r.update(tree_inventories=[]),
            lambda r: r["owner_receipt_pins"].pop("fixed_pair_host_receipt"),
        ]
        # Change ordinal to a duplicate tuple, rather than its already-correct value.
        changes[4] = lambda r: r["empty_tmp_proofs"][3].update(member_ordinal=0)
        for change in changes:
            with self.subTest(change=changes.index(change)):
                body = copy.deepcopy(request_fixture())
                change(body)
                with self.assertRaises(packet.TransferPacketError):
                    packet._validate_request(signed_request(body))

    def test_v2_empty_inventory_still_refuses(self):
        body = request_fixture()
        body.update(schema=packet.REQUEST_SCHEMA_V2, tree_inventories=[])
        with self.assertRaisesRegex(packet.TransferPacketError, "at least one exact tree"):
            packet._validate_request(signed_request(body))

    def test_full_v3_ack_document_closure_and_checkpoint_downgrade_refusal(self):
        documents = bundle_documents(signed_request(request_fixture()))
        self.assertEqual(packet._validate_ack_bundle_documents(
            *(canonical(value) for value in documents), b"signature", 32), documents)
        checkpoint, manifest, ack = copy.deepcopy(documents)
        checkpoint["schema"] = "allocatbelt.application-source5-evidence-job-checkpoint.v1"
        checkpoint["checkpoint_sha256"] = digest(canonical({k: v for k, v in checkpoint.items()
                                                          if k != "checkpoint_sha256"}))
        with self.assertRaisesRegex(packet.TransferPacketError, "request self digest"):
            packet._validate_ack_bundle_documents(canonical(checkpoint), canonical(manifest),
                                                  canonical(ack), b"signature", 32)

    def test_v3_checkpoint_reconstructs_v3_before_manifest_validation(self):
        body = request_fixture()
        request = signed_request(body)
        request_raw = canonical(request)
        checkpoint = {
            **{k: v for k, v in body.items() if k != "schema"},
            "schema": "allocatbelt.application-source5-evidence-job-checkpoint.v3",
            "request_pin": {"path": "/component/request.json", "raw_sha256": digest(request_raw),
                            "semantic_sha256": request["request_sha256"]},
            "object_manifest_pin": pin("/component/manifest.json"),
        }
        checkpoint["checkpoint_sha256"] = digest(canonical(checkpoint))
        # A deliberately invalid manifest proves schema/request reconstruction ran first.
        with self.assertRaisesRegex(packet.TransferPacketError, "object manifest"):
            packet._validate_ack_bundle_documents(canonical(checkpoint), b"{}\n", b"{}\n", b"signature", 32)
        bad = copy.deepcopy(checkpoint)
        bad["schema"] = "allocatbelt.application-source5-evidence-job-checkpoint.v1"
        bad["checkpoint_sha256"] = digest(canonical({k: v for k, v in bad.items() if k != "checkpoint_sha256"}))
        with self.assertRaisesRegex(packet.TransferPacketError, "request self digest"):
            packet._validate_ack_bundle_documents(canonical(bad), b"{}\n", b"{}\n", b"signature", 32)


if __name__ == "__main__":
    unittest.main()
