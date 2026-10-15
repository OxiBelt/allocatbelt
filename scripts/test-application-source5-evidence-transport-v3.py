#!/usr/bin/env python3
"""Bounded round trips and closure counterexamples for Source5 v3 transport."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
TRANSPORT_PATH = SCRIPT_DIR / "application-source5-evidence-transport-v3.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


transport = load_module("source5_evidence_transport_v3_test_target", TRANSPORT_PATH)


def pin(path: Path, raw: bytes, semantic: str | None = None) -> dict[str, str]:
    digest = hashlib.sha256(raw).hexdigest()
    return {"path": str(path), "raw_sha256": digest,
            "semantic_sha256": digest if semantic is None else semantic}


def private(path: Path) -> Path:
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)
    return path


class IndexV3Tests(unittest.TestCase):
    def test_page_tree_streams_ordered_rows_and_binds_budget(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-index-v3-") as tmp:
            root = Path(tmp)
            source_root = str(root / "source")
            input_root = str(root / "input")
            output_root = str(root / "output")
            index_dir = private(root / "index")
            budget_pin = pin(root / "budget.json", b"budget")
            raw_sha = hashlib.sha256(b"x").hexdigest()

            def entries():
                for ordinal in range(1025):
                    long_name = "p" * 1650 + f"-{ordinal:04d}"
                    path = str(root / "origin" / long_name)
                    yield {
                        "role": "normal_app_output", "host_id": "host-a",
                        "origin_path": path, "local_path": path,
                        "raw_sha256": raw_sha, "semantic_sha256": None,
                        "byte_count": 1, "maximum_bytes": 1,
                    }

            index, index_pin, _files = transport.write_index_v3(
                campaign_id="campaign-a", host_id="host-a",
                source_root=source_root, input_root=input_root,
                output_root=output_root, host_evidence_budget=budget_pin,
                entries=entries(), directory=index_dir,
                maximum_entries=2048, maximum_index_bytes=16 * 1024 * 1024,
                chunk_bytes=64 * 1024, fanout=4,
            )
            checked = transport.validate_index_v3(
                index, budget_pin=budget_pin, campaign_id="campaign-a",
                host_id="host-a", source_root=source_root,
                input_root=input_root, output_root=output_root,
                maximum_entries=2048, maximum_index_bytes=16 * 1024 * 1024,
                chunk_bytes=64 * 1024, fanout=4,
            )
            rows = list(transport.iter_index_entries_v3(
                checked, chunk_bytes=64 * 1024, fanout=4,
            ))
            self.assertEqual(len(rows), 1025)
            self.assertGreater(
                checked["manifest_page_count"], len(checked["manifest_pages"]),
            )
            self.assertEqual(rows[0]["origin_path"],
                             min(row["origin_path"] for row in rows))
            self.assertEqual(index_pin["semantic_sha256"],
                             checked["index_sha256"])
            catalogue = [{
                "path": row["origin_path"], "kind": "file",
                "role": row["role"], "host_id": row["host_id"],
                "max_file_bytes": row["maximum_bytes"], "origin_pin": None,
                "aggregate_id": None, "aggregate_max_bytes": None,
            } for row in rows]
            summary = transport.validate_index_against_catalogue_v3(
                iter(rows), iter(catalogue),
            )
            self.assertEqual(summary["entry_count"], len(rows))
            with self.assertRaisesRegex(transport.EvidenceTransportError,
                                        "outside the producer path catalogue"):
                transport.validate_index_against_catalogue_v3(iter(rows), iter(()))
            pinned_path = rows[0]["origin_path"]
            missing_pin = [{
                "path": pinned_path, "kind": "file", "role": rows[0]["role"],
                "host_id": rows[0]["host_id"],
                "max_file_bytes": rows[0]["maximum_bytes"],
                "origin_pin": {"raw_sha256": rows[0]["raw_sha256"],
                               "semantic_sha256": None},
                "aggregate_id": None, "aggregate_max_bytes": None,
            }]
            with self.assertRaisesRegex(transport.EvidenceTransportError,
                                        "omits its pinned immutable input"):
                transport.validate_index_against_catalogue_v3(iter(()),
                                                              iter(missing_pin))
            _opened_root, lookup = transport.open_index_v3(
                index_pin, budget_pin=budget_pin,
                campaign_id="campaign-a", host_id="host-a",
                source_root=source_root, input_root=input_root,
                output_root=output_root, maximum_entries=2048,
                maximum_index_bytes=16 * 1024 * 1024,
                chunk_bytes=64 * 1024, fanout=4,
            )
            self.assertEqual(len(lookup), 1025)
            self.assertEqual(lookup.get(rows[64]["origin_path"]), rows[64])

            captured_root = private(root / "captured-index")
            captured_paths: dict[str, Path] = {}
            for ordinal, item in enumerate(_files):
                origin = Path(item["path"])
                local = captured_root / f"{ordinal:05d}-{origin.name}"
                shutil.copyfile(origin, local)
                os.chmod(local, 0o600)
                captured_paths[str(origin)] = local
            _captured_root, captured_lookup = transport.open_index_v3(
                index_pin, budget_pin=budget_pin,
                campaign_id="campaign-a", host_id="host-a",
                source_root=source_root, input_root=input_root,
                output_root=output_root, maximum_entries=2048,
                maximum_index_bytes=16 * 1024 * 1024,
                chunk_bytes=64 * 1024, fanout=4,
                read_path=lambda origin: captured_paths[origin],
            )
            self.assertEqual(captured_lookup.get(rows[64]["origin_path"]),
                             rows[64])

            underreported = {
                **index,
                "manifest_pages": [dict(item) for item in index["manifest_pages"]],
            }
            underreported["manifest_pages"][0]["byte_count"] = 1
            index_body = {key: value for key, value in underreported.items()
                          if key != "index_sha256"}
            underreported["index_sha256"] = hashlib.sha256(
                transport._canonical(index_body),
            ).hexdigest()
            underreported_raw = transport._canonical(underreported)
            underreported_path = index_dir / "repinned-underreported-root.json"
            underreported_path.write_bytes(underreported_raw)
            os.chmod(underreported_path, 0o600)
            underreported_pin = {
                "path": str(underreported_path),
                "raw_sha256": hashlib.sha256(underreported_raw).hexdigest(),
                "semantic_sha256": underreported["index_sha256"],
            }
            page_size = Path(index["manifest_pages"][0]["path"]).stat().st_size
            actual_index_bytes = sum(item["byte_count"] for item in _files)
            understated_index_ceiling = actual_index_bytes - page_size + 1
            with self.assertRaisesRegex(
                    transport.EvidenceTransportError,
                    "byte count differs from its exact descriptor"):
                transport.open_index_v3(
                    underreported_pin, budget_pin=budget_pin,
                    campaign_id="campaign-a", host_id="host-a",
                    source_root=source_root, input_root=input_root,
                    output_root=output_root, maximum_entries=2048,
                    maximum_index_bytes=understated_index_ceiling,
                    chunk_bytes=64 * 1024, fanout=4,
                )

            data_chunk = next(Path(item["path"]) for item in _files
                              if item["role"] == "evidence_index_data_chunk")
            original_bytes = data_chunk.read_bytes()
            calls = 0

            def replace_after_first_check(origin: str) -> Path:
                nonlocal calls
                path = Path(origin)
                if path == data_chunk:
                    calls += 1
                    if calls == 2:
                        changed = bytearray(original_bytes)
                        changed[0] = ord("{") if changed[0] != ord("{") else ord("[")
                        data_chunk.write_bytes(changed)
                        os.chmod(data_chunk, 0o600)
                return path

            with self.assertRaises(transport.EvidenceTransportError):
                transport.iter_index_entries_v3(
                    checked, chunk_bytes=64 * 1024, fanout=4,
                    read_path=replace_after_first_check,
                ).__next__()

    def test_tiny_chunk_or_index_budget_is_rejected_before_data_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-index-v3-budget-") as tmp:
            root = Path(tmp)
            budget_pin = pin(root / "budget.json", b"budget")
            directory = private(root / "index")
            origin = str(root / "origin" / "only.json")
            row = {
                "role": "component_receipt", "host_id": "host-a",
                "origin_path": origin, "local_path": origin,
                "raw_sha256": hashlib.sha256(b"x").hexdigest(),
                "semantic_sha256": None, "byte_count": 1, "maximum_bytes": 1,
            }
            with self.assertRaises(transport.EvidenceTransportError):
                transport.write_index_v3(
                    campaign_id="campaign-a", host_id="host-a",
                    source_root=str(root / "source"), input_root=str(root / "input"),
                    output_root=str(root / "output"),
                    host_evidence_budget=budget_pin, entries=[row],
                    directory=directory, maximum_entries=2,
                    maximum_index_bytes=1024, chunk_bytes=1, fanout=2,
                )
            self.assertEqual(list(directory.iterdir()), [])
            with self.assertRaises(transport.EvidenceTransportError):
                transport.write_index_v3(
                    campaign_id="campaign-a", host_id="host-a",
                    source_root=str(root / "source"), input_root=str(root / "input"),
                    output_root=str(root / "output"),
                    host_evidence_budget=budget_pin, entries=[row],
                    directory=directory, maximum_entries=2,
                    maximum_index_bytes=1, fanout=2,
                )
            self.assertEqual(list(directory.iterdir()), [])

    def test_index_rejects_a_changed_chunk(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-index-v3-tamper-") as tmp:
            root = Path(tmp)
            index_dir = private(root / "index")
            budget_pin = pin(root / "budget.json", b"budget")
            entry_path = str(root / "origin" / "only.json")
            index, _index_pin, files = transport.write_index_v3(
                campaign_id="campaign-b", host_id="host-b",
                source_root=str(root / "source"), input_root=str(root / "input"),
                output_root=str(root / "output"), host_evidence_budget=budget_pin,
                entries=[{
                    "role": "component_receipt", "host_id": "host-b",
                    "origin_path": entry_path, "local_path": entry_path,
                    "raw_sha256": hashlib.sha256(b"x").hexdigest(),
                    "semantic_sha256": None, "byte_count": 1, "maximum_bytes": 1,
                }], directory=index_dir, maximum_entries=4,
                maximum_index_bytes=1024 * 1024,
            )
            chunk = next(Path(item["path"]) for item in files
                         if item["role"] == "evidence_index_data_chunk")
            with chunk.open("ab") as stream:
                stream.write(b"tamper")
            with self.assertRaises(transport.EvidenceTransportError):
                transport.validate_index_v3(
                    index, budget_pin=budget_pin, campaign_id="campaign-b",
                    host_id="host-b", source_root=str(root / "source"),
                    input_root=str(root / "input"), output_root=str(root / "output"),
                    maximum_entries=4, maximum_index_bytes=1024 * 1024,
                )


class CapturedStoreV2Tests(unittest.TestCase):
    def test_streamed_store_round_trip_rechecks_shards_and_object_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-store-v2-") as tmp:
            root = Path(tmp)
            store_root = private(root / "store")
            source_dir = private(root / "source")
            source = source_dir / "receipt.json"
            payload = b'{"receipt":true}\n'
            source.write_bytes(payload)
            os.chmod(source, 0o600)
            budget_pin = pin(root / "budget.json", b"budget")
            index_pin = pin(root / "index.json", b"index")
            receipt_pin = pin(root / "origin.json", b"origin")
            row = {
                "role": "component_receipt", "host_id": "host-c",
                "origin_path": str(root / "origin" / "receipt.json"),
                "raw_sha256": hashlib.sha256(payload).hexdigest(),
                "semantic_sha256": None, "byte_count": len(payload),
                "maximum_bytes": 4096, "source_path": str(source),
                "source_kind": "file",
            }
            _manifest, store_pin = transport.build_captured_store_v2(
                campaign_id="campaign-c", host_id="host-c",
                budget_pin=budget_pin, index_pin=index_pin,
                origin_receipt_pin=receipt_pin, entries=[row], root=store_root,
                maximum_entries=10, maximum_payload_bytes=4096,
                maximum_metadata_bytes=1024 * 1024,
            )
            captured = transport.open_captured_store_v2(
                store_pin, budget_pin=budget_pin, index_pin=index_pin,
                origin_receipt_pin=receipt_pin, maximum_entries=10,
                maximum_payload_bytes=4096, maximum_metadata_bytes=1024 * 1024,
            )
            entry = captured.get(row["origin_path"])
            self.assertEqual(captured.root_pin, store_pin)
            self.assertIsNotNone(entry)
            self.assertEqual(entry["local_path"], str(entry["raw_bytes"]))
            with entry["raw_bytes"].open("rb") as stream:
                self.assertEqual(stream.read(), payload)
            self.assertEqual(list(captured), [row["origin_path"]])

            object_path = Path(entry["local_path"])
            shard = object_path.parent
            replacement = private(root / "replacement-shard")
            replacement_file = replacement / object_path.name
            shutil.copyfile(object_path, replacement_file)
            os.chmod(replacement_file, 0o600)
            saved_shard = root / "saved-shard"
            shard.rename(saved_shard)
            shard.symlink_to(replacement, target_is_directory=True)
            with self.assertRaises(transport.EvidenceTransportError):
                entry["raw_bytes"].open_stream()
            shard.unlink()
            saved_shard.rename(shard)

            object_path.write_bytes(b"y" * len(payload))
            os.chmod(object_path, 0o600)
            with self.assertRaisesRegex(transport.EvidenceTransportError,
                                        "raw bytes differ"):
                transport.open_captured_store_v2(
                    store_pin, budget_pin=budget_pin, index_pin=index_pin,
                    origin_receipt_pin=receipt_pin, maximum_entries=10,
                    maximum_payload_bytes=4096,
                    maximum_metadata_bytes=1024 * 1024,
                )

    def test_payload_budget_is_checked_before_creating_an_object(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-store-v2-budget-") as tmp:
            root = Path(tmp)
            store_root = private(root / "store")
            source_dir = private(root / "source")
            source = source_dir / "payload.bin"
            payload = b"larger-than-budget"
            source.write_bytes(payload)
            os.chmod(source, 0o600)
            budget_pin = pin(root / "budget.json", b"budget")
            index_pin = pin(root / "index.json", b"index")
            receipt_pin = pin(root / "origin.json", b"origin")
            row = {
                "role": "component_receipt", "host_id": "host-c",
                "origin_path": str(root / "origin" / "payload.bin"),
                "raw_sha256": hashlib.sha256(payload).hexdigest(),
                "semantic_sha256": None, "byte_count": len(payload),
                "maximum_bytes": 4096, "source_path": str(source),
                "source_kind": "file",
            }
            with self.assertRaisesRegex(transport.EvidenceTransportError,
                                        "prospective count/payload ceiling"):
                transport.build_captured_store_v2(
                    campaign_id="campaign-c", host_id="host-c",
                    budget_pin=budget_pin, index_pin=index_pin,
                    origin_receipt_pin=receipt_pin, entries=[row], root=store_root,
                    maximum_entries=10, maximum_payload_bytes=1,
                    maximum_metadata_bytes=1024 * 1024,
                )
            self.assertEqual(list(store_root.iterdir()), [])

    def test_metadata_root_ceiling_is_checked_before_creating_store_children(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-store-v2-root-budget-") as tmp:
            root = Path(tmp)
            store_root = private(root / "store")
            source_dir = private(root / "source")
            source = source_dir / "payload.bin"
            source.write_bytes(b"x")
            os.chmod(source, 0o600)
            budget_pin = pin(root / "budget.json", b"budget")
            index_pin = pin(root / "index.json", b"index")
            receipt_pin = pin(root / "origin.json", b"origin")
            with self.assertRaisesRegex(transport.EvidenceTransportError,
                                        "metadata/root ceilings"):
                transport.build_captured_store_v2(
                    campaign_id="campaign-c", host_id="host-c",
                    budget_pin=budget_pin, index_pin=index_pin,
                    origin_receipt_pin=receipt_pin, entries=[{
                        "role": "component_receipt", "host_id": "host-c",
                        "origin_path": str(root / "origin" / "payload.bin"),
                        "raw_sha256": hashlib.sha256(b"x").hexdigest(),
                        "semantic_sha256": None, "byte_count": 1,
                        "maximum_bytes": 4096, "source_path": str(source),
                        "source_kind": "file",
                    }], root=store_root, maximum_entries=10,
                    maximum_payload_bytes=4096,
                    maximum_metadata_bytes=1024 * 1024,
                    maximum_root_bytes=4096,
                )
            self.assertEqual(list(store_root.iterdir()), [])

    def test_store_stops_on_understated_streamed_count_and_payload(self) -> None:
        for field, value, message in (
            ("entry_count", 1, "remaining root entry count"),
            ("payload_bytes", 1, "owner byte ceiling"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory(
                    prefix="source5-store-v2-aggregate-") as tmp:
                root = Path(tmp)
                store_root = private(root / "store")
                source_dir = private(root / "source")
                payloads = (b"x", b"y" * 8)
                rows = []
                for ordinal, payload in enumerate(payloads):
                    source = source_dir / f"payload-{ordinal}.bin"
                    source.write_bytes(payload)
                    os.chmod(source, 0o600)
                    origin = str(root / "origin" / f"payload-{ordinal}.bin")
                    rows.append({
                        "role": "component_receipt", "host_id": "host-c",
                        "origin_path": origin,
                        "raw_sha256": hashlib.sha256(payload).hexdigest(),
                        "semantic_sha256": None, "byte_count": len(payload),
                        "maximum_bytes": 4096, "source_path": str(source),
                        "source_kind": "file",
                    })
                budget_pin = pin(root / "budget.json", b"budget")
                index_pin = pin(root / "index.json", b"index")
                receipt_pin = pin(root / "origin.json", b"origin")
                _store, store_pin = transport.build_captured_store_v2(
                    campaign_id="campaign-c", host_id="host-c",
                    budget_pin=budget_pin, index_pin=index_pin,
                    origin_receipt_pin=receipt_pin, entries=rows,
                    root=store_root, maximum_entries=10,
                    maximum_payload_bytes=4096,
                    maximum_metadata_bytes=1024 * 1024,
                )
                original_root_path = Path(store_pin["path"])
                store_value = json.loads(original_root_path.read_bytes())
                store_value[field] = value
                body = {key: item for key, item in store_value.items()
                        if key != "store_sha256"}
                store_value["store_sha256"] = hashlib.sha256(
                    transport._canonical(body),
                ).hexdigest()
                root_raw = transport._canonical(store_value)
                root_path = store_root / \
                    f"captured-evidence-v2-{store_value['store_sha256']}.json"
                root_path.write_bytes(root_raw)
                os.chmod(root_path, 0o600)
                altered_pin = {
                    "path": str(root_path),
                    "raw_sha256": hashlib.sha256(root_raw).hexdigest(),
                    "semantic_sha256": store_value["store_sha256"],
                }
                with self.assertRaisesRegex(transport.EvidenceTransportError,
                                            message):
                    transport.open_captured_store_v2(
                        altered_pin, budget_pin=budget_pin,
                        index_pin=index_pin, origin_receipt_pin=receipt_pin,
                        maximum_entries=10, maximum_payload_bytes=4096,
                        maximum_metadata_bytes=1024 * 1024,
                    )

    def test_repinned_noncanonical_and_malformed_metadata_rows_are_rejected(self) -> None:
        mutations = (
            ("noncanonical", "canonical"),
            ("bad-role-type", "role"),
            ("bad-semantic-digest", "semantic_sha256"),
        )
        for name, kind in mutations:
            with self.subTest(name=name), tempfile.TemporaryDirectory(
                    prefix="source5-store-v2-metadata-") as tmp:
                root = Path(tmp)
                store_root = private(root / "store")
                source_dir = private(root / "source")
                source = source_dir / "receipt.json"
                payload = b'{"receipt":true}\n'
                source.write_bytes(payload)
                os.chmod(source, 0o600)
                budget_pin = pin(root / "budget.json", b"budget")
                index_pin = pin(root / "index.json", b"index")
                receipt_pin = pin(root / "origin.json", b"origin")
                origin = str(root / "origin" / "receipt.json")
                _manifest, original_pin = transport.build_captured_store_v2(
                    campaign_id="campaign-meta", host_id="host-meta",
                    budget_pin=budget_pin, index_pin=index_pin,
                    origin_receipt_pin=receipt_pin, entries=[{
                        "role": "component_receipt", "host_id": "host-meta",
                        "origin_path": origin,
                        "raw_sha256": hashlib.sha256(payload).hexdigest(),
                        "semantic_sha256": None, "byte_count": len(payload),
                        "maximum_bytes": 4096, "source_path": str(source),
                        "source_kind": "file",
                    }], root=store_root, maximum_entries=10,
                    maximum_payload_bytes=4096,
                    maximum_metadata_bytes=1024 * 1024,
                )
                store_path = Path(original_pin["path"])
                store_value = json.loads(store_path.read_bytes())
                descriptor = dict(store_value["metadata_chunks"][0])
                metadata_raw = Path(descriptor["path"]).read_bytes()
                if kind == "canonical":
                    changed_metadata = b" " + metadata_raw[1:]
                else:
                    row = json.loads(metadata_raw.decode("ascii"))
                    if kind == "role":
                        row["role"] = 7
                    else:
                        row["semantic_sha256"] = "not-a-sha256"
                    changed_metadata = transport._canonical(row)
                changed_digest = hashlib.sha256(changed_metadata).hexdigest()
                changed_chunk = Path(descriptor["path"]).parent / \
                    f"entries-{changed_digest}.jsonl"
                changed_chunk.write_bytes(changed_metadata)
                os.chmod(changed_chunk, 0o600)
                descriptor.update({
                    "path": str(changed_chunk),
                    "raw_sha256": changed_digest,
                    "semantic_sha256": changed_digest,
                    "byte_count": len(changed_metadata),
                })
                store_value["metadata_chunks"] = [descriptor]
                store_value["metadata_bytes"] = len(changed_metadata)
                body = {key: value for key, value in store_value.items()
                        if key != "store_sha256"}
                store_value["store_sha256"] = hashlib.sha256(
                    transport._canonical(body),
                ).hexdigest()
                changed_root_raw = transport._canonical(store_value)
                changed_root = store_root / \
                    f"captured-evidence-v2-{store_value['store_sha256']}.json"
                changed_root.write_bytes(changed_root_raw)
                os.chmod(changed_root, 0o600)
                changed_pin = {
                    "path": str(changed_root),
                    "raw_sha256": hashlib.sha256(changed_root_raw).hexdigest(),
                    "semantic_sha256": store_value["store_sha256"],
                }
                with self.assertRaises(transport.EvidenceTransportError):
                    transport.open_captured_store_v2(
                        changed_pin, budget_pin=budget_pin,
                        index_pin=index_pin, origin_receipt_pin=receipt_pin,
                        maximum_entries=10, maximum_payload_bytes=4096,
                        maximum_metadata_bytes=1024 * 1024,
                    )


if __name__ == "__main__":
    unittest.main()
