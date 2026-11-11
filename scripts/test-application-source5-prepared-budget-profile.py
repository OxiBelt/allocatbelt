#!/usr/bin/env python3
"""Focused fail-closed witnesses for the read-only V5 budget profile.

These tests cover the primary-pin boundary, the lazy bootstrap custody reader,
the Source-owned width DTO projection, and full-row catalogue parity. They do
not qualify SourceA admission, APP execution, GPG replay, or reclaim.
"""
from __future__ import annotations

import copy
import dataclasses
import hashlib
import importlib.util
import inspect
import json
import os
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
ARCHIVE_PATH = SCRIPT_DIR / "application-source5-evidence-archive.py"
PACKET_PATH = SCRIPT_DIR / "application-source5-evidence-transfer-packet.py"
CAPTURE_PATH = SCRIPT_DIR / "application-source5-lineage-capture.py"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load test dependency {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


archive = load("v5_budget_profile_archive_tests", ARCHIVE_PATH)
packet = load("v5_budget_profile_packet_tests", PACKET_PATH)
capture = load("v5_budget_profile_capture_tests", CAPTURE_PATH)
source5_campaign = load(
    "v5_budget_profile_source5_campaign_tests",
    SCRIPT_DIR / "application-source5-campaign.py",
)
chronology = load(
    "v5_budget_profile_source5_chronology_tests",
    SCRIPT_DIR / "application-campaign-chronology.py",
)
budget_algorithm = load(
    "v5_budget_profile_h6_budget_tests",
    SCRIPT_DIR / "application-source5-evidence-budget.py",
)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def pin(path: str, raw: bytes, semantic: str | None = None) -> dict[str, str]:
    return {
        "path": path, "raw_sha256": sha(raw),
        "semantic_sha256": sha(raw) if semantic is None else semantic,
    }


def budget_case() -> dict[str, object]:
    empty_inventory = []
    tree_sha = sha(canonical({
        "schema": archive.SOURCE_INVENTORY_SCHEMA_V1,
        "entries": empty_inventory,
    }))
    source = {
        "schema": archive.SOURCE_MANIFEST_SCHEMA_V5,
        "source": {
            "git_commit": "a" * 40, "source_tree_sha256": tree_sha,
            "files": empty_inventory,
        },
        "build": {},
    }
    source["manifest_sha256"] = sha(canonical(source))
    source_raw = canonical(source)
    source_a_pin = pin(
        "/origin/host-a-source.json", source_raw,
        source["manifest_sha256"],
    )
    source_b_pin = pin("/origin/host-b-source.json", b"historical-source-b\n")
    plan_pin = pin("/origin/final-plan.json", b"final-plan\n")
    spec_pin = pin("/origin/final-spec.json", b"final-spec\n")
    execution_pin = pin("/origin/final-execution.json", b"final-execution\n")
    width_pin = pin("/origin/current-width.json", b"current-width\n")
    lineage = {
        host: {
            "bridge_header": {
                "path": f"/old/{host}/bridge-header.json",
                "raw_sha256": ("1" if host == "host-a" else "2") * 64,
            },
            "record_index": {
                "path": f"/old/{host}/record-index.jsonl",
                "raw_sha256": ("3" if host == "host-a" else "4") * 64,
            },
        }
        for host in ("host-a", "host-b")
    }
    budget = {name: None for name in archive.HOST_BUDGET_FIELDS_V3}
    budget.update({
        "schema": archive.HOST_BUDGET_SCHEMA_V4,
        "admission_profile": archive.PREPARED_EXPLORATION_ADMISSION_PROFILE,
        "execution_manifest_schema": archive.PREPARED_EXPLORATION_EXECUTION_SCHEMA,
        "campaign_id": "campaign-a", "host_id": "host-a",
        "original_pins": {
            "spec": spec_pin, "plan": plan_pin,
            "execution_manifest": execution_pin,
            "source_manifests": {"host-a": source_a_pin,
                                  "host-b": source_b_pin},
            "source_tree_sha256": tree_sha,
            "prepared_exploration": lineage,
        },
        "journal_width_contract_pin": width_pin,
    })
    budget_body = {key: value for key, value in budget.items()
                   if key != "budget_sha256"}
    budget["budget_sha256"] = sha(canonical(budget_body))
    budget_raw = canonical(budget)
    budget_pin = pin(
        "/origin/host-a-budget-v4.json", budget_raw,
        budget["budget_sha256"],
    )
    context = {
        "schema": archive.CONTEXT_SCHEMA_V1,
        "campaign_id": "campaign-a", "host_id": "host-a",
        "phase": "aa", "job_index": 0,
        "source_manifest_pin": source_a_pin,
        "execution_manifest_pin": execution_pin,
        "plan_pin": plan_pin, "resource_budget_pin": budget_pin,
        "predecessor_ack_pin": None,
        "authorized_signer_fingerprint": "A" * 40,
    }
    return {
        "budget": budget, "budget_raw": budget_raw,
        "budget_pin": budget_pin, "context": context,
        "source": source, "source_raw": source_raw,
        "source_pin": source_a_pin, "tree_sha": tree_sha,
    }


def execution_join_case() -> dict[str, object]:
    campaign_id = "campaign-join"
    hosts = ["host-a", "host-b"]
    source_docs = {}
    source_pins = {}
    module_paths = sorted({
        "scripts/application-campaign.py",
        "scripts/application-campaign-inputs.py",
        "scripts/application-feedback-readback.py",
        "scripts/application-byte-capacity.py",
        chronology.CAPACITY_STAGE_SOURCE_PATH,
        chronology.CHRONOLOGY_SOURCE_PATH,
        chronology.PAIR_RUNNER_SOURCE_PATH,
    })
    module_shas = {
        path: sha(f"resident-module:{path}\n".encode("ascii"))
        for path in module_paths
    }
    build = {"build_id": "research-build", "rustc": "1.99.0"}
    build_sha = sha(canonical(build))
    for index, host in enumerate(hosts):
        files = [{"path": path, "kind": "file", "mode": "100644",
                  "sha256": module_shas[path],
                  "size": len(f"resident-module:{path}\n".encode("ascii"))}
                 for path in module_paths]
        tree_sha = sha(canonical({
            "schema": archive.SOURCE_INVENTORY_SCHEMA_V1,
            "entries": files,
        }))
        doc = {
            "schema": archive.SOURCE_MANIFEST_SCHEMA_V5,
            "manifest_sha256": ("0" * 64),
            "source": {"git_commit": ("a" if index == 0 else "b") * 40,
                       "source_tree_sha256": tree_sha, "files": files},
            "build": build,
            "resource_domain_calibration": {
                "build": build, "build_sha256": build_sha,
            },
        }
        doc["manifest_sha256"] = sha(canonical({
            key: value for key, value in doc.items()
            if key != "manifest_sha256"
        }))
        source_docs[host] = doc
        source_pins[host] = {
            "path": f"/origin/{host}-source.json",
            "raw_sha256": ("c" if index == 0 else "d") * 64,
            "semantic_sha256": doc["manifest_sha256"],
        }
    protocol = {"schema": "synthetic-protocol.v1", "version": 1}
    spec_hosts = []
    observed_documents = {}
    observed_raw = {}
    for index, host in enumerate(hosts):
        controls = {
            "cpu_limit": 8 * (index + 1),
            "memory_limit": 1024 * (index + 1),
            "kernel_release": f"linux-7.0-fixture-{index}",
            "cpu_model": f"fixture-cpu-{index}",
        }
        controls_sha = sha(canonical(controls))
        spec_hosts.append({
            "host_id": host,
            "host_fingerprint_sha256": controls_sha,
            "controls": controls,
        })
        observed_documents[host] = {
            "schema": "allocatbelt.application-capacity-host-context.v1",
            "host_id": host,
            "boot_id_sha256": ("a" if index == 0 else "b") * 64,
            "controls_sha256": controls_sha,
            "controls": controls,
            "kernel_release": controls["kernel_release"],
            "cpu_model": controls["cpu_model"],
            "cpu_affinity": [index * 2, index * 2 + 1],
            "network_namespace_inode": 1001 + index,
        }
        observed_raw[host] = canonical(observed_documents[host])
    spec = {"schema": "allocatbelt.application-campaign-spec.v3",
            "campaign_id": campaign_id, "protocol": protocol,
            "hosts": spec_hosts}
    spec_raw = canonical(spec)
    spec_pin = pin("/origin/final-spec.json", spec_raw, sha(spec_raw))
    plan_body = {"schema": "allocatbelt.application-campaign-plan.v3",
                 "campaign_id": campaign_id, "jobs": {}}
    plan = {**plan_body, "plan_sha256": sha(canonical(plan_body))}
    plan_raw = canonical(plan)
    plan_pin = pin("/origin/final-plan.json", plan_raw, plan["plan_sha256"])
    width_raw = canonical({"schema": "synthetic-width-document.v1"})
    width_pin = pin("/origin/host-a-width.json", width_raw, sha(width_raw))
    execution = {
        "schema": archive.PREPARED_EXPLORATION_EXECUTION_SCHEMA,
        "campaign_id": campaign_id, "hosts": hosts,
        "original_inputs": {
            "spec": {"artifact": {"path": spec_pin["path"],
                                   "raw_sha256": spec_pin["raw_sha256"]},
                     "semantic_sha256": spec_pin["semantic_sha256"]},
            "plan": {"artifact": {"path": plan_pin["path"],
                                   "raw_sha256": plan_pin["raw_sha256"]},
                     "semantic_sha256": plan_pin["semantic_sha256"]},
            "source_manifests": {
                host: {"artifact": {"path": source_pins[host]["path"],
                                     "raw_sha256": source_pins[host]["raw_sha256"]},
                       "semantic_sha256": source_pins[host]["semantic_sha256"]}
                for host in hosts
            },
            "campaign_artifacts_root": "/origin/campaign-artifacts",
        },
        "execution_sources": {
            host: {
                "source_root": (str(SCRIPT_DIR.parent.resolve()) if host == "host-a"
                                else f"/historical/{host}/source"),
                "git_commit": source_docs[host]["source"]["git_commit"],
                "source_tree_sha256": source_docs[host]["source"]["source_tree_sha256"],
                "build_sha256": build_sha,
            }
            for host in hosts
        },
        "modules": {
            host: {
                path: {"path": path, "sha256": module_shas[path]}
                for path in module_paths
            }
            for host in hosts
        },
        "observed_hosts": {
            host: {
                "artifact": {
                    "path": f"/origin/{host}-observed.json",
                    "raw_sha256": sha(observed_raw[host]),
                },
                "host_fingerprint_sha256": next(
                    row["host_fingerprint_sha256"] for row in spec_hosts
                    if row["host_id"] == host
                ),
                "controls_sha256": observed_documents[host]["controls_sha256"],
            }
            for host in hosts
        },
        "artifact_root": "/origin/artifacts", "output_root": "/origin/output",
        "phase_order": list(source5_campaign.PHASE_ORDER),
        "protocol_sha256": sha(canonical(protocol)),
        "qualification_eligible": False,
        "scope": archive.PREPARED_EXPLORATION_SCOPE,
        "prepared_input_generation": {
            "completion": pin("/origin/prepared-completion.json", b"completion\n"),
            "provenance": {
                "schema": "allocatbelt.application-source5-prepared-inputs-provenance.v2",
                "exploration_lineage": {
                    host: {
                        "bridge_header": {"path": f"/old/{host}/header.json",
                                          "raw_sha256": ("5" if host == "host-a" else "6") * 64},
                        "record_index": {"path": f"/old/{host}/index.jsonl",
                                         "raw_sha256": ("7" if host == "host-a" else "8") * 64},
                    }
                    for host in hosts
                },
            },
        },
        "prepared_capacity_registration": {
            "completion": pin("/origin/prepared-completion.json", b"completion\n"),
            "host_completion": pin("/origin/host-completion.json", b"host completion\n"),
            "host_verification": pin("/origin/host-verification.json", b"host verification\n"),
            "ledger": pin("/origin/capacity-ledger.jsonl", b"ledger\n"),
            "capacity_schedule_sha256": "9" * 64,
            "registration_head": "a" * 64,
        },
        "archive_signer_contexts": {
            host: {"artifact": {"path": f"/origin/{host}-signer.json",
                                 "raw_sha256": ("b" if host == "host-a" else "c") * 64},
                   "semantic_sha256": ("d" if host == "host-a" else "e") * 64}
            for host in hosts
        },
        "journal_width_contracts": {
            host: {"artifact": {"path": width_pin["path"] if host == "host-a"
                                         else f"/origin/{host}-width.json",
                                 "raw_sha256": width_pin["raw_sha256"] if host == "host-a"
                                               else "f" * 64},
                   "semantic_sha256": width_pin["semantic_sha256"] if host == "host-a"
                                      else "1" * 64}
            for host in hosts
        },
    }
    execution["manifest_sha256"] = sha(canonical(execution))
    execution_raw = canonical(execution)
    execution_pin = pin("/origin/final-execution.json", execution_raw,
                        execution["manifest_sha256"])
    budget = {name: None for name in archive.HOST_BUDGET_FIELDS_V3}
    budget.update({
        "schema": archive.HOST_BUDGET_SCHEMA_V4,
        "admission_profile": archive.PREPARED_EXPLORATION_ADMISSION_PROFILE,
        "execution_manifest_schema": archive.PREPARED_EXPLORATION_EXECUTION_SCHEMA,
        "campaign_id": campaign_id, "host_id": "host-a",
        "original_pins": {
            "spec": spec_pin, "plan": plan_pin,
            "execution_manifest": execution_pin,
            "source_manifests": source_pins,
            "source_tree_sha256": source_docs["host-a"]["source"]["source_tree_sha256"],
            "prepared_exploration": execution["prepared_input_generation"][
                "provenance"]["exploration_lineage"],
        },
        "journal_width_contract_pin": width_pin,
    })
    return {
        "budget": budget, "context": {"campaign_id": campaign_id,
                                         "host_id": "host-a"},
        "source_docs": source_docs, "source_pins": source_pins,
        "selected_source_doc": source_docs["host-a"],
        "spec": spec,
        "execution": execution, "execution_raw": execution_raw,
        "execution_pin": execution_pin,
        "observed_documents": observed_documents,
        "observed_raw": observed_raw,
        "spec_raw": spec_raw, "plan_raw": plan_raw,
        "width_raw": width_raw,
    }


def invoke_execution_join(case: dict[str, object], execution: dict[str, object],
                          execution_raw: bytes):
    return archive._prepared_execution_manifest(
        execution_raw, case["execution_pin"], case["budget"], case["context"],
        case["source_docs"], case["selected_source_doc"], case["source_pins"],
        case["plan_raw"], case["spec_raw"], case["width_raw"],
    )


def call_archive_profile(case: dict[str, object], *, context=None,
                         source_raw=None, budget_raw=None):
    return archive.validate_prepared_exploration_budget_profile_v1(
        case["budget_raw"] if budget_raw is None else budget_raw,
        case["context"] if context is None else context,
        source_manifest_raw=case["source_raw"] if source_raw is None else source_raw,
        execution_manifest_raw=b"{}\n", plan_raw=b"{}\n",
        journal_width_contract_raw=b"{}\n", spec_raw=b"{}\n",
        lineage_capture_manifest_raw=b"{}\n",
        lineage_capture_stage_root="/private/capture-not-opened",
    )


def make_private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)
    return path


def capture_manifest(objects: list[dict[str, object]]) -> bytes:
    return canonical({
        "schema": capture.CAPTURE_MANIFEST_SCHEMA,
        "objects": objects,
    })


class PreparedProfileFailClosedTests(unittest.TestCase):
    def test_ready_looking_v4_host_still_refuses_v3_admission_before_launch(self) -> None:
        context = types.SimpleNamespace(
            scope="final_frozen", host_id="host-ready",
            manifest={"schema": source5_campaign.EXECUTION_SCHEMA_V4,
                      "campaign_id": "campaign-ready"},
            prepared_input_completion={"complete": True},
            journal_width_contract={"schema": "synthetic-ready-width"},
            journal_width_contract_pin={
                "path": "/private/ready-width.json", "raw_sha256": "a" * 64,
            },
        )
        owners = (
            "run_host", "run_fixed_phase", "run_pressure_phase",
            "run_soak_phase", "analyze_phase", "finalize_host_evidence",
        )
        with self.subTest(boundary="SourceA6 unconditional refusal"), \
                mock.patch.multiple(
                    source5_campaign,
                    **{name: mock.DEFAULT for name in owners},
                ) as patched:
            with self.assertRaisesRegex(
                    source5_campaign.Source5CampaignError,
                    "Source5 v3 execution admission is refused until the selected Source epoch verifies the original prepared-exploration bridge",
            ):
                source5_campaign.activate_source5_host_evidence_budget_v3(
                    context, Path("/private/pressure-index.json"),
                    Path("/private/soak-index.json"),
                    Path("/private/storage-reservation.json"),
                )
            for owner in patched.values():
                owner.assert_not_called()

    def test_h6_budget_exports_the_exact_v4_v5_profile_api(self) -> None:
        self.assertEqual(
            budget_algorithm.SOURCE5_PREPARED_EXPLORATION_ADMISSION_PROFILE,
            archive.PREPARED_EXPLORATION_ADMISSION_PROFILE,
        )
        self.assertEqual(budget_algorithm.EXECUTION_SCHEMA_V5,
                         archive.PREPARED_EXPLORATION_EXECUTION_SCHEMA)
        self.assertTrue(callable(budget_algorithm.validate_host_evidence_budget_v4))
        self.assertTrue(callable(budget_algorithm.required_archive_request_schema_v1))

    def test_source_context_pin_tamper_fails_before_any_source_fallback(self) -> None:
        case = budget_case()
        changed = json.loads(canonical(case["context"]))
        changed["source_manifest_pin"]["raw_sha256"] = "f" * 64
        with self.assertRaises(archive.EvidenceArchiveError):
            call_archive_profile(case, context=changed)

    def test_tampered_primary_source_bytes_fail_before_capture_reads(self) -> None:
        case = budget_case()
        with self.assertRaisesRegex(archive.EvidenceArchiveError, "raw pin"):
            call_archive_profile(case, source_raw=b"{} \n")

    def test_spec_pin_alias_fails_the_exact_six_pin_closure(self) -> None:
        case = budget_case()
        budget = json.loads(canonical(case["budget"]))
        budget["original_pins"]["spec"] = dict(
            budget["original_pins"]["plan"],
        )
        body = {key: value for key, value in budget.items()
                if key != "budget_sha256"}
        budget["budget_sha256"] = sha(canonical(body))
        raw = canonical(budget)
        changed_context = json.loads(canonical(case["context"]))
        changed_context["resource_budget_pin"] = pin(
            case["budget_pin"]["path"], raw, budget["budget_sha256"],
        )
        with self.assertRaisesRegex(archive.EvidenceArchiveError, "alias"):
            call_archive_profile(case, context=changed_context, budget_raw=raw)

    def test_packet_v4_limits_require_explicit_six_copy_and_capture_inputs(self) -> None:
        case = budget_case()
        with self.assertRaisesRegex(
                packet.TransferPacketError,
                "requires its captured lineage manifest"):
            packet._budget_limits_with_archive_profile(
                case["budget_raw"], case["budget_pin"],
                "campaign-a", "host-a", budget_context=case["context"],
            )

    def test_archive_profile_accepts_no_caller_reader_or_proof_authority(self) -> None:
        names = set(inspect.signature(
            archive.validate_prepared_exploration_budget_profile_v1,
        ).parameters)
        self.assertNotIn("lineage_artifact_reader", names)
        self.assertNotIn("proofs_by_host", names)
        self.assertNotIn("declaration", names)


class PreparedBootstrapCaptureTests(unittest.TestCase):
    def test_bootstrap_reads_only_raw_pin_projection_under_requested_cap(self) -> None:
        payload = b"captured-source-manifest\n"
        with tempfile.TemporaryDirectory(prefix="v5-bootstrap-pin-") as tmp:
            root = make_private_directory(Path(tmp) / "stage")
            directory = make_private_directory(root / "objects")
            local = directory / "source.json"
            local.write_bytes(payload)
            local.chmod(0o400)
            origin = {
                "path": "/old/host-a/source.json", "raw_sha256": sha(payload),
            }
            manifest_raw = capture_manifest([{
                "origin_pin": origin, "local_relative_path": "objects/source.json",
                "byte_count": len(payload),
            }])
            reader, _manifest = archive._prepared_bootstrap_capture_reader(
                capture.__dict__, manifest_raw, str(root),
                ["host-a", "host-b"], 1024,
            )
            try:
                self.assertEqual(reader.read(origin, 1024), payload)
                with self.assertRaises(archive.EvidenceArchiveError):
                    reader.read({**origin, "semantic_sha256": "a" * 64}, 1024)
                with self.assertRaises(archive.EvidenceArchiveError):
                    reader.read(origin, len(payload) - 1)
            finally:
                reader.close()

    def test_oversized_sparse_manifest_object_is_refused_before_payload_read(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v5-bootstrap-sparse-") as tmp:
            root = make_private_directory(Path(tmp) / "stage")
            directory = make_private_directory(root / "objects")
            sparse = directory / "oversized.bin"
            with sparse.open("wb") as stream:
                stream.truncate(archive.PREPARED_CAPTURE_BOOTSTRAP_MAX_BYTES + 1)
            sparse.chmod(0o400)
            manifest_raw = capture_manifest([{
                "origin_pin": {"path": "/old/host-a/oversized.bin",
                               "raw_sha256": "a" * 64},
                "local_relative_path": "objects/oversized.bin",
                "byte_count": archive.PREPARED_CAPTURE_BOOTSTRAP_MAX_BYTES + 1,
            }])
            with mock.patch.object(archive.os, "read",
                                   side_effect=AssertionError("payload read attempted")):
                with self.assertRaisesRegex(archive.EvidenceArchiveError,
                                            "Source role cap"):
                    archive._prepared_bootstrap_capture_reader(
                        capture.__dict__, manifest_raw, str(root),
                        ["host-a", "host-b"],
                        archive.PREPARED_CAPTURE_BOOTSTRAP_MAX_BYTES,
                    )

    def test_unknown_sparse_extra_is_rejected_during_metadata_only_scan(self) -> None:
        payload = b"known\n"
        with tempfile.TemporaryDirectory(prefix="v5-bootstrap-extra-") as tmp:
            root = make_private_directory(Path(tmp) / "stage")
            directory = make_private_directory(root / "objects")
            known = directory / "known.bin"
            known.write_bytes(payload)
            known.chmod(0o400)
            extra = directory / "unlisted-sparse.bin"
            with extra.open("wb") as stream:
                stream.truncate(512 * 1024 * 1024)
            extra.chmod(0o400)
            manifest_raw = capture_manifest([{
                "origin_pin": {"path": "/old/host-a/known.bin",
                               "raw_sha256": sha(payload)},
                "local_relative_path": "objects/known.bin",
                "byte_count": len(payload),
            }])
            with mock.patch.object(archive.os, "read",
                                   side_effect=AssertionError("payload read attempted")):
                with self.assertRaisesRegex(archive.EvidenceArchiveError,
                                            "undeclared entry"):
                    archive._prepared_bootstrap_capture_reader(
                        capture.__dict__, manifest_raw, str(root),
                        ["host-a", "host-b"], 1024,
                    )


class SourceWidthProjectionTests(unittest.TestCase):
    def test_resident_wrapper_matches_pure_observation_projection(self) -> None:
        controls = {"cpu_limit": 8, "memory_limit": 1024}
        observed = {
            "boot_id_sha256": "a" * 64,
            "controls_sha256": sha(canonical(controls)),
            "controls": controls, "cpu_affinity": [0, 2],
            "network_namespace_inode": 4242,
        }
        observed_raw = canonical(observed)
        observed_sha = sha(observed_raw)
        host_ids = ["host-a", "host-b"]
        source_pins = {
            host: {
                "path": f"/inputs/{host}-source.json",
                "raw_sha256": ("b" if host == "host-a" else "c") * 64,
                "semantic_sha256": ("d" if host == "host-a" else "e") * 64,
            }
            for host in host_ids
        }
        source_values = {
            host: {
                "manifest_sha256": source_pins[host]["semantic_sha256"],
                "source": {"source_tree_sha256": ("f" if host == "host-a" else "0") * 64},
            }
            for host in host_ids
        }
        module_paths = (
            "scripts/application-campaign.py",
            "scripts/application-campaign-inputs.py",
            "scripts/application-feedback-readback.py",
            "scripts/application-byte-capacity.py",
            chronology.CAPACITY_STAGE_SOURCE_PATH,
            chronology.CHRONOLOGY_SOURCE_PATH,
            chronology.PAIR_RUNNER_SOURCE_PATH,
        )
        module_map = {
            path: {"path": path, "sha256": sha(path.encode("ascii"))}
            for path in module_paths
        }
        spec_pin = {
            "path": "/inputs/final-spec.json", "raw_sha256": "1" * 64,
            "semantic_sha256": "2" * 64,
        }
        plan_pin = {
            "path": "/inputs/final-plan.json", "raw_sha256": "3" * 64,
            "semantic_sha256": "4" * 64,
        }
        with tempfile.TemporaryDirectory(prefix="v5-width-projection-") as tmp:
            observed_path = Path(tmp) / "observed-host.json"
            context = types.SimpleNamespace(
                observed_host_pin={"path": str(observed_path),
                                   "raw_sha256": observed_sha},
                manifest={
                    "campaign_id": "campaign-a", "hosts": host_ids,
                    "modules": {"host-a": module_map},
                },
                host_id="host-a", spec_pin=spec_pin,
                spec_semantic_sha256=spec_pin["semantic_sha256"],
                plan_pin=plan_pin,
                plan_semantic_sha256=plan_pin["semantic_sha256"],
                source_manifest_pins=source_pins, sources=source_values,
                chronology=chronology, journal_width_original_pins=None,
            )
            pure = source5_campaign.build_source5_original_pins_from_observed_v1(
                context, observed, observed_sha,
            )
            chronology._validate_chronology_original_pins(pure)
            observed_path.write_bytes(observed_raw)
            observed_path.chmod(0o600)
            resident = source5_campaign._source5_original_pins_for_context(context)
            self.assertEqual(resident, pure)


class SourceModuleIdentityTests(unittest.TestCase):
    def test_typed_campaign_module_is_registered_before_dataclass_execution(self) -> None:
        module_path = archive.PREPARED_CAMPAIGN_SOURCE_PATH
        source_path = SCRIPT_DIR / "application-source5-campaign.py"
        module_raw = source_path.read_bytes()
        info = source_path.stat(follow_symlinks=False)
        mode = f"{stat.S_IFMT(info.st_mode) | stat.S_IMODE(info.st_mode):06o}"
        module_sha = sha(module_raw)
        files = [{"path": module_path, "kind": "file", "mode": mode,
                  "sha256": module_sha, "size": len(module_raw)}]
        tree_sha = sha(canonical({
            "schema": archive.SOURCE_INVENTORY_SCHEMA_V1, "entries": files,
        }))
        source = {
            "schema": archive.SOURCE_MANIFEST_SCHEMA_V5,
            "source": {"git_commit": "a" * 40,
                       "source_tree_sha256": tree_sha, "files": files},
            "build": {},
        }
        source["manifest_sha256"] = sha(canonical(source))
        source_raw = canonical(source)
        source_pin = pin("/captured/source-manifest.json", source_raw,
                         source["manifest_sha256"])
        execution = {
            "schema": archive.PREPARED_EXPLORATION_EXECUTION_SCHEMA,
            "campaign_id": "campaign-module-load", "hosts": ["host-a"],
            "original_inputs": {"source_manifests": {
                "host-a": {"artifact": {
                    "path": source_pin["path"],
                    "raw_sha256": source_pin["raw_sha256"],
                }, "semantic_sha256": source_pin["semantic_sha256"]},
            }},
            "modules": {"host-a": {module_path: {
                "path": module_path, "sha256": module_sha,
            }}},
        }
        execution["manifest_sha256"] = sha(canonical(execution))
        execution_raw = canonical(execution)
        execution_pin = pin("/captured/execution-v5.json", execution_raw,
                            execution["manifest_sha256"])
        namespace = archive._prepared_typed_module(
            source_raw, execution_raw,
            {"campaign_id": execution["campaign_id"], "host_id": "host-a",
             "source_manifest_pin": source_pin,
             "execution_manifest_pin": execution_pin},
            module_path,
        )
        module = sys.modules[namespace["__name__"]]
        self.assertIsInstance(module, types.ModuleType)
        self.assertIs(module.__dict__, namespace)
        self.assertTrue(dataclasses.is_dataclass(module.CampaignContext))
        self.assertEqual(module.CampaignContext.__module__, module.__name__)
        self.assertEqual(module.__source5_typed_pin__, {
            "path": module_path, "sha256": module_sha,
        })


class FinalExecutionJoinTests(unittest.TestCase):
    @staticmethod
    def reseal(case, mutate):
        changed = copy.deepcopy(case["execution"])
        mutate(changed)
        changed["manifest_sha256"] = sha(canonical({
            key: value for key, value in changed.items()
            if key != "manifest_sha256"
        }))
        raw = canonical(changed)
        changed_case = copy.deepcopy(case)
        changed_pin = pin(case["execution_pin"]["path"], raw,
                          changed["manifest_sha256"])
        changed_case["execution_pin"] = changed_pin
        changed_case["budget"]["original_pins"]["execution_manifest"] = changed_pin
        changed_case["execution"] = changed
        changed_case["execution_raw"] = raw
        return changed_case

    def test_final_execution_joins_both_hosts_without_peer_code_execution(self) -> None:
        case = execution_join_case()
        execution, _spec, _plan, _width = invoke_execution_join(
            case, case["execution"], case["execution_raw"],
        )
        self.assertEqual(execution, case["execution"])

    def test_execution_phase_order_matches_sourceh_exact_eight_phase_contract(self) -> None:
        expected = (
            "exploration", "aa", "confirmation", "fixed_analysis", "pressure",
            "pressure_analysis", "soak", "final_analysis",
        )
        self.assertEqual(tuple(source5_campaign.PHASE_ORDER), expected)

        case = execution_join_case()
        self.assertEqual(case["execution"]["phase_order"], list(expected))
        execution, _spec, _plan, _width = invoke_execution_join(
            case, case["execution"], case["execution_raw"],
        )
        self.assertEqual(execution["hosts"], ["host-a", "host-b"])
        self.assertEqual(execution, case["execution"])

        obsolete_six = [
            "exploration", "aa", "confirmation", "fixed_analysis",
            "pressure", "soak",
        ]
        variants = (
            ("obsolete six-phase order", lambda value: value.update({
                "phase_order": obsolete_six,
            })),
            ("missing pressure analysis", lambda value: value.update({
                "phase_order": [
                    phase for phase in value["phase_order"]
                    if phase != "pressure_analysis"
                ],
            })),
            ("reordered analysis phase", lambda value: value.update({
                "phase_order": [
                    "exploration", "aa", "confirmation", "fixed_analysis",
                    "pressure", "soak", "pressure_analysis", "final_analysis",
                ],
            })),
            ("duplicated analysis phase", lambda value: value.update({
                "phase_order": [
                    "exploration", "aa", "confirmation", "fixed_analysis",
                    "pressure", "pressure_analysis", "pressure_analysis",
                    "soak", "final_analysis",
                ],
            })),
        )
        for label, mutate in variants:
            with self.subTest(phase_order=label):
                changed = self.reseal(case, mutate)
                with self.assertRaisesRegex(
                        archive.EvidenceArchiveError,
                        "phase order differs from Source5 V5"):
                    invoke_execution_join(
                        changed, changed["execution"], changed["execution_raw"],
                    )

    def test_resealed_peer_module_mutation_is_rejected(self) -> None:
        case = execution_join_case()
        changed = self.reseal(case, lambda value: value["modules"]["host-b"][
            "scripts/application-campaign.py"].update({"sha256": "f" * 64}))
        with self.assertRaisesRegex(archive.EvidenceArchiveError,
                                    "module map differs"):
            invoke_execution_join(changed, changed["execution"],
                                  changed["execution_raw"])

    def test_resealed_peer_build_snapshot_mutation_is_rejected(self) -> None:
        case = execution_join_case()
        changed = self.reseal(case, lambda value: value["execution_sources"][
            "host-b"].update({"build_sha256": "e" * 64}))
        with self.assertRaisesRegex(archive.EvidenceArchiveError,
                                    "Source/build snapshot"):
            invoke_execution_join(changed, changed["execution"],
                                  changed["execution_raw"])

    def test_resealed_protocol_digest_mutation_is_rejected(self) -> None:
        case = execution_join_case()
        changed = self.reseal(case, lambda value: value.update({
            "protocol_sha256": "f" * 64,
        }))
        with self.assertRaisesRegex(archive.EvidenceArchiveError,
                                    "protocol digest differs"):
            invoke_execution_join(changed, changed["execution"],
                                  changed["execution_raw"])


    def test_resealed_observed_wrapper_requires_the_exact_three_field_contract(self) -> None:
        case = execution_join_case()
        variants = (
            ("extra semantic alias", lambda value: value["observed_hosts"][
                "host-a"].update({"semantic_sha256": "e" * 64})),
            ("missing controls digest", lambda value: value["observed_hosts"][
                "host-a"].pop("controls_sha256")),
        )
        for label, mutate in variants:
            with self.subTest(wrapper=label):
                changed = self.reseal(case, mutate)
                with self.assertRaisesRegex(
                        archive.EvidenceArchiveError, "unexpected field set"):
                    invoke_execution_join(
                        changed, changed["execution"], changed["execution_raw"],
                    )

    def test_resealed_peer_observed_fingerprint_cannot_cross_spec_hosts(self) -> None:
        case = execution_join_case()

        def cross_fingerprint(value):
            value["observed_hosts"]["host-b"]["host_fingerprint_sha256"] = \
                value["observed_hosts"]["host-a"]["host_fingerprint_sha256"]

        changed = self.reseal(case, cross_fingerprint)
        with self.assertRaisesRegex(
                archive.EvidenceArchiveError,
                "fingerprint differs from immutable final Spec"):
            invoke_execution_join(
                changed, changed["execution"], changed["execution_raw"],
            )


class CapturedObservedHostJoinTests(unittest.TestCase):
    @staticmethod
    def capture_reader(case, root: Path):
        stage = make_private_directory(root / "stage")
        objects = make_private_directory(stage / "observed")
        rows = []
        for host in case["execution"]["hosts"]:
            wrapper = case["execution"]["observed_hosts"][host]
            raw = case["observed_raw"][host]
            local = f"observed/{host}.json"
            path = stage / local
            path.write_bytes(raw)
            path.chmod(0o400)
            rows.append({
                "origin_pin": wrapper["artifact"],
                "local_relative_path": local,
                "byte_count": len(raw),
            })
        reader, _manifest = archive._prepared_bootstrap_capture_reader(
            capture.__dict__, capture_manifest(rows), str(stage),
            case["execution"]["hosts"], archive.PREPARED_CAPTURE_BOOTSTRAP_MAX_BYTES,
        )
        return reader

    @staticmethod
    def source_dto(case, execution, host, joined):
        context = types.SimpleNamespace(
            observed_host_pin=joined["pin"], manifest=execution, host_id=host,
            chronology=chronology,
            spec_pin=case["budget"]["original_pins"]["spec"],
            spec_semantic_sha256=case["budget"]["original_pins"]["spec"][
                "semantic_sha256"],
            plan_pin=case["budget"]["original_pins"]["plan"],
            plan_semantic_sha256=case["budget"]["original_pins"]["plan"][
                "semantic_sha256"],
            source_manifest_pins=case["source_pins"],
            sources=case["source_docs"],
        )
        value = source5_campaign.build_source5_original_pins_from_observed_v1(
            context, joined["value"], sha(joined["raw"]),
        )
        return chronology._validate_chronology_original_pins(value)

    def test_real_captured_observed_bytes_join_spec_and_source_dto(self) -> None:
        case = execution_join_case()
        with tempfile.TemporaryDirectory(prefix="v5-observed-capture-") as tmp:
            reader = self.capture_reader(case, Path(tmp))
            try:
                for host in case["execution"]["hosts"]:
                    joined = archive._prepared_observed_host_dto(
                        case["execution"], case["spec"], host, reader.read,
                        archive.PREPARED_CAPTURE_BOOTSTRAP_MAX_BYTES,
                    )
                    self.assertEqual(joined["raw"], case["observed_raw"][host])
                    self.assertEqual(joined["dto"]["path"],
                                     case["execution"]["observed_hosts"][host][
                                         "artifact"]["path"])
                    source_dto = self.source_dto(
                        case, case["execution"], host, joined,
                    )
                    self.assertEqual(source_dto["observed_host"], {
                        **joined["dto"],
                        "controls": case["observed_documents"][host]["controls"],
                        "cpu_affinity": case["observed_documents"][host][
                            "cpu_affinity"],
                        "network_namespace_inode": case["observed_documents"][host][
                            "network_namespace_inode"],
                    })
            finally:
                reader.close()

    def test_resealed_controls_digest_must_match_captured_observed_bytes(self) -> None:
        case = execution_join_case()

        def change_controls(value):
            value["observed_hosts"]["host-a"]["controls_sha256"] = "f" * 64

        changed = FinalExecutionJoinTests.reseal(case, change_controls)
        invoke_execution_join(
            changed, changed["execution"], changed["execution_raw"],
        )
        with tempfile.TemporaryDirectory(prefix="v5-observed-control-capture-") as tmp:
            reader = self.capture_reader(case, Path(tmp))
            try:
                with self.assertRaisesRegex(
                        archive.EvidenceArchiveError,
                        "bytes differ from their raw/control pins"):
                    archive._prepared_observed_host_dto(
                        changed["execution"], changed["spec"], "host-a",
                        reader.read,
                        archive.PREPARED_CAPTURE_BOOTSTRAP_MAX_BYTES,
                    )
            finally:
                reader.close()

    def test_resealed_captured_controls_cannot_cross_the_immutable_spec(self) -> None:
        case = execution_join_case()
        changed_case = copy.deepcopy(case)
        observed = changed_case["observed_documents"]["host-a"]
        spec_host = next(
            row for row in changed_case["spec"]["hosts"]
            if row["host_id"] == "host-a"
        )
        original_spec_controls = copy.deepcopy(spec_host["controls"])
        observed["controls"] = copy.deepcopy(observed["controls"])
        self.assertIsNot(observed["controls"], spec_host["controls"])
        observed["controls"]["memory_limit"] += 1
        self.assertEqual(spec_host["controls"], original_spec_controls)
        observed["controls_sha256"] = sha(canonical(observed["controls"]))
        changed_case["observed_raw"]["host-a"] = canonical(observed)
        changed_raw_sha = sha(changed_case["observed_raw"]["host-a"])

        def reseal_changed_observed(value):
            value["observed_hosts"]["host-a"]["artifact"][
                "raw_sha256"] = changed_raw_sha
            value["observed_hosts"]["host-a"]["controls_sha256"] = \
                observed["controls_sha256"]

        changed_case = FinalExecutionJoinTests.reseal(
            changed_case, reseal_changed_observed,
        )
        invoke_execution_join(
            changed_case, changed_case["execution"],
            changed_case["execution_raw"],
        )
        with tempfile.TemporaryDirectory(prefix="v5-observed-spec-controls-") as tmp:
            reader = self.capture_reader(changed_case, Path(tmp))
            try:
                with self.assertRaisesRegex(
                        archive.EvidenceArchiveError,
                        "bytes differ from their raw/control pins"):
                    archive._prepared_observed_host_dto(
                        changed_case["execution"], changed_case["spec"],
                        "host-a", reader.read,
                        archive.PREPARED_CAPTURE_BOOTSTRAP_MAX_BYTES,
                    )
            finally:
                reader.close()


class CapturedCatalogueParityTests(unittest.TestCase):
    @staticmethod
    def row(path, role, maximum, *, host_id, owner, phase=None, run_id=None,
            storage_root=None, origin_pin=None):
        return {
            "path": path, "kind": "file", "role": role,
            "host_id": host_id, "max_bytes": maximum,
            "max_file_bytes": maximum, "max_inodes": 1,
            "storage_root": storage_root, "owner": owner,
            "phase": phase, "run_id": run_id,
            "member_index": None, "aggregate_id": None,
            "aggregate_max_bytes": None, "origin_pin": origin_pin,
        }

    def catalogue(self, directory: Path, *, include_capacity_artifact: bool):
        directory.mkdir(mode=0o700)
        rows = [
            self.row(
                "/private/output/job-records/run-a.json", "source5_job_record", 128,
                host_id="host-a", owner="fixed_pair", phase="confirmation",
                run_id="run-a", storage_root="/private/output",
            ),
            self.row(
                "/private/artifacts/run-a/output.json", "normal_app_output", 17,
                host_id="host-a", owner="fixed_pair", phase="confirmation",
                run_id="run-a", storage_root="/private/artifacts",
            ),
        ]
        # Let the actual Source algorithm derive the complete transport roles
        # for this catalogue-only job before publishing real catalogue chunks.
        caps_by_job = budget_algorithm._project_prepared_source5_archive_caps(
            rows, readback=False,
        )
        transport_roles = (
            ("source5_checkpoint_request", "checkpoint_request_bytes"),
            ("source5_transfer_offer", "transfer_offer_bytes"),
            ("source5_transfer_packet", "transfer_packet_bytes"),
            ("source5_ack_bundle", "ack_bundle_bytes"),
            ("source5_ack_bundle_incoming", "ack_bundle_bytes"),
            ("source5_checkpoint", "checkpoint_bytes"),
            ("source5_object_manifest", "object_manifest_bytes"),
            ("source5_archive_ack", "archive_ack_bytes"),
            ("source5_archive_signature", "signature_bytes"),
            ("source5_stage_map", "stage_map_bytes"),
        )
        for (phase, run_id), caps in caps_by_job.items():
            for role, cap_field in transport_roles:
                rows.append(self.row(
                    f"/private/output/transport/{run_id}-{role}.bin",
                    role, caps[cap_field], host_id="host-a", owner="fixed_pair",
                    phase=phase, run_id=run_id, storage_root="/private/output",
                ))
        raw = b"capacity metadata\n"
        capacity_row = self.row(
            "/old/host-a/capacity-artifact.json", "capacity_artifact", len(raw),
            host_id="host-a", owner="inputs",
            origin_pin={"raw_sha256": sha(raw), "semantic_sha256": None},
        )
        if include_capacity_artifact:
            rows.append(capacity_row)
        manifest = budget_algorithm.write_fixed_pair_v3_path_catalogue_chunks(
            rows, directory,
        )
        chunks = {item["path"]: Path(item["path"]).read_bytes()
                  for item in manifest["chunks"]}

        def read_chunk(path, count):
            value = chunks[path]
            if len(value) != count:
                raise AssertionError("catalogue chunk changed its exact byte count")
            return value

        return manifest, read_chunk, budget_algorithm._catalogue_row(
            capacity_row, "Source-derived auxiliary capacity row",
        )

    def test_current_catalogue_must_include_source_derived_capacity_artifact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="v5-capacity-parity-") as tmp:
            root = Path(tmp)
            complete, reader, capacity_row = self.catalogue(
                root / "complete", include_capacity_artifact=True,
            )
            budget_value = {"path_catalogue": complete}
            archive._require_prepared_catalogue_storage_parity(
                budget_algorithm, budget_value, reader, [capacity_row],
            )

            missing, reader, _capacity_row = self.catalogue(
                root / "missing", include_capacity_artifact=False,
            )
            with self.assertRaisesRegex(archive.EvidenceArchiveError,
                                        "omits a Source-derived"):
                archive._require_prepared_catalogue_storage_parity(
                    budget_algorithm, {"path_catalogue": missing},
                    reader, [capacity_row],
                )

if __name__ == "__main__":
    unittest.main()
