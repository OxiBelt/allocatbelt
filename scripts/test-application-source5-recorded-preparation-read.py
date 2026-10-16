#!/usr/bin/env python3
"""Component tests for the pure recorded-preparation read-plan projection.

The positive source-cap witness uses actual two-host SourceH path rows and
recomputes their fixed-pair readback caps through the fixture's typed Source
Budget module. It also binds the generated SourceA lineage raw2 pins and calls
the actual typed indexed-reservation helper for durable ACK/signature origins.
The V2 provenance wrapper is only a structural pin-shape witness over this
H6 fixture's initial Spec/Plan pins; it is not a completed final V5 prepared
generation. The window descriptors remain non-authorizing projections: this
test does not authenticate a signed owner window, open a payload, issue a
capability, launch an APP, or establish readiness.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
MODULE_PATH = SCRIPT_DIR / "application-source5-recorded-preparation-read.py"
SUPPORT_PATH = SCRIPT_DIR / "test-full-profile-preparatory-producer-support.py"


def load_sibling(filename: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, filename)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load test dependency {filename.name}")
    module = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


read_plan = load_sibling(
    MODULE_PATH, "source5_recorded_preparation_read_plan_tests",
)
support = load_sibling(
    SUPPORT_PATH, "source5_recorded_preparation_read_support_tests",
)
lineage_support = load_sibling(
    SCRIPT_DIR / "test-application-source5-prepared-lineage.py",
    "source5_recorded_preparation_actual_lineage_support_tests",
)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return read_plan.canonical_bytes(value)


def sealed(value: dict[str, Any], field: str) -> dict[str, Any]:
    body = {key: item for key, item in value.items() if key != field}
    return {**body, field: digest(canonical(body))}


def pin(path: str, raw: bytes, semantic: str | None = None) -> dict[str, str]:
    return {
        "path": path,
        "raw_sha256": digest(raw),
        "semantic_sha256": digest(raw) if semantic is None else semantic,
    }


def _project_actual_host_rows(view, artifacts, closed_reader) -> dict[str, Any]:
    """Project the already validated Source budget through its closed reader."""
    source_budget = artifacts["budget"]
    catalogue = source_budget["path_catalogue"]
    chunks = {row["path"]: row for row in catalogue["chunks"]}

    def read_chunk(path: str, maximum_bytes: int) -> bytes:
        pin = chunks.get(path)
        if type(pin) is not dict or maximum_bytes != pin["byte_count"]:
            raise AssertionError("closed projection requested an undeclared catalogue chunk")
        return closed_reader(
            {"path": path, "raw_sha256": pin["raw_sha256"]}, maximum_bytes,
        )

    catalogue_rows = list(
        view.budget_module.iter_fixed_pair_v3_path_catalogue_rows_with_reader(
            catalogue, read_chunk,
        ),
    )
    budget_schedule = source_budget["read_schedule"]
    actual_caps = view.budget_module.project_fixed_pair_archive_readback_caps(
        catalogue_rows,
    )
    if (len(budget_schedule) != read_plan.READ_JOB_COUNT_PER_HOST or
            len(actual_caps) != read_plan.READ_JOB_COUNT_PER_HOST or
            [row.get("job_index") for row in budget_schedule] !=
                list(range(read_plan.READ_JOB_COUNT_PER_HOST)) or
            any(row.get("job", {}).get("host_id") != view.host_id
                for row in budget_schedule)):
        raise AssertionError("validated Source budget lost its exact 360-row host schedule")
    return {
        "view": view,
        "catalogue_rows": catalogue_rows,
        "readback_caps": actual_caps,
        "budget_schedule": budget_schedule,
        "width_pin": artifacts["width_pin"],
    }

def _source_manifest_pin(view, host_id: str) -> dict[str, str]:
    return {
        "path": str(view.fixture.manifest_paths[host_id]),
        "raw_sha256": view.fixture.manifest_raw_shas[host_id],
        "semantic_sha256": view.fixture.manifests[host_id]["manifest_sha256"],
    }


def _actual_source_v2_provenance(
    view, hosts: list[str], generated_cases: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Validate a raw2 V2 wrapper assembled from actual H6-generated pins.

    This is a structural pin-shape witness. The Source H6 fixture exposes the
    initial Spec/Plan pins here; it is not a completed final prepared-input V2
    generation and proves no readiness, owner replay, or admission.
    """
    preparation = view.preparation_pin
    provenance = {
        "schema": read_plan.PREPARATION_PROVENANCE_SCHEMA_V2,
        "preparation_pin": {
            "path": preparation["path"], "raw_sha256": preparation["sha256"],
        },
        "final_spec_pin": {
            "path": view.spec_pin["path"],
            "raw_sha256": view.spec_pin["raw_sha256"],
        },
        "final_plan_pin": {
            "path": view.plan_pin["path"],
            "raw_sha256": view.plan_pin["raw_sha256"],
        },
        "exploration_lineage": {
            host: {
                "bridge_header": copy.deepcopy(
                    generated_cases[host]["generated_documents"]["header_pin"],
                ),
                "record_index": copy.deepcopy(
                    generated_cases[host]["generated_documents"]["index_pin"],
                ),
            }
            for host in hosts
        },
    }
    lineage_module = view.modules[
        "scripts/application-source5-prepared-lineage.py"
    ]
    checked = lineage_module.validate_prepared_input_provenance_v2(
        provenance, expected_hosts=hosts,
    )
    if checked != provenance:
        raise AssertionError("actual Source V2 validator changed raw-only provenance pins")
    return checked


def _make_basis(
    view, projections: dict[str, dict[str, Any]],
    provenance: dict[str, Any],
    actual_ancestors: dict[str, dict[str, Any]],
    scratch_root: Path, nonce: str, *, operation_kind: str = "registration_replay",
) -> tuple[dict[str, Any], dict[str, str]]:
    hosts = list(view.host_order)
    campaign_id = view.spec["campaign_id"]
    consumer = view.host_id
    session_root = (scratch_root / campaign_id / "source5" / consumer /
                    "recorded-preparation" / nonce)
    source_maps = {
        host: _source_manifest_pin(view, host)
        for host in hosts
    }
    module_maps = {
        host: copy.deepcopy(projections[host]["view"].module_pins)
        for host in hosts
    }
    ancestors = {
        host: {
            "bridge_header": copy.deepcopy(
                actual_ancestors[host]["bridge_header_pin"],
            ),
            "record_index": copy.deepcopy(
                actual_ancestors[host]["record_index_pin"],
            ),
        }
        for host in hosts
    }
    completion_pin = view.generation_completion
    spec_raw = view.spec_raw
    plan_raw = view.plan_raw
    basis = {
        "schema": read_plan.REPLAY_BASIS_SCHEMA_V1,
        "campaign_id": campaign_id,
        "consumer_host_id": consumer,
        "cohort_hosts": hosts,
        "operation_kind": operation_kind,
        "spec_pin": {
            "path": str(view.spec_path),
            "raw_sha256": digest(spec_raw),
            "semantic_sha256": view.spec_semantic,
        },
        "plan_pin": {
            "path": str(view.plan_path),
            "raw_sha256": digest(plan_raw),
            "semantic_sha256": view.plan_semantic,
        },
        "source_manifest_pins": source_maps,
        "source_module_pins": module_maps,
        "prepared_input_generation": {
            "completion_pin": dict(completion_pin),
            "provenance": copy.deepcopy(provenance),
        },
        "ancestor_pins": ancestors,
        "metadata_capture_manifest_pin": {
            "path": str(view.evidence_root / "closed-metadata-capture.json"),
            "raw_sha256": "9" * 64,
        },
        "width_contract_pin": dict(
            projections[consumer]["width_pin"],
        ),
        "current_roots": {
            "source_root": str(view.fixture.root),
            "input_root": str(view.fixture.input_root),
            "metadata_capture_root": str(view.evidence_root),
            "archive_root": str(view.output_root / "root-archive"),
            "artifact_root": str(view.artifact_root),
            "output_root": str(view.output_root),
            "journal_root": str(view.output_root / campaign_id /
                                 "chronology" / consumer),
        },
        "current_journal_frontier": {
            "head_sha256": "0" * 64,
            "record_count": 0,
        },
        "basis_sha256": "",
    }
    if operation_kind == "refresh_replay":
        basis["execution_manifest_pin"] = {
            "path": str(view.manifest_path),
            "raw_sha256": "b" * 64,
            "semantic_sha256": "c" * 64,
        }
        basis["registration_head"] = view.registration["registration_head"]
    basis = sealed(basis, "basis_sha256")
    basis_raw = canonical(basis)
    basis_pin = {
        "path": str(session_root / "basis.json"),
        "raw_sha256": digest(basis_raw),
        "semantic_sha256": basis["basis_sha256"],
    }
    return basis, basis_pin


def _metadata_pin(view, rows, role: str, host: str, job: dict[str, Any], *,
                  semantic: str | None = None) -> dict[str, str]:
    matches = [row for row in rows
               if row["role"] == role and row["host_id"] == host and
               row["phase"] == "exploration" and
               row["run_id"] == job["run_id"]]
    if len(matches) != 1:
        raise AssertionError(f"SourceH catalogue has no unique {role} row for {job['run_id']}")
    row = matches[0]
    origin = row["origin_pin"]
    raw_sha = (origin["raw_sha256"] if origin is not None else
               digest(canonical({
                   "schema": "recorded-read-plan-test-pin.v1",
                   "role": role, "host_id": host,
                   "run_id": job["run_id"], "path": row["path"],
               })))
    semantic_sha = (origin["semantic_sha256"] if origin is not None and
                    origin["semantic_sha256"] is not None else
                    (semantic if semantic is not None else digest(canonical({
                        "schema": "recorded-read-plan-test-semantic.v1",
                        "role": role, "host_id": host,
                        "run_id": job["run_id"],
                    }))))
    return {"path": row["path"], "raw_sha256": raw_sha,
            "semantic_sha256": semantic_sha}


def _window_metadata(
    projection: dict[str, Any], generated_case: dict[str, Any],
    old_rows_by_path: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    view = projection["view"]
    host = view.host_id
    rows = projection["catalogue_rows"]
    budget = view.budget_module
    excluded = (budget.NON_EXPORTABLE_JOB_RECORD_ROLES |
                budget.FAILURE_WINDOW_ONLY_ROLES |
                budget.ALWAYS_LOCAL_EVIDENCE_ROLES |
                budget.TRANSIENT_JOB_EVIDENCE_ROLES |
                budget.ARCHIVE_LOCAL_METADATA_ROLES |
                {"journal_width_contract"})
    result = []
    generated_rows = generated_case["rows"]
    initial_output_root = generated_case["generated_documents"]["header"][
        "initial_output_root"]
    if len(generated_rows) != read_plan.READ_JOB_COUNT_PER_HOST:
        raise AssertionError("actual SourceA lineage fixture lost an indexed job row")
    for schedule in projection["budget_schedule"]:
        job = schedule["job"]
        index = schedule["job_index"]
        run_id = job["run_id"]
        index_row = generated_rows[index]
        if index_row["job"] != job or index_row["job_sha256"] != schedule[
                "job_sha256"]:
            raise AssertionError("SourceA generated index row differs from the exact H job")
        cap = projection["readback_caps"][("exploration", run_id)]
        object_catalogue_rows = sorted((
            row for row in rows
            if row["phase"] == "exploration" and row["run_id"] == run_id and
            row["kind"] == "file" and row["role"] not in excluded
        ), key=lambda row: row["path"])
        if len(object_catalogue_rows) != cap["object_count"]:
            raise AssertionError(
                f"Source H row/object count differs for {host}/{run_id}",
            )
        archive_root = str(
            view.output_root / view.spec["campaign_id"] / host / "source5",
        )
        job_sha = schedule["job_sha256"]
        objects = []
        for row in object_catalogue_rows:
            origin = row["origin_pin"]
            raw_sha = (origin["raw_sha256"] if origin is not None else
                       digest(canonical({
                           "schema": "recorded-read-plan-object-fixture.v1",
                           "host_id": host, "run_id": run_id,
                           "path": row["path"],
                       })))
            semantic_sha = (origin["semantic_sha256"] if origin is not None
                            else None)
            object_id = read_plan._archive_read_object_id(row["path"], raw_sha)
            object_pin = {
                "path": str(Path(archive_root) / "objects" / object_id),
                "raw_sha256": raw_sha,
                "semantic_sha256": raw_sha,
                "byte_count": row["max_file_bytes"],
            }
            objects.append({
                "origin_path": row["path"], "role": row["role"],
                "object_id": object_id,
                "byte_count": row["max_file_bytes"],
                "raw_sha256": raw_sha,
                "semantic_sha256": semantic_sha,
                "object_pin": object_pin,
            })
        payload = sum(row["byte_count"] for row in objects)
        host_receipt = next(
            row for row in objects if row["role"] == "fixed_pair_host_receipt"
        )
        job_record_pin = copy.deepcopy(index_row["job_record_pin"])
        request_pin = copy.deepcopy(index_row["archive_pins"]["request_pin"])
        checkpoint_pin = copy.deepcopy(
            index_row["archive_pins"]["checkpoint_pin"],
        )
        ack_pin = copy.deepcopy(index_row["archive_pins"]["ack_pin"])
        signature_pin = copy.deepcopy(
            index_row["archive_pins"]["signature_pin"],
        )
        role_pin_names = {
            "source5_job_record": index_row["job_record_pin"],
            "source5_checkpoint_request": index_row["archive_pins"]["request_pin"],
            "source5_checkpoint": index_row["archive_pins"]["checkpoint_pin"],
            "source5_object_manifest": index_row["archive_pins"]["object_manifest_pin"],
            "source5_archive_ack": index_row["archive_pins"]["ack_pin"],
            "source5_archive_signature": index_row["archive_pins"]["signature_pin"],
        }
        indexed_reservation_bindings = {}
        for role, pin_value in role_pin_names.items():
            _indexed_pin, reservation_row = \
                budget.source5_indexed_reservation_binding_v1(
                    index_row, pin_value, role, job,
                    initial_output_root=initial_output_root,
                    campaign_id=view.spec["campaign_id"],
                    selected_host=host,
                    old_rows=old_rows_by_path,
                )
            indexed_reservation_bindings[role] = copy.deepcopy(
                reservation_row,
            )
        manifest_body = {
            "schema": "allocatbelt.application-source5-evidence-object-manifest.v1",
            "campaign_id": view.spec["campaign_id"],
            "host_id": host,
            "phase": "exploration",
            "job_index": schedule["job_index"],
            "job_ordinal": job["ordinal"],
            "job_sha256": job_sha,
            "run_id": run_id,
            "job_record_raw_sha256": job_record_pin["raw_sha256"],
            "predecessor_ack_pin": None,
            "objects": objects,
            "object_count": len(objects),
            "payload_bytes": payload,
            "manifest_sha256": "",
        }
        manifest = sealed(manifest_body, "manifest_sha256")
        manifest_raw = canonical(manifest)
        manifest_pin = {
            "path": _metadata_pin(
                view, rows, "source5_object_manifest", host, job,
            )["path"],
            "raw_sha256": digest(manifest_raw),
            "semantic_sha256": manifest["manifest_sha256"],
        }
        host_receipt_pin = {
            "path": host_receipt["origin_path"],
            "raw_sha256": host_receipt["raw_sha256"],
            "host_verification_sha256": (
                host_receipt["semantic_sha256"] or
                digest(canonical({"host_receipt": host_receipt["origin_path"]}))
            ),
        }
        if host_receipt["semantic_sha256"] is None:
            # Keep the test metadata internally joined without presenting it
            # as an actual owner receipt or verified signature.
            host_receipt["semantic_sha256"] = \
                host_receipt_pin["host_verification_sha256"]
            manifest_body = {
                **manifest_body,
                "objects": objects,
            }
            manifest = sealed(manifest_body, "manifest_sha256")
            manifest_raw = canonical(manifest)
            manifest_pin["raw_sha256"] = digest(manifest_raw)
            manifest_pin["semantic_sha256"] = manifest["manifest_sha256"]
        result.append({
            "host_id": host,
            "schedule_row": schedule,
            "job_record_pin": job_record_pin,
            "request_pin": request_pin,
            "checkpoint_pin": checkpoint_pin,
            "object_manifest_pin": manifest_pin,
            "ack_pin": ack_pin,
            "signature_pin": signature_pin,
            "host_receipt_pin": host_receipt_pin,
            "indexed_reservation_bindings": indexed_reservation_bindings,
            "archive_source5_root": archive_root,
            "manifest": manifest,
        })
    return result


class ActualH6RecordedReadPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(
            prefix="source5-recorded-read-plan-",
        )
        cls.source_fixture_class = \
            lineage_support.GeneratedH6TwoHostBridgeTests
        cls._source_fixture_started = False
        try:
            cls.source_fixture_class.setUpClass()
            cls._source_fixture_started = True
            cls.fixture = cls.source_fixture_class.fixture
            cls.hosts = list(cls.source_fixture_class.host_ids)
            cls.views = cls.source_fixture_class.views
            cls.generated_cases = cls.source_fixture_class.cases_by_host
            cls.old_rows_by_host = cls.source_fixture_class.old_rows_by_host
            cls.proofs = cls.source_fixture_class.proofs
            cls.actual_ancestors = {
                host: cls.proofs[host]["ancestor"] for host in cls.hosts
            }
            cls.projections = {
                host: _project_actual_host_rows(
                    cls.views[host], cls.source_fixture_class.artifacts_by_host[host],
                    cls.source_fixture_class.raw_reader,
                )
                for host in cls.hosts
            }
            cls.catalogues = {
                host: cls.projections[host]["catalogue_rows"]
                for host in cls.hosts
            }
            cls.readback_caps = {}
            cls.windows = {}
            for host in cls.hosts:
                projection = cls.projections[host]
                cls.readback_caps[host] = {
                    run_id: cap
                    for (phase, run_id), cap in
                    projection["readback_caps"].items()
                    if phase == "exploration"
                }
                cls.windows[host] = _window_metadata(
                    projection, cls.generated_cases[host],
                    cls.old_rows_by_host[host],
                )
            cls.consumer = cls.hosts[0]
            cls.provenance = _actual_source_v2_provenance(
                cls.views[cls.consumer], cls.hosts, cls.generated_cases,
            )
            cls.nonce = "a" * 32
            cls.scratch_root = Path(cls.temporary.name) / "recorded-read-scratch"
            filesystem = os.statvfs(cls.scratch_root.parent)
            cls.scratch = {
                "schema": read_plan.SCRATCH_DECLARATION_SCHEMA_V3,
                "root": str(cls.scratch_root),
                "device_id": cls.scratch_root.parent.stat().st_dev,
                "allocation_block_bytes": (filesystem.f_frsize or
                                            filesystem.f_bsize),
                # Explicit structural-test budget, not a filesystem measurement.
                # Production Root must supply its approved aggregate bound.
                "directory_metadata_reserve_bytes":
                    read_plan.MAX_METADATA_BYTES,
                "reserved_bytes": 1 << 40,
                "reserved_inodes": 1 << 20,
            }
            cls.timeouts = {
                "maximum_io_window_seconds": 120,
                "maximum_operation_seconds": 24 * 60 * 60,
            }
            cls.basis, cls.basis_pin = _make_basis(
                cls.views[cls.consumer], cls.projections,
                cls.provenance, cls.actual_ancestors,
                cls.scratch_root, cls.nonce,
            )
            cls.plan, cls.window_chunks = cls.build_plan()
            cls.plan_pin = read_plan.recorded_preparation_read_plan_pin_v2(
                cls.plan,
            )
        except BaseException:
            if cls._source_fixture_started:
                cls.source_fixture_class.tearDownClass()
            cls.temporary.cleanup()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            if cls._source_fixture_started:
                cls.source_fixture_class.tearDownClass()
        finally:
            cls.temporary.cleanup()

    @classmethod
    def build_plan(cls, **overrides):
        arguments = {
            "basis_value": cls.basis,
            "basis_pin": cls.basis_pin,
            "old_catalogues_by_host": cls.catalogues,
            "old_readback_caps_by_host": cls.readback_caps,
            "window_metadata_by_host": cls.windows,
            "session_nonce": cls.nonce,
            "scratch_declaration": cls.scratch,
            "timeout_declaration": cls.timeouts,
        }
        arguments.update(overrides)
        return read_plan.build_recorded_preparation_read_plan_v2(
            arguments.pop("basis_value"), arguments.pop("basis_pin"),
            old_catalogues_by_host=arguments.pop("old_catalogues_by_host"),
            old_readback_caps_by_host=arguments.pop(
                "old_readback_caps_by_host"),
            window_metadata_by_host=arguments.pop("window_metadata_by_host"),
            session_nonce=arguments.pop("session_nonce"),
            scratch_declaration=arguments.pop("scratch_declaration"),
            timeout_declaration=arguments.pop("timeout_declaration"),
        )

    def window_chunk_for(self, ordinal, *, plan=None, chunks=None):
        plan = self.plan if plan is None else plan
        chunks = self.window_chunks if chunks is None else chunks
        index = plan["window_index"][ordinal]
        return chunks[index["chunk_ordinal"]]

    def window_row_for(self, ordinal, *, plan=None, plan_pin=None, chunks=None):
        plan = self.plan if plan is None else plan
        plan_pin = self.plan_pin if plan_pin is None else plan_pin
        chunk = self.window_chunk_for(ordinal, plan=plan, chunks=chunks)
        return read_plan.validate_recorded_preparation_read_window_v2(
            plan, plan_pin, chunk, ordinal,
        )

    def test_actual_h5_schedule_joins_recomputed_caps_and_builds_720_windows(self) -> None:
        self.assertEqual(len(self.hosts), 2)
        self.assertEqual(len(self.plan["window_index"]), 720)
        self.assertEqual([row["read_ordinal"] for row in self.plan["window_index"]],
                         list(range(720)))
        self.assertEqual(
            [row["owner_host_id"] for row in self.plan["window_index"][:360]],
            [self.hosts[0]] * 360,
        )
        self.assertEqual(
            [row["owner_host_id"] for row in self.plan["window_index"][360:]],
            [self.hosts[1]] * 360,
        )
        self.assertGreaterEqual(len(self.window_chunks), 45)
        self.assertEqual(len(self.window_chunks),
                         len(self.plan["window_chunks"]))
        for ordinal, (chunk, reference) in enumerate(zip(
            self.window_chunks, self.plan["window_chunks"],
        )):
            raw = canonical(chunk)
            self.assertLessEqual(len(chunk["rows"]),
                                 read_plan.MAX_WINDOWS_PER_METADATA_CHUNK)
            self.assertLessEqual(len(raw), read_plan.MAX_METADATA_BYTES)
            self.assertEqual(len(raw), reference["byte_count"])
            self.assertEqual(digest(raw), reference["pin"]["raw_sha256"])
            self.assertEqual(chunk["window_chunk_sha256"],
                             reference["pin"]["semantic_sha256"])
            self.assertEqual(chunk["chunk_ordinal"], ordinal)
            self.assertEqual(chunk["read_ordinals"], reference["read_ordinals"])
            self.assertTrue(all(
                read_plan.validate_recorded_preparation_read_window_v2(
                    self.plan, self.plan_pin, chunk, row_ordinal,
                )["read_ordinal"] == row_ordinal
                for row_ordinal in reference["read_ordinals"]
            ))

        for host in self.hosts:
            projection = self.projections[host]
            self.assertEqual(len(projection["budget_schedule"]), 360)
            self.assertEqual(len(projection["readback_caps"]), 360)
            self.assertEqual(
                projection["readback_caps"],
                self.views[host].budget_module.project_fixed_pair_archive_readback_caps(
                    projection["catalogue_rows"],
                ),
            )
            schedule = self.source_fixture_class.artifacts_by_host[host]["budget"][
                "read_schedule"]
            self.assertEqual(projection["budget_schedule"], schedule)

        first_row = self.window_row_for(0)
        self.assertEqual(
            first_row["source_budget_schedule_caps"].keys(),
            {"bundle_bytes", "maximum_request_bytes", "maximum_response_bytes",
             "object_count", "stage_bytes"},
        )
        self.assertEqual(
            set(first_row["recomputed_source_caps"]),
            {"maximum_request_bytes", "maximum_response_bytes", "bundle_bytes",
             "stage_bytes", "stage_inodes", "object_count",
             "maximum_object_bytes", "live_window_bytes", "live_window_inodes"},
        )
        for pin_name, role in (
            ("ack", "source5_archive_ack"),
            ("signature", "source5_archive_signature"),
        ):
            durable = first_row["original_pins"][pin_name]
            reservation = first_row["indexed_reservation_bindings"][role]
            self.assertNotEqual(reservation["path"], durable["path"])
            self.assertEqual(
                reservation,
                next(row for row in self.catalogues[first_row["owner_host_id"]]
                     if row["path"] == reservation["path"]),
            )
            self.assertGreater(reservation["max_file_bytes"], 0)

        # The Source producer's ordinary payload rows retain their real null
        # host labels. The selected schedule/manifest/job binding above keeps
        # the projection scoped to this host without rewriting those rows.
        first_host = self.hosts[0]
        first_source_window = self.windows[first_host][0]
        source_rows_by_path = {
            row["path"]: row for row in self.catalogues[first_host]
        }
        nullable_objects = [
            obj for obj in first_source_window["manifest"]["objects"]
            if source_rows_by_path[obj["origin_path"]]["host_id"] is None
        ]
        self.assertTrue(nullable_objects)
        projected_origins = {obj["origin_path"] for obj in first_row["objects"]}
        for obj in nullable_objects:
            self.assertIsNone(source_rows_by_path[obj["origin_path"]]["host_id"])
            self.assertIn(obj["origin_path"], projected_origins)

        projection = self.plan["resource_projection"]
        allocation_block = self.scratch["allocation_block_bytes"]

        def rounded_file(raw_bytes: int) -> int:
            if raw_bytes == 0:
                return 0
            return ((raw_bytes + allocation_block - 1) // allocation_block) * \
                allocation_block

        complete_rows = [row for chunk in self.window_chunks
                         for row in chunk["rows"]]
        self.assertEqual(len(complete_rows), read_plan.READ_WINDOW_COUNT)
        physical_charges = []
        for row in complete_rows:
            bounds = row["resource_bounds"]
            physical_charges.append(
                rounded_file(bounds["outer_request_bytes"]) +
                2 * rounded_file(bounds["outer_response_bytes"]) +
                2 * rounded_file(bounds["tar_bytes"]) +
                sum(rounded_file(obj["byte_count"]) for obj in row["objects"])
            )
            self.assertNotEqual(row["session_paths"]["response_incoming"],
                                row["session_paths"]["response"])
            self.assertNotEqual(row["session_paths"]["bundle_incoming"],
                                row["session_paths"]["bundle"])
        maximum_physical_charge = max(physical_charges)
        self.assertEqual(maximum_physical_charge,
                         projection["window_physical_bytes"])
        self.assertEqual(projection["failure_window_physical_bytes"],
                         maximum_physical_charge)
        self.assertEqual(projection["directory_metadata_reserve_bytes"],
                         self.scratch["directory_metadata_reserve_bytes"])
        self.assertEqual(projection["directory_node_bytes"],
                         self.scratch["directory_metadata_reserve_bytes"])
        self.assertGreater(projection["directory_node_bytes"], 0)
        directory_nodes = len(self.plan["session_paths"]["directories"])
        self.assertEqual(directory_nodes, 8)
        self.assertEqual(projection["directory_node_count"], directory_nodes)
        self.assertEqual(
            projection["required_inodes"],
            2 * projection["window_inodes"] + 3 + 1 + 1 +
            directory_nodes + len(self.window_chunks),
        )
        chunk_bytes = sum(len(canonical(chunk)) for chunk in self.window_chunks)
        self.assertEqual(chunk_bytes, projection["window_metadata_chunk_bytes"])
        allocated_chunk_bytes = sum(
            ((len(canonical(chunk)) + self.scratch["allocation_block_bytes"] - 1) //
             self.scratch["allocation_block_bytes"]) *
            self.scratch["allocation_block_bytes"]
            for chunk in self.window_chunks
        )
        self.assertEqual(allocated_chunk_bytes,
                         projection["window_metadata_chunk_allocated_bytes"])
        self.assertEqual(projection["window_metadata_allocation_block_bytes"],
                         self.scratch["allocation_block_bytes"])
        self.assertEqual(len(self.window_chunks),
                         projection["window_metadata_chunk_count"])
        self.assertEqual(projection["window_metadata_chunk_inode_count"],
                         len(self.window_chunks) + 1)
        self.assertEqual(projection["window_metadata_chunk_file_fsync_count"],
                         len(self.window_chunks))
        self.assertEqual(projection["window_metadata_chunk_directory_fsync_count"], 1)
        self.assertEqual(projection["window_metadata_chunk_parent_fsync_count"], 1)
        self.assertEqual(projection["window_metadata_chunk_fsync_count"],
                         len(self.window_chunks) + 2)
        self.assertEqual(projection["window_index_document_bytes"],
                         len(canonical(self.plan["window_index"])))
        self.assertEqual(projection["window_chunk_ref_document_bytes"],
                         len(canonical(self.plan["window_chunks"])))
        self.assertLessEqual(projection["window_index_document_bytes"],
                             read_plan.MAX_METADATA_BYTES)
        self.assertLessEqual(projection["window_chunk_ref_document_bytes"],
                             read_plan.MAX_METADATA_BYTES)
        self.assertEqual(projection["control_event_count"], 1440)
        self.assertEqual(projection["maximum_retained_failure_windows"], 1)
        _descriptor, descriptor_raw, _descriptor_pin = \
            read_plan.build_recorded_preparation_read_session_descriptor_v2(
                self.plan, self.plan_pin,
            )
        self.assertEqual(len(descriptor_raw), projection["session_descriptor_bytes"])
        failure_receipt_bytes = read_plan._failure_receipt_size(
            self.plan["basis_pin"], self.plan["session_paths"]["read_plan"],
            self.plan["session_nonce"], self.plan["consumer_host_id"],
            self.plan["operation_kind"], {
                "window_bytes": projection["window_bytes"],
                "window_inodes": projection["window_inodes"],
            },
        )
        self.assertEqual(failure_receipt_bytes,
                         projection["failure_receipt_bytes"])

        maximum_request_bytes = 0
        maximum_response_bytes = 0
        serialized_ledger_bytes = 0
        for ordinal in range(720):
            chunk = self.window_chunk_for(ordinal)
            row = self.window_row_for(ordinal)
            request, request_raw, request_pin = \
                read_plan.build_recorded_preparation_read_request_v2(
                    self.basis, self.basis_pin, self.plan, self.plan_pin,
                    ordinal, chunk,
                )
            self.assertLessEqual(len(request_raw), read_plan.MAX_METADATA_BYTES)
            self.assertLessEqual(len(request_raw),
                                 row["resource_bounds"]["outer_request_bytes"])
            self.assertEqual(
                read_plan.validate_recorded_preparation_read_request_v2(
                    request_raw, self.basis, self.basis_pin, self.plan,
                    self.plan_pin, chunk,
                ), request,
            )
            legacy_response = read_plan._legacy_response(
                request["legacy_request"], "d" * 64,
                row["resource_bounds"]["tar_bytes"],
            )
            response, response_raw, response_pin = \
                read_plan.build_recorded_preparation_read_response_v2(
                    request_raw, legacy_response, canonical(legacy_response),
                    self.basis, self.basis_pin, self.plan, self.plan_pin, chunk,
                )
            self.assertLessEqual(len(response_raw), read_plan.MAX_METADATA_BYTES)
            self.assertLessEqual(len(response_raw),
                                 row["resource_bounds"]["outer_response_bytes"])
            self.assertEqual(
                read_plan.validate_recorded_preparation_read_response_v2(
                    response_raw, request_raw, self.basis, self.basis_pin,
                    self.plan, self.plan_pin, chunk,
                ), response,
            )
            maximum_request_bytes = max(maximum_request_bytes, len(request_raw))
            maximum_response_bytes = max(maximum_response_bytes, len(response_raw))
            request_event = read_plan.build_recorded_preparation_read_control_event_v2(
                self.plan, self.plan_pin, ordinal, chunk, "request_published",
                request_pin=request_pin,
            )
            release_event = read_plan.build_recorded_preparation_read_control_event_v2(
                self.plan, self.plan_pin, ordinal, chunk, "view_released",
                request_pin=request_pin, response_pin=response_pin,
                bundle_pin={"path": row["session_paths"]["bundle"],
                            "raw_sha256": "e" * 64,
                            "byte_count": row["resource_bounds"]["tar_bytes"]},
            )
            for event in (request_event, release_event):
                serialized_ledger_bytes += len(canonical({
                    "previous_sha256": "f" * 64,
                    "record": event,
                    "record_sha256": "f" * 64,
                }))
        self.assertLessEqual(maximum_request_bytes, read_plan.MAX_METADATA_BYTES)
        self.assertLessEqual(maximum_response_bytes, read_plan.MAX_METADATA_BYTES)
        self.assertLessEqual(serialized_ledger_bytes, read_plan.MAX_METADATA_BYTES)
        self.assertEqual(serialized_ledger_bytes, projection["control_ledger_bytes"])
        document_raw_sizes = {
            "basis_document_bytes": len(canonical(self.basis)),
            "read_plan_document_bytes": len(canonical(self.plan)),
            "session_descriptor_bytes": len(descriptor_raw),
            "control_ledger_bytes": serialized_ledger_bytes,
            "failure_receipt_bytes": failure_receipt_bytes,
        }
        document_allocation_fields = {
            "basis_document_bytes": "basis_document_allocated_bytes",
            "read_plan_document_bytes": "read_plan_document_allocated_bytes",
            "session_descriptor_bytes": "session_descriptor_allocated_bytes",
            "control_ledger_bytes": "control_ledger_allocated_bytes",
            "failure_receipt_bytes": "failure_receipt_allocated_bytes",
        }
        document_allocated_total = 0
        for raw_field, allocated_field in document_allocation_fields.items():
            expected = rounded_file(document_raw_sizes[raw_field])
            self.assertEqual(projection[raw_field], document_raw_sizes[raw_field])
            self.assertEqual(projection[allocated_field], expected)
            document_allocated_total += expected
        expected_total_physical_bytes = (
            2 * maximum_physical_charge + document_allocated_total +
            projection["window_metadata_chunk_allocated_bytes"] +
            self.scratch["directory_metadata_reserve_bytes"]
        )
        self.assertEqual(projection["required_bytes"],
                         expected_total_physical_bytes)
        self.serialized_metadata_size_bounds = {
            "basis_bytes": len(canonical(self.basis)),
            "plan_bytes": len(canonical(self.plan)),
            "window_index_bytes": len(canonical(self.plan["window_index"])),
            "maximum_window_chunk_bytes": max(
                len(canonical(chunk)) for chunk in self.window_chunks
            ),
            "maximum_outer_request_bytes": maximum_request_bytes,
            "maximum_outer_response_bytes": maximum_response_bytes,
            "control_ledger_bytes": serialized_ledger_bytes,
            "session_descriptor_bytes": len(descriptor_raw),
            "failure_receipt_bytes": failure_receipt_bytes,
        }
        self.assertTrue(all(
            0 < size <= read_plan.MAX_METADATA_BYTES
            for size in self.serialized_metadata_size_bounds.values()
        ))
        self.assertGreater(projection["required_bytes"], projection["window_bytes"])
        self.assertGreater(projection["required_inodes"], projection["window_inodes"])
        self.assertNotIn("verified", self.plan)
        self.assertNotIn("ready", self.plan)
        self.assertNotIn("may_read", self.plan)
        self.assertNotIn("execution_manifest_pin", self.plan)
        self.assertNotIn("registration_head", self.plan)

    def test_plan_rebuild_rejects_resealed_window_mutation(self) -> None:
        altered_plan = copy.deepcopy(self.plan)
        altered_chunks = copy.deepcopy(self.window_chunks)
        altered_chunk = altered_chunks[0]
        altered_chunk["rows"][0]["job_index"] = 1
        altered_chunk = sealed(altered_chunk, "window_chunk_sha256")
        altered_chunks[0] = altered_chunk
        altered_ref = altered_plan["window_chunks"][0]
        altered_ref["pin"]["raw_sha256"] = digest(canonical(altered_chunk))
        altered_ref["pin"]["semantic_sha256"] = altered_chunk[
            "window_chunk_sha256"]
        altered_ref["byte_count"] = len(canonical(altered_chunk))
        altered_plan = sealed(altered_plan, "read_plan_sha256")
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            read_plan.validate_recorded_preparation_read_plan_v2(
                altered_plan, altered_chunks, self.basis, self.basis_pin,
                old_catalogues_by_host=self.catalogues,
                old_readback_caps_by_host=self.readback_caps,
                window_metadata_by_host=self.windows,
                session_nonce=self.nonce,
                scratch_declaration=self.scratch,
                timeout_declaration=self.timeouts,
            )
        altered_pin = read_plan.recorded_preparation_read_plan_pin_v2(
            altered_plan,
        )
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            read_plan.validate_recorded_preparation_read_window_v2(
                altered_plan, altered_pin, altered_chunk, 0,
            )

    def test_registration_and_refresh_basis_shapes_are_conditional(self) -> None:
        lineage_module = self.views[self.consumer].modules[
            "scripts/application-source5-prepared-lineage.py"
        ]
        self.assertEqual(set(self.provenance), {
            "schema", "preparation_pin", "final_spec_pin", "final_plan_pin",
            "exploration_lineage",
        })
        self.assertEqual(
            self.provenance["preparation_pin"], {
                "path": self.fixture.preparation_pin["path"],
                "raw_sha256": self.fixture.preparation_pin["sha256"],
            },
        )
        self.assertEqual(
            lineage_module.validate_prepared_input_provenance_v2(
                self.provenance, expected_hosts=self.hosts,
            ),
            self.provenance,
        )
        for changed in (
            {**self.provenance, "imported": True},
            {key: value for key, value in self.provenance.items()
             if key != "final_plan_pin"},
            {**self.provenance, "schema": "allocatbelt.bad.v1"},
        ):
            with self.assertRaises(
                    lineage_module.PreparedExplorationLineageError):
                lineage_module.validate_prepared_input_provenance_v2(
                    changed, expected_hosts=self.hosts,
                )
        semantic_ancestor = copy.deepcopy(self.provenance)
        semantic_ancestor["exploration_lineage"][self.hosts[0]][
            "bridge_header"]["semantic_sha256"] = "a" * 64
        with self.assertRaises(
                lineage_module.PreparedExplorationLineageError):
            lineage_module.validate_prepared_input_provenance_v2(
                semantic_ancestor, expected_hosts=self.hosts,
            )

        registration_with_future = copy.deepcopy(self.basis)
        registration_with_future["execution_manifest_pin"] = {
            "path": "/tmp/future-manifest.json",
            "raw_sha256": "d" * 64, "semantic_sha256": "e" * 64,
        }
        registration_with_future["registration_head"] = "f" * 64
        registration_with_future = sealed(
            registration_with_future, "basis_sha256",
        )
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            read_plan._validate_basis(registration_with_future, self.basis_pin)

        refresh_missing = copy.deepcopy(self.basis)
        refresh_missing["operation_kind"] = "refresh_replay"
        refresh_missing = sealed(refresh_missing, "basis_sha256")
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            read_plan._validate_basis(refresh_missing, self.basis_pin)

        crossed_final = copy.deepcopy(self.basis)
        crossed_final["prepared_input_generation"]["provenance"][
            "final_spec_pin"] = copy.deepcopy(self.provenance["final_plan_pin"])
        crossed_final = sealed(crossed_final, "basis_sha256")
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            read_plan._validate_basis(crossed_final, self.basis_pin)

        crossed_ancestor = copy.deepcopy(self.basis)
        crossed_ancestor["ancestor_pins"][self.hosts[0]]["bridge_header"] = \
            copy.deepcopy(self.provenance["exploration_lineage"][
                self.hosts[1]]["bridge_header"])
        crossed_ancestor = sealed(crossed_ancestor, "basis_sha256")
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            read_plan._validate_basis(crossed_ancestor, self.basis_pin)

        self.assertNotEqual(
            self.provenance["preparation_pin"],
            self.provenance["final_spec_pin"],
            "the fixture must keep its original preparation identity distinct",
        )
        malformed_preparation = copy.deepcopy(self.provenance)
        malformed_preparation["preparation_pin"]["semantic_sha256"] = "a" * 64
        with self.assertRaises(
                lineage_module.PreparedExplorationLineageError):
            lineage_module.validate_prepared_input_provenance_v2(
                malformed_preparation, expected_hosts=self.hosts,
            )

        missing_preparation_pin = copy.deepcopy(self.basis)
        missing_preparation_pin["prepared_input_generation"]["provenance"].pop(
            "preparation_pin",
        )
        missing_preparation_pin = sealed(
            missing_preparation_pin, "basis_sha256",
        )
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            read_plan._validate_basis(missing_preparation_pin, self.basis_pin)

        refresh_basis, refresh_pin = _make_basis(
            self.views[self.consumer], self.projections,
            self.provenance, self.actual_ancestors,
            self.scratch_root, self.nonce, operation_kind="refresh_replay",
        )
        checked, _pin, _hosts = read_plan._validate_basis(
            refresh_basis, refresh_pin,
        )
        self.assertEqual(checked["operation_kind"], "refresh_replay")
        self.assertIn("execution_manifest_pin", checked)
        self.assertIn("registration_head", checked)

        self.assertEqual(
            read_plan._signature_pin({
                "path": "/historical/signature.sig",
                "raw_sha256": "d" * 64,
                "signer_fingerprint": "A" * 64,
            }, "64-character Source fingerprint"),
            {"path": "/historical/signature.sig",
             "raw_sha256": "d" * 64,
             "signer_fingerprint": "A" * 64},
        )
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            read_plan._signature_pin({
                "path": "/historical/signature.sig",
                "raw_sha256": "d" * 64,
                "signer_fingerprint": "a" * 40,
            }, "lowercase Source fingerprint")

    def test_nonce_is_exact_and_changes_every_derived_session_path(self) -> None:
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            self.build_plan(session_nonce="A" * 32)
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            self.build_plan(session_nonce="a" * 31)
        other_nonce = "b" * 32
        other_basis, other_pin = _make_basis(
            self.views[self.consumer], self.projections,
            self.provenance, self.actual_ancestors,
            self.scratch_root, other_nonce,
        )
        other_plan, _other_chunks = self.build_plan(
            basis_value=other_basis, basis_pin=other_pin,
            session_nonce=other_nonce,
        )
        self.assertNotEqual(other_plan["read_plan_sha256"],
                            self.plan["read_plan_sha256"])
        self.assertNotEqual(other_plan["session_paths"]["slot"],
                            self.plan["session_paths"]["slot"])
        self.assertNotEqual(
            other_plan["session_paths"]["window_metadata_root"],
            self.plan["session_paths"]["window_metadata_root"],
        )

    def test_repeated_original_ordinals_preserve_source_job_identity(self) -> None:
        witnessed = False
        for host_cursor, host in enumerate(self.hosts):
            by_ordinal = {}
            for index, window in enumerate(self.windows[host]):
                by_ordinal.setdefault(window["schedule_row"]["job"]["ordinal"], []).append(index)
            repeated = next((indices for indices in by_ordinal.values()
                             if len(indices) > 1), None)
            if repeated is None:
                continue
            witnessed = True
            for index in repeated[:2]:
                row = self.window_row_for(host_cursor * 360 + index)
                self.assertEqual(row["job_index"], index)
                self.assertEqual(row["job"], self.windows[host][index]["schedule_row"]["job"])
                self.assertEqual(row["job_sha256"], digest(canonical(row["job"])))
            duplicate = copy.deepcopy(self.windows)
            duplicate[host][1] = copy.deepcopy(duplicate[host][0])
            with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
                self.build_plan(window_metadata_by_host=duplicate)
        self.assertTrue(witnessed, "actual Source fixture must retain repeated original ordinals")

    def test_host_order_and_original_per_host_ordinals_are_exact(self) -> None:
        reverse_basis = copy.deepcopy(self.basis)
        reverse_basis["cohort_hosts"] = list(reversed(self.hosts))
        reverse_basis = sealed(reverse_basis, "basis_sha256")
        reverse_pin = {
            **self.basis_pin,
            "raw_sha256": digest(canonical(reverse_basis)),
            "semantic_sha256": reverse_basis["basis_sha256"],
        }
        reverse_plan, _reverse_chunks = self.build_plan(
            basis_value=reverse_basis, basis_pin=reverse_pin,
        )
        self.assertEqual(
            [row["owner_host_id"] for row in reverse_plan["window_index"][:360]],
            [self.hosts[1]] * 360,
        )
        self.assertEqual(reverse_plan["window_index"][360]["job_index"], 0)
        reverse_plan_pin = read_plan.recorded_preparation_read_plan_pin_v2(
            reverse_plan,
        )
        reverse_chunks = _reverse_chunks
        for host_cursor, host in enumerate(reversed(self.hosts)):
            first_ordinal = host_cursor * 360
            first = self.window_row_for(
                first_ordinal, plan=reverse_plan, plan_pin=reverse_plan_pin,
                chunks=reverse_chunks,
            )
            last = self.window_row_for(
                first_ordinal + 359, plan=reverse_plan,
                plan_pin=reverse_plan_pin, chunks=reverse_chunks,
            )
            self.assertEqual(first["owner_host_id"], host)
            self.assertEqual(last["owner_host_id"], host)
            self.assertEqual((first["job_index"], last["job_index"]), (0, 359))
        altered_windows = copy.deepcopy(self.windows)
        altered_windows[self.hosts[0]][0], altered_windows[self.hosts[0]][1] = (
            altered_windows[self.hosts[0]][1], altered_windows[self.hosts[0]][0],
        )
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            self.build_plan(window_metadata_by_host=altered_windows)

    def test_manifest_object_subset_and_wrong_old_cap_are_rejected(self) -> None:
        altered = copy.deepcopy(self.windows)
        window = altered[self.hosts[0]][0]
        manifest = window["manifest"]
        removed = manifest["objects"].pop()
        manifest["object_count"] -= 1
        manifest["payload_bytes"] -= removed["byte_count"]
        manifest = sealed(manifest, "manifest_sha256")
        window["manifest"] = manifest
        window["object_manifest_pin"]["raw_sha256"] = digest(canonical(manifest))
        window["object_manifest_pin"]["semantic_sha256"] = manifest[
            "manifest_sha256"]
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            self.build_plan(window_metadata_by_host=altered)

        host = self.hosts[0]
        window = self.windows[host][0]
        strict_origin = next(
            item["origin_path"] for item in window["manifest"]["objects"]
            if item["role"] == "fixed_pair_host_receipt"
        )
        crossed_catalogues = copy.deepcopy(self.catalogues)
        strict_row = next(row for row in crossed_catalogues[host]
                          if row["path"] == strict_origin)
        self.assertEqual(strict_row["host_id"], host)
        strict_row["host_id"] = self.hosts[1]
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            self.build_plan(old_catalogues_by_host=crossed_catalogues)

        ack_role = "source5_archive_ack"
        durable_ack_path = window["ack_pin"]["path"]
        actual_ack_reservation = window["indexed_reservation_bindings"][ack_role]
        self.assertNotEqual(actual_ack_reservation["path"], durable_ack_path)

        crossed = copy.deepcopy(self.windows)
        crossed_binding = crossed[host][0]["indexed_reservation_bindings"][ack_role]
        crossed_binding["path"] = durable_ack_path
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            self.build_plan(window_metadata_by_host=crossed)

        crossed_role = copy.deepcopy(self.windows)
        crossed_role[host][0]["indexed_reservation_bindings"][ack_role] = \
            copy.deepcopy(crossed_role[host][0]["indexed_reservation_bindings"][
                "source5_archive_signature"])
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            self.build_plan(window_metadata_by_host=crossed_role)

        crossed_host = copy.deepcopy(self.windows)
        crossed_host[host][0]["indexed_reservation_bindings"][ack_role] = \
            copy.deepcopy(crossed_host[self.hosts[1]][0][
                "indexed_reservation_bindings"][ack_role])
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            self.build_plan(window_metadata_by_host=crossed_host)

        changed_origin = copy.deepcopy(self.windows)
        origin_row = changed_origin[host][0]["indexed_reservation_bindings"][
            ack_role]
        origin_row["origin_pin"] = {
            "raw_sha256": "0" * 64, "semantic_sha256": None,
        }
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            self.build_plan(window_metadata_by_host=changed_origin)

        lowered_reservation = copy.deepcopy(self.windows)
        low_row = lowered_reservation[host][0]["indexed_reservation_bindings"][
            ack_role]
        self.assertGreater(low_row["max_file_bytes"], 1)
        low_row["max_file_bytes"] -= 1
        low_row["max_bytes"] -= 1
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            self.build_plan(window_metadata_by_host=lowered_reservation)

        lowered = copy.deepcopy(self.readback_caps)
        run_id = self.windows[host][0]["schedule_row"]["job"]["run_id"]
        cap = lowered[host][run_id]
        schedule_window = copy.deepcopy(self.windows)
        tar_size = read_plan._archive_read_tar_size([
            {"byte_count": row["byte_count"]}
            for row in schedule_window[host][0]["manifest"]["objects"]
        ])
        self.assertGreater(tar_size, read_plan.MIN_TAR_BYTES)
        self.assertEqual(tar_size, cap["bundle_bytes"])
        cap["bundle_bytes"] = tar_size - 1
        schedule_window[host][0]["schedule_row"]["caps"]["bundle_bytes"] = tar_size - 1
        maximum_bundle = max(
            row["bundle_bytes"] for row in lowered[host].values()
        )
        for cap_row in lowered[host].values():
            cap_row["maximum_bundle_bytes"] = maximum_bundle
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            self.build_plan(
                old_readback_caps_by_host=lowered,
                window_metadata_by_host=schedule_window,
            )

    def test_finite_scratch_reservation_rejects_one_byte_or_inode_short(self) -> None:
        projection = self.plan["resource_projection"]
        allocation_block = self.scratch["allocation_block_bytes"]
        for raw_bytes, expected in (
            (0, 0),
            (allocation_block - 1, allocation_block),
            (allocation_block, allocation_block),
            (allocation_block + 1, 2 * allocation_block),
        ):
            self.assertEqual(
                read_plan._round_file_allocation_bytes(raw_bytes,
                                                       allocation_block),
                expected,
            )

        # A zero-byte object consumes no file-data blocks. Every nonzero file
        # is rounded independently, including the incoming/final response and
        # tar names. Aggregate rounding of the same raw 6B sum would be 6B,
        # while the actual file-by-file charge below is 8B.
        synthetic_window = {
            "resource_bounds": {
                "outer_request_bytes": allocation_block + 1,
                "outer_response_bytes": allocation_block - 1,
                "tar_bytes": allocation_block,
            },
            "objects": [
                {"byte_count": 0},
                {"byte_count": allocation_block + 1},
            ],
        }
        self.assertEqual(
            read_plan._physical_window_charge(synthetic_window,
                                               allocation_block),
            8 * allocation_block,
        )

        exact_scratch = dict(self.scratch)
        exact_scratch["reserved_bytes"] = projection["required_bytes"]
        exact_plan = None
        for _attempt in range(16):
            try:
                exact_plan, _exact_chunks = self.build_plan(
                    scratch_declaration=exact_scratch,
                )
            except read_plan.RecordedPreparationReadPlanError:
                exact_scratch["reserved_bytes"] += allocation_block
                continue
            exact_required = exact_plan["resource_projection"]["required_bytes"]
            if exact_required == exact_scratch["reserved_bytes"]:
                break
            exact_scratch["reserved_bytes"] = exact_required
        self.assertIsNotNone(exact_plan)
        assert exact_plan is not None
        self.assertEqual(exact_plan["resource_projection"]["required_bytes"],
                         exact_scratch["reserved_bytes"])
        exact_projection = exact_plan["resource_projection"]
        byte_scratch = dict(exact_scratch)
        byte_scratch["reserved_bytes"] = exact_projection["required_bytes"] - 1
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            self.build_plan(scratch_declaration=byte_scratch)
        inode_scratch = dict(exact_scratch)
        inode_scratch["reserved_inodes"] = exact_projection["required_inodes"] - 1
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            self.build_plan(scratch_declaration=inode_scratch)

    def test_timeout_policy_is_finite_and_monotonic_representable(self) -> None:
        invalid = [
            {"maximum_io_window_seconds": 0,
             "maximum_operation_seconds": 60},
            {"maximum_io_window_seconds": 301,
             "maximum_operation_seconds": 86400},
            {"maximum_io_window_seconds": 60,
             "maximum_operation_seconds": 86401},
            {"maximum_io_window_seconds": 120,
             "maximum_operation_seconds": 119},
        ]
        for declaration in invalid:
            with self.subTest(declaration=declaration):
                with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
                    self.build_plan(timeout_declaration=declaration)
        self.assertEqual(
            read_plan._validate_timeouts({
                "maximum_io_window_seconds": 300,
                "maximum_operation_seconds": 86400,
            })["maximum_io_window_seconds"],
            300,
        )

    def test_zero_byte_objects_still_charge_tar_headers_and_inodes(self) -> None:
        self.assertEqual(
            read_plan._archive_read_tar_size([{"byte_count": 0}]),
            read_plan.MIN_TAR_BYTES,
        )
        altered = copy.deepcopy(self.windows)
        window = altered[self.hosts[0]][0]
        manifest = window["manifest"]
        first = manifest["objects"][0]
        old_count = first["byte_count"]
        first["byte_count"] = 0
        first["object_pin"]["byte_count"] = 0
        manifest["payload_bytes"] -= old_count
        manifest = sealed(manifest, "manifest_sha256")
        window["manifest"] = manifest
        window["object_manifest_pin"]["raw_sha256"] = digest(canonical(manifest))
        window["object_manifest_pin"]["semantic_sha256"] = manifest[
            "manifest_sha256"]
        plan, chunks = self.build_plan(window_metadata_by_host=altered)
        plan_pin = read_plan.recorded_preparation_read_plan_pin_v2(plan)
        projected = self.window_row_for(
            0, plan=plan, plan_pin=plan_pin, chunks=chunks,
        )
        self.assertEqual(projected["objects"][0]["byte_count"], 0)
        self.assertEqual(projected["resource_bounds"]["object_count"],
                         len(window["manifest"]["objects"]))
        self.assertGreaterEqual(projected["resource_bounds"]["window_inodes"], 7)

    def test_outer_request_response_and_control_events_bind_exact_row(self) -> None:
        ordinal = 0
        chunk = self.window_chunk_for(ordinal)
        row = self.window_row_for(ordinal)
        request, request_raw, request_pin = \
            read_plan.build_recorded_preparation_read_request_v2(
                self.basis, self.basis_pin, self.plan, self.plan_pin,
                ordinal, chunk,
            )
        checked_request = read_plan.validate_recorded_preparation_read_request_v2(
            request_raw, self.basis, self.basis_pin,
            self.plan, self.plan_pin, chunk,
        )
        self.assertEqual(checked_request, request)
        bad_request = copy.deepcopy(request)
        bad_request["owner_host_id"] = self.hosts[1]
        bad_request = sealed(bad_request, "request_sha256")
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            read_plan.validate_recorded_preparation_read_request_v2(
                canonical(bad_request), self.basis, self.basis_pin,
                self.plan, self.plan_pin, chunk,
            )
        legacy_response = read_plan._legacy_response(
            request["legacy_request"], "d" * 64,
            row["resource_bounds"]["tar_bytes"],
        )
        response, response_raw, response_pin = \
            read_plan.build_recorded_preparation_read_response_v2(
                request_raw, legacy_response, canonical(legacy_response),
                self.basis, self.basis_pin, self.plan, self.plan_pin, chunk,
            )
        checked_response = read_plan.validate_recorded_preparation_read_response_v2(
            response_raw, request_raw, self.basis, self.basis_pin,
            self.plan, self.plan_pin, chunk,
        )
        self.assertEqual(checked_response, response)
        self.assertEqual(request_pin["path"], row["session_paths"]["request"])
        self.assertEqual(response_pin["path"], row["session_paths"]["response"])

        changed = copy.deepcopy(response)
        changed["owner_host_id"] = self.hosts[1]
        changed = sealed(changed, "response_sha256")
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            read_plan.validate_recorded_preparation_read_response_v2(
                canonical(changed), request_raw, self.basis,
                self.basis_pin, self.plan, self.plan_pin, chunk,
            )
        request_event = read_plan.build_recorded_preparation_read_control_event_v2(
            self.plan, self.plan_pin, ordinal, chunk, "request_published",
            request_pin=request_pin,
        )
        release_event = read_plan.build_recorded_preparation_read_control_event_v2(
            self.plan, self.plan_pin, ordinal, chunk, "view_released",
            request_pin=request_pin,
            response_pin=response_pin,
            bundle_pin={
                "path": row["session_paths"]["bundle"],
                "raw_sha256": "e" * 64,
                "byte_count": row["resource_bounds"]["tar_bytes"],
            },
        )
        self.assertEqual(request_event["sequence"], 1)
        self.assertEqual(release_event["sequence"], 2)
        self.assertEqual(request_event["action"], "request_published")
        self.assertEqual(release_event["action"], "view_released")
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            read_plan.build_recorded_preparation_read_control_event_v2(
                self.plan, self.plan_pin, ordinal, chunk, "request_published",
                request_pin=request_pin, response_pin=response_pin,
            )
        altered_chunk = copy.deepcopy(chunk)
        altered_chunk["rows"][0]["job_index"] = 2
        altered_chunk = sealed(altered_chunk, "window_chunk_sha256")
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            read_plan.build_recorded_preparation_read_request_v2(
                self.basis, self.basis_pin, self.plan, self.plan_pin,
                ordinal, altered_chunk,
            )

    def test_payload_view_is_exact_object_projection_not_verification(self) -> None:
        ordinal = 0
        chunk = self.window_chunk_for(ordinal)
        row = self.window_row_for(ordinal)
        refs = {}
        for obj in row["objects"]:
            member_digest = digest(obj["origin_path"].encode("utf-8"))
            refs[obj["origin_path"]] = {
                "origin_path": obj["origin_path"],
                "path": str(Path(row["session_paths"]["stage"]) /
                            f"{member_digest}-{obj['raw_sha256']}"),
                "role": obj["role"], "host_id": row["owner_host_id"],
                "raw_sha256": obj["raw_sha256"],
                "semantic_sha256": obj["semantic_sha256"],
                "byte_count": obj["byte_count"],
                "maximum_bytes": obj["byte_count"],
            }
        view = read_plan.project_recorded_preparation_payload_view_v2(
            self.plan, self.plan_pin, ordinal, chunk,
            outer_request_pin={
                "path": row["session_paths"]["request"],
                "raw_sha256": "1" * 64, "semantic_sha256": "2" * 64,
            },
            outer_response_pin={
                "path": row["session_paths"]["response"],
                "raw_sha256": "3" * 64, "semantic_sha256": "4" * 64,
            },
            bundle_pin={
                "path": row["session_paths"]["bundle"],
                "raw_sha256": "5" * 64,
                "byte_count": row["resource_bounds"]["tar_bytes"],
            },
            stage_root=row["session_paths"]["stage"],
            refs_by_origin=refs,
        )
        self.assertEqual(
            read_plan.validate_recorded_preparation_payload_view_v2(
                view, self.plan, self.plan_pin, chunk,
            ),
            view,
        )
        self.assertNotIn("verified", view)
        self.assertNotIn("may_read", view)
        missing = dict(refs)
        missing.pop(next(iter(missing)))
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            read_plan.project_recorded_preparation_payload_view_v2(
                self.plan, self.plan_pin, ordinal, chunk,
                outer_request_pin=view["outer_request_pin"],
                outer_response_pin=view["outer_response_pin"],
                bundle_pin=view["bundle_pin"],
                stage_root=view["stage_root"], refs_by_origin=missing,
            )
        escaped = copy.deepcopy(refs)
        first_origin = next(iter(escaped))
        escaped[first_origin]["path"] = "/foreign/stage/object"
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            read_plan.project_recorded_preparation_payload_view_v2(
                self.plan, self.plan_pin, ordinal, chunk,
                outer_request_pin=view["outer_request_pin"],
                outer_response_pin=view["outer_response_pin"],
                bundle_pin=view["bundle_pin"],
                stage_root=view["stage_root"], refs_by_origin=escaped,
            )

    def test_metadata_limit_and_scratch_overlap_fail_closed(self) -> None:
        oversized_caps = copy.deepcopy(self.readback_caps)
        selected_host = self.hosts[0]
        selected_run = self.windows[selected_host][0]["schedule_row"]["job"][
            "run_id"]
        oversized_caps[selected_host][selected_run]["request_bytes"] = \
            read_plan.MAX_METADATA_BYTES + 1
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            read_plan._validate_readback_caps(oversized_caps, self.hosts)

        oversized_objects = copy.deepcopy(self.readback_caps)
        oversized_objects[selected_host][selected_run]["object_count"] = \
            read_plan.MAX_OBJECTS_PER_WINDOW + 1
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            read_plan._validate_readback_caps(oversized_objects, self.hosts)

        basis = copy.deepcopy(self.basis)
        host = self.hosts[0]
        modules = {}
        suffix = "x" * 3970
        # A little over 16 MiB serialized is enough to exercise the closed
        # metadata limit without allocating the maximum 4096-entry module map.
        for index in range(2100):
            path = f"scripts/{index:04d}/{suffix}.py"
            modules[path] = {"path": path, "sha256": "a" * 64}
        basis["source_module_pins"][host] = modules
        basis = sealed(basis, "basis_sha256")
        basis_pin = {
            **self.basis_pin,
            "raw_sha256": digest(canonical(basis)),
            "semantic_sha256": basis["basis_sha256"],
        }
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            read_plan._validate_basis(basis, basis_pin)

        overlapping = dict(self.scratch)
        overlapping["root"] = self.views[self.consumer].output_root.as_posix()
        overlap_basis, overlap_basis_pin = _make_basis(
            self.views[self.consumer], self.projections,
            self.provenance, self.actual_ancestors,
            Path(overlapping["root"]), self.nonce,
        )
        with self.assertRaises(read_plan.RecordedPreparationReadPlanError):
            self.build_plan(
                basis_value=overlap_basis, basis_pin=overlap_basis_pin,
                scratch_declaration=overlapping,
            )


if __name__ == "__main__":
    unittest.main()
