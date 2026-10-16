#!/usr/bin/env python3
"""Filesystem-backed producer/full-validator tests for the prep-only budget.

This is an explicitly synthetic SourceV5 fixture.  It preserves the real
360-row selected-host Plan and runs the selected SourceH width, catalogue,
budget, restore, and full budget-validator algorithms.  The outer
capacity-generation/registration evidence is shape-only and no application
owner or campaign authorization is invoked.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


SCRIPTS = Path(__file__).resolve().parent
CONTROLLER_PATH = SCRIPTS / "application-source5-campaign.py"
PREPARATORY_PATH = SCRIPTS / "application-source5-preparatory-budget.py"
EVIDENCE_BUDGET_PATH = SCRIPTS / "application-source5-evidence-budget.py"
EVIDENCE_CATALOGUE_PATH = SCRIPTS / "application-source5-evidence-catalogue.py"
RECIPE_TESTS_PATH = SCRIPTS / "test-application-soak-recipe.py"


def load_exact(path: Path, name: str) -> types.ModuleType:
    raw = path.read_bytes()
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ""
    sys.modules[name] = module
    try:
        exec(compile(raw, str(path), "exec", dont_inherit=True), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def write_private(path: Path, raw: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
        getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), mode,
    )
    try:
        os.fchmod(descriptor, mode)
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def seal(value: dict, field: str, hash_function) -> dict:
    body = {key: item for key, item in value.items() if key != field}
    return {**body, field: hash_function(body)}


# Reuse the full typed SourceH producer fixture so the primary test uses
# the same source-derived transport-catalogue setup as the shared suite.
_shared_producer_support = load_exact(
    SCRIPTS / "test-full-profile-preparatory-producer-support.py",
    "source5_primary_shared_producer_support",
)
PreparatoryProducerFixture = _shared_producer_support.PreparatoryProducerFixture


def _reader_for(chunks: dict[str, bytes]):
    def read(path: str, maximum_bytes: int) -> bytes:
        raw = chunks.get(path)
        if raw is None or len(raw) != maximum_bytes:
            raise OSError("fixture reader refused an undeclared catalogue chunk")
        return raw
    return read


def _budget_manifest_pair(fixture: PreparatoryProducerFixture,
                          budget: dict) -> dict:
    prep = fixture.prep_module
    manifest = copy.deepcopy(fixture.context.manifest)
    body = {key: value for key, value in manifest.items()
            if key != "manifest_sha256"}
    body["preparatory_host_budgets"] = {
        fixture.host_id: {
            "artifact": {
                "path": fixture.context.preparatory_budget_pin["path"],
                "raw_sha256": digest(fixture.controller.canonical_bytes(budget)),
            },
            "semantic_sha256": budget["budget_sha256"],
        },
    }
    return prep.seal_execution_manifest(body)


class PreparatoryProducerPathTests(unittest.TestCase):
    def test_real_360_job_builder_restore_and_full_validator_mutants(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-prep-full-producer-") as directory:
            fixture = PreparatoryProducerFixture(Path(directory))
            try:
                artifacts = fixture.build()
                budget = artifacts["budget"]
                self.assertEqual(len(fixture.context.plan["jobs"]["exploration"]), 1080)
                self.assertEqual(len(budget["read_schedule"]), 360)
                rows = list(fixture.budget_module.iter_path_catalogue_rows(
                    budget["path_catalogue"],
                ))
                self.assertEqual(len(rows), len({row["path"] for row in rows}))
                aggregate_rows = [row for row in rows
                                  if row["aggregate_id"] is not None]
                aggregate_by_run = {
                    job["run_id"]: "fixed-output-" +
                    digest(fixture.controller.canonical_bytes(job))
                    for job in fixture.controller._host_jobs(
                        fixture.context, "exploration",
                    )
                }
                aggregate_ids = {row["aggregate_id"]
                                 for row in aggregate_rows}
                self.assertEqual(set(aggregate_by_run.values()), aggregate_ids)
                self.assertEqual(len(aggregate_ids), 360)
                self.assertTrue(all(
                    len(aggregate_id) <= 96 and
                    aggregate_id[0].isalnum() and
                    all(character.isalnum() or character in "._-"
                        for character in aggregate_id)
                    for aggregate_id in aggregate_ids
                ))
                pair_limit = fixture.context.owner_evidence_contract[
                    "fixed_pair"]["limits"]["MAX_PAIR_OUTPUT_BYTES"]
                for run_id, aggregate_id in aggregate_by_run.items():
                    members = [row for row in aggregate_rows
                               if row["run_id"] == run_id]
                    self.assertTrue(members)
                    self.assertEqual(
                        {row["aggregate_id"] for row in members},
                        {aggregate_id},
                    )
                    self.assertEqual(
                        {row["aggregate_max_bytes"] for row in members},
                        {pair_limit},
                    )
                for malformed in ("fixed-output:bad", "x" * 97):
                    mutant = copy.deepcopy(aggregate_rows[0])
                    mutant["aggregate_id"] = malformed
                    with self.subTest(aggregate_id=malformed[:20]):
                        with self.assertRaises(
                                fixture.budget_module.BudgetPlanError):
                            fixture.budget_module._catalogue_row(
                                mutant, "mutated aggregate group row",
                            )
                directory_rows = [row for row in rows
                                  if row["role"] == "directory_node"]
                directory_paths = {row["path"] for row in directory_rows}
                selected_jobs = fixture.controller._host_jobs(
                    fixture.context, "exploration",
                )
                job_roots = {
                    str(fixture.artifact_root / fixture.spec["campaign_id"] /
                        "source5" / fixture.host_id / "job-artifacts" /
                        "exploration" / job["run_id"])
                    for job in selected_jobs
                }
                self.assertEqual(len(selected_jobs), 360)
                self.assertEqual(len(job_roots), 360)
                self.assertTrue(job_roots <= directory_paths)
                tree_roots = {row["path"] for row in rows
                              if row["kind"] == "tree" and
                              row["role"] != "directory_node"}
                self.assertTrue(directory_paths.isdisjoint(tree_roots))
                expected_directories = set()
                for row in rows:
                    storage_root = row["storage_root"]
                    if storage_root is None:
                        continue
                    path = Path(row["path"])
                    root = Path(storage_root)
                    self.assertTrue(path.is_relative_to(root))
                    current = path if row["role"] == "directory_node" else path.parent
                    while current.is_relative_to(root):
                        expected_directories.add(str(current))
                        if current == root:
                            break
                        current = current.parent
                self.assertEqual(directory_paths, expected_directories)
                for row in directory_rows:
                    path = Path(row["path"])
                    matching_roots = [root for root in job_roots
                                      if path.is_relative_to(Path(root))]
                    if matching_roots:
                        self.assertEqual(len(matching_roots), 1)
                        run_id = Path(matching_roots[0]).name
                        self.assertEqual(
                            (row["owner"], row["phase"], row["run_id"]),
                            ("fixed_pair", "exploration", run_id),
                        )
                    else:
                        self.assertEqual(
                            (row["owner"], row["phase"], row["run_id"]),
                            ("source5_controller", None, None),
                        )
                self.assertEqual(len(budget["schedule"]["maximum_job_record_bytes_by_ordinal"]), 360)
                self.assertEqual(len(fixture.context.source5_archive_read_schedule), 360)
                self.assertEqual(fixture.context.source5_archive_read_ordinal, 0)
                self.assertFalse(budget["readiness"]["qualification_eligible"])
                self.assertFalse(budget["readiness"]["full_horizon_execution_ready"])
                pilot_rows = [row for row in fixture.budget_module.iter_path_catalogue_rows(
                    budget["path_catalogue"],
                ) if row["role"] == "capacity_artifact" and
                    row["phase"] == "exploration" and
                    row["owner"] == "source5_controller"]
                self.assertEqual(len(pilot_rows), 1)
                pilot_row = pilot_rows[0]
                pilot_maximum = fixture.input_preparation.capacity_pilot_maximum_bytes(
                    fixture.spec, fixture.host_id, fixture.campaign.ALLOCATORS,
                    fixture.campaign.preregistration_digest(fixture.spec),
                )
                self.assertEqual(pilot_row, {
                    "path": str(fixture.output_root / fixture.spec["campaign_id"] /
                                "source5" / fixture.host_id / "exploration" /
                                "capacity-pilot.json"),
                    "kind": "file", "role": "capacity_artifact",
                    "host_id": fixture.host_id,
                    "max_bytes": pilot_maximum,
                    "max_file_bytes": pilot_maximum,
                    "max_inodes": 1,
                    "storage_root": str(fixture.output_root),
                    "owner": "source5_controller", "phase": "exploration",
                    "run_id": None, "member_index": None,
                    "aggregate_id": None, "aggregate_max_bytes": None,
                    "origin_pin": None,
                })
                fixture.validator(budget, artifacts["manifest"])

                swapped = copy.deepcopy(budget)
                owner = swapped["owner_contract"]
                pins = owner["owner_source_pins"]
                pins["fixed_pair"], pins["pressure_pair"] = (
                    pins["pressure_pair"], pins["fixed_pair"],
                )
                owner["owner_contract_sha256"] = digest(
                    fixture.controller.canonical_bytes({
                        key: value for key, value in owner.items()
                        if key != "owner_contract_sha256"
                    }),
                )
                swapped["budget_sha256"] = digest(
                    fixture.controller.canonical_bytes({
                        key: value for key, value in swapped.items()
                        if key != "budget_sha256"
                    }),
                )
                swapped_manifest = _budget_manifest_pair(fixture, swapped)
                with self.assertRaises(fixture.prep_module.PreparatoryBudgetError):
                    fixture.validator(swapped, swapped_manifest)

                rows = list(fixture.budget_module.iter_path_catalogue_rows(
                    budget["path_catalogue"],
                ))
                for mutated_role in (
                        "source5_archive_read_stage",
                        fixture.budget_module.SOURCE5_ARCHIVE_READ_CONTROL_ROLE):
                    with self.subTest(role=mutated_role):
                        # The genuine writer or full validator may reject at its natural boundary.
                        with self.assertRaises((
                                fixture.budget_module.BudgetPlanError,
                                fixture.prep_module.PreparatoryBudgetError,
                        )):
                            mutated_rows = copy.deepcopy(rows)
                            selected = [row for row in mutated_rows
                                        if row["role"] == mutated_role]
                            self.assertEqual(len(selected), 1)
                            selected[0]["max_bytes"] = 1
                            selected[0]["max_file_bytes"] = 1
                            if mutated_role == "source5_archive_read_stage":
                                selected[0]["max_inodes"] = 1
                            mutant_dir = (fixture.temporary_root / "mutant-catalogues" /
                                          mutated_role)
                            mutant_dir.mkdir(mode=0o700, parents=True)
                            mutant_catalogue = fixture.budget_module.write_path_catalogue_chunks(
                                mutated_rows, mutant_dir,
                                scratch_directory_value=fixture.scratch_root,
                            )
                            raw_chunks = {}
                            for chunk in mutant_catalogue["chunks"]:
                                raw, raw_sha, info = fixture.controller.read_stable(
                                    Path(chunk["path"]),
                                    "synthetic mutated prep catalogue chunk",
                                    chunk["byte_count"], chunk["raw_sha256"],
                                )
                                self.assertTrue(stat.S_ISREG(info.st_mode))
                                self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
                                self.assertEqual(info.st_nlink, 1)
                                self.assertEqual(raw_sha, chunk["semantic_sha256"])
                                raw_chunks[chunk["path"]] = raw
                            mutant_budget = copy.deepcopy(budget)
                            mutant_budget["path_catalogue"] = mutant_catalogue
                            mutant_budget["budget_sha256"] = digest(
                                fixture.controller.canonical_bytes({
                                    key: value for key, value in mutant_budget.items()
                                    if key != "budget_sha256"
                                }),
                            )
                            mutant_manifest = _budget_manifest_pair(fixture, mutant_budget)
                            fixture.validator(
                                mutant_budget, mutant_manifest, raw_chunks,
                            )
                def reject_capacity_catalogue_mutation(
                    mutation_name: str, mutated_rows: list[dict],
                ) -> None:
                    with self.subTest(capacity_pilot=mutation_name):
                        # Keep the real writer and full validator on their strict paths.
                        with self.assertRaises((
                                fixture.budget_module.BudgetPlanError,
                                fixture.prep_module.PreparatoryBudgetError,
                        )):
                            mutant_dir = (fixture.temporary_root / "mutant-catalogues" /
                                          f"capacity-pilot-{mutation_name}")
                            mutant_dir.mkdir(mode=0o700, parents=True)
                            mutant_catalogue = fixture.budget_module.write_path_catalogue_chunks(
                                mutated_rows, mutant_dir,
                                scratch_directory_value=fixture.scratch_root,
                            )
                            raw_chunks = {}
                            for chunk in mutant_catalogue["chunks"]:
                                raw, raw_sha, _info = fixture.controller.read_stable(
                                    Path(chunk["path"]),
                                    "synthetic capacity-pilot catalogue mutation",
                                    chunk["byte_count"], chunk["raw_sha256"],
                                )
                                self.assertEqual(raw_sha, chunk["semantic_sha256"])
                                raw_chunks[chunk["path"]] = raw
                            mutant_budget = copy.deepcopy(budget)
                            mutant_budget["path_catalogue"] = mutant_catalogue
                            mutant_budget["budget_sha256"] = digest(
                                fixture.controller.canonical_bytes({
                                    key: value for key, value in mutant_budget.items()
                                    if key != "budget_sha256"
                                }),
                            )
                            mutant_manifest = _budget_manifest_pair(fixture, mutant_budget)
                            fixture.validator(mutant_budget, mutant_manifest, raw_chunks)
                pilot_index = next(
                    index for index, row in enumerate(rows)
                    if row["path"] == pilot_row["path"]
                )
                omitted_pilot = copy.deepcopy(rows)
                omitted_pilot.pop(pilot_index)
                reject_capacity_catalogue_mutation("omitted", omitted_pilot)
                changed_path_pilot = copy.deepcopy(rows)
                changed_path_pilot[pilot_index]["path"] += ".changed"
                reject_capacity_catalogue_mutation("path", changed_path_pilot)
                changed_cap_pilot = copy.deepcopy(rows)
                changed_cap_pilot[pilot_index]["max_bytes"] -= 1
                changed_cap_pilot[pilot_index]["max_file_bytes"] -= 1
                reject_capacity_catalogue_mutation("cap", changed_cap_pilot)
            finally:
                fixture.close()


if __name__ == "__main__":
    unittest.main()
