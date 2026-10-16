#!/usr/bin/env python3
"""Counterexamples for the prospective Source5 horizon budget audit."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import tempfile
import sys
import unittest
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
BUDGET_PATH = SCRIPT_DIR / "application-source5-evidence-budget.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


budget = load_module("source5_evidence_budget_test_target", BUDGET_PATH)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sealed(value: dict[str, Any], field: str) -> dict[str, Any]:
    body = {key: item for key, item in value.items() if key != field}
    value[field] = sha(canonical(body))
    return value


def cells() -> list[dict[str, str]]:
    return [
        {"family": family, "profile": profile}
        for family, profiles in (
            ("cpu", ("steady", "burst", "oversubscribed")),
            ("memory", ("steady", "burst", "oversubscribed")),
            ("http", ("steady", "burst", "oversubscribed")),
            ("disk", ("steady", "burst", "oversubscribed")),
            ("mixed", ("mixed", "burst", "oversubscribed")),
        )
        for profile in profiles
    ]


def source_manifest(host_id: str) -> dict[str, Any]:
    records = [{
        "path": "LICENSE", "kind": "file", "mode": "100644",
        "sha256": sha(b"source-license\n"), "size": len(b"source-license\n"),
    }]
    owner_paths = (
        "scripts/application-fixed-pair.py",
        "scripts/application-pressure-pair.py",
        "scripts/application-source5-campaign.py",
        "scripts/application-source5-soak.py",
        "scripts/application-soak-readback.py",
        "scripts/application-feedback-composition.py",
        "scripts/application-feedback-readback.py",
        "scripts/application-pressure-readback.py",
        "scripts/application-source5-evidence-transport-v3.py",
        "scripts/application-source5-offline-dispatch.py",
        "scripts/application-campaign-chronology.py",
    )
    records.extend({
        "path": path, "kind": "file", "mode": "100644",
        "sha256": f"{index + 10:064x}", "size": 1024 + index,
    } for index, path in enumerate(owner_paths))
    records.sort(key=lambda item: item["path"])
    tree_sha = sha(canonical({
        "schema": budget.INVENTORY_SCHEMA, "entries": records,
    }))
    body = {
        "schema": budget.SOURCE_SCHEMA,
        "source": {
            "git_commit": "a" * 40,
            "source_tree_sha256": tree_sha,
            "cargo_lock_sha256": "b" * 64,
            "files": records,
        },
        "build": {
            "host_id": host_id, "rustc_release": "1.99.0",
            "rustc_verbose": ["rustc 1.99.0"], "cargo_version": "cargo 1.99.0",
            "target_triple": "x86_64-unknown-linux-gnu",
            "target_cpu": "x86-64-v3", "profile": "release",
            "features_sha256": "c" * 64, "build_inputs_sha256": "d" * 64,
        },
        "artifacts": {
            name: {"path": f"target/app/{name}", "sha256": f"{index + 1:x}" * 64}
            for index, name in enumerate(budget.ALLOCATORS)
        },
        "soak_artifacts": {
            "allocatbelt": {"path": "target/soak/allocatbelt", "sha256": "5" * 64},
        },
        "analysis_artifact": {"path": "target/analyzer", "sha256": "6" * 64},
        "resource_domain_calibration": {
            "binary": {"path": "target/calibrator", "sha256": "7" * 64},
            "output": {"path": "target/calibration.json", "sha256": "8" * 64},
            "record": {}, "source": {}, "build": {},
            "build_sha256": "9" * 64,
        },
    }
    return sealed(body, "manifest_sha256")


def make_job(host_id: str, phase: str, run_id: str, **fields: Any) -> dict[str, Any]:
    return {"host_id": host_id, "phase": phase, "run_id": run_id, **fields}


def fixture() -> dict[str, Any]:
    host_ids = ["host-a", "host-b", "host-c"]
    source_values = {host: source_manifest(host) for host in host_ids}
    source_pins = {
        host: {
            "path": f"/inputs/sources/{host}.json",
            "raw_sha256": sha(canonical(value)),
            "semantic_sha256": value["manifest_sha256"],
        }
        for host, value in source_values.items()
    }
    spec = {
        "schema": budget.SPEC_SCHEMA,
        "campaign_id": "campaign-a",
        "hosts": [{"host_id": host} for host in host_ids],
        "cells": cells(),
        "protocol": {"exploration_pairs": 6, "confirmation_pairs": 36},
        "aa_controls": [
            {"control_id": "aa-one", "allocator": "allocatbelt",
             "family": "cpu", "profile": "steady", "mode": "capacity",
             "load_percent": None, "executor": "bounded", "pairs": 2,
             "purpose": "fixture control"},
            {"control_id": "aa-two", "allocator": "system",
             "family": "mixed", "profile": "mixed", "mode": "capacity",
             "load_percent": None, "executor": "tokio", "pairs": 3,
             "purpose": "fixture control"},
        ],
        "rates": [
            {"host_id": host, "family": cell["family"],
             "profile": cell["profile"], "load_percent": load}
            for host in host_ids for cell in cells() for load in budget.LOADS
        ],
        "source_manifests": [
            {"host_id": host, "relative_path": f"sources/{host}.json",
             "sha256": source_values[host]["manifest_sha256"]}
            for host in host_ids
        ],
    }
    spec_raw = canonical(spec)
    spec_pin = {
        "path": "/inputs/spec.json", "raw_sha256": sha(spec_raw),
        "semantic_sha256": sha(spec_raw),
    }
    jobs: dict[str, list[dict[str, Any]]] = {
        phase: [] for phase in budget.PHASES
    }
    for host in host_ids:
        for ordinal in range(360):
            jobs["exploration"].append(make_job(
                host, "exploration", f"{host}-explore-{ordinal:03d}",
            ))
        for control in spec["aa_controls"]:
            for ordinal in range(1, control["pairs"] + 1):
                jobs["aa"].append(make_job(
                    host, "aa", f"{host}-{control['control_id']}-{ordinal:02d}",
                    control_id=control["control_id"], pairs=control["pairs"],
                    ordinal=ordinal,
                ))
        for cell_index, cell in enumerate(cells()):
            for load in (None, *budget.LOADS):
                for ordinal in range(1, 37):
                    for contrast in range(5):
                        mode = "capacity" if load is None else "open_loop"
                        common = {
                            "family": cell["family"],
                            "profile": cell["profile"],
                            "mode": mode, "load_percent": load,
                            "comparison_kind": "allocator" if contrast < 2 else "executor",
                            "ordinal": ordinal,
                            "allocator": "allocatbelt" if contrast < 2 else budget.ALLOCATORS[contrast - 2],
                            "baseline_allocator": budget.ALLOCATORS[contrast + 1] if contrast < 2 else None,
                            "executor": "bounded" if contrast != 4 else "tokio",
                            "pair_kind": f"contrast-{contrast}",
                        }
                        stem = f"{host}-{cell_index}-{load}-{ordinal}-{contrast}"
                        confirmation_id = f"{stem}-confirmation"
                        jobs["confirmation"].append(make_job(
                            host, "confirmation", confirmation_id, **common,
                        ))
                        pressure = {
                            **common,
                            "pair_kind": f"pressure-{common['pair_kind']}",
                            "predecessor_run_ids": [confirmation_id],
                        }
                        jobs["pressure"].append(make_job(
                            host, "pressure", f"{stem}-pressure", **pressure,
                        ))
        jobs["soak"].append(make_job(
            host, "soak", f"{host}-mixed-mixed-soak-allocatbelt-01",
        ))
    plan_body = {
        "schema": budget.PLAN_SCHEMA,
        "campaign_id": spec["campaign_id"],
        "spec_sha256": sha(spec_raw),
        "host_ids": host_ids,
        "source_manifests": {
            host: source_values[host]["manifest_sha256"]
            for host in host_ids
        },
        "jobs": jobs,
    }
    plan = sealed(plan_body, "plan_sha256")
    plan_raw = canonical(plan)
    plan_pin = {
        "path": "/inputs/plan.json", "raw_sha256": sha(plan_raw),
        "semantic_sha256": plan["plan_sha256"],
    }
    original_inputs = {
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
            for host in host_ids
        },
        "campaign_artifacts_root": "/campaign-artifacts",
    }
    execution_body = {
        "schema": "allocatbelt.application-source5-campaign-execution.v3",
        "campaign_id": spec["campaign_id"], "hosts": host_ids,
        "original_inputs": original_inputs,
        "execution_sources": {
            host: {"source_root": f"/source/{host}",
                   "git_commit": source_values[host]["source"]["git_commit"],
                   "source_tree_sha256": source_values[host]["source"]["source_tree_sha256"],
                   "build_sha256": sha(canonical(source_values[host]["build"]))}
            for host in host_ids
        },
        "qualification_eligible": False,
    }
    execution = sealed(execution_body, "manifest_sha256")
    execution_raw = canonical(execution)
    execution_pin = {
        "path": "/output/execution-manifest.json",
        "raw_sha256": sha(execution_raw),
        "semantic_sha256": execution["manifest_sha256"],
    }
    pins = {
        "spec": spec_pin, "plan": plan_pin,
        "execution_manifest": execution_pin,
        "source_manifests": source_pins,
    }
    return {
        "spec": spec, "plan": plan, "sources": source_values,
        "host_id": "host-a", "execution": execution, "pins": pins,
    }


def repin_plan_case(value: dict[str, Any]) -> None:
    plan = value["plan"]
    plan = sealed({key: item for key, item in plan.items()
                   if key != "plan_sha256"}, "plan_sha256")
    value["plan"] = plan
    plan_raw = canonical(plan)
    value["pins"]["plan"] = {
        "path": "/inputs/plan.json", "raw_sha256": sha(plan_raw),
        "semantic_sha256": plan["plan_sha256"],
    }
    execution = copy.deepcopy(value["execution"])
    execution["original_inputs"]["plan"] = {
        "artifact": {"path": value["pins"]["plan"]["path"],
                     "raw_sha256": value["pins"]["plan"]["raw_sha256"]},
        "semantic_sha256": value["pins"]["plan"]["semantic_sha256"],
    }
    execution = sealed({key: item for key, item in execution.items()
                        if key != "manifest_sha256"}, "manifest_sha256")
    execution_raw = canonical(execution)
    value["execution"] = execution
    value["pins"]["execution_manifest"] = {
        "path": "/output/execution-manifest.json",
        "raw_sha256": sha(execution_raw),
        "semantic_sha256": execution["manifest_sha256"],
    }


class Source5EvidenceBudgetPlanTests(unittest.TestCase):
    def test_schedule_derives_aa_count_callbacks_and_false_readiness(self) -> None:
        value = fixture()
        audit = budget.build_host_evidence_budget_plan(
            value["spec"], value["plan"], value["sources"],
            value["execution"], value["host_id"], pins_value=value["pins"],
        )
        self.assertEqual(audit["schedule"]["aa_pair_count_from_spec"], 5)
        self.assertEqual(audit["schedule"]["job_counts"], {
            "exploration": 360, "aa": 5, "confirmation": 8100,
            "pressure": 8100, "soak": 1,
        })
        self.assertEqual(audit["schedule"]["total_job_count"], 16_566)
        self.assertEqual(audit["schedule"]["maximum_callback_events"], 99_401)
        self.assertEqual(audit["schedule"]["worst_case_journal_bytes"],
                         min(budget.CORE_ROLE_BYTES_CAP,
                             99_401 * budget.MAX_EVENT_BYTES))
        self.assertGreater(audit["producer_catalogue"][
            "lower_bound_store_entries_before_soak/common_inputs"], 800_000)
        self.assertFalse(audit["readiness"]["budget_complete"])
        self.assertFalse(audit["readiness"]["execution_ready"])
        self.assertFalse(audit["readiness"]["qualification_eligible"])

    def test_budget_audit_rejects_missing_original_aa_repeat_and_predecessor(self) -> None:
        value = fixture()
        broken_aa = copy.deepcopy(value)
        broken_aa["plan"]["jobs"]["aa"] = [
            row for row in broken_aa["plan"]["jobs"]["aa"]
            if not (row["host_id"] == "host-a" and row["control_id"] == "aa-one" and row["ordinal"] == 2)
        ]
        repin_plan_case(broken_aa)
        with self.assertRaisesRegex(budget.BudgetPlanError,
                                    "full original protocol/A/A controls"):
            budget.build_host_evidence_budget_plan(
                broken_aa["spec"], broken_aa["plan"], broken_aa["sources"],
                broken_aa["execution"], broken_aa["host_id"],
                pins_value=broken_aa["pins"],
            )

        broken_predecessor = copy.deepcopy(value)
        broken_predecessor["plan"]["jobs"]["pressure"][0]["predecessor_run_ids"] = []
        repin_plan_case(broken_predecessor)
        with self.assertRaisesRegex(budget.BudgetPlanError,
                                    "one original confirmation predecessor"):
            budget.build_host_evidence_budget_plan(
                broken_predecessor["spec"], broken_predecessor["plan"],
                broken_predecessor["sources"], broken_predecessor["execution"],
                broken_predecessor["host_id"],
                pins_value=broken_predecessor["pins"],
            )

    def test_execution_manifest_pin_mismatch_is_not_relabelled(self) -> None:
        value = fixture()
        broken = copy.deepcopy(value)
        broken["execution"]["original_inputs"]["spec"]["semantic_sha256"] = "f" * 64
        broken["execution"] = sealed({key: item for key, item in broken["execution"].items()
                                      if key != "manifest_sha256"}, "manifest_sha256")
        with self.assertRaisesRegex(budget.BudgetPlanError,
                                    "execution manifest changed the original spec pin"):
            budget.build_host_evidence_budget_plan(
                broken["spec"], broken["plan"], broken["sources"],
                broken["execution"], broken["host_id"], pins_value=broken["pins"],
            )


class Source5JournalWidthContractTests(unittest.TestCase):
    @staticmethod
    def summary_fixture(*, include_audit_budget_pins: bool):
        catalogue_roles = {
            "fixed_pair", "pressure_pair", "source5_controller", "source5_soak",
            "soak_reader", "offline_dispatcher", "chronology",
            "evidence_transport",
        }
        budget_roles = {
            "fixed_pair", "pressure_pair", "source5_controller", "source5_soak",
            "soak_reader", "feedback_composer", "feedback_reader",
            "pressure_reader", "evidence_transport",
        }
        role_rows = {}
        for index, role in enumerate(sorted(catalogue_roles | budget_roles), 1):
            role_rows[role] = {
                "path": f"scripts/source-{role.replace('_', '-')}.py",
                "raw_sha256": f"{index:064x}",
                "byte_count": 100 + index,
            }
        catalogue_pins = {
            role: dict(role_rows[role]) for role in catalogue_roles
        }
        original_pins = {
            "plan": {
                "path": "/inputs/plan.json", "raw_sha256": "a" * 64,
                "semantic_sha256": "b" * 64,
            },
            "source_manifests": {"host-a": {
                "path": "/inputs/source.json", "raw_sha256": "c" * 64,
                "semantic_sha256": "d" * 64,
            }},
        }
        event_counts = {
            "source5_authorized": 1,
            "source5_app_started": 2,
            "source5_app_terminal": 2,
            "source5_job_terminal": 1,
        }
        event_widths = {kind: 100 for kind in event_counts}
        job_row = {
            "phase": "exploration", "job_index": 0, "ordinal": 1,
            "run_id": "original-run-1", "job_sha256": "e" * 64,
            "event_counts": event_counts,
            "maximum_event_bytes_by_kind": event_widths,
            "failed_event_counts": event_counts,
            "failed_event_bytes_by_kind": dict(event_widths),
            "success_job_bytes": 600, "failed_window_bytes": 600,
            "failed_event_count": 6, "failed_event_count_uplift": 0,
            "byte_uplift": 0,
        }
        phase_totals = [{
            "phase": phase, "job_count": int(phase == "exploration"),
            "event_count": 6 if phase == "exploration" else 0,
            "success_event_bytes": 600 if phase == "exploration" else 0,
        } for phase in budget.PHASES]
        fixed_event_widths = [{
            "event": event, "phase": phase, "count": 1,
            "maximum_line_bytes": 100,
        } for event, phase in (
            ("source5_prepared_capacity_registered", "registration"),
            *(("source5_analysis", phase) for phase in (
                "exploration", "aa", "fixed_analysis", "pressure_analysis",
                "soak", "final_analysis",
            )),
        )]
        failed_window = {
            key: job_row[key] for key in (
                "phase", "job_index", "ordinal", "run_id", "job_sha256",
                "failed_event_count", "failed_event_count_uplift",
                "failed_window_bytes", "success_job_bytes", "byte_uplift",
            )
        }
        body = {
            "schema": budget.JOURNAL_WIDTH_CONTRACT_SCHEMA,
            "campaign_id": "campaign-a", "host_id": "host-a",
            "original_pins_sha256": "f" * 64,
            "plan_pin": original_pins["plan"],
            "source_manifest_pin": original_pins["source_manifests"]["host-a"],
            "owner_pins": role_rows,
            "job_rows": [job_row], "phase_totals": phase_totals,
            "fixed_event_widths": fixed_event_widths,
            "total_event_count": 13, "total_event_bytes": 1300,
            "failed_owner_window": failed_window,
        }
        contract = sealed(body, "contract_sha256")
        audit = {
            "campaign_id": "campaign-a", "host_id": "host-a",
            "original_pins": original_pins,
            "schedule": {
                "job_counts": {phase: int(phase == "exploration")
                                for phase in budget.PHASES},
                "maximum_callback_events": 13,
            },
        }
        if include_audit_budget_pins:
            audit["producer_catalogue"] = {
                "owner_schema_pins": {
                    role: {
                        "path": role_rows[role]["path"], "mode": "100644",
                        "sha256": role_rows[role]["raw_sha256"],
                        "size": role_rows[role]["byte_count"],
                    } for role in budget_roles
                },
            }
        return contract, audit, {"owner_source_pins": catalogue_pins}

    def test_width_contract_verifies_captured_bytes_without_opening_origin(self) -> None:
        body = {"schema": budget.JOURNAL_WIDTH_CONTRACT_SCHEMA}
        contract = {**body, "contract_sha256": sha(canonical(body))}
        raw = canonical(contract)
        pin = {
            "path": "/host-origin/not-readable-on-coordinator.json",
            "raw_sha256": sha(raw),
            "semantic_sha256": contract["contract_sha256"],
        }
        checked, checked_raw, checked_pin = \
            budget._verify_captured_journal_width_contract(pin, raw)
        self.assertEqual(checked, contract)
        self.assertEqual(checked_raw, raw)
        self.assertEqual(checked_pin, pin)

        with self.assertRaisesRegex(budget.BudgetPlanError, "raw pin differs"):
            budget._verify_captured_journal_width_contract(pin, raw + b" ")

    def test_width_summary_replays_eleven_role_union_without_serializing_audit_profile(self) -> None:
        contract, audit, owner_contract = self.summary_fixture(
            include_audit_budget_pins=False,
        )
        checked, event_count, maximum_line = \
            budget._validate_journal_width_contract_summary(
                contract, audit, owner_contract,
            )
        self.assertEqual(checked, contract)
        self.assertEqual(event_count, 13)
        self.assertEqual(maximum_line, 100)

    def test_width_summary_compares_all_nine_budget_pins_when_audit_is_available(self) -> None:
        contract, audit, owner_contract = self.summary_fixture(
            include_audit_budget_pins=True,
        )
        budget._validate_journal_width_contract_summary(
            contract, audit, owner_contract,
        )
        audit["producer_catalogue"]["owner_schema_pins"]["feedback_reader"][
            "sha256"
        ] = "0" * 64
        with self.assertRaisesRegex(
                budget.BudgetPlanError,
                "exact campaign/host/input/source pins"):
            budget._validate_journal_width_contract_summary(
                contract, audit, owner_contract,
            )


class Source5PathCatalogueTests(unittest.TestCase):
    @staticmethod
    def row(path: str, *, role: str = "normal_app_output",
            kind: str = "file", maximum: int = 11,
            file_maximum: int | None = None, inodes: int = 1,
            aggregate: str | None = None,
            aggregate_maximum: int | None = None) -> dict[str, Any]:
        if file_maximum is None:
            file_maximum = maximum
        return {
            "path": path, "kind": kind, "role": role,
            "host_id": "host-a", "max_bytes": maximum,
            "max_file_bytes": file_maximum, "max_inodes": inodes,
            "storage_root": "/private/artifacts", "owner": "fixed_pair",
            "phase": "confirmation", "run_id": "original-run-01",
            "member_index": None, "aggregate_id": aggregate,
            "aggregate_max_bytes": aggregate_maximum,
            "origin_pin": None,
        }

    def test_external_sort_closes_duplicates_and_owner_aggregate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-catalogue-") as tmp:
            directory = Path(tmp) / "catalogue"
            directory.mkdir(mode=0o700)
            rows = [self.row(f"/private/artifacts/z-{index:04d}")
                    for index in range(budget.PATH_CATALOGUE_RUN_ROWS + 3, 0, -1)]
            rows.extend([
                self.row("/private/artifacts/job-a", maximum=30,
                         aggregate="fixed-output", aggregate_maximum=50),
                self.row("/private/artifacts/job-b", maximum=40,
                         role="fixed_pair_artifact", aggregate="fixed-output",
                         aggregate_maximum=50),
                self.row("/private/artifacts/job-a", maximum=30,
                         aggregate="fixed-output", aggregate_maximum=50),
                self.row("/private/artifacts/tmp", role="normal_app_output",
                         kind="tree", maximum=1024, file_maximum=128, inodes=5),
            ])
            manifest = budget.write_path_catalogue_chunks(rows, directory)
            checked = budget.validate_path_catalogue_manifest(manifest)
            self.assertEqual(checked["entry_count"], budget.PATH_CATALOGUE_RUN_ROWS + 6)
            self.assertEqual(checked["file_count"], budget.PATH_CATALOGUE_RUN_ROWS + 5)
            self.assertEqual(checked["tree_count"], 1)
            self.assertEqual(checked["maximum_payload_bytes"],
                             (budget.PATH_CATALOGUE_RUN_ROWS + 3) * 11 + 50 + 1024)
            self.assertEqual(checked["maximum_index_entries"],
                             budget.PATH_CATALOGUE_RUN_ROWS + 5 + 4)
            self.assertEqual(checked["retention_policy"]["mode"],
                             budget.RETENTION_POLICY_MODE_V2)
            self.assertEqual(checked["maximum_live_inode_count"],
                             sum(checked["retention_policy"][
                                 "maximum_live_root_inode_bounds"].values()))
            first_chunk = checked["chunks"][0]
            raw = Path(first_chunk["path"]).read_bytes()
            self.assertEqual(sha(raw), first_chunk["raw_sha256"])
            decoded = [json.loads(line) for line in raw.splitlines()]
            self.assertEqual(decoded[0]["path"], "/private/artifacts/job-a")
            self.assertEqual(
                decoded[-1]["path"],
                f"/private/artifacts/z-{budget.PATH_CATALOGUE_RUN_ROWS + 3:04d}",
            )
            chunks = {
                item["path"]: Path(item["path"]).read_bytes()
                for item in checked["chunks"]
            }

            def captured_reader(path: str, byte_count: int) -> bytes:
                value = chunks[path]
                self.assertEqual(len(value), byte_count)
                return value

            captured_rows = list(budget.iter_path_catalogue_rows_with_reader(
                checked, captured_reader,
            ))
            self.assertEqual(len(captured_rows), checked["entry_count"])
            validated = budget.verify_path_catalogue_chunks_with_reader(
                checked, captured_reader,
            )
            self.assertEqual(validated["entry_count"], checked["entry_count"])

    def test_catalogue_conflicting_duplicate_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-catalogue-conflict-") as tmp:
            directory = Path(tmp) / "catalogue"
            directory.mkdir(mode=0o700)
            rows = [
                self.row("/private/artifacts/shared", role="normal_app_output"),
                self.row("/private/artifacts/shared", role="opaque_trace"),
            ]
            with self.assertRaisesRegex(budget.BudgetPlanError,
                                        "incompatible declarations"):
                budget.write_path_catalogue_chunks(rows, directory)

    def test_always_local_job_records_accumulate_across_completed_windows(self) -> None:
        rows = []
        record_sizes = {"original-run-01": 100, "original-run-02": 200}
        for run_id, record_size in record_sizes.items():
            record = self.row(
                f"/private/artifacts/job-records/{run_id}.json",
                role="source5_job_record", maximum=record_size,
            )
            record["run_id"] = run_id
            rows.append(record)
            app_output = self.row(
                f"/private/artifacts/pairs/{run_id}/stdout.tsv",
                maximum=17,
            )
            app_output["run_id"] = run_id
            rows.append(app_output)

        caps_by_job = budget.project_archive_job_caps(rows)
        catalogue_rows = []
        for run_id in record_sizes:
            local_catalogue = self.row(
                f"/private/artifacts/job-path-catalogues/{run_id}.jsonl",
                role="source5_job_row_catalogue", maximum=37,
            )
            local_catalogue["run_id"] = run_id
            catalogue_rows.append(local_catalogue)
        rows.extend(catalogue_rows)
        cleanup_cap = budget._cleanup_sidecar_source_bound(
            budget.SOURCE5_CLEANUP_SESSION_MEMBER_LIMIT,
        )
        for ordinal, run_id in enumerate(record_sizes, 1):
            for member_index in (0, 1):
                prefix = (f"/private/output/confirmation/cleanup-sidecars/"
                          f"{ordinal:06d}-{'a' * 64}-member{member_index}.json")
                for role, path, maximum in (
                    (budget.SOURCE5_CLEANUP_SIDECAR_ROLE,
                     prefix, cleanup_cap),
                    (budget.SOURCE5_CLEANUP_SIDECAR_REFUSAL_ROLE,
                     prefix + ".refusal.json",
                     budget.SOURCE5_CLEANUP_REFUSAL_BYTES),
                ):
                    cleanup_row = self.row(path, role=role, maximum=maximum)
                    cleanup_row["phase"] = "confirmation"
                    cleanup_row["run_id"] = run_id
                    cleanup_row["member_index"] = member_index
                    cleanup_row["storage_root"] = "/private/output"
                    rows.append(cleanup_row)
        self.assertEqual(budget.project_archive_job_caps(rows), caps_by_job)
        transport_roles = (
            ("source5_checkpoint_request", "checkpoint_request_bytes", "/private/output"),
            ("source5_transfer_offer", "transfer_offer_bytes", "/private/output"),
            ("source5_transfer_packet", "transfer_packet_bytes", "/private/scratch"),
            ("source5_ack_bundle", "ack_bundle_bytes", "/private/output"),
            ("source5_ack_bundle_incoming", "ack_bundle_bytes", "/private/output"),
            ("source5_checkpoint", "checkpoint_bytes", "/private/output"),
            ("source5_object_manifest", "object_manifest_bytes", "/private/output"),
            ("source5_archive_ack", "archive_ack_bytes", "/private/output"),
            ("source5_archive_signature", "signature_bytes", "/private/output"),
            ("source5_stage_map", "stage_map_bytes", "/private/output"),
        )
        for (phase, run_id), caps in caps_by_job.items():
            for role, cap_field, storage_root in transport_roles:
                row = self.row(
                    f"{storage_root}/evidence/{run_id}-{role}.bin",
                    role=role, maximum=caps[cap_field],
                )
                row["run_id"] = run_id
                row["storage_root"] = storage_root
                rows.append(row)

        retention = budget._retention_projection(rows)
        self.assertEqual(
            retention["persistent_root_byte_bounds"]["/private/artifacts"],
            sum(record_sizes.values()) + 37 * len(record_sizes),
        )
        self.assertEqual(retention["persistent_local_job_record_count"], 2)
        self.assertEqual(retention["maximum_job_record_bytes"], 200)
        self.assertEqual(retention["archive_metadata_job_group_count"], 2)
        self.assertEqual(retention["maximum_failed_cleanup_window_bytes"],
                         786_770_440)
        self.assertEqual(retention["maximum_failed_cleanup_window_inodes"], 2)

    def test_archive_readback_caps_include_every_probe_tree_file_child(self) -> None:
        rows = [
            self.row("/private/output/confirmation/component.json",
                     role="component_receipt", maximum=128),
            self.row("/private/output/confirmation/probe/receipt.json",
                     role="probe_capture_receipt_member0", maximum=256),
            self.row("/private/output/confirmation/probe/inventory.json",
                     role="probe_capture_inventory_member0", maximum=1024),
            self.row("/private/output/confirmation/probe/tmp",
                     role="opaque_trace", kind="tree", maximum=4096,
                     file_maximum=1024, inodes=3),
        ]
        rows[1]["member_index"] = 0
        rows[2]["member_index"] = 0
        rows[3]["member_index"] = 0
        caps = budget.project_archive_readback_caps(rows)[
            ("confirmation", "original-run-01")
        ]
        self.assertEqual(caps["object_count"], 5)
        self.assertEqual(caps["stage_bytes"], 128 + 256 + 1024 + 4096)
        self.assertEqual(caps["stage_inodes"], 6)
        self.assertEqual(caps["maximum_object_bytes"], 1024)
        self.assertLessEqual(
            caps["request_bytes"], budget.MAX_ARCHIVE_READ_METADATA_BYTES,
        )
        self.assertLessEqual(
            caps["response_bytes"], budget.MAX_ARCHIVE_READ_METADATA_BYTES,
        )

    def test_cleanup_source_shape_binds_generic_member_and_error_caps(self) -> None:
        shape = budget._cleanup_source_shape(
            budget.SOURCE5_CLEANUP_SESSION_MEMBER_LIMIT,
        )
        self.assertEqual(shape["maximum_session_members_per_snapshot"], 262_144)
        self.assertEqual(shape["maximum_pidfd_signal_entries_per_snapshot"], 262_144)
        self.assertEqual(shape["maximum_signal_snapshots"], 5)
        self.assertEqual(shape["maximum_cleanup_errors"], 1348)
        self.assertEqual(shape["maximum_error_text_bytes"], 8192)
        self.assertEqual(shape["source_maximum_bytes"], 393_385_220)
        self.assertEqual(shape["admission_maximum_bytes"], 393_385_220)
        self.assertEqual(shape["maximum_window_bytes"], 786_770_440)
        self.assertEqual(shape["refusal_file_bytes"], 65_536)
        self.assertEqual(shape["maximum_refusal_window_bytes"], 131_072)

    def test_archive_caps_cover_r3_stage_schema_and_original_run_id_width(self) -> None:
        row = self.row(
            "/private/artifacts/pairs/original-run-01/stdout.tsv",
            maximum=4096,
        )
        stage = json.loads(budget._archive_stage_entry_bound(row))
        self.assertEqual(set(stage), {
            "origin_path", "object_id", "remote_object_pin", "local_staged_file",
        })
        self.assertEqual(stage["remote_object_pin"]["byte_count"], 4096)
        self.assertEqual(set(stage["local_staged_file"]), {
            "path", "kind", "device", "inode", "mode", "byte_count",
            "raw_sha256",
        })
        self.assertEqual(stage["local_staged_file"]["byte_count"], 4096)
        short = budget._archive_ack_bundle_bounds(
            "confirmation", "run-1", (), 1, 0, 0,
        )
        long_run_id = "original-run-" + "x" * 240
        long = budget._archive_ack_bundle_bounds(
            "confirmation", long_run_id, (), 1, 0, 0,
        )
        self.assertGreater(long["object_manifest_bytes"],
                           short["object_manifest_bytes"])

    def test_v4_analyzer_spool_adds_to_the_active_archive_readback_window(self) -> None:
        scratch_root = "/private/scratch"
        output_root = "/private/output"
        rows = []
        for role, name, maximum, kind, file_maximum, inodes in (
            ("source5_archive_read_request_slot", "request.json", 11,
             "file", 11, 1),
            ("source5_archive_read_response_slot", "response.json", 13,
             "file", 13, 1),
            ("source5_archive_read_response_incoming",
             "response.json.incoming", 13, "file", 13, 1),
            ("source5_archive_read_bundle", "response.tar", 17,
             "file", 17, 1),
            ("source5_archive_read_bundle_incoming",
             "response.tar.incoming", 17, "file", 17, 1),
            ("source5_archive_read_stage", "stage", 100,
             "tree", 80, 4),
        ):
            row = Source5PathCatalogueTests.row(
                f"{scratch_root}/campaign/host/archive-readback/{name}",
                role=role, maximum=maximum, kind=kind,
                file_maximum=file_maximum, inodes=inodes,
            )
            row.update({"phase": None, "run_id": None,
                        "member_index": None, "aggregate_id": None,
                        "owner": "source5_controller",
                        "storage_root": scratch_root})
            rows.append(row)
        control = Source5PathCatalogueTests.row(
            f"{output_root}/campaign/source5/host/archive-read-control.jsonl",
            role=budget.SOURCE5_ARCHIVE_READ_CONTROL_ROLE, maximum=23,
        )
        control.update({"phase": None, "run_id": None,
                        "member_index": None, "aggregate_id": None,
                        "owner": "source5_controller",
                        "storage_root": output_root})
        rows.append(control)
        width = Source5PathCatalogueTests.row(
            f"{output_root}/campaign/source5/host/journal-width.json",
            role="journal_width_contract", maximum=29,
        )
        width.update({"phase": None, "run_id": None,
                      "member_index": None, "aggregate_id": None,
                      "owner": "source5_controller",
                      "storage_root": output_root})
        rows.append(width)
        analyzer = Source5PathCatalogueTests.row(
            f"{scratch_root}/campaign/host/analyzer-spool",
            role=budget.SOURCE5_ANALYZER_SPOOL_ROLE,
            kind="tree", maximum=101, file_maximum=77, inodes=3,
        )
        analyzer.update({"phase": None, "run_id": None,
                         "member_index": None, "aggregate_id": None,
                         "owner": "source5_controller",
                         "storage_root": scratch_root})
        rows.append(analyzer)
        rows.append(Source5PathCatalogueTests.row(
            "/private/artifacts/confirmation/original-run-01/output.json",
            maximum=20,
        ))

        with tempfile.TemporaryDirectory(prefix="source5-v4-analyzer-window-") as tmp:
            catalogue_directory = Path(tmp) / "catalogue"
            catalogue_directory.mkdir(mode=0o700)
            manifest = budget.write_path_catalogue_chunks(
                rows, catalogue_directory,
            )
        policy = manifest["retention_policy"]
        expected_scratch_bytes = 11 + 13 + 17 + 100 + 101
        expected_scratch_inodes = 1 + 1 + 1 + 4 + 3
        self.assertEqual(
            policy["maximum_window_root_byte_bounds"][scratch_root],
            expected_scratch_bytes,
        )
        self.assertEqual(
            policy["maximum_window_root_inode_bounds"][scratch_root],
            expected_scratch_inodes,
        )
        self.assertEqual(policy["maximum_window_total_bytes"],
                         expected_scratch_bytes)
        self.assertEqual(policy["maximum_window_total_inodes"],
                         expected_scratch_inodes)
        self.assertEqual(manifest["maximum_payload_bytes"], 243)
        self.assertEqual(
            manifest["role_byte_bounds"][budget.SOURCE5_ANALYZER_SPOOL_ROLE],
            101,
        )
        self.assertNotIn(budget.SOURCE5_ANALYZER_SPOOL_ROLE,
                         policy["always_local_roles"])



class Source5HostEvidenceBudgetV2Tests(unittest.TestCase):
    def test_budget_reserves_its_own_artifact_and_store_bytes_once(self) -> None:
        fixture_value = fixture()
        audit = budget.build_host_evidence_budget_plan(
            fixture_value["spec"], fixture_value["plan"],
            fixture_value["sources"], fixture_value["execution"],
            fixture_value["host_id"], pins_value=fixture_value["pins"],
        )
        # This budget-construction regression keeps one exact original job so
        # its storage arithmetic stays small and legible. The full schedule
        # and producer-count tests remain covered above.
        audit = copy.deepcopy(audit)
        audit["schedule"]["job_counts"] = {
            "exploration": 1, "aa": 0, "confirmation": 0,
            "pressure": 0, "soak": 0,
        }
        audit["schedule"]["fixed_job_count"] = 1
        audit["schedule"]["pressure_job_count"] = 0
        audit["schedule"]["total_job_count"] = 1
        audit["schedule"]["maximum_callback_events"] = 13
        audit["schedule"]["worst_case_journal_bytes"] = 13 * budget.MAX_EVENT_BYTES
        audit = sealed({key: item for key, item in audit.items()
                        if key != "budget_plan_sha256"}, "budget_plan_sha256")
        source_digest = audit["original_pins"]["source_manifests"][
            fixture_value["host_id"]
        ]["semantic_sha256"]
        contract_body = {
            "schema": "allocatbelt.application-source5-owner-evidence-catalogue.v1",
            "source_manifest_sha256": source_digest,
            "owner_source_pins": {}, "fixed_pair": {}, "pressure_pair": {},
            "soak": {}, "transport_caps": {
                "chronology": {"MAX_COMPLETION_BYTES": 16 * 1024 * 1024},
            },
            "cleanup_source_shape": {
                key: value for key, value in budget._cleanup_source_shape(
                    budget.SOURCE5_CLEANUP_SESSION_MEMBER_LIMIT,
                ).items()
                if key in {
                    "maximum_session_members_per_snapshot",
                    "maximum_pidfd_signal_entries_per_snapshot",
                    "maximum_signal_snapshots", "maximum_cleanup_errors",
                    "maximum_error_text_bytes", "normal_cleanup_poll_count",
                    "emergency_cleanup_poll_count", "term_grace_seconds",
                    "kill_reap_seconds", "cleanup_poll_interval_seconds",
                }
            },
            "role_ceiling_conflicts": {},
            "exact_full_path_catalogue_complete": True,
            "execution_ready": False, "qualification_eligible": False,
        }
        contract = {
            **contract_body,
            "owner_contract_sha256": sha(canonical(contract_body)),
        }
        with tempfile.TemporaryDirectory(prefix="source5-budget-v2-") as tmp:
            root = Path(tmp)
            catalogue_directory = root / "catalogue"
            catalogue_directory.mkdir(mode=0o700)
            core_rows = [Source5PathCatalogueTests.row(
                "/private/artifacts/app-output", maximum=1024,
            ), Source5PathCatalogueTests.row(
                "/private/artifacts/job-records/original-run-01.json",
                role="source5_job_record", maximum=128 * 1024,
            )]
            cleanup_cap = budget._cleanup_sidecar_source_bound(
                budget.SOURCE5_CLEANUP_SESSION_MEMBER_LIMIT,
            )
            for member_index in (0, 1):
                cleanup_stem = (f"/private/output/confirmation/cleanup-sidecars/"
                                f"000001-{'a' * 64}-member{member_index}.json")
                for role, path, maximum in (
                    (budget.SOURCE5_CLEANUP_SIDECAR_ROLE,
                     cleanup_stem, cleanup_cap),
                    (budget.SOURCE5_CLEANUP_SIDECAR_REFUSAL_ROLE,
                     cleanup_stem + ".refusal.json",
                     budget.SOURCE5_CLEANUP_REFUSAL_BYTES),
                ):
                    cleanup_row = Source5PathCatalogueTests.row(
                        path, role=role, maximum=maximum,
                    )
                    cleanup_row["phase"] = "confirmation"
                    cleanup_row["run_id"] = "original-run-01"
                    cleanup_row["member_index"] = member_index
                    cleanup_row["storage_root"] = "/private/output"
                    core_rows.append(cleanup_row)
            caps = budget.project_archive_job_caps(core_rows)[
                ("confirmation", "original-run-01")
            ]
            transport_rows = []
            for role, field, root in (
                ("source5_checkpoint_request", "checkpoint_request_bytes", "/private/output"),
                ("source5_transfer_offer", "transfer_offer_bytes", "/private/output"),
                ("source5_transfer_packet", "transfer_packet_bytes", "/private/scratch"),
                ("source5_ack_bundle", "ack_bundle_bytes", "/private/output"),
                ("source5_ack_bundle_incoming", "ack_bundle_bytes", "/private/output"),
                ("source5_checkpoint", "checkpoint_bytes", "/private/output"),
                ("source5_object_manifest", "object_manifest_bytes", "/private/output"),
                ("source5_archive_ack", "archive_ack_bytes", "/private/output"),
                ("source5_archive_signature", "signature_bytes", "/private/output"),
                ("source5_stage_map", "stage_map_bytes", "/private/output"),
            ):
                row = Source5PathCatalogueTests.row(
                    f"{root}/evidence/{role}.bin", role=role,
                    maximum=caps[field],
                )
                row["storage_root"] = root
                transport_rows.append(row)
            catalogue = budget.write_path_catalogue_chunks(
                [*core_rows, *transport_rows], catalogue_directory,
            )
            roots = [
                {"path": "/private/artifacts", "role": "artifact",
                 "reserved_bytes": budget.MAX_U64,
                 "reserved_inodes": budget.MAX_U64, "filesystem_id": "1"},
                {"path": "/private/output", "role": "output",
                 "reserved_bytes": budget.MAX_U64,
                 "reserved_inodes": budget.MAX_U64, "filesystem_id": "2"},
                {"path": "/private/scratch", "role": "scratch",
                 "reserved_bytes": budget.MAX_U64,
                 "reserved_inodes": budget.MAX_U64, "filesystem_id": "3"},
                {"path": "/private/store", "role": "evidence_store",
                 "reserved_bytes": budget.MAX_U64,
                 "reserved_inodes": budget.MAX_U64, "filesystem_id": "4"},
            ]
            reservation = budget.build_storage_reservation_value(
                "campaign-a", "host-a", roots,
            )
            reservation_raw = canonical(reservation)
            reservation_pin = {
                "path": "/private/reservation.json",
                "raw_sha256": sha(reservation_raw),
                "semantic_sha256": reservation["reservation_sha256"],
                "byte_count": len(reservation_raw),
            }
            result = budget.build_host_evidence_budget_v2(
                audit, contract, catalogue, reservation, reservation_pin,
            )
            checked = budget.validate_host_evidence_budget_v2(result)
            self.assertEqual(result, checked)
            self.assertEqual(set(result), {
                "schema", "campaign_id", "host_id", "original_pins",
                "schedule", "owner_contract", "path_catalogue",
                "storage_reservation", "role_byte_reservations", "transport",
                "execution_blockers", "readiness", "budget_sha256",
            })
            self.assertNotIn("journal_width_contract_pin", result)
            self.assertEqual(
                catalogue["retention_policy"]["maximum_job_record_bytes"],
                128 * 1024,
            )
            encoded_budget_bytes = len(canonical(result))
            catalogue_chunk_bytes = sum(
                item["byte_count"] for item in catalogue["chunks"]
            )
            required = result["storage_reservation"]["required_bytes_by_root"]
            self.assertEqual(
                required["/private/artifacts"],
                catalogue["root_byte_bounds"]["/private/artifacts"] +
                catalogue_chunk_bytes + encoded_budget_bytes,
            )
            self.assertEqual(
                required["/private/store"],
                result["transport"]["maximum_index_bytes"] +
                result["transport"]["maximum_store_payload_bytes"] +
                result["transport"]["maximum_store_metadata_bytes"] +
                result["transport"]["maximum_store_root_bytes"] +
                encoded_budget_bytes,
            )
            self.assertEqual(
                result["storage_reservation"]["required_inodes_by_root"]["/private/store"],
                catalogue["maximum_index_chunks"] +
                catalogue["maximum_index_manifest_pages"] + 1 +
                result["transport"]["maximum_store_entries"] + 260,
            )
            self.assertEqual(
                required["/private/output"],
                catalogue["retention_policy"][
                    "maximum_live_root_byte_bounds"]["/private/output"] +
                16 * 1024 * 1024,
            )
            self.assertFalse(result["readiness"]["execution_ready"])
            self.assertFalse(result["readiness"]["budget_complete"])
            self.assertEqual(result["execution_blockers"], [
                "source_derived_journal_width_not_bound",
                "verified_between_pair_archive_ack_reclaim_not_integrated",
            ])

    def test_retention_projects_all_static_files_and_only_one_failed_tmp_window(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-retention-window-") as tmp:
            directory = Path(tmp) / "catalogue"
            directory.mkdir(mode=0o700)
            rows = [
                Source5PathCatalogueTests.row(
                    "/private/artifacts/phase-a-ledger", role="source5_phase_ledger",
                    maximum=7,
                ),
                Source5PathCatalogueTests.row(
                    "/private/artifacts/run-a/output.json", maximum=10,
                ),
                Source5PathCatalogueTests.row(
                    "/private/artifacts/run-a/tmp", role="normal_app_output",
                    kind="tree", maximum=4096, file_maximum=4096, inodes=5,
                ),
                {
                    **Source5PathCatalogueTests.row(
                        "/private/artifacts/run-b/output.json", maximum=20,
                    ),
                    "run_id": "original-run-02",
                },
                {
                    **Source5PathCatalogueTests.row(
                        "/private/artifacts/phase-b-ledger", role="source5_phase_ledger",
                        maximum=11,
                    ),
                    "run_id": "original-run-02",
                },
                {
                    **Source5PathCatalogueTests.row(
                        "/private/artifacts/run-b/tmp", role="normal_app_output",
                        kind="tree", maximum=8192, file_maximum=8192, inodes=9,
                    ),
                    "run_id": "original-run-02",
                },
            ]
            manifest = budget.write_path_catalogue_chunks(rows, directory)
            policy = manifest["retention_policy"]
            self.assertEqual(manifest["file_count"], 4)
            self.assertEqual(policy["maximum_full_index_entries"], 4 + 8)
            self.assertEqual(manifest["maximum_index_entries"], 4 + 8)
            self.assertEqual(manifest["maximum_payload_bytes"], 7 + 11 + 10 + 20 + 8192)
            self.assertEqual(
                policy["maximum_live_root_byte_bounds"]["/private/artifacts"],
                7 + 11 + 20 + 8192,
            )
            self.assertEqual(
                policy["persistent_root_byte_bounds"]["/private/artifacts"],
                7 + 11,
            )
            self.assertEqual(policy["maximum_failure_window_tmp_index_entries"], 8)
            self.assertEqual(policy["maximum_failure_window_tmp_payload_bytes"], 8192)
            self.assertGreater(
                policy["maximum_transfer_packet_bytes"],
                policy["maximum_window_total_bytes"],
            )
            self.assertEqual(policy["maximum_transfer_packet_inodes"], 1)



class Source5HostEvidenceBudgetV3SchemaTests(unittest.TestCase):
    def test_v3_ready_flags_require_json_booleans_not_integer_aliases(self) -> None:
        readiness = {
            "budget_complete": True,
            "execution_ready": True,
            "component_gate_ready": False,
            "qualification_eligible": False,
        }
        budget._validate_source5_v3_ready_state(readiness)
        for field, integer in (
            ("budget_complete", 1), ("execution_ready", 1),
            ("component_gate_ready", 0), ("qualification_eligible", 0),
        ):
            with self.subTest(field=field):
                mutant = dict(readiness)
                mutant[field] = integer
                with self.assertRaisesRegex(
                        budget.BudgetPlanError, "literal ready/unqualified booleans"):
                    budget._validate_source5_v3_ready_state(mutant)



if __name__ == "__main__":
    unittest.main()
