#!/usr/bin/env python3
"""Native unit regressions for the original prepared-lineage projector."""
from __future__ import annotations

import importlib.util
import copy
import hashlib
import json
import os
import shutil
import sys
import stat
import types
import unittest
import tempfile
from pathlib import Path, PurePosixPath
from typing import Callable


SOURCE = Path(__file__).with_name("application-source5-prepared-lineage.py")
SPEC = importlib.util.spec_from_file_location("source5_prepared_lineage_tests", SOURCE)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load the Source-pinned prepared-lineage unit target")
lineage = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lineage
SPEC.loader.exec_module(lineage)

CHRONOLOGY_SOURCE = Path(__file__).with_name("application-campaign-chronology.py")
CHRONOLOGY_SPEC = importlib.util.spec_from_file_location(
    "source5_prepared_lineage_chronology_tests", CHRONOLOGY_SOURCE,
)
if CHRONOLOGY_SPEC is None or CHRONOLOGY_SPEC.loader is None:
    raise RuntimeError("cannot load the Source-owned chronology unit target")
chronology = importlib.util.module_from_spec(CHRONOLOGY_SPEC)
sys.modules[CHRONOLOGY_SPEC.name] = chronology
CHRONOLOGY_SPEC.loader.exec_module(chronology)


def load_sibling_module(filename: str, module_name: str):
    source = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, source)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load Source-pinned test dependency {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


campaign_core = load_sibling_module(
    "application-campaign.py", "source5_prepared_lineage_campaign_tests",
)
prep_budget = load_sibling_module(
    "application-source5-preparatory-budget.py",
    "source5_prepared_lineage_prep_budget_tests",
)
source5_campaign = load_sibling_module(
    "application-source5-campaign.py", "source5_prepared_lineage_source5_tests",
)
fixed_pair = load_sibling_module(
    "application-fixed-pair.py", "source5_prepared_lineage_fixed_pair_tests",
)
producer_support = load_sibling_module(
    "test-full-profile-preparatory-producer-support.py",
    "source5_full_profile_prep_producer_support_tests",
)


def original_jobs(host_id: str = "host-kvm-a") -> list[dict[str, object]]:
    return [
        {
            "phase": "exploration", "host_id": host_id,
            "family": f"family-{family}", "profile": f"profile-{profile}",
            "allocator": f"allocator-{allocator}", "ordinal": ordinal,
            "run_id": f"run-{family}-{profile}-{allocator}-{ordinal}",
        }
        for family in range(5)
        for profile in range(3)
        for allocator in range(4)
        for ordinal in range(1, 7)
    ]


def synthetic_full_replay_case(*, generated=None):
    """Build a SourceA protocol-component chain, with no observed process facts."""
    lineage = globals()["lineage"]
    chronology = globals()["chronology"]
    campaign_core = globals()["campaign_core"]
    prep_budget = globals()["prep_budget"]
    source5_campaign = globals()["source5_campaign"]
    if generated is not None:
        typed_modules = generated[0].modules
        lineage = typed_modules["scripts/application-source5-prepared-lineage.py"]
        chronology = typed_modules["scripts/application-campaign-chronology.py"]
        campaign_core = typed_modules["scripts/application-campaign.py"]
        prep_budget = typed_modules["scripts/application-source5-preparatory-budget.py"]
        source5_campaign = typed_modules["scripts/application-source5-campaign.py"]
    campaign_id, host_id = "synthetic-lineage", "host-kvm-a"
    output_root = "/tmp/synthetic-initial-output"
    spec = {
        "campaign_id": campaign_id,
        "hosts": [{"host_id": host_id}],
        "cells": [
            {"family": f"family-{family}", "profile": f"profile-{profile}",
             "workload": f"workload-{family}-{profile}", "arrivals": []}
            for family in range(5) for profile in range(3)
        ],
        "protocol": {"exploration_pairs": 6, "schedule_seed": 1},
        "rates": [], "oracles": [],
    }
    jobs = campaign_core.build_jobs(spec, "exploration", host_id)
    digest = lambda char: char * 64
    spec_pin = {"path": "/tmp/synthetic-input/initial-spec.json",
                "raw_sha256": digest("1"), "semantic_sha256": digest("2")}
    plan_pin = {"path": "/tmp/synthetic-input/initial-plan.json",
                "raw_sha256": digest("3"), "semantic_sha256": digest("4")}
    source_pins = [
        {"host_id": host, "path": f"/tmp/synthetic-input/{host}.json",
         "raw_sha256": digest(raw), "semantic_sha256": digest(semantic),
         "source_tree_sha256": digest(tree)}
        for host, raw, semantic, tree in (
            (host_id, "5", "7", "9"),
            ("host-kvm-b", "6", "8", "0"),
        )
    ]
    controls = {"control": 1}
    observed = {
        "path": "/tmp/synthetic-input/observed-host.json",
        "raw_sha256": digest("a"), "boot_id_sha256": digest("b"),
        "controls_sha256": chronology.sha256_bytes(chronology.canonical_bytes(controls)),
        "controls": controls,
        "cpu_affinity": [0, 1], "network_namespace_inode": 44,
    }
    original_pins = {
        "schema": chronology.CHRONOLOGY_SCHEMA,
        "campaign_id": campaign_id, "host_id": host_id,
        "spec": spec_pin, "plan": plan_pin,
        "source_manifests": source_pins, "observed_host": observed,
        "capacity_stage": {"path": chronology.CAPACITY_STAGE_SOURCE_PATH,
                           "sha256": digest("d")},
        "chronology_module": {"path": chronology.CHRONOLOGY_SOURCE_PATH,
                              "sha256": digest("e")},
        "pair_runner": {"path": chronology.PAIR_RUNNER_SOURCE_PATH,
                        "sha256": digest("f")},
        "captured_modules": [],
    }
    kinds = tuple(chronology._SOURCE5_WIDTH_KINDS)
    counts = {
        "source5_authorized": 1, "source5_app_started": 2,
        "source5_app_terminal": 2, "source5_job_terminal": 1,
    }
    max_line = chronology.MAX_EVENT_BYTES
    job_rows = []
    for index, job in enumerate(jobs):
        widths = {kind: max_line for kind in kinds}
        success_bytes = sum(counts[kind] * widths[kind] for kind in kinds)
        job_rows.append({
            "phase": "exploration", "job_index": index,
            "ordinal": job["ordinal"], "run_id": job["run_id"],
            "job_sha256": chronology.sha256_bytes(chronology.canonical_bytes(job)),
            "event_counts": dict(counts),
            "maximum_event_bytes_by_kind": widths,
            "failed_event_counts": dict(counts),
            "failed_event_bytes_by_kind": dict(widths),
            "success_job_bytes": success_bytes,
            "failed_window_bytes": success_bytes,
            "failed_event_count": sum(counts.values()),
            "failed_event_count_uplift": 0, "byte_uplift": 0,
        })
    width_contract = {
        "schema": "allocatbelt.application-source5-preparatory-journal-width-contract.v1",
        "campaign_id": campaign_id, "host_id": host_id,
        "original_pins_sha256": chronology.sha256_bytes(
            chronology.canonical_bytes(original_pins),
        ),
        "plan_pin": plan_pin,
        "source_manifest_pin": {
            key: source_pins[0][key]
            for key in ("path", "raw_sha256", "semantic_sha256")
        },
        "owner_pins": {}, "job_rows": job_rows,
        "phase_totals": [],
        "fixed_event_widths": [{
            "event": "source5_prepared_capacity_registered",
            "phase": "registration", "count": 1,
            "maximum_line_bytes": max_line,
        }],
        "setup_event_widths": [{
            "event": "source5_prepared_capacity_registered",
            "phase": "registration", "count": 1,
            "maximum_line_bytes": max_line,
        }],
        "total_event_count": 2161,
        "total_event_bytes": chronology.MAX_SOURCE5_JOURNAL_BYTES,
        "original_callback_event_count": 2160, "setup_event_count": 1,
        "maximum_failed_event_count_uplift": 0,
        "execution_basis_sha256": digest("9"),
    }
    width_contract["contract_sha256"] = chronology.sha256_bytes(
        chronology.canonical_bytes({
            key: value for key, value in width_contract.items()
            if key != "contract_sha256"
        }),
    )
    width_projection, event_projection = \
        chronology._source5_preparatory_journal_projection(
            width_contract, jobs, host_id,
        )
    generation_completion = {
        "path": "/tmp/synthetic-input/capacity-generation.json",
        "raw_sha256": digest("a"), "semantic_sha256": digest("b"),
    }
    host_completion = {
        "path": "/tmp/synthetic-input/host-capacity.json",
        "raw_sha256": digest("c"), "semantic_sha256": digest("d"),
    }
    host_verification = {"path": "/tmp/synthetic-input/host-verification.json",
                         "raw_sha256": digest("e"), "receipt_sha256": digest("f")}
    capacity_ledger = {"path": "/tmp/synthetic-input/capacity-ledger.jsonl",
                       "raw_sha256": digest("1"), "terminal_head": digest("2")}
    schedule_sha256 = digest("3")
    generation = {
        "completion": generation_completion,
        "provenance": {
            "schema": chronology.SOURCE5_PREPARATORY_CAPACITY_PROVENANCE_SCHEMA,
            "preparation_pin": {"path": "/tmp/synthetic-input/preparation.json",
                                "raw_sha256": digest("4")},
            "initial_spec_pin": {"path": spec_pin["path"],
                                 "raw_sha256": spec_pin["raw_sha256"]},
            "initial_plan_pin": {"path": plan_pin["path"],
                                 "raw_sha256": plan_pin["raw_sha256"]},
        },
    }
    registration = {
        "completion": generation_completion,
        "host_completion": host_completion,
        "host_verification": host_verification,
        "ledger": capacity_ledger,
        "capacity_schedule_sha256": schedule_sha256,
        "registration_head": None,
    }
    execution_pin = {"path": "/tmp/synthetic-artifacts/execution.json",
                     "raw_sha256": digest("5"), "semantic_sha256": digest("6")}
    header = {
        "campaign_id": campaign_id, "host_id": host_id,
        "initial_output_root": output_root,
        "initial": {
            "execution_manifest_pin": execution_pin,
            "spec_pin": spec_pin, "plan_pin": plan_pin,
            "source_manifest_pins": source_pins,
            "observed_host_pin": {key: observed[key] for key in (
                "path", "raw_sha256", "boot_id_sha256", "controls_sha256",
            )},
            "capacity_generation_sha256": generation_completion["semantic_sha256"],
            "capacity_registration_head": None,
        },
    }
    expected_setup_head = None
    generated_fixture = None
    generated_artifacts = None
    setup_details = {
        "campaign_id": campaign_id, "host_id": host_id,
        "completion": generation_completion, "provenance": generation["provenance"],
        "host_completion": host_completion, "host_verification": host_verification,
        "capacity_ledger": capacity_ledger,
        "capacity_schedule_sha256": schedule_sha256,
        "entries": [{"entry": index} for index in range(15)],
        "qualification_eligible": False, "controller_chronology_proven": False,
    }

    if generated is not None:
        generated_fixture, generated_artifacts, original_pins, setup_details, \
            expected_setup_head = generated
        lineage = generated_fixture.lineage_module
        chronology = generated_fixture.chronology
        campaign_core = generated_fixture.campaign
        prep_budget = generated_fixture.prep_module
        source5_campaign = generated_fixture.controller
        campaign_id = generated_fixture.spec["campaign_id"]
        host_id = generated_fixture.host_id
        output_root = str(generated_fixture.output_root)
        spec = generated_fixture.spec
        jobs = [job for job in generated_fixture.plan["jobs"]["exploration"]
                if job["host_id"] == host_id]
        digest = lambda value: hashlib.sha256(value.encode("utf-8")).hexdigest()
        spec_pin = {
            "path": str(generated_fixture.spec_path),
            "raw_sha256": generated_fixture.spec_sha256,
            "semantic_sha256": generated_fixture.spec_semantic,
        }
        plan_pin = {
            "path": str(generated_fixture.plan_path),
            "raw_sha256": generated_fixture.plan_file_sha256,
            "semantic_sha256": generated_fixture.plan_semantic,
        }
        source_pins = []
        for selected_host in generated_fixture.fixture.host_ids:
            source_doc = generated_fixture.fixture.manifests[selected_host]
            source_pins.append({
                "host_id": selected_host,
                "path": str(generated_fixture.fixture.manifest_paths[selected_host]),
                "raw_sha256": generated_fixture.fixture.manifest_raw_shas[selected_host],
                "semantic_sha256": source_doc["manifest_sha256"],
                "source_tree_sha256": source_doc["source"]["source_tree_sha256"],
            })
        observed = original_pins["observed_host"]
        width_contract = generated_artifacts["width"]
        width_projection, event_projection = \
            chronology._source5_preparatory_journal_projection(
                width_contract, jobs, host_id,
            )
        generation_completion = generated_fixture.generation_completion
        generation = generated_artifacts["manifest"][
            "preparatory_capacity_generation"]
        registration = generated_artifacts["manifest"][
            "preparatory_capacity_registration"]
        selected_capacity = next(
            row for row in generated_fixture.generation["capacity_preparations"]
            if row["host_id"] == host_id
        )
        host_completion = {
            **selected_capacity["completion"],
            "semantic_sha256": selected_capacity["completion_sha256"],
        }
        host_verification = selected_capacity["host_verification"]
        capacity_ledger = selected_capacity["ledger"]
        schedule_sha256 = selected_capacity[
            "capacity_preparation_templates_sha256"]
        execution_manifest = generated_artifacts["manifest"]
        execution_raw = generated_artifacts["manifest_raw"]
        execution_pin = {
            "path": str(generated_fixture.manifest_path),
            "raw_sha256": chronology.sha256_bytes(execution_raw),
            "semantic_sha256": execution_manifest["manifest_sha256"],
        }
        budget_source_pin = generated_artifacts["budget_pin"]
        width_source_pin = generated_artifacts["width_pin"]
        fixed_spec_host_pin = {
            **generated_fixture.context.fixed_spec_host_pin,
            "semantic_sha256": generated_fixture.context.prepared_fixed_host_binding[
                "spec_host_semantic_sha256"],
        }
        signer_pin = generated_fixture.signer_pin
        signer = generated_fixture.signer_context
        header = {
            "campaign_id": campaign_id,
            "host_id": host_id,
            "initial_output_root": output_root,
            "initial": {
                "execution_manifest_pin": execution_pin,
                "spec_pin": spec_pin,
                "plan_pin": plan_pin,
                "source_manifest_pins": source_pins,
                "observed_host_pin": {
                    key: observed[key] for key in (
                        "path", "raw_sha256", "boot_id_sha256", "controls_sha256",
                    )
                },
                "capacity_generation_sha256":
                    generation_completion["semantic_sha256"],
                "capacity_registration_head": expected_setup_head,
                "host_budget_pin": {
                    key: budget_source_pin[key]
                    for key in ("path", "raw_sha256", "semantic_sha256")
                },
                "journal_width_pin": {
                    key: width_source_pin[key]
                    for key in ("path", "raw_sha256", "semantic_sha256")
                },
                "fixed_spec_host_pin": fixed_spec_host_pin,
                "prepared_host_binding_sha256":
                    generated_fixture.context.prepared_fixed_host_binding[
                        "binding_sha256"],
                "signer_context_pin": signer_pin,
                "signer_fingerprint": signer[
                    "authorized_primary_fingerprint"],
                "maximum_signature_bytes": signer["maximum_signature_bytes"],
            },
        }
        original_context = {
            "original_pins": original_pins,
            "execution_manifest": execution_manifest,
            "width_projection": width_projection,
            "event_projection": event_projection,
            "cleanup_limits": chronology._source5_cleanup_limits_from_budget(
                generated_artifacts["budget"],
            ),
            "phase_ledger_maximum_bytes": generated_artifacts["budget"][
                "schedule"]["maximum_phase_ledger_bytes"],
            "phase_ledger_record_maximum_bytes": chronology.MAX_EVENT_BYTES,
        }
        expected_projection = lineage.project_prepared_exploration_lineage_outputs(
            campaign_id, host_id, output_root, jobs,
        )
        journal_path = str(Path(output_root) / campaign_id / "chronology" /
                           host_id / "dispatch-journal.jsonl")
        ledger_path = str(Path(output_root) / campaign_id / "source5" /
                          host_id / "exploration" / "controller-ledger.jsonl")
        record_store = {}
        index_rows = []
        pilot_pair_by_key = {}
    journal_path = f"{output_root}/{campaign_id}/chronology/{host_id}/dispatch-journal.jsonl"
    ledger_path = (f"{output_root}/{campaign_id}/source5/{host_id}/exploration/"
                   "controller-ledger.jsonl")
    journal_lines: list[bytes] = []
    previous = "0" * 64
    record_count = 0
    last_record_sha = previous

    def append_event(event: str, details: dict[str, object]) -> str:
        nonlocal previous, record_count, last_record_sha
        record_count += 1
        record = {
            "schema": chronology.JOURNAL_SCHEMA,
            "sequence": record_count, "monotonic_ns": record_count,
            "campaign_id": campaign_id, "host_id": host_id,
            "boot_id_sha256": observed["boot_id_sha256"],
            "original_pins": original_pins, "event": event, "details": details,
        }
        unsigned = {"previous_sha256": previous, "record": record}
        record_sha = chronology.sha256_bytes(chronology.canonical_bytes(unsigned))
        journal_lines.append(chronology.canonical_bytes({
            **unsigned, "record_sha256": record_sha,
        }))
        previous = last_record_sha = record_sha
        return record_sha

    registration_head = append_event(
        "source5_prepared_capacity_registered", setup_details,
    )
    if expected_setup_head is not None and registration_head != expected_setup_head:
        raise AssertionError(
            "generated H6 registration head differs from its exact first SourceA event",
        )
    registration["registration_head"] = registration_head
    header["initial"]["capacity_registration_head"] = registration_head
    if generated_fixture is None:
        original_context = {
            "original_pins": original_pins,
            "execution_manifest": {
                "preparatory_capacity_generation": generation,
                "preparatory_capacity_registration": registration,
            },
            "width_projection": width_projection,
            "event_projection": event_projection,
            "cleanup_limits": {},
            # This low-level SourceA parser component uses only a finite test
            # allowance; production calls receive the exact verified prep schedule.
            "phase_ledger_maximum_bytes": lineage.HOST_JOB_COUNT * lineage.MAX_RECORD_BYTES,
            "phase_ledger_record_maximum_bytes": chronology.MAX_EVENT_BYTES,
        }
    index_rows: list[dict[str, object]] = []
    ledger_lines: list[bytes] = []
    record_store: dict[str, bytes] = {}
    # Any PID/start-tick integers below exist only to satisfy the SourceA
    # journal parser's data shape. They are not read from or attributed to an
    # operating system; this structural fixture makes no process/owner claim.
    for job_index, job in enumerate(jobs):
        pair_root = f"{output_root}/{campaign_id}/pairs/{job['run_id']}"
        members = [
            {"pair": f"pair-{job_index}", "executor": executor,
             "allocator": job["allocator"]}
            for executor in ("bounded", "tokio")
        ]
        helper_input_path = f"{output_root}/{campaign_id}/helper/{job['run_id']}.json"
        helper_input_raw = chronology.canonical_bytes({
            "campaign_id": campaign_id, "host_id": host_id,
            "run_id": job["run_id"], "members": members,
            "qualification_eligible": False,
        })
        if generated_fixture is None:
            helper_module = {
                "path": "scripts/application-fixed-pair.py",
                "sha256": digest("8"), "size": 1,
                "mode": "100644", "kind": "file",
            }
            helper_input_sha256 = digest("7")
        else:
            typed_helper = next(
                row for row in generated_fixture.fixture.manifests[host_id][
                    "source"]["files"]
                if row["path"] == "scripts/application-fixed-pair.py"
            )
            helper_module = {
                "path": typed_helper["path"],
                "sha256": typed_helper["sha256"],
                "size": typed_helper["size"],
                "mode": typed_helper["mode"],
                "kind": "file",
            }
            helper_input_sha256 = chronology.sha256_bytes(helper_input_raw)
            record_store[helper_input_path] = helper_input_raw
        authorization = {
            "authorization_id": "", "campaign_id": campaign_id,
            "host_id": host_id, "phase": "exploration", "job_index": job_index,
            "job": job,
            "job_sha256": chronology.sha256_bytes(chronology.canonical_bytes(job)),
            "members": members,
            "members_sha256": chronology.sha256_bytes(chronology.canonical_bytes(members)),
            "execution_manifest": {"path": execution_pin["path"],
                                   "raw_sha256": execution_pin["raw_sha256"]},
            "helper_input": {"path": helper_input_path,
                             "raw_sha256": helper_input_sha256},
            "helper_module": helper_module,
            "capacity_registration_head": registration_head,
            "capacity_completion": {"path": host_completion["path"],
                                    "raw_sha256": host_completion["raw_sha256"]},
            "capacity_ledger_raw_sha256": capacity_ledger["raw_sha256"],
            "capacity_terminal_head": capacity_ledger["terminal_head"],
            "capacity_schedule_sha256": schedule_sha256,
            "prerequisites": {}, "outer_deadline_seconds": 30,
            "effective_timeout_seconds": 30,
            "input_snapshot_sha256": (helper_input_sha256
                                       if generated_fixture is not None
                                       else digest("9")),
            "output_root": pair_root,
            "qualification_eligible": False,
            "host_evidence_budget": {}, "tmpdir_budget": {},
        }
        authorization["authorization_id"] = "source5-" + chronology.sha256_bytes(
            chronology.canonical_bytes({
                key: value for key, value in authorization.items()
                if key != "authorization_id"
            }),
        )[:48]
        authorization_id = append_event("source5_authorized", authorization)
        start_heads, terminal_heads = [], []
        start_events, terminal_events, member_processes = [], [], []
        if generated_fixture is None:
            overlay_sha = digest(str(job_index % 10))
            receipt_sha = digest("a")
            host_receipt_sha = digest("b")
            host_verification_sha = digest("c")
            overlay_path = f"{output_root}/{campaign_id}/overlay/{job['run_id']}.json"
            receipt_path = f"{output_root}/{campaign_id}/receipt/{job['run_id']}.json"
            host_receipt_path = f"{output_root}/{campaign_id}/host/{job['run_id']}.json"
        else:
            process_rows = [{
                "executor": executor, "completed_on_time": "1",
                "completed_late": "0", "attempted": "1", "admitted": "1",
                "rejected_full": "0", "rejected_resource": "0",
            } for executor in ("bounded", "tokio")]
            overlay_raw = chronology.canonical_bytes({
                "schema": "allocatbelt.application-fixed-pair-execution-overlay.v1",
                "campaign_id": campaign_id, "host_id": host_id,
                "run_id": job["run_id"], "members": members,
                "qualification_eligible": False,
            })
            receipt_raw = chronology.canonical_bytes({
                "schema": "allocatbelt.application-fixed-pair-execution-receipt.v1",
                "campaign_id": campaign_id, "host_id": host_id,
                "run_id": job["run_id"], "status": "valid_pair",
                "process_rows": process_rows,
                "qualification_eligible": False,
            })
            host_receipt_raw = chronology.canonical_bytes({
                "schema": "synthetic.structural-fixed-host-receipt.v1",
                "campaign_id": campaign_id, "host_id": host_id,
                "run_id": job["run_id"], "qualification_eligible": False,
            })
            overlay_sha = chronology.sha256_bytes(overlay_raw)
            receipt_sha = chronology.sha256_bytes(receipt_raw)
            host_receipt_sha = chronology.sha256_bytes(host_receipt_raw)
            host_verification_sha = chronology.sha256_bytes(
                chronology.canonical_bytes({"receipt_sha256": host_receipt_sha}),
            )
            overlay_path = f"{output_root}/{campaign_id}/overlay/{job['run_id']}.json"
            receipt_path = f"{output_root}/{campaign_id}/receipt/{job['run_id']}.json"
            host_receipt_path = f"{output_root}/{campaign_id}/host/{job['run_id']}.json"
            record_store[overlay_path] = overlay_raw
            record_store[receipt_path] = receipt_raw
            record_store[host_receipt_path] = host_receipt_raw
        evidence = {
            "kind": "source5_fixed_pair",
            "overlay": {"path": overlay_path, "raw_sha256": overlay_sha},
            "receipt": {"path": receipt_path, "raw_sha256": receipt_sha},
            "host_receipt": {
                "path": host_receipt_path,
                "raw_sha256": host_receipt_sha,
                "host_verification_sha256": host_verification_sha,
            },
            "execution_manifest": authorization["execution_manifest"],
        }
        for member_index, member in enumerate(members):
            pid, start_ticks = 10000 + job_index * 2 + member_index, 100 + member_index
            proof = {
                "campaign_id": campaign_id, "host_id": host_id,
                "run_id": job["run_id"], "descriptor": member,
                "member_ordinal": member_index,
                "proof": {"pid": pid, "start_ticks": start_ticks},
            }
            start_details = {
                "authorization_id": authorization["authorization_id"],
                "member_index": member_index, "descriptor": member,
                "pid": pid, "start_ticks": start_ticks,
                "proof_sha256": chronology.sha256_bytes(chronology.canonical_bytes(proof)),
                "proof": proof, "qualification_eligible": False,
            }
            start_head = append_event("source5_app_started", start_details)
            start_heads.append(start_head)
            start_events.append(proof)
            member_processes.append({
                "descriptor": member, "pid": pid,
                "start_ticks": start_ticks, "member_index": member_index,
            })
            cleanup = {
                "cleanup_status": "verified", "leader_reaped": True,
                "group_signal_after_leader_reap_count": 0,
            }
            terminal_time = record_count + 1
            terminal_event = {
                "schema": "allocatbelt.application-fixed-pair-app-terminal.v1",
                "overlay_sha256": overlay_sha,
                "campaign_id": campaign_id, "host_id": host_id,
                "run_id": job["run_id"], "member_ordinal": member_index,
                "descriptor": member, "pid": pid, "status": 0,
                "child_return_code": 0, "signal": None,
                "cleanup": cleanup, "cleanup_sidecar": None,
                "terminal_monotonic_ns": terminal_time,
            }
            terminal_details = {
                "authorization_id": authorization["authorization_id"],
                "member_index": member_index, "descriptor": member,
                "pid": pid, "status": 0, "child_return_code": 0,
                "signal": None, "cleanup": cleanup,
                "terminal_monotonic_ns": terminal_time,
                "qualification_eligible": False, "cleanup_sidecar": None,
            }
            terminal_head = append_event("source5_app_terminal", terminal_details)
            terminal_heads.append(terminal_head)
            terminal_events.append(terminal_event)
        metrics = [{"executor": "bounded", "completed": 1},
                   {"executor": "tokio", "completed": 1}]
        metrics_sha = chronology.sha256_bytes(chronology.canonical_bytes(metrics))
        component_sha = digest("d")
        terminal_details = {
            "authorization_id": authorization["authorization_id"],
            "state": "valid_pair", "blocked_reason": None,
            "component_sha256": component_sha,
            "process_metrics_sha256": metrics_sha,
            "started_count": 2, "terminal_count": 2,
            "qualification_eligible": False,
        }
        terminal_job_head = append_event("source5_job_terminal", terminal_details)
        record = {
            "schema": chronology.SOURCE5_JOB_RECORD_SCHEMA, "state": "valid_pair",
            "job": job, "pair_directory": pair_root,
            "process_metrics": metrics, "evidence": evidence,
            "chronology": {
                "authorization_id": authorization["authorization_id"],
                "authorization_head": authorization_id,
                "app_started_heads": start_heads,
                "app_terminal_heads": terminal_heads,
                "job_terminal_head": terminal_job_head,
                "component_sha256": component_sha,
                "process_metrics_sha256": metrics_sha,
                "app_start_events": start_events,
                "app_terminal_events": terminal_events,
                "member_processes": member_processes,
            },
            "qualification_eligible": False,
        }
        record["record_sha256"] = chronology.sha256_bytes(
            chronology.canonical_bytes(record),
        )
        record_raw = chronology.canonical_bytes(record)
        record_path = (f"{output_root}/{campaign_id}/source5/{host_id}/exploration/"
                       f"job-records/{job['run_id']}.json")
        record_store[record_path] = record_raw
        ledger_lines.append(record_raw)
        leaf = f"{job['ordinal']:06d}-{chronology.sha256_bytes(chronology.canonical_bytes(job))}"
        metadata = (f"{output_root}/{campaign_id}/chronology/{host_id}/"
                    "evidence-checkpoints/exploration")
        if generated_fixture is None:
            ack_path = f"/tmp/synthetic-root/acks/exploration/{leaf}.json"
            signature_path = f"/tmp/synthetic-root/acks/signatures/exploration/{leaf}.sig"
            archive_pins = {
                "request_pin": {"path": f"{metadata}/{leaf}.request.json",
                                "raw_sha256": digest("e"), "semantic_sha256": digest("f")},
                "checkpoint_pin": {"path": f"{metadata}/{leaf}.checkpoint.json",
                                    "raw_sha256": digest("1"), "semantic_sha256": digest("2")},
                "object_manifest_pin": {"path": f"{metadata}/{leaf}.object-manifest.json",
                                         "raw_sha256": digest("3"), "semantic_sha256": digest("4")},
                "ack_pin": {"path": ack_path, "raw_sha256": digest("5"),
                            "semantic_sha256": digest("6")},
                "signature_pin": {"path": signature_path,
                                   "raw_sha256": digest("7"),
                                   "signer_fingerprint": "A" * 40},
            }
            pilot_pair_sha = digest("8")
        else:
            record_pin = {
                "path": record_path,
                "raw_sha256": chronology.sha256_bytes(record_raw),
            }
            request_body = {
                "schema": "allocatbelt.application-source5-evidence-checkpoint-request.structural-v1",
                "campaign_id": campaign_id, "host_id": host_id,
                "job": job, "job_record_pin": record_pin,
            }
            request_semantic = chronology.sha256_bytes(
                chronology.canonical_bytes(request_body),
            )
            request_value = {
                **request_body, "request_sha256": request_semantic,
            }
            request_raw = chronology.canonical_bytes(request_value)
            request_pin = {
                "path": f"{metadata}/{leaf}.request.json",
                "raw_sha256": chronology.sha256_bytes(request_raw),
                "semantic_sha256": request_semantic,
            }
            checkpoint_body = {
                "schema": "allocatbelt.application-source5-evidence-checkpoint.structural-v1",
                "request_pin": request_pin,
                "job_record_pin": record_pin,
            }
            checkpoint_semantic = chronology.sha256_bytes(
                chronology.canonical_bytes(checkpoint_body),
            )
            checkpoint_value = {
                **checkpoint_body, "checkpoint_sha256": checkpoint_semantic,
            }
            checkpoint_raw = chronology.canonical_bytes(checkpoint_value)
            checkpoint_pin = {
                "path": f"{metadata}/{leaf}.checkpoint.json",
                "raw_sha256": chronology.sha256_bytes(checkpoint_raw),
                "semantic_sha256": checkpoint_semantic,
            }
            manifest_body = {
                "schema": "allocatbelt.application-source5-evidence-object-manifest.structural-v1",
                "objects": [{"path": record_path,
                             "raw_sha256": record_pin["raw_sha256"]}],
            }
            manifest_semantic = chronology.sha256_bytes(
                chronology.canonical_bytes(manifest_body),
            )
            manifest_value = {
                **manifest_body, "manifest_sha256": manifest_semantic,
            }
            manifest_raw = chronology.canonical_bytes(manifest_value)
            object_manifest_pin = {
                "path": f"{metadata}/{leaf}.object-manifest.json",
                "raw_sha256": chronology.sha256_bytes(manifest_raw),
                "semantic_sha256": manifest_semantic,
            }
            ack_path = (
                f"{generated_fixture.evidence_root}/archive-root/acks/"
                f"exploration/{leaf}.json"
            )
            signature_path = (
                f"{generated_fixture.evidence_root}/archive-root/acks/"
                f"signatures/exploration/{leaf}.sig"
            )
            signature_fingerprint = generated_fixture.signer_context[
                "authorized_primary_fingerprint"]
            ack_body = {
                "schema": "allocatbelt.application-source5-evidence-ack.structural-v1",
                "checkpoint_pin": checkpoint_pin,
                "object_manifest_pin": object_manifest_pin,
                "signer_fingerprint": signature_fingerprint,
            }
            ack_semantic = chronology.sha256_bytes(
                chronology.canonical_bytes(ack_body),
            )
            ack_value = {**ack_body, "ack_sha256": ack_semantic}
            ack_raw = chronology.canonical_bytes(ack_value)
            signature_raw = (
                b"synthetic structural signature witness for " +
                job["run_id"].encode("ascii") + b"\n"
            )
            archive_pins = {
                "request_pin": request_pin,
                "checkpoint_pin": checkpoint_pin,
                "object_manifest_pin": object_manifest_pin,
                "ack_pin": {
                    "path": ack_path,
                    "raw_sha256": chronology.sha256_bytes(ack_raw),
                    "semantic_sha256": ack_semantic,
                },
                "signature_pin": {
                    "path": signature_path,
                    "raw_sha256": chronology.sha256_bytes(signature_raw),
                    "signer_fingerprint": signature_fingerprint,
                },
            }
            record_store.update({
                request_pin["path"]: request_raw,
                checkpoint_pin["path"]: checkpoint_raw,
                object_manifest_pin["path"]: manifest_raw,
                ack_path: ack_raw,
                signature_path: signature_raw,
            })
            pair_binding = {
                "overlay_raw_sha256": evidence["overlay"]["raw_sha256"],
                "receipt_raw_sha256": evidence["receipt"]["raw_sha256"],
                "verified_receipt_sha256": evidence["receipt"]["raw_sha256"],
                "run_id": job["run_id"],
            }
            pilot_pair_sha = chronology.sha256_bytes(
                chronology.canonical_bytes(pair_binding),
            )
            pilot_pair_by_key[(job["family"], job["profile"],
                               job["allocator"], job["ordinal"])] = pilot_pair_sha
        index_rows.append(lineage.build_prepared_exploration_lineage_index_row(
            job_index, job, campaign_id, host_id, output_root,
            {"path": record_path, "raw_sha256": chronology.sha256_bytes(record_raw)},
            archive_pins, pilot_pair_sha, record,
        ))
    journal_raw = b"".join(journal_lines)
    ledger_raw = b"".join(ledger_lines)
    header.update({
        "journal": {
            "pin": {"path": journal_path,
                    "raw_sha256": chronology.sha256_bytes(journal_raw)},
            "byte_count": len(journal_raw), "record_count": record_count,
            "head": last_record_sha,
        },
        "phase_ledger": {
            "pin": {"path": ledger_path,
                    "raw_sha256": chronology.sha256_bytes(ledger_raw)},
            "row_count": len(jobs),
        },
    })
    generated_documents = None
    if generated_fixture is not None:
        pilot_cells = []
        for cell in spec["cells"]:
            for allocator in campaign_core.ALLOCATORS:
                pairs = []
                for ordinal in range(1, 7):
                    key = (cell["family"], cell["profile"], allocator, ordinal)
                    pairs.append({
                        "ordinal": ordinal,
                        "bounded_status": "valid", "tokio_status": "valid",
                        "bounded_on_time": 1, "bounded_late": 0,
                        "bounded_attempted": 1, "bounded_admitted": 1,
                        "bounded_rejected": 0,
                        "tokio_on_time": 1, "tokio_late": 0,
                        "tokio_attempted": 1, "tokio_admitted": 1,
                        "tokio_rejected": 0,
                        "raw_pair_sha256": pilot_pair_by_key[key],
                    })
                pilot_cells.append({
                    "family": cell["family"], "profile": cell["profile"],
                    "allocator": allocator, "pairs": pairs,
                })
        pilot = {
            "schema": lineage.PILOT_SCHEMA,
            "spec_sha256": campaign_core.preregistration_digest(spec),
            "host_id": host_id, "cells": pilot_cells,
        }
        pilot_raw = chronology.canonical_bytes(pilot)
        pilot_sha = chronology.sha256_bytes(pilot_raw)
        pilot_maximum = generated_fixture.input_preparation.capacity_pilot_maximum_bytes(
            spec, host_id, campaign_core.ALLOCATORS, pilot["spec_sha256"],
        )
        if len(pilot_raw) > pilot_maximum:
            raise AssertionError("synthetic pilot exceeds the actual Source cap")
        # Lineage only joins the original pair digests. These counts remain
        # explicitly synthetic fixture shape; this structural milestone does
        # not derive rates or make a readiness decision.
        pilot_path = (f"{output_root}/{campaign_id}/source5/{host_id}/exploration/"
                      "capacity-pilot.json")

        projected_outputs = lineage.project_prepared_exploration_lineage_outputs(
            campaign_id, host_id, output_root, jobs,
        )
        index_path = projected_outputs["index"]["path"]
        index_raw = chronology._source5_preparatory_lineage_index_bytes(
            index_rows, projected_outputs["index"]["max_bytes"],
        )
        record_index_pin = {
            "path": index_path,
            "raw_sha256": chronology.sha256_bytes(index_raw),
        }
        pilot_pin = {
            "path": pilot_path, "raw_sha256": pilot_sha,
            "semantic_sha256": campaign_core.digest_object(pilot),
        }
        header = lineage.build_prepared_exploration_bridge_header(
            campaign_id, host_id, output_root, header["initial"],
            header["journal"], header["phase_ledger"], pilot_pin,
            record_index_pin,
        )
        header_raw = chronology.canonical_bytes(header)
        header_path = projected_outputs["header"]["path"]
        record_store.update({
            pilot_path: pilot_raw,
            index_path: index_raw,
            header_path: header_raw,
            journal_path: journal_raw,
            ledger_path: ledger_raw,
        })
        generated_documents = {
            "header": header, "header_raw": header_raw,
            "header_pin": {
                "path": header_path,
                "raw_sha256": chronology.sha256_bytes(header_raw),
            },
            "index_raw": index_raw, "index_pin": record_index_pin,
            "pilot": pilot, "pilot_raw": pilot_raw,
            "pilot_pin": pilot_pin,
            "final_prepared": {
                "campaign_id": campaign_id,
                "host_id": host_id,
                "output_root": str(generated_fixture.view_root / "final-output"),
                "original_pins": copy.deepcopy(original_pins),
                "source5_preparatory_capacity_generation": copy.deepcopy(generation),
            },
        }
    def artifact_reader(pin: dict[str, str], maximum: int) -> bytes:
        value = record_store.get(pin["path"])
        if value is None or len(value) > maximum or chronology.sha256_bytes(value) != pin["raw_sha256"]:
            raise AssertionError("synthetic closed reader rejected a record pin")
        return value

    return {
        "header": header, "jobs": jobs, "rows": index_rows,
        "original_context": original_context,
        "width_contract": width_contract,
        "journal_raw": journal_raw, "phase_ledger_raw": ledger_raw,
        "artifact_reader": artifact_reader,
        "record_store": record_store,
        "generated_documents": generated_documents,
        "chronology_module": chronology,
        "campaign_module": campaign_core,
        "preparatory_budget_module": prep_budget,
        "source5_campaign_module": source5_campaign,
        "lineage_module": lineage,
    }


def _write_origin_file(path: str, raw: bytes, mode: int = 0o600) -> None:
    target = Path(path)
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if target.exists():
        info = target.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != mode or target.read_bytes() != raw):
            raise AssertionError("fixture origin already exists with different bytes")
        return
    descriptor = os.open(
        target, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
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


def _capture_and_remove_origins(
    origins: dict[str, bytes], capture_root: Path, *,
    origin_modes: dict[str, int] | None = None,
) -> tuple[
    dict[str, tuple[str, Path, int]],
    Callable[[dict[str, str], int], bytes],
    list[tuple[str, int]],
]:
    """Copy exact old payload bytes to a private 0400 closed capture reader."""
    capture_root.mkdir(mode=0o700)
    capture_root.chmod(0o700)
    captured: dict[str, tuple[str, Path, int]] = {}
    origin_to_capture: dict[tuple[str, str], tuple[Path, int]] = {}
    expected_modes = {} if origin_modes is None else dict(origin_modes)
    if not set(expected_modes) <= set(origins):
        raise AssertionError("origin mode map names an uncaptured source")
    for index, (origin, raw) in enumerate(sorted(origins.items())):
        if type(raw) is not bytes or not raw:
            raise AssertionError("closed lineage fixture needs nonempty exact bytes")
        expected_mode = expected_modes.get(origin, 0o600)
        _write_origin_file(origin, raw, expected_mode)
        source = Path(origin)
        info = source.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                stat.S_IMODE(info.st_mode) != expected_mode or source.read_bytes() != raw):
            raise AssertionError("historical lineage origin is not the expected private file")
        captured_path = capture_root / f"{index:04d}.bin"
        descriptor = os.open(
            captured_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
            getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o400,
        )
        try:
            os.fchmod(descriptor, 0o400)
            offset = 0
            while offset < len(raw):
                offset += os.write(descriptor, raw[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        raw_sha256 = hashlib.sha256(raw).hexdigest()
        captured[captured_path.as_posix()] = (raw_sha256, captured_path, len(raw))
        origin_to_capture[(origin, raw_sha256)] = (captured_path, len(raw))

    if stat.S_IMODE(capture_root.lstat().st_mode) != 0o700:
        raise AssertionError("closed capture root is not private")
    expected_children = {path.name for _sha, path, _size in captured.values()}
    if {path.name for path in capture_root.iterdir()} != expected_children:
        raise AssertionError("closed capture root contains unlisted children")

    for origin in origins:
        Path(origin).unlink()
    if any(Path(origin).exists() or Path(origin).is_symlink() for origin in origins):
        raise AssertionError("a historical origin remained available after capture")

    reads: list[tuple[str, int]] = []

    def reader(pin: dict[str, str], maximum_bytes: int) -> bytes:
        if type(pin) is not dict or set(pin) != {"path", "raw_sha256"}:
            raise AssertionError("SourceA reader did not receive an exact raw-only pin")
        if type(maximum_bytes) is not int or maximum_bytes <= 0:
            raise AssertionError("SourceA reader received an invalid Source byte cap")
        path = pin["path"]
        expected = origin_to_capture.get((path, pin["raw_sha256"]))
        if expected is None or expected[1] > maximum_bytes:
            raise OSError("closed SourceA reader rejected an uncaptured or over-cap origin")
        captured_path, size = expected
        descriptor = os.open(
            captured_path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
            getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o400 or
                    info.st_nlink != 1 or info.st_size != size or info.st_size > maximum_bytes):
                raise OSError("closed SourceA capture file changed custody or size")
            raw = os.read(descriptor, maximum_bytes + 1)
            if len(raw) != size or hashlib.sha256(raw).hexdigest() != pin["raw_sha256"]:
                raise OSError("closed SourceA capture file changed its raw digest")
        finally:
            os.close(descriptor)
        reads.append((path, maximum_bytes))
        return raw

    return captured, reader, reads


def _generated_lineage_origin_bytes(
    fixture, artifacts: dict[str, object], case: dict[str, object],
) -> dict[str, bytes]:
    origins: dict[str, bytes] = {}

    def add(path: str | Path, raw: bytes) -> None:
        key = str(path)
        if type(raw) is not bytes or not raw:
            raise AssertionError(f"generated lineage origin {key} has no exact bytes")
        previous = origins.get(key)
        if previous is not None and previous != raw:
            raise AssertionError(f"generated lineage origin {key} changed bytes")
        origins[key] = raw

    add(fixture.spec_path, fixture.spec_raw)
    add(fixture.plan_path, fixture.plan_raw)
    for host in fixture.fixture.host_ids:
        add(fixture.fixture.manifest_paths[host],
            fixture.fixture.manifest_paths[host].read_bytes())
        observed_path = Path(fixture.observed_pins[host]["path"])
        add(observed_path, observed_path.read_bytes())
    add(fixture.manifest_path, artifacts["manifest_raw"])
    add(artifacts["width_pin"]["path"],
        Path(artifacts["width_pin"]["path"]).read_bytes())
    add(artifacts["budget_pin"]["path"],
        Path(artifacts["budget_pin"]["path"]).read_bytes())
    add(fixture.signer_pin["path"],
        fixture.controller.canonical_bytes(fixture.signer_context))
    for signer_field in ("keyring_pin", "gpgv_pin"):
        signer_tool = fixture.signer_context[signer_field]
        add(signer_tool["path"], Path(signer_tool["path"]).read_bytes())
    fixed_host_path = fixture.context.fixed_spec_host_pin["path"]
    add(fixed_host_path, Path(fixed_host_path).read_bytes())

    generation_path = fixture.generation_completion["path"]
    add(generation_path, Path(generation_path).read_bytes())
    preparation_path = fixture.generation["provenance"]["preparation_pin"]["path"]
    add(preparation_path, Path(preparation_path).read_bytes())
    selected = next(row for row in fixture.generation["capacity_preparations"]
                    if row["host_id"] == fixture.host_id)
    for pin in (
        selected["completion"], selected["host_verification"], selected["ledger"],
    ):
        add(pin["path"], Path(pin["path"]).read_bytes())
    for entry in selected["entries"]:
        for role in ("request", "artifact", "receipt"):
            pin = entry[role]
            add(pin["path"], Path(pin["path"]).read_bytes())
    for pin in fixture.generation["resource_budgets"].values():
        add(pin["path"], Path(pin["path"]).read_bytes())

    catalogue = artifacts["budget"]["path_catalogue"]
    chunks = {row["path"]: row for row in catalogue["chunks"]}

    def read_chunk(path: str, maximum_bytes: int) -> bytes:
        chunk = chunks.get(path)
        if type(chunk) is not dict or maximum_bytes != chunk["byte_count"]:
            raise AssertionError("generated H6 reader requested an undeclared catalogue chunk")
        raw = Path(path).read_bytes()
        if (len(raw) != maximum_bytes or
                hashlib.sha256(raw).hexdigest() != chunk["raw_sha256"]):
            raise AssertionError("generated H6 catalogue chunk differs from its raw pin")
        add(path, raw)
        return raw

    for chunk in catalogue["chunks"]:
        read_chunk(chunk["path"], chunk["byte_count"])
    retained_global_roles = {
        "preparation", "source_manifest", "spec_v3", "plan_v3",
        "execution_manifest", "observed_host", "host_evidence_budget",
        "journal_width_contract", "preparatory_journal_width_contract",
        "capacity_artifact", "capacity_completion", "capacity_host_receipt",
        "capacity_ledger", "source5_archive_signer_context",
        "source5_archive_signer_keyring", "source5_archive_signer_gpgv",
        "journal", "source5_phase_ledger", "source5_job_record",
        "source5_checkpoint_request", "source5_checkpoint",
        "source5_object_manifest", "source5_archive_ack",
        "source5_archive_signature", "source5_stage_map",
    }
    for row in fixture.budget_module.iter_fixed_pair_v3_path_catalogue_rows_with_reader(
            catalogue, read_chunk):
        if (row["kind"] != "file" or row.get("phase") is not None or
                row["role"] not in retained_global_roles):
            continue
        origin = row.get("origin_pin")
        if type(origin) is dict and type(origin.get("raw_sha256")) is str:
            raw = Path(row["path"]).read_bytes()
            if hashlib.sha256(raw).hexdigest() != origin["raw_sha256"]:
                raise AssertionError("generated H6 catalogue origin differs from its raw pin")
            add(row["path"], raw)

    for path, raw in case["record_store"].items():
        add(path, raw)
    return origins


def _merge_generated_lineage_origins(
    generated: list[tuple[object, dict[str, object], dict[str, object]]],
) -> tuple[dict[str, bytes], dict[str, int]]:
    origins: dict[str, bytes] = {}
    origin_modes: dict[str, int] = {}
    for fixture, artifacts, case in generated:
        for path, raw in _generated_lineage_origin_bytes(
                fixture, artifacts, case).items():
            prior = origins.get(path)
            if prior is not None and prior != raw:
                raise AssertionError(
                    f"shared generated lineage origin {path} changed across host views",
                )
            origins[path] = raw
        gpgv_path = fixture.signer_context["gpgv_pin"]["path"]
        mode = stat.S_IMODE(Path(gpgv_path).lstat().st_mode)
        previous_mode = origin_modes.get(gpgv_path)
        if previous_mode is not None and previous_mode != mode:
            raise AssertionError("shared generated GPGV executable mode changed")
        origin_modes[gpgv_path] = mode
    return origins, origin_modes


def _materialize_production_capture(
    declaration: dict[str, object],
    artifact_reader: Callable[[dict[str, str], int], bytes],
    capture_module: types.ModuleType,
    capture_root: Path,
) -> tuple[dict[str, object], object]:
    capture_root.mkdir(mode=0o700)
    capture_root.chmod(0o700)
    objects_root = capture_root / "objects"
    objects_root.mkdir(mode=0o700)
    objects_root.chmod(0o700)
    manifest_rows = []
    for index, descriptor in enumerate(declaration["objects"]):
        pin = dict(descriptor["origin_pin"])
        raw = artifact_reader(pin, descriptor["maximum_bytes"])
        if (type(raw) is not bytes or not raw or
                len(raw) > descriptor["maximum_bytes"] or
                hashlib.sha256(raw).hexdigest() != pin["raw_sha256"]):
            raise AssertionError("production capture source object differs from its declaration")
        relative = f"objects/{index:08d}.bin"
        local = capture_root / relative
        fd = os.open(
            local, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
            getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), 0o400,
        )
        try:
            os.fchmod(fd, 0o400)
            offset = 0
            while offset < len(raw):
                offset += os.write(fd, raw[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        info = local.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o400 or
                info.st_nlink != 1 or info.st_size != len(raw)):
            raise AssertionError("production capture object lacks exact private file custody")
        manifest_rows.append({
            "origin_pin": pin, "local_relative_path": relative,
            "byte_count": len(raw),
        })
    manifest = {
        "schema": capture_module.CAPTURE_MANIFEST_SCHEMA,
        "objects": manifest_rows,
    }
    reader = capture_module.PreparedExplorationLineageCaptureReaderV1(
        declaration, manifest, str(capture_root),
    )
    return manifest, reader


def producer_shaped_initial_context_case():
    """Seal captured prep inputs with the actual SourceH/SourceA/PurePrep APIs.

    The two-host byte fixtures are explicitly structural test inputs. Their
    process facts are never used; this case exercises producer schemas and
    closed-reader joins only.
    """
    campaign_id, host_id, other_host = (
        "producer-shape-lineage", "host-kvm-a", "host-kvm-b",
    )
    output_root = "/tmp/lineage-producer-initial-output"
    artifact_root = "/tmp/lineage-producer-artifacts"
    spec_path = "/tmp/lineage-producer-input/initial-spec.json"
    plan_path = "/tmp/lineage-producer-input/initial-plan.json"
    hosts = [host_id, other_host]

    required_paths = {
        chronology.CAPACITY_STAGE_SOURCE_PATH,
        chronology.CHRONOLOGY_SOURCE_PATH,
        chronology.PAIR_RUNNER_SOURCE_PATH,
        chronology.CONTROLLER_SOURCE_PATH,
        "scripts/application-campaign-inputs.py",
        "scripts/application-feedback-readback.py",
        "scripts/application-byte-capacity.py",
        source5_campaign.PREPARATORY_BUDGET_SOURCE_PATH,
        *chronology.SOURCE5_WIDTH_OWNER_PATHS.values(),
    }
    typed_files = []
    for relative in sorted(required_paths):
        local = Path(__file__).with_name(PurePosixPath(relative).name)
        raw = local.read_bytes()
        typed_files.append({
            "path": relative, "kind": "file",
            "sha256": lineage.sha256_bytes(raw), "size": len(raw),
        })
    typed_by_path = {row["path"]: row for row in typed_files}
    typed_modules = {
        row["path"]: {"path": row["path"], "sha256": row["sha256"]}
        for row in typed_files
        if PurePosixPath(row["path"]).suffix in {".py", ".sh"}
    }

    source_documents = {}
    source_manifest_pins = []
    source_raws = {}
    for index, selected_host in enumerate(hosts):
        source_tree = lineage.sha256_bytes(lineage.canonical_bytes(typed_files))
        source_body = {
            "schema": chronology.SOURCE_SCHEMA,
            "source": {
                "source_tree_sha256": source_tree,
                "git_commit": "synthetic-structural-component",
                "files": typed_files,
            },
            "build": {"component_scope": "synthetic-structural-only"},
        }
        source_doc = {
            **source_body,
            "manifest_sha256": lineage.sha256_bytes(
                lineage.canonical_bytes(source_body),
            ),
        }
        source_path = f"/tmp/lineage-producer-input/sources/{selected_host}.json"
        source_raw = lineage.canonical_bytes(source_doc)
        source_sha = lineage.sha256_bytes(source_raw)
        semantic_sha = source_doc["manifest_sha256"]
        source_documents[selected_host] = source_doc
        source_raws[source_path] = source_raw
        source_manifest_pins.append({
            "host_id": selected_host, "path": source_path,
            "raw_sha256": source_sha, "semantic_sha256": semantic_sha,
            "source_tree_sha256": source_tree,
        })

    spec_body = {
        "schema": campaign_core.SPEC_SCHEMA_V3,
        "campaign_id": campaign_id,
        "hosts": [{"host_id": host} for host in hosts],
        "cells": [
            {"family": f"family-{family}", "profile": f"profile-{profile}",
             "workload": f"workload-{family}-{profile}", "arrivals": []}
            for family in range(5) for profile in range(3)
        ],
        "protocol": {"exploration_pairs": 6, "schedule_seed": 1},
        "rates": [], "oracles": [],
        "source_manifests": [
            {"host_id": pin["host_id"],
             "relative_path": f"sources/{pin['host_id']}.json",
             "sha256": pin["semantic_sha256"]}
            for pin in source_manifest_pins
        ],
    }
    spec_doc = dict(spec_body)
    spec_doc["manifest_sha256"] = campaign_core.digest_object(spec_doc)
    spec_raw = lineage.canonical_bytes(spec_doc)
    spec_pin = {
        "path": spec_path, "raw_sha256": lineage.sha256_bytes(spec_raw),
        "semantic_sha256": campaign_core.digest_object(spec_doc),
    }
    jobs = campaign_core.build_jobs(spec_doc, "exploration", host_id)
    plan_body = {
        "schema": campaign_core.PLAN_SCHEMA_V3,
        "campaign_id": campaign_id,
        "jobs": {phase: (jobs if phase == "exploration" else [])
                 for phase in ("exploration", "aa", "confirmation", "pressure", "soak")},
    }
    plan_doc = {
        **plan_body,
        "plan_sha256": lineage.sha256_bytes(lineage.canonical_bytes(plan_body)),
    }
    plan_raw = lineage.canonical_bytes(plan_doc)
    plan_pin = {
        "path": plan_path, "raw_sha256": lineage.sha256_bytes(plan_raw),
        "semantic_sha256": plan_doc["plan_sha256"],
    }

    observed_documents = {}
    observed_map = {}
    observed_pins = {}
    for index, selected_host in enumerate(hosts):
        controls = {"component_scope": "synthetic-structural-only", "slot": index}
        controls_sha = lineage.sha256_bytes(lineage.canonical_bytes(controls))
        observed_body = {
            "schema": "synthetic-component-observed-host.v1",
            "host_id": selected_host,
            "boot_id_sha256": ("b" if index == 0 else "c") * 64,
            "controls_sha256": controls_sha,
            "controls": controls,
            "cpu_affinity": [0, 1], "network_namespace_inode": 100 + index,
        }
        observed_doc = dict(observed_body)
        observed_raw = lineage.canonical_bytes(observed_doc)
        observed_path = f"/tmp/lineage-producer-input/observed/{selected_host}.json"
        observed_sha = lineage.sha256_bytes(observed_raw)
        observed_documents[selected_host] = observed_doc
        observed_pins[selected_host] = {
            "path": observed_path, "raw_sha256": observed_sha,
            "boot_id_sha256": observed_body["boot_id_sha256"],
            "controls_sha256": controls_sha,
        }
        observed_map[selected_host] = {
            "artifact": {"path": observed_path, "raw_sha256": observed_sha},
            "host_fingerprint_sha256": controls_sha,
            "controls_sha256": controls_sha,
        }

    preparation_pin = {
        "path": "/tmp/lineage-producer-input/preparation.json",
        "raw_sha256": "d" * 64,
    }
    generation_completion = {
        "path": "/tmp/lineage-producer-input/capacity-generation.json",
        "raw_sha256": "e" * 64, "semantic_sha256": "f" * 64,
    }
    generation = {
        "completion": generation_completion,
        "provenance": {
            "schema": chronology.SOURCE5_PREPARATORY_CAPACITY_PROVENANCE_SCHEMA,
            "preparation_pin": preparation_pin,
            "initial_spec_pin": {key: spec_pin[key]
                                  for key in ("path", "raw_sha256")},
            "initial_plan_pin": {key: plan_pin[key]
                                 for key in ("path", "raw_sha256")},
        },
    }
    registration = {
        "completion": generation_completion,
        "host_completion": {
            "path": "/tmp/lineage-producer-input/capacity-host.json",
            "raw_sha256": "1" * 64, "semantic_sha256": "2" * 64,
        },
        "host_verification": {
            "path": "/tmp/lineage-producer-input/capacity-host-receipt.json",
            "raw_sha256": "3" * 64, "receipt_sha256": "4" * 64,
        },
        "ledger": {
            "path": f"{output_root}/{campaign_id}/chronology/{host_id}/capacity.jsonl",
            "raw_sha256": "5" * 64, "terminal_head": "6" * 64,
        },
        "capacity_schedule_sha256": "7" * 64,
        "registration_head": "8" * 64,
    }
    signer_body = {
        "schema": "allocatbelt.application-source5-archive-signer-context.v1",
        "campaign_id": campaign_id, "host_id": host_id,
        "authorized_primary_fingerprint": "A" * 40,
        "maximum_signature_bytes": lineage.MAX_SIGNATURE_BYTES,
    }
    signer_doc = {
        **signer_body,
        "signer_context_sha256": lineage.sha256_bytes(
            lineage.canonical_bytes(signer_body),
        ),
    }
    signer_raw = lineage.canonical_bytes(signer_doc)
    signer_pin = {
        "path": "/tmp/lineage-producer-input/archive-signer-context.json",
        "raw_sha256": lineage.sha256_bytes(signer_raw),
        "semantic_sha256": signer_doc["signer_context_sha256"],
    }
    archive_signers = {host_id: {
        "artifact": {"path": signer_pin["path"], "raw_sha256": signer_pin["raw_sha256"]},
        "semantic_sha256": signer_pin["semantic_sha256"],
    }}

    execution_sources = {}
    source_wrapper_map = {}
    for selected_host, source_pin in zip(hosts, source_manifest_pins, strict=True):
        source_doc = source_documents[selected_host]
        source_wrapper_map[selected_host] = {
            "artifact": {"path": source_pin["path"],
                         "raw_sha256": source_pin["raw_sha256"]},
            "semantic_sha256": source_pin["semantic_sha256"],
        }
        execution_sources[selected_host] = {
            "source_root": f"/tmp/lineage-producer-source/{selected_host}",
            "git_commit": source_doc["source"]["git_commit"],
            "source_tree_sha256": source_doc["source"]["source_tree_sha256"],
            "build_sha256": lineage.sha256_bytes(
                lineage.canonical_bytes(source_doc["build"]),
            ),
        }
    execution_core = {
        "schema": prep_budget.PREPARATORY_EXECUTION_SCHEMA,
        "campaign_id": campaign_id, "host_id": host_id, "hosts": hosts,
        "original_inputs": {
            "spec": {"artifact": {"path": spec_pin["path"],
                                   "raw_sha256": spec_pin["raw_sha256"]},
                     "semantic_sha256": spec_pin["semantic_sha256"]},
            "plan": {"artifact": {"path": plan_pin["path"],
                                   "raw_sha256": plan_pin["raw_sha256"]},
                     "semantic_sha256": plan_pin["semantic_sha256"]},
            "source_manifests": source_wrapper_map,
            "campaign_artifacts_root": "/tmp/lineage-producer-input/campaign-artifacts",
        },
        "execution_sources": execution_sources,
        "modules": {selected_host: typed_modules for selected_host in hosts},
        "observed_hosts": observed_map,
        "artifact_root": artifact_root, "output_root": output_root,
        "scope": source5_campaign.PREPARATORY_SCOPE,
        "phase_order": ["exploration"],
        "protocol_sha256": lineage.sha256_bytes(
            lineage.canonical_bytes(spec_doc["protocol"]),
        ),
        "preparatory_capacity_generation": generation,
        "preparatory_capacity_registration": registration,
        "archive_signer_contexts": archive_signers,
        "qualification_eligible": False,
    }
    basis = prep_budget.build_execution_basis(execution_core)
    prep_context = types.SimpleNamespace(
        manifest=execution_core,
        preparatory_capacity_generation=generation,
        preparatory_capacity_registration=registration,
        preparatory_execution_basis_sha256=basis,
        source_manifest_pins={pin["host_id"]: pin for pin in source_manifest_pins},
        sources=source_documents, host_id=host_id,
        spec_pin=spec_pin, spec_semantic_sha256=spec_pin["semantic_sha256"],
        plan_pin=plan_pin, plan_semantic_sha256=plan_pin["semantic_sha256"],
        archive_signer_context_pin=signer_pin,
    )
    preparatory_original_pins = source5_campaign._source5_preparatory_original_pins(
        prep_context,
    )

    counts = {
        "source5_authorized": 1, "source5_app_started": 2,
        "source5_app_terminal": 2, "source5_job_terminal": 1,
    }
    widths = {kind: 16 * 1024 for kind in prep_budget.PREPARATORY_JOURNAL_EVENTS}
    success_bytes = sum(counts[kind] * widths[kind] for kind in counts)
    width_rows = []
    for index, job in enumerate(jobs):
        job_sha = lineage.sha256_bytes(lineage.canonical_bytes(job))
        width_rows.append({
            "phase": "exploration", "job_index": index,
            "ordinal": job["ordinal"], "run_id": job["run_id"],
            "job_sha256": job_sha,
            "event_counts": dict(counts),
            "maximum_event_bytes_by_kind": dict(widths),
            "failed_event_counts": dict(counts),
            "failed_event_bytes_by_kind": dict(widths),
            "success_job_bytes": success_bytes,
            "failed_window_bytes": success_bytes,
            "failed_event_count": 6,
            "failed_event_count_uplift": 0, "byte_uplift": 0,
        })
    owner_pins = {
        role: {"path": relative,
               "raw_sha256": typed_by_path[relative]["sha256"],
               "byte_count": typed_by_path[relative]["size"]}
        for role, relative in chronology.SOURCE5_WIDTH_OWNER_PATHS.items()
    }
    selected_source_pin = source_manifest_pins[0]
    width_contract = prep_budget.build_journal_width_contract(
        campaign_id=campaign_id, host_id=host_id,
        execution_basis_sha256=basis,
        original_pins=preparatory_original_pins,
        initial_spec_pin=spec_pin, initial_plan_pin=plan_pin,
        capacity_generation_pin=generation_completion,
        source_manifest_pin={key: selected_source_pin[key] for key in (
            "path", "raw_sha256", "semantic_sha256",
        )},
        owner_pins=owner_pins, setup_line_bytes=16 * 1024,
        job_rows=width_rows,
    )
    width_path = (f"{artifact_root}/{campaign_id}/source5/{host_id}/evidence-budget/"
                  "preparatory-journal-width-v1.json")
    width_raw = lineage.canonical_bytes(width_contract)
    width_pin = {
        "path": width_path, "raw_sha256": lineage.sha256_bytes(width_raw),
        "semantic_sha256": width_contract["contract_sha256"],
    }

    cleanup_context = types.SimpleNamespace(
        fixed_pair=fixed_pair, journal_width_cleanup_source_bytes=None,
    )
    source_maximum = source5_campaign.source5_cleanup_sidecar_source_byte_bound(
        cleanup_context,
    )
    poll_interval = 0.01
    normal_polls = int((fixed_pair.TERM_GRACE_SECONDS +
                        fixed_pair.KILL_REAP_SECONDS) / poll_interval) + 4
    emergency_polls = int(fixed_pair.KILL_REAP_SECONDS / poll_interval) + 4
    refusal_bytes = chronology.MAX_SOURCE5_CLEANUP_REFUSAL_BYTES
    cleanup_shape_fields = {
        "maximum_session_members_per_snapshot": fixed_pair.MAX_PROC_ENTRIES,
        "maximum_pidfd_signal_entries_per_snapshot": fixed_pair.MAX_PROC_ENTRIES,
        "maximum_signal_snapshots": source5_campaign.MAX_SOURCE5_CLEANUP_SIGNAL_SNAPSHOTS,
        "maximum_cleanup_errors": source5_campaign.MAX_SOURCE5_CLEANUP_ERROR_ENTRIES,
        "maximum_error_text_bytes": source5_campaign.MAX_SOURCE5_CLEANUP_ERROR_TEXT_BYTES,
        "normal_cleanup_poll_count": normal_polls,
        "emergency_cleanup_poll_count": emergency_polls,
        "term_grace_seconds": fixed_pair.TERM_GRACE_SECONDS,
        "kill_reap_seconds": fixed_pair.KILL_REAP_SECONDS,
        "cleanup_poll_interval_seconds": poll_interval,
    }
    cleanup_shape = {
        **cleanup_shape_fields,
        "source_maximum_bytes": source_maximum,
        "admission_maximum_bytes": source_maximum,
        "maximum_window_bytes": 2 * source_maximum,
        "refusal_file_bytes": refusal_bytes,
        "maximum_refusal_window_bytes": 2 * refusal_bytes,
    }
    retention = {
        "cleanup_source_shape": cleanup_shape,
        "maximum_cleanup_sidecar_source_bytes": source_maximum,
        "maximum_cleanup_sidecar_bytes": source_maximum,
        "maximum_failed_cleanup_window_bytes": 2 * source_maximum,
        "maximum_cleanup_sidecar_refusal_bytes": refusal_bytes,
        "maximum_failed_cleanup_refusal_window_bytes": 2 * refusal_bytes,
        "maximum_failed_cleanup_window_inodes": 2,
        "maximum_failed_cleanup_refusal_window_inodes": 2,
    }
    maximum_record_bytes = 64 * 1024
    record_bounds = [
        {"ordinal": job["ordinal"], "run_id": job["run_id"],
         "job_sha256": width_rows[index]["job_sha256"],
         "maximum_record_bytes": maximum_record_bytes}
        for index, job in enumerate(jobs)
    ]
    schedule = {
        "phase": "exploration", "original_job_count": 360,
        "original_callback_event_count": 2160, "setup_event_count": 1,
        "maximum_failed_event_count_uplift": 0,
        "maximum_journal_event_count": 2161,
        "maximum_journal_bytes": width_contract["total_event_bytes"],
        "maximum_phase_ledger_bytes": 360 * maximum_record_bytes,
        "maximum_job_record_bytes_by_ordinal": record_bounds,
    }
    read_schedule = [
        {
            "analysis_phase": "exploration", "owner_phase": "exploration",
            "job_index": index, "job": job,
            "job_sha256": width_rows[index]["job_sha256"],
            "request_ordinal": index, "use": "capacity_pilot_export",
            "caps": {"bundle_bytes": 1, "maximum_request_bytes": 1,
                     "maximum_response_bytes": 1, "object_count": 1,
                     "stage_bytes": 1},
        }
        for index, job in enumerate(jobs)
    ]
    budget_body = {
        "schema": prep_budget.PREPARATORY_BUDGET_SCHEMA,
        "campaign_id": campaign_id, "host_id": host_id,
        "profile": prep_budget.PREPARATORY_PROFILE,
        "execution_basis_sha256": basis,
        "original_pins": preparatory_original_pins,
        "owner_contract": {
            "cleanup_source_shape": cleanup_shape_fields,
            "fixed_pair": {"limits": {"MAX_PROC_ENTRIES": fixed_pair.MAX_PROC_ENTRIES}},
        },
        "schedule": schedule, "read_schedule": read_schedule,
        "journal_width_contract_pin": width_pin,
        "path_catalogue": {"retention_policy": retention},
        "archive_transport": {}, "retention_policy": retention,
        "storage_reservation": {},
        "readiness": {
            "preparatory_budget_complete": True,
            "preparatory_execution_ready": True,
            "full_horizon_execution_ready": False,
            "component_gate_ready": False,
            "qualification_eligible": False,
        },
    }
    budget_doc = {
        **budget_body,
        "budget_sha256": lineage.sha256_bytes(lineage.canonical_bytes(budget_body)),
    }
    budget_path = (f"{artifact_root}/{campaign_id}/source5/{host_id}/evidence-budget/"
                   "host-evidence-budget-preparatory-v1.json")
    budget_raw = lineage.canonical_bytes(budget_doc)
    budget_pin = {
        "path": budget_path, "raw_sha256": lineage.sha256_bytes(budget_raw),
        "semantic_sha256": budget_doc["budget_sha256"],
    }
    execution_body = {
        **execution_core,
        "preparatory_journal_width_contracts": {host_id: {
            "artifact": {"path": width_pin["path"], "raw_sha256": width_pin["raw_sha256"]},
            "semantic_sha256": width_pin["semantic_sha256"],
        }},
        "preparatory_host_budgets": {host_id: {
            "artifact": {"path": budget_pin["path"], "raw_sha256": budget_pin["raw_sha256"]},
            "semantic_sha256": budget_pin["semantic_sha256"],
        }},
        "preparatory_execution_basis_sha256": basis,
    }
    execution_doc = {
        **execution_body,
        "manifest_sha256": lineage.sha256_bytes(lineage.canonical_bytes(execution_body)),
    }
    prep_budget.validate_execution_manifest(execution_doc)
    execution_path = f"{artifact_root}/{campaign_id}/source5/{host_id}/preparatory-execution.json"
    execution_raw = lineage.canonical_bytes(execution_doc)
    execution_pin = {
        "path": execution_path, "raw_sha256": lineage.sha256_bytes(execution_raw),
        "semantic_sha256": execution_doc["manifest_sha256"],
    }
    initial = {
        "execution_manifest_pin": execution_pin,
        "spec_pin": spec_pin, "plan_pin": plan_pin,
        "source_manifest_pins": source_manifest_pins,
        "observed_host_pin": observed_pins[host_id],
        "capacity_generation_sha256": generation_completion["semantic_sha256"],
        "capacity_registration_head": registration["registration_head"],
        "host_budget_pin": budget_pin, "journal_width_pin": width_pin,
        "signer_context_pin": signer_pin,
        "signer_fingerprint": signer_doc["authorized_primary_fingerprint"],
        "maximum_signature_bytes": signer_doc["maximum_signature_bytes"],
    }
    header = {
        "campaign_id": campaign_id, "host_id": host_id,
        "initial_output_root": output_root, "initial": initial,
    }
    selected_files = {row["path"]: row for row in typed_files}
    chronology_original_pins = {
        "schema": chronology.CHRONOLOGY_SCHEMA,
        "campaign_id": campaign_id, "host_id": host_id,
        "spec": spec_pin, "plan": plan_pin,
        "source_manifests": source_manifest_pins,
        "observed_host": {
            **observed_pins[host_id],
            "controls": observed_documents[host_id]["controls"],
            "cpu_affinity": observed_documents[host_id]["cpu_affinity"],
            "network_namespace_inode": observed_documents[host_id][
                "network_namespace_inode"],
        },
        "capacity_stage": {
            "path": chronology.CAPACITY_STAGE_SOURCE_PATH,
            "sha256": selected_files[chronology.CAPACITY_STAGE_SOURCE_PATH]["sha256"],
        },
        "chronology_module": {
            "path": chronology.CHRONOLOGY_SOURCE_PATH,
            "sha256": selected_files[chronology.CHRONOLOGY_SOURCE_PATH]["sha256"],
        },
        "pair_runner": {
            "path": chronology.PAIR_RUNNER_SOURCE_PATH,
            "sha256": selected_files[chronology.PAIR_RUNNER_SOURCE_PATH]["sha256"],
        },
        "captured_modules": [
            {"role": role, "path": relative,
             "sha256": selected_files[relative]["sha256"]}
            for role, relative in (
                ("campaign_controller", chronology.CONTROLLER_SOURCE_PATH),
                ("campaign_inputs", "scripts/application-campaign-inputs.py"),
                ("feedback_reader", "scripts/application-feedback-readback.py"),
                ("capacity_producer", "scripts/application-byte-capacity.py"),
            )
        ],
    }
    final_prepared = {
        "original_pins": chronology_original_pins,
        "source5_preparatory_capacity_generation": generation,
    }
    reader_store = {
        spec_path: spec_raw, plan_path: plan_raw,
        execution_path: execution_raw, signer_pin["path"]: signer_raw,
        width_path: width_raw, budget_path: budget_raw,
        **source_raws,
    }
    reader_store.update({
        observed_pins[selected_host]["path"]: lineage.canonical_bytes(
            observed_documents[selected_host],
        )
        for selected_host in hosts
    })
    reader_calls = []

    def artifact_reader(pin: dict[str, str], maximum: int) -> bytes:
        reader_calls.append((dict(pin), maximum))
        if set(pin) != {"path", "raw_sha256"}:
            raise AssertionError("producer fixture reader received a non-raw pin")
        raw = reader_store.get(pin["path"])
        if raw is None or len(raw) > maximum or lineage.sha256_bytes(raw) != pin["raw_sha256"]:
            raise AssertionError("producer fixture closed reader rejected an unpinned read")
        return raw

    return {
        "header": header, "spec": spec_doc, "plan": plan_doc,
        "jobs": jobs, "final_prepared": final_prepared,
        "width": width_contract, "budget": budget_doc,
        "reader": artifact_reader, "reader_calls": reader_calls,
        "source5_campaign_module": source5_campaign,
        "preparatory_budget_module": prep_budget,
    }


class PreparedLineageProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # Synthetic structural component only: SourceA replay is real, while
        # no APP, numeric owner, GPG, or qualification result is claimed.
        cls.synthetic = synthetic_full_replay_case()
        cls.producer_context = producer_shaped_initial_context_case()

    def replay_initial(self, *, header=None, context=None, journal_raw=None,
                       phase_ledger_raw=None):
        case = self.synthetic
        return lineage._replay_initial_preparatory_journal_and_ledger(
            copy.deepcopy(case["header"]) if header is None else header,
            case["jobs"], case["rows"],
            copy.deepcopy(case["original_context"]) if context is None else context,
            artifact_reader=case["artifact_reader"],
            chronology_module=case["chronology_module"],
            campaign_module=case["campaign_module"],
            journal_raw=case["journal_raw"] if journal_raw is None else journal_raw,
            phase_ledger_raw=(case["phase_ledger_raw"]
                              if phase_ledger_raw is None else phase_ledger_raw),
        )

    def test_sourcea_replays_full_synthetic_360_job_journal_and_ledger(self) -> None:
        proof = self.replay_initial()
        self.assertEqual(proof["initial_journal_record_count"], 2161)
        self.assertEqual(proof["initial_phase_ledger_row_count"], 360)
        self.assertEqual(proof["initial_phase_ledger_byte_count"],
                         len(self.synthetic["phase_ledger_raw"]))
        self.assertEqual(proof["job_count"], 360)
        self.assertEqual(proof["callback_count"], 2160)
        self.assertTrue(proof["structural_only"])
        self.assertTrue(proof["component_replay_required"])
        self.assertTrue(proof["fresh_sourcea_gpg_replay_required"])
        self.assertFalse(proof["qualification_eligible"])

    def test_sourcea_replay_rejects_wrong_terminal_head(self) -> None:
        header = copy.deepcopy(self.synthetic["header"])
        header["journal"]["head"] = "f" * 64
        with self.assertRaises(lineage.PreparedExplorationLineageError):
            self.replay_initial(header=header)

    def test_sourcea_replay_rejects_journal_digest_mismatch(self) -> None:
        header = copy.deepcopy(self.synthetic["header"])
        header["journal"]["pin"]["raw_sha256"] = "f" * 64
        with self.assertRaises(lineage.PreparedExplorationLineageError):
            self.replay_initial(header=header)

    def test_sourcea_replay_rejects_reordered_or_missing_phase_ledger_rows(self) -> None:
        case = self.synthetic
        lines = case["phase_ledger_raw"].splitlines(keepends=True)
        reordered = b"".join([lines[1], lines[0], *lines[2:]])
        header = copy.deepcopy(case["header"])
        header["phase_ledger"]["pin"]["raw_sha256"] = chronology.sha256_bytes(reordered)
        with self.assertRaises(lineage.PreparedExplorationLineageError):
            self.replay_initial(header=header, phase_ledger_raw=reordered)

        missing = b"".join(lines[:-1])
        header = copy.deepcopy(case["header"])
        header["phase_ledger"]["pin"]["raw_sha256"] = chronology.sha256_bytes(missing)
        with self.assertRaises(lineage.PreparedExplorationLineageError):
            self.replay_initial(header=header, phase_ledger_raw=missing)

    def test_sourcea_replay_rejects_phase_ledger_digest_mismatch(self) -> None:
        header = copy.deepcopy(self.synthetic["header"])
        header["phase_ledger"]["pin"]["raw_sha256"] = "f" * 64
        with self.assertRaises(lineage.PreparedExplorationLineageError):
            self.replay_initial(header=header)

    def test_sourcea_replay_rejects_width_and_original_pin_context_changes(self) -> None:
        case = self.synthetic
        width = copy.deepcopy(case["width_contract"])
        width["fixed_event_widths"][0]["maximum_line_bytes"] = 1
        width["setup_event_widths"][0]["maximum_line_bytes"] = 1
        width_projection, event_projection = \
            chronology._source5_preparatory_journal_projection(
                width, case["jobs"], case["header"]["host_id"],
            )
        context = copy.deepcopy(case["original_context"])
        context["width_projection"] = width_projection
        context["event_projection"] = event_projection
        with self.assertRaises(lineage.PreparedExplorationLineageError):
            self.replay_initial(context=context)

        context = copy.deepcopy(case["original_context"])
        context["original_pins"]["host_id"] = "another-host"
        with self.assertRaises(lineage.PreparedExplorationLineageError):
            self.replay_initial(context=context)

    def test_initial_context_replays_actual_sourceh_prep_original_pins(self) -> None:
        case = self.producer_context
        context = lineage._source5_prepared_lineage_initial_context(
            case["header"], case["spec"], case["plan"],
            case["final_prepared"], case["jobs"],
            artifact_reader=case["reader"], chronology_module=chronology,
            source5_campaign_module=case["source5_campaign_module"],
            preparatory_budget_module=case["preparatory_budget_module"],
        )
        self.assertEqual(context["preparatory_original_pins"],
                         case["budget"]["original_pins"])
        self.assertEqual(
            context["width_contract"]["initial_plan_pin"],
            case["header"]["initial"]["plan_pin"],
        )
        self.assertNotIn("plan_pin", context["width_contract"])
        self.assertEqual(
            context["phase_ledger_maximum_bytes"],
            case["budget"]["schedule"]["maximum_phase_ledger_bytes"],
        )
        self.assertEqual(
            context["phase_ledger_record_maximum_bytes"],
            chronology.MAX_EVENT_BYTES,
        )
        self.assertGreaterEqual(len(case["reader_calls"]), 7)

    def test_public_verifier_obtains_header_only_from_closed_reader(self) -> None:
        campaign_id, host_id = "closed-reader-component", "host-kvm-a"
        output_root = "/tmp/closed-reader-final-output"
        header_pin = {
            "path": "/tmp/closed-reader-initial/bridge-header.json",
            "raw_sha256": "a" * 64,
        }
        index_pin = {
            "path": "/tmp/closed-reader-initial/record-index.jsonl",
            "raw_sha256": "b" * 64,
        }
        reads = []

        def closed_reader(pin, maximum):
            reads.append((dict(pin), maximum))
            raise AssertionError("reader denies every uncaptured artifact")

        with self.assertRaisesRegex(AssertionError, "uncaptured artifact"):
            lineage.verify_source5_prepared_exploration_lineage(
                {"campaign_id": campaign_id, "host_id": host_id,
                 "output_root": output_root},
                {"bridge_header": header_pin, "record_index": index_pin},
                artifact_reader=closed_reader, campaign_module=campaign_core,
                input_preparation_module=object(), campaign_inputs_module=object(),
                chronology_module=chronology, source5_campaign_module=source5_campaign,
                preparatory_budget_module=prep_budget,
            )
        self.assertEqual(reads, [(header_pin, 256 * 1024)])

    def _documents(self):
        # Synthetic structural documents only; no APP, journal replay or GPG.
        jobs = original_jobs()
        campaign_id, host_id, output = "campaign-kvm", "host-kvm-a", "/tmp/lineage-output"
        header = lineage._header_template(campaign_id, host_id, output)
        source = header["initial"]["source_manifest_pins"][0]
        header["initial"]["source_manifest_pins"] = [
            {**source, "host_id": host, "path": f"/tmp/{host}.source.json"}
            for host in (host_id, "host-kvm-b")
        ]
        rows = []
        for index, job in enumerate(jobs):
            row = lineage._index_row_template(index, job, campaign_id, host_id, output)
            leaf = f"{job['ordinal']:06d}-{row['job_sha256']}"
            row["archive_pins"]["ack_pin"]["path"] = f"/tmp/root/acks/exploration/{leaf}.json"
            row["archive_pins"]["signature_pin"]["path"] = f"/tmp/root/acks/signatures/exploration/{leaf}.sig"
            rows.append(row)
        raw = chronology._source5_preparatory_lineage_index_bytes(
            rows, lineage.project_prepared_exploration_lineage_outputs(
                campaign_id, host_id, output, jobs,
            )["index"]["max_bytes"],
        )
        header["record_index"]["pin"]["raw_sha256"] = lineage.sha256_bytes(raw)
        return header, rows, raw, jobs

    def test_complete_360_document_roundtrip_uses_real_root_layout_and_job_shape(self):
        header, rows, raw, jobs = self._documents()
        self.assertTrue(all("campaign_id" not in job for job in jobs))
        checked_header, checked_rows = lineage.validate_prepared_exploration_lineage_documents(
            lineage.canonical_bytes(header), raw, jobs,
        )
        self.assertEqual(checked_header, header)
        self.assertEqual(checked_rows, rows)
        self.assertEqual(sum(row["callback_witness"]["callback_count"] for row in rows), 2160)

    def test_header_accepts_uppercase_gpg_fingerprints_and_rejects_digest_confusion(self):
        header, _rows, _raw, _jobs = self._documents()
        for fingerprint in ("A1" * 20, "B2" * 32):
            with self.subTest(fingerprint=fingerprint):
                header["initial"]["signer_fingerprint"] = fingerprint
                lineage._validate_header(header, "campaign-kvm", "host-kvm-a", "/tmp/lineage-output")
        for fingerprint in ("a1" * 20, "f" * 64, "G" * 40, 123, None):
            with self.subTest(fingerprint=fingerprint):
                header["initial"]["signer_fingerprint"] = fingerprint
                with self.assertRaises(lineage.PreparedExplorationLineageError):
                    lineage._validate_header(header, "campaign-kvm", "host-kvm-a", "/tmp/lineage-output")

    def test_document_index_pin_line_endings_and_cardinality_are_bound(self):
        header, _rows, raw, jobs = self._documents()
        for changed in (raw + b"\n", raw[:-1], raw.split(b"\n", 1)[1], raw.replace(b"\n", b"\n\n")):
            with self.subTest(length=len(changed)):
                pinned = copy.deepcopy(header)
                pinned["record_index"]["pin"]["raw_sha256"] = lineage.sha256_bytes(changed)
                with self.assertRaises(lineage.PreparedExplorationLineageError):
                    lineage.validate_prepared_exploration_lineage_documents(
                        lineage.canonical_bytes(pinned), changed, jobs,
                    )
        changed_header = copy.deepcopy(header)
        changed_header["record_index"]["pin"]["raw_sha256"] = "f" * 64
        with self.assertRaises(lineage.PreparedExplorationLineageError):
            lineage.validate_prepared_exploration_lineage_documents(
                lineage.canonical_bytes(changed_header), raw, jobs,
            )

    def test_actual_signature_hierarchy_is_required(self):
        header, rows, _raw, jobs = self._documents()
        rows[0]["archive_pins"]["signature_pin"]["path"] = (
            rows[0]["archive_pins"]["signature_pin"]["path"].replace("/acks/signatures/", "/signatures/")
        )
        changed = b"".join(lineage.canonical_bytes(row) for row in rows)
        header["record_index"]["pin"]["raw_sha256"] = lineage.sha256_bytes(changed)
        with self.assertRaises(lineage.PreparedExplorationLineageError):
            lineage.validate_prepared_exploration_lineage_documents(
                lineage.canonical_bytes(header), changed, jobs,
            )

    def test_projection_keeps_repeated_original_ordinals_and_exact_keys(self) -> None:
        jobs = original_jobs()
        self.assertEqual(len(jobs), 360)
        self.assertEqual({job["ordinal"] for job in jobs}, set(range(1, 7)))

        rows = lineage.project_prepared_exploration_lineage_outputs(
            "campaign-kvm", "host-kvm-a", "/tmp/lineage-output", jobs,
        )

        self.assertEqual(set(rows), {"header", "index"})
        self.assertEqual(rows["header"]["role"], "preparation")
        self.assertEqual(rows["index"]["role"], "preparation")
        self.assertEqual(rows["header"]["host_id"], "host-kvm-a")
        self.assertEqual(rows["index"]["host_id"], "host-kvm-a")
        self.assertEqual(rows["index"]["max_bytes"], sum(
            len(lineage.canonical_bytes(lineage._index_row_template(
                index, job, "campaign-kvm", "host-kvm-a", "/tmp/lineage-output",
            )))
            for index, job in enumerate(jobs)
        ))

    def test_projection_rejects_duplicate_identity_and_path_escaping_run_id(self) -> None:
        jobs = original_jobs()
        duplicated = list(jobs)
        duplicated[1] = duplicated[0]
        with self.assertRaises(lineage.PreparedExplorationLineageError):
            lineage.project_prepared_exploration_lineage_outputs(
                "campaign-kvm", "host-kvm-a", "/tmp/lineage-output", duplicated,
            )

        escaped = list(jobs)
        escaped[0] = {**escaped[0], "run_id": "../outside"}
        with self.assertRaises(lineage.PreparedExplorationLineageError):
            lineage.project_prepared_exploration_lineage_outputs(
                "campaign-kvm", "host-kvm-a", "/tmp/lineage-output", escaped,
            )

    def test_path_cap_covers_utf8_json_escaping_and_quotes(self) -> None:
        witness = lineage._max_path()
        unicode_and_quote = "/" + "\u0080" * 2047 + '"'
        supplementary = "/" + "\U0001f600" * 1023 + "abc"
        self.assertEqual(len(witness.encode("utf-8")), lineage.MAX_PATH_BYTES)
        self.assertEqual(witness, unicode_and_quote)
        self.assertEqual(len(supplementary.encode("utf-8")), lineage.MAX_PATH_BYTES)
        self.assertGreater(
            len(json.dumps(witness, ensure_ascii=True).encode("ascii")),
            len(json.dumps(supplementary, ensure_ascii=True).encode("ascii")),
        )

        rows = lineage.project_prepared_exploration_lineage_outputs(
            "campaign-kvm", "host-kvm-a", "/tmp/lineage-output", original_jobs(),
        )
        witness_row = lineage._index_row_template(
            0, original_jobs()[0], "campaign-kvm", "host-kvm-a", "/tmp/lineage-output",
        )
        self.assertIn(witness, witness_row["archive_pins"]["ack_pin"]["path"])
        self.assertGreater(rows["index"]["max_bytes"], 360 * 4096)

    def test_header_validation_accepts_actual_two_or_three_host_cohorts(self) -> None:
        for host_count in (2, 3):
            with self.subTest(host_count=host_count):
                header = lineage._header_template(
                    "campaign-kvm", "host-a", "/tmp/lineage-output",
                )
                source_template = header["initial"]["source_manifest_pins"][0]
                header["initial"]["source_manifest_pins"] = [
                    {
                        **source_template,
                        "host_id": f"host-{index}",
                        "path": f"/tmp/source-{index}.json",
                    }
                    for index in range(host_count)
                ]
                header["initial"]["source_manifest_pins"][0]["host_id"] = "host-a"
                checked = lineage._validate_header(
                    header, "campaign-kvm", "host-a", "/tmp/lineage-output",
                )
                self.assertEqual(len(checked["initial"]["source_manifest_pins"]), host_count)

    def test_sourcea_publisher_serializes_exactly_360_canonical_lf_lines(self) -> None:
        rows = [{"row_index": index, "text": "retained pair \u0080 \""}
                for index in range(360)]
        exact_cap = sum(len(chronology.canonical_bytes(row)) for row in rows)

        raw = chronology._source5_preparatory_lineage_index_bytes(rows, exact_cap)

        expected = b"".join(chronology.canonical_bytes(row) for row in rows)
        lines = raw.splitlines(keepends=True)
        self.assertEqual(raw, expected)
        self.assertEqual(len(lines), 360)
        self.assertTrue(all(line.endswith(b"\n") and not line.endswith(b"\n\n")
                            for line in lines))
        with self.assertRaises(chronology.ChronologyError):
            chronology._source5_preparatory_lineage_index_bytes(rows, exact_cap - 1)

    def test_v2_provenance_requires_exact_two_host_raw_pin_map(self) -> None:
        hosts = ["host-kvm-a", "host-kvm-b"]
        digest = "a" * 64

        def pin(path: str) -> dict[str, str]:
            return {"path": path, "raw_sha256": digest}

        provenance = {
            "schema": lineage.SOURCE5_PREPARED_INPUTS_PROVENANCE_SCHEMA_V2,
            "preparation_pin": pin("/tmp/final/preparation.json"),
            "final_spec_pin": pin("/tmp/final/spec.json"),
            "final_plan_pin": pin("/tmp/final/plan.json"),
            "exploration_lineage": {
                host: {
                    "bridge_header": pin(f"/tmp/initial/{host}/bridge-header.json"),
                    "record_index": pin(f"/tmp/initial/{host}/record-index.jsonl"),
                }
                for host in hosts
            },
        }
        checked = lineage.validate_prepared_input_provenance_v2(
            provenance, expected_hosts=hosts,
        )
        self.assertEqual(checked, provenance)
        for changed in (
            {**provenance, "imported": True},
            {**provenance, "exploration_lineage": {
                hosts[0]: provenance["exploration_lineage"][hosts[0]],
            }},
        ):
            with self.subTest(fields=tuple(sorted(changed))):
                with self.assertRaises(lineage.PreparedExplorationLineageError):
                    lineage.validate_prepared_input_provenance_v2(
                        changed, expected_hosts=hosts,
                    )
        bad_pin = copy.deepcopy(provenance)
        bad_pin["exploration_lineage"][hosts[0]]["record_index"][
            "semantic_sha256"
        ] = digest
        with self.assertRaises(lineage.PreparedExplorationLineageError):
            lineage.validate_prepared_input_provenance_v2(
                bad_pin, expected_hosts=hosts,
            )


class GeneratedH6PublicLineageTests(unittest.TestCase):
    """Synthetic structure only: no APP, owner, GPG, or qualification claim."""

    def test_generated_h6_budget_reaches_public_sourcea_lineage_through_0400_capture(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-generated-lineage-") as directory:
            fixture = producer_support.PreparatoryProducerFixture(
                Path(directory), two_kvm_profile=True,
            )
            try:
                original_pins, setup_details, setup_head = \
                    fixture.bind_registration_to_sourcea_first_event()
                artifacts = fixture.build()
                for host_id in fixture.fixture.host_ids:
                    observed_hash = fixture.observed_values[host_id]["controls_sha256"]
                    self.assertEqual(
                        artifacts["manifest"]["observed_hosts"][host_id][
                            "host_fingerprint_sha256"],
                        observed_hash,
                    )
                    self.assertEqual(
                        artifacts["manifest"]["observed_hosts"][host_id][
                            "controls_sha256"],
                        observed_hash,
                    )
                # This is the actual H6 full validator over the generated
                # execution/Plan/Spec/width/source/catalogue bytes and chunks.
                fixture.validator(artifacts["budget"], artifacts["manifest"])
                self.assertEqual(len(artifacts["budget"]["read_schedule"]), 360)
                self.assertEqual(artifacts["width"]["total_event_count"], 2161)

                case = synthetic_full_replay_case(generated=(
                    fixture, artifacts, original_pins, setup_details, setup_head,
                ))
                documents = case["generated_documents"]
                self.assertIsNotNone(documents)
                self.assertEqual(len(case["jobs"]), 360)
                self.assertEqual(len(case["rows"]), 360)
                self.assertEqual(
                    documents["header"]["initial"]["capacity_registration_head"],
                    setup_head,
                )

                origins = _generated_lineage_origin_bytes(fixture, artifacts, case)
                signer_executable_path = fixture.signer_context["gpgv_pin"]["path"]
                captured, reader, reads = _capture_and_remove_origins(
                    origins, Path(directory) / "closed-capture",
                    origin_modes={
                        signer_executable_path: stat.S_IMODE(
                            Path(signer_executable_path).lstat().st_mode,
                        ),
                    },
                )
                self.assertTrue(captured)
                self.assertTrue(all(Path(module.__file__).is_file()
                                    for module in fixture.modules.values()))
                for _sha, path, _size in captured.values():
                    info = path.lstat()
                    self.assertTrue(stat.S_ISREG(info.st_mode))
                    self.assertEqual(stat.S_IMODE(info.st_mode), 0o400)
                    self.assertEqual(info.st_nlink, 1)

                header_pin = documents["header_pin"]
                sourcea_lineage = case["lineage_module"]
                with self.assertRaises(AssertionError):
                    reader({**header_pin, "semantic_sha256": "0" * 64}, 256 * 1024)
                with self.assertRaises(OSError):
                    reader({"path": header_pin["path"],
                            "raw_sha256": "0" * 64}, 256 * 1024)
                with self.assertRaises(OSError):
                    reader({"path": "/tmp/unlisted-lineage-origin.json",
                            "raw_sha256": "0" * 64}, 256 * 1024)

                proof = sourcea_lineage.verify_source5_prepared_exploration_lineage(
                    documents["final_prepared"],
                    {"bridge_header": documents["header_pin"],
                     "record_index": documents["index_pin"]},
                    artifact_reader=reader,
                    campaign_module=fixture.campaign,
                    input_preparation_module=fixture.input_preparation,
                    campaign_inputs_module=fixture.inputs_module,
                    chronology_module=fixture.chronology,
                    source5_campaign_module=fixture.controller,
                    preparatory_budget_module=fixture.prep_module,
                )
                self.assertEqual(proof["job_count"], 360)
                self.assertEqual(proof["callback_count"], 2160)
                self.assertEqual(proof["initial_journal_record_count"], 2161)
                self.assertEqual(proof["initial_phase_ledger_row_count"], 360)
                self.assertTrue(proof["allowed_slot_fill_proved"])
                self.assertTrue(proof["component_replay_required"])
                self.assertTrue(proof["fresh_sourcea_gpg_replay_required"])
                self.assertFalse(proof["qualification_eligible"])

                indexed_paths = set()
                for row in case["rows"]:
                    indexed_paths.add(row["job_record_pin"]["path"])
                    indexed_paths.update(
                        pin["path"] for pin in row["archive_pins"].values()
                    )
                read_counts = {}
                for path, _maximum in reads:
                    if path in indexed_paths:
                        read_counts[path] = read_counts.get(path, 0) + 1
                self.assertEqual(len(indexed_paths), 2160)
                self.assertEqual(set(read_counts), indexed_paths)
                self.assertTrue(all(count == 1 for count in read_counts.values()))

                wrong_head = copy.deepcopy(documents["header"])
                wrong_head["initial"]["capacity_registration_head"] = "0" * 64
                with self.assertRaises(sourcea_lineage.PreparedExplorationLineageError):
                    sourcea_lineage._replay_initial_preparatory_journal_and_ledger(
                        wrong_head, case["jobs"], case["rows"],
                        case["original_context"], artifact_reader=reader,
                        chronology_module=fixture.chronology,
                        campaign_module=fixture.campaign,
                        journal_raw=case["journal_raw"],
                        phase_ledger_raw=case["phase_ledger_raw"],
                    )
            finally:
                fixture.close()


class GeneratedH6RichLineageProofTests(unittest.TestCase):
    """Real H6 bytes exercise the additive rich proof and A6 window join."""

    def test_generated_v2_matches_lean_and_projects_actual_a6_windows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="source5-generated-rich-lineage-") as directory:
            fixture = producer_support.PreparatoryProducerFixture(
                Path(directory), two_kvm_profile=True,
            )
            try:
                original_pins, setup_details, setup_head = \
                    fixture.bind_registration_to_sourcea_first_event()
                artifacts = fixture.build()
                fixture.validator(artifacts["budget"], artifacts["manifest"])
                case = synthetic_full_replay_case(generated=(
                    fixture, artifacts, original_pins, setup_details, setup_head,
                ))
                documents = case["generated_documents"]
                origins = _generated_lineage_origin_bytes(fixture, artifacts, case)
                gpgv_path = fixture.signer_context["gpgv_pin"]["path"]
                _captured, reader, _reads = _capture_and_remove_origins(
                    origins, Path(directory) / "rich-closed-capture",
                    origin_modes={
                        gpgv_path: stat.S_IMODE(Path(gpgv_path).lstat().st_mode),
                    },
                )
                sourcea = fixture.lineage_module
                lineage_pins = {
                    "bridge_header": documents["header_pin"],
                    "record_index": documents["index_pin"],
                }
                verifier_args = {
                    "artifact_reader": reader,
                    "campaign_module": fixture.campaign,
                    "input_preparation_module": fixture.input_preparation,
                    "campaign_inputs_module": fixture.inputs_module,
                    "chronology_module": fixture.chronology,
                    "source5_campaign_module": fixture.controller,
                    "preparatory_budget_module": fixture.prep_module,
                }
                lean = sourcea.verify_source5_prepared_exploration_lineage(
                    documents["final_prepared"], lineage_pins, **verifier_args,
                )
                rich = sourcea.verify_source5_prepared_exploration_lineage_v2(
                    documents["final_prepared"], lineage_pins, **verifier_args,
                )

                lean_fields = {
                    "schema", "campaign_id", "host_id", "initial_output_root",
                    "final_output_root", "bridge_header_pin", "record_index_pin",
                    "job_count", "callback_count", "allowed_slot_fill_proved",
                    "initial_journal_pin", "initial_journal_structurally_replayed",
                    "initial_phase_ledger_structurally_replayed", "initial_journal_head",
                    "initial_journal_record_count", "initial_phase_ledger_pin",
                    "initial_phase_ledger_byte_count", "initial_phase_ledger_row_count",
                    "component_replay_required", "fresh_sourcea_gpg_replay_required",
                    "qualification_eligible",
                }
                rich_fields = lean_fields | {
                    "bridge_header", "index_rows", "capture_context", "records",
                    "journal_authorizations", "journal_finished", "ancestor",
                }
                self.assertEqual(set(lean), lean_fields)
                self.assertEqual(lean["schema"],
                                 "allocatbelt.application-source5-prepared-exploration-lineage-proof.v1")
                self.assertEqual(set(rich), rich_fields)
                self.assertEqual(rich["schema"],
                                 "allocatbelt.application-source5-prepared-exploration-lineage-proof.v2")
                lean_projection = {key: rich[key] for key in lean_fields}
                lean_projection["schema"] = lean["schema"]
                self.assertEqual(lean, lean_projection)

                self.assertEqual(rich["bridge_header"], documents["header"])
                self.assertEqual(rich["index_rows"], case["rows"])
                self.assertEqual(set(rich["capture_context"]), {
                    "execution_manifest", "width_contract", "budget",
                    "preparatory_original_pins",
                })
                self.assertEqual(rich["capture_context"]["execution_manifest"],
                                 artifacts["manifest"])
                self.assertEqual(rich["capture_context"]["width_contract"],
                                 artifacts["width"])
                self.assertEqual(rich["capture_context"]["budget"],
                                 artifacts["budget"])
                self.assertEqual(rich["capture_context"]["preparatory_original_pins"],
                                 artifacts["budget"]["original_pins"])

                attach_root = Path(directory) / "prepared-context-lock-root"
                attach_root.mkdir(mode=0o700)
                prepared_context = {
                    "source5_execution_schema": fixture.controller.EXECUTION_SCHEMA_V5,
                    "source5_prepared_input_provenance_v2": rich,
                    "source5_journal_width_contract_pin": artifacts["width_pin"],
                    "campaign_id": fixture.spec["campaign_id"],
                    "host_id": fixture.host_id,
                    "plan": fixture.plan,
                }
                with fixture.chronology.campaign_host_lock(
                        attach_root, fixture.spec["campaign_id"], fixture.host_id) as lock:
                    attached = fixture.chronology._source5_attach_prepared_exploration_context(
                        lock, prepared_context, rich,
                    )
                self.assertIs(
                    attached,
                    prepared_context["source5_prepared_exploration_ancestor"],
                )
                self.assertEqual(len(attached["index_rows"]), 360)
                for index, authorization in enumerate(rich["journal_authorizations"]):
                    row = attached["index_rows"][index]
                    self.assertEqual(row["row_index"], index)
                    self.assertEqual(
                        row["job_sha256"],
                        fixture.chronology.sha256_bytes(
                            fixture.chronology.canonical_bytes(row["job"]),
                        ),
                    )
                    self.assertEqual(authorization["job_index"], row["row_index"])
                    self.assertEqual(authorization["job_sha256"], row["job_sha256"])

                expected_jobs = case["jobs"]
                expected_records = [
                    json.loads(line)
                    for line in case["phase_ledger_raw"].splitlines()
                ]
                self.assertEqual(len(rich["records"]), 360)
                self.assertEqual(rich["records"], expected_records)
                authorization_fields = {
                    "authorization_id", "phase", "job_index", "job", "job_run_id",
                    "job_sha256", "members_sha256", "capacity_registration_head",
                    "authorization_head", "execution_manifest", "helper_input",
                    "helper_module", "capacity_completion", "capacity_ledger_raw_sha256",
                    "capacity_terminal_head", "capacity_schedule_sha256", "prerequisites",
                    "input_snapshot_sha256", "output_root", "outer_deadline_seconds",
                    "effective_timeout_seconds", "member_count", "members", "starts",
                    "terminals", "job_terminal", "authorization_record_count",
                }
                finished_fields = {
                    "phase", "job_run_id", "authorization_id",
                    "authorization_head", "job_terminal",
                }
                self.assertEqual(len(rich["journal_authorizations"]), 360)
                self.assertEqual(len(rich["journal_finished"]), 360)
                for index, (job, authorization, finished) in enumerate(zip(
                        expected_jobs, rich["journal_authorizations"],
                        rich["journal_finished"], strict=True)):
                    self.assertEqual(set(authorization), authorization_fields)
                    self.assertEqual(set(finished), finished_fields)
                    self.assertEqual(authorization["job"], job)
                    self.assertEqual(authorization["job_index"], index)
                    self.assertEqual(authorization["job_run_id"], job["run_id"])
                    self.assertEqual(authorization["authorization_record_count"],
                                     index * 6 + 2)
                    self.assertEqual(finished["job_run_id"], job["run_id"])
                    self.assertEqual(finished["authorization_id"],
                                     authorization["authorization_id"])
                    self.assertEqual(finished["authorization_head"],
                                     authorization["authorization_head"])
                    self.assertEqual(finished["job_terminal"],
                                     authorization["job_terminal"])

                ancestor = rich["ancestor"]
                self.assertEqual(set(ancestor), {
                    "bridge_header_pin", "record_index_pin", "header_byte_count",
                    "index_byte_count", "job_list_sha256", "journal", "phase_ledger",
                })
                self.assertEqual(ancestor["bridge_header_pin"], documents["header_pin"])
                self.assertEqual(ancestor["record_index_pin"], documents["index_pin"])
                self.assertEqual(ancestor["header_byte_count"],
                                 len(documents["header_raw"]))
                self.assertEqual(ancestor["index_byte_count"],
                                 len(documents["index_raw"]))
                self.assertEqual(ancestor["job_list_sha256"],
                                 fixture.chronology.sha256_bytes(
                                     fixture.chronology.canonical_bytes(expected_jobs),
                                 ))
                self.assertEqual(set(ancestor["journal"]), {
                    "pin", "byte_count", "record_count", "head",
                })
                self.assertEqual(ancestor["journal"]["pin"], documents["header"]["journal"]["pin"])
                self.assertEqual(ancestor["journal"]["byte_count"],
                                 len(case["journal_raw"]))
                self.assertEqual(ancestor["journal"]["record_count"], 2161)
                self.assertEqual(ancestor["journal"]["head"],
                                 documents["header"]["journal"]["head"])
                self.assertEqual(set(ancestor["phase_ledger"]), {
                    "pin", "byte_count", "row_count",
                })
                self.assertEqual(ancestor["phase_ledger"]["pin"],
                                 documents["header"]["phase_ledger"]["pin"])
                self.assertEqual(ancestor["phase_ledger"]["byte_count"],
                                 len(case["phase_ledger_raw"]))
                self.assertEqual(ancestor["phase_ledger"]["row_count"], 360)

                windows = fixture.chronology._source5_prepared_ack_window_inputs(rich)
                self.assertEqual(len(windows), 360)
                for index, (index_row, record, authorization, finished) in enumerate(windows):
                    self.assertEqual(index_row, rich["index_rows"][index])
                    self.assertEqual(record, rich["records"][index])
                    self.assertEqual(authorization, rich["journal_authorizations"][index])
                    self.assertEqual(finished, rich["journal_finished"][index])
                with self.assertRaises(fixture.chronology.ChronologyError):
                    fixture.chronology._source5_prepared_ack_window_inputs(lean)

                def swap_authorization_windows(proof: dict[str, object]) -> None:
                    rows = proof["journal_authorizations"]
                    rows[0], rows[1] = rows[1], rows[0]

                def swap_records(proof: dict[str, object]) -> None:
                    rows = proof["records"]
                    rows[0], rows[1] = rows[1], rows[0]

                def alter_sequence(proof: dict[str, object]) -> None:
                    proof["journal_authorizations"][0][
                        "authorization_record_count"] += 1

                def alter_job_hash(proof: dict[str, object]) -> None:
                    proof["journal_authorizations"][0]["job_sha256"] = "0" * 64

                def remove_start(proof: dict[str, object]) -> None:
                    proof["journal_authorizations"][0]["starts"].pop()

                def alter_finished_terminal(proof: dict[str, object]) -> None:
                    proof["journal_finished"][0]["authorization_id"] = "mismatched"

                def remove_exact_key(proof: dict[str, object]) -> None:
                    del proof["ancestor"]

                def remove_authorization_key(proof: dict[str, object]) -> None:
                    del proof["journal_authorizations"][0]["members"]

                def remove_finished_key(proof: dict[str, object]) -> None:
                    del proof["journal_finished"][0]["job_terminal"]

                for label, corrupt in (
                    ("missing rich proof key", remove_exact_key),
                    ("missing authorization key", remove_authorization_key),
                    ("missing finished key", remove_finished_key),
                    ("authorization sequence", alter_sequence),
                    ("job/index binding", swap_records),
                    ("authorization member window", swap_authorization_windows),
                    ("job hash", alter_job_hash),
                    ("start cardinality", remove_start),
                    ("finished terminal join", alter_finished_terminal),
                ):
                    corrupted = copy.deepcopy(rich)
                    corrupt(corrupted)
                    with self.subTest(window_corruption=label):
                        with self.assertRaises(fixture.chronology.ChronologyError):
                            fixture.chronology._source5_prepared_ack_window_inputs(
                                corrupted,
                            )

                tamper_paths = {
                    documents["header_pin"]["path"],
                    documents["index_pin"]["path"],
                    documents["header"]["journal"]["pin"]["path"],
                    documents["header"]["phase_ledger"]["pin"]["path"],
                    documents["header"]["pilot"]["pin"]["path"],
                    case["rows"][0]["archive_pins"]["request_pin"]["path"],
                }
                journal_path = documents["header"]["journal"]["pin"]["path"]
                member_digest = rich["journal_authorizations"][0][
                    "members_sha256"].encode("ascii")
                member_digest_marker = b'"members_sha256":"' + member_digest + b'"'

                def replace_journal_event_field(
                    raw: bytes, event: bytes, old: bytes, new: bytes,
                ) -> bytes:
                    event_position = raw.find(event)
                    if event_position < 0:
                        raise AssertionError("journal event marker was not present")
                    line_start = raw.rfind(b"\n", 0, event_position) + 1
                    line_end = raw.find(b"\n", event_position)
                    if line_end < 0:
                        raise AssertionError("journal event is not newline terminated")
                    line = raw[line_start:line_end]
                    changed_line = line.replace(old, new, 1)
                    if changed_line == line:
                        raise AssertionError("journal event field marker was not present")
                    return raw[:line_start] + changed_line + raw[line_end:]

                for target in sorted(tamper_paths):
                    read_before = len(_reads)

                    def tampering_reader(
                        pin: dict[str, str], maximum: int, *,
                        selected_path: str = target,
                    ) -> bytes:
                        raw = reader(pin, maximum)
                        if pin["path"] != selected_path:
                            return raw
                        if selected_path == journal_path:
                            # Change real authorization-member and APP-start fields;
                            # both Source routes must reject the journal's old raw pin.
                            changed = replace_journal_event_field(
                                raw, b'"event":"source5_authorized"',
                                member_digest_marker,
                                b'"members_sha256":"' + b"0" * 64 + b'"',
                            )
                            changed = replace_journal_event_field(
                                changed, b'"event":"source5_app_started"',
                                b'"member_index":0', b'"member_index":1',
                            )
                            return changed
                        return raw + b"\x00"

                    for verifier in (
                        sourcea.verify_source5_prepared_exploration_lineage,
                        sourcea.verify_source5_prepared_exploration_lineage_v2,
                    ):
                        with self.assertRaises(sourcea.PreparedExplorationLineageError):
                            verifier(
                                documents["final_prepared"], lineage_pins,
                                **{**verifier_args, "artifact_reader": tampering_reader},
                            )
                    self.assertTrue(
                        any(path == target for path, _maximum in _reads[read_before:]),
                        f"closed reader did not receive the tampered source pin {target}",
                    )

                def refusing_reader(_pin: dict[str, str], _maximum: int) -> bytes:
                    raise OSError("closed proof reader refused the raw pin")

                for verifier in (
                    sourcea.verify_source5_prepared_exploration_lineage,
                    sourcea.verify_source5_prepared_exploration_lineage_v2,
                ):
                    with self.assertRaises(OSError):
                        verifier(
                            documents["final_prepared"], lineage_pins,
                            **{**verifier_args, "artifact_reader": refusing_reader},
                        )
                    changed_pins = copy.deepcopy(lineage_pins)
                    changed_pins["bridge_header"]["raw_sha256"] = "0" * 64
                    successful_read_count = len(_reads)
                    with self.assertRaises(OSError):
                        verifier(
                            documents["final_prepared"], changed_pins,
                            **verifier_args,
                        )
                    self.assertEqual(len(_reads), successful_read_count)
                    changed_pins = copy.deepcopy(lineage_pins)
                    changed_pins["record_index"]["raw_sha256"] = "0" * 64
                    successful_read_count = len(_reads)
                    with self.assertRaises(sourcea.PreparedExplorationLineageError):
                        verifier(
                            documents["final_prepared"], changed_pins,
                            **verifier_args,
                        )
                    self.assertEqual(
                        _reads[successful_read_count:],
                        [(lineage_pins["bridge_header"]["path"], 256 * 1024)],
                    )

                missing_v2_context = types.SimpleNamespace(
                    manifest={
                        "schema": fixture.controller.EXECUTION_SCHEMA_V5,
                        "hosts": [fixture.host_id],
                    },
                    scope=fixture.controller.PREPARED_EXPLORATION_REUSE_SCOPE,
                    prepared_input_provenance_v2={},
                    lineage_artifact_reader=reader,
                    modules={
                        fixture.controller.SOURCE5_PREPARED_LINEAGE_SOURCE_PATH:
                            sourcea,
                        fixture.controller.SOURCE5_PREPARED_BRIDGE_BUDGET_SOURCE_PATH:
                            fixture.bridge_budget_module,
                    },
                )
                self.assertTrue(callable(
                    sourcea.verify_source5_prepared_exploration_lineage,
                ))
                rich_verifier = sourcea.verify_source5_prepared_exploration_lineage_v2
                delattr(sourcea, "verify_source5_prepared_exploration_lineage_v2")
                try:
                    with self.assertRaisesRegex(
                            fixture.controller.Source5CampaignError,
                            "lacks its structural proof"):
                        fixture.controller._source5_validate_prepared_exploration_context(
                            missing_v2_context,
                        )
                finally:
                    sourcea.verify_source5_prepared_exploration_lineage_v2 = rich_verifier
            finally:
                fixture.close()


class GeneratedH6TwoHostBridgeTests(unittest.TestCase):
    """Synthetic two-host Source closure only; no native authority claim."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls._temporary = tempfile.TemporaryDirectory(
            prefix="source5-generated-two-host-bridge-",
        )
        cls.root = Path(cls._temporary.name)
        cls.fixture = None
        cls.capture_reader = None
        try:
            cls.fixture = producer_support.PreparatoryProducerFixture(
                cls.root, two_kvm_profile=True,
            )
            cls.host_ids = list(cls.fixture.host_order)
            if (len(cls.host_ids) != 2 or
                    [row["host_id"] for row in cls.fixture.spec["hosts"]] != cls.host_ids):
                raise AssertionError("two-host fixture changed its canonical cohort order")
            cls.views = {
                host: cls.fixture.selected_host_view(host)
                for host in cls.host_ids
            }
            cls.artifacts_by_host = {}
            cls.cases_by_host = {}
            cls.setup_by_host = {}
            cls.catalogue_pins_by_host = {}
            cls.producer_pins_by_host = {}
            cls.proofs = {}
            for host in cls.host_ids:
                view = cls.views[host]
                original_pins, setup_details, setup_head = \
                    view.bind_registration_to_sourcea_first_event()
                artifacts = view.build()
                view.validator(artifacts["budget"], artifacts["manifest"])
                case = synthetic_full_replay_case(generated=(
                    view, artifacts, original_pins, setup_details, setup_head,
                ))
                if (len(case["jobs"]) != 360 or len(case["rows"]) != 360 or
                        artifacts["width"]["total_event_count"] != 2161 or
                        len(artifacts["budget"]["read_schedule"]) != 360):
                    raise AssertionError("generated H6 host view lost its exact source schedule")
                cls.artifacts_by_host[host] = artifacts
                cls.cases_by_host[host] = case
                cls.setup_by_host[host] = (original_pins, setup_details, setup_head)
                cls.catalogue_pins_by_host[host] = copy.deepcopy(
                    artifacts["budget"]["path_catalogue"]["chunks"],
                )
                cls.producer_pins_by_host[host] = {
                    "budget": copy.deepcopy(artifacts["budget_pin"]),
                    "width": copy.deepcopy(artifacts["width_pin"]),
                    "execution": copy.deepcopy(view.context.manifest_pin),
                }

            first, second = (cls.views[host] for host in cls.host_ids)
            for view in (first, second):
                if (view.spec_pin != first.spec_pin or view.plan_pin != first.plan_pin or
                        view.spec_raw != first.spec_raw or view.plan_raw != first.plan_raw or
                        tuple(view.fixture.host_ids) != tuple(cls.host_ids)):
                    raise AssertionError("host views do not share the exact initial Spec/Plan cohort")
            if (first.artifact_root == second.artifact_root or
                    first.output_root == second.output_root or
                    first.scratch_root == second.scratch_root or
                    first.evidence_root == second.evidence_root or
                    first.signer_pin["path"] == second.signer_pin["path"]):
                raise AssertionError("host views share a selected-host artifact root/context")
            if (first.context.source_manifest_pins != second.context.source_manifest_pins or
                    first.context.manifest["hosts"] != second.context.manifest["hosts"] or
                    first.context.host_id == second.context.host_id or
                    first.registration is second.registration or
                    first.signer_context["host_id"] != first.host_id or
                    second.signer_context["host_id"] != second.host_id or
                    first.signer_context["keyring_pin"] != second.signer_context["keyring_pin"] or
                    first.signer_context["gpgv_pin"] != second.signer_context["gpgv_pin"]):
                raise AssertionError("selected-host contexts do not preserve their shared cohort")
            for view in (first, second):
                for relative in (
                    "scripts/application-source5-prepared-lineage.py",
                    "scripts/application-source5-prepared-bridge-budget.py",
                    "scripts/application-source5-lineage-capture.py",
                    "scripts/application-source5-evidence-budget.py",
                ):
                    module = view.modules[relative]
                    expected_path = str(view.fixture.root / relative)
                    if (not isinstance(module, types.ModuleType) or
                            module.__file__ != expected_path or
                            sys.modules.get(module.__name__) is not module or
                            type(getattr(module, "__source5_typed_pin__", None)) is not dict):
                        raise AssertionError("two-host Source algorithm is not a typed registered module")
            if first.budget_module.__source5_typed_pin__.get("path") != \
                    "scripts/application-source5-evidence-budget.py":
                raise AssertionError("two-host bridge lacks the selected typed catalogue module")

            generated = [
                (cls.views[host], cls.artifacts_by_host[host], cls.cases_by_host[host])
                for host in cls.host_ids
            ]
            cls.origins, cls.origin_modes = _merge_generated_lineage_origins(generated)
            cls.captured, raw_reader, cls.raw_reads = _capture_and_remove_origins(
                cls.origins, cls.root / "closed-original-capture",
                origin_modes=cls.origin_modes,
            )
            cls.raw_reader = staticmethod(raw_reader)
            if any(Path(path).exists() or Path(path).is_symlink()
                   for path in cls.origins):
                raise AssertionError("a historical payload origin remained available")
            if not all(Path(module.__file__).is_file()
                       for view in cls.views.values()
                       for module in view.modules.values()):
                raise AssertionError("closed origin capture removed a selected typed Source file")

            for host in cls.host_ids:
                view = cls.views[host]
                case = cls.cases_by_host[host]
                documents = case["generated_documents"]
                if type(documents) is not dict:
                    raise AssertionError("generated H6 host view omitted SourceA documents")
                proof = case["lineage_module"].verify_source5_prepared_exploration_lineage_v2(
                    documents["final_prepared"],
                    {"bridge_header": documents["header_pin"],
                     "record_index": documents["index_pin"]},
                    artifact_reader=cls.raw_reader,
                    campaign_module=view.campaign,
                    input_preparation_module=view.input_preparation,
                    campaign_inputs_module=view.inputs_module,
                    chronology_module=view.chronology,
                    source5_campaign_module=view.controller,
                    preparatory_budget_module=view.prep_module,
                )
                cls.proofs[host] = proof

            cls.bridge_reads = []

            def bridge_reader(pin: dict[str, str], maximum_bytes: int) -> bytes:
                cls.bridge_reads.append((pin["path"], maximum_bytes))
                return cls.raw_reader(pin, maximum_bytes)

            cls.old_rows_by_host = {}
            for host in cls.host_ids:
                view = cls.views[host]
                catalogue = cls.artifacts_by_host[host]["budget"]["path_catalogue"]
                chunks = {row["path"]: row for row in catalogue["chunks"]}

                def read_chunk(path: str, maximum_bytes: int,
                               _chunks=chunks) -> bytes:
                    chunk = _chunks.get(path)
                    if type(chunk) is not dict or maximum_bytes != chunk["byte_count"]:
                        raise AssertionError("fixture catalogue requested an undeclared chunk")
                    return cls.raw_reader(
                        {"path": path, "raw_sha256": chunk["raw_sha256"]},
                        maximum_bytes,
                    )

                rows = view.budget_module.iter_fixed_pair_v3_path_catalogue_rows_with_reader(
                    catalogue, read_chunk,
                )
                cls.old_rows_by_host[host] = {
                    row["path"]: row for row in rows
                    if row["kind"] == "file"
                }

            cls.expected_jobs = {
                host: [row for row in first.plan["jobs"]["exploration"]
                       if row["host_id"] == host]
                for host in cls.host_ids
            }
            cls.bridge_module = first.bridge_budget_module
            cls.capture_module = first.lineage_capture_module
            cls.declaration, cls.storage_rows = \
                cls.bridge_module.build_prepared_exploration_capture_storage_v1(
                    cls.host_ids, cls.proofs,
                    expected_ancestors={
                        host: cls.proofs[host]["ancestor"] for host in cls.host_ids
                    },
                    expected_exploration_jobs=cls.expected_jobs,
                    artifact_reader=bridge_reader,
                    evidence_budget_module=first.budget_module,
                )
            cls.capture_root = cls.root / "production-capture"
            cls.capture_manifest, cls.capture_reader = _materialize_production_capture(
                cls.declaration, cls.raw_reader, cls.capture_module,
                cls.capture_root,
            )
            cls.production_proofs = {}
            for host in cls.host_ids:
                view = cls.views[host]
                documents = cls.cases_by_host[host]["generated_documents"]
                cls.production_proofs[host] = \
                    cls.cases_by_host[host]["lineage_module"].verify_source5_prepared_exploration_lineage_v2(
                        documents["final_prepared"],
                        {"bridge_header": documents["header_pin"],
                         "record_index": documents["index_pin"]},
                        artifact_reader=cls.capture_reader,
                        campaign_module=view.campaign,
                        input_preparation_module=view.input_preparation,
                        campaign_inputs_module=view.inputs_module,
                        chronology_module=view.chronology,
                        source5_campaign_module=view.controller,
                        preparatory_budget_module=view.prep_module,
                    )
            cls.rebuilt_declaration, cls.rebuilt_storage_rows = \
                cls.bridge_module.build_prepared_exploration_capture_storage_v1(
                    cls.host_ids, cls.production_proofs,
                    expected_ancestors={
                        host: cls.production_proofs[host]["ancestor"]
                        for host in cls.host_ids
                    },
                    expected_exploration_jobs=cls.expected_jobs,
                    artifact_reader=cls.capture_reader,
                    evidence_budget_module=first.budget_module,
                )
        except BaseException:
            if cls.capture_reader is not None:
                cls.capture_reader.close()
            if cls.fixture is not None:
                cls.fixture.close()
            cls._temporary.cleanup()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            if cls.capture_reader is not None:
                cls.capture_reader.close()
            if cls.fixture is not None:
                cls.fixture.close()
        finally:
            cls._temporary.cleanup()
            super().tearDownClass()

    def _indexed_binding(self, host: str, row_index: int, role: str):
        index_row = self.proofs[host]["index_rows"][row_index]
        if role == "source5_job_record":
            pin_value = index_row["job_record_pin"]
        else:
            archive_key = {
                "source5_checkpoint_request": "request_pin",
                "source5_checkpoint": "checkpoint_pin",
                "source5_object_manifest": "object_manifest_pin",
                "source5_archive_ack": "ack_pin",
                "source5_archive_signature": "signature_pin",
            }[role]
            pin_value = index_row["archive_pins"][archive_key]
        return index_row, pin_value, index_row["job"]

    def _initial_output_root(self, host: str) -> str:
        return self.cases_by_host[host]["generated_documents"]["header"][
            "initial_output_root"]

    def test_generated_two_host_bridge_replays_from_production_capture(self) -> None:
        self.assertEqual(self.declaration["cohort_host_ids"], self.host_ids)
        indexed = [row for row in self.declaration["objects"]
                   if row["phase"] == "exploration"]
        self.assertEqual(len(indexed), 4320)
        expected_roles = {
            "source5_job_record", "source5_checkpoint_request",
            "source5_checkpoint", "source5_object_manifest",
            "source5_archive_ack", "source5_archive_signature",
        }
        for host in self.host_ids:
            host_rows = [row for row in indexed if row["host_id"] == host]
            self.assertEqual(len(host_rows), 2160)
            by_job = {}
            for row in host_rows:
                key = (row["host_id"], row["row_index"])
                by_job.setdefault(key, set()).add(row["role"])
                job = self.expected_jobs[host][row["row_index"]]
                self.assertEqual(row["run_id"], job["run_id"])
                self.assertEqual(row["job_sha256"],
                                 hashlib.sha256(self.views[host].chronology.canonical_bytes(job)).hexdigest())
            self.assertEqual(set(by_job), {
                (host, row_index) for row_index in range(360)
            })
            self.assertTrue(all(roles == expected_roles for roles in by_job.values()))

        for host in self.host_ids:
            artifacts = self.artifacts_by_host[host]
            documents = self.cases_by_host[host]["generated_documents"]
            original_pins, _setup, _head = self.setup_by_host[host]
            self.assertEqual(
                artifacts["budget"]["path_catalogue"]["chunks"],
                self.catalogue_pins_by_host[host],
            )
            self.assertEqual(artifacts["budget_pin"],
                             self.producer_pins_by_host[host]["budget"])
            self.assertEqual(artifacts["width_pin"],
                             self.producer_pins_by_host[host]["width"])
            self.assertEqual(artifacts["budget"],
                             self.proofs[host]["capture_context"]["budget"])
            self.assertEqual(artifacts["width"],
                             self.proofs[host]["capture_context"]["width_contract"])
            self.assertEqual(artifacts["manifest"],
                             self.proofs[host]["capture_context"]["execution_manifest"])
            self.assertEqual(
                self.producer_pins_by_host[host]["execution"],
                {key: documents["header"]["initial"]["execution_manifest_pin"][key]
                 for key in ("path", "raw_sha256")},
            )
            self.assertEqual(
                artifacts["budget"]["original_pins"],
                self.proofs[host]["capture_context"]["preparatory_original_pins"],
            )
            case = self.cases_by_host[host]
            self.assertEqual(original_pins, case["original_context"]["original_pins"])
            first_event = json.loads(case["journal_raw"].splitlines()[0])
            self.assertEqual(first_event["record"]["original_pins"], original_pins)
            for proof in (self.proofs[host], self.production_proofs[host]):
                self.assertEqual(proof["job_count"], 360)
                self.assertEqual(proof["callback_count"], 2160)
                self.assertEqual(proof["initial_journal_record_count"], 2161)
                self.assertEqual(proof["initial_phase_ledger_row_count"], 360)
                self.assertEqual(len(proof["index_rows"]), 360)
                self.assertTrue(proof["allowed_slot_fill_proved"])
                self.assertTrue(proof["component_replay_required"])
                self.assertTrue(proof["fresh_sourcea_gpg_replay_required"])
                self.assertFalse(proof["qualification_eligible"])

        self.assertEqual(self.declaration, self.rebuilt_declaration)
        self.assertEqual(self.storage_rows, self.rebuilt_storage_rows)
        self.assertEqual(len(self.storage_rows), len(self.declaration["objects"]))
        sourceh_original = self.proofs[self.host_ids[0]]["capture_context"][
            "preparatory_original_pins"]
        shared_inputs = (
            (sourceh_original["preparation"], "preparation"),
            (sourceh_original["capacity_generation"], "capacity_completion"),
        )
        for pin, role in shared_inputs:
            matches = [row for row in self.declaration["objects"]
                       if row["origin_pin"]["path"] == pin["path"] and
                       row["origin_pin"]["raw_sha256"] == pin["raw_sha256"]]
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0]["role"], role)
            self.assertIsNone(matches[0]["host_id"])
            self.assertIsNone(matches[0]["phase"])
        storage_by_pin = {
            (row["path"], row["origin_pin"]["raw_sha256"]): row
            for row in self.storage_rows
        }
        for descriptor in indexed:
            key = (descriptor["origin_pin"]["path"],
                   descriptor["origin_pin"]["raw_sha256"])
            storage = storage_by_pin[key]
            self.assertEqual(storage["role"], descriptor["role"])
            self.assertEqual(storage["host_id"], descriptor["host_id"])
            self.assertEqual(storage["max_bytes"], descriptor["byte_count"])
            self.assertEqual(storage["max_file_bytes"], descriptor["byte_count"])
            self.assertEqual(storage["origin_pin"]["raw_sha256"], key[1])
            if descriptor["role"] in {
                    "source5_archive_ack", "source5_archive_signature"}:
                self.assertEqual(storage["path"], descriptor["origin_pin"]["path"])
        self.capture_reader.storage_usage()

    def test_indexed_alias_rejects_crossed_leaf_host_or_role(self) -> None:
        host, other_host = self.host_ids
        bridge = self.bridge_module
        row, pin, job = self._indexed_binding(host, 0, "source5_archive_ack")
        view = self.views[host]
        args = {
            "initial_output_root": self._initial_output_root(host),
            "campaign_id": view.spec["campaign_id"],
            "selected_host": host,
            "old_rows": self.old_rows_by_host[host],
            "evidence_budget_module": view.budget_module,
        }
        leaf = f"{job['ordinal']:06d}-{row['job_sha256']}"

        wrong_leaf = copy.deepcopy(row)
        wrong_leaf["archive_pins"]["ack_pin"]["path"] = \
            wrong_leaf["archive_pins"]["ack_pin"]["path"].replace(
                f"{leaf}.json", f"{leaf}.wrong.json",
            )
        with self.assertRaises(bridge.PreparedBridgeBudgetError):
            bridge._source5_indexed_reservation_binding(
                wrong_leaf, wrong_leaf["archive_pins"]["ack_pin"],
                "source5_archive_ack", job, **args,
            )

        wrong_root = copy.deepcopy(row)
        wrong_root["archive_pins"]["signature_pin"]["path"] = str(
            self.views[other_host].evidence_root / "archive-root" / "acks" /
            "signatures" / "exploration" / f"{leaf}.sig",
        )
        with self.assertRaises(bridge.PreparedBridgeBudgetError):
            bridge._source5_indexed_reservation_binding(
                wrong_root, wrong_root["archive_pins"]["ack_pin"],
                "source5_archive_ack", job, **args,
            )

        request_row, request_pin, request_job = self._indexed_binding(
            host, 0, "source5_checkpoint_request",
        )
        crossed_host = copy.deepcopy(request_job)
        crossed_host["host_id"] = other_host
        with self.assertRaises(bridge.PreparedBridgeBudgetError):
            bridge._source5_indexed_reservation_binding(
                request_row, request_pin, "source5_checkpoint_request",
                crossed_host,
                initial_output_root=self._initial_output_root(host),
                campaign_id=view.spec["campaign_id"], selected_host=host,
                old_rows=self.old_rows_by_host[host],
                evidence_budget_module=view.budget_module,
            )
        crossed_run = copy.deepcopy(request_job)
        crossed_run["run_id"] = self.expected_jobs[other_host][0]["run_id"]
        with self.assertRaises(bridge.PreparedBridgeBudgetError):
            bridge._source5_indexed_reservation_binding(
                request_row, request_pin, "source5_checkpoint_request",
                crossed_run,
                initial_output_root=self._initial_output_root(host),
                campaign_id=view.spec["campaign_id"], selected_host=host,
                old_rows=self.old_rows_by_host[host],
                evidence_budget_module=view.budget_module,
            )

        metadata = (PurePosixPath(request_pin["path"]).parent)
        ack_like = {**request_pin, "path": str(metadata / f"{leaf}.ack.json")}
        with self.assertRaises(bridge.PreparedBridgeBudgetError):
            bridge._source5_indexed_reservation_binding(
                request_row, ack_like, "source5_checkpoint_request",
                request_job,
                initial_output_root=self._initial_output_root(host),
                campaign_id=view.spec["campaign_id"], selected_host=host,
                old_rows=self.old_rows_by_host[host],
                evidence_budget_module=view.budget_module,
            )

    def test_indexed_binding_retains_pinned_origin_and_old_cap(self) -> None:
        host = self.host_ids[0]
        role = "source5_checkpoint_request"
        index_row, pin_value, job = self._indexed_binding(host, 0, role)
        original_root = self.cases_by_host[host]["generated_documents"][
            "header"]["initial_output_root"]
        kwargs = {
            "initial_output_root": original_root,
            "campaign_id": self.views[host].spec["campaign_id"],
            "selected_host": host,
            "evidence_budget_module": self.views[host].budget_module,
        }
        row_map = self.old_rows_by_host[host]
        pin, reservation = self.bridge_module._source5_indexed_reservation_binding(
            index_row, pin_value, role, job, old_rows=row_map, **kwargs,
        )
        mismatch_rows = dict(row_map)
        mismatched = copy.deepcopy(reservation)
        mismatched["origin_pin"] = {
            "raw_sha256": "0" * 64, "semantic_sha256": None,
        }
        mismatch_rows[reservation["path"]] = mismatched
        budget_module = self.views[host].budget_module
        with self.assertRaises(budget_module.BudgetPlanError):
            budget_module.source5_indexed_reservation_binding_v1(
                index_row, pin_value, role, job,
                old_rows=mismatch_rows, **{
                    key: value for key, value in kwargs.items()
                    if key != "evidence_budget_module"
                },
            )
        with self.assertRaises(self.bridge_module.PreparedBridgeBudgetError):
            self.bridge_module._source5_indexed_reservation_binding(
                index_row, pin_value, role, job,
                old_rows=mismatch_rows, **kwargs,
            )

        wrong_semantic_rows = dict(row_map)
        wrong_semantic = copy.deepcopy(reservation)
        bad_semantic = ("0" * 64 if pin_value["semantic_sha256"] != "0" * 64
                        else "f" * 64)
        wrong_semantic["origin_pin"] = {
            "raw_sha256": pin_value["raw_sha256"],
            "semantic_sha256": bad_semantic,
        }
        wrong_semantic_rows[reservation["path"]] = wrong_semantic
        with self.assertRaises(budget_module.BudgetPlanError):
            budget_module.source5_indexed_reservation_binding_v1(
                index_row, pin_value, role, job,
                old_rows=wrong_semantic_rows, **{
                    key: value for key, value in kwargs.items()
                    if key != "evidence_budget_module"
                },
            )
        with self.assertRaises(self.bridge_module.PreparedBridgeBudgetError):
            self.bridge_module._source5_indexed_reservation_binding(
                index_row, pin_value, role, job,
                old_rows=wrong_semantic_rows, **kwargs,
            )

        missing_rows = dict(row_map)
        missing_rows.pop(reservation["path"])
        with self.assertRaises(budget_module.BudgetPlanError):
            budget_module.source5_indexed_reservation_binding_v1(
                index_row, pin_value, role, job,
                old_rows=missing_rows, **{
                    key: value for key, value in kwargs.items()
                    if key != "evidence_budget_module"
                },
            )

        descriptor = next(row for row in self.declaration["objects"]
                          if row["host_id"] == host and row["row_index"] == 0 and
                          row["role"] == role)
        actual_count = descriptor["byte_count"]
        self.assertGreater(actual_count, 1)
        low_rows = dict(row_map)
        low_cap_row = copy.deepcopy(reservation)
        low_cap_row["max_file_bytes"] = actual_count - 1
        low_rows[reservation["path"]] = low_cap_row
        low_pin, low_reservation = \
            self.bridge_module._source5_indexed_reservation_binding(
                index_row, pin_value, role, job,
                old_rows=low_rows, **kwargs,
            )
        with self.assertRaises(OSError):
            self.raw_reader(low_pin, low_reservation["max_file_bytes"])

        by_path = {}
        for path, maximum in self.bridge_reads:
            by_path.setdefault(path, []).append(maximum)
        old_paths_by_host = {host: set() for host in self.host_ids}
        for descriptor in (row for row in self.declaration["objects"]
                           if row["phase"] == "exploration"):
            row_index = descriptor["row_index"]
            index_row = self.proofs[descriptor["host_id"]]["index_rows"][row_index]
            role = descriptor["role"]
            if role == "source5_job_record":
                pin_value = index_row["job_record_pin"]
            else:
                archive_key = {
                    "source5_checkpoint_request": "request_pin",
                    "source5_checkpoint": "checkpoint_pin",
                    "source5_object_manifest": "object_manifest_pin",
                    "source5_archive_ack": "ack_pin",
                    "source5_archive_signature": "signature_pin",
                }[role]
                pin_value = index_row["archive_pins"][archive_key]
            pin, selected_row = \
                self.bridge_module._source5_indexed_reservation_binding(
                    index_row, pin_value, role, index_row["job"],
                    initial_output_root=self.cases_by_host[descriptor["host_id"]][
                        "generated_documents"]["header"]["initial_output_root"],
                    campaign_id=self.views[descriptor["host_id"]].spec["campaign_id"],
                    selected_host=descriptor["host_id"],
                    old_rows=self.old_rows_by_host[descriptor["host_id"]],
                    evidence_budget_module=self.views[
                        descriptor["host_id"]].budget_module,
                )
            budget_module = self.views[descriptor["host_id"]].budget_module
            budget_pin, budget_row = budget_module.source5_indexed_reservation_binding_v1(
                index_row, pin_value, role, index_row["job"],
                initial_output_root=self.cases_by_host[descriptor["host_id"]][
                    "generated_documents"]["header"]["initial_output_root"],
                campaign_id=self.views[descriptor["host_id"]].spec["campaign_id"],
                selected_host=descriptor["host_id"],
                old_rows=self.old_rows_by_host[descriptor["host_id"]],
            )
            self.assertEqual(descriptor["maximum_bytes"],
                             selected_row["max_file_bytes"])
            self.assertEqual(budget_pin, pin)
            self.assertEqual(budget_row, selected_row)
            old_paths_by_host[descriptor["host_id"]].add(budget_row["path"])
            self.assertEqual(by_path.get(pin["path"]),
                             [selected_row["max_file_bytes"]] * 2)
            if role in {"source5_archive_ack", "source5_archive_signature"}:
                self.assertNotIn(selected_row["path"], by_path)

        for host in self.host_ids:
            expected_rows = {
                descriptor["origin_pin"]["path"]: {
                    "raw_sha256": descriptor["origin_pin"]["raw_sha256"],
                    "byte_count": descriptor["byte_count"],
                    "role": descriptor["role"], "host_id": host,
                    "phase": "exploration", "run_id": descriptor["run_id"],
                    "catalogue_hosts": {host},
                }
                for descriptor in self.declaration["objects"]
                if descriptor["host_id"] == host and
                descriptor["phase"] == "exploration"
            }
            budget_module = self.views[host].budget_module
            old_needed = budget_module._source5_prepared_lineage_indexed_rows_v4(
                expected_rows, self.proofs[host]["index_rows"],
                self.old_rows_by_host[host],
                initial_output_root=self.cases_by_host[host][
                    "generated_documents"]["header"]["initial_output_root"],
                campaign_id=self.views[host].spec["campaign_id"],
                selected_host=host,
            )
            self.assertEqual(set(old_needed), old_paths_by_host[host])
            self.assertEqual(len(old_needed), 2160)
            for path, expected in old_needed.items():
                row = self.old_rows_by_host[host][path]
                self.assertEqual(row["role"], expected["role"])
                self.assertEqual(row["host_id"], host)
                self.assertEqual(row["phase"], "exploration")
                self.assertEqual(row["run_id"], expected["run_id"])
                self.assertGreaterEqual(
                    row["max_file_bytes"], expected["byte_count"],
                )

            request_descriptor = next(
                descriptor for descriptor in self.declaration["objects"]
                if descriptor["host_id"] == host and
                descriptor["role"] == "source5_checkpoint_request" and
                descriptor["phase"] == "exploration"
            )
            self.assertGreater(request_descriptor["byte_count"], 1)
            request_index = self.proofs[host]["index_rows"][
                request_descriptor["row_index"]]
            request_reservation = budget_module.source5_indexed_reservation_binding_v1(
                request_index, request_index["archive_pins"]["request_pin"],
                "source5_checkpoint_request", request_index["job"],
                initial_output_root=self.cases_by_host[host][
                    "generated_documents"]["header"]["initial_output_root"],
                campaign_id=self.views[host].spec["campaign_id"],
                selected_host=host, old_rows=self.old_rows_by_host[host],
            )[1]
            low_cap_rows = dict(self.old_rows_by_host[host])
            low_cap_row = copy.deepcopy(request_reservation)
            low_cap_row["max_file_bytes"] = request_descriptor["byte_count"] - 1
            low_cap_rows[request_reservation["path"]] = low_cap_row
            with self.assertRaises(budget_module.BudgetPlanError):
                budget_module._source5_prepared_lineage_indexed_rows_v4(
                    expected_rows, self.proofs[host]["index_rows"], low_cap_rows,
                    initial_output_root=self.cases_by_host[host][
                        "generated_documents"]["header"]["initial_output_root"],
                    campaign_id=self.views[host].spec["campaign_id"],
                    selected_host=host,
                )

    def test_shared_cohort_mismatch_is_rejected(self) -> None:
        cohort_inputs = [
            {
                "host_id": host,
                "original_pins": self.proofs[host]["capture_context"][
                    "preparatory_original_pins"],
                "execution_manifest": self.proofs[host]["capture_context"][
                    "execution_manifest"],
                "header": self.proofs[host]["bridge_header"],
            }
            for host in self.host_ids
        ]
        budget_module = self.views[self.host_ids[0]].budget_module
        shared = budget_module.source5_preparatory_shared_originals_v1(
            cohort_inputs,
        )
        first_original = cohort_inputs[0]["original_pins"]
        self.assertEqual(shared["preparation"], first_original["preparation"])
        self.assertEqual(
            shared["capacity_generation"]["provenance"],
            first_original["capacity_generation"]["provenance"],
        )

        changed_peer_preparation = copy.deepcopy(cohort_inputs)
        peer = changed_peer_preparation[1]
        peer["original_pins"]["preparation"]["raw_sha256"] = "0" * 64
        peer["original_pins"]["capacity_generation"]["provenance"][
            "preparation_pin"]["raw_sha256"] = "0" * 64
        peer["execution_manifest"]["preparatory_capacity_generation"][
            "provenance"]["preparation_pin"]["raw_sha256"] = "0" * 64
        with self.assertRaisesRegex(
                budget_module.BudgetPlanError,
                "shared SourceH preparation/generation pins differ across the cohort",
        ):
            budget_module.source5_preparatory_shared_originals_v1(
                changed_peer_preparation,
            )

        changed_peer_plan = copy.deepcopy(cohort_inputs)
        peer = changed_peer_plan[1]
        peer["original_pins"]["capacity_generation"]["provenance"][
            "initial_plan_pin"]["raw_sha256"] = "0" * 64
        peer["execution_manifest"]["preparatory_capacity_generation"][
            "provenance"]["initial_plan_pin"]["raw_sha256"] = "0" * 64
        with self.assertRaisesRegex(
                budget_module.BudgetPlanError,
                "generation initial_plan_pin differs",
        ):
            budget_module.source5_preparatory_shared_originals_v1(
                changed_peer_plan,
            )

        with self.assertRaises(self.bridge_module.PreparedBridgeBudgetError):
            self.bridge_module.build_prepared_exploration_capture_declaration_v1(
                list(reversed(self.host_ids)), self.proofs,
                artifact_reader=self.raw_reader,
                evidence_budget_module=self.views[self.host_ids[0]].budget_module,
            )

        changed = copy.deepcopy(self.proofs)
        first_host = self.host_ids[0]
        changed[first_host]["bridge_header"]["initial"][
            "source_manifest_pins"][0]["raw_sha256"] = "0" * 64
        with self.assertRaises(self.bridge_module.PreparedBridgeBudgetError):
            self.bridge_module.build_prepared_exploration_capture_declaration_v1(
                self.host_ids, changed, artifact_reader=self.raw_reader,
                evidence_budget_module=self.views[first_host].budget_module,
            )

        changed_shared = copy.deepcopy(self.proofs)
        peer_host = self.host_ids[1]
        peer_context = changed_shared[peer_host]["capture_context"]
        peer_budget = peer_context["budget"]
        peer_original = peer_context["preparatory_original_pins"]
        peer_original["preparation"]["raw_sha256"] = "0" * 64
        peer_original["capacity_generation"]["provenance"][
            "preparation_pin"]["raw_sha256"] = "0" * 64
        peer_context["execution_manifest"]["preparatory_capacity_generation"][
            "provenance"]["preparation_pin"]["raw_sha256"] = "0" * 64
        peer_budget["original_pins"] = copy.deepcopy(peer_original)
        peer_budget["budget_sha256"] = self.bridge_module._sha(
            self.bridge_module._canonical({
                key: value for key, value in peer_budget.items()
                if key != "budget_sha256"
            }),
        )
        with self.assertRaisesRegex(
                self.bridge_module.PreparedBridgeBudgetError,
                "shared SourceH preparation/generation pins differ across the cohort",
        ):
            self.bridge_module.build_prepared_exploration_capture_declaration_v1(
                self.host_ids, changed_shared, artifact_reader=self.raw_reader,
                evidence_budget_module=self.views[first_host].budget_module,
            )

    def _retained_storage_context(self, proofs):
        selected = self.views[self.host_ids[0]].context
        return types.SimpleNamespace(
            manifest=selected.manifest,
            prepared_exploration_proofs=proofs,
            prepared_capture_declaration=self.rebuilt_declaration,
            prepared_capture_storage_rows=self.rebuilt_storage_rows,
            lineage_artifact_reader=self.capture_reader,
            modules={
                source5_campaign.SOURCE5_PREPARED_BRIDGE_BUDGET_SOURCE_PATH:
                    self.bridge_module,
            },
        )

    def test_retained_storage_rows_are_exact_source_bridge_rows_after_origin_removal(self) -> None:
        """Exercise the projection helper on fresh proofs and a closed capture only."""
        context = self._retained_storage_context(self.production_proofs)
        retained, retained_by_path, _hostless_roles = \
            source5_campaign._source5_prepared_capture_storage_rows(
                context, self.views[self.host_ids[0]].budget_module,
            )
        self.assertEqual(retained, self.rebuilt_storage_rows)
        self.assertEqual(
            retained_by_path,
            {row["path"]: row for row in self.rebuilt_storage_rows},
        )
        self.assertEqual(len(retained), len(self.rebuilt_declaration["objects"]))
        self.assertTrue(all(
            not Path(origin).exists() and not Path(origin).is_symlink()
            for origin in self.origins
        ))

    def test_retained_storage_projection_rejects_crossed_shared_raw_pin(self) -> None:
        changed = copy.deepcopy(self.production_proofs)
        peer = self.host_ids[1]
        changed[peer]["capture_context"]["preparatory_original_pins"][
            "preparation"]["raw_sha256"] = "0" * 64
        context = self._retained_storage_context(changed)
        with self.assertRaisesRegex(
                source5_campaign.Source5CampaignError,
                "common preparation/Spec/Plan raw pins differ across proofs",
        ):
            source5_campaign._source5_prepared_capture_storage_rows(
                context, self.views[self.host_ids[0]].budget_module,
            )

    def test_retained_storage_projection_keeps_execution_pin_exactly_full(self) -> None:
        """Keep the original full execution pin exact before raw projection."""
        host = self.host_ids[0]
        for mutation in ("extra-field", "crossed-raw"):
            changed = copy.deepcopy(self.production_proofs)
            pin = changed[host]["bridge_header"]["initial"][
                "execution_manifest_pin"]
            if mutation == "extra-field":
                pin["unexpected"] = True
            else:
                pin["raw_sha256"] = (
                    "0" * 64 if pin["raw_sha256"] != "0" * 64 else "1" * 64
                )
            context = self._retained_storage_context(changed)
            with self.subTest(mutation=mutation), self.assertRaises(
                    source5_campaign.Source5CampaignError):
                source5_campaign._source5_prepared_capture_storage_rows(
                    context, self.views[host].budget_module,
                )

    def test_retained_current_inputs_join_source_and_signer_rows_without_origin_reads(self) -> None:
        """Exercise the producer's current-input resolver on closed real capture data."""
        host, peer_host = self.host_ids
        view = self.views[host]
        context = self._retained_storage_context(self.production_proofs)
        retained, retained_by_path, hostless_roles = \
            source5_campaign._source5_prepared_capture_storage_rows(
                context, view.budget_module,
            )
        current_input_pins = {}
        retained_keys = {
            (row["path"], row["origin_pin"]["raw_sha256"])
            for row in retained
        }
        first_source_pin = view.context.source_manifest_pins[host]
        with self.assertRaisesRegex(
                source5_campaign.Source5CampaignError,
                "precedes its exact Bridge row",
        ):
            source5_campaign._source5_captured_current_input_row(
                context, retained_by_path, hostless_roles, current_input_pins,
                set(), first_source_pin, "source_manifest",
                16 * 1024 * 1024, "test input before retained row",
                semantic_sha256=view.context.sources[host]["manifest_sha256"],
                host=host,
            )
        emitted_retained_keys = source5_campaign._source5_emit_retained_storage_rows(
            retained, retained_keys, lambda _row: None, lambda *_args: None,
        )

        def remember(pin_value, role, current_host, maximum, semantic, label,
                     *, expected_raw=None):
            source5_campaign._source5_register_current_input_pin(
                current_input_pins, pin_value, role, current_host, maximum,
                semantic, label, expected_raw=expected_raw,
            )

        for source_host, source_doc in view.context.sources.items():
            pin = view.context.source_manifest_pins[source_host]
            source_raw = source5_campaign.canonical_bytes(source_doc)
            semantic = source_doc["manifest_sha256"]
            remember(
                pin, "source_manifest", source_host, 16 * 1024 * 1024,
                semantic, f"test current {source_host} Source manifest",
                expected_raw=source_raw,
            )
            matched = source5_campaign._source5_captured_current_input_row(
                context, retained_by_path, hostless_roles, current_input_pins,
                emitted_retained_keys, pin, "source_manifest", 16 * 1024 * 1024,
                f"test current {source_host} Source manifest",
                semantic_sha256=semantic, host=source_host,
            )
            self.assertEqual(matched["row"], retained_by_path[pin["path"]])
            self.assertEqual(matched["captured_raw"], source_raw)
            self.assertIsNone(matched["row"]["origin_pin"]["semantic_sha256"])
            self.assertEqual(matched["row"]["owner"], "inputs")

        source_pin = view.context.source_manifest_pins[host]
        source_doc = view.context.sources[host]
        source_row = retained_by_path[source_pin["path"]]
        wrong_raw = ("0" * 64 if source_pin["raw_sha256"] != "0" * 64
                     else "1" * 64)
        with self.assertRaises(source5_campaign.Source5CampaignError):
            source5_campaign._source5_captured_current_input_row(
                context, retained_by_path, hostless_roles, current_input_pins,
                emitted_retained_keys,
                {"path": source_pin["path"], "raw_sha256": wrong_raw},
                "source_manifest", 16 * 1024 * 1024,
                "test crossed Source raw identity",
                semantic_sha256=source_doc["manifest_sha256"], host=host,
            )
        for wrong_role, wrong_host, wrong_maximum, wrong_semantic in (
            ("capacity_completion", host, 16 * 1024 * 1024,
             source_doc["manifest_sha256"]),
            ("source_manifest", peer_host, 16 * 1024 * 1024,
             source_doc["manifest_sha256"]),
            ("source_manifest", host, source_row["max_file_bytes"] - 1,
             source_doc["manifest_sha256"]),
            ("source_manifest", host, 16 * 1024 * 1024,
             "a" * 64 if source_doc["manifest_sha256"] != "a" * 64 else "b" * 64),
        ):
            with self.subTest(role=wrong_role, host=wrong_host,
                              maximum=wrong_maximum, semantic=wrong_semantic), \
                    self.assertRaises(source5_campaign.Source5CampaignError):
                source5_campaign._source5_captured_current_input_row(
                    context, retained_by_path, hostless_roles,
                    current_input_pins, emitted_retained_keys,
                    source_pin, wrong_role,
                    wrong_maximum, "test crossed current Source join",
                    semantic_sha256=wrong_semantic, host=wrong_host,
                )

        source5_campaign._source5_register_current_signer_tool_pins(
            view.context, remember,
        )
        for name, role, maximum in (
            ("keyring_pin", "source5_archive_signer_keyring",
             source5_campaign.MAX_ARCHIVE_KEYRING_BYTES),
            ("gpgv_pin", "source5_archive_signer_gpgv",
             source5_campaign.MAX_ARCHIVE_GPGV_BYTES),
        ):
            pin = view.context.archive_signer_context[name]
            matched = source5_campaign._source5_captured_current_input_row(
                context, retained_by_path, hostless_roles, current_input_pins,
                emitted_retained_keys, pin, role, maximum,
                f"test current signer {name}", host=host,
            )
            self.assertEqual(matched["row"], retained_by_path[pin["path"]])
            self.assertIsNone(matched["row"]["host_id"])
            self.assertEqual(matched["row"]["role"], role)
            self.assertEqual(matched["row"]["owner"], "inputs")
            self.assertIsNone(matched["row"]["origin_pin"]["semantic_sha256"])
            self.assertEqual(
                matched["captured_raw"],
                self.capture_reader(pin, maximum),
            )
            with self.assertRaises(source5_campaign.Source5CampaignError):
                source5_campaign._source5_captured_current_input_row(
                    context, retained_by_path, {}, current_input_pins,
                    emitted_retained_keys, pin, role, maximum,
                    f"test unproven hostless {name}",
                    host=host,
                )

        with self.assertRaises(source5_campaign.Source5CampaignError):
            source5_campaign._source5_validate_retained_file_alias(
                source_row, path=Path(source_row["path"]),
                role=source_row["role"], owner="fixed_pair",
                host_id=source_row["host_id"], phase=source_row["phase"],
                run_id=source_row["run_id"],
                maximum=source_row["max_file_bytes"],
                exact_size=source_row["max_file_bytes"],
                raw_sha256=source_row["origin_pin"]["raw_sha256"],
            )
        self.assertTrue(all(
            not Path(origin).exists() and not Path(origin).is_symlink()
            for origin in self.origins
        ))
        self.assertEqual(len(retained), len(self.rebuilt_storage_rows))

    def test_retained_rows_use_bounded_producer_spool_and_close_on_failure(self) -> None:
        """Exercise retained emission/streaming helpers, not a full V5 catalogue."""
        context = self._retained_storage_context(self.production_proofs)
        retained, _retained_by_path, _hostless_roles = \
            source5_campaign._source5_prepared_capture_storage_rows(
                context, self.views[self.host_ids[0]].budget_module,
            )
        budget_module = self.views[self.host_ids[0]].budget_module
        encoded_size = sum(
            len(source5_campaign.canonical_bytes(row)) for row in retained
        )
        self.assertGreater(encoded_size, 0)
        spool = tempfile.TemporaryFile(mode="w+b", dir=self.root)
        retained_keys = {
            (row["path"], row["origin_pin"]["raw_sha256"])
            for row in retained
        }
        emitted = source5_campaign._source5_emit_retained_storage_rows(
            retained, retained_keys,
            lambda row: source5_campaign._source5_append_catalogue_spool_record(
                spool, row, encoded_size * 3,
            ),
            lambda *_args: None,
        )
        self.assertEqual(emitted, retained_keys)
        self.assertEqual(len(emitted), len(retained))
        run_count = max(
            1, (len(retained) + budget_module.PATH_CATALOGUE_RUN_ROWS - 1) //
            budget_module.PATH_CATALOGUE_RUN_ROWS,
        )
        merge_overlap = (
            (run_count + budget_module.PATH_CATALOGUE_MERGE_FANOUT - 1) //
            budget_module.PATH_CATALOGUE_MERGE_FANOUT
            if run_count > budget_module.PATH_CATALOGUE_MERGE_FANOUT else 0
        )
        scratch = {
            "reserved_bytes": encoded_size * 3,
            "reserved_inodes": 2 + run_count + merge_overlap,
        }
        stream = source5_campaign._source5_catalogue_record_stream(
            spool, len(retained), {}, scratch, budget_module,
        )
        self.assertEqual(list(stream), retained)
        self.assertTrue(spool.closed)

        capped_spool = tempfile.TemporaryFile(mode="w+b", dir=self.root)
        with self.assertRaisesRegex(
                source5_campaign.Source5CampaignError,
                "producer path spool exceeded",
        ):
            source5_campaign._source5_emit_retained_storage_rows(
                retained, retained_keys,
                lambda row: source5_campaign._source5_append_catalogue_spool_record(
                    capped_spool, row, encoded_size - 1,
                ),
                lambda *_args: None,
            )
        self.assertLessEqual(capped_spool.tell(), encoded_size - 1)
        capped_spool.close()

        under_reserved_spool = tempfile.TemporaryFile(mode="w+b", dir=self.root)
        for row in retained:
            source5_campaign._source5_append_catalogue_spool_record(
                under_reserved_spool, row, encoded_size * 3,
            )
        under_reserved = dict(scratch)
        under_reserved["reserved_bytes"] -= 1
        failed_stream = source5_campaign._source5_catalogue_record_stream(
            under_reserved_spool, len(retained), {}, under_reserved,
            budget_module,
        )
        with self.assertRaisesRegex(
                source5_campaign.Source5CampaignError,
                "bounded external sort peak",
        ):
            next(failed_stream)
        self.assertTrue(under_reserved_spool.closed)

    def test_selected_source_artifact_reader_ignores_peer_elf_and_detects_selected_mutation(self) -> None:
        """Test the selected-artifact helper, not a resealed peer Source cohort."""
        selected_host, peer_host = self.host_ids
        view = self.views[selected_host]
        selected_context = copy.copy(view.context)
        selected_source = view.context.sources[selected_host]
        peer_source = copy.deepcopy(view.context.sources[peer_host])
        artifact_name, selected_artifact = next(
            iter(selected_source["artifacts"].items()),
        )
        peer_artifact = dict(selected_artifact)
        peer_artifact["sha256"] = (
            "0" * 64 if selected_artifact["sha256"] != "0" * 64 else "1" * 64
        )
        peer_source["artifacts"][artifact_name] = peer_artifact
        selected_context.sources = dict(view.context.sources)
        selected_context.sources[peer_host] = peer_source
        selected_context.source = selected_source
        chronology_roles = view.context.owner_evidence_contract[
            "pressure_pair"]["chronology_role_byte_limits"]
        records = source5_campaign._source5_selected_source_artifact_records(
            selected_context, chronology_roles,
        )
        self.assertTrue(records)
        self.assertEqual({record["host_id"] for record in records}, {selected_host})

        with tempfile.TemporaryDirectory(
                prefix="source5-selected-resident-mutation-", dir=self.root) as temporary:
            mutated_root = Path(temporary)
            for record in records:
                source_path = record["path"]
                relative = source_path.relative_to(view.context.source_root)
                target = mutated_root / relative
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                shutil.copy2(source_path, target)
            selected_path = records[0]["path"]
            target = mutated_root / selected_path.relative_to(view.context.source_root)
            before = target.read_bytes()
            self.assertTrue(before)
            mode = stat.S_IMODE(target.stat().st_mode)
            target.chmod(mode | stat.S_IWUSR)
            target.write_bytes(bytes([before[0] ^ 1]) + before[1:])
            target.chmod(mode)
            mutated_context = copy.copy(selected_context)
            mutated_context.source_root = mutated_root
            with self.assertRaises(source5_campaign.Source5CampaignError):
                source5_campaign._source5_selected_source_artifact_records(
                    mutated_context, chronology_roles,
                )

    def test_production_capture_rejects_missing_or_tampered_indexed_object(self) -> None:
        descriptor_by_pin = {
            (row["origin_pin"]["path"], row["origin_pin"]["raw_sha256"]): row
            for row in self.declaration["objects"]
        }

        def row_for(role: str) -> dict:
            return next(
                row for row in self.capture_manifest["objects"]
                if descriptor_by_pin[(row["origin_pin"]["path"],
                                     row["origin_pin"]["raw_sha256"])]["role"] == role
                and descriptor_by_pin[(row["origin_pin"]["path"],
                                       row["origin_pin"]["raw_sha256"])]["phase"] == "exploration"
            )

        def clone(name: str) -> Path:
            target = self.root / name
            shutil.copytree(self.capture_root, target, copy_function=shutil.copy2)
            return target

        ack_row = row_for("source5_archive_ack")
        missing_root = clone("capture-missing-ack")
        (missing_root / ack_row["local_relative_path"]).unlink()
        with self.assertRaises(self.capture_module.PreparedExplorationLineageCaptureError):
            self.capture_module.PreparedExplorationLineageCaptureReaderV1(
                self.declaration, self.capture_manifest, str(missing_root),
            )

        signature_row = row_for("source5_archive_signature")
        tampered_root = clone("capture-tampered-signature")
        signature_path = tampered_root / signature_row["local_relative_path"]
        signature_path.chmod(0o600)
        signature_path.write_bytes(b"tampered structural signature\n")
        signature_path.chmod(0o400)
        with self.assertRaises(self.capture_module.PreparedExplorationLineageCaptureError):
            self.capture_module.PreparedExplorationLineageCaptureReaderV1(
                self.declaration, self.capture_manifest, str(tampered_root),
            )

        extra_root = clone("capture-extra-child")
        extra_path = extra_root / "objects" / "unlisted.bin"
        extra_path.write_bytes(b"unlisted\n")
        extra_path.chmod(0o400)
        with self.assertRaises(self.capture_module.PreparedExplorationLineageCaptureError):
            self.capture_module.PreparedExplorationLineageCaptureReaderV1(
                self.declaration, self.capture_manifest, str(extra_root),
            )


if __name__ == "__main__":
    unittest.main()
