#!/usr/bin/env python3
"""Native unit regressions for the original prepared-lineage projector."""
from __future__ import annotations

import importlib.util
import copy
import json
import sys
import types
import unittest
from pathlib import Path, PurePosixPath


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


def synthetic_full_replay_case():
    """Build a SourceA protocol-component chain, with no observed process facts."""
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

    setup_details = {
        "campaign_id": campaign_id, "host_id": host_id,
        "completion": generation_completion, "provenance": generation["provenance"],
        "host_completion": host_completion, "host_verification": host_verification,
        "capacity_ledger": capacity_ledger,
        "capacity_schedule_sha256": schedule_sha256,
        "entries": [{"entry": index} for index in range(15)],
        "qualification_eligible": False, "controller_chronology_proven": False,
    }
    registration_head = append_event(
        "source5_prepared_capacity_registered", setup_details,
    )
    registration["registration_head"] = registration_head
    header["initial"]["capacity_registration_head"] = registration_head
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
        authorization = {
            "authorization_id": "", "campaign_id": campaign_id,
            "host_id": host_id, "phase": "exploration", "job_index": job_index,
            "job": job,
            "job_sha256": chronology.sha256_bytes(chronology.canonical_bytes(job)),
            "members": members,
            "members_sha256": chronology.sha256_bytes(chronology.canonical_bytes(members)),
            "execution_manifest": {"path": execution_pin["path"],
                                   "raw_sha256": execution_pin["raw_sha256"]},
            "helper_input": {"path": f"{output_root}/{campaign_id}/helper/{job['run_id']}.json",
                             "raw_sha256": digest("7")},
            "helper_module": {"path": "scripts/application-fixed-pair.py",
                              "sha256": digest("8"), "size": 1,
                              "mode": "100644", "kind": "file"},
            "capacity_registration_head": registration_head,
            "capacity_completion": {"path": host_completion["path"],
                                    "raw_sha256": host_completion["raw_sha256"]},
            "capacity_ledger_raw_sha256": capacity_ledger["raw_sha256"],
            "capacity_terminal_head": capacity_ledger["terminal_head"],
            "capacity_schedule_sha256": schedule_sha256,
            "prerequisites": {}, "outer_deadline_seconds": 30,
            "effective_timeout_seconds": 30,
            "input_snapshot_sha256": digest("9"),
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
        overlay_sha = digest(str(job_index % 10))
        evidence = {
            "kind": "source5_fixed_pair",
            "overlay": {"path": f"{output_root}/{campaign_id}/overlay/{job['run_id']}.json",
                        "raw_sha256": overlay_sha},
            "receipt": {"path": f"{output_root}/{campaign_id}/receipt/{job['run_id']}.json",
                        "raw_sha256": digest("a")},
            "host_receipt": {
                "path": f"{output_root}/{campaign_id}/host/{job['run_id']}.json",
                "raw_sha256": digest("b"),
                "host_verification_sha256": digest("c"),
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
        index_rows.append(lineage.build_prepared_exploration_lineage_index_row(
            job_index, job, campaign_id, host_id, output_root,
            {"path": record_path, "raw_sha256": chronology.sha256_bytes(record_raw)},
            archive_pins, digest("8"), record,
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
        "chronology_module": chronology,
        "campaign_module": campaign_core,
        "preparatory_budget_module": prep_budget,
        "source5_campaign_module": source5_campaign,
    }


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


class CapturedReaderPinContractTests(unittest.TestCase):
    def test_semantic_document_pin_reaches_exact_raw_reader(self) -> None:
        raw = lineage.canonical_bytes({"schema": "captured-document-component"})
        pin = {
            "path": "/absent-origin/initial-spec.json",
            "raw_sha256": lineage.sha256_bytes(raw),
            "semantic_sha256": "e" * 64,
        }
        original_pin = dict(pin)
        reads = []

        def closed_reader(raw_pin, maximum):
            self.assertEqual(set(raw_pin), {"path", "raw_sha256"})
            self.assertEqual(raw_pin["path"], pin["path"])
            self.assertEqual(raw_pin["raw_sha256"], lineage.sha256_bytes(raw))
            reads.append((dict(raw_pin), maximum))
            return raw

        self.assertEqual(
            lineage._reader_bytes(closed_reader, pin, len(raw), "captured Spec"),
            raw,
        )
        self.assertEqual(pin, original_pin)
        self.assertEqual(len(reads), 1)

    def test_raw_projection_preserves_digest_and_byte_bounds(self) -> None:
        raw = b"captured bytes\n"
        pin = {
            "path": "/absent-origin/metadata.json",
            "raw_sha256": lineage.sha256_bytes(raw),
            "semantic_sha256": "e" * 64,
        }
        for changed_raw, maximum in ((raw + b"changed", 128), (raw, len(raw) - 1)):
            with self.subTest(raw=changed_raw, maximum=maximum):
                with self.assertRaises(lineage.PreparedExplorationLineageError):
                    lineage._reader_bytes(
                        lambda _pin, _maximum: changed_raw,
                        pin, maximum, "captured metadata",
                    )


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


if __name__ == "__main__":
    unittest.main()
