#!/usr/bin/env python3
"""Pure schemas for the bounded Source5 preparatory exploration profile.

This module is selected and pinned by the preparatory Source5 manifest. It
does not open files, launch owners, infer readiness, or change the legacy
all-horizon host-evidence budget schemas.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath
from typing import Any


PREPARATORY_EXECUTION_SCHEMA = (
    "allocatbelt.application-source5-preparatory-exploration-execution.v1"
)
PREPARATORY_BUDGET_SCHEMA = (
    "allocatbelt.application-source5-preparatory-exploration-budget.v1"
)
PREPARATORY_WIDTH_SCHEMA = (
    "allocatbelt.application-source5-preparatory-journal-width-contract.v1"
)
PREPARATORY_PROFILE = "preparatory_exploration_360_v1"
PREPARATORY_PHASE = "exploration"
PREPARATORY_JOB_COUNT = 360
PREPARATORY_CALLBACKS_PER_JOB = 6
PREPARATORY_SETUP_EVENT = "source5_prepared_capacity_registered"
EVIDENCE_BUDGET_SOURCE_PATH = "scripts/application-source5-evidence-budget.py"
SOURCE_BUDGET_MODULE_PATH = EVIDENCE_BUDGET_SOURCE_PATH
OWNER_CATALOGUE_SOURCE_PATH = "scripts/application-source5-evidence-catalogue.py"
CAMPAIGN_SOURCE_PATH = "scripts/application-campaign.py"
INPUT_PREPARATION_SOURCE_PATH = "scripts/application-source5-input-preparation.py"
OWNER_PROFILE_SCHEMA = "allocatbelt.application-source5-owner-evidence-catalogue.v1"
OWNER_PROFILE_SOURCE_ROLES = {
    "fixed_pair", "pressure_pair", "source5_controller", "source5_soak",
    "soak_reader", "offline_dispatcher", "chronology", "evidence_transport",
}
WIDTH_EXTRA_OWNER_PATHS = {
    "feedback_composer": "scripts/application-feedback-composition.py",
    "feedback_reader": "scripts/application-feedback-readback.py",
    "pressure_reader": "scripts/application-pressure-readback.py",
}
ARCHIVE_READ_CONTROL_EVENT_SCHEMA = (
    "allocatbelt.application-source5-archive-read-control-event.v1"
)
PREPARATORY_JOURNAL_EVENTS = (
    "source5_authorized", "source5_app_started",
    "source5_app_terminal", "source5_job_terminal",
)
MAX_U64 = (1 << 64) - 1
MAX_EVENT_BYTES = 4 * 1024 * 1024
MAX_BUDGET_BYTES = 128 * 1024 * 1024
MAX_READ_METADATA_BYTES = 16 * 1024 * 1024
MAX_READ_OBJECTS = 262_144
MAX_ARCHIVE_BYTES = 1 << 48
SIGNATURE_BYTES = 4096

EXECUTION_FIELDS = {
    "schema", "campaign_id", "host_id", "hosts", "original_inputs",
    "execution_sources", "modules", "observed_hosts", "artifact_root",
    "output_root", "scope", "phase_order", "protocol_sha256",
    "preparatory_capacity_generation", "preparatory_capacity_registration",
    "preparatory_journal_width_contracts", "preparatory_host_budgets",
    "archive_signer_contexts", "preparatory_execution_basis_sha256",
    "qualification_eligible", "manifest_sha256",
}
EXECUTION_CORE_FIELDS = {
    "schema", "campaign_id", "host_id", "hosts", "original_inputs",
    "execution_sources", "modules", "observed_hosts", "artifact_root",
    "output_root", "scope", "phase_order", "protocol_sha256",
    "preparatory_capacity_generation", "preparatory_capacity_registration",
    "archive_signer_contexts", "qualification_eligible",
}
BASIS_FIELDS = {
    "schema", "campaign_id", "host_id", "hosts", "original_inputs",
    "execution_sources", "modules", "observed_hosts", "artifact_root",
    "output_root", "scope", "phase_order", "protocol_sha256",
    "preparatory_capacity_generation", "archive_signer_contexts",
}
BUDGET_FIELDS = {
    "schema", "campaign_id", "host_id", "profile",
    "execution_basis_sha256", "original_pins", "owner_contract", "schedule",
    "read_schedule", "journal_width_contract_pin", "path_catalogue",
    "archive_transport", "retention_policy", "storage_reservation",
    "readiness", "budget_sha256",
}
WIDTH_FIELDS = {
    "schema", "campaign_id", "host_id", "profile",
    "execution_basis_sha256", "original_pins_sha256", "initial_spec_pin",
    "initial_plan_pin", "capacity_generation_pin", "source_manifest_pin",
    "owner_pins", "setup_event_widths", "job_rows", "phase_totals",
    "original_callback_event_count", "setup_event_count",
    "maximum_failed_event_count_uplift",
    "maximum_failed_owner_window_bytes", "total_event_count",
    "total_event_bytes", "failed_owner_window", "contract_sha256",
}
JOB_WIDTH_FIELDS = {
    "phase", "job_index", "ordinal", "run_id", "job_sha256",
    "event_counts", "maximum_event_bytes_by_kind", "failed_event_counts",
    "failed_event_bytes_by_kind", "success_job_bytes", "failed_window_bytes",
    "failed_event_count", "failed_event_count_uplift", "byte_uplift",
}
JOB_BOUNDS_FIELDS = {
    "ordinal", "run_id", "job_sha256", "maximum_record_bytes",
}
READ_FIELDS = {
    "analysis_phase", "owner_phase", "job_index", "job", "job_sha256",
    "request_ordinal", "use", "caps",
}
READ_CAP_FIELDS = {
    "bundle_bytes", "maximum_request_bytes", "maximum_response_bytes",
    "object_count", "stage_bytes",
}
ORIGINAL_PINS_FIELDS = {
    "preparation", "capacity_generation", "initial_spec", "initial_plan",
    "source_manifests", "observed_hosts", "typed_modules",
    "archive_signer_context", "capacity_registration",
    "execution_basis_sha256",
}


class PreparatoryBudgetError(ValueError):
    """A preparatory Source5 manifest, width, or budget is malformed."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PreparatoryBudgetError(message)


def canonical_bytes(value: object) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    except (TypeError, ValueError) as error:
        raise PreparatoryBudgetError(f"value is not canonical JSON: {error}") from error


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _is_sha(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _exact(value: object, fields: set[str], label: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == fields,
             f"{label} has an unexpected field set")
    return value


def _uint(value: object, label: str, *, positive: bool = False,
          maximum: int = MAX_U64) -> int:
    _require(type(value) is int and (value > 0 if positive else value >= 0) and
             value <= maximum, f"{label} is outside its finite unsigned range")
    return value


def _pin(value: object, label: str, *, semantic: bool = False) -> dict[str, Any]:
    fields = {"path", "raw_sha256"}
    if semantic:
        fields.add("semantic_sha256")
    row = _exact(value, fields, label)
    _require(type(row["path"]) is str and row["path"].startswith("/") and
             "\\" not in row["path"] and "\x00" not in row["path"] and
             _is_sha(row["raw_sha256"]), f"{label} is malformed")
    if semantic:
        _require(_is_sha(row["semantic_sha256"]),
                 f"{label} semantic digest is malformed")
    return row


def _artifact_wrapper(value: object, label: str) -> dict[str, Any]:
    row = _exact(value, {"artifact", "semantic_sha256"}, label)
    _pin(row["artifact"], f"{label} artifact")
    _require(_is_sha(row["semantic_sha256"]),
             f"{label} semantic digest is malformed")
    return row


def _selected_singleton(value: object, host_id: str, label: str) -> dict[str, Any]:
    row = _exact(value, {host_id}, label)
    return row


def execution_basis_projection(value: object) -> dict[str, Any]:
    """Return the exact non-cyclic, host-scoped manifest basis projection."""
    if type(value) is dict and frozenset(value) in {
            frozenset(EXECUTION_CORE_FIELDS),
            frozenset(EXECUTION_FIELDS - {"manifest_sha256"})}:
        manifest = value
    else:
        manifest = _exact(value, EXECUTION_FIELDS,
                          "preparatory execution manifest")
    _require(manifest["schema"] == PREPARATORY_EXECUTION_SCHEMA and
             manifest["scope"] == "preparatory_exploration" and
             manifest["phase_order"] == [PREPARATORY_PHASE] and
             manifest["qualification_eligible"] is False and
             type(manifest["host_id"]) is str and manifest["host_id"] and
             type(manifest["hosts"]) is list and len(manifest["hosts"]) == 3 and
             len(set(manifest["hosts"])) == 3 and
             manifest["host_id"] in manifest["hosts"],
             "preparatory execution identity/scope differs")
    host_id = manifest["host_id"]
    is_core = set(manifest) == EXECUTION_CORE_FIELDS
    if not is_core:
        _selected_singleton(manifest["preparatory_journal_width_contracts"],
                            host_id, "preparatory journal-width map")
        _selected_singleton(manifest["preparatory_host_budgets"],
                            host_id, "preparatory host-budget map")
    _selected_singleton(manifest["archive_signer_contexts"],
                        host_id, "preparatory signer-context map")
    generation = _exact(manifest["preparatory_capacity_generation"],
                        {"completion", "provenance"},
                        "preparatory capacity generation")
    _pin(generation["completion"], "preparatory capacity completion", semantic=True)
    provenance = _exact(generation["provenance"], {
        "schema", "preparation_pin", "initial_spec_pin", "initial_plan_pin",
    }, "preparatory capacity provenance")
    _require(provenance["schema"] ==
             "allocatbelt.application-source5-preparatory-capacity-provenance.v1",
             "preparatory capacity provenance schema differs")
    for name in ("preparation_pin", "initial_spec_pin", "initial_plan_pin"):
        _pin(provenance[name], f"preparatory capacity {name}")
    registration = _exact(manifest["preparatory_capacity_registration"], {
        "completion", "host_completion", "host_verification", "ledger",
        "capacity_schedule_sha256", "registration_head",
    }, "selected preparatory capacity registration")
    # SourceA's existing registration row stores these as flat semantic pins;
    # preserve that exact result shape rather than converting them to the
    # execution-manifest artifact-wrapper shape.
    _pin(registration["completion"],
         "selected preparatory registration completion", semantic=True)
    _pin(registration["host_completion"],
         "selected preparatory host completion", semantic=True)
    _exact(registration["host_verification"], {
        "path", "raw_sha256", "receipt_sha256",
    }, "selected preparatory host verification")
    _exact(registration["ledger"], {
        "path", "raw_sha256", "terminal_head",
    }, "selected preparatory capacity ledger")
    _require(_is_sha(registration["capacity_schedule_sha256"]) and
             _is_sha(registration["registration_head"]),
             "selected preparatory registration digest is malformed")
    signer = _selected_singleton(manifest["archive_signer_contexts"], host_id,
                                 "preparatory signer-context map")[host_id]
    _artifact_wrapper(signer, "selected preparatory signer context")

    projection = {name: manifest[name] for name in sorted(BASIS_FIELDS)}
    # The selected registration is included exactly once with an explicit name;
    # width/budget pin maps and manifest self-digests are intentionally absent.
    projection["selected_capacity_registration"] = registration
    return projection


def build_execution_basis(value: object) -> str:
    """Hash the shared exact execution basis, excluding circular artifact pins."""
    return _sha(canonical_bytes(execution_basis_projection(value)))


def seal_execution_manifest(body_value: object) -> dict[str, Any]:
    body = _exact(body_value, EXECUTION_FIELDS - {"manifest_sha256"},
                  "preparatory execution manifest body")
    expected_basis = build_execution_basis(body)
    _require(body["preparatory_execution_basis_sha256"] == expected_basis,
             "preparatory manifest execution basis digest differs")
    _artifact_wrapper(
        _selected_singleton(body["preparatory_journal_width_contracts"],
                            body["host_id"], "preparatory journal-width map")[body["host_id"]],
        "selected preparatory width contract",
    )
    _artifact_wrapper(
        _selected_singleton(body["preparatory_host_budgets"], body["host_id"],
                            "preparatory host-budget map")[body["host_id"]],
        "selected preparatory host budget",
    )
    result = {**body, "manifest_sha256": _sha(canonical_bytes(body))}
    validate_execution_manifest(result)
    return result


def validate_execution_manifest(value: object) -> dict[str, Any]:
    manifest = _exact(value, EXECUTION_FIELDS, "preparatory execution manifest")
    basis = build_execution_basis(manifest)
    _require(manifest["preparatory_execution_basis_sha256"] == basis and
             _is_sha(manifest["manifest_sha256"]) and
             manifest["manifest_sha256"] == _sha(canonical_bytes({
                 key: item for key, item in manifest.items()
                 if key != "manifest_sha256"
             })), "preparatory execution manifest digest/basis differs")
    return manifest


def build_journal_width_contract(
    *, campaign_id: str, host_id: str, execution_basis_sha256: str,
    original_pins: dict[str, Any], initial_spec_pin: dict[str, Any],
    initial_plan_pin: dict[str, Any], capacity_generation_pin: dict[str, Any],
    source_manifest_pin: dict[str, Any], owner_pins: dict[str, Any],
    setup_line_bytes: int, job_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Close one source-derived setup line and the exact 360 job rows."""
    _require(type(campaign_id) is str and campaign_id and
             type(host_id) is str and host_id and
             _is_sha(execution_basis_sha256),
             "preparatory width identity is malformed")
    _pin(initial_spec_pin, "initial Spec pin", semantic=True)
    _pin(initial_plan_pin, "initial Plan pin", semantic=True)
    _pin(capacity_generation_pin, "capacity generation pin", semantic=True)
    _pin(source_manifest_pin, "selected Source manifest pin", semantic=True)
    _require(type(original_pins) is dict and type(owner_pins) is dict and
             len(original_pins) > 0 and len(owner_pins) > 0,
             "preparatory width provenance is missing")
    _uint(setup_line_bytes, "preparatory capacity registration line width",
          positive=True, maximum=MAX_EVENT_BYTES)
    _require(type(job_rows) is list and
             len(job_rows) == PREPARATORY_JOB_COUNT,
             "preparatory journal width must cover exactly 360 original exploration jobs")
    expected_counts = {
        "source5_authorized": 1,
        "source5_app_started": 2,
        "source5_app_terminal": 2,
        "source5_job_terminal": 1,
    }
    normalized: list[dict[str, Any]] = []
    winner: dict[str, Any] | None = None
    phase_bytes = 0
    for index, candidate in enumerate(job_rows):
        row = _exact(candidate, JOB_WIDTH_FIELDS,
                     f"preparatory width job row[{index}]")
        _require(row["phase"] == PREPARATORY_PHASE and
                 row["job_index"] == index and
                 type(row["ordinal"]) is int and row["ordinal"] > 0 and
                 type(row["run_id"]) is str and row["run_id"] and
                 _is_sha(row["job_sha256"]) and
                 row["event_counts"] == expected_counts and
                 row["failed_event_counts"] == expected_counts and
                 type(row["maximum_event_bytes_by_kind"]) is dict and
                 set(row["maximum_event_bytes_by_kind"]) == set(PREPARATORY_JOURNAL_EVENTS) and
                 type(row["failed_event_bytes_by_kind"]) is dict and
                 set(row["failed_event_bytes_by_kind"]) == set(PREPARATORY_JOURNAL_EVENTS),
                 f"preparatory width job row[{index}] identity/counts differ")
        for event in PREPARATORY_JOURNAL_EVENTS:
            _uint(row["maximum_event_bytes_by_kind"][event],
                  f"preparatory success line width {index}/{event}",
                  positive=True, maximum=MAX_EVENT_BYTES)
            _uint(row["failed_event_bytes_by_kind"][event],
                  f"preparatory failure line width {index}/{event}",
                  positive=True, maximum=MAX_EVENT_BYTES)
        success_bytes = sum(expected_counts[event] *
                            row["maximum_event_bytes_by_kind"][event]
                            for event in PREPARATORY_JOURNAL_EVENTS)
        failed_bytes = sum(expected_counts[event] *
                           row["failed_event_bytes_by_kind"][event]
                           for event in PREPARATORY_JOURNAL_EVENTS)
        _require(row["success_job_bytes"] == success_bytes and
                 row["failed_window_bytes"] == failed_bytes and
                 row["failed_event_count"] == PREPARATORY_CALLBACKS_PER_JOB and
                 row["failed_event_count_uplift"] == 0 and
                 row["byte_uplift"] == max(0, failed_bytes - success_bytes),
                 f"preparatory width job row[{index}] byte/count arithmetic differs")
        _uint(row["ordinal"], f"preparatory width ordinal[{index}]", positive=True)
        normalized.append(dict(row))
        phase_bytes += success_bytes
        candidate_winner = {
            "phase": row["phase"], "job_index": index,
            "ordinal": row["ordinal"], "run_id": row["run_id"],
            "job_sha256": row["job_sha256"],
            "failed_event_count": row["failed_event_count"],
            "failed_event_count_uplift": row["failed_event_count_uplift"],
            "failed_window_bytes": failed_bytes,
            "success_job_bytes": success_bytes,
            "byte_uplift": row["byte_uplift"],
        }
        # Stable first-original-row tie behavior.
        if winner is None or (candidate_winner["byte_uplift"],
                              candidate_winner["failed_event_count_uplift"]) > (
                                  winner["byte_uplift"],
                                  winner["failed_event_count_uplift"]):
            winner = candidate_winner
    _require(len({row["run_id"] for row in normalized}) == PREPARATORY_JOB_COUNT,
             "preparatory width rows repeat original Plan run IDs")
    setup = [{"event": PREPARATORY_SETUP_EVENT, "phase": "registration",
              "count": 1, "maximum_line_bytes": setup_line_bytes}]
    original_count = PREPARATORY_JOB_COUNT * PREPARATORY_CALLBACKS_PER_JOB
    total_count = original_count + 1 + winner["failed_event_count_uplift"]
    total_bytes = setup_line_bytes + phase_bytes + max(0, winner["byte_uplift"])
    body = {
        "schema": PREPARATORY_WIDTH_SCHEMA,
        "campaign_id": campaign_id, "host_id": host_id,
        "profile": PREPARATORY_PROFILE,
        "execution_basis_sha256": execution_basis_sha256,
        "original_pins_sha256": _sha(canonical_bytes(original_pins)),
        "initial_spec_pin": initial_spec_pin,
        "initial_plan_pin": initial_plan_pin,
        "capacity_generation_pin": capacity_generation_pin,
        "source_manifest_pin": source_manifest_pin,
        "owner_pins": owner_pins,
        "setup_event_widths": setup,
        "job_rows": normalized,
        "phase_totals": [{
            "phase": PREPARATORY_PHASE,
            "job_count": PREPARATORY_JOB_COUNT,
            "event_count": original_count,
            "success_event_bytes": phase_bytes,
        }],
        "original_callback_event_count": original_count,
        "setup_event_count": 1,
        "maximum_failed_event_count_uplift": winner["failed_event_count_uplift"],
        "maximum_failed_owner_window_bytes": winner["failed_window_bytes"],
        "total_event_count": total_count,
        "total_event_bytes": total_bytes,
        "failed_owner_window": winner,
    }
    return {**body, "contract_sha256": _sha(canonical_bytes(body))}


def validate_journal_width_contract(
    value: object, *, expected_campaign_id: str, expected_host_id: str,
    expected_execution_basis_sha256: str, expected_original_pins: dict[str, Any],
    expected_job_rows: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    contract = _exact(value, WIDTH_FIELDS, "preparatory journal-width contract")
    _require(contract["schema"] == PREPARATORY_WIDTH_SCHEMA and
             contract["campaign_id"] == expected_campaign_id and
             contract["host_id"] == expected_host_id and
             contract["profile"] == PREPARATORY_PROFILE and
             contract["execution_basis_sha256"] == expected_execution_basis_sha256 and
             contract["original_pins_sha256"] == _sha(canonical_bytes(expected_original_pins)) and
             contract["contract_sha256"] == _sha(canonical_bytes({
                 key: item for key, item in contract.items()
                 if key != "contract_sha256"
             })) and
             (expected_job_rows is None or contract["job_rows"] == expected_job_rows),
             "preparatory journal-width identity or deterministic projection differs")
    rebuilt = build_journal_width_contract(
        campaign_id=contract["campaign_id"], host_id=contract["host_id"],
        execution_basis_sha256=contract["execution_basis_sha256"],
        original_pins=expected_original_pins,
        initial_spec_pin=contract["initial_spec_pin"],
        initial_plan_pin=contract["initial_plan_pin"],
        capacity_generation_pin=contract["capacity_generation_pin"],
        source_manifest_pin=contract["source_manifest_pin"],
        owner_pins=contract["owner_pins"],
        setup_line_bytes=contract["setup_event_widths"][0]["maximum_line_bytes"],
        job_rows=contract["job_rows"],
    )
    _require(rebuilt == contract,
             "preparatory journal-width aggregate arithmetic differs")
    return contract


def _validate_read_schedule(value: object, width: dict[str, Any]) -> list[dict[str, Any]]:
    _require(type(value) is list and len(value) == PREPARATORY_JOB_COUNT,
             "preparatory archive schedule must contain exactly 360 read rows")
    rows: list[dict[str, Any]] = []
    width_jobs = width["job_rows"]
    for index, candidate in enumerate(value):
        row = _exact(candidate, READ_FIELDS,
                     f"preparatory archive read row[{index}]")
        job = row["job"]
        _require(type(job) is dict and
                 row["analysis_phase"] == PREPARATORY_PHASE and
                 row["owner_phase"] == PREPARATORY_PHASE and
                 row["job_index"] == index and
                 row["request_ordinal"] == index and
                 row["use"] == "capacity_pilot_export" and
                 row["job_sha256"] == _sha(canonical_bytes(job)) and
                 job.get("run_id") == width_jobs[index]["run_id"] and
                 job.get("ordinal") == width_jobs[index]["ordinal"] and
                 row["job_sha256"] == width_jobs[index]["job_sha256"],
                 f"preparatory archive read row[{index}] differs from its original Plan job")
        caps = _exact(row["caps"], READ_CAP_FIELDS,
                      f"preparatory archive read caps[{index}]")
        _uint(caps["bundle_bytes"], f"preparatory read bundle cap[{index}]",
              positive=True, maximum=MAX_ARCHIVE_BYTES)
        _uint(caps["maximum_request_bytes"], f"preparatory read request cap[{index}]",
              positive=True, maximum=MAX_READ_METADATA_BYTES)
        _uint(caps["maximum_response_bytes"], f"preparatory read response cap[{index}]",
              positive=True, maximum=MAX_READ_METADATA_BYTES)
        _uint(caps["object_count"], f"preparatory read object count[{index}]",
              positive=True, maximum=MAX_READ_OBJECTS)
        _uint(caps["stage_bytes"], f"preparatory read stage cap[{index}]",
              positive=True, maximum=MAX_ARCHIVE_BYTES)
        rows.append(row)
    return rows


def _validate_schedule(value: object, width: dict[str, Any]) -> dict[str, Any]:
    row = _exact(value, {
        "phase", "original_job_count", "original_callback_event_count",
        "setup_event_count", "maximum_failed_event_count_uplift",
        "maximum_journal_event_count", "maximum_journal_bytes",
        "maximum_phase_ledger_bytes", "maximum_job_record_bytes_by_ordinal",
    }, "preparatory schedule")
    _require(row["phase"] == PREPARATORY_PHASE and
             row["original_job_count"] == PREPARATORY_JOB_COUNT and
             row["original_callback_event_count"] == width["original_callback_event_count"] and
             row["setup_event_count"] == 1 and
             row["maximum_failed_event_count_uplift"] ==
                 width["maximum_failed_event_count_uplift"] and
             row["maximum_journal_event_count"] == width["total_event_count"] and
             row["maximum_journal_bytes"] == width["total_event_bytes"] and
             type(row["maximum_job_record_bytes_by_ordinal"]) is list and
             len(row["maximum_job_record_bytes_by_ordinal"]) == PREPARATORY_JOB_COUNT,
             "preparatory schedule differs from its 360-job width contract")
    records = []
    previous = 0
    for index, candidate in enumerate(row["maximum_job_record_bytes_by_ordinal"]):
        bound = _exact(candidate, JOB_BOUNDS_FIELDS,
                        f"preparatory job-record byte bound[{index}]")
        _require(bound["ordinal"] == width["job_rows"][index]["ordinal"] and
                 bound["run_id"] == width["job_rows"][index]["run_id"] and
                 bound["job_sha256"] == width["job_rows"][index]["job_sha256"],
                 f"preparatory job-record byte bound[{index}] identity differs")
        _uint(bound["maximum_record_bytes"],
              f"preparatory job-record byte bound[{index}]", positive=True,
              maximum=MAX_EVENT_BYTES)
        records.append(bound)
        previous += bound["maximum_record_bytes"]
    _require(row["maximum_phase_ledger_bytes"] == previous,
             "preparatory phase-ledger cap does not sum all 360 source-derived row caps")
    return row


def _validate_readiness(value: object) -> dict[str, Any]:
    row = _exact(value, {
        "preparatory_budget_complete", "preparatory_execution_ready",
        "full_horizon_execution_ready", "component_gate_ready",
        "qualification_eligible",
    }, "preparatory readiness")
    expected = {
        "preparatory_budget_complete": True,
        "preparatory_execution_ready": True,
        "full_horizon_execution_ready": False,
        "component_gate_ready": False,
        "qualification_eligible": False,
    }
    _require(all(type(row[name]) is bool and row[name] is expected[name]
                 for name in expected),
             "preparatory profile readiness flags differ from its scoped state")
    return row


def _catalogue_module_and_reader(
    budget: dict[str, Any], catalogue_module: object, catalogue_row_reader: object,
) -> tuple[Any, Any]:
    original = budget.get("original_pins")
    _require(type(original) is dict and
             type(original.get("typed_modules")) is dict,
             "preparatory budget has no selected typed-module pin map")
    module_pin = _exact(
        original["typed_modules"].get(EVIDENCE_BUDGET_SOURCE_PATH),
        {"path", "sha256"}, "selected Source path-catalogue module pin",
    )
    _require(module_pin["path"] == EVIDENCE_BUDGET_SOURCE_PATH and
             _is_sha(module_pin["sha256"]),
             "preparatory budget path-catalogue module pin is malformed")
    loaded_pin = getattr(catalogue_module, "__source5_typed_pin__", None)
    _require(loaded_pin == module_pin,
             "path-catalogue algorithm was not loaded from its selected typed Source pin")
    required = (
        "validate_path_catalogue_manifest",
        "verify_path_catalogue_chunks_with_reader",
        "iter_path_catalogue_rows_with_reader",
        "project_archive_job_caps", "project_archive_readback_caps",
        "build_storage_reservation_value",
    )
    _require(all(callable(getattr(catalogue_module, name, None))
                 for name in required),
             "selected typed Source path-catalogue module lacks its pure projection API")
    _require(callable(catalogue_row_reader),
             "preparatory catalogue row reader is not an explicit captured-byte adapter")
    return catalogue_module, catalogue_row_reader


def _preparatory_owner_catalogue_paths(
    budget: dict[str, Any], owner_catalogue_module: object,
) -> dict[str, str]:
    """Resolve the exact eight role paths from the selected typed owner module."""
    original = budget.get("original_pins")
    _require(type(original) is dict and
             type(original.get("typed_modules")) is dict,
             "preparatory budget has no selected typed-module pin map")
    module_pin = _exact(
        original["typed_modules"].get(OWNER_CATALOGUE_SOURCE_PATH),
        {"path", "sha256"}, "selected Source owner-catalogue module pin",
    )
    _require(module_pin["path"] == OWNER_CATALOGUE_SOURCE_PATH and
             _is_sha(module_pin["sha256"]) and
             getattr(owner_catalogue_module, "__source5_typed_pin__", None) ==
                 module_pin,
             "owner-role algorithm was not loaded from its selected typed Source pin")
    paths = getattr(owner_catalogue_module, "OWNER_PATHS", None)
    _require(type(paths) is dict and set(paths) == OWNER_PROFILE_SOURCE_ROLES,
             "selected typed Source owner catalogue has a different exact role set")
    for role, path in paths.items():
        normalized = PurePosixPath(path) if type(path) is str else None
        _require(normalized is not None and path.startswith("scripts/") and
                 not normalized.is_absolute() and ".." not in normalized.parts and
                 str(normalized) == path,
                 f"selected typed Source owner path for {role} is malformed")
    owner = budget.get("owner_contract")
    _require(type(owner) is dict and
             type(owner.get("owner_source_pins")) is dict and
             set(owner["owner_source_pins"]) == OWNER_PROFILE_SOURCE_ROLES,
             "preparatory source owner pins do not have the exact eight roles")
    for role, value in owner["owner_source_pins"].items():
        pin = _exact(value, {"path", "raw_sha256", "byte_count"},
                     f"preparatory owner pin {role}")
        _require(pin["path"] == paths[role],
                 f"preparatory owner pin {role} is bound to the wrong canonical role path")
    return dict(paths)


def _capacity_pilot_expected_row(
    budget: dict[str, Any], *, spec_raw: bytes,
    source_manifest_raw: bytes, execution_module_pins: object,
    campaign_module: object, input_preparation_module: object,
    catalogue_module: Any,
) -> dict[str, Any]:
    """Derive the exact global capacity-pilot row from pinned Source inputs."""
    original = _exact(budget.get("original_pins"), ORIGINAL_PINS_FIELDS,
                      "preparatory capacity-pilot original pins")
    host_id = budget["host_id"]
    spec_pin = _pin(original["initial_spec"],
                    "preparatory capacity-pilot initial Spec pin",
                    semantic=True)
    spec = _canonical_object(spec_raw, "original capacity-pilot SpecV3 bytes")
    _require(_sha(spec_raw) == spec_pin["raw_sha256"] and
             type(spec.get("schema")) is str and
             spec.get("schema") == "allocatbelt.application-campaign-spec.v3" and
             spec.get("rates") == [] and spec.get("oracles") == [],
             "capacity-pilot Spec bytes differ from the original empty-rate Spec pin")
    source = _canonical_object(source_manifest_raw,
                               "selected capacity-pilot SourceV5 bytes")
    source_pin = _exact(original["source_manifests"].get(host_id), {
        "path", "raw_sha256", "semantic_sha256", "source_tree_sha256",
    }, "preparatory selected capacity-pilot Source pin")
    _require(source.get("schema") == "allocatbelt.application-source-manifest.v5" and
             _sha(source_manifest_raw) == source_pin["raw_sha256"] and
             source.get("manifest_sha256") == source_pin["semantic_sha256"] and
             type(source.get("source")) is dict and
             source["source"].get("source_tree_sha256") ==
                 source_pin["source_tree_sha256"] and
             type(source["source"].get("files")) is list,
             "capacity-pilot SourceV5 bytes differ from the selected original host pin")
    source_body = {key: value for key, value in source.items()
                   if key != "manifest_sha256"}
    _require(source["manifest_sha256"] == _sha(canonical_bytes(source_body)),
             "capacity-pilot SourceV5 semantic digest differs")
    typed_module_value = original.get("typed_modules")
    _require(type(typed_module_value) is dict and bool(typed_module_value),
             "preparatory selected typed-module pins are malformed")
    typed_modules = _exact(typed_module_value, set(typed_module_value),
                           "preparatory selected typed-module pins")
    selected_modules = _exact(execution_module_pins, set(typed_modules),
                              "capacity-pilot execution module map")
    _require(selected_modules == typed_modules,
             "capacity-pilot modules differ from selected execution pins")
    source_rows: dict[str, dict[str, Any]] = {}
    for index, candidate in enumerate(source["source"]["files"]):
        _require(type(candidate) is dict,
                 f"capacity-pilot Source file row[{index}] is malformed")
        kind = candidate.get("kind")
        fields = ({"path", "kind", "mode", "sha256", "size"}
                  if kind == "file" else
                  {"path", "kind", "mode", "sha256", "size", "target"}
                  if kind == "symlink" else set())
        row = _exact(candidate, fields,
                     f"capacity-pilot Source file row[{index}]")
        _require(type(row["path"]) is str and row["path"] not in source_rows,
                 f"capacity-pilot Source file row[{index}] repeats its path")
        source_rows[row["path"]] = row
    for path, module in (
            (CAMPAIGN_SOURCE_PATH, campaign_module),
            (INPUT_PREPARATION_SOURCE_PATH, input_preparation_module)):
        pin = _exact(typed_modules.get(path), {"path", "sha256"},
                     f"capacity-pilot typed module pin {path}")
        row = source_rows.get(path)
        _require(pin["path"] == path and _is_sha(pin["sha256"]) and
                 type(row) is dict and row["kind"] == "file" and
                 row["mode"] in {"100644", "100755"} and
                 type(row["size"]) is int and row["size"] > 0 and
                 row["sha256"] == pin["sha256"] and
                 getattr(module, "__source5_typed_pin__", None) == pin,
                 f"capacity-pilot module {path} is not the exact typed Source file")
    preregistration_digest = getattr(campaign_module,
                                    "preregistration_digest", None)
    digest_object = getattr(campaign_module, "digest_object", None)
    allocators = getattr(campaign_module, "ALLOCATORS", None)
    maximum_bytes = getattr(input_preparation_module,
                            "capacity_pilot_maximum_bytes", None)
    _require(callable(preregistration_digest) and callable(digest_object) and
             callable(maximum_bytes) and
             digest_object(spec) == spec_pin["semantic_sha256"],
             "capacity-pilot exporter or original Spec digest is unavailable from typed Source")
    try:
        spec_preregistration_sha256 = preregistration_digest(spec)
        cap = maximum_bytes(
            spec, host_id, allocators, spec_preregistration_sha256,
        )
    except Exception as error:
        raise PreparatoryBudgetError(
            f"typed Source capacity-pilot byte projection failed: {error}",
        ) from error
    _require(_is_sha(spec_preregistration_sha256) and type(cap) is int and
             0 < cap <= MAX_U64,
             "typed Source capacity-pilot byte projection is not a positive u64")
    roots = budget["storage_reservation"].get("roots")
    _require(type(roots) is list,
             "preparatory capacity-pilot reservation has no root map")
    output_roots = [row for row in roots
                    if type(row) is dict and row.get("role") == "output"]
    _require(len(output_roots) == 1 and
             type(output_roots[0].get("path")) is str,
             "preparatory capacity-pilot reservation has no unique output root")
    output_root = output_roots[0]["path"]
    normalized_root = PurePosixPath(output_root)
    _require(normalized_root.is_absolute() and
             normalized_root.as_posix() == output_root and
             ".." not in normalized_root.parts,
             "preparatory capacity-pilot output root is not normalized")
    path = str(normalized_root / budget["campaign_id"] / "source5" /
               host_id / PREPARATORY_PHASE / "capacity-pilot.json")
    row = {
        "path": path, "kind": "file", "role": "capacity_artifact",
        "host_id": host_id, "max_bytes": cap, "max_file_bytes": cap,
        "max_inodes": 1, "storage_root": output_root,
        "owner": "source5_controller", "phase": PREPARATORY_PHASE,
        "run_id": None, "member_index": None, "aggregate_id": None,
        "aggregate_max_bytes": None, "origin_pin": None,
    }
    return catalogue_module._catalogue_row(
        row, "Source5 preparatory capacity-pilot reservation row",
    )


def _canonical_object(raw: bytes, label: str) -> dict[str, Any]:
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_BUDGET_BYTES,
             f"{label} is not a bounded raw artifact")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise PreparatoryBudgetError(f"{label} is malformed") from error
    _require(type(value) is dict and raw == canonical_bytes(value),
             f"{label} is not canonical JSON")
    return value


def _validate_preparatory_raw_bindings(
    budget: dict[str, Any], *, expected_width_pin: dict[str, Any],
    expected_width: dict[str, Any], execution_manifest_raw: bytes,
    source_manifest_raw: bytes, plan_raw: bytes, width_contract_raw: bytes,
    owner_catalogue_module: object,
) -> dict[str, Any]:
    """Bind budget, width and selected source to the sealed prep manifest."""
    manifest = _canonical_object(execution_manifest_raw,
                                 "preparatory execution manifest bytes")
    validate_execution_manifest(manifest)
    source = _canonical_object(source_manifest_raw,
                               "selected preparatory Source manifest bytes")
    plan = _canonical_object(plan_raw, "original preparatory PlanV3 bytes")
    width = _canonical_object(width_contract_raw,
                              "preparatory journal-width contract bytes")
    original = _exact(budget["original_pins"], ORIGINAL_PINS_FIELDS,
                      "preparatory original pin closure")
    host = budget["host_id"]
    hosts = manifest["hosts"]
    _require(host == manifest["host_id"] and
             type(hosts) is list and len(hosts) == 3 and
             type(source.get("manifest_sha256")) is str and
             _is_sha(source["manifest_sha256"]) and
             type(source.get("source")) is dict and
             type(source["source"].get("files")) is list,
             "preparatory selected Source/host shape differs")
    manifest_body = {key: value for key, value in manifest.items()
                     if key != "manifest_sha256"}
    _require(manifest["manifest_sha256"] == _sha(canonical_bytes(manifest_body)),
             "preparatory execution manifest semantic digest differs")
    source_body = {key: value for key, value in source.items()
                   if key != "manifest_sha256"}
    _require(source["manifest_sha256"] == _sha(canonical_bytes(source_body)),
             "preparatory selected Source manifest semantic digest differs")
    generation = manifest["preparatory_capacity_generation"]
    selected_manifest_ref = manifest["original_inputs"][
        "source_manifests"][host]
    selected_source_pin = {
        "path": selected_manifest_ref["artifact"]["path"],
        "raw_sha256": selected_manifest_ref["artifact"]["raw_sha256"],
        "semantic_sha256": selected_manifest_ref["semantic_sha256"],
        "source_tree_sha256": source["source"]["source_tree_sha256"],
    }
    _require(_sha(source_manifest_raw) == selected_source_pin["raw_sha256"] and
             source["manifest_sha256"] == selected_source_pin["semantic_sha256"] and
             original["source_manifests"].get(host) == selected_source_pin,
             "preparatory selected Source raw/semantic/tree pin differs")
    expected_source_manifests = {}
    for selected_host in hosts:
        ref = manifest["original_inputs"]["source_manifests"][selected_host]
        expected_source_manifests[selected_host] = {
            "path": ref["artifact"]["path"],
            "raw_sha256": ref["artifact"]["raw_sha256"],
            "semantic_sha256": ref["semantic_sha256"],
            "source_tree_sha256": (source["source"]["source_tree_sha256"]
                                   if selected_host == host else
                                   original["source_manifests"].get(
                                       selected_host, {}).get("source_tree_sha256")),
        }
    _require(original["source_manifests"] == expected_source_manifests,
             "preparatory original source-manifest map differs from the sealed cohort")
    expected_modules = manifest["modules"][host]
    _require(type(expected_modules) is dict and
             original["typed_modules"] == expected_modules and
             all(type(pin) is dict and set(pin) == {"path", "sha256"} and
                 pin["path"] == path and _is_sha(pin["sha256"])
                 for path, pin in expected_modules.items()),
             "preparatory selected typed-module pins differ from the manifest")
    files = {}
    for index, candidate in enumerate(source["source"]["files"]):
        _require(type(candidate) is dict,
                 f"selected Source inventory row[{index}] is malformed")
        kind = candidate.get("kind")
        fields = ({"path", "kind", "mode", "sha256", "size"}
                  if kind == "file" else
                  {"path", "kind", "mode", "sha256", "size", "target"}
                  if kind == "symlink" else set())
        row = _exact(candidate, fields,
                     f"selected Source inventory row[{index}]")
        _require(type(row["path"]) is str and row["path"] not in files and
                 _is_sha(row["sha256"]) and type(row["size"]) is int and
                 row["size"] >= 0,
                 f"selected Source inventory identity row[{index}] differs")
        if row["kind"] == "file":
            _require(row["mode"] in {"100644", "100755"},
                     f"selected Source regular-file mode differs at row[{index}]")
        else:
            _require(type(row["target"]) is str,
                     f"selected Source symlink target is malformed at row[{index}]")
            target_bytes = row["target"].encode("utf-8", "strict")
            _require(row["mode"] == "120000" and
                     row["size"] == len(target_bytes) and
                     _sha(target_bytes) == row["sha256"],
                     f"selected Source symlink target digest differs at row[{index}]")
        files[row["path"]] = row
    source_records = source["source"]["files"]
    _require([row["path"] for row in source_records] ==
             sorted((row["path"] for row in source_records),
                    key=lambda path: path.encode("utf-8", "strict")) and
             source["source"]["source_tree_sha256"] ==
                 _sha(canonical_bytes({
                     "schema": "allocatbelt.application-source-inventory.v1",
                     "entries": source_records,
                 })),
             "selected Source typed inventory order/tree digest differs")
    for path, pin in expected_modules.items():
        source_row = files.get(path)
        _require(type(source_row) is dict and source_row["kind"] == "file" and
                 source_row["sha256"] == pin["sha256"] and
                 source_row["mode"] in {"100644", "100755"},
                 f"preparatory typed module {path} differs from its Source row")
    spec_ref = manifest["original_inputs"]["spec"]
    plan_ref = manifest["original_inputs"]["plan"]
    _require(original["initial_spec"] == {
                 "path": spec_ref["artifact"]["path"],
                 "raw_sha256": spec_ref["artifact"]["raw_sha256"],
                 "semantic_sha256": spec_ref["semantic_sha256"],
             } and original["initial_plan"] == {
                 "path": plan_ref["artifact"]["path"],
                 "raw_sha256": plan_ref["artifact"]["raw_sha256"],
                 "semantic_sha256": plan_ref["semantic_sha256"],
             }, "preparatory Spec/Plan pins differ from the sealed manifest")
    _require(_sha(plan_raw) == original["initial_plan"]["raw_sha256"] and
             plan.get("campaign_id") == budget["campaign_id"] and
             type(plan.get("jobs")) is dict and
             type(plan["jobs"].get(PREPARATORY_PHASE)) is list and
             _is_sha(plan.get("plan_sha256")) and
             plan["plan_sha256"] == _sha(canonical_bytes({
                 key: value for key, value in plan.items()
                 if key != "plan_sha256"
             })) == original["initial_plan"]["semantic_sha256"],
             "preparatory PlanV3 raw pin or original job map differs")
    expected_observed = {
        selected_host: manifest["observed_hosts"][selected_host]["artifact"]
        for selected_host in hosts
    }
    _require(original["observed_hosts"] == expected_observed,
             "preparatory observed-host pins differ from the sealed manifest")
    expected_generation = {
        "path": generation["completion"]["path"],
        "raw_sha256": generation["completion"]["raw_sha256"],
        "semantic_sha256": generation["completion"]["semantic_sha256"],
        "provenance": generation["provenance"],
    }
    _require(original["preparation"] == generation["provenance"]["preparation_pin"] and
             original["capacity_generation"] == expected_generation and
             original["capacity_registration"] == {
                 "registration_head": manifest[
                     "preparatory_capacity_registration"]["registration_head"],
                 "capacity_schedule_sha256": manifest[
                     "preparatory_capacity_registration"][
                         "capacity_schedule_sha256"],
                 "ledger": manifest["preparatory_capacity_registration"]["ledger"],
             } and
             original["execution_basis_sha256"] ==
                 manifest["preparatory_execution_basis_sha256"] ==
                 budget["execution_basis_sha256"],
             "preparatory setup/generation/source basis pins differ")
    signer = manifest["archive_signer_contexts"][host]
    _require(original["archive_signer_context"] == signer,
             "preparatory archive signer pin differs from the sealed manifest")

    width_pin_map = manifest["preparatory_journal_width_contracts"][host]
    manifest_width_pin = {
        "path": width_pin_map["artifact"]["path"],
        "raw_sha256": width_pin_map["artifact"]["raw_sha256"],
        "semantic_sha256": width_pin_map["semantic_sha256"],
    }
    _require(width == expected_width and
             _sha(width_contract_raw) == manifest_width_pin["raw_sha256"] and
             width["contract_sha256"] == manifest_width_pin["semantic_sha256"] and
             expected_width_pin == manifest_width_pin and
             budget["journal_width_contract_pin"] == manifest_width_pin,
             "preparatory width raw/semantic/manifest wrapper differs")
    validate_journal_width_contract(
        width, expected_campaign_id=budget["campaign_id"],
        expected_host_id=host,
        expected_execution_basis_sha256=budget["execution_basis_sha256"],
        expected_original_pins=original,
        expected_job_rows=width["job_rows"],
    )
    original_jobs = [job for job in plan["jobs"][PREPARATORY_PHASE]
                     if type(job) is dict and job.get("host_id") == host]
    _require(len(original_jobs) == PREPARATORY_JOB_COUNT and
             len(budget["read_schedule"]) == PREPARATORY_JOB_COUNT,
             "preparatory PlanV3 does not contain exactly 360 selected-host jobs")
    for index, (job, width_row, read_row) in enumerate(zip(
            original_jobs, width["job_rows"], budget["read_schedule"], strict=True)):
        _require(read_row["job"] == job and
                 read_row["job_sha256"] == width_row["job_sha256"] ==
                    _sha(canonical_bytes(job)) and
                 width_row["job_index"] == index and
                 width_row["ordinal"] == job.get("ordinal") and
                 width_row["run_id"] == job.get("run_id"),
                 f"preparatory original Plan/read/width row[{index}] differs")
    budget_map = manifest["preparatory_host_budgets"][host]
    budget_artifact = budget_map["artifact"]
    budget_raw = canonical_bytes(budget)
    _require(budget_artifact["raw_sha256"] == _sha(budget_raw) and
             budget_map["semantic_sha256"] == budget["budget_sha256"],
             "preparatory host-budget bytes differ from the sealed manifest pin")

    owner = _exact(budget["owner_contract"], {
        "schema", "source_manifest_sha256", "owner_source_pins",
        "cleanup_source_shape", "fixed_pair", "pressure_pair", "soak",
        "transport_caps", "role_ceiling_conflicts",
        "exact_full_path_catalogue_complete", "execution_ready",
        "qualification_eligible", "owner_contract_sha256",
    }, "preparatory source owner contract")
    owner_body = {key: item for key, item in owner.items()
                  if key != "owner_contract_sha256"}
    owner_pins = owner["owner_source_pins"]
    owner_paths = _preparatory_owner_catalogue_paths(
        budget, owner_catalogue_module,
    )
    _require(owner["schema"] == OWNER_PROFILE_SCHEMA and
             owner["source_manifest_sha256"] == source["manifest_sha256"] and
             owner["owner_contract_sha256"] == _sha(canonical_bytes(owner_body)) and
             set(owner_pins) == OWNER_PROFILE_SOURCE_ROLES and
             owner["exact_full_path_catalogue_complete"] is False and
             owner["execution_ready"] is False and
             owner["qualification_eligible"] is False,
             "preparatory source owner contract identity/profile differs")
    for role, value in owner_pins.items():
        pin = _exact(value, {"path", "raw_sha256", "byte_count"},
                     f"preparatory owner pin {role}")
        typed = files.get(pin["path"])
        _require(pin["path"] == owner_paths[role] and
                 type(typed) is dict and typed["kind"] == "file" and
                 typed["sha256"] == pin["raw_sha256"] and
                 typed["size"] == pin["byte_count"],
                 f"preparatory owner pin {role} differs from the selected typed Source")
    expected_width_roles = set(OWNER_PROFILE_SOURCE_ROLES) | set(WIDTH_EXTRA_OWNER_PATHS)
    _require(type(width["owner_pins"]) is dict and
             set(width["owner_pins"]) == expected_width_roles,
             "preparatory width owner-pin union does not close over the eleven Source roles")
    for role, owner_pin in owner_pins.items():
        width_pin_row = _exact(width["owner_pins"][role], {
            "path", "raw_sha256", "byte_count",
        }, f"preparatory width shared owner pin {role}")
        _require(width_pin_row == owner_pin,
                 f"preparatory width owner pin {role} differs from the profile pin")
    for role, path in WIDTH_EXTRA_OWNER_PATHS.items():
        pin = _exact(width["owner_pins"][role], {
            "path", "raw_sha256", "byte_count",
        }, f"preparatory width catalogue owner pin {role}")
        typed = files.get(path)
        _require(pin["path"] == path and type(typed) is dict and
                 typed["kind"] == "file" and
                 pin["raw_sha256"] == typed["sha256"] and
                 pin["byte_count"] == typed["size"],
                 f"preparatory width catalogue role {role} changed its exact Source path")
    return manifest


def _control_event_value(
    *, campaign_id: str, host_id: str, analysis_phase: str,
    request_ordinal: int, job_index: int, owner_phase: str,
    job: dict[str, Any], job_sha256: str, use: str, action: str,
    sequence: int, object_manifest_path: str, request_slot_path: str,
    response_slot_path: str, bundle_slot_path: str,
    request_pin: dict[str, Any], response_pin: dict[str, Any] | None,
    bundle_pin: dict[str, Any] | None, object_count: int,
    payload_bytes: int,
) -> dict[str, Any]:
    return {
        "schema": ARCHIVE_READ_CONTROL_EVENT_SCHEMA,
        "sequence": sequence, "campaign_id": campaign_id,
        "host_id": host_id, "action": action,
        "analysis_phase": analysis_phase, "request_use": use,
        "request_ordinal": request_ordinal,
        "owner_job": {
            "phase": owner_phase, "job_index": job_index,
            "ordinal": job["ordinal"], "run_id": job["run_id"],
            "job_sha256": job_sha256,
        },
        "object_manifest_pin": {
            "path": object_manifest_path,
            "raw_sha256": "f" * 64, "semantic_sha256": "f" * 64,
        },
        "request_slot_path": request_slot_path,
        "response_slot_path": response_slot_path,
        "bundle_slot_path": bundle_slot_path,
        "request_pin": request_pin,
        "response_pin": response_pin,
        "bundle_pin": bundle_pin,
        "object_count": object_count, "payload_bytes": payload_bytes,
        "qualification_eligible": False,
    }


def _source_derived_read_control_widths(
    *, campaign_id: str, host_id: str, output_root: str,
    read_schedule: list[dict[str, Any]], slot_paths: dict[str, str],
) -> dict[str, int]:
    metadata_root = (PurePosixPath(output_root) / campaign_id / "chronology" /
                     host_id / "evidence-checkpoints")
    total = 0
    maximum_line = 0
    for item in read_schedule:
        job = item["job"]
        ordinal = item["request_ordinal"]
        leaf = f"{job['ordinal']:06d}-{item['job_sha256']}"
        object_manifest_path = str(
            metadata_root / item["owner_phase"] /
            f"{leaf}.object-manifest.json"
        )
        caps = item["caps"]
        request_pin = {
            "path": slot_paths["source5_archive_read_request_slot"],
            "raw_sha256": "f" * 64, "semantic_sha256": "f" * 64,
            "byte_count": caps["maximum_request_bytes"],
        }
        response_pin = {
            "path": slot_paths["source5_archive_read_response_slot"],
            "raw_sha256": "f" * 64, "semantic_sha256": "f" * 64,
            "byte_count": caps["maximum_response_bytes"],
        }
        bundle_pin = {
            "path": slot_paths["source5_archive_read_bundle"],
            "raw_sha256": "f" * 64, "byte_count": caps["bundle_bytes"],
        }
        common = {
            "campaign_id": campaign_id, "host_id": host_id,
            "analysis_phase": item["analysis_phase"],
            "request_ordinal": ordinal, "job_index": item["job_index"],
            "owner_phase": item["owner_phase"], "job": job,
            "job_sha256": item["job_sha256"], "use": item["use"],
            "object_manifest_path": object_manifest_path,
            "request_slot_path": slot_paths["source5_archive_read_request_slot"],
            "response_slot_path": slot_paths["source5_archive_read_response_slot"],
            "bundle_slot_path": slot_paths["source5_archive_read_bundle"],
            "object_count": caps["object_count"],
            "payload_bytes": caps["stage_bytes"],
        }
        request_record = _control_event_value(
            **common, action="request_published", sequence=2 * ordinal + 1,
            request_pin=request_pin, response_pin=None, bundle_pin=None,
        )
        response_record = _control_event_value(
            **common, action="response_verified", sequence=2 * ordinal + 2,
            request_pin=request_pin, response_pin=response_pin,
            bundle_pin=bundle_pin,
        )
        for record in (request_record, response_record):
            line = canonical_bytes({
                "previous_sha256": "f" * 64,
                "record": record, "record_sha256": "f" * 64,
            })
            total += len(line)
            maximum_line = max(maximum_line, len(line))
    _require(len(read_schedule) > 0 and total > 0,
             "preparatory read-control width has no original rows")
    return {"maximum_bytes": total, "maximum_line_bytes": maximum_line,
            "maximum_event_count": 2 * len(read_schedule)}


def _validate_preparatory_read_slot_rows(
    *, campaign_id: str, host_id: str, output_root: str, scratch_root: str,
    readback_caps: dict[tuple[str, str], dict[str, Any]],
    slot_rows: dict[str, dict[str, Any]], transient_roles: object,
    control_role: str, control: dict[str, int],
) -> None:
    """Close each reusable read slot to its exact path, root and derived cap."""
    expected_transient = {
        "source5_archive_read_request_slot",
        "source5_archive_read_response_slot",
        "source5_archive_read_response_incoming",
        "source5_archive_read_bundle",
        "source5_archive_read_bundle_incoming",
        "source5_archive_read_stage",
    }
    _require(type(transient_roles) in {set, frozenset} and
             set(transient_roles) == expected_transient and
             control_role == "source5_archive_read_control_ledger" and
             type(readback_caps) is dict and bool(readback_caps),
             "preparatory read-slot role or projection set differs")
    _require(set(slot_rows) == expected_transient | {control_role},
             "preparatory catalogue does not close over exactly seven read/control rows")
    fields = (
        "request_bytes", "response_bytes", "bundle_bytes", "stage_bytes",
        "stage_inodes", "maximum_object_bytes",
    )
    caps = {name: max(row[name] for row in readback_caps.values())
            for name in fields}
    readback_root = (PurePosixPath(scratch_root) / campaign_id / host_id /
                     "archive-readback")
    expected = {
        "source5_archive_read_request_slot": (
            "file", caps["request_bytes"], caps["request_bytes"], 1,
            "request.json",
        ),
        "source5_archive_read_response_slot": (
            "file", caps["response_bytes"], caps["response_bytes"], 1,
            "response.json",
        ),
        "source5_archive_read_response_incoming": (
            "file", caps["response_bytes"], caps["response_bytes"], 1,
            "response.json.incoming",
        ),
        "source5_archive_read_bundle": (
            "file", caps["bundle_bytes"], caps["bundle_bytes"], 1,
            "response.tar",
        ),
        "source5_archive_read_bundle_incoming": (
            "file", caps["bundle_bytes"], caps["bundle_bytes"], 1,
            "response.tar.incoming",
        ),
        "source5_archive_read_stage": (
            "tree", caps["stage_bytes"], caps["maximum_object_bytes"],
            caps["stage_inodes"], "stage",
        ),
    }
    _require(output_root.startswith("/") and scratch_root.startswith("/") and
             type(control) is dict and
             type(control.get("maximum_bytes")) is int and
             control["maximum_bytes"] > 0 and
             type(control.get("maximum_line_bytes")) is int and
             0 < control["maximum_line_bytes"] <= control["maximum_bytes"] and
             type(control.get("maximum_event_count")) is int and
             control["maximum_event_count"] > 0,
             "preparatory read-control projection is malformed")
    for role, (kind, maximum, maximum_file, inodes, basename) in expected.items():
        row = slot_rows[role]
        _require(type(row) is dict and row.get("path") == str(readback_root / basename) and
                 row.get("kind") == kind and row.get("role") == role and
                 row.get("host_id") == host_id and
                 row.get("max_bytes") == maximum and
                 row.get("max_file_bytes") == maximum_file and
                 row.get("max_inodes") == inodes and
                 row.get("storage_root") == scratch_root and
                 row.get("owner") == "source5_controller" and
                 row.get("phase") is None and row.get("run_id") is None and
                 row.get("member_index") is None and
                 row.get("aggregate_id") is None and
                 row.get("aggregate_max_bytes") is None and
                 row.get("origin_pin") is None,
                 f"preparatory archive-read slot {role} differs from its exact path/root/cap")
    ledger = slot_rows[control_role]
    expected_ledger = (PurePosixPath(output_root) / campaign_id / "source5" /
                       host_id / "archive-read-control.jsonl")
    _require(type(ledger) is dict and ledger.get("path") == str(expected_ledger) and
             ledger.get("kind") == "file" and ledger.get("role") == control_role and
             ledger.get("host_id") == host_id and
             ledger.get("max_bytes") == control["maximum_bytes"] and
             ledger.get("max_file_bytes") == control["maximum_bytes"] and
             ledger.get("max_inodes") == 1 and
             ledger.get("storage_root") == output_root and
             ledger.get("owner") == "source5_controller" and
             ledger.get("phase") is None and ledger.get("run_id") is None and
             ledger.get("member_index") is None and
             ledger.get("aggregate_id") is None and
             ledger.get("aggregate_max_bytes") is None and
             ledger.get("origin_pin") is None,
             "preparatory read-control row differs from its exact output path/root/derived cap")


def _validate_catalogue_transport_and_storage(
    budget: dict[str, Any], width: dict[str, Any],
    catalogue_module: Any, catalogue_row_reader,
    capacity_pilot_row: dict[str, Any],
) -> None:
    """Recompute prep catalogue/transport/retention/storage from typed rows."""
    catalogue, reader = _catalogue_module_and_reader(
        budget, catalogue_module, catalogue_row_reader,
    )
    try:
        manifest = catalogue.verify_path_catalogue_chunks_with_reader(
            budget["path_catalogue"], reader,
        )
        job_caps = catalogue.project_archive_job_caps(
            catalogue.iter_path_catalogue_rows_with_reader(manifest, reader),
        )
        readback_caps = catalogue.project_archive_readback_caps(
            catalogue.iter_path_catalogue_rows_with_reader(manifest, reader),
        )
    except (OSError, TypeError, ValueError, KeyError) as error:
        raise PreparatoryBudgetError(
            f"typed Source path-catalogue projection failed: {error}",
        ) from error
    jobs = budget["read_schedule"]
    capacity_pilot_path_rows = []
    capacity_pilot_role_rows = []
    for row in catalogue.iter_path_catalogue_rows_with_reader(manifest, reader):
        if row["path"] == capacity_pilot_row["path"]:
            capacity_pilot_path_rows.append(row)
        if (row["role"] == "capacity_artifact" and
                row["host_id"] == budget["host_id"] and
                row["phase"] == PREPARATORY_PHASE and
                row["owner"] == "source5_controller"):
            capacity_pilot_role_rows.append(row)
    _require(capacity_pilot_path_rows == [capacity_pilot_row] and
             capacity_pilot_role_rows == [capacity_pilot_row],
             "preparatory catalogue omits or changes the exact global capacity-pilot reservation row")
    expected_groups = {
        (PREPARATORY_PHASE, row["run_id"])
        for row in width["job_rows"]
    }
    _require(set(job_caps) == expected_groups and
             set(readback_caps) == expected_groups and
             len(jobs) == PREPARATORY_JOB_COUNT,
             "preparatory source catalogue is not exactly the original 360-job domain")

    expected_per_job = []
    metadata_total = 0
    payload_total = 0
    object_total = 0
    readback_windows = []
    for index, width_row in enumerate(width["job_rows"]):
        read = jobs[index]
        job = read["job"]
        key = (PREPARATORY_PHASE, width_row["run_id"])
        transfer = job_caps[key]
        rb = readback_caps[key]
        _require(read["job_index"] == index and
                 read["job_sha256"] == width_row["job_sha256"] and
                 job["run_id"] == width_row["run_id"] and
                 job["ordinal"] == width_row["ordinal"],
                 f"preparatory catalogue transport row[{index}] changed Plan identity")
        expected_per_job.append({
            "phase": PREPARATORY_PHASE, "job_index": index,
            "ordinal": width_row["ordinal"], "run_id": width_row["run_id"],
            "job_sha256": width_row["job_sha256"], **transfer,
            "readback_request_bytes": rb["request_bytes"],
            "readback_response_bytes": rb["response_bytes"],
            "readback_bundle_bytes": rb["bundle_bytes"],
            "readback_stage_bytes": rb["stage_bytes"],
            "readback_stage_inodes": rb["stage_inodes"],
            "readback_object_count": rb["object_count"],
            "readback_window_bytes": rb["live_window_bytes"],
            "readback_window_inodes": rb["live_window_inodes"],
        })
        expected_read = {
            "analysis_phase": PREPARATORY_PHASE,
            "owner_phase": PREPARATORY_PHASE,
            "job_index": index, "job": job,
            "job_sha256": width_row["job_sha256"],
            "request_ordinal": index, "use": "capacity_pilot_export",
            "caps": {
                "bundle_bytes": rb["bundle_bytes"],
                "maximum_request_bytes": rb["request_bytes"],
                "maximum_response_bytes": rb["response_bytes"],
                "object_count": rb["object_count"],
                "stage_bytes": rb["stage_bytes"],
            },
        }
        _require(read == expected_read,
                 f"preparatory captured read schedule row[{index}] differs from typed catalogue")
        metadata_total += sum(transfer[field] for field in (
            "checkpoint_request_bytes", "transfer_offer_bytes", "checkpoint_bytes",
            "object_manifest_bytes", "archive_ack_bytes", "signature_bytes",
            "stage_map_bytes",
        ))
        payload_total += rb["stage_bytes"]
        object_total += rb["object_count"]
        readback_windows.append((rb["live_window_bytes"], rb["live_window_inodes"]))
    maximum_archive = {
        field: max(row[field] for row in expected_per_job)
        for field in (
            "checkpoint_request_bytes", "transfer_packet_bytes", "checkpoint_bytes",
            "object_manifest_bytes", "archive_ack_bytes", "signature_bytes",
            "ack_bundle_bytes", "stage_map_bytes", "transfer_offer_bytes",
        )
    }
    max_readback_bytes = max(item[0] for item in readback_windows)
    max_readback_inodes = max(item[1] for item in readback_windows)
    slot_roles = set(catalogue.SOURCE5_ARCHIVE_READ_TRANSIENT_ROLES) | {
        catalogue.SOURCE5_ARCHIVE_READ_CONTROL_ROLE,
    }
    slot_rows: dict[str, dict[str, Any]] = {}
    for row in catalogue.iter_path_catalogue_rows_with_reader(manifest, reader):
        if row["role"] in slot_roles:
            _require(row["role"] not in slot_rows,
                     "preparatory catalogue repeats a reusable read slot")
            slot_rows[row["role"]] = row
    _require(set(slot_rows) == slot_roles,
             "preparatory catalogue omits a fixed readback/control slot")
    slot_paths = {role: row["path"] for role, row in slot_rows.items()}
    output_roots = [row for row in budget["storage_reservation"]["roots"]
                    if row["role"] == "output"]
    _require(len(output_roots) == 1,
             "preparatory reservation has no unique output root")
    scratch_roots = [row for row in budget["storage_reservation"]["roots"]
                     if row["role"] == "scratch"]
    _require(len(scratch_roots) == 1,
             "preparatory reservation has no unique readback scratch root")
    control = _source_derived_read_control_widths(
        campaign_id=budget["campaign_id"], host_id=budget["host_id"],
        output_root=output_roots[0]["path"], read_schedule=jobs,
        slot_paths=slot_paths,
    )
    _validate_preparatory_read_slot_rows(
        campaign_id=budget["campaign_id"], host_id=budget["host_id"],
        output_root=output_roots[0]["path"], scratch_root=scratch_roots[0]["path"],
        readback_caps=readback_caps, slot_rows=slot_rows,
        transient_roles=catalogue.SOURCE5_ARCHIVE_READ_TRANSIENT_ROLES,
        control_role=catalogue.SOURCE5_ARCHIVE_READ_CONTROL_ROLE,
        control=control,
    )
    expected_transport = {
        "schema": "allocatbelt.application-source5-preparatory-archive-transport.v1",
        "per_job": expected_per_job, "maximum_per_job": maximum_archive,
        "unique_object_payload_bytes": payload_total,
        "unique_object_count": object_total,
        "maximum_signature_bytes": SIGNATURE_BYTES,
        "read_request_count": PREPARATORY_JOB_COUNT,
        "read_control_event_count": control["maximum_event_count"],
        "read_control_ledger_bytes": control["maximum_bytes"],
        "read_control_ledger_maximum_line_bytes": control["maximum_line_bytes"],
        "maximum_readback_window_bytes": max_readback_bytes,
        "maximum_readback_window_inodes": max_readback_inodes,
    }
    _require(budget["archive_transport"] == expected_transport,
             "preparatory archive transport differs from source-derived catalogue rows")

    record_bounds = budget["schedule"]["maximum_job_record_bytes_by_ordinal"]
    ledger_bytes = sum(row["maximum_record_bytes"] for row in record_bounds)
    policy = manifest["retention_policy"]
    expected_retention = {
        "schema": "allocatbelt.application-source5-preparatory-retention.v1",
        "source_policy": policy,
        "persistent_job_record_bytes": ledger_bytes,
        "persistent_job_record_count": PREPARATORY_JOB_COUNT,
        "persistent_archive_metadata_bytes": metadata_total,
        "maximum_failed_owner_window_bytes": width[
            "maximum_failed_owner_window_bytes"],
        "maximum_active_transfer_window_bytes": policy[
            "maximum_window_total_bytes"],
        "maximum_active_transfer_window_inodes": policy[
            "maximum_window_total_inodes"],
        "maximum_active_readback_window_bytes": max_readback_bytes,
        "maximum_active_readback_window_inodes": max_readback_inodes,
        "maximum_catalogue_sort_scratch_bytes": manifest[
            "maximum_sort_scratch_bytes"],
        "maximum_catalogue_sort_scratch_inodes": manifest[
            "maximum_sort_scratch_inodes"],
        "no_reclaim_roles": [
            "typed_source_file", "typed_source_symlink", "source_manifest",
            "spec_v3", "plan_v3", "observed_host", "preparation",
            "capacity_completion", "capacity_host_receipt", "capacity_ledger",
            "capacity_artifact", "source5_archive_signer_context",
            "source5_archive_signer_keyring", "source5_archive_signer_gpgv",
        ],
    }
    _require(budget["retention_policy"] == expected_retention and
             budget["schedule"]["maximum_phase_ledger_bytes"] == ledger_bytes,
             "preparatory retention or phase-ledger total differs from catalogue rows")

    storage = budget["storage_reservation"]
    roots = storage["roots"]
    reservation_value = catalogue.build_storage_reservation_value(
        budget["campaign_id"], budget["host_id"], roots,
    )
    reservation_raw = canonical_bytes(reservation_value)
    reservation_pin = _exact(storage["pin"], {
        "path", "raw_sha256", "semantic_sha256", "byte_count",
    }, "preparatory storage reservation pin")
    _require(reservation_pin["path"].startswith("/") and
             _is_sha(reservation_pin["raw_sha256"]) and
             reservation_pin["raw_sha256"] == _sha(reservation_raw) and
             reservation_pin["semantic_sha256"] ==
                reservation_value["reservation_sha256"] and
             reservation_pin["byte_count"] == len(reservation_raw) and
             storage["roots"] == reservation_value["roots"],
             "preparatory storage reservation raw/semantic/root projection differs")
    root_paths = {row["path"] for row in roots}
    required_bytes = dict(policy["maximum_live_root_byte_bounds"])
    required_inodes = dict(policy["maximum_live_root_inode_bounds"])
    for root in roots:
        required_bytes.setdefault(root["path"], 0)
        required_inodes.setdefault(root["path"], 0)
    artifact_roots = [row["path"] for row in roots if row["role"] == "artifact"]
    scratch_roots = [row["path"] for row in roots if row["role"] == "scratch"]
    _require(len(artifact_roots) == len(scratch_roots) == 1,
             "preparatory storage reservation lacks its exact artifact/scratch roots")
    required_bytes[artifact_roots[0]] += sum(
        row["byte_count"] for row in manifest["chunks"]
    )
    required_inodes[artifact_roots[0]] += len(manifest["chunks"])
    scratch = scratch_roots[0]
    required_bytes[scratch] = max(
        required_bytes[scratch],
        policy["persistent_root_byte_bounds"].get(scratch, 0) +
        manifest["maximum_sort_scratch_bytes"],
    )
    required_inodes[scratch] = max(
        required_inodes[scratch],
        policy["persistent_root_inode_bounds"].get(scratch, 0) +
        manifest["maximum_sort_scratch_inodes"],
    )
    _require(set(required_bytes) == root_paths == set(required_inodes) and
             storage["required_bytes_by_root"] == required_bytes and
             storage["required_inodes_by_root"] == required_inodes and
             all(row["reserved_bytes"] >= required_bytes[row["path"]] and
                 row["reserved_inodes"] >= required_inodes[row["path"]]
                 for row in roots),
             "preparatory storage reservation does not cover exact catalogue/window bounds")


def build_host_evidence_budget_v1(
    value: object, *, catalogue_module: Any, owner_catalogue_module: object,
    campaign_module: object, input_preparation_module: object,
    spec_raw: bytes, source_manifest_raw: bytes,
    execution_module_pins: object, catalogue_row_reader,
) -> dict[str, Any]:
    """Seal one producer-populated prep budget after checking closed arithmetic."""
    body = _exact(value, BUDGET_FIELDS - {"budget_sha256"},
                  "preparatory host-budget body")
    _require(body["schema"] == PREPARATORY_BUDGET_SCHEMA and
             body["profile"] == PREPARATORY_PROFILE and
             type(body["campaign_id"]) is str and body["campaign_id"] and
             type(body["host_id"]) is str and body["host_id"] and
             _is_sha(body["execution_basis_sha256"]),
             "preparatory host-budget identity differs")
    _require(type(body["original_pins"]) is dict and
             body["original_pins"].get("execution_basis_sha256") ==
                 body["execution_basis_sha256"] and
             "execution_manifest" not in body["original_pins"] and
             "journal_width_contract" not in body["original_pins"] and
             "host_budget" not in body["original_pins"],
             "preparatory original pins contain circular manifest/width/budget identity")
    width_pin = _pin(body["journal_width_contract_pin"],
                     "preparatory width contract pin", semantic=True)
    width = body["owner_contract"].get("journal_width_contract")
    width_raw = body["owner_contract"].get("journal_width_contract_raw")
    _require(type(width) is dict and type(width_raw) is bytes and
             width_raw == canonical_bytes(width) and
             _sha(width_raw) == width_pin["raw_sha256"] and
             width["contract_sha256"] == width_pin["semantic_sha256"],
             "preparatory budget does not bind the exact raw width artifact")
    # These two internal build-time fields are projected away before sealing;
    # the serialized owner contract itself remains the exact public source schema.
    owner_contract = {key: item for key, item in body["owner_contract"].items()
                      if key not in {"journal_width_contract", "journal_width_contract_raw"}}
    _require(type(owner_contract) is dict and owner_contract,
             "preparatory owner contract is empty")
    schedule = _validate_schedule(body["schedule"], width)
    reads = _validate_read_schedule(body["read_schedule"], width)
    _require(type(body["path_catalogue"]) is dict and
             type(body["archive_transport"]) is dict and
             type(body["retention_policy"]) is dict and
             type(body["storage_reservation"]) is dict,
             "preparatory catalogue/transport/retention/reservation sections are malformed")
    _validate_readiness(body["readiness"])
    _preparatory_owner_catalogue_paths(body, owner_catalogue_module)
    result_body = {**body, "owner_contract": owner_contract,
                   "schedule": schedule, "read_schedule": reads}
    raw_body = canonical_bytes(result_body)
    result = {**result_body, "budget_sha256": _sha(raw_body)}
    _require(len(canonical_bytes(result)) <= MAX_BUDGET_BYTES,
             "preparatory budget exceeds its finite canonical metadata ceiling")
    validate_journal_width_contract(
        width, expected_campaign_id=result["campaign_id"],
        expected_host_id=result["host_id"],
        expected_execution_basis_sha256=result["execution_basis_sha256"],
        expected_original_pins=result["original_pins"],
    )
    capacity_pilot_row = _capacity_pilot_expected_row(
        result, spec_raw=spec_raw,
        source_manifest_raw=source_manifest_raw,
        execution_module_pins=execution_module_pins,
        campaign_module=campaign_module,
        input_preparation_module=input_preparation_module,
        catalogue_module=catalogue_module,
    )
    _validate_catalogue_transport_and_storage(
        result, width, catalogue_module, catalogue_row_reader,
        capacity_pilot_row,
    )
    return result


def validate_host_evidence_budget_v1(
    value: object, *, expected_campaign_id: str, expected_host_id: str,
    owner_catalogue_module: object,
    expected_execution_basis_sha256: str,
    expected_width_pin: dict[str, Any],
    expected_width: dict[str, Any],
    execution_manifest_raw: bytes, source_manifest_raw: bytes,
    plan_raw: bytes, width_contract_raw: bytes,
    catalogue_module: Any, catalogue_row_reader,
    campaign_module: object, input_preparation_module: object,
    spec_raw: bytes,
) -> dict[str, Any]:
    budget = _exact(value, BUDGET_FIELDS, "preparatory host evidence budget")
    _require(budget["campaign_id"] == expected_campaign_id and
             budget["host_id"] == expected_host_id and
             budget["execution_basis_sha256"] == expected_execution_basis_sha256 and
             budget["journal_width_contract_pin"] == expected_width_pin,
             "preparatory budget differs from the selected manifest basis/width pin")
    _require(budget["owner_contract"].get("journal_width_contract") is None,
             "serialized preparatory budget carries an internal width object")
    _require(_is_sha(budget["budget_sha256"]) and
             budget["budget_sha256"] == _sha(canonical_bytes({
                 key: item for key, item in budget.items()
                 if key != "budget_sha256"
             })), "preparatory budget self-digest differs")
    schedule = _validate_schedule(budget["schedule"], expected_width)
    reads = _validate_read_schedule(budget["read_schedule"], expected_width)
    _require(schedule == budget["schedule"] and reads == budget["read_schedule"] and
             _validate_readiness(budget["readiness"]) == budget["readiness"] and
             type(budget["path_catalogue"]) is dict and
             type(budget["archive_transport"]) is dict and
             type(budget["retention_policy"]) is dict and
             type(budget["storage_reservation"]) is dict,
             "preparatory budget sections differ from their closed profile")
    execution_manifest = _validate_preparatory_raw_bindings(
        budget, expected_width_pin=expected_width_pin,
        expected_width=expected_width,
        execution_manifest_raw=execution_manifest_raw,
        source_manifest_raw=source_manifest_raw, plan_raw=plan_raw,
        width_contract_raw=width_contract_raw,
        owner_catalogue_module=owner_catalogue_module,
    )
    capacity_pilot_row = _capacity_pilot_expected_row(
        budget, spec_raw=spec_raw,
        source_manifest_raw=source_manifest_raw,
        execution_module_pins=execution_manifest["modules"][expected_host_id],
        campaign_module=campaign_module,
        input_preparation_module=input_preparation_module,
        catalogue_module=catalogue_module,
    )
    _validate_catalogue_transport_and_storage(
        budget, expected_width, catalogue_module, catalogue_row_reader,
        capacity_pilot_row,
    )
    return budget
