#!/usr/bin/env python3
"""Pure width and captured-metadata projections for prepared exploration reuse.

This module contains arithmetic and closed DTO validation only.  It never
opens an origin path, performs a signature check, or grants an execution gate.
The selected Source owns the caller-supplied Plan rows and lineage proof.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath
from typing import Any, Callable


SOURCE5_JOURNAL_WIDTH_CONTRACT_SCHEMA_V1 = \
    "allocatbelt.application-source5-journal-width-contract.v1"
SOURCE5_JOURNAL_WIDTH_CONTRACT_SCHEMA_V2 = \
    "allocatbelt.application-source5-journal-width-contract.v2"
SOURCE5_PREPARED_EXPLORATION_ADMISSION_PROFILE = \
    "source5_prepared_exploration_reuse_v1"
SOURCE5_PREPARED_EXPLORATION_CAPTURE_DECLARATION_SCHEMA_V1 = \
    "allocatbelt.application-source5-lineage-capture-declaration.v1"
MAX_EVENT_BYTES = 4 * 1024 * 1024
PREPARED_EXPLORATION_JOB_COUNT = 360
PHASES = ("exploration", "aa", "confirmation", "pressure", "soak")
EVENT_NAMES = (
    "source5_authorized", "source5_app_started",
    "source5_app_terminal", "source5_job_terminal",
)
WIDTH_V1_FIELDS = {
    "schema", "campaign_id", "host_id", "original_pins_sha256",
    "plan_pin", "source_manifest_pin", "owner_pins", "job_rows",
    "phase_totals", "fixed_event_widths", "total_event_count",
    "total_event_bytes", "failed_owner_window", "contract_sha256",
}
WIDTH_V2_FIELDS = WIDTH_V1_FIELDS | {"admission_profile", "ancestor"}
ANCESTOR_FIELDS = {
    "bridge_header_pin", "record_index_pin", "header_byte_count",
    "index_byte_count", "job_list_sha256", "journal", "phase_ledger",
}
FIXED_IDENTITIES = (
    ("source5_prepared_capacity_registered", "registration"),
    *(('source5_analysis', phase) for phase in (
        "exploration", "aa", "fixed_analysis", "pressure_analysis",
        "soak", "final_analysis",
    )),
)
JOB_ROW_FIELDS = {
    "phase", "job_index", "ordinal", "run_id", "job_sha256",
    "event_counts", "maximum_event_bytes_by_kind", "failed_event_counts",
    "failed_event_bytes_by_kind", "success_job_bytes", "failed_window_bytes",
    "failed_event_count", "failed_event_count_uplift", "byte_uplift",
}
FIXED_ROW_FIELDS = {"event", "phase", "count", "maximum_line_bytes"}
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}\Z")


class PreparedBridgeBudgetError(ValueError):
    """A width-v2 or captured-metadata projection is malformed."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PreparedBridgeBudgetError(message)


def _canonical(value: object) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    except (TypeError, ValueError) as error:
        raise PreparedBridgeBudgetError(
            f"value is not canonical JSON: {error}",
        ) from error


def _sha(raw: bytes) -> str:
    _require(type(raw) is bytes, "prepared bridge hash input must be bytes")
    return hashlib.sha256(raw).hexdigest()


def _exact(value: object, fields: set[str], label: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == fields,
             f"{label} has an unexpected field set")
    return value


def _digest(value: object, label: str) -> str:
    _require(type(value) is str and _DIGEST.fullmatch(value) is not None,
             f"{label} is not a lowercase SHA-256 digest")
    return value


def _uint(value: object, label: str, *, positive: bool = False) -> int:
    _require(type(value) is int and 0 <= value <= (1 << 64) - 1 and
             (not positive or value > 0),
             f"{label} is outside its finite unsigned range")
    return value


def _token(value: object, label: str) -> str:
    _require(type(value) is str and _TOKEN.fullmatch(value) is not None,
             f"{label} is not a canonical token")
    return value


def _pin(value: object, label: str) -> dict[str, str]:
    pin = _exact(value, {"path", "raw_sha256"}, label)
    path = pin["path"]
    _require(type(path) is str and path.startswith("/") and
             len(path.encode("utf-8")) <= 4096 and "\\" not in path and
             "\x00" not in path and PurePosixPath(path).as_posix() == path and
             ".." not in PurePosixPath(path).parts and
             "." not in PurePosixPath(path).parts and path != "/" and
             not path.endswith("/"),
             f"{label} path is not a normalized absolute path")
    _digest(pin["raw_sha256"], f"{label} raw digest")
    return pin


def _full_pin(value: object, label: str) -> dict[str, str]:
    pin = _exact(value, {"path", "raw_sha256", "semantic_sha256"}, label)
    _pin({"path": pin["path"], "raw_sha256": pin["raw_sha256"]}, label)
    _digest(pin["semantic_sha256"], f"{label} semantic digest")
    return pin


def source_raw_pin_projection(value: object, label: str) -> dict[str, str]:
    """Project Source-issued raw/semantic or signer pins to raw identity."""
    _require(type(value) is dict and
             {"path", "raw_sha256"} <= set(value) and
             set(value) <= {"path", "raw_sha256", "semantic_sha256",
                            "signer_fingerprint"},
             f"{label} contains unknown fields or lacks its raw pin")
    pin = _pin({"path": value["path"], "raw_sha256": value["raw_sha256"]}, label)
    if "semantic_sha256" in value:
        _digest(value["semantic_sha256"], f"{label} semantic digest")
    if "signer_fingerprint" in value:
        _require(type(value["signer_fingerprint"]) is str and
                 re.fullmatch(r"[A-F0-9]{40}|[A-F0-9]{64}",
                              value["signer_fingerprint"]) is not None,
                 f"{label} signer fingerprint is malformed")
    return pin


def _source_manifest_pin_projection(
    value: object, expected_host: str, label: str,
) -> dict[str, Any]:
    row = _exact(value, {
        "host_id", "path", "raw_sha256", "semantic_sha256",
        "source_tree_sha256",
    }, label)
    _require(row["host_id"] == expected_host,
             f"{label} host identity differs")
    pin = _full_pin({key: row[key] for key in (
        "path", "raw_sha256", "semantic_sha256",
    )}, label)
    _digest(row["source_tree_sha256"], f"{label} source-tree digest")
    return {"host_id": expected_host, **pin,
            "source_tree_sha256": row["source_tree_sha256"]}


def _original_source_manifest_pin_projection(
    value: object, expected_host: str, label: str,
) -> dict[str, Any]:
    row = _exact(value, {
        "path", "raw_sha256", "semantic_sha256", "source_tree_sha256",
    }, label)
    pin = _full_pin({key: row[key] for key in (
        "path", "raw_sha256", "semantic_sha256",
    )}, label)
    _digest(row["source_tree_sha256"], f"{label} source-tree digest")
    return {"host_id": expected_host, **pin,
            "source_tree_sha256": row["source_tree_sha256"]}


def _observed_host_pin_projection(
    value: object, label: str,
) -> dict[str, str]:
    row = _exact(value, {
        "path", "raw_sha256", "boot_id_sha256", "controls_sha256",
    }, label)
    pin = _pin({"path": row["path"], "raw_sha256": row["raw_sha256"]}, label)
    _digest(row["boot_id_sha256"], f"{label} boot-ID digest")
    _digest(row["controls_sha256"], f"{label} controls digest")
    return pin


def _old_catalogue_role_matches(expected_role: str, actual_role: str) -> bool:
    if expected_role == "evidence_index":
        return actual_role in {"preparation", "evidence_index"}
    if expected_role == "fixed_spec_host":
        return actual_role == "observed_host"
    if expected_role == "journal_width_contract":
        return actual_role in {
            "journal_width_contract",
            "preparatory_journal_width_contract",
        }
    return actual_role == expected_role


def _old_catalogue_host_matches(
    row_host: object, expected_host: str | None, selected_host: str,
) -> bool:
    if expected_host is None:
        return row_host is None or row_host == selected_host
    return row_host == expected_host


def _source5_indexed_reservation_binding(
    index_row: object, pin_value: object, role: str, job: object, *,
    initial_output_root: str, campaign_id: str, selected_host: str,
    old_rows: dict[str, dict[str, Any]], evidence_budget_module: object,
) -> tuple[dict[str, str], dict[str, Any]]:
    """Forward one indexed join to the selected typed Source budget algorithm.

    Keep the Bridge error boundary stable for callers while the pure shared
    reservation logic remains owned by the evidence-budget Source.
    """
    typed_pin = getattr(evidence_budget_module, "__source5_typed_pin__", None)
    bind = getattr(evidence_budget_module,
                   "source5_indexed_reservation_binding_v1", None)
    budget_error = getattr(evidence_budget_module, "BudgetPlanError", None)
    _require(type(typed_pin) is dict and
             typed_pin.get("path") ==
                "scripts/application-source5-evidence-budget.py" and
             callable(bind) and type(budget_error) is type and
             issubclass(budget_error, Exception),
             "prepared capture requires its selected typed evidence-budget binding")
    try:
        return bind(
            index_row, pin_value, role, job,
            initial_output_root=initial_output_root,
            campaign_id=campaign_id, selected_host=selected_host,
            old_rows=old_rows,
        )
    except budget_error as error:
        raise PreparedBridgeBudgetError(str(error)) from error


def _validate_ancestor(value: object) -> dict[str, Any]:
    ancestor = _exact(value, ANCESTOR_FIELDS, "prepared exploration ancestor")
    _pin(ancestor["bridge_header_pin"], "prepared bridge header pin")
    _pin(ancestor["record_index_pin"], "prepared record index pin")
    _uint(ancestor["header_byte_count"], "prepared bridge header byte count", positive=True)
    _uint(ancestor["index_byte_count"], "prepared record index byte count", positive=True)
    _digest(ancestor["job_list_sha256"], "prepared exploration job-list digest")
    journal = _exact(ancestor["journal"], {
        "pin", "byte_count", "record_count", "head",
    }, "prepared ancestor journal")
    _pin(journal["pin"], "prepared ancestor journal pin")
    _uint(journal["byte_count"], "prepared ancestor journal byte count", positive=True)
    _require(_uint(journal["record_count"], "prepared ancestor record count") == 2161,
             "prepared ancestor journal does not contain its exact original 2161 rows")
    _digest(journal["head"], "prepared ancestor journal head")
    ledger = _exact(ancestor["phase_ledger"], {
        "pin", "byte_count", "row_count",
    }, "prepared ancestor phase ledger")
    _pin(ledger["pin"], "prepared ancestor phase-ledger pin")
    _uint(ledger["byte_count"], "prepared ancestor phase-ledger byte count", positive=True)
    _require(_uint(ledger["row_count"], "prepared ancestor phase-ledger row count") ==
             PREPARED_EXPLORATION_JOB_COUNT,
             "prepared ancestor phase ledger does not contain its exact 360 original jobs")
    return ancestor


def _job_counts(jobs_by_phase: object) -> dict[str, list[dict[str, Any]]]:
    _require(type(jobs_by_phase) is dict and set(jobs_by_phase) == set(PHASES),
             "prepared width Plan projection does not contain the exact phase map")
    jobs = {}
    run_ids = set()
    for phase in PHASES:
        rows = jobs_by_phase[phase]
        _require(type(rows) is list and all(type(row) is dict for row in rows),
                 f"prepared width {phase} Plan rows are malformed")
        for index, row in enumerate(rows):
            _require(row.get("phase") == phase and
                     type(row.get("ordinal")) is int and row["ordinal"] > 0 and
                     type(row.get("run_id")) is str and
                     _TOKEN.fullmatch(row["run_id"]) is not None and
                     row["run_id"] not in run_ids,
                     f"prepared width {phase} Plan row[{index}] has invalid/duplicate identity")
            run_ids.add(row["run_id"])
        jobs[phase] = rows
    expected = {"exploration": PREPARED_EXPLORATION_JOB_COUNT,
                "aa": 48, "confirmation": 8100,
                "pressure": 8100, "soak": 1}
    _require({phase: len(jobs[phase]) for phase in PHASES} == expected,
             "prepared width Plan changes the exact per-host logical schedule")
    return jobs


def _event_counts(phase: str) -> dict[str, int]:
    members = 1 if phase == "soak" else 2
    return {
        "source5_authorized": 1,
        "source5_app_started": members,
        "source5_app_terminal": members,
        "source5_job_terminal": 1,
    }


def _candidate(row: dict[str, Any]) -> dict[str, Any]:
    return {key: row[key] for key in (
        "phase", "job_index", "ordinal", "run_id", "job_sha256",
        "failed_event_count", "failed_event_count_uplift",
        "failed_window_bytes", "success_job_bytes", "byte_uplift",
    )}


def _validate_width_v2(
    contract_value: object, *, jobs_by_phase: object,
    expected_campaign_id: str | None = None,
    expected_host_id: str | None = None,
    expected_original_pins_sha256: str | None = None,
    expected_plan_pin: object | None = None,
    expected_source_manifest_pin: object | None = None,
    expected_ancestor: object | None = None,
) -> tuple[dict[str, Any], int, int]:
    contract = _exact(contract_value, WIDTH_V2_FIELDS,
                      "prepared exploration journal-width v2 contract")
    body = {key: value for key, value in contract.items()
            if key != "contract_sha256"}
    _require(contract["schema"] == SOURCE5_JOURNAL_WIDTH_CONTRACT_SCHEMA_V2 and
             contract["admission_profile"] ==
                 SOURCE5_PREPARED_EXPLORATION_ADMISSION_PROFILE and
             _digest(contract["contract_sha256"], "prepared width contract digest") ==
                 _sha(_canonical(body)),
             "prepared width-v2 schema/profile/self-digest differs")
    _token(contract["campaign_id"], "prepared width campaign ID")
    _token(contract["host_id"], "prepared width host ID")
    _digest(contract["original_pins_sha256"], "prepared width original-pin digest")
    _require(expected_campaign_id is None or
             contract["campaign_id"] == expected_campaign_id,
             "prepared width campaign differs from its caller-bound context")
    _require(expected_host_id is None or contract["host_id"] == expected_host_id,
             "prepared width host differs from its caller-bound context")
    _require(expected_original_pins_sha256 is None or
             contract["original_pins_sha256"] == expected_original_pins_sha256,
             "prepared width original pins differ from their caller-bound context")
    _full_pin(contract["plan_pin"], "prepared width final Plan pin")
    _full_pin(contract["source_manifest_pin"],
              "prepared width Source manifest pin")
    if expected_plan_pin is not None:
        _require(contract["plan_pin"] == expected_plan_pin,
                 "prepared width final Plan pin differs from selected Plan")
    if expected_source_manifest_pin is not None:
        _require(contract["source_manifest_pin"] == expected_source_manifest_pin,
                 "prepared width Source pin differs from selected Source")
    ancestor = _validate_ancestor(contract["ancestor"])
    if expected_ancestor is not None:
        _require(ancestor == expected_ancestor,
                 "prepared width ancestor differs from freshly replayed lineage")
    jobs = _job_counts(jobs_by_phase)
    exploration_jobs = jobs["exploration"]
    _require(ancestor["job_list_sha256"] == _sha(_canonical(exploration_jobs)),
             "prepared width ancestor does not bind the exact final-Plan exploration rows")
    expected_owner_roles = {
        "fixed_pair", "pressure_pair", "source5_controller", "source5_soak",
        "soak_reader", "offline_dispatcher", "chronology",
        "evidence_transport", "feedback_composer", "feedback_reader",
        "pressure_reader",
    }
    _require(type(contract["owner_pins"]) is dict and
             set(contract["owner_pins"]) == expected_owner_roles,
             "prepared width owner-pin map does not close over its exact source roles")
    for role, pin_value in contract["owner_pins"].items():
        _token(role, "prepared width owner role")
        pin = _exact(pin_value, {"path", "raw_sha256", "byte_count"},
                     f"prepared width owner pin {role}")
        _require(type(pin["path"]) is str and bool(pin["path"]),
                 f"prepared width owner pin {role} path is malformed")
        _digest(pin["raw_sha256"], f"prepared width owner pin {role} raw digest")
        _uint(pin["byte_count"], f"prepared width owner pin {role} byte count", positive=True)
    _require(type(contract["job_rows"]) is list and
             len(contract["job_rows"]) == 16249 and
             type(contract["phase_totals"]) is list and
             len(contract["phase_totals"]) == len(PHASES),
             "prepared width-v2 rows do not cover exactly the current local jobs")
    position = 0
    expected_totals = []
    successful_count = 0
    successful_bytes = 0
    winner = None
    maximum_line_bytes = 0
    for phase in PHASES:
        phase_jobs = jobs[phase]
        phase_count = 0
        phase_bytes = 0
        if phase == "exploration":
            expected_totals.append({
                "phase": phase, "job_count": 0, "event_count": 0,
                "success_event_bytes": 0,
            })
            continue
        for job_index, job in enumerate(phase_jobs):
            row = _exact(contract["job_rows"][position], JOB_ROW_FIELDS,
                         f"prepared width {phase} row[{job_index}]")
            position += 1
            expected_counts = _event_counts(phase)
            _require(row["phase"] == phase and row["job_index"] == job_index and
                     row["ordinal"] == job.get("ordinal") and
                     row["run_id"] == job.get("run_id") and
                     row["job_sha256"] == _sha(_canonical(job)) and
                     row["event_counts"] == expected_counts and
                     row["failed_event_counts"] == expected_counts,
                     f"prepared width {phase} row[{job_index}] differs from its exact Plan job")
            success = _exact(row["maximum_event_bytes_by_kind"], set(EVENT_NAMES),
                             "prepared width success event ceilings")
            failed = _exact(row["failed_event_bytes_by_kind"], set(EVENT_NAMES),
                            "prepared width failure event ceilings")
            for name in EVENT_NAMES:
                _uint(success[name], f"prepared width {phase}.{name} success", positive=True)
                _uint(failed[name], f"prepared width {phase}.{name} failure", positive=True)
                _require(success[name] <= MAX_EVENT_BYTES and
                         failed[name] <= MAX_EVENT_BYTES,
                         "prepared width event line exceeds its finite source ceiling")
                maximum_line_bytes = max(maximum_line_bytes, success[name], failed[name])
            success_job_bytes = sum(expected_counts[name] * success[name]
                                    for name in EVENT_NAMES)
            failed_window_bytes = sum(expected_counts[name] * failed[name]
                                      for name in EVENT_NAMES)
            count = sum(expected_counts.values())
            _require(row["success_job_bytes"] == success_job_bytes and
                     row["failed_window_bytes"] == failed_window_bytes and
                     row["failed_event_count"] == count and
                     row["failed_event_count_uplift"] == 0 and
                     row["byte_uplift"] == max(0, failed_window_bytes-success_job_bytes),
                     f"prepared width {phase} event or failure arithmetic differs")
            phase_count += count
            phase_bytes += success_job_bytes
            candidate = _candidate(row)
            if winner is None or (candidate["byte_uplift"],
                                  candidate["failed_event_count_uplift"]) > (
                                      winner["byte_uplift"],
                                      winner["failed_event_count_uplift"]):
                winner = candidate
        expected_totals.append({
            "phase": phase, "job_count": len(phase_jobs),
            "event_count": phase_count,
            "success_event_bytes": phase_bytes,
        })
        successful_count += phase_count
        successful_bytes += phase_bytes
    _require(position == len(contract["job_rows"]) and
             contract["phase_totals"] == expected_totals,
             "prepared width-v2 phase totals or row order differ from the current Plan")
    fixed_rows = contract["fixed_event_widths"]
    _require(type(fixed_rows) is list and len(fixed_rows) == len(FIXED_IDENTITIES),
             "prepared width-v2 fixed events omit a current setup or analysis event")
    fixed_count = 0
    fixed_bytes = 0
    for index, (row_value, identity) in enumerate(zip(
            fixed_rows, FIXED_IDENTITIES, strict=True)):
        row = _exact(row_value, FIXED_ROW_FIELDS,
                     f"prepared width fixed row[{index}]")
        width = _uint(row["maximum_line_bytes"],
                      f"prepared width fixed row[{index}] bytes", positive=True)
        _require((row["event"], row["phase"]) == identity and
                 row["count"] == 1 and width <= MAX_EVENT_BYTES,
                 f"prepared width fixed row[{index}] identity/width differs")
        fixed_count += 1
        fixed_bytes += width
        maximum_line_bytes = max(maximum_line_bytes, width)
    _require(winner is not None and contract["failed_owner_window"] == winner,
             "prepared width failure owner window is not the current local maximum")
    expected_event_count = fixed_count + successful_count
    expected_event_bytes = fixed_bytes + successful_bytes + max(0, winner["byte_uplift"])
    _require(expected_event_count == 97499 and
             contract["total_event_count"] == expected_event_count and
             contract["total_event_bytes"] == expected_event_bytes,
             "prepared width-v2 current event horizon or byte sum differs")
    _uint(contract["total_event_bytes"], "prepared width total bytes", positive=True)
    return contract, expected_event_count, maximum_line_bytes


def build_prepared_exploration_width_contract_v2(
    width_v1_value: object, *, jobs_by_phase: object,
    ancestor_value: object, expected_campaign_id: str,
    expected_host_id: str, expected_original_pins_sha256: str,
    expected_plan_pin: object, expected_source_manifest_pin: object,
) -> dict[str, Any]:
    """Project a source-derived full v1 width into the current-only v2 horizon."""
    base = _exact(width_v1_value, WIDTH_V1_FIELDS,
                  "source-derived journal-width v1 contract")
    body = {key: value for key, value in base.items() if key != "contract_sha256"}
    _require(base["schema"] == SOURCE5_JOURNAL_WIDTH_CONTRACT_SCHEMA_V1 and
             _digest(base["contract_sha256"], "source-derived width v1 digest") ==
                 _sha(_canonical(body)),
             "source-derived width v1 contract schema/digest differs")
    jobs = _job_counts(jobs_by_phase)
    ancestor = _validate_ancestor(ancestor_value)
    _require(ancestor["job_list_sha256"] == _sha(_canonical(jobs["exploration"])),
             "prepared ancestor does not match original exploration Plan rows")
    base_rows = base["job_rows"]
    _require(type(base_rows) is list and len(base_rows) == 16609,
             "source-derived width v1 does not close over the full logical Plan")
    current_rows = []
    cursor = 0
    for phase in PHASES:
        source_rows = [row for row in base_rows if type(row) is dict and
                       row.get("phase") == phase]
        _require(len(source_rows) == len(jobs[phase]),
                 f"source-derived width v1 {phase} rows differ from original Plan count")
        if phase == "exploration":
            continue
        for job_index, job in enumerate(jobs[phase]):
            row = source_rows[job_index]
            _require(row.get("job_index") == job_index and
                     row.get("ordinal") == job.get("ordinal") and
                     row.get("run_id") == job.get("run_id") and
                     row.get("job_sha256") == _sha(_canonical(job)),
                     f"source-derived width v1 {phase} row[{job_index}] differs from Plan")
            current_rows.append(row)
            cursor += 1
    _require(cursor == 16249,
             "prepared width v2 projection did not retain the exact current rows")
    phase_totals = []
    for phase in PHASES:
        if phase == "exploration":
            phase_totals.append({"phase": phase, "job_count": 0,
                                 "event_count": 0, "success_event_bytes": 0})
        else:
            source = next(row for row in base["phase_totals"]
                          if type(row) is dict and row.get("phase") == phase)
            phase_totals.append(dict(source))
    projected = {key: value for key, value in base.items()
                 if key in WIDTH_V1_FIELDS - {"schema", "job_rows", "phase_totals",
                                              "total_event_count", "total_event_bytes",
                                              "failed_owner_window", "contract_sha256"}}
    projected.update({
        "schema": SOURCE5_JOURNAL_WIDTH_CONTRACT_SCHEMA_V2,
        "admission_profile": SOURCE5_PREPARED_EXPLORATION_ADMISSION_PROFILE,
        "job_rows": current_rows,
        "phase_totals": phase_totals,
        "fixed_event_widths": base["fixed_event_widths"],
        "ancestor": ancestor,
    })
    successful_count = sum(row["event_count"] for row in phase_totals)
    successful_bytes = sum(row["success_event_bytes"] for row in phase_totals)
    fixed_count = sum(row["count"] for row in projected["fixed_event_widths"])
    fixed_bytes = sum(row["count"] * row["maximum_line_bytes"]
                      for row in projected["fixed_event_widths"])
    winner = None
    for row in current_rows:
        candidate = _candidate(row)
        if winner is None or (candidate["byte_uplift"],
                              candidate["failed_event_count_uplift"]) > (
                                  winner["byte_uplift"],
                                  winner["failed_event_count_uplift"]):
            winner = candidate
    _require(winner is not None,
             "prepared width v2 has no current owner failure window")
    projected["failed_owner_window"] = winner
    projected["total_event_count"] = fixed_count + successful_count
    projected["total_event_bytes"] = (
        fixed_bytes + successful_bytes + max(0, winner["byte_uplift"])
    )
    _require(projected["campaign_id"] == expected_campaign_id and
             projected["host_id"] == expected_host_id and
             projected["original_pins_sha256"] == expected_original_pins_sha256 and
             projected["plan_pin"] == expected_plan_pin and
             projected["source_manifest_pin"] == expected_source_manifest_pin,
             "prepared width v2 projection input pins differ from selected final context")
    projected["contract_sha256"] = _sha(_canonical(projected))
    _validate_width_v2(
        projected, jobs_by_phase=jobs,
        expected_campaign_id=expected_campaign_id,
        expected_host_id=expected_host_id,
        expected_original_pins_sha256=expected_original_pins_sha256,
        expected_plan_pin=expected_plan_pin,
        expected_source_manifest_pin=expected_source_manifest_pin,
        expected_ancestor=ancestor,
    )
    return projected


def validate_prepared_exploration_width_contract_v2(
    value: object, *, jobs_by_phase: object,
    expected_campaign_id: str | None = None,
    expected_host_id: str | None = None,
    expected_original_pins_sha256: str | None = None,
    expected_plan_pin: object | None = None,
    expected_source_manifest_pin: object | None = None,
    expected_ancestor: object | None = None,
) -> tuple[dict[str, Any], int, int]:
    """Validate current-only rows while retaining the full logical Plan hash."""
    return _validate_width_v2(
        value, jobs_by_phase=jobs_by_phase,
        expected_campaign_id=expected_campaign_id,
        expected_host_id=expected_host_id,
        expected_original_pins_sha256=expected_original_pins_sha256,
        expected_plan_pin=expected_plan_pin,
        expected_source_manifest_pin=expected_source_manifest_pin,
        expected_ancestor=expected_ancestor,
    )


def prepared_exploration_logical_horizon(
    jobs_by_phase: object, ancestor_value: object,
) -> dict[str, int]:
    """Derive logical/current counts from exact Plan rows and checked ancestry."""
    jobs = _job_counts(jobs_by_phase)
    ancestor = _validate_ancestor(ancestor_value)
    _require(ancestor["job_list_sha256"] == _sha(_canonical(jobs["exploration"])),
             "prepared logical horizon does not match the exact exploration Plan rows")
    current_jobs = sum(len(jobs[phase]) for phase in PHASES if phase != "exploration")
    current_callbacks = sum(
        len(jobs[phase]) * sum(_event_counts(phase).values())
        for phase in PHASES if phase != "exploration"
    )
    logical_jobs = current_jobs + len(jobs["exploration"])
    logical_callbacks = current_callbacks + 2160
    current_rows = current_callbacks + 7
    _require((len(jobs["exploration"]), current_jobs, logical_jobs,
              current_callbacks, logical_callbacks, current_rows,
              ancestor["journal"]["record_count"] + current_rows) ==
             (360, 16249, 16609, 97492, 99652, 97499, 99660),
             "prepared logical/current horizon arithmetic differs from the frozen protocol")
    # Existing Source5 summary counts include the one setup event and six
    # analysis events in the callback total: 99,659 logical callbacks.
    logical_callbacks += 7
    _require(logical_callbacks == 99659,
             "prepared logical callback count does not include the seven fixed events")
    return {
        "ancestor_job_count": len(jobs["exploration"]),
        "current_job_count": current_jobs,
        "logical_job_count": logical_jobs,
        "ancestor_callback_count": 2160,
        "current_job_callback_count": current_callbacks,
        "current_event_count": current_rows,
        "logical_callback_count": logical_callbacks,
        "ancestor_physical_record_count": ancestor["journal"]["record_count"],
        "combined_physical_record_count": ancestor["journal"]["record_count"] + current_rows,
    }


def prepared_exploration_primary_origin_pins(
    *, source_manifest_pin: object, plan_pin: object,
    host_budget_pin: object, execution_manifest_pin: object,
    journal_width_contract_pin: object, spec_pin: object,
) -> list[dict[str, Any]]:
    """Build the exact V5 six-primary Root transport closure in order."""
    roles_and_values = (
        ("source_manifest", source_manifest_pin),
        ("plan", plan_pin),
        ("host_budget", host_budget_pin),
        ("execution_manifest", execution_manifest_pin),
        ("journal_width_contract", journal_width_contract_pin),
        ("spec_v3", spec_pin),
    )
    result = []
    seen_paths = set()
    for role, value in roles_and_values:
        pin = _exact(value, {"path", "raw_sha256", "semantic_sha256"},
                     f"V5 {role} primary pin")
        _pin({"path": pin["path"], "raw_sha256": pin["raw_sha256"]},
             f"V5 {role} primary raw pin")
        _digest(pin["semantic_sha256"], f"V5 {role} primary semantic digest")
        _require(pin["path"] not in seen_paths,
                 "V5 primary documents alias one origin path")
        seen_paths.add(pin["path"])
        result.append({"role": role, "pin": dict(pin)})
    return result


def build_prepared_exploration_capture_declaration_v1(
    expected_host_ids: object, proofs_by_host: object, *,
    artifact_reader: Callable[[dict[str, str], int], bytes],
    evidence_budget_module: object,
) -> dict[str, Any]:
    """Derive the full retained-origin closure from SourceA proof/catalogues.

    Every role and cap comes from the proof-bound old path catalogue or the
    exact validated index/header pin. The reader supplies bytes only; this
    routine verifies raw hashes and counts before emitting a declaration.
    """
    _require(type(expected_host_ids) is list and len(expected_host_ids) in (2, 3) and
             all(type(host) is str and _TOKEN.fullmatch(host) is not None
                 for host in expected_host_ids) and
             len(set(expected_host_ids)) == len(expected_host_ids),
             "prepared capture host order is malformed")
    _require(type(proofs_by_host) is dict and
             set(proofs_by_host) == set(expected_host_ids) and
             callable(artifact_reader),
             "prepared capture proofs do not close over the selected host order")
    typed_pin = getattr(evidence_budget_module, "__source5_typed_pin__", None)
    _require(type(typed_pin) is dict and
             typed_pin.get("path") == "scripts/application-source5-evidence-budget.py" and
             callable(getattr(evidence_budget_module,
                              "verify_path_catalogue_chunks_with_reader", None)) and
             callable(getattr(evidence_budget_module,
                              "iter_path_catalogue_rows_with_reader", None)) and
             callable(getattr(evidence_budget_module,
                              "source5_indexed_reservation_binding_v1", None)) and
             callable(getattr(evidence_budget_module,
                              "source5_preparatory_shared_originals_v1", None)) and
             type(getattr(evidence_budget_module, "BudgetPlanError", None)) is type and
             issubclass(evidence_budget_module.BudgetPlanError, Exception),
             "prepared capture requires the selected typed path-catalogue algorithm")

    cohort_inputs = []
    for host in expected_host_ids:
        proof = proofs_by_host[host]
        _require(type(proof) is dict and
                 proof.get("schema") ==
                    "allocatbelt.application-source5-prepared-exploration-lineage-proof.v2" and
                 proof.get("host_id") == host and
                 type(proof.get("bridge_header")) is dict and
                 type(proof.get("capture_context")) is dict,
                 f"prepared capture {host} proof is incomplete")
        context = _exact(proof["capture_context"], {
            "execution_manifest", "width_contract", "budget",
            "preparatory_original_pins",
        }, f"prepared capture {host} SourceA context")
        cohort_inputs.append({
            "host_id": host,
            "original_pins": context["preparatory_original_pins"],
            "execution_manifest": context["execution_manifest"],
            "header": proof["bridge_header"],
        })
    try:
        cohort_shared_originals = \
            evidence_budget_module.source5_preparatory_shared_originals_v1(
                cohort_inputs,
            )
    except evidence_budget_module.BudgetPlanError as error:
        raise PreparedBridgeBudgetError(str(error)) from error

    descriptors: dict[tuple[str, str], dict[str, Any]] = {}
    per_host_counts = {
        host: {role: 0 for role in (
            "evidence_index", "journal", "source5_phase_ledger",
            "source_manifest", "observed_host", "host_evidence_budget",
            "journal_width_contract", "capacity_artifact", "preparation",
            "source5_job_row_catalogue", "source5_archive_signer_context",
            "fixed_spec_host",
        )}
        for host in expected_host_ids
    }
    global_counts = {role: 0 for role in (
        "spec_v3", "plan_v3", "execution_manifest",
        "source5_archive_signer_keyring", "source5_archive_signer_gpgv",
    )}
    indexed_counts = {host: 0 for host in expected_host_ids}
    global_roles = {
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
    phase_roles = {
        "source5_job_record", "source5_checkpoint_request", "source5_checkpoint",
        "source5_object_manifest", "source5_archive_ack",
        "source5_archive_signature",
    }

    def bounded_read(pin: dict[str, str], maximum: int, label: str) -> bytes:
        try:
            raw = artifact_reader(dict(pin), maximum)
        except Exception as error:
            raise PreparedBridgeBudgetError(
                f"{label} is unavailable from the closed captured reader",
            ) from error
        _require(type(raw) is bytes and 0 < len(raw) <= maximum and
                 _sha(raw) == pin["raw_sha256"],
                 f"{label} captured bytes differ from their raw pin/cap")
        return raw

    def raw_pin_projection(value: object, label: str) -> dict[str, str]:
        return source_raw_pin_projection(value, label)

    def add(
        pin_value: object, role: str, host: str | None, maximum: int,
        *, phase: str | None = None, run_id: str | None = None,
        row_index: int | None = None, job_sha256: str | None = None,
        label: str,
    ) -> bytes:
        pin = raw_pin_projection(pin_value, f"{label} origin pin")
        maximum = _uint(maximum, f"{label} source cap", positive=True)
        role = _token(role, f"{label} role")
        if role in {"spec_v3", "plan_v3", "execution_manifest",
                    "source5_archive_signer_keyring", "source5_archive_signer_gpgv"}:
            host = None
        if host is not None:
            _token(host, f"{label} host ID")
        if phase is None:
            _require(run_id is None and row_index is None and job_sha256 is None,
                     f"{label} global descriptor has a job join")
        else:
            _require(phase == "exploration" and host in indexed_counts and
                     type(run_id) is str and type(row_index) is int and
                     0 <= row_index < PREPARED_EXPLORATION_JOB_COUNT and
                     type(job_sha256) is str,
                     f"{label} indexed descriptor join is malformed")
            _digest(job_sha256, f"{label} job digest")
        raw = bounded_read(pin, maximum, label)
        key = (pin["path"], pin["raw_sha256"])
        descriptor = {
            "origin_pin": pin, "role": role, "host_id": host,
            "maximum_bytes": maximum, "byte_count": len(raw),
            "phase": phase, "run_id": run_id,
            "row_index": row_index, "job_sha256": job_sha256,
        }
        prior = descriptors.get(key)
        if prior is not None:
            _require(prior == descriptor,
                     f"prepared capture origin {pin['path']} has conflicting source roles/joins")
            return raw
        descriptors[key] = descriptor
        if phase is not None:
            indexed_counts[host] += 1
        elif host in per_host_counts and role in per_host_counts[host]:
            per_host_counts[host][role] += 1
        if phase is None and role in global_counts:
            global_counts[role] += 1
        return raw

    for host in expected_host_ids:
        proof = proofs_by_host[host]
        _require(type(proof) is dict and
                 proof.get("schema") ==
                    "allocatbelt.application-source5-prepared-exploration-lineage-proof.v2" and
                 proof.get("host_id") == host and
                 proof.get("qualification_eligible") is False and
                 proof.get("component_replay_required") is True and
                 type(proof.get("bridge_header")) is dict and
                 type(proof.get("index_rows")) is list and
                 len(proof["index_rows"]) == PREPARED_EXPLORATION_JOB_COUNT and
                 type(proof.get("capture_context")) is dict,
                 f"prepared capture {host} proof is incomplete or authorizing")
        header = proof["bridge_header"]
        context = _exact(proof["capture_context"], {
            "execution_manifest", "width_contract", "budget",
            "preparatory_original_pins",
        }, f"prepared capture {host} SourceA context")
        old_budget = context["budget"]
        _require(type(old_budget) is dict and
                 old_budget.get("schema") ==
                    "allocatbelt.application-source5-preparatory-exploration-budget.v1" and
                 old_budget.get("budget_sha256") ==
                    _sha(_canonical({key: value for key, value in old_budget.items()
                                     if key != "budget_sha256"})),
                 f"prepared capture {host} old budget self-digest differs")
        old_catalogue = evidence_budget_module.validate_fixed_pair_v3_path_catalogue_manifest(
            old_budget.get("path_catalogue"),
        )
        chunk_by_path = {row["path"]: row for row in old_catalogue["chunks"]}

        def read_chunk(path: str, maximum: int) -> bytes:
            chunk = chunk_by_path.get(path)
            _require(type(chunk) is dict and maximum == chunk["byte_count"],
                     "prepared capture old catalogue requested an undeclared chunk")
            return bounded_read(
                {"path": path, "raw_sha256": chunk["raw_sha256"]},
                maximum, "prepared capture old catalogue chunk",
            )

        old_catalogue = evidence_budget_module.verify_fixed_pair_v3_path_catalogue_chunks_with_reader(
            old_catalogue, read_chunk,
        )
        original = context["preparatory_original_pins"]
        _require(type(original) is dict,
                 f"prepared capture {host} original pins are malformed")
        _require(original == old_budget.get("original_pins"),
                 f"prepared capture {host} SourceH pins differ from its old budget")
        original = _exact(original, {
            "preparation", "capacity_generation", "initial_spec", "initial_plan",
            "source_manifests", "observed_hosts", "typed_modules",
            "archive_signer_context", "capacity_registration",
            "execution_basis_sha256",
        }, f"prepared capture {host} SourceH original pins")
        shared_originals = cohort_shared_originals
        source_rows = header["initial"]["source_manifest_pins"]
        _require(type(source_rows) is list and
                 len(source_rows) == len(expected_host_ids),
                 f"prepared capture {host} header Source cohort differs")
        source_map = {}
        for source_host, source_value in zip(expected_host_ids, source_rows, strict=True):
            source_map[source_host] = _source_manifest_pin_projection(
                source_value, source_host,
                f"prepared capture {host} header {source_host} Source pin",
            )
        original_source_map = _exact(
            original.get("source_manifests"), set(expected_host_ids),
            f"prepared capture {host} original Source manifest pins",
        )
        for source_host in expected_host_ids:
            original_source = _original_source_manifest_pin_projection(
                original_source_map[source_host], source_host,
                f"prepared capture {host} original {source_host} Source pin",
            )
            _require(original_source == source_map[source_host],
                     f"prepared capture {host} changed {source_host} original Source pin")

        # Source-derived global catalogue rows provide exact roles/caps. The
        # two bridge files are special: their raw pins come from the validated
        # header/index proof while their reservation caps come from the same
        # old catalogue rows.
        old_rows: dict[str, dict[str, Any]] = {}
        for row in evidence_budget_module.iter_fixed_pair_v3_path_catalogue_rows_with_reader(
                old_catalogue, read_chunk):
            if row["kind"] == "file" and row["role"] in global_roles:
                old_rows[row["path"]] = row

        unpinned_source_roles = {
            "preparation", "evidence_index", "journal",
            "source5_phase_ledger", "capacity_artifact",
            "host_evidence_budget",
        }

        def source_catalogue_row(
            pin_value: object, role: str, expected_host: str | None,
            label: str, *, allow_unpinned_origin: bool = False,
        ) -> tuple[dict[str, str], dict[str, Any]]:
            pin = raw_pin_projection(pin_value, f"{label} origin pin")
            row = old_rows.get(pin["path"])
            _require(type(row) is dict and row["kind"] == "file" and
                     _old_catalogue_role_matches(role, row["role"]) and
                     _old_catalogue_host_matches(row["host_id"], expected_host, host) and
                     row["max_file_bytes"] > 0,
                     f"prepared capture {host} {label} differs from its old Source catalogue role/host/cap")
            origin = row.get("origin_pin")
            if origin is None:
                _require(role in unpinned_source_roles or allow_unpinned_origin,
                         f"prepared capture {host} {label} lacks its old Source raw origin binding")
            else:
                origin = _exact(origin, {"raw_sha256", "semantic_sha256"},
                                f"prepared capture {host} {label} old Source origin")
                _require(origin["raw_sha256"] == pin["raw_sha256"] and
                         (type(pin_value) is not dict or
                          "semantic_sha256" not in pin_value or
                          origin["semantic_sha256"] is None or
                          origin["semantic_sha256"] == pin_value["semantic_sha256"]),
                         f"prepared capture {host} {label} differs from its old Source origin pin")
            return pin, row

        header_pin = proof["bridge_header_pin"]
        index_pin = proof["record_index_pin"]
        for pin_value, role, label in (
            (header_pin, "preparation", "bridge header"),
            (index_pin, "evidence_index", "record index"),
        ):
            pin, row = source_catalogue_row(
                pin_value, role, host, f"{host} {label}",
            )
            captured_raw = add(
                pin, role, host, row["max_file_bytes"], label=f"{host} {label}",
            )
            if role == "preparation":
                _require(captured_raw == _canonical(header),
                         f"prepared capture {host} proof header differs from its captured bytes")
            else:
                _require(captured_raw == b"".join(
                    _canonical(row) for row in proof["index_rows"]
                ), f"prepared capture {host} proof index rows differ from their captured bytes")

        special_global_pins = [
            (header["journal"]["pin"], "journal", host),
            (header["phase_ledger"]["pin"], "source5_phase_ledger", host),
            (header["pilot"]["pin"], "capacity_artifact", host),
            (header["initial"]["host_budget_pin"], "host_evidence_budget", host),
            (header["initial"]["journal_width_pin"],
             "journal_width_contract", host),
            (header["initial"]["fixed_spec_host_pin"], "fixed_spec_host", host),
            (header["initial"]["signer_context_pin"],
             "source5_archive_signer_context", host),
        ]
        execution_pin = header["initial"]["execution_manifest_pin"]
        spec_pin = header["initial"]["spec_pin"]
        plan_pin = header["initial"]["plan_pin"]
        special_global_pins.extend((
            (execution_pin, "execution_manifest", None),
            (spec_pin, "spec_v3", None),
            (plan_pin, "plan_v3", None),
        ))
        special_global_pins.append((header["initial"]["observed_host_pin"],
                                    "observed_host", host))
        for source_host, pin in source_map.items():
            special_global_pins.append((pin, "source_manifest", source_host))
        special_global_paths = {value[0]["path"] for value in special_global_pins}
        for pin_value, role, pin_host in special_global_pins:
            label = f"prepared capture {host} {role}"
            if role == "source_manifest":
                checked = _source_manifest_pin_projection(pin_value, pin_host, label)
                catalogue_pin = {key: checked[key] for key in (
                    "path", "raw_sha256", "semantic_sha256",
                )}
            elif role == "observed_host":
                catalogue_pin = _observed_host_pin_projection(pin_value, label)
            elif role == "execution_manifest":
                execution = _exact(pin_value, {
                    "path", "raw_sha256", "semantic_sha256",
                }, label)
                execution_pin = _full_pin(execution, label)
                execution_value = context["execution_manifest"]
                _require(type(execution_value) is dict and
                         type(execution_value.get("manifest_sha256")) is str and
                         execution_value.get("campaign_id") == old_budget.get("campaign_id") and
                         execution_value.get("host_id") == host and
                         execution_value["manifest_sha256"] ==
                            execution_pin["semantic_sha256"] ==
                            _sha(_canonical({
                                key: value for key, value in execution_value.items()
                                if key != "manifest_sha256"
                            })),
                         f"prepared capture {host} execution manifest differs from its exact header/source pins")
                catalogue_pin = execution_pin
            elif role in {
                "host_evidence_budget", "journal_width_contract",
                "fixed_spec_host", "source5_archive_signer_context",
                "spec_v3", "plan_v3", "capacity_artifact",
            }:
                catalogue_pin = _full_pin(pin_value, label)
            else:
                catalogue_pin = _pin(pin_value, label)
            pin, source_row = source_catalogue_row(
                catalogue_pin, role, pin_host, label,
                allow_unpinned_origin=(role == "execution_manifest"),
            )
            if role == "source_manifest" and source_row["origin_pin"] is not None:
                _require(source_row["origin_pin"]["semantic_sha256"] ==
                         checked["semantic_sha256"],
                         f"prepared capture {host} Source manifest semantic origin differs")
            captured_raw = add(
                pin, role, pin_host, source_row["max_file_bytes"],
                label=f"{host} {role}",
            )
            if role == "host_evidence_budget":
                _require(captured_raw == _canonical(old_budget),
                         f"prepared capture {host} host budget differs from SourceA capture context")
            elif role == "journal_width_contract":
                _require(captured_raw == _canonical(context["width_contract"]),
                         f"prepared capture {host} width contract differs from SourceA capture context")
            elif role == "execution_manifest":
                _require(captured_raw == _canonical(context["execution_manifest"]),
                         f"prepared capture {host} execution manifest differs from SourceA capture context")

        signer_pin = _full_pin(header["initial"]["signer_context_pin"],
                               f"{host} old signer context")
        signer_pin_raw, signer_row = source_catalogue_row(
            signer_pin, "source5_archive_signer_context", host,
            f"{host} old signer context",
        )
        signer_raw = bounded_read(signer_pin_raw,
                                  signer_row["max_file_bytes"],
                                  f"{host} old signer context")
        try:
            signer_context = json.loads(signer_raw)
        except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
            raise PreparedBridgeBudgetError(
                f"prepared capture {host} old signer context is malformed",
            ) from error
        _require(type(signer_context) is dict and signer_raw == _canonical(signer_context),
                 f"prepared capture {host} old signer context is noncanonical")
        for field, role in (("keyring_pin", "source5_archive_signer_keyring"),
                            ("gpgv_pin", "source5_archive_signer_gpgv")):
            pin, source_row = source_catalogue_row(
                signer_context[field], role, None,
                f"{host} old signer {field}",
            )
            add(pin, role, None, source_row["max_file_bytes"],
                label=f"{host} old signer {field}")

        # Preserve host joins for every retained input except the exact
        # SourceH preparation intent and capacity-generation completion. Those
        # two pins are one shared, provenance-checked input for the cohort.
        shared_rows = {
            shared_originals["preparation"]["path"]: (
                "preparation", shared_originals["preparation"]["raw_sha256"], None,
            ),
            shared_originals["capacity_generation"]["path"]: (
                "capacity_completion",
                shared_originals["capacity_generation"]["raw_sha256"],
                shared_originals["capacity_generation"]["semantic_sha256"],
            ),
        }
        shared_rows_seen: set[str] = set()
        for path, row in old_rows.items():
            role = row["role"]
            if (role not in global_roles or row.get("phase") is not None or
                    path in special_global_paths or
                    path in {header_pin["path"], index_pin["path"]}):
                continue
            origin = row.get("origin_pin")
            if type(origin) is not dict or type(origin.get("raw_sha256")) is not str:
                _require(path not in shared_rows,
                         f"prepared capture {host} shared SourceH origin is not raw-pinned")
                continue
            pin = {"path": path, "raw_sha256": origin["raw_sha256"]}
            descriptor_host = row.get("host_id")
            shared_row = shared_rows.get(path)
            if shared_row is not None:
                shared_role, shared_raw, shared_semantic = shared_row
                _require(role == shared_role and row.get("host_id") == host and
                         row.get("owner") == {
                             "preparation": "inputs",
                             "capacity_completion": "capacity_stage",
                         }[shared_role] and
                         row.get("phase") is None and row.get("run_id") is None and
                         pin["raw_sha256"] == shared_raw and
                         origin.get("semantic_sha256") == shared_semantic,
                         f"prepared capture {host} shared SourceH row differs from its exact pin/provenance")
                descriptor_host = None
                shared_rows_seen.add(shared_role)
            if role in {"spec_v3", "plan_v3", "execution_manifest",
                        "source5_archive_signer_keyring", "source5_archive_signer_gpgv"}:
                descriptor_host = None
            add(pin, role, descriptor_host, row["max_file_bytes"],
                label=f"{host} retained global {role}")
        _require(shared_rows_seen == {"preparation", "capacity_completion"},
                 f"prepared capture {host} old catalogue omits a shared SourceH origin")

        index_rows = proof["index_rows"]
        for row_index, index_row in enumerate(index_rows):
            job = index_row["job"]
            job_sha = index_row["job_sha256"]
            _require(type(job) is dict and job.get("phase") == "exploration" and
                     job.get("host_id") == host and index_row.get("row_index") == row_index and
                     job_sha == _sha(_canonical(job)),
                     f"prepared capture {host} index row[{row_index}] changed its Plan join")
            archive = index_row["archive_pins"]
            entries = (
                (index_row["job_record_pin"], "source5_job_record"),
                *((archive[key], role) for key, role in (
                    ("request_pin", "source5_checkpoint_request"),
                    ("checkpoint_pin", "source5_checkpoint"),
                    ("object_manifest_pin", "source5_object_manifest"),
                    ("ack_pin", "source5_archive_ack"),
                    ("signature_pin", "source5_archive_signature"),
                )),
            )
            roles_for_row: set[str] = set()
            for pin_value, expected_role in entries:
                label = f"prepared capture {host} indexed {expected_role}[{row_index}]"
                pin, source_row = _source5_indexed_reservation_binding(
                    index_row, pin_value, expected_role, job,
                    initial_output_root=header["initial_output_root"],
                    campaign_id=header["campaign_id"],
                    selected_host=host, old_rows=old_rows,
                    evidence_budget_module=evidence_budget_module,
                )
                _require(source_row["host_id"] == host and
                         source_row["phase"] == "exploration" and
                         source_row["run_id"] == job["run_id"] and
                         source_row["role"] == expected_role and
                         source_row["role"] in phase_roles,
                         f"prepared capture {host} indexed object is outside its old Plan catalogue row")
                _require(expected_role not in roles_for_row,
                         f"prepared capture {host} row[{row_index}] repeats an indexed role")
                roles_for_row.add(expected_role)
                add(pin, expected_role, host,
                    source_row["max_file_bytes"], phase="exploration",
                    run_id=job["run_id"], row_index=row_index,
                    job_sha256=job_sha,
                    label=f"{host} indexed {expected_role}[{row_index}]")
            _require(roles_for_row == phase_roles,
                     f"prepared capture {host} row[{row_index}] lacks its exact six metadata roles")

        for chunk in old_catalogue["chunks"]:
            pin = {"path": chunk["path"], "raw_sha256": chunk["raw_sha256"]}
            raw = bounded_read(pin, chunk["byte_count"],
                               f"{host} old job-row catalogue chunk")
            _require(len(raw) == chunk["byte_count"],
                     f"{host} old catalogue chunk actual byte count differs")
            add(pin, "source5_job_row_catalogue", host, chunk["byte_count"],
                label=f"{host} old job-row catalogue chunk")
        indexed_counts[host] = sum(
            1 for descriptor in descriptors.values()
            if descriptor["host_id"] == host and descriptor["phase"] == "exploration"
        )

    _require(type(cohort_shared_originals) is dict,
             "prepared capture has no verified shared SourceH cohort origins")
    for role, pin in (
        ("preparation", cohort_shared_originals["preparation"]),
        ("capacity_completion", cohort_shared_originals["capacity_generation"]),
    ):
        descriptor = descriptors.get((pin["path"], pin["raw_sha256"]))
        _require(type(descriptor) is dict and descriptor["role"] == role and
                 descriptor["host_id"] is None and descriptor["phase"] is None and
                 descriptor["run_id"] is None,
                 f"prepared capture shared SourceH {role} was not projected once at cohort scope")

    required_per_host = {
        "evidence_index", "journal", "source5_phase_ledger", "source_manifest",
        "observed_host", "host_evidence_budget", "journal_width_contract",
        "fixed_spec_host",
    }
    _require(all(indexed_counts[host] == 2160 and
                 all(per_host_counts[host][role] == 1 for role in required_per_host) and
                 per_host_counts[host]["capacity_artifact"] >= 1 and
                 per_host_counts[host]["preparation"] >= 1 and
                 per_host_counts[host]["source5_job_row_catalogue"] >= 1 and
                 per_host_counts[host]["source5_archive_signer_context"] >= 1
                 for host in expected_host_ids) and
             all(global_counts[role] >= 1 for role in global_counts),
             "prepared capture descriptor closure omits required per-host/global origins")
    objects = sorted(descriptors.values(),
                     key=lambda row: (row["origin_pin"]["path"],
                                      row["origin_pin"]["raw_sha256"]))
    return {
        "schema": SOURCE5_PREPARED_EXPLORATION_CAPTURE_DECLARATION_SCHEMA_V1,
        "cohort_host_ids": list(expected_host_ids), "objects": objects,
    }


def _prepared_exploration_metadata_storage_declarations(
    capture_declaration: object, *, expected_host_ids: object,
    expected_ancestors: object, expected_exploration_jobs: object,
    artifact_reader: Callable[[dict[str, str], int], bytes],
) -> list[dict[str, Any]]:
    """Privately validate a rebuilt declaration and project its exact rows.

    The production entry point below first reconstructs the declaration from
    SourceA proofs and the pinned old catalogue; this helper only checks its
    captured raw bytes and storage-row projection.
    """
    declaration = _exact(capture_declaration, {
        "schema", "cohort_host_ids", "objects",
    },
                         "prepared lineage capture declaration")
    _require(type(expected_host_ids) is list and len(expected_host_ids) in (2, 3) and
             all(type(host) is str and _TOKEN.fullmatch(host) is not None
                 for host in expected_host_ids) and
             len(set(expected_host_ids)) == len(expected_host_ids),
             "prepared lineage expected host order is malformed")
    _require(type(expected_ancestors) is dict and
             set(expected_ancestors) == set(expected_host_ids),
             "prepared lineage ancestor map does not close over its host order")
    _require(type(expected_exploration_jobs) is dict and
             set(expected_exploration_jobs) == set(expected_host_ids),
             "prepared lineage exploration-job map does not close over its host order")
    _require(declaration["cohort_host_ids"] == expected_host_ids,
             "prepared lineage declaration host order differs from selected Spec")
    ancestors = {host: _validate_ancestor(expected_ancestors[host])
                 for host in expected_host_ids}
    jobs_by_host = {}
    for host in expected_host_ids:
        jobs = expected_exploration_jobs[host]
        _require(type(jobs) is list and
                 len(jobs) == PREPARED_EXPLORATION_JOB_COUNT and
                 all(type(job) is dict and job.get("phase") == "exploration" and
                     job.get("host_id") == host for job in jobs),
                 f"prepared lineage {host} exploration Plan rows are malformed")
        _require(ancestors[host]["job_list_sha256"] == _sha(_canonical(jobs)),
                 f"prepared lineage {host} ancestor differs from exact exploration Plan rows")
        jobs_by_host[host] = jobs
    _require(declaration["schema"] ==
             SOURCE5_PREPARED_EXPLORATION_CAPTURE_DECLARATION_SCHEMA_V1 and
             type(declaration["objects"]) is list and
             callable(artifact_reader),
             "prepared lineage capture declaration/reader is unsupported")
    rows = []
    previous = None
    origins = set()
    ancestor_origins: dict[tuple[str, str], tuple[str, str, int]] = {}
    for host in expected_host_ids:
        ancestor = ancestors[host]
        ancestor_origins[(ancestor["bridge_header_pin"]["path"],
                          ancestor["bridge_header_pin"]["raw_sha256"])] = (
            host, "preparation", ancestor["header_byte_count"],
        )
        ancestor_origins[(ancestor["record_index_pin"]["path"],
                          ancestor["record_index_pin"]["raw_sha256"])] = (
            host, "evidence_index", ancestor["index_byte_count"],
        )
        journal = ancestor["journal"]
        ancestor_origins[(journal["pin"]["path"],
                          journal["pin"]["raw_sha256"])] = (
            host, "journal", journal["byte_count"],
        )
        ledger = ancestor["phase_ledger"]
        ancestor_origins[(ledger["pin"]["path"],
                          ledger["pin"]["raw_sha256"])] = (
            host, "source5_phase_ledger", ledger["byte_count"],
        )
    seen_ancestor_origins = set()
    indexed_counts = {host: 0 for host in expected_host_ids}
    indexed_roles_by_row: dict[tuple[str, int], set[str]] = {}
    per_host_global_counts = {
        host: {role: 0 for role in (
            "evidence_index", "journal", "source5_phase_ledger",
            "source_manifest", "observed_host", "host_evidence_budget",
            "journal_width_contract", "capacity_artifact",
            "preparation", "source5_job_row_catalogue",
            "source5_archive_signer_context", "fixed_spec_host",
        )}
        for host in expected_host_ids
    }
    required_global_roles = {
        "spec_v3", "plan_v3", "execution_manifest",
        "source5_archive_signer_context", "source5_archive_signer_keyring",
        "source5_archive_signer_gpgv",
    }
    global_role_counts = {role: 0 for role in required_global_roles}
    for index, item_value in enumerate(declaration["objects"]):
        item = _exact(item_value, {
            "origin_pin", "role", "host_id", "maximum_bytes", "byte_count",
            "phase", "run_id", "row_index", "job_sha256",
        }, f"prepared lineage object declaration[{index}]")
        pin = _pin(item["origin_pin"],
                   f"prepared lineage object declaration[{index}] origin")
        key = (pin["path"], pin["raw_sha256"])
        _require(key not in origins and
                 (previous is None or previous < key),
                 "prepared lineage declaration origins are repeated or unordered")
        origins.add(key)
        previous = key
        role = _token(item["role"], f"prepared lineage object[{index}] role")
        host_id = item["host_id"]
        _require(host_id is None or _token(host_id,
                                           f"prepared lineage object[{index}] host ID"),
                 f"prepared lineage object[{index}] host ID is malformed")
        maximum = _uint(item["maximum_bytes"],
                        f"prepared lineage object[{index}] source cap", positive=True)
        expected_count = item["byte_count"]
        if expected_count is not None:
            _uint(expected_count,
                  f"prepared lineage object[{index}] declared actual size", positive=True)
            _require(expected_count <= maximum,
                     f"prepared lineage object[{index}] declared size exceeds its source cap")
        phase, run_id = item["phase"], item["run_id"]
        row_index, job_sha = item["row_index"], item["job_sha256"]
        if phase is None:
            _require(run_id is None and row_index is None and job_sha is None,
                     f"prepared lineage global object[{index}] carries job identity")
            if host_id in per_host_global_counts and role in per_host_global_counts[host_id]:
                per_host_global_counts[host_id][role] += 1
            if role in global_role_counts:
                global_role_counts[role] += 1
        else:
            _require(phase == "exploration" and host_id in jobs_by_host and
                     type(row_index) is int and
                     0 <= row_index < PREPARED_EXPLORATION_JOB_COUNT and
                     type(run_id) is str and type(job_sha) is str and
                     _digest(job_sha, f"prepared lineage object[{index}] job digest") ==
                         _sha(_canonical(jobs_by_host[host_id][row_index])) and
                     run_id == jobs_by_host[host_id][row_index].get("run_id"),
                     f"prepared lineage indexed object[{index}] differs from its Plan row")
            expected_index_roles = {
                "source5_job_record", "source5_checkpoint_request",
                "source5_checkpoint", "source5_object_manifest",
                "source5_archive_ack", "source5_archive_signature",
            }
            _require(role in expected_index_roles,
                     f"prepared lineage indexed object[{index}] has an unsupported Source role")
            role_key = (host_id, row_index)
            roles_for_row = indexed_roles_by_row.setdefault(role_key, set())
            _require(role not in roles_for_row,
                     f"prepared lineage {host_id} row[{row_index}] repeats a metadata role")
            roles_for_row.add(role)
            indexed_counts[host_id] += 1
        ancestor_identity = ancestor_origins.get(key)
        if ancestor_identity is not None:
            expected_host, expected_role, expected_size = ancestor_identity
            _require(host_id == expected_host and role == expected_role and
                     expected_count == expected_size,
                     f"prepared lineage ancestor object[{index}] differs from its fresh proof")
            seen_ancestor_origins.add(key)
        try:
            raw = artifact_reader(dict(pin), maximum)
        except Exception as error:
            raise PreparedBridgeBudgetError(
                f"prepared lineage object[{index}] could not be read from the closed capture store",
            ) from error
        _require(type(raw) is bytes and 0 < len(raw) <= maximum and
                 _sha(raw) == pin["raw_sha256"] and
                 (expected_count is None or len(raw) == expected_count),
                 f"prepared lineage object[{index}] actual bytes differ from exact raw pin/source cap")
        rows.append({
            "path": pin["path"], "kind": "file", "role": role,
            "host_id": host_id, "max_bytes": len(raw),
            "max_file_bytes": len(raw), "max_inodes": 1,
            "storage_root": None, "owner": "inputs", "phase": phase,
            "run_id": run_id, "member_index": None, "aggregate_id": None,
            "aggregate_max_bytes": None,
            "origin_pin": {"raw_sha256": pin["raw_sha256"],
                           "semantic_sha256": None},
        })
    required_per_host = {
        "evidence_index", "journal", "source5_phase_ledger",
        "source_manifest", "observed_host", "host_evidence_budget",
        "journal_width_contract",
        "fixed_spec_host",
    }
    _require(bool(rows) and seen_ancestor_origins == set(ancestor_origins) and
             all(indexed_counts[host] == 2160 for host in expected_host_ids) and
             set(indexed_roles_by_row) == {
                 (host, row_index) for host in expected_host_ids
                 for row_index in range(PREPARED_EXPLORATION_JOB_COUNT)
             } and
             all(roles == {
                 "source5_job_record", "source5_checkpoint_request",
                 "source5_checkpoint", "source5_object_manifest",
                 "source5_archive_ack", "source5_archive_signature",
             } for roles in indexed_roles_by_row.values()) and
             all(all(counts[role] == 1 for role in required_per_host) and
                 counts["capacity_artifact"] >= 1 and
                 counts["preparation"] >= 1 and
                 counts["source5_job_row_catalogue"] >= 1 and
                 counts["source5_archive_signer_context"] >= 1
                 for counts in per_host_global_counts.values()) and
             all(global_role_counts[role] >= 1 for role in required_global_roles),
             "prepared lineage capture declaration omits required per-host/global closure")
    return rows


def build_prepared_exploration_capture_storage_v1(
    expected_host_ids: object, proofs_by_host: object, *,
    expected_ancestors: object, expected_exploration_jobs: object,
    artifact_reader: Callable[[dict[str, str], int], bytes],
    evidence_budget_module: object,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Build and validate capture rows from SourceA proofs in one call.

    Callers cannot submit a free-standing declaration to the production
    metadata projection. The declaration is rebuilt from the pinned old
    catalogue and exact SourceA index rows, then the resulting raw objects are
    read and checked before storage rows are returned.
    """
    declaration = build_prepared_exploration_capture_declaration_v1(
        expected_host_ids, proofs_by_host, artifact_reader=artifact_reader,
        evidence_budget_module=evidence_budget_module,
    )
    rows = _prepared_exploration_metadata_storage_declarations(
        declaration, expected_host_ids=expected_host_ids,
        expected_ancestors=expected_ancestors,
        expected_exploration_jobs=expected_exploration_jobs,
        artifact_reader=artifact_reader,
    )
    _require(declaration.get("cohort_host_ids") == expected_host_ids and
             len(rows) == len(declaration["objects"]),
             "prepared SourceA capture projection differs from its exact object closure")
    return declaration, rows
