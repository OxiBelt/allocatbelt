#!/usr/bin/env python3
"""Pure Source-owned schema and resource projection for recorded replay I/O.

This module performs no I/O and loads no other Source module. It binds a
finite, ordered two-host preparation-read plan to exact source-projected
catalogue caps, pins, and manifest descriptors. The persisted plan contains a
compact ordered index; separate self-pinned chunks retain every complete row
under the unchanged per-document limit. Its output is a resource plan only:
it grants no read authority, verification, numeric result, readiness,
admission, or qualification. A SourceA/Root caller must first validate the
actual H6 budgets/catalogues and independently recompute
``project_fixed_pair_archive_readback_caps`` with its selected typed Source
Budget module before calling this pure projection. It must persist each chunk
at its nonce-derived pin path, bind ``allocation_block_bytes`` to an actual
statvfs observation for the declared scratch device, and supply an explicitly
approved finite ``directory_metadata_reserve_bytes`` for that device and the
plan's directory layout. The directory reserve is an input budget, not a
measured or universal filesystem fact. The planner's DTO checks do not replace
those source-owned validations or filesystem checks.

The 300-second per-window and 24-hour per-operation maxima below are new
bounded-I/O policy ceilings. They are not measured transfer times and do not
change an Original APP deadline or claim a campaign timing result.

The additive prepared-input construction schema has its own acyclic basis,
plan, chunk, and envelope versions. It reuses the same ordered 720-row Source
projection and bounded physical-window accounting, while keeping the final
completion-output reservation separate from payload scratch. Construction
plans remain data-only and do not represent an authenticated completion.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath
from typing import Any


REPLAY_BASIS_SCHEMA_V1 = (
    "allocatbelt.application-source5-recorded-preparation-replay-basis.v1"
)
PREPARED_INPUT_CONSTRUCTION_BASIS_SCHEMA_V1 = (
    "allocatbelt.application-source5-prepared-input-construction-basis.v1"
)
READ_PLAN_SCHEMA_V2 = (
    "allocatbelt.application-source5-recorded-preparation-read-plan.v2"
)
PREPARED_INPUT_CONSTRUCTION_READ_PLAN_SCHEMA_V1 = (
    "allocatbelt.application-source5-prepared-input-construction-read-plan.v1"
)
WINDOW_METADATA_CHUNK_SCHEMA_V1 = (
    "allocatbelt.application-source5-recorded-preparation-read-window-chunk.v1"
)
PREPARED_INPUT_CONSTRUCTION_WINDOW_CHUNK_SCHEMA_V1 = (
    "allocatbelt.application-source5-prepared-input-construction-window-chunk.v1"
)
REQUEST_SCHEMA_V2 = (
    "allocatbelt.application-source5-recorded-preparation-read-request.v2"
)
PREPARED_INPUT_CONSTRUCTION_REQUEST_SCHEMA_V1 = (
    "allocatbelt.application-source5-prepared-input-construction-read-request.v1"
)
RESPONSE_SCHEMA_V2 = (
    "allocatbelt.application-source5-recorded-preparation-read-response.v2"
)
PREPARED_INPUT_CONSTRUCTION_RESPONSE_SCHEMA_V1 = (
    "allocatbelt.application-source5-prepared-input-construction-read-response.v1"
)
CONTROL_EVENT_SCHEMA_V2 = (
    "allocatbelt.application-source5-recorded-preparation-read-control-event.v2"
)
PREPARED_INPUT_CONSTRUCTION_CONTROL_EVENT_SCHEMA_V1 = (
    "allocatbelt.application-source5-prepared-input-construction-read-control-event.v1"
)
PAYLOAD_VIEW_SCHEMA_V2 = (
    "allocatbelt.application-source5-recorded-preparation-payload-view.v2"
)
PREPARED_INPUT_CONSTRUCTION_PAYLOAD_VIEW_SCHEMA_V1 = (
    "allocatbelt.application-source5-prepared-input-construction-payload-view.v1"
)
SESSION_DESCRIPTOR_SCHEMA_V2 = (
    "allocatbelt.application-source5-recorded-preparation-read-session.v2"
)
PREPARED_INPUT_CONSTRUCTION_SESSION_DESCRIPTOR_SCHEMA_V1 = (
    "allocatbelt.application-source5-prepared-input-construction-read-session.v1"
)
FAILURE_RECEIPT_SCHEMA_V2 = (
    "allocatbelt.application-source5-recorded-preparation-read-failure.v2"
)
PREPARED_INPUT_CONSTRUCTION_FAILURE_RECEIPT_SCHEMA_V1 = (
    "allocatbelt.application-source5-prepared-input-construction-read-failure.v1"
)
PREPARED_INPUT_COMPLETION_RESERVATION_SCHEMA_V1 = (
    "allocatbelt.application-source5-prepared-input-completion-reservation.v1"
)
PREPARED_INPUT_CONSTRUCTION_OPERATION = "completion_construction"
PREPARED_INPUT_COMPLETION_MAX_BYTES = 64 * 1024 * 1024
PREPARED_INPUT_COMPLETION_PATH_NAME = "prepared-inputs-completion.json"

LEGACY_REQUEST_SCHEMA_V1 = (
    "allocatbelt.application-source5-archive-read-request.v1"
)
LEGACY_RESPONSE_SCHEMA_V1 = (
    "allocatbelt.application-source5-archive-read-response.v1"
)
OBJECT_MANIFEST_SCHEMA_V1 = (
    "allocatbelt.application-source5-evidence-object-manifest.v1"
)
PREPARATION_PROVENANCE_SCHEMA_V2 = (
    "allocatbelt.application-source5-prepared-inputs-provenance.v2"
)
SCRATCH_DECLARATION_SCHEMA_V3 = (
    "allocatbelt.application-source5-recorded-preparation-scratch.v3"
)

READ_PHASE = "exploration"
READ_USE = "capacity_pilot_export"
READ_JOB_COUNT_PER_HOST = 360
READ_COHORT_SIZE = 2
READ_WINDOW_COUNT = READ_JOB_COUNT_PER_HOST * READ_COHORT_SIZE
READ_CONTROL_EVENTS_PER_WINDOW = 2
READ_CONTROL_EVENT_COUNT = READ_WINDOW_COUNT * READ_CONTROL_EVENTS_PER_WINDOW
MAX_WINDOWS_PER_METADATA_CHUNK = 16
ORIGINAL_JOB_PHASES = {"exploration", "aa", "confirmation", "pressure", "soak"}

# These values match the existing Source campaign/archive limits. The typed
# Source caller remains responsible for comparing its pinned constants.
MAX_METADATA_BYTES = 16 * 1024 * 1024
MAX_OBJECTS_PER_WINDOW = 262_144
MAX_OBJECTS_PER_SESSION = 262_144
MIN_TAR_BYTES = 10 * 1024
MAX_ARCHIVE_BYTES = 1 << 48
MAX_U64 = (1 << 64) - 1
MAX_PATH_BYTES = 4096
MAX_SOURCE_MODULES_PER_HOST = 4096
MAX_CATALOGUE_ROWS_PER_HOST = 1_000_000
MAX_CONTROL_LEDGER_BYTES = 128 * 1024 * 1024
MAX_MONOTONIC_NS = (1 << 63) - 1

# New I/O policy maxima, not measured durations and not APP deadlines.
MAX_IO_WINDOW_SECONDS = 300
MAX_OPERATION_SECONDS = 24 * 60 * 60
NANOSECONDS_PER_SECOND = 1_000_000_000

_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}\Z")
_LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_UPPER_FINGERPRINT = re.compile(r"(?:[A-F0-9]{40}|[A-F0-9]{64})\Z")
_NONCE = re.compile(r"[0-9a-f]{32}\Z")

_BASIS_COMMON_FIELDS = {
    "schema", "campaign_id", "consumer_host_id", "cohort_hosts",
    "operation_kind", "spec_pin", "plan_pin", "source_manifest_pins",
    "source_module_pins", "prepared_input_generation", "ancestor_pins",
    "metadata_capture_manifest_pin", "width_contract_pin", "current_roots",
    "current_journal_frontier", "basis_sha256",
}
_BASIS_REFRESH_FIELDS = {"execution_manifest_pin", "registration_head"}
_CONSTRUCTION_BASIS_FIELDS = {
    "schema", "campaign_id", "consumer_host_id", "cohort_hosts",
    "operation_kind", "spec_pin", "plan_pin", "source_manifest_pins",
    "source_module_pins", "construction_inputs", "ancestor_pins",
    "metadata_capture_manifest_pin", "current_roots",
    "current_journal_frontier", "basis_sha256",
}
_CONSTRUCTION_INPUT_FIELDS = {
    "preparation_pin", "capacity_generation_pin", "pressure_bindings_pin",
    "probe_capture_index_pin", "pilot_pins", "oracle_inputs",
    "completion_output_reservation",
}
_COMPLETION_OUTPUT_INPUT_FIELDS = {
    "schema", "path", "device_id", "allocation_block_bytes",
    "maximum_file_bytes", "directory_growth_reserve_bytes",
    "reserved_bytes", "reserved_inodes",
}
_COMPLETION_OUTPUT_PLAN_FIELDS = {
    "schema", "path", "device_id", "allocation_block_bytes",
    "maximum_file_bytes", "directory_growth_reserve_bytes",
    "required_bytes", "required_inodes",
    "declared_reserved_bytes", "declared_reserved_inodes",
    "same_device_as_scratch", "same_device_required_bytes",
    "same_device_required_inodes",
}


def _plan_schema_set(*, construction: bool) -> dict[str, str]:
    if construction:
        return {
            "plan": PREPARED_INPUT_CONSTRUCTION_READ_PLAN_SCHEMA_V1,
            "chunk": PREPARED_INPUT_CONSTRUCTION_WINDOW_CHUNK_SCHEMA_V1,
            "request": PREPARED_INPUT_CONSTRUCTION_REQUEST_SCHEMA_V1,
            "response": PREPARED_INPUT_CONSTRUCTION_RESPONSE_SCHEMA_V1,
            "control": PREPARED_INPUT_CONSTRUCTION_CONTROL_EVENT_SCHEMA_V1,
            "session": PREPARED_INPUT_CONSTRUCTION_SESSION_DESCRIPTOR_SCHEMA_V1,
            "failure": PREPARED_INPUT_CONSTRUCTION_FAILURE_RECEIPT_SCHEMA_V1,
            "payload_view": PREPARED_INPUT_CONSTRUCTION_PAYLOAD_VIEW_SCHEMA_V1,
        }
    return {
        "plan": READ_PLAN_SCHEMA_V2,
        "chunk": WINDOW_METADATA_CHUNK_SCHEMA_V1,
        "request": REQUEST_SCHEMA_V2,
        "response": RESPONSE_SCHEMA_V2,
        "control": CONTROL_EVENT_SCHEMA_V2,
        "session": SESSION_DESCRIPTOR_SCHEMA_V2,
        "failure": FAILURE_RECEIPT_SCHEMA_V2,
        "payload_view": PAYLOAD_VIEW_SCHEMA_V2,
    }
_CURRENT_ROOT_FIELDS = {
    "source_root", "input_root", "metadata_capture_root", "archive_root",
    "artifact_root", "output_root", "journal_root",
}
_READBACK_CAP_FIELDS = {
    "request_bytes", "response_bytes", "bundle_bytes", "stage_bytes",
    "stage_inodes", "object_count", "maximum_object_bytes",
    "live_window_bytes", "live_window_inodes", "maximum_request_bytes",
    "maximum_response_bytes", "maximum_bundle_bytes", "maximum_stage_bytes",
    "maximum_stage_inodes", "maximum_object_count",
    "maximum_live_window_bytes", "maximum_live_window_inodes",
}
_BUDGET_READ_CAP_FIELDS = {
    "bundle_bytes", "maximum_request_bytes", "maximum_response_bytes",
    "object_count", "stage_bytes",
}
_SOURCE_SCHEDULE_FIELDS = {
    "analysis_phase", "owner_phase", "job_index", "job", "job_sha256",
    "request_ordinal", "use", "caps",
}
_WINDOW_FIELDS = {
    "host_id", "schedule_row", "job_record_pin", "request_pin",
    "checkpoint_pin", "object_manifest_pin", "ack_pin", "signature_pin",
    "host_receipt_pin", "indexed_reservation_bindings",
    "archive_source5_root", "manifest",
}
_WINDOW_INDEX_FIELDS = {
    "read_ordinal", "owner_host_id", "job_index", "job_sha256",
    "chunk_ordinal", "chunk_row", "row_sha256",
}
_WINDOW_CHUNK_REF_FIELDS = {
    "chunk_ordinal", "first_read_ordinal", "window_count",
    "read_ordinals", "pin", "byte_count",
}
_WINDOW_CHUNK_FIELDS = {
    "schema", "basis_pin", "campaign_id", "consumer_host_id",
    "cohort_hosts", "operation_kind", "session_nonce", "chunk_ordinal",
    "first_read_ordinal", "read_ordinals", "rows",
    "window_chunk_sha256",
}
_PLAN_ROW_FIELDS = {
    "read_ordinal", "consumer_host_id", "owner_host_id", "operation_kind",
    "job_index", "job", "job_sha256", "original_pins",
    "indexed_reservation_bindings", "archive_source5_root",
    "manifest_summary", "objects",
    "source_budget_schedule_caps", "recomputed_source_caps",
    "legacy_request_sha256", "resource_bounds", "session_stage_root",
    "session_paths",
}
_PLAN_ORIGINAL_PIN_FIELDS = {
    "job_record", "request", "checkpoint", "object_manifest", "ack",
    "signature", "host_receipt",
}
_RECOMPUTED_SOURCE_CAP_FIELDS = {
    "maximum_request_bytes", "maximum_response_bytes", "bundle_bytes",
    "stage_bytes", "stage_inodes", "object_count",
    "maximum_object_bytes", "live_window_bytes", "live_window_inodes",
}
_RESOURCE_BOUND_FIELDS = {
    "legacy_request_bytes", "legacy_response_bytes", "outer_request_bytes",
    "outer_response_bytes", "tar_bytes", "payload_bytes", "object_count",
    "maximum_object_bytes", "window_bytes", "window_inodes",
}
_CATALOGUE_ROW_FIELDS = {
    "path", "kind", "role", "host_id", "max_bytes", "max_file_bytes",
    "max_inodes", "storage_root", "owner", "phase", "run_id",
    "member_index", "aggregate_id", "aggregate_max_bytes", "origin_pin",
}
_MANIFEST_FIELDS = {
    "schema", "campaign_id", "host_id", "phase", "job_index",
    "job_ordinal", "job_sha256", "run_id", "job_record_raw_sha256",
    "predecessor_ack_pin", "objects", "object_count", "payload_bytes",
    "manifest_sha256",
}
_MANIFEST_OBJECT_FIELDS = {
    "origin_path", "role", "object_id", "byte_count", "raw_sha256",
    "semantic_sha256", "object_pin",
}
_OBJECT_PIN_FIELDS = {"path", "raw_sha256", "semantic_sha256", "byte_count"}
_PIN3_FIELDS = {"path", "raw_sha256", "semantic_sha256"}
_PIN2_FIELDS = {"path", "raw_sha256"}
_SIGNATURE_PIN_FIELDS = {"path", "raw_sha256", "signer_fingerprint"}
_HOST_RECEIPT_PIN_FIELDS = {
    "path", "raw_sha256", "host_verification_sha256",
}
_INDEXED_RESERVATION_ROLES = {
    "source5_job_record", "source5_checkpoint_request",
    "source5_checkpoint", "source5_object_manifest",
    "source5_archive_ack", "source5_archive_signature",
}


class RecordedPreparationReadPlanError(ValueError):
    """A recorded-preparation basis, envelope, or finite read plan is invalid."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RecordedPreparationReadPlanError(message)


def _exact(value: object, fields: set[str], label: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == fields,
             f"{label} has an unexpected field set")
    return value


def _sha(value: object, label: str) -> str:
    _require(type(value) is str and _LOWER_SHA256.fullmatch(value) is not None,
             f"{label} is not a lowercase SHA-256")
    return value


def _uint(
    value: object, label: str, *, positive: bool = False,
    maximum: int = MAX_U64,
) -> int:
    _require(type(value) is int and
             (value > 0 if positive else value >= 0) and value <= maximum,
             f"{label} is outside its finite unsigned range")
    return value


def _token(value: object, label: str) -> str:
    _require(type(value) is str and _TOKEN.fullmatch(value) is not None,
             f"{label} is not a bounded Source token")
    return value


def _absolute_path(value: object, label: str) -> str:
    _require(type(value) is str and value.startswith("/") and
             len(value.encode("utf-8", "strict")) <= MAX_PATH_BYTES and
             "\\" not in value and "\x00" not in value and
             PurePosixPath(value).as_posix() == value and
             ".." not in PurePosixPath(value).parts and
             not any(ord(character) < 32 or ord(character) == 127
                     for character in value),
             f"{label} is not a bounded normalized absolute path")
    return value


def _relative_module_path(value: object, label: str) -> str:
    _require(type(value) is str and value.startswith("scripts/") and
             len(value.encode("utf-8", "strict")) <= MAX_PATH_BYTES and
             "\\" not in value and "\x00" not in value and
             PurePosixPath(value).as_posix() == value and
             ".." not in PurePosixPath(value).parts and
             not any(ord(character) < 32 or ord(character) == 127
                     for character in value),
             f"{label} is not a normalized typed Source module path")
    return value


def canonical_bytes(value: object) -> bytes:
    """Return the existing Source canonical JSON encoding, including LF."""
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    except (TypeError, ValueError, RecursionError) as error:
        raise RecordedPreparationReadPlanError(
            f"value is not bounded canonical JSON: {error}",
        ) from error


def sha256(raw: bytes) -> str:
    _require(type(raw) is bytes,
             "recorded-preparation digest input must be immutable bytes")
    return hashlib.sha256(raw).hexdigest()


def _seal(value: dict[str, Any], field: str) -> dict[str, Any]:
    body = {key: item for key, item in value.items() if key != field}
    return {**body, field: sha256(canonical_bytes(body))}


def _pin3(value: object, label: str) -> dict[str, Any]:
    pin = _exact(value, _PIN3_FIELDS, label)
    _absolute_path(pin["path"], f"{label} path")
    _sha(pin["raw_sha256"], f"{label} raw digest")
    _sha(pin["semantic_sha256"], f"{label} semantic digest")
    return pin


def _pin2(value: object, label: str) -> dict[str, Any]:
    pin = _exact(value, _PIN2_FIELDS, label)
    _absolute_path(pin["path"], f"{label} path")
    _sha(pin["raw_sha256"], f"{label} raw digest")
    return pin


def _signature_pin(value: object, label: str) -> dict[str, Any]:
    pin = _exact(value, _SIGNATURE_PIN_FIELDS, label)
    _absolute_path(pin["path"], f"{label} path")
    _sha(pin["raw_sha256"], f"{label} raw digest")
    _require(type(pin["signer_fingerprint"]) is str and
             _UPPER_FINGERPRINT.fullmatch(pin["signer_fingerprint"]) is not None,
             f"{label} signer fingerprint is malformed")
    return pin


def _host_receipt_pin(value: object, label: str) -> dict[str, Any]:
    pin = _exact(value, _HOST_RECEIPT_PIN_FIELDS, label)
    _absolute_path(pin["path"], f"{label} path")
    _sha(pin["raw_sha256"], f"{label} raw digest")
    _sha(pin["host_verification_sha256"],
         f"{label} host-verification digest")
    return pin


def _validate_basis(
    basis_value: object, basis_pin_value: object,
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    _require(type(basis_value) is dict,
             "recorded-preparation replay basis must be an exact object")
    operation = basis_value.get("operation_kind")
    fields = set(_BASIS_COMMON_FIELDS)
    if operation == "refresh_replay":
        fields |= _BASIS_REFRESH_FIELDS
    basis = _exact(basis_value, fields,
                   "recorded-preparation replay basis")
    _require(basis["schema"] == REPLAY_BASIS_SCHEMA_V1 and
             operation in {"registration_replay", "refresh_replay"},
             "recorded-preparation replay basis schema or operation differs")
    campaign_id = _token(basis["campaign_id"], "basis campaign ID")
    consumer = _token(basis["consumer_host_id"], "basis consumer host ID")
    hosts_value = basis["cohort_hosts"]
    _require(type(hosts_value) is list and len(hosts_value) == READ_COHORT_SIZE,
             "recorded-preparation basis must retain the exact two-host cohort")
    hosts = [_token(host, f"basis cohort host[{index}]")
             for index, host in enumerate(hosts_value)]
    _require(len(set(hosts)) == READ_COHORT_SIZE and consumer in hosts,
             "recorded-preparation basis repeats or omits its consumer host")
    _pin3(basis["spec_pin"], "basis final Spec pin")
    _pin3(basis["plan_pin"], "basis final Plan pin")

    source_pins = _exact(basis["source_manifest_pins"], set(hosts),
                         "basis Source manifest map")
    module_pins = _exact(basis["source_module_pins"], set(hosts),
                         "basis typed Source module maps")
    ancestor_pins = _exact(basis["ancestor_pins"], set(hosts),
                           "basis two-host ancestor map")
    prepared_generation = _exact(basis["prepared_input_generation"], {
        "completion_pin", "provenance",
    }, "basis prepared-input generation")
    _pin3(prepared_generation["completion_pin"],
          "basis prepared-input completion pin")
    provenance = _exact(prepared_generation["provenance"], {
        "schema", "preparation_pin", "final_spec_pin", "final_plan_pin",
        "exploration_lineage",
    }, "basis prepared-input provenance V2")
    _require(provenance["schema"] == PREPARATION_PROVENANCE_SCHEMA_V2,
             "basis prepared-input provenance is not the exact V2 schema")
    _pin2(
        provenance["preparation_pin"],
        "basis Source V2 original preparation pin",
    )
    provenance_spec_pin = _pin2(
        provenance["final_spec_pin"], "basis Source V2 final Spec pin",
    )
    provenance_plan_pin = _pin2(
        provenance["final_plan_pin"], "basis Source V2 final Plan pin",
    )
    _require(provenance_spec_pin == {
                 "path": basis["spec_pin"]["path"],
                 "raw_sha256": basis["spec_pin"]["raw_sha256"],
             } and provenance_plan_pin == {
                 "path": basis["plan_pin"]["path"],
                 "raw_sha256": basis["plan_pin"]["raw_sha256"],
             }, "Source V2 final raw pins differ from the basis full Spec/Plan pins")
    lineage = _exact(provenance["exploration_lineage"], set(hosts),
                     "basis two-host exploration lineage")
    for host in hosts:
        _pin3(source_pins[host], f"basis {host} Source manifest pin")
        modules = module_pins[host]
        _require(type(modules) is dict and
                 0 < len(modules) <= MAX_SOURCE_MODULES_PER_HOST,
                 f"basis {host} typed Source module set is empty or oversized")
        for path, pin_value in modules.items():
            _relative_module_path(path, f"basis {host} module key")
            module_pin = _exact(pin_value, {"path", "sha256"},
                                f"basis {host} module pin {path}")
            _require(module_pin["path"] == path,
                     f"basis {host} module key and pin path differ")
            _sha(module_pin["sha256"], f"basis {host} module digest {path}")
        ancestor = _exact(ancestor_pins[host], {
            "bridge_header", "record_index",
        }, f"basis {host} old ancestor pins")
        _pin2(ancestor["bridge_header"],
              f"basis {host} bridge-header pin")
        _pin2(ancestor["record_index"],
              f"basis {host} record-index pin")
        lineage_row = _exact(lineage[host], {
            "bridge_header", "record_index",
        }, f"basis {host} V2 lineage provenance")
        _pin2(lineage_row["bridge_header"],
              f"basis {host} V2 bridge-header pin")
        _pin2(lineage_row["record_index"],
              f"basis {host} V2 record-index pin")
        _require(lineage_row["bridge_header"] == ancestor["bridge_header"] and
                 lineage_row["record_index"] == ancestor["record_index"],
                 f"basis {host} V2 provenance differs from the exact ancestor pins")

    # The existing closed capture manifest has the explicitly raw-only
    # `{path, raw_sha256}` pin grammar; do not invent a semantic digest.
    _pin2(basis["metadata_capture_manifest_pin"],
          "basis closed metadata-capture manifest pin")
    _pin3(basis["width_contract_pin"], "basis selected current width pin")
    roots = _exact(basis["current_roots"], _CURRENT_ROOT_FIELDS,
                   "basis current root map")
    for name, path in roots.items():
        _absolute_path(path, f"basis current {name}")
    frontier = _exact(basis["current_journal_frontier"], {
        "head_sha256", "record_count",
    }, "basis held-journal frontier")
    _sha(frontier["head_sha256"], "basis current journal head")
    _uint(frontier["record_count"], "basis current journal count")
    if operation == "refresh_replay":
        _pin3(basis["execution_manifest_pin"],
              "refresh basis sealed execution-manifest pin")
        _sha(basis["registration_head"], "refresh basis registration head")
    _sha(basis["basis_sha256"], "basis self digest")
    _require(basis["basis_sha256"] == sha256(canonical_bytes({
        key: value for key, value in basis.items() if key != "basis_sha256"
    })), "recorded-preparation basis self digest differs")
    basis_raw = canonical_bytes(basis)
    _require(0 < len(basis_raw) <= MAX_METADATA_BYTES,
             "recorded-preparation basis exceeds the 16 MiB metadata ceiling")
    basis_pin = _pin3(basis_pin_value, "recorded-preparation basis pin")
    _require(basis_pin["raw_sha256"] == sha256(basis_raw) and
             basis_pin["semantic_sha256"] == basis["basis_sha256"],
             "recorded-preparation basis raw/semantic pin differs")
    _require(campaign_id == basis["campaign_id"],
             "recorded-preparation basis campaign identity changed")
    return basis, basis_pin, hosts


def _validate_completion_output_reservation(
    value: object, plan_path: str, input_root: str, source_root: str,
) -> dict[str, Any]:
    declaration = _exact(
        value, _COMPLETION_OUTPUT_INPUT_FIELDS,
        "construction final-completion output reservation",
    )
    expected_path = str(
        PurePosixPath(plan_path).parent / PREPARED_INPUT_COMPLETION_PATH_NAME,
    )
    path = _absolute_path(
        declaration["path"], "construction final-completion output path",
    )
    root_parts = PurePosixPath(input_root).parts
    output_parts = PurePosixPath(path).parts
    source_parts = PurePosixPath(source_root).parts
    _require(path == expected_path and len(output_parts) > len(root_parts) and
             output_parts[:len(root_parts)] == root_parts and
             output_parts[:len(source_parts)] != source_parts,
             "construction completion reservation differs from the fixed InputPrep path outside Source")
    _require(declaration["schema"] ==
             PREPARED_INPUT_COMPLETION_RESERVATION_SCHEMA_V1,
             "construction final-completion output reservation schema differs")
    device_id = _uint(
        declaration["device_id"], "completion-output filesystem device ID",
    )
    allocation_block = _uint(
        declaration["allocation_block_bytes"],
        "completion-output filesystem allocation block", positive=True,
        maximum=MAX_METADATA_BYTES,
    )
    maximum_file_bytes = _uint(
        declaration["maximum_file_bytes"],
        "completion-output maximum file bytes", positive=True,
    )
    _require(maximum_file_bytes == PREPARED_INPUT_COMPLETION_MAX_BYTES,
             "completion-output declaration differs from the fixed 64 MiB ceiling")
    directory_growth_reserve = _uint(
        declaration["directory_growth_reserve_bytes"],
        "completion-output parent-directory growth reserve", positive=True,
    )
    declared_bytes = _uint(
        declaration["reserved_bytes"],
        "completion-output byte reservation", positive=True,
    )
    declared_inodes = _uint(
        declaration["reserved_inodes"],
        "completion-output inode reservation", positive=True,
    )
    required_bytes = (
        _round_file_allocation_bytes(
            maximum_file_bytes, allocation_block,
        ) + directory_growth_reserve
    )
    required_inodes = 1
    _require(declared_bytes >= required_bytes and
             declared_inodes >= required_inodes,
             "construction final-completion output reservation is below its exact finite output bound")
    return {
        "schema": PREPARED_INPUT_COMPLETION_RESERVATION_SCHEMA_V1,
        "path": path,
        "device_id": device_id,
        "allocation_block_bytes": allocation_block,
        "maximum_file_bytes": maximum_file_bytes,
        "directory_growth_reserve_bytes": directory_growth_reserve,
        "required_bytes": required_bytes,
        "required_inodes": required_inodes,
        "declared_reserved_bytes": declared_bytes,
        "declared_reserved_inodes": declared_inodes,
    }


def _validate_construction_basis(
    basis_value: object, basis_pin_value: object,
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    """Validate the acyclic completion-construction basis schema only."""
    basis = _exact(
        basis_value, _CONSTRUCTION_BASIS_FIELDS,
        "prepared-input construction basis",
    )
    _require(basis["schema"] == PREPARED_INPUT_CONSTRUCTION_BASIS_SCHEMA_V1 and
             basis["operation_kind"] == PREPARED_INPUT_CONSTRUCTION_OPERATION,
             "prepared-input construction basis schema or operation differs")
    campaign_id = _token(basis["campaign_id"], "construction basis campaign ID")
    consumer = _token(
        basis["consumer_host_id"], "construction basis consumer host ID",
    )
    hosts_value = basis["cohort_hosts"]
    _require(type(hosts_value) is list and len(hosts_value) == READ_COHORT_SIZE,
             "prepared-input construction basis requires the exact two-host cohort")
    hosts = [_token(host, f"construction basis host[{index}]")
             for index, host in enumerate(hosts_value)]
    _require(len(set(hosts)) == READ_COHORT_SIZE and consumer in hosts,
             "prepared-input construction basis repeats or omits its consumer")
    spec_pin = _pin3(basis["spec_pin"], "construction final Spec pin")
    plan_pin = _pin3(basis["plan_pin"], "construction final Plan pin")

    source_pins = _exact(
        basis["source_manifest_pins"], set(hosts),
        "construction Source manifest map",
    )
    module_pins = _exact(
        basis["source_module_pins"], set(hosts),
        "construction typed Source module maps",
    )
    ancestors = _exact(
        basis["ancestor_pins"], set(hosts),
        "construction two-host ancestor map",
    )
    inputs = _exact(
        basis["construction_inputs"], _CONSTRUCTION_INPUT_FIELDS,
        "prepared-input construction inputs",
    )
    _pin2(inputs["preparation_pin"], "construction preparation pin")
    _pin3(inputs["capacity_generation_pin"],
          "construction capacity-generation pin")
    _pin2(inputs["pressure_bindings_pin"],
          "construction pressure-bindings pin")
    _pin2(inputs["probe_capture_index_pin"],
          "construction ProbeV2 capture-index pin")
    pilot_pins = _exact(
        inputs["pilot_pins"], set(hosts), "construction ordered-host pilot pins",
    )
    oracle_inputs = _exact(
        inputs["oracle_inputs"], set(hosts),
        "construction ordered-host oracle inputs",
    )
    for host in hosts:
        _pin3(source_pins[host], f"construction {host} Source manifest pin")
        modules = module_pins[host]
        _require(type(modules) is dict and
                 0 < len(modules) <= MAX_SOURCE_MODULES_PER_HOST,
                 f"construction {host} typed Source module set is empty or oversized")
        for path, pin_value in modules.items():
            _relative_module_path(path, f"construction {host} module key")
            module_pin = _exact(
                pin_value, {"path", "sha256"},
                f"construction {host} module pin {path}",
            )
            _require(module_pin["path"] == path,
                     f"construction {host} module key and pin path differ")
            _sha(module_pin["sha256"],
                 f"construction {host} module digest {path}")
        _pin3(pilot_pins[host], f"construction {host} pilot pin")
        oracle = _exact(oracle_inputs[host], {
            "manifest_pin", "artifact_root",
        }, f"construction {host} oracle input")
        _pin3(oracle["manifest_pin"],
              f"construction {host} oracle manifest pin")
        _absolute_path(oracle["artifact_root"],
                       f"construction {host} oracle artifact root")
        ancestor = _exact(ancestors[host], {
            "bridge_header", "record_index",
        }, f"construction {host} old ancestor pins")
        _pin2(ancestor["bridge_header"],
              f"construction {host} bridge-header pin")
        _pin2(ancestor["record_index"],
              f"construction {host} record-index pin")

    _pin2(basis["metadata_capture_manifest_pin"],
          "construction closed metadata-capture manifest pin")
    roots = _exact(basis["current_roots"], _CURRENT_ROOT_FIELDS,
                   "construction current root map")
    for name, path in roots.items():
        _absolute_path(path, f"construction current {name}")
    _validate_completion_output_reservation(
        inputs["completion_output_reservation"], plan_pin["path"],
        roots["input_root"], roots["source_root"],
    )
    frontier = _exact(basis["current_journal_frontier"], {
        "head_sha256", "record_count",
    }, "construction held-journal frontier")
    _sha(frontier["head_sha256"], "construction current journal head")
    _uint(frontier["record_count"], "construction current journal count")

    _sha(basis["basis_sha256"], "construction basis self digest")
    _require(basis["basis_sha256"] == sha256(canonical_bytes({
        key: value for key, value in basis.items() if key != "basis_sha256"
    })), "prepared-input construction basis self digest differs")
    basis_raw = canonical_bytes(basis)
    _require(0 < len(basis_raw) <= MAX_METADATA_BYTES,
             "prepared-input construction basis exceeds the 16 MiB metadata ceiling")
    basis_pin = _pin3(basis_pin_value, "construction basis pin")
    _require(basis_pin["raw_sha256"] == sha256(basis_raw) and
             basis_pin["semantic_sha256"] == basis["basis_sha256"],
             "prepared-input construction basis raw/semantic pin differs")
    _require(campaign_id == basis["campaign_id"],
             "prepared-input construction campaign identity changed")
    return basis, basis_pin, hosts


def validate_prepared_input_construction_basis_v1(
    basis_value: object, basis_pin_value: object,
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    """Validate the exact acyclic basis used only for completion construction."""
    return _validate_construction_basis(basis_value, basis_pin_value)


def _construction_output_plan_reservation(
    basis: dict[str, Any], scratch: dict[str, Any],
    resource_projection: dict[str, Any],
) -> dict[str, Any]:
    roots = basis["current_roots"]
    reservation = _validate_completion_output_reservation(
        basis["construction_inputs"]["completion_output_reservation"],
        basis["plan_pin"]["path"], roots["input_root"],
        roots["source_root"],
    )
    same_device = reservation["device_id"] == scratch["device_id"]
    if same_device:
        _require(reservation["allocation_block_bytes"] ==
                 scratch["allocation_block_bytes"],
                 "same-device scratch and completion reservations disagree on allocation block size")
        combined_bytes = (resource_projection["required_bytes"] +
                          reservation["required_bytes"])
        combined_inodes = (resource_projection["required_inodes"] +
                           reservation["required_inodes"])
    else:
        combined_bytes = 0
        combined_inodes = 0
    return {
        **reservation,
        "same_device_as_scratch": same_device,
        "same_device_required_bytes": combined_bytes,
        "same_device_required_inodes": combined_inodes,
    }


def _validate_scratch(value: object) -> dict[str, Any]:
    scratch = _exact(value, {
        "schema", "root", "device_id", "allocation_block_bytes",
        "directory_metadata_reserve_bytes",
        "reserved_bytes", "reserved_inodes",
    }, "recorded-preparation scratch declaration")
    _require(scratch["schema"] == SCRATCH_DECLARATION_SCHEMA_V3,
             "recorded-preparation scratch declaration schema differs")
    _absolute_path(scratch["root"], "recorded-preparation scratch root")
    _uint(scratch["device_id"], "recorded-preparation scratch device ID")
    _uint(scratch["allocation_block_bytes"],
          "recorded-preparation filesystem allocation block", positive=True,
          maximum=MAX_METADATA_BYTES)
    _uint(scratch["directory_metadata_reserve_bytes"],
          "recorded-preparation directory metadata reserve", positive=True)
    _uint(scratch["reserved_bytes"],
          "recorded-preparation scratch byte reservation", positive=True)
    _uint(scratch["reserved_inodes"],
          "recorded-preparation scratch inode reservation", positive=True)
    return scratch


def _validate_timeouts(value: object) -> dict[str, int]:
    timeouts = _exact(value, {
        "maximum_io_window_seconds", "maximum_operation_seconds",
    }, "recorded-preparation timeout declaration")
    io_seconds = _uint(
        timeouts["maximum_io_window_seconds"],
        "recorded-preparation per-window timeout", positive=True,
    )
    operation_seconds = _uint(
        timeouts["maximum_operation_seconds"],
        "recorded-preparation operation timeout", positive=True,
    )
    _require(io_seconds <= MAX_IO_WINDOW_SECONDS and
             operation_seconds <= MAX_OPERATION_SECONDS and
             operation_seconds >= io_seconds and
             io_seconds <= MAX_MONOTONIC_NS // NANOSECONDS_PER_SECOND and
             operation_seconds <= MAX_MONOTONIC_NS // NANOSECONDS_PER_SECOND,
             "recorded-preparation timeouts exceed finite Source policy or monotonic range")
    return timeouts


def _path_parts(path: str) -> tuple[str, ...]:
    return PurePosixPath(path).parts


def _paths_overlap(left: str, right: str) -> bool:
    left_parts = _path_parts(left)
    right_parts = _path_parts(right)
    common = min(len(left_parts), len(right_parts))
    return left_parts[:common] == right_parts[:common]


def _layout(root: str, campaign_id: str, consumer: str, nonce: str) -> dict[str, Any]:
    session = (PurePosixPath(root) / campaign_id / "source5" / consumer /
               "recorded-preparation" / nonce)
    slot = session / "slot"
    session_paths = {
        "basis": str(session / "basis.json"),
        "read_plan": str(session / "read-plan.json"),
        "session": str(session / "session.json"),
        "control_ledger": str(session / "control-ledger.jsonl"),
        "failure_receipt": str(session / "failure-receipt.json"),
        "window_metadata_root": str(session / "window-metadata"),
        "slot": str(slot),
        "request": str(slot / "request.json"),
        "response_incoming": str(slot / "response.json.incoming"),
        "response": str(slot / "response.json"),
        "bundle_incoming": str(slot / "response.tar.incoming"),
        "bundle": str(slot / "response.tar"),
        "stage": str(slot / "stage"),
    }
    session_paths["directories"] = [
        str(PurePosixPath(root) / campaign_id),
        str(PurePosixPath(root) / campaign_id / "source5"),
        str(PurePosixPath(root) / campaign_id / "source5" / consumer),
        str(PurePosixPath(root) / campaign_id / "source5" / consumer /
            "recorded-preparation"),
        str(session), str(session / "window-metadata"),
        str(slot), str(slot / "stage"),
    ]
    return session_paths


def _construction_layout(
    root: str, campaign_id: str, consumer: str, nonce: str,
) -> dict[str, Any]:
    session = (PurePosixPath(root) / campaign_id / "source5" / consumer /
               "prepared-input-construction" / nonce)
    slot = session / "slot"
    session_paths = {
        "basis": str(session / "basis.json"),
        "read_plan": str(session / "read-plan.json"),
        "session": str(session / "session.json"),
        "control_ledger": str(session / "control-ledger.jsonl"),
        "failure_receipt": str(session / "failure-receipt.json"),
        "window_metadata_root": str(session / "window-metadata"),
        "slot": str(slot),
        "request": str(slot / "request.json"),
        "response_incoming": str(slot / "response.json.incoming"),
        "response": str(slot / "response.json"),
        "bundle_incoming": str(slot / "response.tar.incoming"),
        "bundle": str(slot / "response.tar"),
        "stage": str(slot / "stage"),
    }
    session_paths["directories"] = [
        str(PurePosixPath(root) / campaign_id),
        str(PurePosixPath(root) / campaign_id / "source5"),
        str(PurePosixPath(root) / campaign_id / "source5" / consumer),
        str(PurePosixPath(root) / campaign_id / "source5" / consumer /
            "prepared-input-construction"),
        str(session), str(session / "window-metadata"),
        str(slot), str(slot / "stage"),
    ]
    return session_paths


def _validate_layout_disjointness(
    scratch_root: str, basis: dict[str, Any],
    catalogues_by_host: dict[str, list[dict[str, Any]]],
    windows_by_host: dict[str, list[dict[str, Any]]],
) -> None:
    protected = list(basis["current_roots"].values())
    for host, rows in catalogues_by_host.items():
        for row in rows:
            if row["storage_root"] is not None:
                protected.append(row["storage_root"])
    for windows in windows_by_host.values():
        for window in windows:
            protected.append(window["archive_source5_root"])
            for key in (
                "job_record_pin", "request_pin", "checkpoint_pin",
                "object_manifest_pin", "ack_pin", "signature_pin",
                "host_receipt_pin",
            ):
                pin = window[key]
                protected.append(pin["path"])
            for obj in window["manifest"]["objects"]:
                protected.append(obj["origin_path"])
                protected.append(obj["object_pin"]["path"])
    for index, path in enumerate(protected):
        _absolute_path(path, f"protected historical/current path[{index}]")
        _require(not _paths_overlap(scratch_root, path),
                 f"recorded-preparation scratch overlaps protected path: {path}")


def _validate_catalogue_row(value: object, label: str) -> dict[str, Any]:
    row = _exact(value, _CATALOGUE_ROW_FIELDS, label)
    path = _absolute_path(row["path"], f"{label} path")
    _require(row["kind"] in {"file", "tree"},
             f"{label} kind is unsupported")
    _token(row["role"], f"{label} role")
    _require(row["host_id"] is None or
             (type(row["host_id"]) is str and row["host_id"]),
             f"{label} host ID is malformed")
    _uint(row["max_bytes"], f"{label} maximum bytes")
    _uint(row["max_file_bytes"], f"{label} maximum file bytes")
    _uint(row["max_inodes"], f"{label} maximum inodes")
    _require(row["max_file_bytes"] <= row["max_bytes"] and
             (row["kind"] != "file" or row["max_file_bytes"] == row["max_bytes"]) and
             ((row["kind"] == "file" and row["max_inodes"] == 1) or
              (row["kind"] == "tree" and row["max_inodes"] > 0)),
             f"{label} file/tree bounds disagree")
    if row["storage_root"] is not None:
        _absolute_path(row["storage_root"], f"{label} storage root")
    _token(row["owner"], f"{label} owner")
    _require(row["phase"] is None or row["phase"] in ORIGINAL_JOB_PHASES,
             f"{label} phase is outside the original job-phase enum")
    if row["run_id"] is not None:
        _require(type(row["run_id"]) is str and
                 0 < len(row["run_id"].encode("utf-8", "strict")) <= MAX_PATH_BYTES and
                 not any(ord(character) < 32 or ord(character) == 127
                         for character in row["run_id"]),
                 f"{label} run ID is not bounded path-safe text")
    _require(row["member_index"] is None or
             (type(row["member_index"]) is int and row["member_index"] in {0, 1}),
             f"{label} member index is malformed")
    if row["aggregate_id"] is None:
        _require(row["aggregate_max_bytes"] is None,
                 f"{label} has an aggregate byte cap without an ID")
    else:
        _token(row["aggregate_id"], f"{label} aggregate ID")
        _uint(row["aggregate_max_bytes"],
              f"{label} aggregate maximum bytes", positive=True)
    if row["origin_pin"] is not None:
        origin = _exact(row["origin_pin"],
                        {"raw_sha256", "semantic_sha256"},
                        f"{label} original pin")
        _sha(origin["raw_sha256"], f"{label} origin raw digest")
        if origin["semantic_sha256"] is not None:
            _sha(origin["semantic_sha256"],
                 f"{label} origin semantic digest")
    _require(path == row["path"], f"{label} path changed during validation")
    return row


def _validate_catalogues(
    value: object, hosts: list[str],
) -> dict[str, list[dict[str, Any]]]:
    raw_map = _exact(value, set(hosts), "old Source catalogue map")
    result: dict[str, list[dict[str, Any]]] = {}
    for host in hosts:
        rows_value = raw_map[host]
        _require(type(rows_value) is list and
                 0 < len(rows_value) <= MAX_CATALOGUE_ROWS_PER_HOST,
                 f"old Source {host} catalogue row set is empty or oversized")
        rows = [_validate_catalogue_row(row, f"old Source {host} row[{index}]")
                for index, row in enumerate(rows_value)]
        paths = [row["path"] for row in rows]
        _require(len(set(paths)) == len(paths),
                 f"old Source {host} catalogue repeats a path")
        result[host] = rows
    return result


def _validate_readback_caps(
    value: object, hosts: list[str],
) -> dict[str, dict[str, dict[str, int]]]:
    raw_map = _exact(value, set(hosts), "old Source readback cap map")
    result: dict[str, dict[str, dict[str, int]]] = {}
    for host in hosts:
        host_caps = raw_map[host]
        _require(type(host_caps) is dict and
                 0 < len(host_caps) <= READ_JOB_COUNT_PER_HOST,
                 f"old Source {host} readback cap map is empty or oversized")
        checked: dict[str, dict[str, int]] = {}
        for run_id, caps_value in host_caps.items():
            _require(type(run_id) is str and run_id and
                     len(run_id.encode("utf-8", "strict")) <= MAX_PATH_BYTES and
                     not any(ord(character) < 32 or ord(character) == 127
                             for character in run_id),
                     f"old Source {host} cap-map run ID is malformed")
            caps = _exact(caps_value, _READBACK_CAP_FIELDS,
                          f"old Source {host}/{run_id} readback caps")
            for name in ("request_bytes", "response_bytes"):
                _uint(caps[name], f"old Source {host}/{run_id} {name}",
                      positive=True, maximum=MAX_METADATA_BYTES)
            _uint(caps["bundle_bytes"],
                  f"old Source {host}/{run_id} tar ceiling", positive=True,
                  maximum=MAX_ARCHIVE_BYTES)
            _require(caps["bundle_bytes"] >= MIN_TAR_BYTES,
                     f"old Source {host}/{run_id} tar ceiling is below the v1 minimum")
            _uint(caps["stage_bytes"],
                  f"old Source {host}/{run_id} stage-byte cap",
                  maximum=MAX_ARCHIVE_BYTES)
            _uint(caps["stage_inodes"],
                  f"old Source {host}/{run_id} stage-inode cap", positive=True)
            _uint(caps["object_count"],
                  f"old Source {host}/{run_id} object count", positive=True,
                  maximum=MAX_OBJECTS_PER_WINDOW)
            _uint(caps["maximum_object_bytes"],
                  f"old Source {host}/{run_id} maximum object bytes",
                  maximum=MAX_ARCHIVE_BYTES)
            _uint(caps["live_window_bytes"],
                  f"old Source {host}/{run_id} live-window bytes",
                  maximum=2 * MAX_ARCHIVE_BYTES + 2 * MAX_METADATA_BYTES)
            _uint(caps["live_window_inodes"],
                  f"old Source {host}/{run_id} live-window inodes", positive=True)
            _require(caps["stage_inodes"] == caps["object_count"] + 1 and
                     caps["live_window_inodes"] == caps["object_count"] + 4 and
                     caps["live_window_bytes"] == sum(caps[name] for name in (
                         "request_bytes", "response_bytes", "bundle_bytes",
                         "stage_bytes",
                     )),
                     f"old Source {host}/{run_id} per-window cap arithmetic differs")
            checked[run_id] = caps
        maximum_fields = {
            "maximum_request_bytes": "request_bytes",
            "maximum_response_bytes": "response_bytes",
            "maximum_bundle_bytes": "bundle_bytes",
            "maximum_stage_bytes": "stage_bytes",
            "maximum_stage_inodes": "stage_inodes",
            "maximum_object_count": "object_count",
            "maximum_live_window_bytes": "live_window_bytes",
            "maximum_live_window_inodes": "live_window_inodes",
        }
        for caps in checked.values():
            for maximum_field, local_field in maximum_fields.items():
                _uint(caps[maximum_field],
                      f"old Source {host} global {maximum_field}", positive=True)
                _require(caps[maximum_field] == max(
                    item[local_field] for item in checked.values()
                ), f"old Source {host} global {maximum_field} differs")
            _require(caps["maximum_object_bytes"] == max(
                item["maximum_object_bytes"] for item in checked.values()
            ), f"old Source {host} global maximum object size differs")
        result[host] = checked
    return result


def _validate_source_schedule(
    value: object, host: str, index: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    row = _exact(value, _SOURCE_SCHEDULE_FIELDS,
                 f"old Source {host} schedule row[{index}]")
    _require(row["analysis_phase"] == READ_PHASE and
             row["owner_phase"] == READ_PHASE and
             type(row["job_index"]) is int and
             row["job_index"] == index and
             type(row["request_ordinal"]) is int and
             row["request_ordinal"] == index and
             row["use"] == READ_USE,
             f"old Source {host} schedule row[{index}] phase, use, or ordinal differs")
    caps = _exact(row["caps"], _BUDGET_READ_CAP_FIELDS,
                  f"old Source {host} budget schedule caps[{index}]")
    for name in ("bundle_bytes", "maximum_request_bytes",
                 "maximum_response_bytes", "stage_bytes"):
        _uint(caps[name], f"old Source {host} budget cap {name}[{index}]")
    _uint(caps["object_count"],
          f"old Source {host} budget object count[{index}]", positive=True)
    return row, caps


def _archive_read_object_id(origin_path: str, raw_sha256: str) -> str:
    origin_digest = sha256(origin_path.encode("utf-8", "strict"))
    return f"{origin_digest[:2]}/{origin_digest}-{raw_sha256}.bin"


def _archive_read_tar_size(objects: list[dict[str, Any]]) -> int:
    content = sum(
        512 + ((row["byte_count"] + 511) // 512) * 512
        for row in objects
    )
    return ((content + 1024 + MIN_TAR_BYTES - 1) // MIN_TAR_BYTES) * MIN_TAR_BYTES


def _round_file_allocation_bytes(raw_bytes: int, allocation_block_bytes: int) -> int:
    _uint(raw_bytes, "physical allocation file bytes")
    _uint(allocation_block_bytes, "physical allocation block bytes", positive=True)
    if raw_bytes == 0:
        return 0
    return ((raw_bytes + allocation_block_bytes - 1) // allocation_block_bytes) * \
        allocation_block_bytes


def _physical_window_charge(row: dict[str, Any], allocation_block_bytes: int) -> int:
    """Round every physical file in the protocol window independently."""
    bounds = row["resource_bounds"]
    objects = row["objects"]
    return (
        _round_file_allocation_bytes(bounds["outer_request_bytes"],
                                     allocation_block_bytes) +
        2 * _round_file_allocation_bytes(bounds["outer_response_bytes"],
                                         allocation_block_bytes) +
        2 * _round_file_allocation_bytes(bounds["tar_bytes"],
                                         allocation_block_bytes) +
        sum(_round_file_allocation_bytes(item["byte_count"],
                                         allocation_block_bytes)
            for item in objects)
    )


def _catalogue_row_for_pin(
    rows_by_path: dict[str, dict[str, Any]], pin: dict[str, Any],
    *, role: str, host: str, run_id: str, label: str,
    reservation_binding: object = None,
) -> dict[str, Any]:
    binding = None
    if reservation_binding is not None:
        binding = _validate_catalogue_row(
            reservation_binding, f"{label} indexed reservation binding",
        )
        reservation_path = binding["path"]
    else:
        reservation_path = pin["path"]
    row = rows_by_path.get(reservation_path)
    _require(type(row) is dict and row["kind"] == "file" and
             row["role"] == role and row["host_id"] == host and
             row["phase"] == READ_PHASE and row["run_id"] == run_id,
             f"{label} does not bind its exact old Source catalogue row")
    _require(binding is None or binding == row,
             f"{label} indexed reservation row differs from its exact old catalogue row")
    if role in {"source5_archive_ack", "source5_archive_signature"}:
        _require(reservation_path != pin["path"],
                 f"{label} collapsed its durable Root origin into the old local reservation")
    else:
        _require(reservation_path == pin["path"],
                 f"{label} old reservation path differs from its durable source pin")
    matching_rows = [candidate for candidate in rows_by_path.values()
                     if candidate["role"] == role and
                     candidate["host_id"] == host and
                     candidate["phase"] == READ_PHASE and
                     candidate["run_id"] == run_id]
    _require(len(matching_rows) == 1 and matching_rows[0] == row,
             f"{label} is not the unique exact old reservation row for this job")
    origin = row["origin_pin"]
    if origin is not None:
        _require(pin["raw_sha256"] == origin["raw_sha256"] and
                 ("semantic_sha256" not in pin or
                  origin["semantic_sha256"] is None or
                  pin["semantic_sha256"] == origin["semantic_sha256"]),
                 f"{label} differs from its present old Source origin pin")
    return row


def _validate_indexed_reservation_bindings(
    value: object, pins: dict[str, Any], host: str, run_id: str,
    label: str, *, rows_by_path: dict[str, dict[str, Any]] | None = None,
) -> dict[str, dict[str, Any]]:
    bindings = _exact(value, _INDEXED_RESERVATION_ROLES,
                      f"{label} indexed reservation bindings")
    pin_names = {
        "source5_job_record": "job_record",
        "source5_checkpoint_request": "request",
        "source5_checkpoint": "checkpoint",
        "source5_object_manifest": "object_manifest",
        "source5_archive_ack": "ack",
        "source5_archive_signature": "signature",
    }
    checked: dict[str, dict[str, Any]] = {}
    for role, pin_name in pin_names.items():
        pin = pins[pin_name]
        binding = _validate_catalogue_row(
            bindings[role], f"{label} {role} reservation row",
        )
        _require(binding["role"] == role and binding["host_id"] == host and
                 binding["phase"] == READ_PHASE and
                 binding["run_id"] == run_id,
                 f"{label} {role} reservation row has a crossed role/host/job")
        reservation_path = binding["path"]
        if role in {"source5_archive_ack", "source5_archive_signature"}:
            _require(reservation_path != pin["path"],
                     f"{label} {role} reservation aliases its durable Root path")
        else:
            _require(reservation_path == pin["path"],
                     f"{label} {role} reservation path differs from its durable pin")
        origin = binding["origin_pin"]
        if origin is not None:
            _require(pin["raw_sha256"] == origin["raw_sha256"] and
                     ("semantic_sha256" not in pin or
                      origin["semantic_sha256"] is None or
                      pin["semantic_sha256"] == origin["semantic_sha256"]),
                     f"{label} {role} reservation raw/semantic origin differs")
        if rows_by_path is not None:
            exact_row = rows_by_path.get(reservation_path)
            _require(type(exact_row) is dict and exact_row == binding,
                     f"{label} {role} helper binding differs from the supplied old catalogue")
            unique = [row for row in rows_by_path.values()
                      if row["role"] == role and row["host_id"] == host and
                      row["phase"] == READ_PHASE and row["run_id"] == run_id]
            _require(len(unique) == 1 and unique[0] == exact_row,
                     f"{label} {role} helper binding is not the unique old row")
        checked[role] = binding
    return checked


def _validate_window_metadata(
    value: object, host: str, index: int,
    rows_by_path: dict[str, dict[str, Any]],
    readback_caps: dict[str, int],
    host_budget_schedule: list[dict[str, Any]],
    campaign_id: str,
) -> dict[str, Any]:
    window = _exact(value, _WINDOW_FIELDS,
                    f"Source window metadata {host}[{index}]")
    _require(window["host_id"] == host,
             f"Source window metadata {host}[{index}] owner host differs")
    schedule, budget_caps = _validate_source_schedule(
        window["schedule_row"], host, index,
    )
    _require(schedule == host_budget_schedule[index],
             f"Source window metadata {host}[{index}] differs from its exact H budget row")
    job = schedule["job"]
    _require(type(job) is dict and job.get("phase") == READ_PHASE and
             job.get("host_id") == host and
             type(job.get("run_id")) is str and
             0 < len(job["run_id"].encode("utf-8", "strict")) <= MAX_PATH_BYTES and
             type(job.get("ordinal")) is int and job["ordinal"] > 0,
             f"Source window metadata {host}[{index}] job identity is malformed")
    job_sha = _sha(schedule["job_sha256"],
                   f"Source window metadata {host}[{index}] job digest")
    _require(job_sha == sha256(canonical_bytes(job)),
             f"Source window metadata {host}[{index}] job digest differs")
    run_id = job["run_id"]
    caps = readback_caps
    _require(budget_caps == {
        "bundle_bytes": caps["bundle_bytes"],
        "maximum_request_bytes": caps["request_bytes"],
        "maximum_response_bytes": caps["response_bytes"],
        "object_count": caps["object_count"],
        "stage_bytes": caps["stage_bytes"],
    }, f"Source window metadata {host}/{run_id} H5 caps differ from recomputed Source caps")
    job_record_pin = _pin2(window["job_record_pin"],
                           f"Source window {host}/{run_id} job-record pin")
    request_pin = _pin3(window["request_pin"],
                        f"Source window {host}/{run_id} original request pin")
    checkpoint_pin = _pin3(window["checkpoint_pin"],
                           f"Source window {host}/{run_id} checkpoint pin")
    manifest_pin = _pin3(window["object_manifest_pin"],
                         f"Source window {host}/{run_id} object-manifest pin")
    ack_pin = _pin3(window["ack_pin"],
                    f"Source window {host}/{run_id} ACK pin")
    signature_pin = _signature_pin(
        window["signature_pin"],
        f"Source window {host}/{run_id} signature pin",
    )
    receipt_pin = _host_receipt_pin(
        window["host_receipt_pin"],
        f"Source window {host}/{run_id} fixed host-receipt pin",
    )
    original_pins = {
        "job_record": job_record_pin,
        "request": request_pin,
        "checkpoint": checkpoint_pin,
        "object_manifest": manifest_pin,
        "ack": ack_pin,
        "signature": signature_pin,
    }
    reservation_bindings = _validate_indexed_reservation_bindings(
        window["indexed_reservation_bindings"], original_pins,
        host, run_id, f"Source window {host}/{run_id}",
        rows_by_path=rows_by_path,
    )
    metadata_rows = (
        (job_record_pin, "source5_job_record", "job-record"),
        (request_pin, "source5_checkpoint_request", "request"),
        (checkpoint_pin, "source5_checkpoint", "checkpoint"),
        (manifest_pin, "source5_object_manifest", "object manifest"),
        (ack_pin, "source5_archive_ack", "ACK"),
        (signature_pin, "source5_archive_signature", "signature"),
    )
    for pin, role, label in metadata_rows:
        _catalogue_row_for_pin(
            rows_by_path, pin, role=role, host=host, run_id=run_id,
            label=f"Source window {host}/{run_id} {label}",
            reservation_binding=reservation_bindings[role],
        )
    archive_root = _absolute_path(
        window["archive_source5_root"],
        f"Source window {host}/{run_id} old archive Source5 root",
    )
    _require(PurePosixPath(archive_root).name == "source5",
             f"Source window {host}/{run_id} archive root is not a Source5 root")
    manifest = _exact(window["manifest"], _MANIFEST_FIELDS,
                      f"Source window {host}/{run_id} signed manifest metadata")
    _require(manifest["schema"] == OBJECT_MANIFEST_SCHEMA_V1 and
             manifest["campaign_id"] == campaign_id and
             manifest["host_id"] == host and manifest["phase"] == READ_PHASE and
             manifest["job_index"] == index and
             manifest["job_ordinal"] == job["ordinal"] and
             manifest["job_sha256"] == job_sha and
             manifest["run_id"] == run_id and
             manifest["job_record_raw_sha256"] == job_record_pin["raw_sha256"] and
             manifest["predecessor_ack_pin"] is None,
             f"Source window {host}/{run_id} manifest does not bind its original job")
    _sha(manifest["manifest_sha256"],
         f"Source window {host}/{run_id} manifest self digest")
    _require(manifest["manifest_sha256"] ==
             sha256(canonical_bytes({
                 key: value for key, value in manifest.items()
                 if key != "manifest_sha256"
             })) and
             manifest_pin["semantic_sha256"] == manifest["manifest_sha256"],
             f"Source window {host}/{run_id} manifest semantic pin differs")
    _uint(manifest["object_count"],
          f"Source window {host}/{run_id} manifest object count", positive=True,
          maximum=MAX_OBJECTS_PER_WINDOW)
    _uint(manifest["payload_bytes"],
          f"Source window {host}/{run_id} manifest payload bytes",
          maximum=MAX_ARCHIVE_BYTES)
    objects_value = manifest["objects"]
    _require(type(objects_value) is list and
             0 < len(objects_value) <= MAX_OBJECTS_PER_WINDOW and
             len(objects_value) == manifest["object_count"] == caps["object_count"],
             f"Source window {host}/{run_id} object closure differs from its old cap")
    object_rows = []
    previous_origin = ""
    seen_origins = set()
    payload_bytes = 0
    maximum_object_bytes = 0
    receipt_rows = []
    for position, object_value in enumerate(objects_value):
        obj = _exact(object_value, _MANIFEST_OBJECT_FIELDS,
                     f"Source window {host}/{run_id} manifest object[{position}]")
        origin = _absolute_path(
            obj["origin_path"],
            f"Source window {host}/{run_id} object[{position}] origin",
        )
        _token(obj["role"],
               f"Source window {host}/{run_id} object[{position}] role")
        _sha(obj["raw_sha256"],
             f"Source window {host}/{run_id} object[{position}] raw digest")
        if obj["semantic_sha256"] is not None:
            _sha(obj["semantic_sha256"],
                 f"Source window {host}/{run_id} object[{position}] semantic digest")
        # The old v1 reader accepts zero-byte members; tar headers and padded
        # blocks still count. Keep its strict exclusive 2^33 byte ceiling.
        byte_count = _uint(
            obj["byte_count"],
            f"Source window {host}/{run_id} object[{position}] byte count",
            maximum=(1 << 33) - 1,
        )
        object_id = obj["object_id"]
        _require(type(object_id) is str and
                 object_id == _archive_read_object_id(origin, obj["raw_sha256"]),
                 f"Source window {host}/{run_id} object[{position}] content ID differs")
        object_pin = _exact(obj["object_pin"], _OBJECT_PIN_FIELDS,
                            f"Source window {host}/{run_id} object[{position}] archive pin")
        _uint(object_pin["byte_count"],
              f"Source window {host}/{run_id} object[{position}] archive byte count",
              maximum=(1 << 33) - 1)
        expected_object_path = str(PurePosixPath(archive_root) / "objects" / object_id)
        _require(object_pin["path"] == expected_object_path and
                 object_pin["raw_sha256"] == obj["raw_sha256"] and
                 object_pin["semantic_sha256"] == obj["raw_sha256"] and
                 object_pin["byte_count"] == byte_count,
                 f"Source window {host}/{run_id} object[{position}] archive pin differs")
        _absolute_path(object_pin["path"],
                       f"Source window {host}/{run_id} object[{position}] archive path")
        catalogue_row = rows_by_path.get(origin)
        # The Source caller must authenticate this selected manifest before
        # supplying the row. Its H schedule and manifest fields bind the
        # window to ``host`` here. Preserve Source's null labels on ordinary
        # payload rows while checking every present host and exact path/role/
        # phase/run/cap joins.
        _require(type(catalogue_row) is dict and
                 catalogue_row["kind"] == "file" and
                 catalogue_row["role"] == obj["role"] and
                 (catalogue_row["host_id"] is None or
                  catalogue_row["host_id"] == host) and
                 catalogue_row["phase"] == READ_PHASE and
                 catalogue_row["run_id"] == run_id and
                 byte_count <= catalogue_row["max_file_bytes"],
                 f"Source window {host}/{run_id} object[{position}] is outside its old catalogue row")
        origin_pin = catalogue_row["origin_pin"]
        if origin_pin is not None:
            _require(obj["raw_sha256"] == origin_pin["raw_sha256"] and
                     (origin_pin["semantic_sha256"] is None or
                      obj["semantic_sha256"] == origin_pin["semantic_sha256"]),
                     f"Source window {host}/{run_id} object[{position}] differs from its old origin pin")
        _require(origin not in seen_origins and origin > previous_origin,
                 f"Source window {host}/{run_id} objects are repeated or not sorted")
        seen_origins.add(origin)
        previous_origin = origin
        payload_bytes += byte_count
        _require(payload_bytes <= MAX_ARCHIVE_BYTES,
                 f"Source window {host}/{run_id} payload exceeds the Source archive ceiling")
        maximum_object_bytes = max(maximum_object_bytes, byte_count)
        if obj["role"] == "fixed_pair_host_receipt":
            receipt_rows.append(obj)
        object_rows.append(obj)
    _require(payload_bytes == manifest["payload_bytes"] and
             payload_bytes <= caps["stage_bytes"] and
             maximum_object_bytes <= caps["maximum_object_bytes"] and
             _archive_read_tar_size([
                 {"byte_count": obj["byte_count"]} for obj in object_rows
             ]) <= caps["bundle_bytes"],
             f"Source window {host}/{run_id} objects exceed their exact old readback caps")
    _require(manifest_pin["raw_sha256"] != "" and
             len(receipt_rows) == 1 and
             receipt_rows[0]["origin_path"] == receipt_pin["path"] and
             receipt_rows[0]["raw_sha256"] == receipt_pin["raw_sha256"] and
             receipt_rows[0]["semantic_sha256"] ==
                 receipt_pin["host_verification_sha256"],
             f"Source window {host}/{run_id} manifest omits its exact host receipt")
    return {
        "host_id": host,
        "schedule_row": schedule,
        "job": job,
        "job_sha256": job_sha,
        "job_index": index,
        "run_id": run_id,
        "pins": {
            "job_record": job_record_pin,
            "request": request_pin,
            "checkpoint": checkpoint_pin,
            "object_manifest": manifest_pin,
            "ack": ack_pin,
            "signature": signature_pin,
            "host_receipt": receipt_pin,
        },
        "indexed_reservation_bindings": reservation_bindings,
        "archive_source5_root": archive_root,
        "manifest": manifest,
        "objects": object_rows,
        "payload_bytes": payload_bytes,
        "maximum_object_bytes": maximum_object_bytes,
        "tar_bytes": _archive_read_tar_size([
            {"byte_count": obj["byte_count"]} for obj in object_rows
        ]),
    }


def _legacy_request(
    campaign_id: str, owner_host_id: str, read_ordinal: int,
    objects: list[dict[str, Any]], maximum_response_bytes: int,
) -> dict[str, Any]:
    body = {
        "schema": LEGACY_REQUEST_SCHEMA_V1,
        "campaign_id": campaign_id,
        "host_id": owner_host_id,
        "analysis_phase": READ_PHASE,
        "request_ordinal": read_ordinal,
        "objects": objects,
        "maximum_response_bytes": maximum_response_bytes,
        "request_sha256": "",
    }
    return {**body, "request_sha256": sha256(canonical_bytes({
        key: value for key, value in body.items() if key != "request_sha256"
    }))}


def _legacy_request_for_plan_row(
    plan: dict[str, Any], row: dict[str, Any],
) -> dict[str, Any]:
    objects = [{
        "owner_job_sha256": row["job_sha256"],
        "origin_path": obj["origin_path"],
        "raw_sha256": obj["raw_sha256"],
        "byte_count": obj["byte_count"],
    } for obj in row["objects"]]
    request = _legacy_request(
        plan["campaign_id"], row["owner_host_id"], row["read_ordinal"],
        objects, row["recomputed_source_caps"]["bundle_bytes"],
    )
    _require(request["request_sha256"] == row["legacy_request_sha256"],
             f"read-plan row[{row['read_ordinal']}] inner request digest differs")
    return request


def _legacy_response(
    request: dict[str, Any], tar_sha256: str, tar_bytes: int,
) -> dict[str, Any]:
    request_raw = canonical_bytes(request)
    body = {
        "schema": LEGACY_RESPONSE_SCHEMA_V1,
        "campaign_id": request["campaign_id"],
        "host_id": request["host_id"],
        "analysis_phase": request["analysis_phase"],
        "request_ordinal": request["request_ordinal"],
        "request_pin": {
            "raw_sha256": sha256(request_raw),
            "semantic_sha256": request["request_sha256"],
        },
        "objects": request["objects"],
        "body_tar_pin": {"raw_sha256": tar_sha256,
                          "byte_count": tar_bytes},
        "response_sha256": "",
    }
    return {**body, "response_sha256": sha256(canonical_bytes({
        key: value for key, value in body.items() if key != "response_sha256"
    }))}


def _outer_request(
    basis_pin: dict[str, Any], plan_pin: dict[str, Any], nonce: str,
    consumer: str, operation: str, read_ordinal: int,
    row: dict[str, Any], *, request_sha256: str,
    schema: str = REQUEST_SCHEMA_V2,
) -> dict[str, Any]:
    return {
        "schema": schema,
        "basis_pin": basis_pin,
        "read_plan_pin": plan_pin,
        "session_nonce": nonce,
        "consumer_host_id": consumer,
        "owner_host_id": row["owner_host_id"],
        "operation_kind": operation,
        "read_ordinal": read_ordinal,
        "job_index": row["job_index"],
        "job_sha256": row["job_sha256"],
        "object_manifest_pin": row["original_pins"]["object_manifest"],
        "legacy_request": row["legacy_request"],
        "request_sha256": request_sha256,
    }


def _outer_response(
    basis_pin: dict[str, Any], plan_pin: dict[str, Any], nonce: str,
    consumer: str, operation: str, read_ordinal: int,
    request_pin: dict[str, Any], legacy_response: dict[str, Any], *,
    response_sha256: str, schema: str = RESPONSE_SCHEMA_V2,
) -> dict[str, Any]:
    return {
        "schema": schema,
        "basis_pin": basis_pin,
        "read_plan_pin": plan_pin,
        "session_nonce": nonce,
        "consumer_host_id": consumer,
        "owner_host_id": legacy_response["host_id"],
        "operation_kind": operation,
        "read_ordinal": read_ordinal,
        "request_pin": request_pin,
        "legacy_response": legacy_response,
        "response_sha256": response_sha256,
    }


def _read_plan_pin_placeholder(plan_path: str) -> dict[str, str]:
    return {"path": plan_path, "raw_sha256": "f" * 64,
            "semantic_sha256": "f" * 64}


def _validate_readback_caps_host_maxima(
    caps_by_run: dict[str, dict[str, int]], host: str,
) -> None:
    _require(len(caps_by_run) == READ_JOB_COUNT_PER_HOST,
             f"old Source {host} does not have exactly 360 projected read caps")
    maxima = {
        "maximum_request_bytes": "request_bytes",
        "maximum_response_bytes": "response_bytes",
        "maximum_bundle_bytes": "bundle_bytes",
        "maximum_stage_bytes": "stage_bytes",
        "maximum_stage_inodes": "stage_inodes",
        "maximum_object_count": "object_count",
        "maximum_live_window_bytes": "live_window_bytes",
        "maximum_live_window_inodes": "live_window_inodes",
    }
    for cap in caps_by_run.values():
        for maximum_field, local_field in maxima.items():
            _require(cap[maximum_field] == max(
                row[local_field] for row in caps_by_run.values()
            ), f"old Source {host} global {maximum_field} is inconsistent")
        _require(cap["maximum_object_bytes"] == max(
            row["maximum_object_bytes"] for row in caps_by_run.values()
        ), f"old Source {host} global maximum object bytes are inconsistent")


def _project_source_window(
    *, basis: dict[str, Any], basis_pin: dict[str, Any],
    plan_path: str, nonce: str, consumer: str,
    read_ordinal: int, owner_host_id: str, host_position: int,
    window: dict[str, Any], caps: dict[str, int],
    request_schema: str = REQUEST_SCHEMA_V2,
    response_schema: str = RESPONSE_SCHEMA_V2,
) -> dict[str, Any]:
    schedule = window["schedule_row"]
    job_index = window["job_index"]
    _require(read_ordinal == host_position * READ_JOB_COUNT_PER_HOST + job_index,
             "recorded-preparation read ordinal differs from the ordered host cursor")
    legacy_objects = [{
        "owner_job_sha256": window["job_sha256"],
        "origin_path": obj["origin_path"],
        "raw_sha256": obj["raw_sha256"],
        "byte_count": obj["byte_count"],
    } for obj in window["objects"]]
    _require(legacy_objects == sorted(
        legacy_objects, key=lambda obj: obj["origin_path"],
    ), "recorded-preparation legacy objects are not sorted")
    legacy_request = _legacy_request(
        basis["campaign_id"], owner_host_id, read_ordinal,
        legacy_objects, caps["bundle_bytes"],
    )
    legacy_request_raw = canonical_bytes(legacy_request)
    _require(0 < len(legacy_request_raw) <= MAX_METADATA_BYTES and
             len(legacy_request_raw) <= caps["request_bytes"],
             f"recorded-preparation legacy request exceeds old Source cap at {read_ordinal}")
    tar_bytes = window["tar_bytes"]
    legacy_response = _legacy_response(
        legacy_request, "f" * 64, tar_bytes,
    )
    legacy_response_raw = canonical_bytes(legacy_response)
    _require(0 < len(legacy_response_raw) <= MAX_METADATA_BYTES and
             len(legacy_response_raw) <= caps["response_bytes"],
             f"recorded-preparation legacy response exceeds old Source cap at {read_ordinal}")
    plan_pin_placeholder = _read_plan_pin_placeholder(plan_path)
    outer_request = _outer_request(
        basis_pin, plan_pin_placeholder, nonce, consumer,
        basis["operation_kind"], read_ordinal, {
            "owner_host_id": owner_host_id,
            "job_index": job_index,
            "job_sha256": window["job_sha256"],
            "original_pins": window["pins"],
            "legacy_request": legacy_request,
        }, request_sha256="f" * 64,
        schema=request_schema,
    )
    outer_request["request_sha256"] = sha256(canonical_bytes({
        key: value for key, value in outer_request.items()
        if key != "request_sha256"
    }))
    outer_request_bytes = len(canonical_bytes(outer_request))
    outer_request_pin_placeholder = {
        "path": str(PurePosixPath(plan_path).parent / "slot" / "request.json"),
        "raw_sha256": "f" * 64,
        "semantic_sha256": "f" * 64,
    }
    outer_response = _outer_response(
        basis_pin, plan_pin_placeholder, nonce, consumer,
        basis["operation_kind"], read_ordinal,
        outer_request_pin_placeholder, legacy_response,
        response_sha256="f" * 64, schema=response_schema,
    )
    outer_response["response_sha256"] = sha256(canonical_bytes({
        key: value for key, value in outer_response.items()
        if key != "response_sha256"
    }))
    outer_response_bytes = len(canonical_bytes(outer_response))
    _require(0 < outer_request_bytes <= MAX_METADATA_BYTES and
             0 < outer_response_bytes <= MAX_METADATA_BYTES,
             f"recorded-preparation outer envelope exceeds 16 MiB at {read_ordinal}")
    payload_bytes = window["payload_bytes"]
    object_count = len(window["objects"])
    window_bytes = (outer_request_bytes + 2 * outer_response_bytes +
                    2 * tar_bytes + payload_bytes)
    window_inodes = object_count + 6
    _require(window_bytes <= 3 * MAX_ARCHIVE_BYTES + 3 * MAX_METADATA_BYTES and
             window_inodes <= MAX_OBJECTS_PER_WINDOW + 6,
             f"recorded-preparation physical window exceeds finite bounds at {read_ordinal}")
    return {
        "read_ordinal": read_ordinal,
        "consumer_host_id": consumer,
        "owner_host_id": owner_host_id,
        "operation_kind": basis["operation_kind"],
        "job_index": job_index,
        "job": window["job"],
        "job_sha256": window["job_sha256"],
        "original_pins": window["pins"],
        "indexed_reservation_bindings": window[
            "indexed_reservation_bindings"],
        "archive_source5_root": window["archive_source5_root"],
        "manifest_summary": {
            "schema": window["manifest"]["schema"],
            "campaign_id": window["manifest"]["campaign_id"],
            "host_id": window["manifest"]["host_id"],
            "phase": window["manifest"]["phase"],
            "job_index": window["manifest"]["job_index"],
            "job_ordinal": window["manifest"]["job_ordinal"],
            "job_sha256": window["manifest"]["job_sha256"],
            "run_id": window["manifest"]["run_id"],
            "job_record_raw_sha256": window["manifest"][
                "job_record_raw_sha256"],
            "predecessor_ack_pin": window["manifest"][
                "predecessor_ack_pin"],
            "object_count": window["manifest"]["object_count"],
            "payload_bytes": window["manifest"]["payload_bytes"],
            "manifest_sha256": window["manifest"]["manifest_sha256"],
        },
        "objects": window["objects"],
        "source_budget_schedule_caps": schedule["caps"],
        "recomputed_source_caps": {
            "maximum_request_bytes": caps["request_bytes"],
            "maximum_response_bytes": caps["response_bytes"],
            "bundle_bytes": caps["bundle_bytes"],
            "stage_bytes": caps["stage_bytes"],
            "stage_inodes": caps["stage_inodes"],
            "object_count": caps["object_count"],
            "maximum_object_bytes": caps["maximum_object_bytes"],
            "live_window_bytes": caps["live_window_bytes"],
            "live_window_inodes": caps["live_window_inodes"],
        },
        "legacy_request_sha256": legacy_request["request_sha256"],
        "resource_bounds": {
            "legacy_request_bytes": len(legacy_request_raw),
            "legacy_response_bytes": len(legacy_response_raw),
            "outer_request_bytes": outer_request_bytes,
            "outer_response_bytes": outer_response_bytes,
            "tar_bytes": tar_bytes,
            "payload_bytes": payload_bytes,
            "object_count": object_count,
            "maximum_object_bytes": window["maximum_object_bytes"],
            "window_bytes": window_bytes,
            "window_inodes": window_inodes,
        },
    }


def _session_descriptor(
    basis: dict[str, Any], basis_pin: dict[str, Any],
    plan_path: str, nonce: str, *, schema: str = SESSION_DESCRIPTOR_SCHEMA_V2,
) -> dict[str, Any]:
    return _seal({
        "schema": schema,
        "basis_pin": basis_pin,
        "read_plan_pin": _read_plan_pin_placeholder(plan_path),
        "session_nonce": nonce,
        "consumer_host_id": basis["consumer_host_id"],
        "operation_kind": basis["operation_kind"],
        "current_journal_frontier": basis["current_journal_frontier"],
        "session_sha256": "f" * 64,
    }, "session_sha256")


def _control_event_value(
    plan_row: dict[str, Any], basis_pin: dict[str, Any],
    plan_pin: dict[str, Any], nonce: str, action: str, sequence: int,
    *, request_pin: dict[str, Any], response_pin: dict[str, Any] | None,
    bundle_pin: dict[str, Any] | None,
    schema: str = CONTROL_EVENT_SCHEMA_V2,
) -> dict[str, Any]:
    _require(action in {"request_published", "view_released"},
             "recorded-preparation control action is outside the exact schedule")
    row = plan_row
    bounds = row["resource_bounds"]
    return {
        "schema": schema,
        "sequence": sequence,
        "basis_pin": basis_pin,
        "read_plan_pin": plan_pin,
        "session_nonce": nonce,
        "consumer_host_id": row["consumer_host_id"],
        "owner_host_id": row["owner_host_id"],
        "operation_kind": row["operation_kind"],
        "read_ordinal": row["read_ordinal"],
        "job_index": row["job_index"],
        "job_sha256": row["job_sha256"],
        "object_manifest_pin": row["original_pins"]["object_manifest"],
        "action": action,
        "request_pin": request_pin,
        "request_byte_count": bounds["outer_request_bytes"],
        "response_pin": response_pin,
        "response_byte_count": (None if response_pin is None
                                 else bounds["outer_response_bytes"]),
        "bundle_pin": bundle_pin,
        "object_count": bounds["object_count"],
        "payload_bytes": bounds["payload_bytes"],
        "stage_root": row["session_stage_root"],
    }


def _control_ledger_width(
    rows: list[dict[str, Any]], basis_pin: dict[str, Any],
    plan_path: str, nonce: str, consumer: str, *,
    schema: str = CONTROL_EVENT_SCHEMA_V2,
) -> dict[str, int]:
    plan_pin = _read_plan_pin_placeholder(plan_path)
    total = 0
    maximum_line = 0
    for row in rows:
        ordinal = row["read_ordinal"]
        slot_paths = row["session_paths"]
        request_pin = {
            "path": slot_paths["request"],
            "raw_sha256": "f" * 64,
            "semantic_sha256": "f" * 64,
        }
        request_record = _control_event_value(
            row, basis_pin, plan_pin, nonce, "request_published",
            2 * ordinal + 1, request_pin=request_pin,
            response_pin=None, bundle_pin=None, schema=schema,
        )
        response_pin = {
            "path": slot_paths["response"],
            "raw_sha256": "f" * 64,
            "semantic_sha256": "f" * 64,
        }
        bundle_pin = {
            "path": slot_paths["bundle"],
            "raw_sha256": "f" * 64,
            "byte_count": row["resource_bounds"]["tar_bytes"],
        }
        release_record = _control_event_value(
            row, basis_pin, plan_pin, nonce, "view_released",
            2 * ordinal + 2, request_pin=request_pin,
            response_pin=response_pin, bundle_pin=bundle_pin, schema=schema,
        )
        for record in (request_record, release_record):
            line = canonical_bytes({
                "previous_sha256": "f" * 64,
                "record": record,
                "record_sha256": "f" * 64,
            })
            total += len(line)
            maximum_line = max(maximum_line, len(line))
    _require(len(rows) == READ_WINDOW_COUNT and
             total > 0 and maximum_line > 0 and
             maximum_line <= MAX_METADATA_BYTES and
             total <= MAX_CONTROL_LEDGER_BYTES,
             "recorded-preparation control ledger exceeds its finite exact schedule")
    return {
        "event_count": READ_CONTROL_EVENT_COUNT,
        "maximum_line_bytes": maximum_line,
        "maximum_bytes": total,
    }


def _failure_receipt_size(
    basis_pin: dict[str, Any], plan_path: str, nonce: str,
    consumer: str, operation: str, bounds: dict[str, int], *,
    schema: str = FAILURE_RECEIPT_SCHEMA_V2,
) -> int:
    receipt = _seal({
        "schema": schema,
        "basis_pin": basis_pin,
        "read_plan_pin": _read_plan_pin_placeholder(plan_path),
        "session_nonce": nonce,
        "consumer_host_id": consumer,
        "operation_kind": operation,
        "read_ordinal": READ_WINDOW_COUNT - 1,
        "job_index": READ_JOB_COUNT_PER_HOST - 1,
        "failure_kind": "cleanup_failed",
        "retained_window_bytes": bounds["window_bytes"],
        "retained_window_inodes": bounds["window_inodes"],
        "failure_sha256": "f" * 64,
    }, "failure_sha256")
    size = len(canonical_bytes(receipt))
    _require(0 < size <= MAX_METADATA_BYTES,
             "recorded-preparation failure receipt exceeds 16 MiB")
    return size


def _make_window_metadata_chunks(
    read_rows: list[dict[str, Any]], basis_pin: dict[str, Any],
    campaign_id: str, consumer: str, hosts: list[str], operation: str,
    nonce: str, chunk_root: str, *,
    schema: str = WINDOW_METADATA_CHUNK_SCHEMA_V1,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Seal ordered bounded chunks and their compact 720-entry index."""
    index: list[dict[str, Any]] = []
    refs: list[dict[str, Any]] = []
    chunks: list[dict[str, Any]] = []
    first = 0
    while first < len(read_rows):
        count = min(MAX_WINDOWS_PER_METADATA_CHUNK, len(read_rows) - first)
        while count > 0:
            rows = read_rows[first:first + count]
            ordinals = [row["read_ordinal"] for row in rows]
            chunk_ordinal = len(chunks)
            body = {
                "schema": schema,
                "basis_pin": basis_pin,
                "campaign_id": campaign_id,
                "consumer_host_id": consumer,
                "cohort_hosts": hosts,
                "operation_kind": operation,
                "session_nonce": nonce,
                "chunk_ordinal": chunk_ordinal,
                "first_read_ordinal": first,
                "read_ordinals": ordinals,
                "rows": rows,
                "window_chunk_sha256": "",
            }
            chunk = _seal(body, "window_chunk_sha256")
            raw = canonical_bytes(chunk)
            if 0 < len(raw) <= MAX_METADATA_BYTES:
                break
            count -= 1
        _require(count > 0,
                 f"recorded-preparation window {first} exceeds the chunk metadata ceiling")
        path = str(PurePosixPath(chunk_root) / f"chunk-{len(chunks):06d}.json")
        _absolute_path(path, "recorded-preparation window-chunk path")
        pin = {
            "path": path, "raw_sha256": sha256(raw),
            "semantic_sha256": chunk["window_chunk_sha256"],
        }
        chunk_ref = {
            "chunk_ordinal": len(chunks), "first_read_ordinal": first,
            "window_count": count, "read_ordinals": ordinals,
            "pin": pin, "byte_count": len(raw),
        }
        refs.append(chunk_ref)
        chunks.append(chunk)
        for row_index, row in enumerate(rows):
            index.append({
                "read_ordinal": row["read_ordinal"],
                "owner_host_id": row["owner_host_id"],
                "job_index": row["job_index"],
                "job_sha256": row["job_sha256"],
                "chunk_ordinal": len(chunks) - 1,
                "chunk_row": row_index,
                "row_sha256": sha256(canonical_bytes(row)),
            })
        first += count
    _require(len(index) == READ_WINDOW_COUNT and
             [row["read_ordinal"] for row in index] ==
                 list(range(READ_WINDOW_COUNT)) and
             sum(row["window_count"] for row in refs) == READ_WINDOW_COUNT,
             "recorded-preparation chunk index does not close over all 720 windows")
    return index, refs, chunks


def _build_recorded_preparation_read_plan_core(
    basis_value: object,
    basis_pin: object,
    *,
    old_catalogues_by_host: object,
    old_readback_caps_by_host: object,
    window_metadata_by_host: object,
    session_nonce: object,
    scratch_declaration: object,
    timeout_declaration: object,
    _construction: bool,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Build a compact 720-window index and separately pinned row chunks.

    The returned plan contains only an ordered index and exact chunk refs. The
    second return value contains the canonical metadata documents to persist at
    those refs. Each chunk has at most sixteen full rows and each document is
    independently bounded by ``MAX_METADATA_BYTES``. The chunks retain every
    Source-derived row; this does not change the cohort or metadata ceiling.

    ``old_readback_caps_by_host`` must be the complete per-job result of the
    pinned typed Source Budget module's
    ``project_fixed_pair_archive_readback_caps``. The actual Source loader must
    also call the typed ``source5_indexed_reservation_binding_v1`` for all six
    indexed roles. This pure projection checks the supplied results and grants
    no authority or verification claim.

    """
    _require(type(_construction) is bool,
             "recorded-preparation schema selector is malformed")
    if _construction:
        basis, checked_basis_pin, hosts = _validate_construction_basis(
            basis_value, basis_pin,
        )
    else:
        basis, checked_basis_pin, hosts = _validate_basis(
            basis_value, basis_pin,
        )
    schemas = _plan_schema_set(construction=_construction)
    nonce = session_nonce
    _require(type(nonce) is str and _NONCE.fullmatch(nonce) is not None,
             "recorded-preparation session nonce must be fresh lowercase 32-hex text")
    scratch = _validate_scratch(scratch_declaration)
    timeouts = _validate_timeouts(timeout_declaration)
    _require(scratch["root"] != "/",
             "recorded-preparation scratch cannot be a filesystem root")
    layout_builder = _construction_layout if _construction else _layout
    layout = layout_builder(
        scratch["root"], basis["campaign_id"], basis["consumer_host_id"], nonce,
    )
    _require(checked_basis_pin["path"] == layout["basis"],
             "recorded-preparation basis pin is not at its nonce-derived session path")

    catalogues = _validate_catalogues(old_catalogues_by_host, hosts)
    caps_by_host = _validate_readback_caps(old_readback_caps_by_host, hosts)
    windows_map = _exact(window_metadata_by_host, set(hosts),
                         "Source window metadata host map")
    checked_windows: dict[str, list[dict[str, Any]]] = {}
    for host in hosts:
        windows_value = windows_map[host]
        _require(type(windows_value) is list and
                 len(windows_value) == READ_JOB_COUNT_PER_HOST,
                 f"Source window metadata for {host} must contain exactly 360 rows")
        budget_schedule = []
        for index, window_value in enumerate(windows_value):
            _require(type(window_value) is dict and
                     type(window_value.get("schedule_row")) is dict,
                     f"Source window metadata {host}[{index}] lacks its H budget row")
            budget_schedule.append(window_value["schedule_row"])
        checked: list[dict[str, Any]] = []
        rows_by_path = {row["path"]: row for row in catalogues[host]}
        run_ids = set()
        for index, value in enumerate(windows_value):
            _require(type(value) is dict and
                     type(budget_schedule[index]) is dict and
                     type(budget_schedule[index].get("job")) is dict,
                     f"Source window metadata {host}[{index}] lacks an exact H budget job")
            run_id = budget_schedule[index]["job"].get("run_id")
            _require(type(run_id) is str and run_id in caps_by_host[host],
                     f"Source window metadata {host}[{index}] has no recomputed old cap")
            window = _validate_window_metadata(
                value, host, index, rows_by_path,
                caps_by_host[host][run_id],
                budget_schedule, basis["campaign_id"],
            )
            run_id = window["run_id"]
            _require(run_id in caps_by_host[host] and run_id not in run_ids,
                     f"Source window metadata for {host} repeats or lacks an old run")
            run_ids.add(run_id)
            checked.append(window)
        _require(set(run_ids) == set(caps_by_host[host]),
                 f"Source window metadata for {host} differs from its exact 360 caps")
        _validate_readback_caps_host_maxima(caps_by_host[host], host)
        checked_windows[host] = checked

    _validate_layout_disjointness(
        scratch["root"], basis, catalogues, windows_map,
    )
    total_object_count = sum(
        len(window["objects"])
        for host in hosts for window in checked_windows[host]
    )
    _require(0 < total_object_count <= MAX_OBJECTS_PER_SESSION,
             "recorded-preparation session object count exceeds its 262144 ceiling")

    read_rows: list[dict[str, Any]] = []
    for host_position, host in enumerate(hosts):
        for index, window in enumerate(checked_windows[host]):
            read_ordinal = host_position * READ_JOB_COUNT_PER_HOST + index
            caps = caps_by_host[host][window["run_id"]]
            projected = _project_source_window(
                basis=basis, basis_pin=checked_basis_pin,
                plan_path=layout["read_plan"], nonce=nonce,
                consumer=basis["consumer_host_id"],
                read_ordinal=read_ordinal, owner_host_id=host,
                host_position=host_position, window=window, caps=caps,
                request_schema=schemas["request"],
                response_schema=schemas["response"],
            )
            projected["session_stage_root"] = layout["stage"]
            projected["session_paths"] = {
                "request": layout["request"],
                "response_incoming": layout["response_incoming"],
                "response": layout["response"],
                "bundle_incoming": layout["bundle_incoming"],
                "bundle": layout["bundle"],
                "stage": layout["stage"],
            }
            read_rows.append(projected)
    _require(len(read_rows) == READ_WINDOW_COUNT and
             [row["read_ordinal"] for row in read_rows] ==
                 list(range(READ_WINDOW_COUNT)) and
             [row["owner_host_id"] for row in read_rows[:READ_JOB_COUNT_PER_HOST]] ==
                 [hosts[0]] * READ_JOB_COUNT_PER_HOST and
             [row["owner_host_id"] for row in read_rows[READ_JOB_COUNT_PER_HOST:]] ==
                 [hosts[1]] * READ_JOB_COUNT_PER_HOST,
             "recorded-preparation schedule is not the exact ordered 720-row cohort")

    window_bytes = max(row["resource_bounds"]["window_bytes"]
                       for row in read_rows)
    window_inodes = max(row["resource_bounds"]["window_inodes"]
                        for row in read_rows)
    allocation_block = scratch["allocation_block_bytes"]
    window_physical_bytes = max(
        _physical_window_charge(row, allocation_block) for row in read_rows
    )
    basis_bytes = len(canonical_bytes(basis))
    basis_allocated_bytes = _round_file_allocation_bytes(
        basis_bytes, allocation_block,
    )
    session_descriptor = _session_descriptor(
        basis, checked_basis_pin, layout["read_plan"], nonce,
        schema=schemas["session"],
    )
    session_descriptor_bytes = len(canonical_bytes(session_descriptor))
    session_descriptor_allocated_bytes = _round_file_allocation_bytes(
        session_descriptor_bytes, allocation_block,
    )
    control = _control_ledger_width(
        read_rows, checked_basis_pin, layout["read_plan"], nonce,
        basis["consumer_host_id"], schema=schemas["control"],
    )
    _require(control["maximum_bytes"] <= MAX_METADATA_BYTES,
             "recorded-preparation control ledger exceeds the 16 MiB document ceiling")
    failure_bytes = _failure_receipt_size(
        checked_basis_pin, layout["read_plan"], nonce,
        basis["consumer_host_id"], basis["operation_kind"], {
            "window_bytes": window_bytes,
            "window_inodes": window_inodes,
        },
        schema=schemas["failure"],
    )
    control_allocated_bytes = _round_file_allocation_bytes(
        control["maximum_bytes"], allocation_block,
    )
    failure_allocated_bytes = _round_file_allocation_bytes(
        failure_bytes, allocation_block,
    )
    window_index, window_chunks, chunk_values = _make_window_metadata_chunks(
        read_rows, checked_basis_pin, basis["campaign_id"],
        basis["consumer_host_id"], hosts, basis["operation_kind"], nonce,
        layout["window_metadata_root"], schema=schemas["chunk"],
    )
    chunk_bytes = sum(ref["byte_count"] for ref in window_chunks)
    chunk_count = len(window_chunks)
    chunk_allocated_bytes = sum(
        ((ref["byte_count"] + allocation_block - 1) // allocation_block) *
        allocation_block for ref in window_chunks
    )
    index_bytes = len(canonical_bytes(window_index))
    chunk_ref_bytes = len(canonical_bytes(window_chunks))
    chunk_maximum_bytes = max(ref["byte_count"] for ref in window_chunks)
    _require(chunk_count <= READ_WINDOW_COUNT and
             chunk_bytes <= MAX_METADATA_BYTES * READ_WINDOW_COUNT and
             index_bytes <= MAX_METADATA_BYTES and
             chunk_ref_bytes <= MAX_METADATA_BYTES,
             "recorded-preparation chunk metadata exceeds its finite aggregate bounds")
    directories = layout["directories"]
    _require(len(directories) == 8 and len(set(directories)) == 8,
             "recorded-preparation layout does not declare its exact eight directories")
    plan_document_guess = 0
    plan_value: dict[str, Any]
    for _iteration in range(8):
        plan_allocated_bytes = _round_file_allocation_bytes(
            plan_document_guess, allocation_block,
        )
        required_bytes = (
            window_physical_bytes + window_physical_bytes +
            basis_allocated_bytes + plan_allocated_bytes +
            chunk_allocated_bytes + session_descriptor_allocated_bytes +
            control_allocated_bytes + failure_allocated_bytes +
            scratch["directory_metadata_reserve_bytes"]
        )
        directory_nodes = len(directories)
        required_inodes = (window_inodes + window_inodes + 3 + 1 + 1 +
                           directory_nodes + chunk_count)
        projection = {
            "window_bytes": window_bytes,
            "window_inodes": window_inodes,
            "failure_window_bytes": window_bytes,
            "failure_window_inodes": window_inodes,
            "window_physical_bytes": window_physical_bytes,
            "failure_window_physical_bytes": window_physical_bytes,
            "maximum_retained_failure_windows": 1,
            "basis_document_bytes": basis_bytes,
            "basis_document_allocated_bytes": basis_allocated_bytes,
            "read_plan_document_bytes": plan_document_guess,
            "read_plan_document_allocated_bytes": plan_allocated_bytes,
            "window_index_document_bytes": index_bytes,
            "window_chunk_ref_document_bytes": chunk_ref_bytes,
            "window_metadata_chunk_bytes": chunk_bytes,
            "window_metadata_chunk_allocated_bytes": chunk_allocated_bytes,
            "window_metadata_allocation_block_bytes": allocation_block,
            "window_metadata_chunk_count": chunk_count,
            "window_metadata_chunk_max_bytes": chunk_maximum_bytes,
            "window_metadata_chunk_inode_count": chunk_count + 1,
            "window_metadata_chunk_file_fsync_count": chunk_count,
            "window_metadata_chunk_directory_fsync_count": 1,
            "window_metadata_chunk_parent_fsync_count": 1,
            "window_metadata_chunk_fsync_count": chunk_count + 2,
            "session_descriptor_bytes": session_descriptor_bytes,
            "session_descriptor_allocated_bytes":
                session_descriptor_allocated_bytes,
            "control_ledger_bytes": control["maximum_bytes"],
            "control_ledger_allocated_bytes": control_allocated_bytes,
            "control_ledger_maximum_line_bytes": control["maximum_line_bytes"],
            "control_event_count": control["event_count"],
            "failure_receipt_bytes": failure_bytes,
            "failure_receipt_allocated_bytes": failure_allocated_bytes,
            "directory_node_count": directory_nodes,
            "directory_metadata_reserve_bytes":
                scratch["directory_metadata_reserve_bytes"],
            "directory_node_bytes":
                scratch["directory_metadata_reserve_bytes"],
            "required_bytes": required_bytes,
            "required_inodes": required_inodes,
            "declared_reserved_bytes": scratch["reserved_bytes"],
            "declared_reserved_inodes": scratch["reserved_inodes"],
        }
        plan_body = {
            "schema": schemas["plan"],
            "campaign_id": basis["campaign_id"],
            "consumer_host_id": basis["consumer_host_id"],
            "cohort_hosts": hosts,
            "operation_kind": basis["operation_kind"],
            "basis_pin": checked_basis_pin,
            "session_nonce": nonce,
            "scratch_declaration": scratch,
            "timeout_declaration": timeouts,
            "session_paths": layout,
            "current_journal_frontier": basis["current_journal_frontier"],
            "window_index": window_index,
            "window_chunks": window_chunks,
            "resource_projection": projection,
            "failed_window_policy": {
                "retention": "retain_one_exact_failed_window",
                "next_window": "blocked_until_exact_cleanup",
                "new_nonce_before_cleanup": "refused",
            },
            "read_plan_sha256": "",
        }
        if _construction:
            plan_body["completion_output_reservation"] = \
                _construction_output_plan_reservation(
                    basis, scratch, projection,
                )
        plan_value = _seal(plan_body, "read_plan_sha256")
        raw = canonical_bytes(plan_value)
        _require(0 < len(raw) <= MAX_METADATA_BYTES,
                 "recorded-preparation compact read plan exceeds 16 MiB")
        next_guess = len(raw)
        if next_guess == plan_document_guess:
            break
        plan_document_guess = next_guess
    else:
        raise RecordedPreparationReadPlanError(
            "recorded-preparation compact read-plan size projection did not converge",
        )

    projection = plan_value["resource_projection"]
    _require(projection["read_plan_document_bytes"] == len(canonical_bytes(plan_value)) and
             all(0 < len(canonical_bytes(chunk)) <= MAX_METADATA_BYTES
                 for chunk in chunk_values) and
             projection["window_metadata_chunk_bytes"] ==
                 sum(len(canonical_bytes(chunk)) for chunk in chunk_values),
             "recorded-preparation index/chunk size projection differs")
    required_bytes = projection["required_bytes"]
    required_inodes = projection["required_inodes"]
    _require(scratch["reserved_bytes"] >= required_bytes and
             scratch["reserved_inodes"] >= required_inodes,
             "recorded-preparation scratch reservation is below its exact finite plan")
    if _construction:
        output_reservation = plan_value["completion_output_reservation"]
        if output_reservation["same_device_as_scratch"]:
            _require(scratch["reserved_bytes"] +
                     output_reservation["declared_reserved_bytes"] >=
                     output_reservation["same_device_required_bytes"] and
                     scratch["reserved_inodes"] +
                     output_reservation["declared_reserved_inodes"] >=
                     output_reservation["same_device_required_inodes"],
                     "same-device scratch/output allowances are below their combined finite plan")
    _require("execution_manifest_pin" not in plan_value and
             "registration_head" not in plan_value and
             "final_execution_manifest" not in plan_value,
             "recorded-preparation plan contains a future manifest/registration pin")
    if _construction:
        _validate_prepared_input_construction_plan_self(plan_value)
    return plan_value, chunk_values


def build_recorded_preparation_read_plan_v2(
    basis_value: object,
    basis_pin: object,
    *,
    old_catalogues_by_host: object,
    old_readback_caps_by_host: object,
    window_metadata_by_host: object,
    session_nonce: object,
    scratch_declaration: object,
    timeout_declaration: object,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Build the unchanged registration/refresh v2 plan and exact row chunks."""
    return _build_recorded_preparation_read_plan_core(
        basis_value, basis_pin,
        old_catalogues_by_host=old_catalogues_by_host,
        old_readback_caps_by_host=old_readback_caps_by_host,
        window_metadata_by_host=window_metadata_by_host,
        session_nonce=session_nonce,
        scratch_declaration=scratch_declaration,
        timeout_declaration=timeout_declaration,
        _construction=False,
    )


def build_prepared_input_construction_read_plan_v1(
    basis_value: object,
    basis_pin: object,
    *,
    old_catalogues_by_host: object,
    old_readback_caps_by_host: object,
    window_metadata_by_host: object,
    session_nonce: object,
    scratch_declaration: object,
    timeout_declaration: object,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Build the distinct acyclic construction plan from the same 720 projections.

    The returned resource declaration includes the separate fixed-path final
    completion reservation. It is data for SourceA's own device/free-space
    checks and grants no read, publication, or qualification authority.
    """
    return _build_recorded_preparation_read_plan_core(
        basis_value, basis_pin,
        old_catalogues_by_host=old_catalogues_by_host,
        old_readback_caps_by_host=old_readback_caps_by_host,
        window_metadata_by_host=window_metadata_by_host,
        session_nonce=session_nonce,
        scratch_declaration=scratch_declaration,
        timeout_declaration=timeout_declaration,
        _construction=True,
    )


def validate_recorded_preparation_read_plan_v2(
    value: object,
    window_chunk_values: object,
    basis_value: object,
    basis_pin: object,
    *,
    old_catalogues_by_host: object,
    old_readback_caps_by_host: object,
    window_metadata_by_host: object,
    session_nonce: object,
    scratch_declaration: object,
    timeout_declaration: object,
) -> dict[str, Any]:
    """Rebuild the compact index and all chunks from exact Source projections."""
    rebuilt, expected_chunks = build_recorded_preparation_read_plan_v2(
        basis_value, basis_pin,
        old_catalogues_by_host=old_catalogues_by_host,
        old_readback_caps_by_host=old_readback_caps_by_host,
        window_metadata_by_host=window_metadata_by_host,
        session_nonce=session_nonce,
        scratch_declaration=scratch_declaration,
        timeout_declaration=timeout_declaration,
    )
    _require(type(value) is dict and canonical_bytes(value) ==
             canonical_bytes(rebuilt),
             "recorded-preparation compact read plan differs from exact Source inputs")
    _require(type(window_chunk_values) is list and
             len(window_chunk_values) == len(expected_chunks),
             "recorded-preparation metadata chunk count differs")
    for ordinal, (actual, expected) in enumerate(zip(
        window_chunk_values, expected_chunks,
    )):
        _require(type(actual) is dict and
                 0 < len(canonical_bytes(actual)) <= MAX_METADATA_BYTES and
                 canonical_bytes(actual) == canonical_bytes(expected),
                 f"recorded-preparation metadata chunk[{ordinal}] differs")
    return value


def validate_prepared_input_construction_read_plan_v1(
    value: object,
    window_chunk_values: object,
    basis_value: object,
    basis_pin: object,
    *,
    old_catalogues_by_host: object,
    old_readback_caps_by_host: object,
    window_metadata_by_host: object,
    session_nonce: object,
    scratch_declaration: object,
    timeout_declaration: object,
) -> dict[str, Any]:
    """Rebuild the construction plan and chunks from the same Source inputs."""
    rebuilt, expected_chunks = build_prepared_input_construction_read_plan_v1(
        basis_value, basis_pin,
        old_catalogues_by_host=old_catalogues_by_host,
        old_readback_caps_by_host=old_readback_caps_by_host,
        window_metadata_by_host=window_metadata_by_host,
        session_nonce=session_nonce,
        scratch_declaration=scratch_declaration,
        timeout_declaration=timeout_declaration,
    )
    _require(type(value) is dict and canonical_bytes(value) ==
             canonical_bytes(rebuilt),
             "prepared-input construction plan differs from exact Source inputs")
    _require(type(window_chunk_values) is list and
             len(window_chunk_values) == len(expected_chunks),
             "prepared-input construction chunk count differs")
    for ordinal, (actual, expected) in enumerate(zip(
        window_chunk_values, expected_chunks,
    )):
        _require(type(actual) is dict and
                 0 < len(canonical_bytes(actual)) <= MAX_METADATA_BYTES and
                 canonical_bytes(actual) == canonical_bytes(expected),
                 f"prepared-input construction chunk[{ordinal}] differs")
    return value


def prepared_input_construction_read_plan_pin_v1(
    plan_value: object,
) -> dict[str, str]:
    plan = _validate_prepared_input_construction_plan_self(plan_value)
    raw = canonical_bytes(plan)
    return {
        "path": plan["session_paths"]["read_plan"],
        "raw_sha256": sha256(raw),
        "semantic_sha256": plan["read_plan_sha256"],
    }


def recorded_preparation_read_plan_pin_v2(
    plan_value: object,
) -> dict[str, str]:
    plan = _validate_plan_self(plan_value)
    raw = canonical_bytes(plan)
    return {
        "path": plan["session_paths"]["read_plan"],
        "raw_sha256": sha256(raw),
        "semantic_sha256": plan["read_plan_sha256"],
    }


def _validate_plan_self_common(
    value: object, *, construction: bool,
) -> dict[str, Any]:
    schemas = _plan_schema_set(construction=construction)
    fields = {
        "schema", "campaign_id", "consumer_host_id", "cohort_hosts",
        "operation_kind", "basis_pin", "session_nonce",
        "scratch_declaration", "timeout_declaration", "session_paths",
        "current_journal_frontier", "window_index", "window_chunks",
        "resource_projection", "failed_window_policy", "read_plan_sha256",
    }
    if construction:
        fields.add("completion_output_reservation")
    plan_label = ("prepared-input construction read plan" if construction else
                  "recorded-preparation read plan")
    plan = _exact(value, fields, plan_label)
    expected_operations = (
        {PREPARED_INPUT_CONSTRUCTION_OPERATION} if construction else
        {"registration_replay", "refresh_replay"}
    )
    _require(plan["schema"] == schemas["plan"] and
             plan["operation_kind"] in expected_operations,
             ("prepared-input construction read-plan schema or operation differs"
              if construction else
              "recorded-preparation read-plan schema or operation differs"))
    _sha(plan["read_plan_sha256"], "read-plan self digest")
    _require(plan["read_plan_sha256"] == sha256(canonical_bytes({
        key: item for key, item in plan.items() if key != "read_plan_sha256"
    })), "recorded-preparation read-plan self digest differs")
    raw = canonical_bytes(plan)
    _require(0 < len(raw) <= MAX_METADATA_BYTES,
             "recorded-preparation compact read plan exceeds its metadata ceiling")
    _token(plan["campaign_id"], "read-plan campaign ID")
    _token(plan["consumer_host_id"], "read-plan consumer host ID")
    hosts = plan["cohort_hosts"]
    _require(type(hosts) is list and len(hosts) == READ_COHORT_SIZE and
             all(type(host) is str for host in hosts) and len(set(hosts)) ==
             READ_COHORT_SIZE and plan["consumer_host_id"] in hosts,
             "recorded-preparation plan cohort is malformed")
    for index, host in enumerate(hosts):
        _token(host, f"read-plan cohort host[{index}]")
    _pin3(plan["basis_pin"], "read-plan basis pin")
    _require(type(plan["session_nonce"]) is str and
             _NONCE.fullmatch(plan["session_nonce"]) is not None,
             "read-plan session nonce is malformed")
    _validate_timeouts(plan["timeout_declaration"])
    scratch = _validate_scratch(plan["scratch_declaration"])
    layout_builder = _construction_layout if construction else _layout
    expected_layout = layout_builder(
        scratch["root"], plan["campaign_id"], plan["consumer_host_id"],
        plan["session_nonce"],
    )
    _require(plan["session_paths"] == expected_layout,
             "recorded-preparation session paths are not nonce-derived")
    frontier = _exact(plan["current_journal_frontier"], {
        "head_sha256", "record_count",
    }, "read-plan current journal frontier")
    _sha(frontier["head_sha256"], "read-plan current journal head")
    _uint(frontier["record_count"], "read-plan current journal count")

    refs = plan["window_chunks"]
    index_rows = plan["window_index"]
    _require(type(refs) is list and 0 < len(refs) <= READ_WINDOW_COUNT and
             type(index_rows) is list and len(index_rows) == READ_WINDOW_COUNT,
             "recorded-preparation compact index/chunk set has an invalid count")
    covered_ordinals = []
    chunk_sizes = []
    for chunk_ordinal, raw_ref in enumerate(refs):
        ref = _exact(raw_ref, _WINDOW_CHUNK_REF_FIELDS,
                     f"read-plan metadata chunk ref[{chunk_ordinal}]")
        _require(_uint(ref["chunk_ordinal"],
                       f"read-plan chunk ref[{chunk_ordinal}] ordinal",
                       maximum=READ_WINDOW_COUNT - 1) == chunk_ordinal,
                 f"read-plan metadata chunk ref[{chunk_ordinal}] order differs")
        first = _uint(ref["first_read_ordinal"],
                      f"read-plan chunk[{chunk_ordinal}] first ordinal",
                      maximum=READ_WINDOW_COUNT - 1)
        count = _uint(ref["window_count"],
                      f"read-plan chunk[{chunk_ordinal}] window count",
                      positive=True, maximum=MAX_WINDOWS_PER_METADATA_CHUNK)
        ordinals = ref["read_ordinals"]
        _require(type(ordinals) is list and len(ordinals) == count and
                 all(type(item) is int for item in ordinals) and
                 ordinals == list(range(first, first + count)) and
                 first == len(covered_ordinals),
                 f"read-plan chunk[{chunk_ordinal}] ordinal range is not exact")
        pin = _pin3(ref["pin"], f"read-plan metadata chunk pin[{chunk_ordinal}]")
        expected_path = str(PurePosixPath(expected_layout["window_metadata_root"]) /
                            f"chunk-{chunk_ordinal:06d}.json")
        _require(pin["path"] == expected_path,
                 f"read-plan chunk[{chunk_ordinal}] path is not session-derived")
        byte_count = _uint(ref["byte_count"],
                           f"read-plan chunk[{chunk_ordinal}] byte count",
                           positive=True, maximum=MAX_METADATA_BYTES)
        chunk_sizes.append(byte_count)
        covered_ordinals.extend(ordinals)
    _require(covered_ordinals == list(range(READ_WINDOW_COUNT)),
             "read-plan chunks do not cover the ordered 720-window cohort")

    for ordinal, raw_entry in enumerate(index_rows):
        entry = _exact(raw_entry, _WINDOW_INDEX_FIELDS,
                       f"read-plan window index[{ordinal}]")
        _require(_uint(entry["read_ordinal"],
                       f"read-plan window index[{ordinal}] ordinal",
                       maximum=READ_WINDOW_COUNT - 1) == ordinal,
                 f"read-plan window index[{ordinal}] ordinal differs")
        host_position = ordinal // READ_JOB_COUNT_PER_HOST
        job_index = ordinal % READ_JOB_COUNT_PER_HOST
        _token(entry["owner_host_id"],
               f"read-plan window index[{ordinal}] owner host")
        _require(_uint(entry["job_index"],
                       f"read-plan window index[{ordinal}] job index",
                       maximum=READ_JOB_COUNT_PER_HOST - 1) == job_index and
                 entry["owner_host_id"] == hosts[host_position],
                 f"read-plan window index[{ordinal}] cohort/order differs")
        _sha(entry["job_sha256"],
             f"read-plan window index[{ordinal}] job digest")
        chunk_ordinal = _uint(entry["chunk_ordinal"],
                              f"read-plan window index[{ordinal}] chunk ordinal",
                              maximum=len(refs) - 1)
        chunk_row = _uint(entry["chunk_row"],
                          f"read-plan window index[{ordinal}] chunk row",
                          maximum=MAX_WINDOWS_PER_METADATA_CHUNK - 1)
        ref = refs[chunk_ordinal]
        _require(chunk_row < ref["window_count"] and
                 ref["read_ordinals"][chunk_row] == ordinal,
                 f"read-plan window index[{ordinal}] points at a crossed chunk row")
        _sha(entry["row_sha256"],
             f"read-plan window index[{ordinal}] row digest")

    policy = _exact(plan["failed_window_policy"], {
        "retention", "next_window", "new_nonce_before_cleanup",
    }, "read-plan failed-window policy")
    _require(policy == {
        "retention": "retain_one_exact_failed_window",
        "next_window": "blocked_until_exact_cleanup",
        "new_nonce_before_cleanup": "refused",
    }, "recorded-preparation failed-window policy differs")

    projection = _exact(plan["resource_projection"], {
        "window_bytes", "window_inodes", "failure_window_bytes",
        "failure_window_inodes", "window_physical_bytes",
        "failure_window_physical_bytes", "maximum_retained_failure_windows",
        "basis_document_bytes", "basis_document_allocated_bytes",
        "read_plan_document_bytes", "read_plan_document_allocated_bytes",
        "window_index_document_bytes", "window_chunk_ref_document_bytes",
        "window_metadata_chunk_bytes", "window_metadata_chunk_allocated_bytes",
        "window_metadata_allocation_block_bytes", "window_metadata_chunk_count",
        "window_metadata_chunk_max_bytes", "window_metadata_chunk_inode_count",
        "window_metadata_chunk_file_fsync_count",
        "window_metadata_chunk_directory_fsync_count",
        "window_metadata_chunk_parent_fsync_count",
        "window_metadata_chunk_fsync_count", "session_descriptor_bytes",
        "session_descriptor_allocated_bytes", "control_ledger_bytes",
        "control_ledger_allocated_bytes", "control_ledger_maximum_line_bytes",
        "control_event_count", "failure_receipt_bytes",
        "failure_receipt_allocated_bytes", "directory_node_count",
        "directory_metadata_reserve_bytes", "directory_node_bytes",
        "required_bytes", "required_inodes",
        "declared_reserved_bytes", "declared_reserved_inodes",
    }, "recorded-preparation resource projection")
    for name, item in projection.items():
        if name != "maximum_retained_failure_windows":
            _uint(item, f"read-plan resource projection {name}")
    _uint(projection["maximum_retained_failure_windows"],
          "read-plan maximum retained failure windows", positive=True)
    chunk_bytes = sum(chunk_sizes)
    allocation_block = scratch["allocation_block_bytes"]
    chunk_allocated_bytes = sum(
        ((size + allocation_block - 1) // allocation_block) * allocation_block
        for size in chunk_sizes
    )
    expected_allocated_documents = {
        "basis_document_allocated_bytes": _round_file_allocation_bytes(
            projection["basis_document_bytes"], allocation_block,
        ),
        "read_plan_document_allocated_bytes": _round_file_allocation_bytes(
            len(raw), allocation_block,
        ),
        "session_descriptor_allocated_bytes": _round_file_allocation_bytes(
            projection["session_descriptor_bytes"], allocation_block,
        ),
        "control_ledger_allocated_bytes": _round_file_allocation_bytes(
            projection["control_ledger_bytes"], allocation_block,
        ),
        "failure_receipt_allocated_bytes": _round_file_allocation_bytes(
            projection["failure_receipt_bytes"], allocation_block,
        ),
    }
    directory_nodes = len(expected_layout["directories"])
    expected_required_bytes = (
        2 * projection["window_physical_bytes"] +
        sum(expected_allocated_documents.values()) + chunk_allocated_bytes +
        projection["directory_metadata_reserve_bytes"]
    )
    expected_required_inodes = (
        2 * projection["window_inodes"] + 3 + 1 + 1 +
        directory_nodes + len(refs)
    )
    _require(projection["control_event_count"] == READ_CONTROL_EVENT_COUNT and
             projection["maximum_retained_failure_windows"] == 1 and
             projection["failure_window_bytes"] == projection["window_bytes"] and
             projection["failure_window_inodes"] == projection["window_inodes"] and
             projection["window_physical_bytes"] >= projection["window_bytes"] and
             projection["failure_window_physical_bytes"] ==
                 projection["window_physical_bytes"] and
             projection["declared_reserved_bytes"] == scratch["reserved_bytes"] and
             projection["declared_reserved_inodes"] == scratch["reserved_inodes"] and
             projection["read_plan_document_bytes"] == len(raw) and
             projection["window_index_document_bytes"] ==
                 len(canonical_bytes(index_rows)) and
             projection["window_chunk_ref_document_bytes"] ==
                 len(canonical_bytes(refs)) and
             projection["window_metadata_chunk_bytes"] == chunk_bytes and
             projection["window_metadata_chunk_allocated_bytes"] ==
                 chunk_allocated_bytes and
             projection["window_metadata_allocation_block_bytes"] ==
                 allocation_block and
             projection["window_metadata_chunk_count"] == len(refs) and
             projection["window_metadata_chunk_max_bytes"] == max(chunk_sizes) and
             projection["window_metadata_chunk_inode_count"] == len(refs) + 1 and
             projection["window_metadata_chunk_file_fsync_count"] == len(refs) and
             projection["window_metadata_chunk_directory_fsync_count"] == 1 and
             projection["window_metadata_chunk_parent_fsync_count"] == 1 and
             projection["window_metadata_chunk_fsync_count"] == len(refs) + 2 and
             all(projection[name] == expected
                 for name, expected in expected_allocated_documents.items()) and
             projection["control_ledger_bytes"] <= MAX_METADATA_BYTES and
             projection["directory_node_count"] == directory_nodes and
             projection["directory_metadata_reserve_bytes"] ==
                 scratch["directory_metadata_reserve_bytes"] and
             projection["directory_node_bytes"] ==
                 projection["directory_metadata_reserve_bytes"] and
             projection["required_bytes"] == expected_required_bytes and
             projection["required_inodes"] == expected_required_inodes and
             projection["required_bytes"] <= scratch["reserved_bytes"] and
             projection["required_inodes"] <= scratch["reserved_inodes"],
             "recorded-preparation resource declaration or chunk size closure differs")
    if construction:
        output = _exact(
            plan["completion_output_reservation"],
            _COMPLETION_OUTPUT_PLAN_FIELDS,
            "construction completion-output plan reservation",
        )
        output_path = _absolute_path(
            output["path"], "construction completion-output plan path",
        )
        _require(PurePosixPath(output_path).name ==
                 PREPARED_INPUT_COMPLETION_PATH_NAME and
                 output["schema"] ==
                 PREPARED_INPUT_COMPLETION_RESERVATION_SCHEMA_V1,
                 "construction completion-output plan path or schema differs")
        output_device = _uint(
            output["device_id"], "completion-output plan device ID",
        )
        output_block = _uint(
            output["allocation_block_bytes"],
            "completion-output plan allocation block", positive=True,
            maximum=MAX_METADATA_BYTES,
        )
        output_max = _uint(
            output["maximum_file_bytes"],
            "completion-output maximum file bytes", positive=True,
        )
        output_directory_growth = _uint(
            output["directory_growth_reserve_bytes"],
            "completion-output parent-directory growth reserve",
            positive=True,
        )
        output_bytes = _uint(
            output["required_bytes"],
            "completion-output required bytes", positive=True,
        )
        output_inodes = _uint(
            output["required_inodes"],
            "completion-output required inodes", positive=True,
        )
        output_reserved_bytes = _uint(
            output["declared_reserved_bytes"],
            "completion-output declared bytes", positive=True,
        )
        output_reserved_inodes = _uint(
            output["declared_reserved_inodes"],
            "completion-output declared inodes", positive=True,
        )
        same_device = output_device == scratch["device_id"]
        same_device_bytes = _uint(
            output["same_device_required_bytes"],
            "same-device combined required bytes",
        )
        same_device_inodes = _uint(
            output["same_device_required_inodes"],
            "same-device combined required inodes",
        )
        _require(type(output["same_device_as_scratch"]) is bool and
                 output["same_device_as_scratch"] is same_device and
                 output_max == PREPARED_INPUT_COMPLETION_MAX_BYTES and
                 output_bytes == (_round_file_allocation_bytes(
                     output_max, output_block,
                 ) + output_directory_growth) and output_inodes == 1 and
                 output_reserved_bytes >= output_bytes and
                 output_reserved_inodes >= output_inodes and
                 (not same_device or
                  (output_block == allocation_block and
                   same_device_bytes == projection["required_bytes"] +
                       output_bytes and
                   same_device_inodes == projection["required_inodes"] +
                       output_inodes)) and
                 (same_device or
                  (same_device_bytes == 0 and same_device_inodes == 0)),
                 "construction completion-output byte/inode/device allowance differs")
    return plan


def _validate_plan_self(value: object) -> dict[str, Any]:
    return _validate_plan_self_common(value, construction=False)


def _validate_prepared_input_construction_plan_self(
    value: object,
) -> dict[str, Any]:
    return _validate_plan_self_common(value, construction=True)

def _validate_plan_row_common(
    plan: dict[str, Any], row_value: object, ordinal: int, *,
    construction: bool | None,
) -> dict[str, Any]:
    if construction is not None:
        expected_schema = PREPARED_INPUT_CONSTRUCTION_READ_PLAN_SCHEMA_V1 \
            if construction else READ_PLAN_SCHEMA_V2
        _require(plan.get("schema") == expected_schema,
                 "read-plan row validator received a different plan schema")
    row = _exact(row_value, _PLAN_ROW_FIELDS,
                 f"recorded-preparation plan row[{ordinal}]")
    _uint(row["read_ordinal"],
          f"read-plan row[{ordinal}] read ordinal",
          maximum=READ_WINDOW_COUNT - 1)
    _uint(row["job_index"], f"read-plan row[{ordinal}] job index",
          maximum=READ_JOB_COUNT_PER_HOST - 1)
    _require(row["read_ordinal"] == ordinal and
             row["consumer_host_id"] == plan["consumer_host_id"] and
             row["owner_host_id"] ==
                 plan["cohort_hosts"][ordinal // READ_JOB_COUNT_PER_HOST] and
             row["operation_kind"] == plan["operation_kind"] and
             row["job_index"] == ordinal % READ_JOB_COUNT_PER_HOST,
             f"recorded-preparation plan row[{ordinal}] identity differs")
    summary = _exact(row["manifest_summary"], {
        "schema", "campaign_id", "host_id", "phase", "job_index",
        "job_ordinal", "job_sha256", "run_id", "job_record_raw_sha256",
        "predecessor_ack_pin", "object_count", "payload_bytes",
        "manifest_sha256",
    }, f"read-plan row[{ordinal}] manifest summary")
    _uint(summary["job_index"],
          f"read-plan row[{ordinal}] manifest job index",
          maximum=READ_JOB_COUNT_PER_HOST - 1)
    _uint(summary["job_ordinal"],
          f"read-plan row[{ordinal}] manifest job ordinal", positive=True)
    _require(type(summary["run_id"]) is str and summary["run_id"] and
             len(summary["run_id"].encode("utf-8", "strict")) <= MAX_PATH_BYTES and
             not any(ord(character) < 32 or ord(character) == 127
                     for character in summary["run_id"]),
             f"read-plan row[{ordinal}] manifest run ID is malformed")
    job = row["job"]
    _require(type(job) is dict and job.get("host_id") == row["owner_host_id"] and
             job.get("phase") == READ_PHASE and
             job.get("run_id") == summary["run_id"] and
             type(job.get("ordinal")) is int and job["ordinal"] > 0 and
             row["job_sha256"] == sha256(canonical_bytes(job)),
             f"recorded-preparation plan row[{ordinal}] job join differs")
    _sha(row["job_sha256"], f"read-plan row[{ordinal}] job digest")
    _absolute_path(row["archive_source5_root"],
                   f"read-plan row[{ordinal}] old archive root")
    pins = _exact(row["original_pins"], _PLAN_ORIGINAL_PIN_FIELDS,
                  f"read-plan row[{ordinal}] original pins")
    _pin2(pins["job_record"], f"read-plan row[{ordinal}] job-record pin")
    for name in ("request", "checkpoint", "object_manifest", "ack"):
        _pin3(pins[name], f"read-plan row[{ordinal}] {name} pin")
    _signature_pin(pins["signature"],
                   f"read-plan row[{ordinal}] signature pin")
    _host_receipt_pin(pins["host_receipt"],
                      f"read-plan row[{ordinal}] host receipt pin")
    _validate_indexed_reservation_bindings(
        row["indexed_reservation_bindings"], pins, row["owner_host_id"],
        summary["run_id"], f"read-plan row[{ordinal}]",
    )
    _require(summary["schema"] == OBJECT_MANIFEST_SCHEMA_V1 and
             summary["campaign_id"] == plan["campaign_id"] and
             summary["host_id"] == row["owner_host_id"] and
             summary["phase"] == READ_PHASE and
             summary["job_index"] == row["job_index"] and
             summary["job_ordinal"] == job["ordinal"] and
             summary["job_sha256"] == row["job_sha256"] and
             summary["run_id"] == job["run_id"] and
             summary["job_record_raw_sha256"] == pins["job_record"]["raw_sha256"] and
             summary["predecessor_ack_pin"] is None,
             f"read-plan row[{ordinal}] manifest summary differs from the original job")
    _uint(summary["object_count"],
          f"read-plan row[{ordinal}] manifest object count", positive=True,
          maximum=MAX_OBJECTS_PER_WINDOW)
    _uint(summary["payload_bytes"],
          f"read-plan row[{ordinal}] manifest payload bytes",
          maximum=MAX_ARCHIVE_BYTES)
    _sha(summary["manifest_sha256"],
         f"read-plan row[{ordinal}] manifest digest")
    objects = row["objects"]
    _require(type(objects) is list and len(objects) == summary["object_count"] and
             0 < len(objects) <= MAX_OBJECTS_PER_WINDOW,
             f"read-plan row[{ordinal}] object list cardinality differs")
    seen = set()
    payload = 0
    for position, item_value in enumerate(objects):
        obj = _exact(item_value, _MANIFEST_OBJECT_FIELDS,
                     f"read-plan row[{ordinal}] object[{position}]")
        origin = _absolute_path(obj["origin_path"],
                                f"read-plan row[{ordinal}] origin[{position}]")
        _token(obj["role"], f"read-plan row[{ordinal}] role[{position}]")
        raw_sha = _sha(obj["raw_sha256"],
                       f"read-plan row[{ordinal}] raw object[{position}]")
        if obj["semantic_sha256"] is not None:
            _sha(obj["semantic_sha256"],
                 f"read-plan row[{ordinal}] semantic object[{position}]")
        byte_count = _uint(obj["byte_count"],
                           f"read-plan row[{ordinal}] object bytes[{position}]",
                           maximum=(1 << 33) - 1)
        object_id = _archive_read_object_id(origin, raw_sha)
        _require(obj["object_id"] == object_id,
                 f"read-plan row[{ordinal}] object ID[{position}] differs")
        object_pin = _exact(obj["object_pin"], _OBJECT_PIN_FIELDS,
                            f"read-plan row[{ordinal}] object pin[{position}]")
        _require(object_pin["path"] == str(
            PurePosixPath(row["archive_source5_root"]) / "objects" / object_id
        ) and object_pin["raw_sha256"] == raw_sha and
                 object_pin["semantic_sha256"] == raw_sha and
                 object_pin["byte_count"] == byte_count,
                 f"read-plan row[{ordinal}] object pin[{position}] differs")
        _uint(object_pin["byte_count"],
              f"read-plan row[{ordinal}] object-pin bytes[{position}]",
              maximum=(1 << 33) - 1)
        _require(origin not in seen,
                 f"read-plan row[{ordinal}] repeats an object origin")
        seen.add(origin)
        payload += byte_count
    _require(objects == sorted(objects, key=lambda item: item["origin_path"]) and
             payload == summary["payload_bytes"],
             f"read-plan row[{ordinal}] object order or byte total differs")
    budget_caps = _exact(row["source_budget_schedule_caps"],
                         _BUDGET_READ_CAP_FIELDS,
                         f"read-plan row[{ordinal}] H budget caps")
    source_caps = _exact(row["recomputed_source_caps"],
                         _RECOMPUTED_SOURCE_CAP_FIELDS,
                         f"read-plan row[{ordinal}] recomputed Source caps")
    _require(budget_caps == {
        "bundle_bytes": source_caps["bundle_bytes"],
        "maximum_request_bytes": source_caps["maximum_request_bytes"],
        "maximum_response_bytes": source_caps["maximum_response_bytes"],
        "object_count": source_caps["object_count"],
        "stage_bytes": source_caps["stage_bytes"],
    }, f"read-plan row[{ordinal}] H5 and recomputed cap projections differ")
    for name in ("maximum_request_bytes", "maximum_response_bytes"):
        _uint(source_caps[name], f"read-plan row[{ordinal}] {name}",
              positive=True, maximum=MAX_METADATA_BYTES)
    _uint(source_caps["bundle_bytes"], f"read-plan row[{ordinal}] tar cap",
          positive=True, maximum=MAX_ARCHIVE_BYTES)
    _uint(source_caps["stage_bytes"], f"read-plan row[{ordinal}] stage bytes",
          maximum=MAX_ARCHIVE_BYTES)
    _uint(source_caps["stage_inodes"], f"read-plan row[{ordinal}] stage inodes",
          positive=True)
    _uint(source_caps["object_count"], f"read-plan row[{ordinal}] cap object count",
          positive=True, maximum=MAX_OBJECTS_PER_WINDOW)
    _uint(source_caps["maximum_object_bytes"],
          f"read-plan row[{ordinal}] cap maximum object bytes",
          maximum=MAX_ARCHIVE_BYTES)
    _uint(source_caps["live_window_bytes"],
          f"read-plan row[{ordinal}] old live-window bytes",
          maximum=2 * MAX_ARCHIVE_BYTES + 2 * MAX_METADATA_BYTES)
    _uint(source_caps["live_window_inodes"],
          f"read-plan row[{ordinal}] old live-window inodes", positive=True)
    _require(source_caps["object_count"] == len(objects) and
             payload <= source_caps["stage_bytes"] and
             all(obj["byte_count"] <= source_caps["maximum_object_bytes"]
                 for obj in objects),
             f"read-plan row[{ordinal}] object list exceeds old Source caps")
    expected_legacy_objects = [{
        "owner_job_sha256": row["job_sha256"],
        "origin_path": obj["origin_path"],
        "raw_sha256": obj["raw_sha256"],
        "byte_count": obj["byte_count"],
    } for obj in objects]
    _sha(row["legacy_request_sha256"],
         f"read-plan row[{ordinal}] legacy request digest")
    legacy = _legacy_request(
        plan["campaign_id"], row["owner_host_id"], ordinal,
        expected_legacy_objects, source_caps["bundle_bytes"],
    )
    _require(row["legacy_request_sha256"] == legacy["request_sha256"],
             f"read-plan row[{ordinal}] legacy request is not the exact inner projection")
    bounds = _exact(row["resource_bounds"], _RESOURCE_BOUND_FIELDS,
                    f"read-plan row[{ordinal}] resource bounds")
    for name, cap in bounds.items():
        _uint(cap, f"read-plan row[{ordinal}] resource bound {name}")
    tar_bytes = _archive_read_tar_size([
        {"byte_count": obj["byte_count"]} for obj in objects
    ])
    max_object = max(obj["byte_count"] for obj in objects)
    request_raw = canonical_bytes(legacy)
    response_raw = canonical_bytes(_legacy_response(
        legacy, "f" * 64, tar_bytes,
    ))
    _require(bounds["legacy_request_bytes"] == len(request_raw) and
             bounds["legacy_response_bytes"] == len(response_raw) and
             len(request_raw) <= source_caps["maximum_request_bytes"] and
             len(response_raw) <= source_caps["maximum_response_bytes"] and
             bounds["tar_bytes"] == tar_bytes and
             bounds["payload_bytes"] == payload and
             bounds["object_count"] == len(objects) and
             bounds["maximum_object_bytes"] == max_object and
             bounds["window_bytes"] == (
                 bounds["outer_request_bytes"] +
                 2 * bounds["outer_response_bytes"] +
                 2 * tar_bytes + payload
             ) and
             bounds["window_inodes"] == len(objects) + 6 and
             0 < bounds["outer_request_bytes"] <= MAX_METADATA_BYTES and
             0 < bounds["outer_response_bytes"] <= MAX_METADATA_BYTES,
             f"read-plan row[{ordinal}] derived envelope/resource size differs")
    physical_window_bytes = _physical_window_charge(
        row, plan["scratch_declaration"]["allocation_block_bytes"],
    )
    _require(physical_window_bytes <=
             plan["resource_projection"]["window_physical_bytes"],
             f"read-plan row[{ordinal}] exceeds the admitted physical window charge")
    session_paths = _exact(row["session_paths"], {
        "request", "response_incoming", "response", "bundle_incoming",
        "bundle", "stage",
    }, f"read-plan row[{ordinal}] slot path map")
    _require(session_paths == {
        name: plan["session_paths"][name]
        for name in (
            "request", "response_incoming", "response", "bundle_incoming",
            "bundle", "stage",
        )
    } and row["session_stage_root"] == session_paths["stage"],
        f"read-plan row[{ordinal}] slots do not reuse one exact stage")
    return row


def _validate_plan_row(
    plan: dict[str, Any], row_value: object, ordinal: int,
) -> dict[str, Any]:
    return _validate_plan_row_common(
        plan, row_value, ordinal, construction=False,
    )


def _validate_prepared_input_construction_plan_row(
    plan: dict[str, Any], row_value: object, ordinal: int,
) -> dict[str, Any]:
    return _validate_plan_row_common(
        plan, row_value, ordinal, construction=True,
    )


def _validate_read_window_common(
    plan_value: object, plan_pin_value: object,
    window_chunk_value: object, read_ordinal: object,
    *, construction: bool,
) -> dict[str, Any]:
    """Resolve one row only from its exact plan-pinned metadata chunk."""
    schemas = _plan_schema_set(construction=construction)
    plan_validator = (_validate_prepared_input_construction_plan_self
                      if construction else _validate_plan_self)
    row_validator = (_validate_prepared_input_construction_plan_row
                     if construction else _validate_plan_row)
    plan = plan_validator(plan_value)
    plan_pin = _pin3(plan_pin_value, "recorded-preparation window plan pin")
    plan_raw = canonical_bytes(plan)
    _require(plan_pin["path"] == plan["session_paths"]["read_plan"] and
             plan_pin["raw_sha256"] == sha256(plan_raw) and
             plan_pin["semantic_sha256"] == plan["read_plan_sha256"],
             "recorded-preparation window plan pin differs")
    ordinal = _uint(read_ordinal, "recorded-preparation window ordinal",
                    maximum=READ_WINDOW_COUNT - 1)
    index_row = plan["window_index"][ordinal]
    ref = plan["window_chunks"][index_row["chunk_ordinal"]]
    chunk = _exact(window_chunk_value, _WINDOW_CHUNK_FIELDS,
                   f"recorded-preparation metadata chunk[{ref['chunk_ordinal']}]")
    chunk_raw = canonical_bytes(chunk)
    pin = ref["pin"]
    _require(0 < len(chunk_raw) <= MAX_METADATA_BYTES and
             len(chunk_raw) == ref["byte_count"] and
             sha256(chunk_raw) == pin["raw_sha256"] and
              chunk["schema"] == schemas["chunk"] and
             chunk["basis_pin"] == plan["basis_pin"] and
             chunk["campaign_id"] == plan["campaign_id"] and
             chunk["consumer_host_id"] == plan["consumer_host_id"] and
             chunk["cohort_hosts"] == plan["cohort_hosts"] and
             chunk["operation_kind"] == plan["operation_kind"] and
             chunk["session_nonce"] == plan["session_nonce"] and
             _uint(chunk["chunk_ordinal"], "window chunk ordinal",
                   maximum=READ_WINDOW_COUNT - 1) == ref["chunk_ordinal"] and
             _uint(chunk["first_read_ordinal"], "window chunk first ordinal",
                   maximum=READ_WINDOW_COUNT - 1) == ref["first_read_ordinal"] and
             type(chunk["read_ordinals"]) is list and
             all(type(item) is int for item in chunk["read_ordinals"]) and
             chunk["read_ordinals"] == ref["read_ordinals"] and
             type(chunk["rows"]) is list and
             len(chunk["rows"]) == ref["window_count"] and
             chunk["window_chunk_sha256"] == pin["semantic_sha256"] and
             chunk["window_chunk_sha256"] == sha256(canonical_bytes({
                 key: item for key, item in chunk.items()
                 if key != "window_chunk_sha256"
             })),
             "recorded-preparation window chunk pin, context or self digest differs")
    selected = None
    for chunk_row, (current_ordinal, raw_row) in enumerate(zip(
        ref["read_ordinals"], chunk["rows"],
    )):
        compact = plan["window_index"][current_ordinal]
        row = row_validator(plan, raw_row, current_ordinal)
        _require(compact["chunk_ordinal"] == ref["chunk_ordinal"] and
                 compact["chunk_row"] == chunk_row and
                 compact["row_sha256"] == sha256(canonical_bytes(row)) and
                 compact["owner_host_id"] == row["owner_host_id"] and
                 compact["job_index"] == row["job_index"] and
                 compact["job_sha256"] == row["job_sha256"],
                 f"recorded-preparation window index[{current_ordinal}] differs from its chunk row")
        if current_ordinal == ordinal:
            selected = row
    _require(selected is not None,
             "recorded-preparation window ordinal is absent from its plan-pinned chunk")
    return selected


def validate_recorded_preparation_read_window_v2(
    plan_value: object, plan_pin_value: object,
    window_chunk_value: object, read_ordinal: object,
) -> dict[str, Any]:
    return _validate_read_window_common(
        plan_value, plan_pin_value, window_chunk_value, read_ordinal,
        construction=False,
    )


def validate_prepared_input_construction_read_window_v1(
    plan_value: object, plan_pin_value: object,
    window_chunk_value: object, read_ordinal: object,
) -> dict[str, Any]:
    return _validate_read_window_common(
        plan_value, plan_pin_value, window_chunk_value, read_ordinal,
        construction=True,
    )


def _validated_plan_context_common(
    basis_value: object, basis_pin_value: object,
    plan_value: object, plan_pin_value: object,
    *, construction: bool,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    basis_validator = (_validate_construction_basis if construction else
                       _validate_basis)
    plan_validator = (_validate_prepared_input_construction_plan_self
                      if construction else _validate_plan_self)
    basis, basis_pin, hosts = basis_validator(basis_value, basis_pin_value)
    plan = plan_validator(plan_value)
    plan_pin = _pin3(plan_pin_value, "recorded-preparation read-plan pin")
    raw = canonical_bytes(plan)
    _require(plan_pin["path"] == plan["session_paths"]["read_plan"] and
             plan_pin["raw_sha256"] == sha256(raw) and
             plan_pin["semantic_sha256"] == plan["read_plan_sha256"] and
             plan["basis_pin"] == basis_pin and
             plan["campaign_id"] == basis["campaign_id"] and
             plan["consumer_host_id"] == basis["consumer_host_id"] and
             plan["cohort_hosts"] == hosts and
             plan["operation_kind"] == basis["operation_kind"] and
             plan["current_journal_frontier"] ==
                 basis["current_journal_frontier"],
              "recorded-preparation plan pin or basis identity differs")
    if construction:
        _require(plan["completion_output_reservation"] ==
                 _construction_output_plan_reservation(
                     basis, plan["scratch_declaration"],
                     plan["resource_projection"],
                 ),
                 "construction completion-output reservation differs from its basis")
    return basis, basis_pin, plan, plan_pin


def _validated_plan_context(
    basis_value: object, basis_pin_value: object,
    plan_value: object, plan_pin_value: object,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    return _validated_plan_context_common(
        basis_value, basis_pin_value, plan_value, plan_pin_value,
        construction=False,
    )


def _validated_prepared_input_construction_plan_context(
    basis_value: object, basis_pin_value: object,
    plan_value: object, plan_pin_value: object,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    return _validated_plan_context_common(
        basis_value, basis_pin_value, plan_value, plan_pin_value,
        construction=True,
    )


def _build_preparation_read_request_common(
    basis_value: object, basis_pin_value: object,
    plan_value: object, plan_pin_value: object, read_ordinal: object,
    window_chunk_value: object, *, construction: bool,
) -> tuple[dict[str, Any], bytes, dict[str, str]]:
    context_validator = (_validated_prepared_input_construction_plan_context
                         if construction else _validated_plan_context)
    window_validator = (validate_prepared_input_construction_read_window_v1
                        if construction else
                        validate_recorded_preparation_read_window_v2)
    schemas = _plan_schema_set(construction=construction)
    basis, basis_pin, plan, plan_pin = context_validator(
        basis_value, basis_pin_value, plan_value, plan_pin_value,
    )
    ordinal = _uint(read_ordinal, "recorded-preparation request ordinal",
                    maximum=READ_WINDOW_COUNT - 1)
    row = window_validator(plan, plan_pin, window_chunk_value, ordinal)
    outer_row = {
        **row,
        "legacy_request": _legacy_request_for_plan_row(plan, row),
    }
    body = _outer_request(
        basis_pin, plan_pin, plan["session_nonce"],
        plan["consumer_host_id"], plan["operation_kind"], ordinal,
        outer_row, request_sha256="", schema=schemas["request"],
    )
    request = _seal(body, "request_sha256")
    raw = canonical_bytes(request)
    bounds = row["resource_bounds"]
    _require(0 < len(raw) <= MAX_METADATA_BYTES and
             len(raw) <= bounds["outer_request_bytes"],
             "recorded-preparation request exceeds its Source-derived envelope bound")
    pin = {
        "path": row["session_paths"]["request"],
        "raw_sha256": sha256(raw),
        "semantic_sha256": request["request_sha256"],
    }
    return request, raw, pin


def build_recorded_preparation_read_request_v2(
    basis_value: object, basis_pin_value: object,
    plan_value: object, plan_pin_value: object, read_ordinal: object,
    window_chunk_value: object,
) -> tuple[dict[str, Any], bytes, dict[str, str]]:
    return _build_preparation_read_request_common(
        basis_value, basis_pin_value, plan_value, plan_pin_value,
        read_ordinal, window_chunk_value, construction=False,
    )


def build_prepared_input_construction_read_request_v1(
    basis_value: object, basis_pin_value: object,
    plan_value: object, plan_pin_value: object, read_ordinal: object,
    window_chunk_value: object,
) -> tuple[dict[str, Any], bytes, dict[str, str]]:
    return _build_preparation_read_request_common(
        basis_value, basis_pin_value, plan_value, plan_pin_value,
        read_ordinal, window_chunk_value, construction=True,
    )


def _validate_preparation_read_request_common(
    raw: object, basis_value: object, basis_pin_value: object,
    plan_value: object, plan_pin_value: object, window_chunk_value: object,
    *, construction: bool,
) -> dict[str, Any]:
    context_validator = (_validated_prepared_input_construction_plan_context
                         if construction else _validated_plan_context)
    window_validator = (validate_prepared_input_construction_read_window_v1
                        if construction else
                        validate_recorded_preparation_read_window_v2)
    schemas = _plan_schema_set(construction=construction)
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_METADATA_BYTES,
             "recorded-preparation request is outside its metadata ceiling")
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise RecordedPreparationReadPlanError(
            "recorded-preparation request is not canonical ASCII JSON",
        ) from error
    request = _exact(value, {
        "schema", "basis_pin", "read_plan_pin", "session_nonce",
        "consumer_host_id", "owner_host_id", "operation_kind",
        "read_ordinal", "job_index", "job_sha256", "object_manifest_pin",
        "legacy_request", "request_sha256",
    }, "recorded-preparation request")
    basis, basis_pin, plan, plan_pin = context_validator(
        basis_value, basis_pin_value, plan_value, plan_pin_value,
    )
    ordinal = _uint(request["read_ordinal"],
                    "recorded-preparation request ordinal",
                    maximum=READ_WINDOW_COUNT - 1)
    _require(raw == canonical_bytes(request) and
             request["schema"] == schemas["request"] and
             request["basis_pin"] == basis_pin and
             request["read_plan_pin"] == plan_pin and
             request["session_nonce"] == plan["session_nonce"] and
             request["consumer_host_id"] == basis["consumer_host_id"] and
             request["operation_kind"] == basis["operation_kind"],
             "recorded-preparation request outer identity or raw encoding differs")
    row = window_validator(plan, plan_pin, window_chunk_value, ordinal)
    _require(request["owner_host_id"] == row["owner_host_id"] and
             request["job_index"] == row["job_index"] and
             request["job_sha256"] == row["job_sha256"] and
             request["object_manifest_pin"] ==
                 row["original_pins"]["object_manifest"] and
             request["legacy_request"] ==
                 _legacy_request_for_plan_row(plan, row),
             "recorded-preparation request differs from its complete planned row")
    _sha(request["request_sha256"], "recorded-preparation request self digest")
    _require(request["request_sha256"] == sha256(canonical_bytes({
        key: item for key, item in request.items() if key != "request_sha256"
    })), "recorded-preparation request self digest differs")
    _require(len(raw) <= row["resource_bounds"]["outer_request_bytes"],
             "recorded-preparation request exceeds its exact planned bound")
    return request


def validate_recorded_preparation_read_request_v2(
    raw: object, basis_value: object, basis_pin_value: object,
    plan_value: object, plan_pin_value: object, window_chunk_value: object,
) -> dict[str, Any]:
    return _validate_preparation_read_request_common(
        raw, basis_value, basis_pin_value, plan_value, plan_pin_value,
        window_chunk_value, construction=False,
    )


def validate_prepared_input_construction_read_request_v1(
    raw: object, basis_value: object, basis_pin_value: object,
    plan_value: object, plan_pin_value: object, window_chunk_value: object,
) -> dict[str, Any]:
    return _validate_preparation_read_request_common(
        raw, basis_value, basis_pin_value, plan_value, plan_pin_value,
        window_chunk_value, construction=True,
    )


def _validate_legacy_response_for_request(
    response_value: object, request: dict[str, Any], row: dict[str, Any],
) -> dict[str, Any]:
    response = _exact(response_value, {
        "schema", "campaign_id", "host_id", "analysis_phase",
        "request_ordinal", "request_pin", "objects", "body_tar_pin",
        "response_sha256",
    }, "legacy Source5 archive-read response")
    inner_request = request["legacy_request"]
    request_pin = _exact(response["request_pin"],
                         {"raw_sha256", "semantic_sha256"},
                         "legacy response request pin")
    tar_pin = _exact(response["body_tar_pin"],
                     {"raw_sha256", "byte_count"},
                     "legacy response tar pin")
    _require(response["schema"] == LEGACY_RESPONSE_SCHEMA_V1 and
             response["campaign_id"] == inner_request["campaign_id"] and
             response["host_id"] == inner_request["host_id"] and
             response["analysis_phase"] == READ_PHASE and
             response["request_ordinal"] == request["read_ordinal"] and
             response["objects"] == inner_request["objects"] and
             request_pin == {
                 "raw_sha256": sha256(canonical_bytes(inner_request)),
                 "semantic_sha256": inner_request["request_sha256"],
             }, "legacy response differs from the exact planned inner request")
    _sha(tar_pin["raw_sha256"], "legacy response tar raw digest")
    _uint(tar_pin["byte_count"], "legacy response tar byte count", positive=True,
          maximum=MAX_ARCHIVE_BYTES)
    bounds = row["resource_bounds"]
    _require(MIN_TAR_BYTES <= tar_pin["byte_count"] <=
             inner_request["maximum_response_bytes"] and
             tar_pin["byte_count"] == bounds["tar_bytes"],
             "legacy response tar size differs from the exact signed object set")
    _sha(response["response_sha256"], "legacy response self digest")
    _require(response["response_sha256"] == sha256(canonical_bytes({
        key: value for key, value in response.items()
        if key != "response_sha256"
    })), "legacy response self digest differs")
    return response


def _build_preparation_read_response_common(
    request_raw: object,
    legacy_response_value: object,
    legacy_response_raw: object,
    basis_value: object,
    basis_pin_value: object,
    plan_value: object,
    plan_pin_value: object,
    window_chunk_value: object,
    *, construction: bool,
) -> tuple[dict[str, Any], bytes, dict[str, str]]:
    request_validator = (validate_prepared_input_construction_read_request_v1
                         if construction else
                         validate_recorded_preparation_read_request_v2)
    context_validator = (_validated_prepared_input_construction_plan_context
                         if construction else _validated_plan_context)
    window_validator = (validate_prepared_input_construction_read_window_v1
                        if construction else
                        validate_recorded_preparation_read_window_v2)
    schemas = _plan_schema_set(construction=construction)
    request = request_validator(
        request_raw, basis_value, basis_pin_value, plan_value, plan_pin_value,
        window_chunk_value,
    )
    basis, basis_pin, plan, plan_pin = context_validator(
        basis_value, basis_pin_value, plan_value, plan_pin_value,
    )
    _require(type(legacy_response_raw) is bytes and
             0 < len(legacy_response_raw) <= MAX_METADATA_BYTES and
             legacy_response_raw == canonical_bytes(legacy_response_value),
             "legacy response raw bytes differ from their canonical document")
    row = window_validator(
        plan, plan_pin, window_chunk_value, request["read_ordinal"],
    )
    legacy_response = _validate_legacy_response_for_request(
        legacy_response_value, request, row,
    )
    outer_request_pin = {
        "path": row["session_paths"]["request"],
        "raw_sha256": sha256(request_raw),
        "semantic_sha256": request["request_sha256"],
    }
    outer = _outer_response(
        basis_pin, plan_pin, plan["session_nonce"],
        basis["consumer_host_id"], basis["operation_kind"],
        request["read_ordinal"], outer_request_pin,
        legacy_response, response_sha256="", schema=schemas["response"],
    )
    response = _seal(outer, "response_sha256")
    raw = canonical_bytes(response)
    _require(0 < len(raw) <= MAX_METADATA_BYTES and
             len(raw) <= row["resource_bounds"]["outer_response_bytes"],
             "recorded-preparation response exceeds its exact planned bound")
    pin = {
        "path": row["session_paths"]["response"],
        "raw_sha256": sha256(raw),
        "semantic_sha256": response["response_sha256"],
    }
    return response, raw, pin


def build_recorded_preparation_read_response_v2(
    request_raw: object, legacy_response_value: object,
    legacy_response_raw: object, basis_value: object,
    basis_pin_value: object, plan_value: object,
    plan_pin_value: object, window_chunk_value: object,
) -> tuple[dict[str, Any], bytes, dict[str, str]]:
    return _build_preparation_read_response_common(
        request_raw, legacy_response_value, legacy_response_raw,
        basis_value, basis_pin_value, plan_value, plan_pin_value,
        window_chunk_value, construction=False,
    )


def build_prepared_input_construction_read_response_v1(
    request_raw: object, legacy_response_value: object,
    legacy_response_raw: object, basis_value: object,
    basis_pin_value: object, plan_value: object,
    plan_pin_value: object, window_chunk_value: object,
) -> tuple[dict[str, Any], bytes, dict[str, str]]:
    return _build_preparation_read_response_common(
        request_raw, legacy_response_value, legacy_response_raw,
        basis_value, basis_pin_value, plan_value, plan_pin_value,
        window_chunk_value, construction=True,
    )


def _validate_preparation_read_response_common(
    response_raw: object,
    request_raw: object,
    basis_value: object,
    basis_pin_value: object,
    plan_value: object,
    plan_pin_value: object,
    window_chunk_value: object,
    *, construction: bool,
) -> dict[str, Any]:
    request_validator = (validate_prepared_input_construction_read_request_v1
                         if construction else
                         validate_recorded_preparation_read_request_v2)
    context_validator = (_validated_prepared_input_construction_plan_context
                         if construction else _validated_plan_context)
    window_validator = (validate_prepared_input_construction_read_window_v1
                        if construction else
                        validate_recorded_preparation_read_window_v2)
    schemas = _plan_schema_set(construction=construction)
    request = request_validator(
        request_raw, basis_value, basis_pin_value, plan_value, plan_pin_value,
        window_chunk_value,
    )
    _require(type(response_raw) is bytes and
             0 < len(response_raw) <= MAX_METADATA_BYTES,
             "recorded-preparation response is outside its metadata ceiling")
    try:
        value = json.loads(response_raw.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise RecordedPreparationReadPlanError(
            "recorded-preparation response is not canonical ASCII JSON",
        ) from error
    response = _exact(value, {
        "schema", "basis_pin", "read_plan_pin", "session_nonce",
        "consumer_host_id", "owner_host_id", "operation_kind",
        "read_ordinal", "request_pin", "legacy_response", "response_sha256",
    }, "recorded-preparation response")
    basis, basis_pin, plan, plan_pin = context_validator(
        basis_value, basis_pin_value, plan_value, plan_pin_value,
    )
    ordinal = request["read_ordinal"]
    row = window_validator(plan, plan_pin, window_chunk_value, ordinal)
    request_pin = _pin3(response["request_pin"],
                        "recorded-preparation response request pin")
    _require(response_raw == canonical_bytes(response) and
              response["schema"] == schemas["response"] and
             response["basis_pin"] == basis_pin and
             response["read_plan_pin"] == plan_pin and
             response["session_nonce"] == plan["session_nonce"] and
             response["consumer_host_id"] == basis["consumer_host_id"] and
             response["owner_host_id"] == row["owner_host_id"] and
             response["operation_kind"] == basis["operation_kind"] and
             response["read_ordinal"] == ordinal and
             request_pin == {
                 "path": row["session_paths"]["request"],
                 "raw_sha256": sha256(request_raw),
                 "semantic_sha256": request["request_sha256"],
             }, "recorded-preparation response outer identity differs")
    _validate_legacy_response_for_request(
        response["legacy_response"], request, row,
    )
    _sha(response["response_sha256"],
         "recorded-preparation response self digest")
    _require(response["response_sha256"] == sha256(canonical_bytes({
        key: item for key, item in response.items()
        if key != "response_sha256"
    })) and len(response_raw) <=
        row["resource_bounds"]["outer_response_bytes"],
        "recorded-preparation response self digest or size differs")
    return response


def validate_recorded_preparation_read_response_v2(
    response_raw: object, request_raw: object,
    basis_value: object, basis_pin_value: object,
    plan_value: object, plan_pin_value: object,
    window_chunk_value: object,
) -> dict[str, Any]:
    return _validate_preparation_read_response_common(
        response_raw, request_raw, basis_value, basis_pin_value,
        plan_value, plan_pin_value, window_chunk_value,
        construction=False,
    )


def validate_prepared_input_construction_read_response_v1(
    response_raw: object, request_raw: object,
    basis_value: object, basis_pin_value: object,
    plan_value: object, plan_pin_value: object,
    window_chunk_value: object,
) -> dict[str, Any]:
    return _validate_preparation_read_response_common(
        response_raw, request_raw, basis_value, basis_pin_value,
        plan_value, plan_pin_value, window_chunk_value,
        construction=True,
    )


def _build_preparation_read_control_event_common(
    plan_value: object, plan_pin_value: object, read_ordinal: object,
    window_chunk_value: object,
    action: object, *, request_pin: object,
    response_pin: object = None, bundle_pin: object = None,
    construction: bool,
) -> dict[str, Any]:
    """Project one scheduled control event; it is not an admission fact."""
    plan_validator = (_validate_prepared_input_construction_plan_self
                      if construction else _validate_plan_self)
    window_validator = (validate_prepared_input_construction_read_window_v1
                        if construction else
                        validate_recorded_preparation_read_window_v2)
    schemas = _plan_schema_set(construction=construction)
    plan = plan_validator(plan_value)
    plan_pin = _pin3(plan_pin_value, "recorded-preparation control plan pin")
    _require(plan_pin["path"] == plan["session_paths"]["read_plan"] and
             plan_pin["raw_sha256"] == sha256(canonical_bytes(plan)) and
             plan_pin["semantic_sha256"] == plan["read_plan_sha256"],
             "recorded-preparation control plan pin differs")
    ordinal = _uint(read_ordinal, "recorded-preparation control ordinal",
                    maximum=READ_WINDOW_COUNT - 1)
    row = window_validator(plan, plan_pin, window_chunk_value, ordinal)
    request = _pin3(request_pin, "recorded-preparation control request pin")
    _require(request["path"] == row["session_paths"]["request"],
             "recorded-preparation control request path differs")
    if action == "request_published":
        _require(response_pin is None and bundle_pin is None,
                 "request-published event cannot carry response or tar pins")
        response = None
        bundle = None
        sequence = 2 * ordinal + 1
    elif action == "view_released":
        response = _pin3(response_pin,
                         "recorded-preparation control response pin")
        bundle = _exact(bundle_pin, {"path", "raw_sha256", "byte_count"},
                        "recorded-preparation control tar pin")
        _require(response["path"] == row["session_paths"]["response"] and
                 bundle["path"] == row["session_paths"]["bundle"],
                 "view-released event response/tar paths differ")
        _sha(bundle["raw_sha256"], "recorded-preparation control tar digest")
        _require(_uint(bundle["byte_count"],
                       "recorded-preparation control tar bytes", positive=True,
                       maximum=MAX_ARCHIVE_BYTES) ==
                 row["resource_bounds"]["tar_bytes"],
                 "view-released event tar size differs from its planned window")
        sequence = 2 * ordinal + 2
    else:
        raise RecordedPreparationReadPlanError(
            "recorded-preparation control action is outside the exact two-event grammar",
        )
    _require(type(sequence) is int and 1 <= sequence < (1 << 64),
             "recorded-preparation control sequence is outside u64")
    return _control_event_value(
        row, plan["basis_pin"], plan_pin, plan["session_nonce"],
        action, sequence, request_pin=request,
        response_pin=response, bundle_pin=bundle, schema=schemas["control"],
    )


def build_recorded_preparation_read_control_event_v2(
    plan_value: object, plan_pin_value: object, read_ordinal: object,
    window_chunk_value: object, action: object, *, request_pin: object,
    response_pin: object = None, bundle_pin: object = None,
) -> dict[str, Any]:
    return _build_preparation_read_control_event_common(
        plan_value, plan_pin_value, read_ordinal, window_chunk_value,
        action, request_pin=request_pin, response_pin=response_pin,
        bundle_pin=bundle_pin, construction=False,
    )


def build_prepared_input_construction_read_control_event_v1(
    plan_value: object, plan_pin_value: object, read_ordinal: object,
    window_chunk_value: object, action: object, *, request_pin: object,
    response_pin: object = None, bundle_pin: object = None,
) -> dict[str, Any]:
    return _build_preparation_read_control_event_common(
        plan_value, plan_pin_value, read_ordinal, window_chunk_value,
        action, request_pin=request_pin, response_pin=response_pin,
        bundle_pin=bundle_pin, construction=True,
    )


def _build_preparation_read_session_descriptor_common(
    plan_value: object, plan_pin_value: object,
    *, construction: bool,
) -> tuple[dict[str, Any], bytes, dict[str, str]]:
    """Serialize plan pins for Root transport; the descriptor is not a capability."""
    plan_validator = (_validate_prepared_input_construction_plan_self
                      if construction else _validate_plan_self)
    schemas = _plan_schema_set(construction=construction)
    plan = plan_validator(plan_value)
    plan_pin = _pin3(plan_pin_value, "recorded-preparation session plan pin")
    _require(plan_pin["path"] == plan["session_paths"]["read_plan"] and
             plan_pin["raw_sha256"] == sha256(canonical_bytes(plan)) and
             plan_pin["semantic_sha256"] == plan["read_plan_sha256"],
             "recorded-preparation session descriptor plan pin differs")
    descriptor = _seal({
        "schema": schemas["session"],
        "basis_pin": plan["basis_pin"],
        "read_plan_pin": plan_pin,
        "session_nonce": plan["session_nonce"],
        "consumer_host_id": plan["consumer_host_id"],
        "operation_kind": plan["operation_kind"],
        "current_journal_frontier": plan["current_journal_frontier"],
        "session_sha256": "",
    }, "session_sha256")
    raw = canonical_bytes(descriptor)
    expected_bytes = plan["resource_projection"]["session_descriptor_bytes"]
    _require(len(raw) == expected_bytes,
             "recorded-preparation session descriptor differs from its reservation size")
    pin = {
        "path": plan["session_paths"]["session"],
        "raw_sha256": sha256(raw),
        "semantic_sha256": descriptor["session_sha256"],
    }
    return descriptor, raw, pin


def build_recorded_preparation_read_session_descriptor_v2(
    plan_value: object, plan_pin_value: object,
) -> tuple[dict[str, Any], bytes, dict[str, str]]:
    return _build_preparation_read_session_descriptor_common(
        plan_value, plan_pin_value, construction=False,
    )


def build_prepared_input_construction_read_session_descriptor_v1(
    plan_value: object, plan_pin_value: object,
) -> tuple[dict[str, Any], bytes, dict[str, str]]:
    return _build_preparation_read_session_descriptor_common(
        plan_value, plan_pin_value, construction=True,
    )


def _project_preparation_payload_view_common(
    plan_value: object,
    plan_pin_value: object,
    read_ordinal: object,
    window_chunk_value: object,
    *,
    outer_request_pin: object,
    outer_response_pin: object,
    bundle_pin: object,
    stage_root: object,
    refs_by_origin: object,
    construction: bool,
) -> dict[str, Any]:
    """Project validated SourceH refs into an exact data-only payload-view DTO.

    The caller must perform no-follow filesystem, stable-byte, mode, ownership,
    and cleanup checks before using this projection. This function checks only
    schema and plan joins and conveys no proof that those checks occurred.
    """
    plan_validator = (_validate_prepared_input_construction_plan_self
                      if construction else _validate_plan_self)
    window_validator = (validate_prepared_input_construction_read_window_v1
                        if construction else
                        validate_recorded_preparation_read_window_v2)
    schemas = _plan_schema_set(construction=construction)
    plan = plan_validator(plan_value)
    plan_pin = _pin3(plan_pin_value, "recorded-preparation payload-view plan pin")
    _require(plan_pin["path"] == plan["session_paths"]["read_plan"] and
             plan_pin["raw_sha256"] == sha256(canonical_bytes(plan)) and
             plan_pin["semantic_sha256"] == plan["read_plan_sha256"],
             "recorded-preparation payload-view plan pin differs")
    ordinal = _uint(read_ordinal, "recorded-preparation payload-view ordinal",
                    maximum=READ_WINDOW_COUNT - 1)
    row = window_validator(plan, plan_pin, window_chunk_value, ordinal)
    request_pin = _pin3(outer_request_pin,
                        "recorded-preparation payload-view outer request pin")
    response_pin = _pin3(outer_response_pin,
                         "recorded-preparation payload-view outer response pin")
    bundle = _exact(bundle_pin, {"path", "raw_sha256", "byte_count"},
                    "recorded-preparation payload-view tar pin")
    _require(request_pin["path"] == row["session_paths"]["request"] and
             response_pin["path"] == row["session_paths"]["response"] and
             bundle["path"] == row["session_paths"]["bundle"] and
             stage_root == row["session_paths"]["stage"],
             "recorded-preparation payload-view paths differ from the current window")
    _sha(bundle["raw_sha256"], "recorded-preparation payload-view tar digest")
    _require(_uint(bundle["byte_count"],
                   "recorded-preparation payload-view tar bytes", positive=True,
                   maximum=MAX_ARCHIVE_BYTES) ==
             row["resource_bounds"]["tar_bytes"],
             "recorded-preparation payload-view tar size differs")
    expected_objects = row["objects"]
    _require(type(refs_by_origin) is dict and
             set(refs_by_origin) == {obj["origin_path"] for obj in expected_objects},
             "recorded-preparation payload-view refs differ from the exact manifest object set")
    refs = []
    payload_bytes = 0
    for object_row in expected_objects:
        origin = object_row["origin_path"]
        ref = _exact(refs_by_origin[origin], {
            "origin_path", "path", "role", "host_id", "raw_sha256",
            "semantic_sha256", "byte_count", "maximum_bytes",
        }, f"recorded-preparation payload ref {origin}")
        member_digest = sha256(origin.encode("utf-8", "strict"))
        expected_stage_path = str(
            PurePosixPath(stage_root) /
            f"{member_digest}-{object_row['raw_sha256']}"
        )
        _require(ref["origin_path"] == origin and
                 ref["path"] == expected_stage_path and
                 ref["role"] == object_row["role"] and
                 ref["host_id"] == row["owner_host_id"] and
                 ref["raw_sha256"] == object_row["raw_sha256"] and
                 ref["semantic_sha256"] == object_row["semantic_sha256"] and
                 ref["byte_count"] == object_row["byte_count"] and
                 ref["maximum_bytes"] == object_row["byte_count"],
                 f"recorded-preparation payload ref {origin} differs from its signed descriptor")
        refs.append(ref)
        payload_bytes += ref["byte_count"]
    _require(payload_bytes == row["resource_bounds"]["payload_bytes"],
             "recorded-preparation payload-view byte total differs")
    view_body = {
        "schema": schemas["payload_view"],
        "basis_pin": plan["basis_pin"],
        "read_plan_pin": plan_pin,
        "session_nonce": plan["session_nonce"],
        "consumer_host_id": plan["consumer_host_id"],
        "owner_host_id": row["owner_host_id"],
        "operation_kind": plan["operation_kind"],
        "read_ordinal": ordinal,
        "job_index": row["job_index"],
        "job_sha256": row["job_sha256"],
        "original_pins": row["original_pins"],
        "outer_request_pin": request_pin,
        "outer_response_pin": response_pin,
        "bundle_pin": bundle,
        "stage_root": stage_root,
        "objects": refs,
        "payload_bytes": payload_bytes,
        "payload_view_sha256": "",
    }
    return _seal(view_body, "payload_view_sha256")


def project_recorded_preparation_payload_view_v2(
    plan_value: object, plan_pin_value: object, read_ordinal: object,
    window_chunk_value: object, *, outer_request_pin: object,
    outer_response_pin: object, bundle_pin: object, stage_root: object,
    refs_by_origin: object,
) -> dict[str, Any]:
    return _project_preparation_payload_view_common(
        plan_value, plan_pin_value, read_ordinal, window_chunk_value,
        outer_request_pin=outer_request_pin,
        outer_response_pin=outer_response_pin, bundle_pin=bundle_pin,
        stage_root=stage_root, refs_by_origin=refs_by_origin,
        construction=False,
    )


def project_prepared_input_construction_payload_view_v1(
    plan_value: object, plan_pin_value: object, read_ordinal: object,
    window_chunk_value: object, *, outer_request_pin: object,
    outer_response_pin: object, bundle_pin: object, stage_root: object,
    refs_by_origin: object,
) -> dict[str, Any]:
    return _project_preparation_payload_view_common(
        plan_value, plan_pin_value, read_ordinal, window_chunk_value,
        outer_request_pin=outer_request_pin,
        outer_response_pin=outer_response_pin, bundle_pin=bundle_pin,
        stage_root=stage_root, refs_by_origin=refs_by_origin,
        construction=True,
    )


def _validate_preparation_payload_view_common(
    value: object, plan_value: object, plan_pin_value: object,
    window_chunk_value: object, *, construction: bool,
) -> dict[str, Any]:
    """Validate only the closed payload-view schema and plan identity."""
    plan_validator = (_validate_prepared_input_construction_plan_self
                      if construction else _validate_plan_self)
    window_validator = (validate_prepared_input_construction_read_window_v1
                        if construction else
                        validate_recorded_preparation_read_window_v2)
    projector = (project_prepared_input_construction_payload_view_v1
                 if construction else
                 project_recorded_preparation_payload_view_v2)
    schemas = _plan_schema_set(construction=construction)
    view = _exact(value, {
        "schema", "basis_pin", "read_plan_pin", "session_nonce",
        "consumer_host_id", "owner_host_id", "operation_kind",
        "read_ordinal", "job_index", "job_sha256", "original_pins",
        "outer_request_pin", "outer_response_pin", "bundle_pin",
        "stage_root", "objects", "payload_bytes", "payload_view_sha256",
    }, "recorded-preparation payload view")
    plan = plan_validator(plan_value)
    plan_pin = _pin3(plan_pin_value, "payload-view read-plan pin")
    ordinal = _uint(view["read_ordinal"], "payload-view ordinal",
                    maximum=READ_WINDOW_COUNT - 1)
    row = window_validator(plan, plan_pin, window_chunk_value, ordinal)
    _require(view["schema"] == schemas["payload_view"] and
             view["basis_pin"] == plan["basis_pin"] and
             view["read_plan_pin"] == plan_pin and
             view["session_nonce"] == plan["session_nonce"] and
             view["consumer_host_id"] == plan["consumer_host_id"] and
             view["owner_host_id"] == row["owner_host_id"] and
             view["operation_kind"] == plan["operation_kind"] and
             view["job_index"] == row["job_index"] and
             view["job_sha256"] == row["job_sha256"] and
             view["original_pins"] == row["original_pins"] and
             view["stage_root"] == row["session_paths"]["stage"],
             "recorded-preparation payload-view identity differs from its plan row")
    _pin3(view["outer_request_pin"], "payload-view outer request pin")
    _pin3(view["outer_response_pin"], "payload-view outer response pin")
    bundle = _exact(view["bundle_pin"], {"path", "raw_sha256", "byte_count"},
                    "payload-view bundle pin")
    _absolute_path(bundle["path"], "payload-view bundle path")
    _sha(bundle["raw_sha256"], "payload-view bundle digest")
    _uint(bundle["byte_count"], "payload-view bundle byte count", positive=True,
          maximum=MAX_ARCHIVE_BYTES)
    _require(type(view["objects"]) is list,
             "recorded-preparation payload-view objects are not a list")
    refs = {}
    for index, ref in enumerate(view["objects"]):
        _require(type(ref) is dict and type(ref.get("origin_path")) is str and
                 ref["origin_path"] not in refs,
                 f"recorded-preparation payload-view ref[{index}] repeats an origin")
        refs[ref["origin_path"]] = ref
    rebuilt = projector(
        plan, plan_pin, ordinal, window_chunk_value,
        outer_request_pin=view["outer_request_pin"],
        outer_response_pin=view["outer_response_pin"],
        bundle_pin=view["bundle_pin"],
        stage_root=view["stage_root"], refs_by_origin=refs,
    )
    _require(canonical_bytes(view) == canonical_bytes(rebuilt),
             "recorded-preparation payload-view differs from its exact plan projection")
    return view


def validate_recorded_preparation_payload_view_v2(
    value: object, plan_value: object, plan_pin_value: object,
    window_chunk_value: object,
) -> dict[str, Any]:
    return _validate_preparation_payload_view_common(
        value, plan_value, plan_pin_value, window_chunk_value,
        construction=False,
    )


def validate_prepared_input_construction_payload_view_v1(
    value: object, plan_value: object, plan_pin_value: object,
    window_chunk_value: object,
) -> dict[str, Any]:
    return _validate_preparation_payload_view_common(
        value, plan_value, plan_pin_value, window_chunk_value,
        construction=True,
    )
