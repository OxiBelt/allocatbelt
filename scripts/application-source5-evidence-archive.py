#!/usr/bin/env python3
"""Private coordinator for bounded Source5 per-job evidence offload.

This module runs on the private archive coordinator, never in a timed APP lane.
It copies already staged, raw-pinned objects into the accepted Source5 v3 object
layout, seals a per-job checkpoint and manifest, and signs an ACK only after
fsync plus independent reopen and rehash. It does not create the later full-host
v3 index or origin receipt.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import time
import types
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


CONTEXT_SCHEMA_V1 = "allocatbelt.application-source5-evidence-archive-context.v1"
REQUEST_SCHEMA_V1 = "allocatbelt.application-source5-evidence-checkpoint-request.v1"
REQUEST_SCHEMA_V2 = "allocatbelt.application-source5-evidence-checkpoint-request.v2"
REQUEST_SCHEMA_V3 = "allocatbelt.application-source5-evidence-checkpoint-request.v3"
CHECKPOINT_SCHEMA_V1 = "allocatbelt.application-source5-evidence-job-checkpoint.v1"
CHECKPOINT_SCHEMA_V2 = "allocatbelt.application-source5-evidence-job-checkpoint.v2"
CHECKPOINT_SCHEMA_V3 = "allocatbelt.application-source5-evidence-job-checkpoint.v3"
PROBE_TMPDIR_INVENTORY_SCHEMA_V1 = \
    "allocatbelt.application-feedback-probe-tmpdir-inventory.v1"
FIXED_PAIR_OVERLAY_SCHEMA_V1 = \
    "allocatbelt.application-fixed-pair-execution-overlay.v1"
FIXED_PAIR_EXECUTION_RECEIPT_SCHEMA_V1 = \
    "allocatbelt.application-fixed-pair-execution-receipt.v1"
FIXED_PAIR_HOST_RECEIPT_SCHEMA_V1 = \
    "allocatbelt.application-fixed-pair-host-verification.v1"
FIXED_PAIR_HOST_IDENTITY_SCHEMA_V1 = \
    "allocatbelt.application-fixed-pair-host-verification-identity.v1"
OBJECT_MANIFEST_SCHEMA_V1 = "allocatbelt.application-source5-evidence-object-manifest.v1"
ACK_SCHEMA_V1 = "allocatbelt.application-source5-evidence-durable-ack.v1"
STAGE_MAP_SCHEMA_V1 = "allocatbelt.application-source5-evidence-stage-map.v1"
VERIFIED_ACK_SCHEMA_V1 = "allocatbelt.application-source5-evidence-verified-ack.v1"
VERIFIED_PREDECESSOR_ACK_SCHEMA_V1 = \
    "allocatbelt.application-source5-evidence-predecessor-ack.v1"
VERIFIED_READ_ACK_SCHEMA_V1 = \
    "allocatbelt.application-source5-evidence-verified-read-ack.v1"
CATALOGUE_LOCAL_MAP_SCHEMA_V1 = "allocatbelt.application-source5-host-catalogue-local-map.v1"
DEPENDENCY_LOCAL_MAP_SCHEMA_V1 = "allocatbelt.application-source5-dependency-local-map.v1"
SIGNER_CONTEXT_SCHEMA_V1 = "allocatbelt.application-source5-archive-signer-context.v1"
EXECUTION_SCHEMA_V2 = "allocatbelt.application-source5-campaign-execution.v2"
EXECUTION_SCHEMA_V3 = "allocatbelt.application-source5-campaign-execution.v3"
EXECUTION_SCHEMA_V4 = "allocatbelt.application-source5-campaign-execution.v4"
HOST_BUDGET_SCHEMA_V2 = "allocatbelt.application-source5-host-evidence-budget.v2"
HOST_BUDGET_SCHEMA_V3 = "allocatbelt.application-source5-host-evidence-budget.v3"
HOST_BUDGET_SCHEMA_V4 = "allocatbelt.application-source5-host-evidence-budget.v4"
PREPARED_EXPLORATION_ADMISSION_PROFILE = "source5_prepared_exploration_reuse_v1"
PREPARED_EXPLORATION_EXECUTION_SCHEMA = "allocatbelt.application-source5-campaign-execution.v5"
PREPARED_EXPLORATION_SCOPE = "final_prepared_exploration_reuse"
HOST_BUDGET_V3_ADMISSION_PROFILE = "source5_width_v4_captured_replay_v1"
SOURCE5_BUDGET_VALIDATOR_PATH = "scripts/application-source5-evidence-budget.py"
PREPARATORY_EXECUTION_SCHEMA_V1 = (
    "allocatbelt.application-source5-preparatory-exploration-execution.v1"
)
PREPARATORY_BUDGET_SCHEMA_V1 = (
    "allocatbelt.application-source5-preparatory-exploration-budget.v1"
)
PREPARATORY_WIDTH_SCHEMA_V1 = (
    "allocatbelt.application-source5-preparatory-journal-width-contract.v1"
)
PREPARATORY_PROFILE_V1 = "preparatory_exploration_360_v1"
PREPARATORY_BUDGET_VALIDATOR_PATH = (
    "scripts/application-source5-preparatory-budget.py"
)
PREPARATORY_OWNER_CATALOGUE_PATH = (
    "scripts/application-source5-evidence-catalogue.py"
)
PREPARATORY_CAMPAIGN_SOURCE_PATH = "scripts/application-campaign.py"
PREPARATORY_INPUT_PREPARATION_SOURCE_PATH = (
    "scripts/application-source5-input-preparation.py"
)
PREPARED_LINEAGE_SOURCE_PATH = "scripts/application-source5-prepared-lineage.py"
PREPARED_BRIDGE_BUDGET_SOURCE_PATH = (
    "scripts/application-source5-prepared-bridge-budget.py"
)
PREPARED_CAMPAIGN_SOURCE_PATH = "scripts/application-source5-campaign.py"
PREPARED_INPUT_PREPARATION_SOURCE_PATH = (
    "scripts/application-source5-input-preparation.py"
)
PREPARED_CAMPAIGN_INPUTS_SOURCE_PATH = "scripts/application-campaign-inputs.py"
PREPARED_CHRONOLOGY_SOURCE_PATH = "scripts/application-campaign-chronology.py"
PREPARED_CONTROLLER_SOURCE_PATH = "scripts/application-campaign.py"
PREPARED_CAPTURE_SOURCE_PATH = "scripts/application-source5-lineage-capture.py"
PREPARED_CAPTURE_MANIFEST_SCHEMA = (
    "allocatbelt.application-source5-lineage-capture-manifest.v1"
)
PREPARED_CAPTURE_MANIFEST_MAX_BYTES = 32 * 1024 * 1024
PREPARED_CAPTURE_BOOTSTRAP_MAX_BYTES = 256 * 1024 * 1024
PREPARATORY_EXECUTION_FIELDS_V1 = {
    "schema", "campaign_id", "host_id", "hosts", "original_inputs",
    "execution_sources", "modules", "observed_hosts", "artifact_root",
    "output_root", "scope", "phase_order", "protocol_sha256",
    "preparatory_capacity_generation", "preparatory_capacity_registration",
    "preparatory_journal_width_contracts", "preparatory_host_budgets",
    "archive_signer_contexts", "preparatory_execution_basis_sha256",
    "qualification_eligible", "manifest_sha256",
}
PREPARATORY_BUDGET_FIELDS_V1 = {
    "schema", "campaign_id", "host_id", "profile",
    "execution_basis_sha256", "original_pins", "owner_contract", "schedule",
    "read_schedule", "journal_width_contract_pin", "path_catalogue",
    "archive_transport", "retention_policy", "storage_reservation",
    "readiness", "budget_sha256",
}
PREPARATORY_WIDTH_FIELDS_V1 = {
    "schema", "campaign_id", "host_id", "profile",
    "execution_basis_sha256", "original_pins_sha256", "initial_spec_pin",
    "initial_plan_pin", "capacity_generation_pin", "source_manifest_pin",
    "owner_pins", "setup_event_widths", "job_rows", "phase_totals",
    "original_callback_event_count", "setup_event_count",
    "maximum_failed_event_count_uplift",
    "maximum_failed_owner_window_bytes", "total_event_count",
    "total_event_bytes", "failed_owner_window", "contract_sha256",
}
PREPARATORY_MAX_BUDGET_BYTES = 128 * 1024 * 1024
PREPARATORY_MAX_WIDTH_BYTES = 16 * 1024 * 1024
PREPARATORY_MAX_MODULE_BYTES = 64 * 1024 * 1024
PREPARATORY_MAX_SPEC_BYTES = 16 * 1024 * 1024
SOURCE_MANIFEST_SCHEMA_V5 = "allocatbelt.application-source-manifest.v5"
SOURCE_INVENTORY_SCHEMA_V1 = "allocatbelt.application-source-inventory.v1"
MAX_SOURCE_BUDGET_MODULE_BYTES = 64 * 1024 * 1024
MAX_SOURCE5_CATALOGUE_CHUNK_BYTES = 8 * 1024 * 1024
JOURNAL_WIDTH_CONTRACT_SCHEMA = \
    "allocatbelt.application-source5-journal-width-contract.v1"
JOURNAL_WIDTH_CONTRACT_FIELDS = {
    "schema", "campaign_id", "host_id", "original_pins_sha256",
    "plan_pin", "source_manifest_pin", "owner_pins", "job_rows",
    "phase_totals", "fixed_event_widths", "total_event_count",
    "total_event_bytes", "failed_owner_window", "contract_sha256",
}
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_REQUEST_CHECKPOINT_BYTES = 128 * 1024 * 1024
MAX_PLAN_BYTES = 256 * 1024 * 1024
MAX_SOURCE_MANIFEST_BYTES = 256 * 1024 * 1024
MAX_SOURCE_MODULES_PER_HOST = 4096
MAX_PROBE_TMPDIR_INVENTORY_BYTES = 16 * 1024 * 1024
MAX_PATH_BYTES = 4096
MAX_ROWS = 1_000_000
MAX_OBJECT_BYTES = 1 << 40
MAX_TOTAL_BYTES = 1 << 48
# These limits match the H15 source5-campaign readback request parser. They
# bound reusable host slots; they do not narrow any per-job archive payload.
MAX_ARCHIVE_READ_METADATA_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_READ_OBJECTS = 262_144
MIN_ARCHIVE_READ_BUNDLE_BYTES = 10 * 1024
MAX_ARCHIVE_SIGNER_CONTEXT_BYTES = 64 * 1024
SOURCE5_RECORDED_READ_PLAN_PATH = (
    "scripts/application-source5-recorded-preparation-read.py"
)
MAX_ARCHIVE_GPGV_BYTES = 64 * 1024 * 1024
RECORDED_READ_GPG_RESOURCE_SCHEMA_V2 = (
    "allocatbelt.application-source5-recorded-read-gpg-resource.v2"
)
RECORDED_READ_GPG_RESOURCE_FIELDS_V2 = {
    "schema", "scratch_root", "device", "reserved_bytes",
    "allocation_block_bytes", "window_directory_allocated_bytes",
    "required_file_bytes", "required_allocated_bytes",
    "reserved_inodes", "maximum_gpgv_bytes", "maximum_keyring_bytes",
    "maximum_ack_bytes", "maximum_signature_bytes",
    "maximum_stdout_bytes", "maximum_stderr_bytes",
    "maximum_window_seconds", "resource_sha256",
}
RECORDED_READ_ROOT_OUTPUT_SCHEMA_V2 = (
    "allocatbelt.application-source5-recorded-read-root-output-resource.v2"
)
RECORDED_READ_ROOT_OUTPUT_FIELDS_V2 = {
    "schema", "root", "device", "reserved_bytes", "reserved_inodes",
    "allocation_block_bytes", "directory_metadata_bytes",
    "directory_allocated_bytes", "required_file_bytes",
    "required_file_allocated_bytes", "required_allocated_bytes",
    "maximum_response_bytes", "maximum_bundle_bytes",
    "maximum_control_ledger_bytes", "maximum_control_line_bytes",
    "failure_receipt_bytes", "maximum_window_seconds", "resource_sha256",
}
RECORDED_READ_ROOT_CONTROL_SCHEMA_V1 = (
    "allocatbelt.application-source5-recorded-read-root-control-event.v1"
)
RECORDED_READ_ROOT_FAILURE_SCHEMA_V1 = (
    "allocatbelt.application-source5-recorded-read-root-failure.v1"
)
MAX_GPG_OUTPUT_BYTES = 1 << 20
COPY_BLOCK_BYTES = 1024 * 1024
MAX_U64 = (1 << 64) - 1
HOST_BUDGET_FIELDS_LEGACY = {
    "schema", "campaign_id", "host_id", "original_pins", "schedule",
    "owner_contract", "path_catalogue", "storage_reservation",
    "role_byte_reservations", "transport", "execution_blockers",
    "readiness", "budget_sha256",
}
HOST_BUDGET_FIELDS_R6 = HOST_BUDGET_FIELDS_LEGACY | {
    "execution_manifest_schema", "journal_width_contract_pin",
}
HOST_BUDGET_FIELDS_V3 = HOST_BUDGET_FIELDS_R6 | {"admission_profile"}
# Keep the historic public constant bound to its original exact field set.
HOST_BUDGET_FIELDS = HOST_BUDGET_FIELDS_LEGACY
SOURCE5_ARCHIVE_READ_CONTROL_ROLE = "source5_archive_read_control_ledger"
SOURCE5_ANALYZER_SPOOL_ROLE = "source5_analyzer_spool"
SOURCE5_ARCHIVE_READ_TRANSIENT_ROLES = frozenset({
    "source5_archive_read_request_slot",
    "source5_archive_read_response_slot",
    "source5_archive_read_response_incoming",
    "source5_archive_read_bundle",
    "source5_archive_read_bundle_incoming",
    "source5_archive_read_stage",
})
SOURCE5_ARCHIVE_READ_RESPONSE_ALTERNATIVES = frozenset({
    "source5_archive_read_response_slot",
    "source5_archive_read_response_incoming",
})
SOURCE5_ARCHIVE_READ_BUNDLE_ALTERNATIVES = frozenset({
    "source5_archive_read_bundle",
    "source5_archive_read_bundle_incoming",
})
SOURCE5_ARCHIVE_READ_ROLES = (
    SOURCE5_ARCHIVE_READ_TRANSIENT_ROLES |
    {SOURCE5_ARCHIVE_READ_CONTROL_ROLE}
)
SOURCE5_ARCHIVE_READ_CONTROL_CACHE: dict[tuple[str, str], bool] = {}
SOURCE5_PATH_CATALOGUE_FIELDS = {
    "schema", "entry_count", "file_count", "tree_count", "chunk_bytes",
    "sort_input_row_count", "sort_input_byte_count", "chunks",
    "maximum_payload_bytes", "maximum_inode_count",
    "maximum_live_inode_count", "retention_policy", "root_byte_bounds",
    "root_inode_bounds", "maximum_index_entries", "maximum_index_bytes",
    "maximum_index_chunks", "maximum_index_manifest_pages",
    "maximum_index_manifest_bytes", "maximum_sort_scratch_bytes",
    "maximum_sort_scratch_inodes", "maximum_index_sort_scratch_bytes",
    "maximum_index_sort_scratch_inodes", "role_byte_bounds",
    "semantic_sha256",
}
SOURCE5_RETENTION_POLICY_FIELDS = {
    "schema", "mode", "success_empty_tree_roles", "always_local_roles",
    "max_live_job_windows", "max_retained_failure_windows",
    "stop_before_next_authorization_on", "reclaim_after", "archive_io_lane",
    "job_group_count", "persistent_root_byte_bounds",
    "persistent_root_inode_bounds",
    "persistent_archive_metadata_root_byte_bounds",
    "persistent_archive_metadata_root_inode_bounds",
    "persistent_archive_metadata_bytes", "persistent_archive_metadata_inodes",
    "persistent_local_job_record_count",
    "persistent_archive_metadata_byte_bounds_by_role",
    "maximum_window_root_byte_bounds", "maximum_window_root_inode_bounds",
    "maximum_live_root_byte_bounds", "maximum_live_root_inode_bounds",
    "maximum_failure_window_tmp_payload_bytes",
    "maximum_failure_window_disposition_bytes", "maximum_window_total_bytes",
    "maximum_window_total_inodes", "maximum_window_index_entries",
    "maximum_window_index_data_bytes", "maximum_checkpoint_request_bytes",
    "maximum_checkpoint_bytes", "maximum_validation_record_bytes",
    "maximum_job_record_bytes", "maximum_object_manifest_bytes",
    "maximum_archive_ack_bytes", "maximum_signature_bytes",
    "maximum_ack_bundle_bytes", "maximum_stage_map_bytes",
    "maximum_transfer_offer_bytes", "archive_metadata_job_group_count",
    "maximum_transfer_packet_bytes", "maximum_transfer_packet_inodes",
    "maximum_failure_window_tmp_index_entries",
    "maximum_failure_window_tmp_index_data_bytes",
    "maximum_full_index_entries", "maximum_full_index_data_bytes",
}
SOURCE5_CLEANUP_RETENTION_FIELDS = {
    "cleanup_source_shape", "maximum_cleanup_sidecar_source_bytes",
    "maximum_cleanup_sidecar_bytes", "maximum_failed_cleanup_window_bytes",
    "maximum_failed_cleanup_window_inodes",
    "maximum_cleanup_sidecar_refusal_bytes",
    "maximum_failed_cleanup_refusal_window_bytes",
    "maximum_failed_cleanup_refusal_window_inodes",
}
NON_EXPORTABLE_JOB_ROLES = frozenset({
    "source5_job_record", "source5_job_disposition",
    SOURCE5_ANALYZER_SPOOL_ROLE,
})
ALWAYS_LOCAL_EVIDENCE_ROLES_LEGACY = frozenset({
    "directory_node", "source5_phase_ledger", "journal", "evidence_index",
    "evidence_index_data_chunk", "evidence_index_manifest_page",
    "origin_receipt", "host_evidence_budget", "host_evidence_budget_chunk",
    "source5_job_record", "source5_archive_signer_context",
    "source5_archive_signer_keyring", "source5_archive_signer_gpgv",
    "source5_job_row_catalogue", "source5_checkpoint_request",
    "source5_transfer_offer", "source5_checkpoint",
    "source5_object_manifest", "source5_archive_ack",
    "source5_archive_signature", "source5_stage_map",
})
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_OPAQUE_TREE_CATALOGUE_CACHE: dict[
    str, dict[tuple[str, str, str], frozenset[str]],
] = {}


def _checkpoint_schema_for_request_schema(request_schema: object) -> str:
    paired = {
        REQUEST_SCHEMA_V1: CHECKPOINT_SCHEMA_V1,
        REQUEST_SCHEMA_V2: CHECKPOINT_SCHEMA_V2,
        REQUEST_SCHEMA_V3: CHECKPOINT_SCHEMA_V3,
    }
    _require(type(request_schema) is str and request_schema in paired,
             "Source5 checkpoint request schema has no exact checkpoint pairing")
    return paired[request_schema]


class EvidenceArchiveError(ValueError):
    """A Source5 archive input, durable object, or signed ACK is invalid."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceArchiveError(message)


def _exact(value: object, fields: set[str], label: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == fields,
             f"{label} has an unexpected field set")
    return value


def _canonical(value: Any, *, maximum_bytes: int = MAX_JSON_BYTES) -> bytes:
    try:
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    except (TypeError, ValueError) as error:
        raise EvidenceArchiveError(f"{label_type(value)} is not canonical JSON: {error}") from error
    _require(len(raw) <= maximum_bytes,
             "canonical archive metadata exceeds its fixed byte ceiling")
    return raw


def _budget_body_semantic_sha256(value: object) -> str:
    """Hash a budget body under its exact schema-specific byte ceiling."""
    _require(type(value) is dict,
             "host evidence budget body is not an object")
    maximum = (PREPARATORY_MAX_BUDGET_BYTES
               if value.get("schema") == PREPARATORY_BUDGET_SCHEMA_V1
               else MAX_JSON_BYTES)
    body = {key: item for key, item in value.items()
            if key != "budget_sha256"}
    return _sha(_canonical(body, maximum_bytes=maximum))


def _checkpoint_metadata_limit(value: object) -> int:
    if type(value) is dict and value.get("schema") in {
            REQUEST_SCHEMA_V2, CHECKPOINT_SCHEMA_V2}:
        return MAX_ARCHIVE_REQUEST_CHECKPOINT_BYTES
    if type(value) is dict and value.get("schema") in {
            REQUEST_SCHEMA_V3, CHECKPOINT_SCHEMA_V3}:
        return MAX_JSON_BYTES
    return MAX_JSON_BYTES


def _parse_checkpoint_metadata(raw: bytes, label: str) -> dict[str, Any]:
    value = _parse_canonical(
        raw, label, maximum_bytes=MAX_ARCHIVE_REQUEST_CHECKPOINT_BYTES,
    )
    limit = _checkpoint_metadata_limit(value)
    _require(len(raw) <= limit,
             f"{label} exceeds its exact versioned metadata ceiling")
    return value


def _canonical_checkpoint_metadata(value: dict[str, Any]) -> bytes:
    return _canonical(value, maximum_bytes=_checkpoint_metadata_limit(value))


def label_type(value: object) -> str:
    return type(value).__name__


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _digest(value: object, label: str) -> str:
    _require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
             f"{label} is not a lowercase SHA-256")
    return value


def _is_owner_receipt_role(role: str) -> bool:
    return "receipt" in role.lower() and not role.startswith(
        "probe_capture_inventory_",
    )


def _fingerprint(value: object, label: str) -> str:
    _require(type(value) is str and
             re.fullmatch(r"[A-F0-9]{40,64}", value) is not None,
             f"{label} is not an uppercase GPG fingerprint")
    return value


def _uint(
    value: object, label: str, *, positive: bool = False,
    maximum: int = MAX_U64,
) -> int:
    _require(type(maximum) is int and 0 <= maximum <= MAX_U64 and
             type(value) is int and 0 <= value <= maximum and
             (not positive or value > 0), f"{label} is outside its finite integer bound")
    return value


def _absolute_path(value: object, label: str) -> str:
    _require(type(value) is str and value.startswith("/") and "\x00" not in value and
             len(value.encode("utf-8", "strict")) <= MAX_PATH_BYTES and
             not any(ord(char) < 32 or ord(char) == 127 for char in value),
             f"{label} is not a bounded absolute path")
    pure = PurePosixPath(value)
    _require(".." not in pure.parts and pure.as_posix() == value,
             f"{label} is not normalized")
    return value


def _token(value: object, label: str) -> str:
    _require(type(value) is str and
             re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value) is not None,
             f"{label} is malformed")
    return value


def _run_id(value: object, label: str) -> str:
    _require(type(value) is str and
             0 < len(value.encode("utf-8", "strict")) <= MAX_PATH_BYTES and
             not any(ord(char) < 32 or ord(char) == 127 for char in value),
             f"{label} is not bounded original run-ID text")
    return value


def _pin(value: object, label: str) -> dict[str, str]:
    row = _exact(value, {"path", "raw_sha256", "semantic_sha256"}, label)
    return {
        "path": _absolute_path(row["path"], f"{label} path"),
        "raw_sha256": _digest(row["raw_sha256"], f"{label} raw SHA-256"),
        "semantic_sha256": _digest(row["semantic_sha256"],
                                   f"{label} semantic SHA-256"),
    }


def _pin_raw(value: object, label: str) -> dict[str, str]:
    row = _exact(value, {"path", "raw_sha256"}, label)
    return {
        "path": _absolute_path(row["path"], f"{label} path"),
        "raw_sha256": _digest(row["raw_sha256"], f"{label} raw SHA-256"),
    }


def _parse_canonical(
    raw: bytes, label: str, *, maximum_bytes: int = MAX_JSON_BYTES,
) -> dict[str, Any]:
    _require(type(raw) is bytes and len(raw) <= maximum_bytes and raw.endswith(b"\n") and
             b"\r" not in raw, f"{label} exceeds its canonical JSON framing bound")
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise EvidenceArchiveError(f"{label} is not valid bounded JSON: {error}") from error
    _require(type(value) is dict and
             _canonical(value, maximum_bytes=maximum_bytes) == raw,
             f"{label} is not canonical JSON")
    return value


def _read_self_digest(raw: bytes, label: str,
                      fields: tuple[str, ...]) -> tuple[dict[str, Any], str]:
    value = _parse_canonical(raw, label)
    matches = []
    for field in fields:
        candidate = value.get(field)
        body = {key: item for key, item in value.items() if key != field}
        if type(candidate) is str and candidate == _sha(_canonical(body)):
            matches.append((field, candidate))
    _require(len(matches) == 1, f"{label} lacks one exact canonical self digest")
    return value, matches[0][1]


def _info_key(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns, info.st_nlink, info.st_uid)


def _open_dir_path(path_value: object, label: str, *, private_final: bool) -> int:
    path = Path(_absolute_path(str(path_value), label))
    parts = path.parts
    _require(path.is_absolute() and parts and parts[0] == "/",
             f"{label} must be absolute")
    fd = os.open("/", os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW)
    try:
        for component in parts[1:]:
            _require(component not in ("", ".", ".."),
                     f"{label} has an unsafe path component")
            child = os.open(component, os.O_RDONLY | _O_DIRECTORY |
                            _O_CLOEXEC | _O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        _require(stat.S_ISDIR(info.st_mode), f"{label} is not a directory")
        if private_final:
            _require(info.st_uid == os.getuid() and
                     stat.S_IMODE(info.st_mode) == 0o700,
                     f"{label} is not an owned mode-0700 private directory")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _ensure_private_child(parent_fd: int, name: str, label: str) -> int:
    _require(name not in ("", ".", "..") and "/" not in name and "\x00" not in name,
             f"{label} has an unsafe child name")
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except FileExistsError:
        pass
    fd = os.open(name, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW,
                 dir_fd=parent_fd)
    info = os.fstat(fd)
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
             stat.S_IMODE(info.st_mode) == 0o700,
             f"{label} is not an owned mode-0700 directory")
    return fd


def _open_relative_dir(root_fd: int, relative: str, *, create: bool,
                       label: str) -> int:
    parts = PurePosixPath(relative).parts
    _require(parts and all(part not in ("", ".", "..", "/") for part in parts),
             f"{label} has an unsafe relative path")
    fd = os.dup(root_fd)
    try:
        for component in parts:
            if create:
                child = _ensure_private_child(fd, component, label)
            else:
                child = os.open(component, os.O_RDONLY | _O_DIRECTORY |
                                _O_CLOEXEC | _O_NOFOLLOW, dir_fd=fd)
                info = os.fstat(child)
                _require(stat.S_ISDIR(info.st_mode) and
                         info.st_uid == os.getuid() and
                         stat.S_IMODE(info.st_mode) == 0o700,
                         f"{label} traverses a non-private directory")
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_parent(root_fd: int, relative_file: str, *, create: bool,
                 label: str) -> tuple[int, str]:
    pure = PurePosixPath(relative_file)
    _require(not pure.is_absolute() and pure.name not in ("", ".", "..") and
             all(part not in ("", ".", "..", "/") for part in pure.parts),
             f"{label} has an unsafe relative file path")
    parent = "." if len(pure.parts) == 1 else "/".join(pure.parts[:-1])
    fd = os.dup(root_fd) if parent == "." else _open_relative_dir(
        root_fd, parent, create=create, label=f"{label} parent",
    )
    return fd, pure.name


def _read_at(fd: int, name: str, maximum: int, label: str,
             *, expected_bytes: int | None = None,
             collect: bool = True, deadline_ns: int | None = None,
             cancel_event=None) -> tuple[bytes | None, str, os.stat_result]:
    try:
        before_path = os.stat(name, dir_fd=fd, follow_symlinks=False)
        _require(stat.S_ISREG(before_path.st_mode) and before_path.st_uid == os.getuid() and
                 stat.S_IMODE(before_path.st_mode) == 0o600 and
                 before_path.st_nlink == 1 and before_path.st_size <= maximum and
                 (expected_bytes is None or before_path.st_size == expected_bytes),
                 f"{label} is not the exact bounded owned mode-0600 single-link file")
        descriptor = os.open(name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK,
                             dir_fd=fd)
    except OSError as error:
        raise EvidenceArchiveError(f"cannot open {label}: {error}") from error
    try:
        before = os.fstat(descriptor)
        _require(_info_key(before) == _info_key(before_path) and
                 stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
                 stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1,
                 f"{label} changed identity before read")
        hasher = hashlib.sha256()
        blocks: list[bytes] | None = [] if collect else None
        total = 0
        while total < before.st_size:
            _require(deadline_ns is None or time.monotonic_ns() < deadline_ns,
                     f"{label} exceeded its finite read deadline")
            _require(cancel_event is None or not cancel_event.is_set(),
                     f"{label} read was cancelled")
            block = os.read(descriptor, min(COPY_BLOCK_BYTES, before.st_size - total))
            _require(bool(block), f"{label} ended before its pinned size")
            total += len(block)
            _require(total <= maximum and total <= before.st_size,
                     f"{label} exceeded its read ceiling")
            hasher.update(block)
            if blocks is not None:
                blocks.append(block)
        _require(os.read(descriptor, 1) == b"" and total == before.st_size,
                 f"{label} has trailing bytes or changed size")
        after = os.fstat(descriptor)
        after_path = os.stat(name, dir_fd=fd, follow_symlinks=False)
        _require(_info_key(before) == _info_key(after) == _info_key(after_path),
                 f"{label} changed during its stable read")
        return (None if blocks is None else b"".join(blocks),
                hasher.hexdigest(), after)
    finally:
        os.close(descriptor)


def _write_at(fd: int, name: str, raw: bytes, label: str) -> tuple[str, int]:
    _require(type(raw) is bytes and len(raw) <= MAX_JSON_BYTES,
             f"{label} exceeds the bounded metadata writer")
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         _O_CLOEXEC | _O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            _require(written > 0, f"{label} writer made no progress")
            view = view[written:]
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                 stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and
                 info.st_size == len(raw),
                 f"{label} writer did not create the exact private file")
    finally:
        os.close(descriptor)
    os.fsync(fd)
    return _sha(raw), len(raw)


def _semantic_for_document(value: dict[str, Any]) -> str:
    candidates = []
    for field in ("receipt_sha256", "record_sha256", "checkpoint_sha256",
                  "manifest_sha256", "ack_sha256", "stage_map_sha256"):
        candidate = value.get(field)
        body = {key: item for key, item in value.items() if key != field}
        if type(candidate) is str and candidate == _sha(_canonical(body)):
            candidates.append(candidate)
    if candidates:
        _require(len(set(candidates)) == 1,
                 "owner receipt contains conflicting self-digest fields")
        return candidates[0]
    return _sha(_canonical(value))


def _validate_context(value: object) -> dict[str, Any]:
    fields = {
        "schema", "campaign_id", "host_id", "phase", "job_index",
        "source_manifest_pin", "execution_manifest_pin", "plan_pin",
        "resource_budget_pin", "predecessor_ack_pin",
        "authorized_signer_fingerprint",
    }
    context = _exact(value, fields, "Source5 archive context")
    _require(context["schema"] == CONTEXT_SCHEMA_V1,
             "Source5 archive context schema differs")
    _token(context["campaign_id"], "campaign ID")
    _token(context["host_id"], "host ID")
    phase = _token(context["phase"], "original phase")
    job_index = _uint(context["job_index"], "original filtered job index")
    for name in ("source_manifest_pin", "execution_manifest_pin",
                 "plan_pin", "resource_budget_pin"):
        _pin(context[name], f"archive {name}")
    predecessor = context["predecessor_ack_pin"]
    _require(predecessor is None or type(predecessor) is dict,
             "archive predecessor ACK pin is malformed")
    if predecessor is not None:
        _pin(predecessor, "archive predecessor ACK")
    signer = _fingerprint(context["authorized_signer_fingerprint"],
                          "authorized signer fingerprint")
    return {**context, "phase": phase, "job_index": job_index}


def _prepared_exploration_primary_context(
    budget: dict[str, Any], budget_pin: object,
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Project the V5 six-copy closure; this does not admit a host budget."""
    _exact(budget, HOST_BUDGET_FIELDS_V3, "prepared-exploration host budget")
    checked_budget_pin = _pin(budget_pin, "prepared-exploration budget pin")
    _require(budget["schema"] == HOST_BUDGET_SCHEMA_V4 and
             budget["admission_profile"] == PREPARED_EXPLORATION_ADMISSION_PROFILE and
             budget["execution_manifest_schema"] == PREPARED_EXPLORATION_EXECUTION_SCHEMA,
             "prepared-exploration budget schema/profile/execution version differs")
    campaign_id = _token(budget["campaign_id"], "prepared-exploration campaign ID")
    host_id = _token(budget["host_id"], "prepared-exploration host ID")
    original = _exact(budget["original_pins"], {
        "spec", "plan", "execution_manifest", "source_manifests",
        "source_tree_sha256", "prepared_exploration",
    }, "prepared-exploration final original pins")
    sources = original["source_manifests"]
    _require(type(sources) is dict and len(sources) in (2, 3) and host_id in sources,
             "prepared-exploration source cohort is incomplete")
    source_pins = {}
    for source_host, value in sources.items():
        _token(source_host, "prepared-exploration source host")
        source_pins[source_host] = _pin(value, "prepared-exploration Source manifest pin")
    lineage = _exact(original["prepared_exploration"], set(sources),
                      "prepared-exploration ancestor host map")
    lineage_paths = set()
    for source_host, value in lineage.items():
        pair = _exact(value, {"bridge_header", "record_index"},
                       f"prepared-exploration {source_host} ancestor pins")
        for kind in ("bridge_header", "record_index"):
            pin = _pin_raw(pair[kind], f"prepared-exploration {source_host} {kind}")
            _require(pin["path"] not in lineage_paths,
                     "prepared-exploration ancestor metadata repeats an origin path")
            lineage_paths.add(pin["path"])
    tree = original["source_tree_sha256"]
    _require(type(tree) is str and re.fullmatch(r"[0-9a-f]{64}", tree) is not None,
             "prepared-exploration source-tree pin is malformed")
    plan_pin = _pin(original["plan"], "prepared-exploration FINAL Plan pin")
    execution_pin = _pin(original["execution_manifest"], "prepared-exploration FINAL execution pin")
    width_pin = _pin(budget["journal_width_contract_pin"], "prepared-exploration FINAL width pin")
    spec_pin = _pin(original["spec"], "prepared-exploration FINAL Spec pin")
    pins = [source_pins[host_id], plan_pin, checked_budget_pin,
            execution_pin, width_pin, spec_pin]
    _require(len({pin["path"] for pin in pins}) == 6 and
             not ({pin["path"] for pin in pins} & lineage_paths),
             "prepared-exploration final primary pins alias another dependency or ancestor")
    return ({
        "campaign_id": campaign_id, "host_id": host_id,
        "source_manifest_pin": source_pins[host_id], "plan_pin": plan_pin,
        "resource_budget_pin": checked_budget_pin,
        "execution_manifest_pin": execution_pin,
    }, pins)


def _parse_host_budget_value(raw: bytes, label: str) -> tuple[dict[str, Any], bool]:
    """Accept only schema-correlated legacy-v2, width-v2, or admitted-v3 bodies."""
    value = _parse_canonical(raw, label)
    if type(value) is dict and set(value) == HOST_BUDGET_FIELDS_LEGACY:
        parsed = _exact(value, HOST_BUDGET_FIELDS_LEGACY, label)
        _require(parsed.get("schema") == HOST_BUDGET_SCHEMA_V2,
                 f"{label} schema does not match its legacy-v2 field set")
        return parsed, False
    if type(value) is dict and set(value) == HOST_BUDGET_FIELDS_R6:
        parsed = _exact(value, HOST_BUDGET_FIELDS_R6, label)
        _require(parsed.get("schema") == HOST_BUDGET_SCHEMA_V2,
                 f"{label} schema does not match its width-v2 field set")
        return parsed, True
    if type(value) is dict and set(value) == HOST_BUDGET_FIELDS_V3:
        parsed = _exact(value, HOST_BUDGET_FIELDS_V3, label)
        _require(parsed.get("schema") == HOST_BUDGET_SCHEMA_V3 and
                 parsed.get("admission_profile") ==
                    HOST_BUDGET_V3_ADMISSION_PROFILE,
                 f"{label} schema/profile does not match its v3 field set")
        return parsed, True
    _exact(value, HOST_BUDGET_FIELDS_LEGACY, label)
    raise EvidenceArchiveError(f"{label} has an unsupported field set")


def _has_h15_archive_readback_roles(catalogue: object) -> bool:
    if type(catalogue) is not dict:
        return False
    role_bounds = catalogue.get("role_byte_bounds")
    if role_bounds is None:
        return False
    _require(type(role_bounds) is dict,
             "host path catalogue role-byte bounds are malformed")
    declared = {role for role in role_bounds
                if type(role) is str and
                role.startswith("source5_archive_read_")}
    has_analyzer_spool = SOURCE5_ANALYZER_SPOOL_ROLE in role_bounds
    _require(not declared or declared == SOURCE5_ARCHIVE_READ_ROLES,
             "H15 archive-read catalogue roles are partial or unknown")
    _require(not has_analyzer_spool or declared == SOURCE5_ARCHIVE_READ_ROLES,
             "v4 analyzer scratch role lacks the exact H15 readback slot closure")
    return bool(declared)


def _validate_execution_manifest_budget_binding(
    raw: bytes, context: dict[str, Any], budget: dict[str, Any],
    journal_width_contract_raw: bytes,
) -> dict[str, Any]:
    """Bind an R6 budget schema and width pin to the exact original manifest."""
    pin = _pin(context["execution_manifest_pin"],
                "archive execution-manifest context pin")
    _require(type(raw) is bytes and _sha(raw) == pin["raw_sha256"],
             "execution-manifest bytes differ from the original context pin")
    value = _parse_canonical(
        raw, "pinned Source5 execution manifest",
        maximum_bytes=MAX_PLAN_BYTES,
    )
    base = {
        "schema", "campaign_id", "hosts", "original_inputs",
        "execution_sources", "modules", "observed_hosts",
        "capacity_completions", "artifact_root", "output_root",
        "phase_order", "protocol_sha256", "qualification_eligible",
        "manifest_sha256",
    }
    schema = budget["execution_manifest_schema"]
    if schema in {EXECUTION_SCHEMA_V2, EXECUTION_SCHEMA_V3}:
        manifest = _exact(value, (base - {"capacity_completions"}) | {
            "scope", "prepared_input_generation",
            "prepared_capacity_registration",
        }, "pinned Source5 execution manifest v2/v3")
        expected_scope = ("final_prepared" if schema == EXECUTION_SCHEMA_V2
                          else "final_prepared_bounded")
        _require(manifest["scope"] == expected_scope,
                 "legacy Source5 execution-manifest scope differs from its schema")
        _require(budget["journal_width_contract_pin"] is None,
                 "legacy Source5 execution manifest cannot carry a v4 width pin")
    elif schema == EXECUTION_SCHEMA_V4:
        manifest = _exact(value, (base - {"capacity_completions"}) | {
            "scope", "prepared_input_generation",
            "prepared_capacity_registration", "archive_signer_contexts",
            "journal_width_contracts",
        }, "pinned Source5 execution manifest v4")
        _require(manifest["scope"] == "final_prepared_bounded",
                 "Source5 execution manifest v4 scope differs")
        hosts = manifest["hosts"]
        _require(type(hosts) is list and bool(hosts) and
                 all(type(host) is str and bool(host) for host in hosts) and
                 len(hosts) == len(set(hosts)) and
                 context["host_id"] in hosts,
                 "Source5 v4 execution-manifest host set is malformed")
        width_map = _exact(
            manifest["journal_width_contracts"], set(hosts),
            "Source5 v4 journal-width contract map",
        )
        signer_map = _exact(
            manifest["archive_signer_contexts"], set(hosts),
            "Source5 v4 archive signer-context map",
        )
        for host in hosts:
            signer_wrapper = _exact(
                signer_map[host], {"artifact", "semantic_sha256"},
                f"Source5 v4 {host} signer-context wrapper",
            )
            signer_artifact = _exact(
                signer_wrapper["artifact"], {"path", "raw_sha256"},
                f"Source5 v4 {host} signer-context artifact",
            )
            _pin({**signer_artifact,
                  "semantic_sha256": signer_wrapper["semantic_sha256"]},
                 f"Source5 v4 {host} signer-context pin")
        wrapper = _exact(
            width_map[context["host_id"]], {"artifact", "semantic_sha256"},
            "Source5 v4 selected-host journal-width wrapper",
        )
        artifact = _exact(
            wrapper["artifact"], {"path", "raw_sha256"},
            "Source5 v4 selected-host journal-width artifact",
        )
        manifest_width_pin = _pin(
            {**artifact, "semantic_sha256": wrapper["semantic_sha256"]},
            "Source5 v4 selected-host journal-width pin",
        )
        budget_width_pin = _pin(
            budget["journal_width_contract_pin"],
            "Source5 v4 budget journal-width pin",
        )
        _require(manifest_width_pin == budget_width_pin,
                 "v4 host-budget width pin differs from the exact execution-manifest host entry")
        _validate_v4_width_contract_bytes(
            journal_width_contract_raw, budget_width_pin, context,
        )
    else:
        raise EvidenceArchiveError(
            "R6 host budget names an unsupported Source5 execution-manifest schema",
        )
    body = {key: item for key, item in manifest.items()
            if key != "manifest_sha256"}
    _require(manifest["schema"] == schema and
             manifest["campaign_id"] == context["campaign_id"] and
             manifest["qualification_eligible"] is False and
             manifest["manifest_sha256"] == _sha(_canonical(
                 body, maximum_bytes=MAX_PLAN_BYTES,
             )) ==
                 pin["semantic_sha256"],
             "Source5 execution manifest differs from its raw/semantic context pin")
    if budget.get("schema") == HOST_BUDGET_SCHEMA_V3:
        expected_budget_path = _absolute_path(
            str(Path(_absolute_path(
                manifest["artifact_root"],
                "Source5 v3 artifact root",
            )) / context["campaign_id"] / "source5" / context["host_id"] /
                "evidence-budget" / "host-evidence-budget-v3.json"),
            "Source5 v3 deterministic host-budget path",
        )
        budget_pin = _pin(context["resource_budget_pin"],
                          "Source5 v3 host-budget context pin")
        _require(budget_pin["path"] == expected_budget_path and
                 PurePosixPath(budget_pin["path"]).name ==
                    "host-evidence-budget-v3.json",
                 "Source5 v3 budget pin differs from its exact reserved path")
    return manifest


def _validate_v4_width_contract_bytes(
    raw: bytes, pin_value: object, context: dict[str, Any],
) -> dict[str, Any]:
    pin = _pin(pin_value, "R6 v4 journal-width contract pin")
    _require(type(raw) is bytes and _sha(raw) == pin["raw_sha256"],
             "journal-width contract bytes differ from their exact raw pin")
    contract = _exact(
        _parse_canonical(raw, "pinned Source5 journal-width contract"),
        JOURNAL_WIDTH_CONTRACT_FIELDS,
        "Source5 v4 journal-width contract",
    )
    body = {key: item for key, item in contract.items()
            if key != "contract_sha256"}
    _require(contract["schema"] == JOURNAL_WIDTH_CONTRACT_SCHEMA and
             contract["campaign_id"] == context["campaign_id"] and
             contract["host_id"] == context["host_id"] and
             _pin(contract["plan_pin"], "width-contract PlanV3 pin") ==
                 context["plan_pin"] and
             _pin(contract["source_manifest_pin"],
                  "width-contract SourceV5 pin") ==
                 context["source_manifest_pin"] and
             contract["contract_sha256"] == _sha(_canonical(body)) ==
                 pin["semantic_sha256"],
             "Source5 v4 width contract differs from its exact host/context pins")
    return contract


def _read_source_budget_module(
    source_manifest_raw: bytes, context: dict[str, Any],
    execution_manifest_raw: bytes,
) -> dict[str, Any]:
    """Load only the budget validator selected by the raw-pinned SourceV5."""
    source_pin = _pin(context["source_manifest_pin"],
                      "selected SourceV5 manifest pin")
    _require(type(source_manifest_raw) is bytes and
             _sha(source_manifest_raw) == source_pin["raw_sha256"],
             "selected SourceV5 bytes differ from their exact raw pin")
    source = _parse_canonical(
        source_manifest_raw, "selected SourceV5 manifest",
        maximum_bytes=MAX_SOURCE_MANIFEST_BYTES,
    )
    source_body = {key: item for key, item in source.items()
                   if key != "manifest_sha256"}
    source_inventory = source.get("source")
    _require(source.get("schema") == SOURCE_MANIFEST_SCHEMA_V5 and
             type(source.get("manifest_sha256")) is str and
             source["manifest_sha256"] == source_pin["semantic_sha256"] ==
                 _sha(_canonical(source_body,
                                 maximum_bytes=MAX_SOURCE_MANIFEST_BYTES)) and
             type(source_inventory) is dict and
             type(source_inventory.get("files")) is list,
             "selected SourceV5 manifest schema or semantic pin differs")
    files = source_inventory["files"]
    inventory_body = {"schema": SOURCE_INVENTORY_SCHEMA_V1,
                      "entries": files}
    _require(source_inventory.get("source_tree_sha256") ==
             _sha(_canonical(inventory_body,
                             maximum_bytes=MAX_SOURCE_MANIFEST_BYTES)),
             "selected SourceV5 typed inventory does not match its source-tree digest")
    matches = [row for row in files
               if type(row) is dict and
               row.get("path") == SOURCE5_BUDGET_VALIDATOR_PATH]
    _require(len(matches) == 1,
             "selected SourceV5 has no unique budget-validator inventory row")
    module_row = _exact(
        matches[0], {"path", "kind", "mode", "sha256", "size"},
        "selected SourceV5 budget-validator inventory row",
    )
    module_sha = _digest(module_row["sha256"],
                         "selected budget-validator source digest")
    module_size = _uint(module_row["size"],
                         "selected budget-validator source size")
    _require(module_row["kind"] == "file" and
             module_row["mode"] in {"100644", "100755"} and
             0 < module_size <= MAX_SOURCE_BUDGET_MODULE_BYTES,
             "selected SourceV5 budget validator is not a bounded regular script")

    execution_pin = _pin(context["execution_manifest_pin"],
                         "selected execution-manifest pin")
    _require(type(execution_manifest_raw) is bytes and
             _sha(execution_manifest_raw) == execution_pin["raw_sha256"],
             "selected execution-manifest bytes differ from their raw pin")
    execution = _parse_canonical(
        execution_manifest_raw, "selected Source5 execution manifest",
        maximum_bytes=MAX_PLAN_BYTES,
    )
    execution_body = {key: item for key, item in execution.items()
                      if key != "manifest_sha256"}
    hosts = execution.get("hosts")
    _require(execution.get("schema") == EXECUTION_SCHEMA_V4 and
             execution.get("campaign_id") == context["campaign_id"] and
             type(hosts) is list and context["host_id"] in hosts and
             execution.get("manifest_sha256") == execution_pin["semantic_sha256"] ==
                 _sha(_canonical(execution_body,
                                 maximum_bytes=MAX_PLAN_BYTES)),
             "selected execution manifest does not bind the Source5 v4 budget context")
    original_inputs = execution.get("original_inputs")
    _require(type(original_inputs) is dict and
             type(original_inputs.get("source_manifests")) is dict and
             context["host_id"] in original_inputs["source_manifests"],
             "selected execution manifest omits the SourceV5 host pin")
    source_wrapper = _exact(
        original_inputs["source_manifests"][context["host_id"]],
        {"artifact", "semantic_sha256"},
        "execution-manifest selected SourceV5 wrapper",
    )
    source_artifact = _exact(
        source_wrapper["artifact"], {"path", "raw_sha256"},
        "execution-manifest selected SourceV5 artifact",
    )
    _require(source_artifact == {
                 "path": source_pin["path"],
                 "raw_sha256": source_pin["raw_sha256"],
             } and
             source_wrapper["semantic_sha256"] == source_pin["semantic_sha256"],
             "selected SourceV5 pin differs from the execution-manifest original inputs")
    execution_sources = execution.get("execution_sources")
    _require(type(execution_sources) is dict and
             context["host_id"] in execution_sources,
             "selected execution manifest omits its SourceV5 source snapshot")
    source_snapshot = _exact(
        execution_sources[context["host_id"]],
        {"source_root", "git_commit", "source_tree_sha256", "build_sha256"},
        "execution-manifest selected SourceV5 snapshot",
    )
    build = source.get("build")
    _require(type(build) is dict and
             source_snapshot["git_commit"] == source_inventory.get("git_commit") and
             source_snapshot["source_tree_sha256"] ==
                 source_inventory["source_tree_sha256"] and
             source_snapshot["build_sha256"] == _sha(_canonical(build)),
             "execution-manifest source snapshot differs from selected SourceV5")
    modules = execution.get("modules")
    _require(type(modules) is dict and context["host_id"] in modules and
             type(modules[context["host_id"]]) is dict,
             "selected execution manifest omits its SourceV5 module map")
    module_pin = _exact(
        modules[context["host_id"]].get(SOURCE5_BUDGET_VALIDATOR_PATH),
        {"path", "sha256"},
        "execution-manifest selected budget-validator pin",
    )
    _require(module_pin == {"path": SOURCE5_BUDGET_VALIDATOR_PATH,
                            "sha256": module_sha},
             "budget-validator module differs from the execution-manifest Source pin")

    module_filename = globals().get("__file__")
    _require(type(module_filename) is str and bool(module_filename),
             "executing archive module has no Source-root file identity")
    source_root = Path(os.path.abspath(module_filename)).parent.parent
    root_fd = _open_dir_path(str(source_root),
                             "Root-local selected Source5 tree",
                             private_final=False)
    scripts_fd = -1
    try:
        scripts_fd = os.open("scripts", os.O_RDONLY | _O_DIRECTORY |
                             _O_CLOEXEC | _O_NOFOLLOW, dir_fd=root_fd)
        before_path = os.stat("application-source5-evidence-budget.py",
                              dir_fd=scripts_fd, follow_symlinks=False)
        actual_mode = f"{stat.S_IFMT(before_path.st_mode) | stat.S_IMODE(before_path.st_mode):06o}"
        _require(stat.S_ISREG(before_path.st_mode) and
                 before_path.st_size == module_size and
                 actual_mode == module_row["mode"],
                 "Root-local budget-validator file mode/size differs from SourceV5")
        descriptor = os.open("application-source5-evidence-budget.py",
                             os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW |
                             _O_NONBLOCK, dir_fd=scripts_fd)
        try:
            before = os.fstat(descriptor)
            _require(_info_key(before) == _info_key(before_path),
                     "Root-local budget-validator changed before its pinned read")
            blocks: list[bytes] = []
            total = 0
            hasher = hashlib.sha256()
            while total < module_size:
                block = os.read(descriptor,
                                min(COPY_BLOCK_BYTES, module_size - total))
                _require(bool(block),
                         "Root-local budget-validator ended before its typed size")
                total += len(block)
                hasher.update(block)
                blocks.append(block)
            after = os.fstat(descriptor)
            after_path = os.stat("application-source5-evidence-budget.py",
                                 dir_fd=scripts_fd, follow_symlinks=False)
            _require(os.read(descriptor, 1) == b"" and total == module_size and
                     _info_key(before) == _info_key(after) ==
                         _info_key(after_path) and hasher.hexdigest() == module_sha,
                     "Root-local budget-validator bytes differ from its typed Source pin")
            module_raw = b"".join(blocks)
        finally:
            os.close(descriptor)
    finally:
        if scripts_fd >= 0:
            os.close(scripts_fd)
        os.close(root_fd)
    namespace: dict[str, Any] = {
        "__name__": "_allocatbelt_source5_pinned_budget_validator",
        "__file__": str(source_root / SOURCE5_BUDGET_VALIDATOR_PATH),
        "__package__": None,
    }
    try:
        code = compile(module_raw, namespace["__file__"], "exec")
        exec(code, namespace, namespace)
    except Exception as error:
        raise EvidenceArchiveError(
            f"selected Source5 budget validator cannot be loaded: {error}",
        ) from error
    validate = namespace.get("validate_host_evidence_budget_v3")
    _require(callable(validate) and
             namespace.get("HOST_BUDGET_SCHEMA_V3") == HOST_BUDGET_SCHEMA_V3,
             "selected Source5 module does not expose the exact v3 budget validator")
    return namespace


def _read_source_typed_module(
    source_manifest_raw: bytes, execution_manifest_raw: bytes,
    context: dict[str, Any], module_path: str, expected_execution_schema: str,
    *, namespace_name: str, register_module: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Load one module only after its exact Source and execution pins close."""
    source_pin = _pin(context["source_manifest_pin"],
                      "selected SourceV5 manifest pin")
    execution_pin = _pin(context["execution_manifest_pin"],
                         "selected execution-manifest pin")
    _require(type(source_manifest_raw) is bytes and
             _sha(source_manifest_raw) == source_pin["raw_sha256"] and
             type(execution_manifest_raw) is bytes and
             _sha(execution_manifest_raw) == execution_pin["raw_sha256"],
             "typed Source module dependencies differ from their raw pins")
    source = _parse_canonical(
        source_manifest_raw, "selected SourceV5 manifest",
        maximum_bytes=MAX_SOURCE_MANIFEST_BYTES,
    )
    source_body = {key: item for key, item in source.items()
                   if key != "manifest_sha256"}
    inventory = source.get("source")
    _require(source.get("schema") == SOURCE_MANIFEST_SCHEMA_V5 and
             source.get("manifest_sha256") == source_pin["semantic_sha256"] ==
                 _sha(_canonical(source_body,
                                 maximum_bytes=MAX_SOURCE_MANIFEST_BYTES)) and
             type(inventory) is dict and type(inventory.get("files")) is list,
             "selected SourceV5 manifest schema or semantic pin differs")
    inventory_body = {"schema": SOURCE_INVENTORY_SCHEMA_V1,
                      "entries": inventory["files"]}
    _require(inventory.get("source_tree_sha256") ==
             _sha(_canonical(inventory_body,
                             maximum_bytes=MAX_SOURCE_MANIFEST_BYTES)),
             "selected SourceV5 typed inventory digest differs")
    source_rows = [row for row in inventory["files"]
                   if type(row) is dict and row.get("path") == module_path]
    _require(len(source_rows) == 1,
             "selected SourceV5 has no unique typed module row")
    module_row = _exact(source_rows[0], {
        "path", "kind", "mode", "sha256", "size",
    }, "selected SourceV5 typed module row")
    module_sha = _digest(module_row["sha256"],
                         "selected Source module digest")
    module_size = _uint(module_row["size"], "selected Source module size",
                        positive=True)
    _require(module_row["kind"] == "file" and
             module_row["mode"] in {"100644", "100755"} and
             module_size <= PREPARATORY_MAX_MODULE_BYTES,
             "selected Source module is not a bounded typed regular file")
    execution = _parse_canonical(
        execution_manifest_raw, "selected Source5 execution manifest",
        maximum_bytes=MAX_PLAN_BYTES,
    )
    execution_body = {key: item for key, item in execution.items()
                      if key != "manifest_sha256"}
    _require(execution.get("schema") == expected_execution_schema and
             execution.get("campaign_id") == context["campaign_id"] and
             execution.get("manifest_sha256") == execution_pin["semantic_sha256"] ==
                 _sha(_canonical(execution_body,
                                 maximum_bytes=MAX_PLAN_BYTES)) and
             type(execution.get("hosts")) is list and
             context["host_id"] in execution["hosts"],
             "selected execution manifest schema/identity/self digest differs")
    original_inputs = execution.get("original_inputs")
    _require(type(original_inputs) is dict and
             type(original_inputs.get("source_manifests")) is dict and
             context["host_id"] in original_inputs["source_manifests"],
             "selected execution manifest omits its SourceV5 host entry")
    source_wrapper = _exact(
        original_inputs["source_manifests"][context["host_id"]],
        {"artifact", "semantic_sha256"},
        "selected execution-manifest SourceV5 wrapper",
    )
    source_artifact = _exact(source_wrapper["artifact"],
                             {"path", "raw_sha256"},
                             "selected execution-manifest SourceV5 artifact")
    _require(source_artifact == {
                 "path": source_pin["path"],
                 "raw_sha256": source_pin["raw_sha256"],
             } and source_wrapper["semantic_sha256"] ==
                 source_pin["semantic_sha256"],
             "selected SourceV5 pin differs from its execution-manifest entry")
    modules = execution.get("modules")
    _require(type(modules) is dict and context["host_id"] in modules and
             type(modules[context["host_id"]]) is dict,
             "selected execution manifest omits its Source module map")
    module_pin = _exact(modules[context["host_id"]].get(module_path),
                        {"path", "sha256"},
                        "selected execution-manifest module pin")
    _require(module_pin == {"path": module_path, "sha256": module_sha},
             "typed module differs from the execution-manifest module pin")

    module_filename = globals().get("__file__")
    _require(type(module_filename) is str and bool(module_filename),
             "executing archive module has no Source-root identity")
    source_root = Path(os.path.abspath(module_filename)).parent.parent
    root_fd = _open_dir_path(str(source_root),
                             "Root-local selected Source5 tree",
                             private_final=False)
    parent_fd = -1
    descriptor = -1
    try:
        parent_fd = os.dup(root_fd)
        components = PurePosixPath(module_path).parts
        _require(len(components) == 2 and components[0] == "scripts" and
                 components[1] not in ("", ".", ".."),
                 "selected Source module path is outside its closed scripts slot")
        child_fd = os.open(components[0], os.O_RDONLY | _O_DIRECTORY |
                           _O_CLOEXEC | _O_NOFOLLOW, dir_fd=parent_fd)
        os.close(parent_fd)
        parent_fd = child_fd
        before_path = os.stat(components[1], dir_fd=parent_fd,
                              follow_symlinks=False)
        actual_mode = f"{stat.S_IFMT(before_path.st_mode) | stat.S_IMODE(before_path.st_mode):06o}"
        _require(stat.S_ISREG(before_path.st_mode) and
                 before_path.st_size == module_size and
                 actual_mode == module_row["mode"],
                 "Root-local selected Source module mode/size differs from typed inventory")
        descriptor = os.open(components[1], os.O_RDONLY | _O_CLOEXEC |
                             _O_NOFOLLOW | _O_NONBLOCK, dir_fd=parent_fd)
        before = os.fstat(descriptor)
        _require(_info_key(before) == _info_key(before_path),
                 "Root-local selected Source module changed before its pinned read")
        blocks: list[bytes] = []
        total = 0
        hasher = hashlib.sha256()
        while total < module_size:
            block = os.read(descriptor,
                            min(COPY_BLOCK_BYTES, module_size - total))
            _require(bool(block), "selected Source module ended before its typed size")
            total += len(block)
            hasher.update(block)
            blocks.append(block)
        after = os.fstat(descriptor)
        after_path = os.stat(components[1], dir_fd=parent_fd,
                             follow_symlinks=False)
        _require(os.read(descriptor, 1) == b"" and total == module_size and
                 _info_key(before) == _info_key(after) == _info_key(after_path) and
                 hasher.hexdigest() == module_sha,
                 "Root-local selected Source module bytes differ from typed pin")
        module_raw = b"".join(blocks)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_fd >= 0:
            os.close(parent_fd)
        os.close(root_fd)
    filename = str(source_root / module_path)
    if register_module:
        module_name = (
            f"{namespace_name}_{module_sha[:16]}_"
            f"{source_pin['raw_sha256'][:12]}_{execution_pin['raw_sha256'][:12]}"
        )
        module = types.ModuleType(module_name)
        module.__file__ = filename
        module.__package__ = None
        previous = sys.modules.get(module_name)
        sys.modules[module_name] = module
        try:
            code = compile(module_raw, filename, "exec")
            exec(code, module.__dict__, module.__dict__)
        except Exception as error:
            if sys.modules.get(module_name) is module:
                if previous is None:
                    sys.modules.pop(module_name, None)
                else:
                    sys.modules[module_name] = previous
            raise EvidenceArchiveError(
                f"typed Source module cannot be loaded: {error}",
            ) from error
        return module.__dict__, source, execution
    namespace: dict[str, Any] = {
        "__name__": namespace_name, "__file__": filename,
        "__package__": None,
    }
    try:
        exec(compile(module_raw, filename, "exec"), namespace, namespace)
    except Exception as error:
        raise EvidenceArchiveError(
            f"typed Source module cannot be loaded: {error}",
        ) from error
    return namespace, source, execution


def _source_budget_catalogue_reader(
    budget: dict[str, Any], catalogue_chunk_paths: dict[str, str] | None,
    catalogue_cache_root: str | None, *, root_local: bool,
    captured_artifact_reader=None,
):
    """Build the sole v3 validator row reader from exact pinned chunk origins."""
    catalogue = budget.get("path_catalogue")
    _require(type(catalogue) is dict and
             type(catalogue.get("chunks")) is list and
             0 < len(catalogue["chunks"]) <= MAX_ROWS,
             "v3 budget lacks its exact row-catalogue chunk manifest")
    descriptors: dict[str, dict[str, Any]] = {}
    for index, descriptor_value in enumerate(catalogue["chunks"]):
        descriptor = _exact(descriptor_value, {
            "path", "raw_sha256", "semantic_sha256", "byte_count",
            "row_count", "first_path", "last_path",
        }, f"v3 budget catalogue descriptor[{index}]")
        origin = _absolute_path(descriptor["path"],
                                "v3 budget catalogue origin")
        _digest(descriptor["raw_sha256"],
                "v3 budget catalogue raw digest")
        chunk_bytes = _uint(descriptor["byte_count"],
                            "v3 budget catalogue chunk size", positive=True)
        chunk_rows = _uint(descriptor["row_count"],
                           "v3 budget catalogue chunk rows", positive=True)
        _require(origin not in descriptors and
                 chunk_bytes <= MAX_SOURCE5_CATALOGUE_CHUNK_BYTES and
                 chunk_rows <= MAX_ROWS and
                 descriptor["semantic_sha256"] == descriptor["raw_sha256"],
                 "v3 budget catalogue chunk descriptor is duplicate or unpinned")
        descriptors[origin] = descriptor
    if captured_artifact_reader is not None:
        _require(callable(captured_artifact_reader) and root_local and
                 catalogue_chunk_paths is None and catalogue_cache_root is None,
                 "captured catalogue byte reads cannot mix with host or local-path reads")
        cache_root = None
    elif root_local:
        _require(type(catalogue_chunk_paths) is dict and
                 catalogue_cache_root is not None and
                 set(catalogue_chunk_paths) == set(descriptors),
                 "v3 Root validator requires the complete captured catalogue map")
        cache_root = Path(_absolute_path(catalogue_cache_root,
                                         "v3 Root catalogue cache root"))
        cache_fd = _open_dir_path(str(cache_root),
                                  "v3 Root catalogue cache root",
                                  private_final=True)
        os.close(cache_fd)
    else:
        _require(catalogue_chunk_paths is None and catalogue_cache_root is None,
                 "host v3 validation cannot substitute Root-local catalogue paths")
        cache_root = None

    def read_catalogue_chunk(origin_value: str, byte_count_value: int) -> bytes:
        origin = _absolute_path(origin_value, "v3 validator catalogue row origin")
        descriptor = descriptors.get(origin)
        _require(descriptor is not None and
                 _uint(byte_count_value,
                       "v3 validator catalogue chunk byte count", positive=True) ==
                     descriptor["byte_count"],
                 "v3 validator requested a chunk outside the exact source catalogue")
        if captured_artifact_reader is not None:
            pin = {"path": origin, "raw_sha256": descriptor["raw_sha256"]}
            try:
                raw = captured_artifact_reader(pin, descriptor["byte_count"])
            except Exception as error:
                raise EvidenceArchiveError(
                    "captured source-pinned catalogue chunk is unavailable",
                ) from error
            _require(type(raw) is bytes and len(raw) == descriptor["byte_count"] and
                     _sha(raw) == descriptor["raw_sha256"] == descriptor["semantic_sha256"],
                     "captured catalogue chunk differs from its exact Source pin/size")
            return raw
        if root_local:
            local = Path(_absolute_path(catalogue_chunk_paths[origin],
                                        "v3 captured catalogue chunk path"))
            _require(local != Path(origin) and local != cache_root and
                     cache_root in local.parents and
                     local.resolve(strict=True) == local,
                     "v3 captured catalogue chunk escapes its exact private cache")
        else:
            local = Path(origin)
        raw, digest, info = _read_absolute_private_file(
            local, descriptor["byte_count"],
            "v3 source-pinned path catalogue chunk",
        )
        _require(len(raw) == descriptor["byte_count"] and
                 digest == descriptor["raw_sha256"] and
                 digest == descriptor["semantic_sha256"] and
                 info.st_size == descriptor["byte_count"],
                 "v3 path catalogue chunk differs from its raw/semantic pin")
        return raw

    return read_catalogue_chunk


def _prepared_source_document(
    raw: bytes, pin_value: object, label: str,
) -> dict[str, Any]:
    pin = _pin(pin_value, f"{label} Source manifest pin")
    _require(type(raw) is bytes and _sha(raw) == pin["raw_sha256"],
             f"{label} Source manifest differs from its raw pin")
    source = _parse_canonical(
        raw, f"{label} SourceV5 manifest",
        maximum_bytes=MAX_SOURCE_MANIFEST_BYTES,
    )
    body = {key: value for key, value in source.items()
            if key != "manifest_sha256"}
    inventory = source.get("source")
    _require(source.get("schema") == SOURCE_MANIFEST_SCHEMA_V5 and
             source.get("manifest_sha256") == pin["semantic_sha256"] ==
                 _sha(_canonical(body, maximum_bytes=MAX_SOURCE_MANIFEST_BYTES)) and
             type(inventory) is dict and type(inventory.get("files")) is list,
             f"{label} Source manifest schema or semantic pin differs")
    inventory_body = {"schema": SOURCE_INVENTORY_SCHEMA_V1,
                      "entries": inventory["files"]}
    tree_sha = _sha(_canonical(inventory_body,
                               maximum_bytes=MAX_SOURCE_MANIFEST_BYTES))
    _require(inventory.get("source_tree_sha256") == tree_sha,
             f"{label} Source typed inventory digest differs")
    return source


def _prepared_typed_module(
    source_manifest_raw: bytes, execution_manifest_raw: bytes,
    context: dict[str, Any], module_path: str,
) -> dict[str, Any]:
    namespace, source, execution = _read_source_typed_module(
        source_manifest_raw, execution_manifest_raw, context, module_path,
        PREPARED_EXPLORATION_EXECUTION_SCHEMA,
        namespace_name="_allocatbelt_source5_prepared_" +
            module_path.rsplit("/", 1)[-1].replace(".py", "").replace("-", "_"),
        register_module=True,
    )
    module_name = namespace["__name__"]
    module = sys.modules.get(module_name)
    try:
        rows = [row for row in source["source"]["files"]
                if type(row) is dict and row.get("path") == module_path]
        _require(len(rows) == 1,
                 f"selected Source lacks one typed row for {module_path}")
        row = _exact(rows[0], {"path", "kind", "mode", "sha256", "size"},
                     f"selected Source module row {module_path}")
        pin = _exact(execution["modules"][context["host_id"]].get(module_path),
                     {"path", "sha256"},
                     f"selected execution module pin {module_path}")
        _require(row["kind"] == "file" and
                 row["mode"] in {"100644", "100755"} and
                 pin == {"path": module_path, "sha256": row["sha256"]},
                 f"selected Source module identity differs for {module_path}")
        namespace["__source5_typed_pin__"] = pin
    except BaseException:
        if module is not None and sys.modules.get(module_name) is module:
            sys.modules.pop(module_name, None)
        raise
    return namespace


def _recorded_pre_manifest_typed_module(
    source_manifest_raw: bytes, source_manifest_pin_value: object,
    source_module_pins_value: object, module_path: str,
    source_root_value: object, expected_source_root_value: object, *,
    namespace_name: str,
) -> dict[str, Any]:
    """Load one current selected-host Source module before any final manifest.

    This is deliberately narrower than ``_prepared_typed_module``: a
    registration replay has no sealed final execution manifest to consult.
    The current selected Source manifest and the SourceA-issued basis module
    map provide the exact identities instead. Peer Source manifests remain
    metadata and are never opened through this helper.
    """
    source_pin = _pin(source_manifest_pin_value,
                      "recorded-read selected Source manifest pin")
    _require(type(source_manifest_raw) is bytes and
             _sha(source_manifest_raw) == source_pin["raw_sha256"],
             "recorded-read selected Source bytes differ from their basis pin")
    source = _prepared_source_document(
        source_manifest_raw, source_pin, "recorded-read selected current",
    )
    _require(type(source_module_pins_value) is dict and
             0 < len(source_module_pins_value) <= MAX_SOURCE_MODULES_PER_HOST,
             "recorded-read selected Source module map is malformed")
    module_pins = source_module_pins_value
    _require(type(module_path) is str and module_path in module_pins,
             "recorded-read basis omits the selected Source module pin")
    module_pin = _exact(module_pins[module_path], {"path", "sha256"},
                        "recorded-read selected Source module pin")
    _require(module_pin["path"] == module_path and
             module_path.startswith("scripts/") and
             PurePosixPath(module_path).as_posix() == module_path and
             len(PurePosixPath(module_path).parts) == 2 and
             ".." not in PurePosixPath(module_path).parts,
             "recorded-read selected Source module path is not a scripts child")
    module_sha = _digest(module_pin["sha256"],
                         "recorded-read selected Source module digest")
    source_rows = [row for row in source["source"]["files"]
                   if type(row) is dict and row.get("path") == module_path]
    _require(len(source_rows) == 1,
             "recorded-read current Source lacks one selected typed module row")
    module_row = _exact(source_rows[0], {
        "path", "kind", "mode", "sha256", "size",
    }, "recorded-read current Source module inventory row")
    module_size = _uint(module_row["size"],
                        "recorded-read selected Source module size",
                        positive=True, maximum=PREPARATORY_MAX_MODULE_BYTES)
    _require(module_row["kind"] == "file" and
             module_row["mode"] in {"100644", "100755"} and
             module_row["sha256"] == module_sha,
             "recorded-read module differs from the current Source inventory")
    source_root = Path(_absolute_path(
        source_root_value, "recorded-read current selected Source root",
    ))
    expected_source_root = Path(_absolute_path(
        expected_source_root_value,
        "recorded-read basis selected Source root",
    ))
    _require(source_root == expected_source_root and
             source_root.resolve(strict=True) == source_root,
             "recorded-read Source root differs from the selected current basis root")
    root_fd = _open_dir_path(str(source_root),
                             "recorded-read current Source root",
                             private_final=False)
    parent_fd = -1
    descriptor = -1
    try:
        parent_fd = os.open(
            "scripts", os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW,
            dir_fd=root_fd,
        )
        leaf = PurePosixPath(module_path).parts[1]
        before_path = os.stat(leaf, dir_fd=parent_fd,
                              follow_symlinks=False)
        actual_mode = f"{stat.S_IFMT(before_path.st_mode) | stat.S_IMODE(before_path.st_mode):06o}"
        _require(stat.S_ISREG(before_path.st_mode) and
                 before_path.st_size == module_size and
                 actual_mode == module_row["mode"],
                 "recorded-read selected module mode/size differs from its typed inventory")
        descriptor = os.open(
            leaf, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK,
            dir_fd=parent_fd,
        )
        before = os.fstat(descriptor)
        _require(_info_key(before) == _info_key(before_path),
                 "recorded-read selected Source module changed before its pinned read")
        pieces = []
        hasher = hashlib.sha256()
        total = 0
        while total < module_size:
            block = os.read(descriptor,
                            min(COPY_BLOCK_BYTES, module_size - total))
            _require(bool(block),
                     "recorded-read selected Source module ended before its typed size")
            total += len(block)
            hasher.update(block)
            pieces.append(block)
        after = os.fstat(descriptor)
        after_path = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        _require(os.read(descriptor, 1) == b"" and total == module_size and
                 _info_key(before) == _info_key(after) ==
                     _info_key(after_path) and hasher.hexdigest() == module_sha,
                 "recorded-read selected Source module bytes differ from its typed pin")
        module_raw = b"".join(pieces)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_fd >= 0:
            os.close(parent_fd)
        os.close(root_fd)
    filename = str(source_root / module_path)
    module_name = f"{namespace_name}_{module_sha[:16]}_{source_pin['raw_sha256'][:12]}"
    module = types.ModuleType(module_name)
    module.__file__ = filename
    module.__package__ = None
    previous = sys.modules.get(module_name)
    sys.modules[module_name] = module
    try:
        code = compile(module_raw, filename, "exec")
        exec(code, module.__dict__, module.__dict__)
    except Exception as error:
        if sys.modules.get(module_name) is module:
            if previous is None:
                sys.modules.pop(module_name, None)
            else:
                sys.modules[module_name] = previous
        raise EvidenceArchiveError(
            f"typed pre-manifest selected Source module cannot be loaded: {error}",
        ) from error
    module.__source5_typed_pin__ = dict(module_pin)
    return module.__dict__


class _PreparedBootstrapCaptureReader:
    """Lazy custody-checked bootstrap for Source-requested captured bytes only."""

    def __init__(
        self, capture_module: dict[str, Any], manifest: dict[str, Any],
        stage_root: str, maximum_read_bytes: int, *,
        deadline_ns: int | None = None, cancel_event=None,
    ):
        self._capture_module = capture_module
        self._stage_root = capture_module["_absolute_stage_root"](stage_root)
        self._maximum_read_bytes = _uint(
            maximum_read_bytes, "prepared bootstrap Source byte ceiling", positive=True,
        )
        self._deadline_ns = deadline_ns
        self._cancel_event = cancel_event
        _require(deadline_ns is None or
                 (type(deadline_ns) is int and deadline_ns > 0),
                 "prepared bootstrap deadline is malformed")
        _require(cancel_event is None or
                 callable(getattr(cancel_event, "is_set", None)),
                 "prepared bootstrap cancellation token is malformed")
        _require(self._maximum_read_bytes <= PREPARED_CAPTURE_BOOTSTRAP_MAX_BYTES,
                 "selected Source capture algorithms exceed the fixed bootstrap envelope")
        self._closed = True
        self._root_fd = -1
        self._uid = os.geteuid()
        self._root_device = -1
        self._root_identity: tuple[int, int] | None = None
        self._root_chain: tuple[tuple[int, int], ...] = ()
        self._objects: dict[tuple[str, str], dict[str, Any]] = {}
        self._file_identity: dict[str, tuple[int, int, int, int, int]] = {}
        self._directory_identity: dict[str, tuple[int, int]] = {}
        items = _exact(manifest, {"schema", "objects"},
                       "prepared bootstrap capture manifest")
        _require(items["schema"] == PREPARED_CAPTURE_MANIFEST_SCHEMA and
                 type(items["objects"]) is list and
                 0 < len(items["objects"]) <= MAX_ROWS,
                 "prepared bootstrap manifest schema/cardinality differs")
        local_paths: set[str] = set()
        for index, item_value in enumerate(items["objects"]):
            self._check_window("while validating capture-manifest rows")
            item = _exact(item_value, {
                "origin_pin", "local_relative_path", "byte_count",
            }, f"prepared bootstrap object[{index}]")
            pin = _pin_raw(item["origin_pin"],
                           f"prepared bootstrap origin[{index}]")
            local = capture_module["_relative_local"](
                item["local_relative_path"],
            )
            count = _uint(item["byte_count"],
                          f"prepared bootstrap byte count[{index}]", positive=True)
            _require(count <= self._maximum_read_bytes,
                     "prepared capture object exceeds the Source bootstrap envelope")
            key = (pin["path"], pin["raw_sha256"])
            _require(key not in self._objects and local not in local_paths,
                     "prepared capture manifest repeats a pin or local path")
            local_paths.add(local)
            self._objects[key] = {
                "origin_pin": pin, "local_relative_path": local,
                "byte_count": count,
            }
        open_directory = capture_module["_open_absolute_directory"]
        self._root_fd, self._root_chain = open_directory(self._stage_root)
        self._closed = False
        try:
            root_info = os.fstat(self._root_fd)
            self._root_device = root_info.st_dev
            self._require_private_directory(root_info, "capture root")
            self._root_identity = (root_info.st_dev, root_info.st_ino)
            self._scan_metadata()
        except BaseException:
            self.close()
            raise

    def _require_private_directory(self, info: os.stat_result, label: str) -> None:
        _require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and
                 info.st_uid == self._uid and info.st_dev == self._root_device,
                 f"{label} is not a private same-device mode-0700 directory")

    def _check_window(self, label: str) -> None:
        _require(self._cancel_event is None or
                 not self._cancel_event.is_set(),
                 f"prepared capture was cancelled {label}")
        _require(self._deadline_ns is None or
                 time.monotonic_ns() < self._deadline_ns,
                 f"prepared capture exceeded its finite window {label}")

    def _open_root_checked(self) -> int:
        self._check_window("while reopening the capture root")
        _require(not self._closed, "prepared bootstrap reader is closed")
        fd, chain = self._capture_module["_open_absolute_directory"](
            self._stage_root,
        )
        try:
            info = os.fstat(fd)
            self._require_private_directory(info, "capture root")
            _require(chain == self._root_chain and
                     (info.st_dev, info.st_ino) == self._root_identity,
                     "prepared capture root or ancestor changed")
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _open_local_parent(self, root_fd: int, relative: str) -> tuple[int, str]:
        parts = relative.split("/")
        _require(parts and all(part not in ("", ".", "..") for part in parts),
                 "prepared bootstrap path is not normalized")
        current = os.dup(root_fd)
        prefix: list[str] = []
        try:
            for component in parts[:-1]:
                prefix.append(component)
                child = os.open(
                    component, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW,
                    dir_fd=current,
                )
                try:
                    info = os.fstat(child)
                    name = "/".join(prefix)
                    self._require_private_directory(info, "capture subdirectory")
                    _require(self._directory_identity.get(name) ==
                             (info.st_dev, info.st_ino),
                             "prepared capture directory changed after custody scan")
                except BaseException:
                    os.close(child)
                    raise
                os.close(current)
                current = child
            return current, parts[-1]
        except BaseException:
            os.close(current)
            raise

    def _scan_metadata(self) -> None:
        expected_paths = {
            row["local_relative_path"]: (key, row)
            for key, row in self._objects.items()
        }
        expected_dirs = {
            "/".join(parts[:index])
            for relative in expected_paths
            for parts in [relative.split("/")]
            for index in range(1, len(parts))
        }
        expected_children: dict[str, set[str]] = {"": set()}
        for relative in expected_dirs | set(expected_paths):
            parent, _, leaf = relative.rpartition("/")
            expected_children.setdefault(parent, set()).add(leaf)
        root_fd = os.dup(self._root_fd)
        pending = [""]
        seen_files: set[str] = set()
        seen_dirs: set[str] = set()
        inode_ids = {self._root_identity}
        try:
            while pending:
                self._check_window("while scanning its closed tree")
                prefix = pending.pop()
                if prefix:
                    directory_fd, _leaf = self._open_local_parent(
                        root_fd, prefix + "/.bootstrap-sentinel",
                    )
                else:
                    directory_fd = os.dup(root_fd)
                try:
                    allowed = expected_children.get(prefix, set())
                    observed: set[str] = set()
                    with os.scandir(directory_fd) as entries:
                        for entry in entries:
                            self._check_window("while scanning directory entries")
                            name = entry.name
                            _require(name in allowed and name not in observed,
                                     "capture tree contains an undeclared entry")
                            observed.add(name)
                            relative = name if not prefix else prefix + "/" + name
                            info = os.stat(name, dir_fd=directory_fd,
                                           follow_symlinks=False)
                            identity = (info.st_dev, info.st_ino)
                            _require(info.st_dev == self._root_device and
                                     identity not in inode_ids,
                                     "capture tree crosses a device or aliases an inode")
                            inode_ids.add(identity)
                            if relative in expected_dirs:
                                self._require_private_directory(info,
                                                                "capture subdirectory")
                                self._directory_identity[relative] = identity
                                child = os.open(
                                    name,
                                    os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW,
                                    dir_fd=directory_fd,
                                )
                                try:
                                    opened = os.fstat(child)
                                    self._require_private_directory(
                                        opened, "capture subdirectory",
                                    )
                                    _require((opened.st_dev, opened.st_ino) == identity,
                                             "capture directory changed while opening")
                                finally:
                                    os.close(child)
                                seen_dirs.add(relative)
                                pending.append(relative)
                            else:
                                _require(relative in expected_paths and
                                         stat.S_ISREG(info.st_mode) and
                                         stat.S_IMODE(info.st_mode) == 0o400 and
                                         info.st_uid == self._uid and info.st_nlink == 1,
                                         "capture tree contains a non-private file or special object")
                                _key, captured = expected_paths[relative]
                                _require(info.st_size == captured["byte_count"] <=
                                         self._maximum_read_bytes,
                                         "captured metadata size exceeds its bounded declaration")
                                self._file_identity[relative] = (
                                    info.st_dev, info.st_ino, info.st_size,
                                    info.st_mtime_ns, info.st_ctime_ns,
                                )
                                seen_files.add(relative)
                    _require(observed == allowed,
                             "capture directory omits a declared child")
                finally:
                    os.close(directory_fd)
            _require(seen_files == set(expected_paths) and
                     seen_dirs == expected_dirs and
                     len(inode_ids) == 1 + len(seen_files) + len(seen_dirs),
                     "capture metadata tree does not close over its exact manifest")
            check_fd = self._open_root_checked()
            os.close(check_fd)
        finally:
            os.close(root_fd)

    def read(self, pin_value: object, maximum_bytes: int) -> bytes:
        self._check_window("before a captured read")
        pin = _pin_raw(pin_value, "prepared bootstrap read pin")
        key = (pin["path"], pin["raw_sha256"])
        captured = self._objects.get(key)
        _require(captured is not None,
                 "prepared bootstrap reader refuses an uncaptured origin")
        _require(type(maximum_bytes) is int and 0 < maximum_bytes <=
                 self._maximum_read_bytes and
                 captured["byte_count"] <= maximum_bytes,
                 "prepared bootstrap read exceeds its Source-derived byte cap")
        relative = captured["local_relative_path"]
        root_fd = self._open_root_checked()
        parent_fd = -1
        descriptor = -1
        try:
            parent_fd, leaf = self._open_local_parent(root_fd, relative)
            before_path = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            expected_identity = self._file_identity[relative]
            before_identity = (before_path.st_dev, before_path.st_ino,
                              before_path.st_size, before_path.st_mtime_ns,
                              before_path.st_ctime_ns)
            _require(before_identity == expected_identity and
                     stat.S_ISREG(before_path.st_mode) and
                     stat.S_IMODE(before_path.st_mode) == 0o400 and
                     before_path.st_uid == self._uid and before_path.st_nlink == 1 and
                     before_path.st_dev == self._root_device and
                     before_path.st_size <= maximum_bytes,
                     "prepared captured file changed or exceeds its requested cap")
            descriptor = os.open(
                leaf, os.O_RDONLY | _O_NOFOLLOW | _O_CLOEXEC | _O_NONBLOCK,
                dir_fd=parent_fd,
            )
            before = os.fstat(descriptor)
            _require((before.st_dev, before.st_ino, before.st_size,
                      before.st_mtime_ns, before.st_ctime_ns) == expected_identity and
                     stat.S_ISREG(before.st_mode) and
                     stat.S_IMODE(before.st_mode) == 0o400 and
                     before.st_uid == self._uid and before.st_nlink == 1,
                     "prepared captured file changed while opening")
            count = captured["byte_count"]
            output = bytearray(count)
            hasher = hashlib.sha256()
            offset = 0
            while offset < count:
                self._check_window("while reading a captured object")
                block = os.read(descriptor, min(COPY_BLOCK_BYTES, count - offset))
                _require(bool(block), "prepared captured file ended before its manifest size")
                output[offset:offset + len(block)] = block
                hasher.update(block)
                offset += len(block)
            _require(os.read(descriptor, 1) == b"" and
                     hasher.hexdigest() == pin["raw_sha256"],
                     "prepared captured bytes differ from their exact raw pin")
            after = os.fstat(descriptor)
            after_path = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            _require((after.st_dev, after.st_ino, after.st_size,
                      after.st_mtime_ns, after.st_ctime_ns) == expected_identity and
                     (after_path.st_dev, after_path.st_ino, after_path.st_size,
                      after_path.st_mtime_ns, after_path.st_ctime_ns) == expected_identity and
                     stat.S_IMODE(after.st_mode) == 0o400 and
                     after.st_uid == self._uid and after.st_nlink == 1,
                     "prepared captured file changed during its bounded read")
            current_root = self._open_root_checked()
            current_parent, current_leaf = self._open_local_parent(current_root, relative)
            try:
                current_info = os.fstat(current_parent)
                held_info = os.fstat(parent_fd)
                current_path = os.stat(current_leaf, dir_fd=current_parent,
                                       follow_symlinks=False)
                _require((current_info.st_dev, current_info.st_ino) ==
                         (held_info.st_dev, held_info.st_ino) and
                         (current_path.st_dev, current_path.st_ino) ==
                         (after.st_dev, after.st_ino),
                         "prepared captured file left its private tree during read")
            finally:
                os.close(current_parent)
                os.close(current_root)
            return bytes(output)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if parent_fd >= 0:
                os.close(parent_fd)
            os.close(root_fd)

    def __call__(self, pin_value: object, maximum_bytes: int) -> bytes:
        return self.read(pin_value, maximum_bytes)

    def close(self) -> None:
        if not self._closed:
            os.close(self._root_fd)
            self._root_fd = -1
            self._closed = True


def _prepared_bootstrap_capture_reader(
    capture_module: dict[str, Any], capture_manifest_raw: bytes,
    stage_root: str, host_ids: list[str], maximum_read_bytes: int, *,
    deadline_ns: int | None = None, cancel_event=None,
) -> tuple[Any, dict[str, Any]]:
    _require(type(capture_manifest_raw) is bytes and
             len(capture_manifest_raw) <= PREPARED_CAPTURE_MANIFEST_MAX_BYTES,
             "prepared lineage capture manifest exceeds its finite Source bound")
    manifest = _parse_canonical(
        capture_manifest_raw, "prepared lineage capture manifest",
        maximum_bytes=PREPARED_CAPTURE_MANIFEST_MAX_BYTES,
    )
    _exact(manifest, {"schema", "objects"},
           "prepared lineage capture manifest")
    _require(manifest["schema"] == PREPARED_CAPTURE_MANIFEST_SCHEMA and
             type(manifest["objects"]) is list and
             0 < len(manifest["objects"]) <= MAX_ROWS,
             "prepared lineage capture manifest schema/cardinality differs")
    _require(manifest["schema"] == capture_module["CAPTURE_MANIFEST_SCHEMA"],
             "prepared capture manifest schema differs from selected Source")
    _require(type(host_ids) is list and len(host_ids) == 2 and
             len(set(host_ids)) == 2,
             "prepared bootstrap Source host order is malformed")
    _uint(maximum_read_bytes, "prepared bootstrap selected Source read ceiling",
          positive=True)
    _require(maximum_read_bytes <= PREPARED_CAPTURE_BOOTSTRAP_MAX_BYTES,
             "prepared Source role caps exceed the bootstrap envelope")
    seen_origins: set[tuple[str, str]] = set()
    for index, item_value in enumerate(manifest["objects"]):
        item = _exact(item_value, {
            "origin_pin", "local_relative_path", "byte_count",
        }, f"prepared capture manifest object[{index}]")
        pin = _pin_raw(item["origin_pin"],
                       f"prepared capture manifest origin[{index}]")
        key = (pin["path"], pin["raw_sha256"])
        _require(key not in seen_origins,
                 "prepared capture manifest repeats an origin pin")
        seen_origins.add(key)
        count = _uint(item["byte_count"],
                      f"prepared capture manifest byte count[{index}]", positive=True)
        _require(count <= maximum_read_bytes,
                 "prepared capture metadata exceeds every selected Source role cap")
        capture_module["_relative_local"](item["local_relative_path"])
    try:
        reader = _PreparedBootstrapCaptureReader(
            capture_module, manifest, stage_root, maximum_read_bytes,
            deadline_ns=deadline_ns, cancel_event=cancel_event,
        )
    except Exception as error:
        raise EvidenceArchiveError(
            f"prepared capture stage failed its metadata-only private custody scan: {error}",
        ) from error
    return reader, manifest


def _prepared_execution_manifest(
    raw: bytes, pin_value: object, budget: dict[str, Any],
    context: dict[str, Any], source_docs: dict[str, dict[str, Any]],
    selected_source_doc: dict[str, Any],
    source_pins: dict[str, dict[str, str]],
    plan_raw: bytes, spec_raw: bytes,
    journal_width_contract_raw: bytes,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    pin = _pin(pin_value, "prepared execution-manifest pin")
    _require(type(raw) is bytes and len(raw) <= MAX_PLAN_BYTES and
             _sha(raw) == pin["raw_sha256"],
             "prepared execution-manifest bytes differ from their raw pin")
    execution = _parse_canonical(
        raw, "prepared Source5 execution manifest", maximum_bytes=MAX_PLAN_BYTES,
    )
    base = {
        "schema", "campaign_id", "hosts", "original_inputs", "execution_sources",
        "modules", "observed_hosts", "capacity_completions", "artifact_root",
        "output_root", "phase_order", "protocol_sha256", "qualification_eligible",
        "manifest_sha256",
    }
    _exact(execution, (base - {"capacity_completions"}) | {
        "scope", "prepared_input_generation", "prepared_capacity_registration",
        "archive_signer_contexts", "journal_width_contracts",
    }, "prepared Source5 execution manifest V5")
    hosts = execution["hosts"]
    _require(type(hosts) is list and len(hosts) == 2 and
             all(type(host) is str and bool(host) for host in hosts) and
             len(set(hosts)) == 2 and set(hosts) == set(source_pins) and
             context["host_id"] in hosts and
             execution["schema"] == PREPARED_EXPLORATION_EXECUTION_SCHEMA and
             execution["scope"] == PREPARED_EXPLORATION_SCOPE and
             execution["campaign_id"] == context["campaign_id"] and
             execution["qualification_eligible"] is False and
             execution["manifest_sha256"] == pin["semantic_sha256"] ==
                 _sha(_canonical({key: value for key, value in execution.items()
                                  if key != "manifest_sha256"},
                                 maximum_bytes=MAX_PLAN_BYTES)),
             "prepared execution V5 identity, cohort, scope or semantic pin differs")
    original = _exact(execution["original_inputs"], {
        "spec", "plan", "source_manifests", "campaign_artifacts_root",
    }, "prepared execution original inputs")
    _absolute_path(original["campaign_artifacts_root"],
                   "prepared original campaign-artifact root")
    _absolute_path(execution["artifact_root"], "prepared execution artifact root")
    _absolute_path(execution["output_root"], "prepared execution output root")
    _digest(execution["protocol_sha256"], "prepared execution protocol digest")
    spec_pin = _pin(budget["original_pins"]["spec"],
                    "prepared final Spec pin")
    plan_pin = _pin(budget["original_pins"]["plan"],
                    "prepared final Plan pin")
    spec = _parse_canonical(spec_raw, "prepared final SpecV3",
                            maximum_bytes=PREPARATORY_MAX_SPEC_BYTES)
    plan = _parse_canonical(plan_raw, "prepared final PlanV3",
                            maximum_bytes=MAX_PLAN_BYTES)
    _require(type(spec_raw) is bytes and _sha(spec_raw) == spec_pin["raw_sha256"] and
             _sha(spec_raw) == spec_pin["semantic_sha256"] and
             type(plan_raw) is bytes and _sha(plan_raw) == plan_pin["raw_sha256"] and
             plan.get("plan_sha256") == plan_pin["semantic_sha256"] ==
                 _sha(_canonical({key: value for key, value in plan.items()
                                  if key != "plan_sha256"},
                                 maximum_bytes=MAX_PLAN_BYTES)) and
             spec.get("schema") == "allocatbelt.application-campaign-spec.v3" and
             plan.get("schema") == "allocatbelt.application-campaign-plan.v3" and
             spec.get("campaign_id") == plan.get("campaign_id") ==
                 context["campaign_id"],
             "prepared final Spec/Plan schema or raw/semantic pin differs")
    _require(type(spec.get("protocol")) is dict and
             execution["protocol_sha256"] == _sha(_canonical(spec["protocol"])),
             "prepared execution protocol digest differs from the exact final Spec")
    spec_hosts = spec.get("hosts")
    _require(type(spec_hosts) is list and len(spec_hosts) == len(hosts) and
             [row.get("host_id") for row in spec_hosts if type(row) is dict] == hosts,
             "prepared execution host order differs from the immutable final Spec")
    spec_host_by_id = {}
    for host, row in zip(hosts, spec_hosts, strict=True):
        _require(type(row) is dict and row.get("host_id") == host and
                 type(row.get("controls")) is dict,
                 f"prepared final Spec {host} host contract is malformed")
        fingerprint = _digest(
            row.get("host_fingerprint_sha256"),
            f"prepared final Spec {host} host fingerprint",
        )
        _require(fingerprint == _sha(_canonical(row["controls"])),
                 f"prepared final Spec {host} fingerprint differs from its controls")
        spec_host_by_id[host] = row
    spec_wrapper = _exact(original["spec"], {"artifact", "semantic_sha256"},
                          "prepared execution Spec wrapper")
    plan_wrapper = _exact(original["plan"], {"artifact", "semantic_sha256"},
                          "prepared execution Plan wrapper")
    _require(_pin({**_pin_raw(spec_wrapper["artifact"],
                             "prepared execution Spec artifact"),
                   "semantic_sha256": spec_wrapper["semantic_sha256"]},
                  "prepared execution Spec pin") == spec_pin and
             _pin({**_pin_raw(plan_wrapper["artifact"],
                             "prepared execution Plan artifact"),
                   "semantic_sha256": plan_wrapper["semantic_sha256"]},
                  "prepared execution Plan pin") == plan_pin,
             "prepared execution manifest changed its final Spec/Plan pins")
    source_wrappers = _exact(original["source_manifests"], set(hosts),
                             "prepared execution Source wrapper map")
    for host in hosts:
        wrapper = _exact(source_wrappers[host], {"artifact", "semantic_sha256"},
                         f"prepared execution {host} Source wrapper")
        wrapper_pin = _pin({**_pin_raw(wrapper["artifact"],
                                      f"prepared execution {host} Source artifact"),
                            "semantic_sha256": wrapper["semantic_sha256"]},
                           f"prepared execution {host} Source pin")
        _require(wrapper_pin == source_pins[host] and
                 source_docs[host]["manifest_sha256"] == wrapper_pin["semantic_sha256"],
                 f"prepared execution changed the {host} Source manifest pin")
    prepared_generation = _exact(execution["prepared_input_generation"], {
        "completion", "provenance",
    }, "prepared execution input generation")
    provenance = prepared_generation["provenance"]
    _require(type(provenance) is dict and
             provenance.get("schema") ==
                 "allocatbelt.application-source5-prepared-inputs-provenance.v2" and
             type(provenance.get("exploration_lineage")) is dict and
             set(provenance["exploration_lineage"]) == set(hosts) and
             provenance["exploration_lineage"] ==
                 budget["original_pins"]["prepared_exploration"],
             "prepared execution lineage provenance differs from the budget pins")
    registration = _exact(execution["prepared_capacity_registration"], {
        "completion", "host_completion", "host_verification", "ledger",
        "capacity_schedule_sha256", "registration_head",
    }, "prepared execution capacity registration")
    _pin(registration["completion"], "prepared capacity-generation completion")
    _digest(registration["capacity_schedule_sha256"],
            "prepared capacity schedule digest")
    _digest(registration["registration_head"],
            "prepared capacity registration head")
    signer_map = _exact(execution["archive_signer_contexts"], set(hosts),
                        "prepared execution signer-context map")
    width_map = _exact(execution["journal_width_contracts"], set(hosts),
                       "prepared execution width-contract map")
    observed_map = _exact(execution["observed_hosts"], set(hosts),
                          "prepared execution observed-host map")
    for host in hosts:
        signer_wrapper = _exact(signer_map[host], {"artifact", "semantic_sha256"},
                                f"prepared {host} signer-context wrapper")
        _pin({**_pin_raw(signer_wrapper["artifact"],
                         f"prepared {host} signer-context artifact"),
              "semantic_sha256": signer_wrapper["semantic_sha256"]},
             f"prepared {host} signer-context pin")
        current_width_wrapper = _exact(width_map[host], {
            "artifact", "semantic_sha256",
        }, f"prepared {host} width-contract wrapper")
        _pin({**_pin_raw(current_width_wrapper["artifact"],
                         f"prepared {host} width-contract artifact"),
              "semantic_sha256": current_width_wrapper["semantic_sha256"]},
             f"prepared {host} width-contract pin")
        observed_wrapper = _exact(observed_map[host], {
            "artifact", "host_fingerprint_sha256", "controls_sha256",
        }, f"prepared {host} observed-host wrapper")
        _pin_raw(observed_wrapper["artifact"],
                 f"prepared {host} observed-host artifact")
        fingerprint = _digest(
            observed_wrapper["host_fingerprint_sha256"],
            f"prepared {host} observed-host fingerprint",
        )
        controls_sha = _digest(
            observed_wrapper["controls_sha256"],
            f"prepared {host} observed-host controls digest",
        )
        _require(fingerprint == spec_host_by_id[host]["host_fingerprint_sha256"],
                 f"prepared {host} observed-host fingerprint differs from immutable final Spec")
    width_pin = _pin(budget["journal_width_contract_pin"],
                     "prepared current width-contract pin")
    width_wrapper = _exact(
        width_map[context["host_id"]],
        {"artifact", "semantic_sha256"},
        "prepared current width-contract wrapper",
    )
    _require(_pin({**_pin_raw(width_wrapper["artifact"],
                             "prepared current width artifact"),
                   "semantic_sha256": width_wrapper["semantic_sha256"]},
                  "prepared current execution width pin") == width_pin and
             type(journal_width_contract_raw) is bytes and
             _sha(journal_width_contract_raw) == width_pin["raw_sha256"],
             "prepared current width wrapper differs from its exact budget pin")
    width = _parse_canonical(
        journal_width_contract_raw, "prepared current width contract",
        maximum_bytes=PREPARATORY_MAX_WIDTH_BYTES,
    )
    module_maps = _exact(execution["modules"], set(hosts),
                         "prepared execution Source module maps")
    for host in hosts:
        modules = module_maps[host]
        source_files = source_docs[host]["source"]["files"]
        expected_paths = {
            row["path"] for row in source_files
            if type(row) is dict and row.get("kind") == "file" and
            type(row.get("path")) is str and row["path"].startswith("scripts/") and
            PurePosixPath(row["path"]).suffix in {".py", ".sh"}
        }
        _require(type(modules) is dict and set(modules) == expected_paths,
                 f"prepared execution {host} module map differs from its pinned Source inventory")
        file_rows = {row["path"]: row for row in source_files
                     if type(row) is dict and type(row.get("path")) is str}
        selected_paths = expected_paths
        for module_path in selected_paths:
            _require(type(module_path) is str and module_path.startswith("scripts/"),
                     f"prepared execution {host} module path is malformed")
            module_pin = _exact(modules[module_path], {"path", "sha256"},
                                f"prepared execution {host} module pin")
            _require(module_pin["path"] == module_path,
                     f"prepared execution {host} module path differs at {module_path}")
            _digest(module_pin["sha256"],
                    f"prepared execution {host} module digest {module_path}")
            row = file_rows[module_path]
            _require(module_pin["sha256"] == row["sha256"],
                     f"prepared execution {host} module map differs at {module_path}")
    source_roots = _exact(execution["execution_sources"], set(hosts),
                          "prepared execution source/build map")
    for host in hosts:
        root_row = _exact(source_roots[host], {
            "source_root", "git_commit", "source_tree_sha256", "build_sha256",
        }, f"prepared execution {host} source/build row")
        _absolute_path(root_row["source_root"],
                       f"prepared execution {host} Source root")
        _digest(root_row["source_tree_sha256"],
                f"prepared execution {host} source-tree digest")
        _digest(root_row["build_sha256"],
                f"prepared execution {host} build digest")
        _require(type(root_row["git_commit"]) is str and
                 bool(root_row["git_commit"]),
                 f"prepared execution {host} Git identity is malformed")
        source = source_docs[host]
        build = source.get("build")
        calibration = source.get("resource_domain_calibration")
        _require(type(build) is dict and type(calibration) is dict,
                 f"prepared {host} Source build calibration is malformed")
        build_sha = _sha(_canonical(build,
                                    maximum_bytes=MAX_SOURCE_MANIFEST_BYTES))
        _require(root_row["git_commit"] == source["source"].get("git_commit") and
                 root_row["source_tree_sha256"] ==
                     source["source"]["source_tree_sha256"] and
                 root_row["build_sha256"] == build_sha and
                 calibration.get("build") == build and
                 calibration.get("build_sha256") == build_sha,
                 f"prepared execution {host} Source/build snapshot differs")
    _require(selected_source_doc["source"]["source_tree_sha256"] ==
             budget["original_pins"]["source_tree_sha256"],
             "prepared budget Source-tree pin differs from the current selected Source")
    source_root = Path(os.path.abspath(globals()["__file__"])).parent.parent
    _require(source_roots[context["host_id"]]["source_root"] ==
             str(source_root.resolve(strict=True)),
             "prepared selected Source root differs from the resident Archive tree")
    _require(type(execution["phase_order"]) is list and
             execution["phase_order"] == [
                 "exploration", "aa", "confirmation", "fixed_analysis",
                 "pressure", "pressure_analysis", "soak", "final_analysis",
             ],
             "prepared execution phase order differs from Source5 V5")
    return execution, spec, plan, width


def _prepared_observed_host_dto(
    execution: dict[str, Any], spec: dict[str, Any], host: str,
    read_lineage: Any, maximum_bytes: int,
) -> dict[str, Any]:
    """Join one canonical captured observation to its exact Spec host contract."""
    wrapper = _exact(execution["observed_hosts"][host], {
        "artifact", "host_fingerprint_sha256", "controls_sha256",
    }, f"prepared {host} observed-host wrapper")
    pin = _pin_raw(wrapper["artifact"],
                   f"prepared {host} observed-host artifact")
    host_rows = [row for row in spec.get("hosts", [])
                 if type(row) is dict and row.get("host_id") == host]
    _require(len(host_rows) == 1,
             f"prepared {host} immutable Spec host row is missing or repeated")
    host_spec = host_rows[0]
    fingerprint = _digest(
        wrapper["host_fingerprint_sha256"],
        f"prepared {host} observed-host fingerprint",
    )
    controls_sha = _digest(
        wrapper["controls_sha256"],
        f"prepared {host} observed-host controls digest",
    )
    _require(fingerprint == host_spec.get("host_fingerprint_sha256") and
             type(host_spec.get("controls")) is dict and
             fingerprint == _sha(_canonical(host_spec["controls"])),
             f"prepared {host} observed-host fingerprint differs from immutable final Spec")
    try:
        observed_raw = read_lineage(pin, maximum_bytes)
        value = _parse_canonical(
            observed_raw, f"captured prepared {host} observed-host input",
            maximum_bytes=maximum_bytes,
        )
    except Exception as error:
        raise EvidenceArchiveError(
            f"captured prepared {host} observed-host input failed Source checks: {error}",
        ) from error
    observed = _exact(value, {
        "schema", "host_id", "boot_id_sha256", "controls_sha256", "controls",
        "kernel_release", "cpu_model", "cpu_affinity", "network_namespace_inode",
    }, f"captured prepared {host} observed-host DTO")
    _require(_sha(observed_raw) == pin["raw_sha256"] and
             observed["schema"] == "allocatbelt.application-capacity-host-context.v1" and
             observed["host_id"] == host and
             _digest(observed["boot_id_sha256"],
                     f"prepared {host} observed boot ID") and
             type(observed["controls"]) is dict and
             observed["controls"] == host_spec["controls"] and
             observed["controls_sha256"] == controls_sha ==
                 _sha(_canonical(observed["controls"])) and
             observed["kernel_release"] ==
                 host_spec["controls"].get("kernel_release") and
             observed["cpu_model"] == host_spec["controls"].get("cpu_model"),
             f"current prepared {host} observed-host bytes differ from their raw/control pins")
    return {
        "pin": pin, "raw": observed_raw, "value": observed,
        "dto": {
            "path": pin["path"], "raw_sha256": pin["raw_sha256"],
            "boot_id_sha256": observed["boot_id_sha256"],
            "controls_sha256": observed["controls_sha256"],
        },
    }


def _prepared_lineage_closure(
    budget: dict[str, Any], context: dict[str, Any],
    source_manifest_raw: bytes, execution_manifest_raw: bytes,
    plan_raw: bytes, spec_raw: bytes, width_raw: bytes,
    capture_manifest_raw: bytes, capture_stage_root: str,
) -> tuple[Any, dict[str, Any], list[dict[str, Any]], dict[str, Any],
           dict[str, Any], dict[str, Any]]:
    primary_context, _pins = _prepared_exploration_primary_context(
        budget, context["resource_budget_pin"],
    )
    _require(all(context[name] == primary_context[name] for name in (
        "campaign_id", "host_id", "source_manifest_pin", "plan_pin",
        "resource_budget_pin", "execution_manifest_pin",
    )), "prepared V5 full request context differs from its selected six-pin projection")
    source_pins = {
        host: _pin(value, f"prepared {host} Source manifest pin")
        for host, value in budget["original_pins"]["source_manifests"].items()
    }
    source_docs: dict[str, dict[str, Any]] = {}
    modules = {
        "evidence_budget": _prepared_typed_module(
            source_manifest_raw, execution_manifest_raw, primary_context,
            SOURCE5_BUDGET_VALIDATOR_PATH,
        ),
        "lineage": _prepared_typed_module(
            source_manifest_raw, execution_manifest_raw, primary_context,
            PREPARED_LINEAGE_SOURCE_PATH,
        ),
        "bridge": _prepared_typed_module(
            source_manifest_raw, execution_manifest_raw, primary_context,
            PREPARED_BRIDGE_BUDGET_SOURCE_PATH,
        ),
        "source5_campaign": _prepared_typed_module(
            source_manifest_raw, execution_manifest_raw, primary_context,
            PREPARED_CAMPAIGN_SOURCE_PATH,
        ),
        "input_preparation": _prepared_typed_module(
            source_manifest_raw, execution_manifest_raw, primary_context,
            PREPARED_INPUT_PREPARATION_SOURCE_PATH,
        ),
        "campaign_inputs": _prepared_typed_module(
            source_manifest_raw, execution_manifest_raw, primary_context,
            PREPARED_CAMPAIGN_INPUTS_SOURCE_PATH,
        ),
        "chronology": _prepared_typed_module(
            source_manifest_raw, execution_manifest_raw, primary_context,
            PREPARED_CHRONOLOGY_SOURCE_PATH,
        ),
        "controller": _prepared_typed_module(
            source_manifest_raw, execution_manifest_raw, primary_context,
            PREPARED_CONTROLLER_SOURCE_PATH,
        ),
        "preparatory_budget": _prepared_typed_module(
            source_manifest_raw, execution_manifest_raw, primary_context,
            PREPARATORY_BUDGET_VALIDATOR_PATH,
        ),
        "capture": _prepared_typed_module(
            source_manifest_raw, execution_manifest_raw, primary_context,
            PREPARED_CAPTURE_SOURCE_PATH,
        ),
    }
    required_apis = {
        "evidence_budget": (
            "validate_host_evidence_budget_v4",
            "required_archive_request_schema_v1",
            "iter_path_catalogue_rows_with_reader",
            "verify_prepared_source5_path_catalogue_chunks_with_reader",
            "_catalogue_row",
        ),
        "lineage": ("verify_source5_prepared_exploration_lineage_v2",),
        "bridge": (
            "build_prepared_exploration_capture_storage_v1",
            "validate_prepared_exploration_width_contract_v2",
        ),
        "source5_campaign": ("build_source5_original_pins_from_observed_v1",),
        "chronology": ("_validate_chronology_original_pins",),
        "controller": ("digest_object",),
        "capture": ("PreparedExplorationLineageCaptureReaderV1",),
    }
    for module_name, api_names in required_apis.items():
        _require(all(callable(modules[module_name].get(name))
                     for name in api_names),
                 f"typed Source {module_name} module lacks a required V5 API")
    budget_module = modules["evidence_budget"]
    _require(budget_module.get("HOST_BUDGET_SCHEMA_V4") == HOST_BUDGET_SCHEMA_V4 and
             budget_module.get("SOURCE5_PREPARED_EXPLORATION_ADMISSION_PROFILE") ==
                 PREPARED_EXPLORATION_ADMISSION_PROFILE and
             budget_module.get("EXECUTION_SCHEMA_V5") ==
                 PREPARED_EXPLORATION_EXECUTION_SCHEMA,
             "typed Source budget module lacks the exact V4/V5 metadata profile")
    maximums = (
        modules["source5_campaign"].get("MAX_ARTIFACT_BYTES"),
        modules["lineage"].get("MAX_PLAN_BYTES"),
        modules["lineage"].get("MAX_SPEC_BYTES"),
        modules["lineage"].get("MAX_RECORD_BYTES"),
        modules["lineage"].get("MAX_CHECKPOINT_BYTES"),
        modules["lineage"].get("MAX_METADATA_BYTES"),
        modules["lineage"].get("MAX_SIGNATURE_BYTES"),
        modules["chronology"].get("MAX_JOURNAL_BYTES"),
        modules["chronology"].get("MAX_EVENT_BYTES"),
    )
    _require(all(type(value) is int and 0 < value <=
                 PREPARED_CAPTURE_BOOTSTRAP_MAX_BYTES for value in maximums),
             "selected Source historical artifact caps exceed the bootstrap envelope")
    bootstrap_maximum = max(maximums)
    capture_module = modules["capture"]
    bootstrap, capture_manifest = _prepared_bootstrap_capture_reader(
        capture_module, capture_manifest_raw, capture_stage_root,
        list(source_pins), bootstrap_maximum,
    )
    final_reader = None
    try:
        selected_source_doc = _prepared_source_document(
            source_manifest_raw, source_pins[context["host_id"]],
            "selected current",
        )
        for host in source_pins:
            try:
                raw = bootstrap.read(
                    {"path": source_pins[host]["path"],
                     "raw_sha256": source_pins[host]["raw_sha256"]},
                    MAX_SOURCE_MANIFEST_BYTES,
                )
            except Exception as error:
                raise EvidenceArchiveError(
                    f"historical Source manifest {host} is absent from its private capture",
                ) from error
            source_docs[host] = _prepared_source_document(
                raw, source_pins[host], f"prepared {host}",
            )
        execution, spec, plan, width = _prepared_execution_manifest(
            execution_manifest_raw,
            budget["original_pins"]["execution_manifest"],
            budget, context, source_docs, selected_source_doc, source_pins,
            plan_raw, spec_raw, width_raw,
        )

        final_spec_pin = _pin(budget["original_pins"]["spec"],
                              "prepared final Spec")
        final_plan_pin = _pin(budget["original_pins"]["plan"],
                              "prepared final Plan")
        source_objects = {
            name: sys.modules[namespace["__name__"]]
            for name, namespace in modules.items()
        }

        def read_lineage(pin_value: dict[str, str], maximum: int) -> bytes:
            pin = _pin_raw(pin_value, "prepared lineage read pin")
            if pin == {"path": final_spec_pin["path"],
                       "raw_sha256": final_spec_pin["raw_sha256"]}:
                raw = spec_raw
            elif pin == {"path": final_plan_pin["path"],
                         "raw_sha256": final_plan_pin["raw_sha256"]}:
                raw = plan_raw
            else:
                raw = bootstrap.read(pin, maximum)
            _require(type(raw) is bytes and 0 < len(raw) <= maximum and
                     _sha(raw) == pin["raw_sha256"],
                     "prepared Source reader returned bytes outside the requested raw pin/cap")
            return raw

        source_rows = []
        for host in execution["hosts"]:
            source = source_docs[host]
            pin = source_pins[host]
            source_rows.append({
                "host_id": host, "path": pin["path"],
                "raw_sha256": pin["raw_sha256"],
                "semantic_sha256": pin["semantic_sha256"],
                "source_tree_sha256": source["source"]["source_tree_sha256"],
            })
        observed_by_host: dict[str, dict[str, Any]] = {}
        original_pin_dtos: dict[str, dict[str, Any]] = {}
        for host in execution["hosts"]:
            joined_observed = _prepared_observed_host_dto(
                execution, spec, host, read_lineage,
                modules["source5_campaign"]["MAX_ARTIFACT_BYTES"],
            )
            pin = joined_observed["pin"]
            observed_raw = joined_observed["raw"]
            value = joined_observed["value"]
            observed_by_host[host] = joined_observed["dto"]
            observed_context = types.SimpleNamespace(
                observed_host_pin=pin, manifest=execution, host_id=host,
                chronology=source_objects["chronology"],
                spec_pin=final_spec_pin,
                spec_semantic_sha256=final_spec_pin["semantic_sha256"],
                plan_pin=final_plan_pin,
                plan_semantic_sha256=final_plan_pin["semantic_sha256"],
                source_manifest_pins=source_pins, sources=source_docs,
            )
            try:
                dto = source_objects[
                    "source5_campaign"
                ].build_source5_original_pins_from_observed_v1(
                    observed_context, value, _sha(observed_raw),
                )
                source_objects["chronology"]._validate_chronology_original_pins(dto)
            except Exception as error:
                raise EvidenceArchiveError(
                    f"typed Source chronology rejected captured {host} observation: {error}",
                ) from error
            original_pin_dtos[host] = dto
        proofs: dict[str, dict[str, Any]] = {}
        for host in execution["hosts"]:
            final_prepared = {
                "campaign_id": context["campaign_id"], "host_id": host,
                "output_root": execution["output_root"],
                "original_pins": {
                    "spec": final_spec_pin, "plan": final_plan_pin,
                    "source_manifests": source_rows,
                    "observed_host": observed_by_host[host],
                },
            }
            try:
                proof = source_objects["lineage"].verify_source5_prepared_exploration_lineage_v2(
                    final_prepared,
                    budget["original_pins"]["prepared_exploration"][host],
                    artifact_reader=read_lineage,
                    campaign_module=source_objects["controller"],
                    input_preparation_module=source_objects["input_preparation"],
                    campaign_inputs_module=source_objects["campaign_inputs"],
                    chronology_module=source_objects["chronology"],
                    source5_campaign_module=source_objects["source5_campaign"],
                    preparatory_budget_module=source_objects["preparatory_budget"],
                )
            except Exception as error:
                raise EvidenceArchiveError(
                    f"typed Source lineage verifier rejected {host}: {error}",
                ) from error
            _require(type(proof) is dict and
                     proof.get("schema") ==
                         "allocatbelt.application-source5-prepared-exploration-lineage-proof.v2" and
                     proof.get("campaign_id") == context["campaign_id"] and
                     proof.get("host_id") == host and
                     proof.get("qualification_eligible") is False and
                     proof.get("component_replay_required") is True and
                     type(proof.get("index_rows")) is list and
                     len(proof["index_rows"]) == 360,
                     f"typed Source lineage proof for {host} is incomplete or authorizing")
            proofs[host] = proof
        expected_ancestors = {host: proofs[host]["ancestor"]
                              for host in execution["hosts"]}
        jobs_by_host = {
            host: [job for job in plan["jobs"]["exploration"]
                   if type(job) is dict and job.get("host_id") == host]
            for host in execution["hosts"]
        }
        budget_module_object = source_objects["evidence_budget"]
        try:
            declaration, storage_rows = source_objects[
                "bridge"
            ].build_prepared_exploration_capture_storage_v1(
                execution["hosts"], proofs,
                expected_ancestors=expected_ancestors,
                expected_exploration_jobs=jobs_by_host,
                artifact_reader=read_lineage,
                evidence_budget_module=budget_module_object,
            )
        except Exception as error:
            raise EvidenceArchiveError(
                f"typed Source capture-declaration builder rejected lineage closure: {error}",
            ) from error
        storage_rows = [budget_module["_catalogue_row"](
            row, f"prepared captured lineage storage row[{index}]",
        ) for index, row in enumerate(storage_rows)]
        _require(declaration.get("cohort_host_ids") == execution["hosts"] and
                 len(storage_rows) == len(declaration.get("objects", [])),
                 "typed Source capture declaration does not close over its storage rows")
        selected_host = context["host_id"]
        try:
            original_width_pins = original_pin_dtos[selected_host]
            selected_jobs = {
                phase: [job for job in plan["jobs"][phase]
                        if type(job) is dict and job.get("host_id") == selected_host]
                for phase in ("exploration", "aa", "confirmation", "pressure", "soak")
            }
            checked_width, width_events, max_line = source_objects[
                "bridge"
            ].validate_prepared_exploration_width_contract_v2(
                width, jobs_by_phase=selected_jobs,
                expected_campaign_id=context["campaign_id"],
                expected_host_id=selected_host,
                expected_original_pins_sha256=_sha(_canonical(original_width_pins)),
                expected_plan_pin=_pin(budget["original_pins"]["plan"],
                                        "prepared width Plan pin"),
                expected_source_manifest_pin=source_pins[selected_host],
                expected_ancestor=proofs[selected_host]["ancestor"],
            )
        except Exception as error:
            raise EvidenceArchiveError(
                f"typed Source width validator rejected the current V5 horizon: {error}",
            ) from error
        _require(checked_width == width and width_events == 97499 and max_line > 0,
                 "typed Source width validator returned a changed current horizon")
        _require(all(
            _uint(row["maximum_bytes"],
                  "derived prepared capture role cap", positive=True) <= bootstrap_maximum and
            _uint(row["byte_count"],
                  "derived prepared capture byte count", positive=True) <=
                  row["maximum_bytes"]
            for row in declaration["objects"]
        ), "derived prepared capture exceeds the Source bootstrap role envelope")
        captured_by_pin = {
            (item["origin_pin"]["path"], item["origin_pin"]["raw_sha256"]): item
            for item in capture_manifest["objects"]
        }
        expected_manifest_rows = []
        for row in declaration["objects"]:
            key = (row["origin_pin"]["path"], row["origin_pin"]["raw_sha256"])
            captured = captured_by_pin.get(key)
            _require(captured is not None,
                     "derived prepared capture object is absent from its transport manifest")
            expected_manifest_rows.append({
                "origin_pin": row["origin_pin"],
                "local_relative_path": captured["local_relative_path"],
                "byte_count": row["byte_count"],
            })
        _require(expected_manifest_rows == capture_manifest["objects"] and
                 len(expected_manifest_rows) == len(declaration["objects"]),
                 "private capture manifest differs from the full freshly derived Source closure")
    finally:
        bootstrap.close()
    try:
        final_reader = capture_module["PreparedExplorationLineageCaptureReaderV1"](
            declaration, capture_manifest, capture_stage_root,
        )
    except Exception as error:
        raise EvidenceArchiveError(
            f"derived prepared capture reader failed its exact physical closure: {error}",
        ) from error
    return (final_reader, declaration, storage_rows, execution, width,
            source_objects["evidence_budget"])


def _recorded_pre_manifest_source_closure(
    basis: dict[str, Any], basis_pin: dict[str, Any],
    selected_source_manifest_raw: bytes,
    capture_manifest_raw: bytes, capture_stage_root: str,
    source_root_value: str, final_plan_module: object, *,
    deadline_ns: int | None = None, cancel_event=None,
) -> dict[str, Any]:
    """Rebuild the actual SourceV2/Bridge capture graph before one read.

    The final execution manifest is intentionally absent. The selected current
    Source inventory in the cyclic-free basis pins each resident module. Peer
    Source manifests and bridge/index data are read from the closed capture;
    this helper never opens a peer Source tree or ELF.
    """
    basis_hosts = basis["cohort_hosts"]
    consumer = basis["consumer_host_id"]
    source_pins = {
        host: _pin(basis["source_manifest_pins"][host],
                   f"recorded-read {host} Source manifest pin")
        for host in basis_hosts
    }
    selected_pin = source_pins[consumer]
    source_root = Path(_absolute_path(
        source_root_value, "recorded-read selected Source root",
    ))
    _require(source_root == Path(basis["current_roots"]["source_root"]) and
             source_root.resolve(strict=True) == source_root,
             "recorded-read source root differs from the current selected basis root")
    archive_code_root = Path(os.path.abspath(globals()["__file__"]))
    archive_code_root = archive_code_root.parent.parent.resolve(strict=True)
    _require(archive_code_root == source_root,
             "Root recorded-read verifier is not executing from the selected Source root")
    module_pins = basis["source_module_pins"][consumer]
    namespaces: dict[str, dict[str, Any]] = {}
    for name, path in (
        ("evidence_budget", SOURCE5_BUDGET_VALIDATOR_PATH),
        ("lineage", PREPARED_LINEAGE_SOURCE_PATH),
        ("bridge", PREPARED_BRIDGE_BUDGET_SOURCE_PATH),
        ("source5_campaign", PREPARED_CAMPAIGN_SOURCE_PATH),
        ("input_preparation", PREPARED_INPUT_PREPARATION_SOURCE_PATH),
        ("campaign_inputs", PREPARED_CAMPAIGN_INPUTS_SOURCE_PATH),
        ("chronology", PREPARED_CHRONOLOGY_SOURCE_PATH),
        ("controller", PREPARED_CONTROLLER_SOURCE_PATH),
        ("preparatory_budget", PREPARATORY_BUDGET_VALIDATOR_PATH),
        ("capture", PREPARED_CAPTURE_SOURCE_PATH),
    ):
        namespaces[name] = _recorded_pre_manifest_typed_module(
            selected_source_manifest_raw, selected_pin, module_pins,
            path, source_root, source_root,
            namespace_name="_allocatbelt_recorded_pre_manifest_" + name,
        )
    objects = {
        name: sys.modules[namespace["__name__"]]
        for name, namespace in namespaces.items()
    }
    required_apis = {
        "evidence_budget": (
            "_catalogue_row", "iter_path_catalogue_rows_with_reader",
            "source5_indexed_reservation_binding_v1",
            "project_fixed_pair_archive_readback_caps",
        ),
        "lineage": ("verify_source5_prepared_exploration_lineage_v2",),
        "bridge": (
            "build_prepared_exploration_capture_storage_v1",
            "validate_prepared_exploration_width_contract_v2",
        ),
        "source5_campaign": ("build_source5_original_pins_from_observed_v1",),
        "chronology": ("_validate_chronology_original_pins",),
        "controller": ("digest_object",),
        "capture": ("PreparedExplorationLineageCaptureReaderV1",),
    }
    _require(all(callable(getattr(objects[module], api, None))
                 for module, apis in required_apis.items()
                 for api in apis),
             "selected Source lacks a required current prepared-input validator")
    _require(type(capture_manifest_raw) is bytes and
             _sha(capture_manifest_raw) ==
                 basis["metadata_capture_manifest_pin"]["raw_sha256"],
             "recorded-read capture manifest differs from its exact raw basis pin")
    bootstrap, capture_manifest = _prepared_bootstrap_capture_reader(
        namespaces["capture"], capture_manifest_raw, capture_stage_root,
        basis_hosts, PREPARED_CAPTURE_BOOTSTRAP_MAX_BYTES,
        deadline_ns=deadline_ns, cancel_event=cancel_event,
    )
    final_reader = None
    try:
        source_docs: dict[str, dict[str, Any]] = {}
        for host in basis_hosts:
            pin = source_pins[host]
            if host == consumer:
                raw = selected_source_manifest_raw
            else:
                raw = bootstrap.read({
                    "path": pin["path"], "raw_sha256": pin["raw_sha256"],
                }, MAX_SOURCE_MANIFEST_BYTES)
            source_docs[host] = _prepared_source_document(
                raw, pin, f"recorded-read {host}",
            )
        spec_pin = _pin(basis["spec_pin"],
                        "recorded-read final Spec pin")
        plan_pin = _pin(basis["plan_pin"],
                        "recorded-read final Plan pin")
        spec_raw = bootstrap.read({
            "path": spec_pin["path"], "raw_sha256": spec_pin["raw_sha256"],
        }, PREPARATORY_MAX_SPEC_BYTES)
        plan_raw = bootstrap.read({
            "path": plan_pin["path"], "raw_sha256": plan_pin["raw_sha256"],
        }, MAX_PLAN_BYTES)
        spec = _parse_canonical(spec_raw, "recorded-read final Spec",
                                maximum_bytes=PREPARATORY_MAX_SPEC_BYTES)
        source_plan = _parse_canonical(plan_raw, "recorded-read final Plan",
                                       maximum_bytes=MAX_PLAN_BYTES)
        _require(spec.get("campaign_id") == basis["campaign_id"] and
                 _sha(spec_raw) == spec_pin["raw_sha256"] and
                 objects["controller"].digest_object(spec) ==
                     spec_pin["semantic_sha256"] and
                 _sha(plan_raw) == plan_pin["raw_sha256"] and
                 source_plan.get("plan_sha256") == plan_pin["semantic_sha256"] ==
                     _sha(_canonical({key: value for key, value in
                                      source_plan.items()
                                      if key != "plan_sha256"},
                                     maximum_bytes=MAX_PLAN_BYTES)),
                 "recorded-read final Spec/Plan differs from its exact basis pins")
        source_rows = []
        for host in basis_hosts:
            doc = source_docs[host]
            pin = source_pins[host]
            source_rows.append({
                "host_id": host, "path": pin["path"],
                "raw_sha256": pin["raw_sha256"],
                "semantic_sha256": pin["semantic_sha256"],
                "source_tree_sha256": doc["source"]["source_tree_sha256"],
            })

        def bootstrap_reader(pin_value: dict[str, str], maximum: int) -> bytes:
            _require(cancel_event is None or not cancel_event.is_set(),
                     "recorded-read Source graph replay was cancelled")
            _require(deadline_ns is None or
                     time.monotonic_ns() < deadline_ns,
                     "recorded-read Source graph replay exceeded its window")
            pin = _pin_raw(pin_value, "recorded-read closed metadata request")
            if pin == {"path": spec_pin["path"],
                      "raw_sha256": spec_pin["raw_sha256"]}:
                raw = spec_raw
            elif pin == {"path": plan_pin["path"],
                        "raw_sha256": plan_pin["raw_sha256"]}:
                raw = plan_raw
            elif pin == {"path": selected_pin["path"],
                        "raw_sha256": selected_pin["raw_sha256"]}:
                raw = selected_source_manifest_raw
            else:
                raw = bootstrap.read(pin, maximum)
            _require(type(raw) is bytes and 0 < len(raw) <= maximum and
                     _sha(raw) == pin["raw_sha256"],
                     "recorded-read closed reader returned bytes outside the exact pin/cap")
            _require(cancel_event is None or not cancel_event.is_set(),
                     "recorded-read Source graph replay was cancelled after a read")
            _require(deadline_ns is None or
                     time.monotonic_ns() < deadline_ns,
                     "recorded-read Source graph replay exceeded its window")
            return raw

        original_pin_dtos: dict[str, dict[str, Any]] = {}
        for host in basis_hosts:
            header_pin = _pin_raw(basis["ancestor_pins"][host]["bridge_header"],
                                  f"recorded-read {host} bridge header pin")
            header_raw = bootstrap_reader(header_pin, 256 * 1024)
            header = _parse_canonical(header_raw,
                                      f"recorded-read {host} bridge header",
                                      maximum_bytes=256 * 1024)
            initial = _exact(header.get("initial"), {
                "execution_manifest_pin", "spec_pin", "plan_pin",
                "source_manifest_pins", "observed_host_pin",
                "capacity_generation_sha256", "capacity_registration_head",
                "host_budget_pin", "journal_width_pin",
                "fixed_spec_host_pin", "prepared_host_binding_sha256",
                "signer_context_pin", "signer_fingerprint",
                "maximum_signature_bytes",
            }, f"recorded-read {host} initial bridge context")
            observed_pin = _pin_raw(initial["observed_host_pin"],
                                    f"recorded-read {host} observed-host pin")
            observed_raw = bootstrap_reader(
                observed_pin, objects["source5_campaign"].MAX_ARTIFACT_BYTES,
            )
            observed = _parse_canonical(
                observed_raw, f"recorded-read {host} observed-host document",
                maximum_bytes=objects["source5_campaign"].MAX_ARTIFACT_BYTES,
            )
            observed_context = types.SimpleNamespace(
                observed_host_pin=observed_pin,
                manifest={"hosts": basis_hosts,
                          "modules": basis["source_module_pins"]},
                host_id=host, chronology=objects["chronology"],
                spec_pin=spec_pin,
                spec_semantic_sha256=spec_pin["semantic_sha256"],
                plan_pin=plan_pin,
                plan_semantic_sha256=plan_pin["semantic_sha256"],
                source_manifest_pins=source_pins,
                sources=source_docs,
            )
            try:
                original = objects[
                    "source5_campaign"
                ].build_source5_original_pins_from_observed_v1(
                    observed_context, observed, _sha(observed_raw),
                )
                objects["chronology"]._validate_chronology_original_pins(original)
            except Exception as error:
                raise EvidenceArchiveError(
                    f"typed Source chronology rejected recorded-read {host}: {error}",
                ) from error
            original_pin_dtos[host] = original

        proofs: dict[str, dict[str, Any]] = {}
        for host in basis_hosts:
            final_prepared = {
                "campaign_id": basis["campaign_id"], "host_id": host,
                "output_root": basis["current_roots"]["output_root"],
                "original_pins": original_pin_dtos[host],
            }
            try:
                proof = objects["lineage"].verify_source5_prepared_exploration_lineage_v2(
                    final_prepared, basis["ancestor_pins"][host],
                    artifact_reader=bootstrap_reader,
                    campaign_module=objects["controller"],
                    input_preparation_module=objects["input_preparation"],
                    campaign_inputs_module=objects["campaign_inputs"],
                    chronology_module=objects["chronology"],
                    source5_campaign_module=objects["source5_campaign"],
                    preparatory_budget_module=objects["preparatory_budget"],
                )
            except Exception as error:
                raise EvidenceArchiveError(
                    f"typed Source lineage verifier rejected recorded-read {host}: {error}",
                ) from error
            _require(type(proof) is dict and proof.get("host_id") == host and
                     proof.get("campaign_id") == basis["campaign_id"] and
                     proof.get("qualification_eligible") is False and
                     proof.get("component_replay_required") is True and
                     type(proof.get("index_rows")) is list and
                     len(proof["index_rows"]) == 360,
                     f"recorded-read {host} rich lineage proof is incomplete or authorizing")
            proofs[host] = proof
        expected_ancestors = {
            host: proofs[host]["ancestor"] for host in basis_hosts
        }
        jobs_by_host = {
            host: [job for job in source_plan["jobs"]["exploration"]
                   if type(job) is dict and job.get("host_id") == host]
            for host in basis_hosts
        }
        try:
            declaration, storage_rows = objects[
                "bridge"
            ].build_prepared_exploration_capture_storage_v1(
                basis_hosts, proofs,
                expected_ancestors=expected_ancestors,
                expected_exploration_jobs=jobs_by_host,
                artifact_reader=bootstrap_reader,
                evidence_budget_module=objects["evidence_budget"],
            )
        except Exception as error:
            raise EvidenceArchiveError(
                f"typed Source capture closure builder rejected recorded replay: {error}",
            ) from error
        storage_rows = [objects["evidence_budget"]._catalogue_row(
            row, f"recorded-read captured storage row[{index}]",
        ) for index, row in enumerate(storage_rows)]
        _require(declaration.get("cohort_host_ids") == basis_hosts and
                 len(storage_rows) == len(declaration.get("objects", [])),
                 "recorded-read Source capture declaration is not a complete cohort")
        width_pin = _pin(basis["width_contract_pin"],
                         "recorded-read current width contract pin")
        width_raw = bootstrap_reader(
            {"path": width_pin["path"],
             "raw_sha256": width_pin["raw_sha256"]},
            PREPARATORY_MAX_WIDTH_BYTES,
        )
        width = _parse_canonical(
            width_raw, "recorded-read current width contract",
            maximum_bytes=PREPARATORY_MAX_WIDTH_BYTES,
        )
        selected_jobs = {
            phase: [job for job in source_plan["jobs"][phase]
                    if type(job) is dict and job.get("host_id") == consumer]
            for phase in ("exploration", "aa", "confirmation", "pressure", "soak")
        }
        try:
            checked_width, width_events, max_line = objects[
                "bridge"
            ].validate_prepared_exploration_width_contract_v2(
                width, jobs_by_phase=selected_jobs,
                expected_campaign_id=basis["campaign_id"],
                expected_host_id=consumer,
                expected_original_pins_sha256=_sha(_canonical(
                    original_pin_dtos[consumer],
                )), expected_plan_pin=plan_pin,
                expected_source_manifest_pin=selected_pin,
                expected_ancestor=proofs[consumer]["ancestor"],
            )
        except Exception as error:
            raise EvidenceArchiveError(
                f"typed Source width validator rejected recorded-read basis: {error}",
            ) from error
        _require(checked_width == width and width_events == 97499 and
                 max_line > 0 and _sha(width_raw) == width_pin["raw_sha256"] and
                 _sha(_canonical({key: value for key, value in width.items()
                                  if key != "contract_sha256"})) ==
                     width_pin["semantic_sha256"],
                 "recorded-read current width contract differs from its exact basis pin")
        captured_by_pin = {
            (item["origin_pin"]["path"],
             item["origin_pin"]["raw_sha256"]): item
            for item in capture_manifest["objects"]
        }
        expected_capture_rows = []
        for row in declaration["objects"]:
            key = (row["origin_pin"]["path"],
                   row["origin_pin"]["raw_sha256"])
            captured = captured_by_pin.get(key)
            _require(captured is not None,
                     "recorded-read derived Source object is absent from closed capture")
            expected_capture_rows.append({
                "origin_pin": row["origin_pin"],
                "local_relative_path": captured["local_relative_path"],
                "byte_count": row["byte_count"],
            })
        _require(expected_capture_rows == capture_manifest["objects"] and
                 len(expected_capture_rows) == len(declaration["objects"]),
                 "recorded-read closed capture manifest differs from the full Source-derived declaration")
        return {
        "reader": bootstrap, "declaration": declaration,
        "storage_rows": storage_rows, "proofs": proofs,
        "source_docs": source_docs, "source_modules": objects,
        "source_plan": source_plan, "spec": spec, "width": width,
        "source_pins": source_pins, "selected_source_pin": selected_pin,
        }
    except BaseException:
        bootstrap.close()
        raise


def _recorded_read_root_output_context(
    resource_value: object, basis: dict[str, Any],
    basis_pin: dict[str, Any], plan: dict[str, Any],
    plan_pin: dict[str, Any], read_ordinal: int,
    window_chunk: dict[str, Any], plan_module: object,
) -> dict[str, Any]:
    resource = _exact(resource_value, RECORDED_READ_ROOT_OUTPUT_FIELDS_V2,
                      "Root recorded-read output reservation")
    body = {key: value for key, value in resource.items()
            if key != "resource_sha256"}
    _require(resource["schema"] == RECORDED_READ_ROOT_OUTPUT_SCHEMA_V2 and
             resource["resource_sha256"] == _sha(_canonical(body)),
             "Root recorded-read output reservation self digest differs")
    root = Path(_absolute_path(resource["root"],
                               "Root recorded-read output root"))
    root_device = _uint(resource["device"],
                        "Root recorded-read output device")
    reserved_bytes = _uint(resource["reserved_bytes"],
                           "Root recorded-read output bytes", positive=True)
    reserved_inodes = _uint(resource["reserved_inodes"],
                            "Root recorded-read output inodes", positive=True)
    allocation_block = _uint(
        resource["allocation_block_bytes"],
        "Root recorded-read output allocation block", positive=True,
        maximum=1 << 20,
    )
    directory_metadata = _uint(
        resource["directory_metadata_bytes"],
        "Root recorded-read output per-directory metadata reserve", positive=True,
    )
    directory_allocated = _uint(
        resource["directory_allocated_bytes"],
        "Root recorded-read output directory allocation projection", positive=True,
    )
    projected_file_bytes = _uint(
        resource["required_file_bytes"],
        "Root recorded-read output raw file projection", positive=True,
    )
    projected_file_allocated = _uint(
        resource["required_file_allocated_bytes"],
        "Root recorded-read output rounded file projection", positive=True,
    )
    projected_allocated = _uint(
        resource["required_allocated_bytes"],
        "Root recorded-read output physical projection", positive=True,
    )
    maximum_response = _uint(
        resource["maximum_response_bytes"],
        "Root recorded-read output response cap", positive=True,
        maximum=MAX_ARCHIVE_READ_METADATA_BYTES,
    )
    maximum_bundle = _uint(
        resource["maximum_bundle_bytes"],
        "Root recorded-read output bundle cap", positive=True,
        maximum=MAX_TOTAL_BYTES,
    )
    maximum_ledger = _uint(
        resource["maximum_control_ledger_bytes"],
        "Root recorded-read control-ledger cap", positive=True,
        maximum=MAX_TOTAL_BYTES,
    )
    maximum_line = _uint(
        resource["maximum_control_line_bytes"],
        "Root recorded-read control-line cap", positive=True,
        maximum=MAX_ARCHIVE_READ_METADATA_BYTES,
    )
    failure_bytes = _uint(
        resource["failure_receipt_bytes"],
        "Root recorded-read failure-receipt cap", positive=True,
        maximum=MAX_ARCHIVE_READ_METADATA_BYTES,
    )
    maximum_window = _uint(
        resource["maximum_window_seconds"],
        "Root recorded-read output timeout", positive=True, maximum=300,
    )
    row = plan_module.validate_recorded_preparation_read_window_v2(
        plan, plan_pin, window_chunk, read_ordinal,
    )
    _require(maximum_window ==
             plan["timeout_declaration"]["maximum_io_window_seconds"] and
             maximum_response >= row["resource_bounds"]["outer_response_bytes"] and
             maximum_bundle >= row["resource_bounds"]["tar_bytes"],
             "Root output caps/deadline do not cover this exact Source window")
    required_directories = [
        str(root / basis["campaign_id"]),
        str(root / basis["campaign_id"] / "source5"),
        str(root / basis["campaign_id"] / "source5" /
            basis["consumer_host_id"]),
        str(root / basis["campaign_id"] / "source5" /
            basis["consumer_host_id"] / "recorded-preparation"),
        str(root / basis["campaign_id"] / "source5" /
            basis["consumer_host_id"] / "recorded-preparation" /
            plan["session_nonce"]),
        str(root / basis["campaign_id"] / "source5" /
            basis["consumer_host_id"] / "recorded-preparation" /
            plan["session_nonce"] / "slot"),
    ]
    session = Path(required_directories[-2])
    slot = Path(required_directories[-1])
    paths = {
        "session": str(session),
        "slot": str(slot),
        "response": str(slot / "response.json.incoming"),
        "bundle": str(slot / "response.tar.incoming"),
        "control_ledger": str(session / "control-ledger.jsonl"),
        "failure_receipt": str(session / "failure-receipt.json"),
        "directories": required_directories,
    }
    protected_roots = list(basis["current_roots"].values()) + [
        plan["scratch_declaration"]["root"], row["archive_source5_root"],
    ]
    for protected in protected_roots:
        _require(not plan_module._paths_overlap(str(root), protected),
                 "Root response scratch overlaps a Source/current/archive root")
    file_caps = (maximum_response, maximum_bundle,
                 maximum_ledger, failure_bytes)
    required_file_bytes = sum(file_caps)
    required_file_allocated = sum(
        ((cap + allocation_block - 1) // allocation_block) *
        allocation_block for cap in file_caps
    )
    required_directories_count = len(required_directories)
    required_directory_bytes = required_directories_count * directory_metadata
    required_allocated = required_directory_bytes + required_file_allocated
    required_inodes = 2 + 1 + 1 + len(required_directories)
    _require(directory_metadata == allocation_block and
             directory_allocated == required_directory_bytes and
             projected_file_bytes == required_file_bytes and
             projected_file_allocated == required_file_allocated and
             projected_allocated == required_allocated and
             reserved_bytes >= required_allocated and
             reserved_inodes >= required_inodes and
             maximum_ledger >= (2 * plan_module.READ_WINDOW_COUNT * maximum_line),
             "Root recorded-read output reservation is below its complete bounded session")
    return {
        "resource": resource, "root": root, "device": root_device,
        "maximum_response_bytes": maximum_response,
        "maximum_bundle_bytes": maximum_bundle,
        "maximum_control_ledger_bytes": maximum_ledger,
        "maximum_control_line_bytes": maximum_line,
        "failure_receipt_bytes": failure_bytes,
        "maximum_window_seconds": maximum_window,
        "allocation_block_bytes": allocation_block,
        "directory_metadata_bytes": directory_metadata,
        "directory_allocated_bytes": directory_allocated,
        "required_file_bytes": projected_file_bytes,
        "required_file_allocated_bytes": projected_file_allocated,
        "required_allocated_bytes": projected_allocated,
        "maximum_response_allocated_bytes": (
            (maximum_response + allocation_block - 1) // allocation_block *
            allocation_block
        ),
        "maximum_bundle_allocated_bytes": (
            (maximum_bundle + allocation_block - 1) // allocation_block *
            allocation_block
        ),
        "maximum_control_ledger_allocated_bytes": (
            (maximum_ledger + allocation_block - 1) // allocation_block *
            allocation_block
        ),
        "failure_receipt_allocated_bytes": (
            (failure_bytes + allocation_block - 1) // allocation_block *
            allocation_block
        ),
        "reserved_bytes": reserved_bytes,
        "reserved_inodes": reserved_inodes,
        "paths": paths,
    }


def _recorded_read_root_output_directory_baseline(
    context: dict[str, Any],
) -> dict[str, int]:
    baseline = {}
    for path_text in context["paths"]["directories"]:
        directory_fd = _open_dir_path(
            path_text, "Root recorded-read output directory baseline",
            private_final=True,
        )
        try:
            info = os.fstat(directory_fd)
            _require(info.st_dev == context["device"] and
                     stat.S_ISDIR(info.st_mode) and
                     info.st_uid == os.getuid() and
                     stat.S_IMODE(info.st_mode) == 0o700,
                     "Root output directory baseline identity differs")
            baseline[path_text] = info.st_blocks * 512
        finally:
            os.close(directory_fd)
    return baseline


def _recorded_read_root_output_missing_directory_count(
    root_fd: int, context: dict[str, Any],
) -> int:
    current_fd = os.dup(root_fd)
    try:
        directories = context["paths"]["directories"]
        for index, path_text in enumerate(directories):
            leaf = Path(path_text).name
            try:
                path_info = os.stat(leaf, dir_fd=current_fd,
                                    follow_symlinks=False)
            except FileNotFoundError:
                return len(directories) - index
            _require(stat.S_ISDIR(path_info.st_mode) and
                     path_info.st_uid == os.getuid() and
                     stat.S_IMODE(path_info.st_mode) == 0o700 and
                     path_info.st_dev == context["device"],
                     "Root output existing directory is not private same-device storage")
            child_fd = os.open(
                leaf, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW,
                dir_fd=current_fd,
            )
            try:
                _require(_info_key(path_info) == _info_key(os.fstat(child_fd)),
                         "Root output directory changed during preflight")
            except BaseException:
                os.close(child_fd)
                raise
            os.close(current_fd)
            current_fd = child_fd
        return 0
    finally:
        os.close(current_fd)


def _prepare_recorded_read_root_output_dirs(context: dict[str, Any]) -> None:
    root_fd = _open_dir_path(context["root"],
                             "Root recorded-read output root",
                             private_final=True)
    try:
        root_info = os.fstat(root_fd)
        initial_space = os.fstatvfs(root_fd)
        initial_block = initial_space.f_frsize or initial_space.f_bsize
        _require(root_info.st_dev == context["device"] and
                 initial_block == context["allocation_block_bytes"],
                 "Root recorded-read output root device/allocation block differs")
        missing_directories = _recorded_read_root_output_missing_directory_count(
            root_fd, context,
        )
        try:
            session_fd = _open_dir_path(
                context["paths"]["session"],
                "Root recorded-read session inode preflight",
                private_final=True,
            )
        except FileNotFoundError:
            ledger_inode_remaining = 1
        else:
            try:
                try:
                    ledger_info = os.stat(
                        Path(context["paths"]["control_ledger"]).name,
                        dir_fd=session_fd, follow_symlinks=False,
                    )
                except FileNotFoundError:
                    ledger_inode_remaining = 1
                else:
                    _require(stat.S_ISREG(ledger_info.st_mode) and
                             ledger_info.st_uid == os.getuid() and
                             stat.S_IMODE(ledger_info.st_mode) == 0o600 and
                             ledger_info.st_nlink == 1,
                             "Root output inode preflight found a foreign ledger")
                    ledger_inode_remaining = 0
            finally:
                os.close(session_fd)
        initial_space = os.fstatvfs(root_fd)
        _require(initial_space.f_favail >=
                     missing_directories + 3 + ledger_inode_remaining,
                 "Root output root lacks directory and current file inodes")
        _require(os.fstat(root_fd).st_dev == context["device"],
                 "Root recorded-read output root is on the wrong device")
        current_fd = os.dup(root_fd)
        try:
            for path_text in context["paths"]["directories"]:
                leaf = Path(path_text).name
                try:
                    before_child = os.stat(
                        leaf, dir_fd=current_fd, follow_symlinks=False,
                    )
                except FileNotFoundError:
                    before_child = None
                child_fd = _ensure_private_child(
                    current_fd, leaf, "Root recorded-read output directory",
                )
                child_info = os.fstat(child_fd)
                _require(child_info.st_dev == context["device"] and
                         stat.S_ISDIR(child_info.st_mode) and
                         child_info.st_uid == os.getuid() and
                         stat.S_IMODE(child_info.st_mode) == 0o700,
                         "Root output directory crossed device/mode or its explicit metadata reserve")
                if before_child is None:
                    allocated_delta = child_info.st_blocks * 512
                else:
                    _require(_info_key(before_child) == _info_key(child_info),
                             "Root output directory changed during identity check")
                    allocated_delta = max(
                        0, child_info.st_blocks - before_child.st_blocks,
                    ) * 512
                _require(allocated_delta <=
                         context["directory_metadata_bytes"],
                         "Root output directory growth exceeded its explicit metadata reserve")
                os.close(current_fd)
                current_fd = child_fd
        finally:
            os.close(current_fd)
        context["directory_allocation_baseline"] = \
            _recorded_read_root_output_directory_baseline(context)
        remaining_bytes, remaining_inodes = \
            _recorded_read_root_output_remaining_capacity(context)
        space = os.fstatvfs(root_fd)
        block_bytes = space.f_frsize or space.f_bsize
        _require(block_bytes == context["allocation_block_bytes"] and
                 space.f_bavail * block_bytes >= remaining_bytes and
                 space.f_favail >= remaining_inodes,
                 "Root recorded-read output root lacks its remaining reserved window")
        session_fd = _open_dir_path(
            context["paths"]["session"],
            "Root recorded-read current session directory",
            private_final=True,
        )
        try:
            _require(set(os.listdir(session_fd)) <= {
                         "slot", "control-ledger.jsonl",
                     } and "slot" in os.listdir(session_fd),
                     "Root recorded-read session contains an undeclared entry")
        finally:
            os.close(session_fd)
        slot_fd = _open_dir_path(
            context["paths"]["slot"],
            "Root recorded-read current slot directory",
            private_final=True,
        )
        try:
            _require(not os.listdir(slot_fd),
                     "Root recorded-read current Root slot still holds an output")
        finally:
            os.close(slot_fd)
        os.fsync(root_fd)
    finally:
        os.close(root_fd)


def _verify_recorded_read_root_output_directory_growth(
    context: dict[str, Any],
) -> None:
    baseline = context.get("directory_allocation_baseline")
    _require(type(baseline) is dict and
             set(baseline) == set(context["paths"]["directories"]),
             "Root output directory allocation baseline is absent")
    total_growth = 0
    for path_text in context["paths"]["directories"]:
        directory_fd = _open_dir_path(
            path_text, "Root recorded-read output directory growth",
            private_final=True,
        )
        try:
            info = os.fstat(directory_fd)
            _require(info.st_dev == context["device"] and
                     stat.S_ISDIR(info.st_mode) and
                     info.st_uid == os.getuid() and
                     stat.S_IMODE(info.st_mode) == 0o700,
                     "Root output directory changed identity or mode")
            allocated = info.st_blocks * 512
            growth = max(0, allocated - baseline[path_text])
            _require(growth <= context["directory_metadata_bytes"],
                     "Root output directory exceeded its per-directory metadata reserve")
            total_growth += growth
        finally:
            os.close(directory_fd)
    _require(total_growth <= context["directory_allocated_bytes"],
             "Root output directories exceeded their aggregate metadata reserve")


def _recorded_read_root_output_remaining_capacity(
    context: dict[str, Any],
) -> tuple[int, int]:
    ledger_path = Path(context["paths"]["control_ledger"])
    try:
        ledger_info = ledger_path.lstat()
        _require(stat.S_ISREG(ledger_info.st_mode) and
                 ledger_info.st_uid == os.getuid() and
                 stat.S_IMODE(ledger_info.st_mode) == 0o600 and
                 ledger_info.st_nlink == 1 and
                 ledger_info.st_size <= context["maximum_control_ledger_bytes"] and
                 ledger_info.st_blocks * 512 <=
                    context["maximum_control_ledger_allocated_bytes"],
                 "Root output control ledger exceeds its remaining physical reservation")
        ledger_allocated = ledger_info.st_blocks * 512
        ledger_inode_remaining = 0
    except FileNotFoundError:
        ledger_allocated = 0
        ledger_inode_remaining = 1
    for key in ("response", "bundle", "failure_receipt"):
        path = Path(context["paths"][key])
        _require(not path.exists() and not path.is_symlink(),
                 "Root output reservation has a retained prior window")
    remaining_bytes = (
        context["maximum_response_allocated_bytes"] +
        context["maximum_bundle_allocated_bytes"] +
        context["failure_receipt_allocated_bytes"] +
        max(0, context["maximum_control_ledger_allocated_bytes"] -
            ledger_allocated)
    )
    remaining_inodes = 3 + ledger_inode_remaining
    return remaining_bytes, remaining_inodes


def _check_recorded_read_root_resource_pair(
    output_context: dict[str, Any], gpg_resource: dict[str, Any], *,
    deadline_ns: int, cancel_event=None,
) -> None:
    _require(time.monotonic_ns() < deadline_ns and
             (cancel_event is None or not cancel_event.is_set()),
             "Root recorded-read combined resource check was cancelled or expired")
    gpg_root = Path(_absolute_path(
        gpg_resource["scratch_root"], "Root GPG auxiliary scratch root",
    ))
    output_fd: int | None = None
    gpg_fd = _open_dir_path(
        gpg_root, "Root recorded-read GPG auxiliary root",
        private_final=True,
    )
    try:
        output_fd = _open_dir_path(
            output_context["root"], "Root recorded-read output root",
            private_final=True,
        )
        gpg_info = os.fstat(gpg_fd)
        output_info = os.fstat(output_fd)
        gpg_space = os.fstatvfs(gpg_fd)
        output_space = os.fstatvfs(output_fd)
        gpg_block = gpg_space.f_frsize or gpg_space.f_bsize
        output_block = output_space.f_frsize or output_space.f_bsize
        gpg_bytes = _uint(
            gpg_resource["reserved_bytes"],
            "Root GPG reserved physical bytes", positive=True,
        )
        gpg_inodes = _uint(
            gpg_resource["reserved_inodes"],
            "Root GPG reserved inodes", positive=True,
        )
        _require(gpg_info.st_dev == gpg_resource["device"] and
                 gpg_block == gpg_resource["allocation_block_bytes"] and
                 output_info.st_dev == output_context["device"] and
                 output_block == output_context["allocation_block_bytes"],
                 "Root GPG/output root device or allocation-block identity differs")
        output_bytes, output_inodes = \
            _recorded_read_root_output_remaining_capacity(output_context)
        if gpg_info.st_dev == output_info.st_dev:
            _require(gpg_space.f_bavail * gpg_block >=
                         gpg_bytes + output_bytes and
                     gpg_space.f_favail >= gpg_inodes + output_inodes,
                     "Root GPG plus output windows exceed the shared device reservation")
        else:
            _require(gpg_space.f_bavail * gpg_block >= gpg_bytes and
                     gpg_space.f_favail >= gpg_inodes and
                     output_space.f_bavail * output_block >= output_bytes and
                     output_space.f_favail >= output_inodes,
                     "Root GPG or output window lacks its separate device reservation")
    finally:
        try:
            if output_fd is not None:
                os.close(output_fd)
        finally:
            os.close(gpg_fd)


def _recorded_root_control_event(
    basis: dict[str, Any], basis_pin: dict[str, Any],
    plan: dict[str, Any], plan_pin: dict[str, Any],
    row: dict[str, Any], sequence: int, action: str,
    request_pin: dict[str, Any], root_paths: dict[str, Any],
    response_pin=None, bundle_pin=None,
) -> dict[str, Any]:
    _require(action in {"request_accepted", "response_published"} and
             type(sequence) is int and 0 < sequence < (1 << 64),
             "Root recorded-read event action/sequence differs")
    request = _exact(request_pin, {
        "path", "raw_sha256", "semantic_sha256",
    }, "Root recorded-read event request pin")
    _require(request["path"] == row["session_paths"]["request"],
             "Root recorded-read event request path differs from its Source row")
    _digest(request["raw_sha256"], "Root recorded-read event request raw digest")
    _digest(request["semantic_sha256"],
            "Root recorded-read event request semantic digest")
    if action == "request_accepted":
        _require(response_pin is None and bundle_pin is None,
                 "Root request-accepted event cannot carry an output pin")
    else:
        response_pin = _exact(response_pin, {
            "path", "raw_sha256", "semantic_sha256",
        }, "Root recorded-read event response pin")
        bundle_pin = _exact(bundle_pin, {
            "path", "raw_sha256", "byte_count",
        }, "Root recorded-read event bundle pin")
        _require(response_pin["path"] == root_paths["response"] and
                 bundle_pin["path"] == root_paths["bundle"],
                 "Root recorded-read event output path differs from its current Root slots")
        _digest(response_pin["raw_sha256"],
                "Root recorded-read event response raw digest")
        _digest(response_pin["semantic_sha256"],
                "Root recorded-read event response semantic digest")
        _digest(bundle_pin["raw_sha256"],
                "Root recorded-read event bundle raw digest")
        _require(_uint(bundle_pin["byte_count"],
                       "Root recorded-read event bundle byte count",
                       positive=True) == row["resource_bounds"]["tar_bytes"],
                 "Root recorded-read event bundle size differs from its exact row")
    body = {
        "schema": RECORDED_READ_ROOT_CONTROL_SCHEMA_V1,
        "sequence": sequence,
        "basis_pin": basis_pin,
        "read_plan_pin": plan_pin,
        "session_nonce": plan["session_nonce"],
        "consumer_host_id": plan["consumer_host_id"],
        "owner_host_id": row["owner_host_id"],
        "operation_kind": plan["operation_kind"],
        "read_ordinal": row["read_ordinal"],
        "job_index": row["job_index"],
        "job_sha256": row["job_sha256"],
        "action": action,
        "request_pin": request_pin,
        "response_path": root_paths["response"],
        "bundle_path": root_paths["bundle"],
        "response_pin": response_pin,
        "bundle_pin": bundle_pin,
        "qualification_eligible": False,
        "event_sha256": "",
    }
    return {**body, "event_sha256": _sha(_canonical({
        key: value for key, value in body.items()
        if key != "event_sha256"
    }))}


def _open_recorded_read_root_ledger(context: dict[str, Any]) -> int:
    path = Path(context["paths"]["control_ledger"])
    if not path.exists() and not path.is_symlink():
        parent_fd = _open_dir_path(
            path.parent, "Root recorded-read control-ledger parent",
            private_final=True,
        )
        try:
            _require(os.fstat(parent_fd).st_dev == context["device"],
                     "Root recorded-read control-ledger parent device differs")
            _write_at(parent_fd, path.name, b"",
                      "Root recorded-read current control ledger")
        finally:
            os.close(parent_fd)
    parent_fd = _open_dir_path(
        path.parent, "Root recorded-read current ledger parent",
        private_final=True,
    )
    try:
        _require(os.fstat(parent_fd).st_dev == context["device"],
                 "Root recorded-read current ledger parent device differs")
        info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                 stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and
                 0 <= info.st_size <= context["maximum_control_ledger_bytes"] and
                 info.st_blocks * 512 <=
                    context["maximum_control_ledger_allocated_bytes"],
                 "Root recorded-read current ledger is outside its exact private bounds")
        descriptor = os.open(
            path.name,
            os.O_RDWR | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK,
            dir_fd=parent_fd,
        )
        try:
            _require(_info_key(info) == _info_key(os.fstat(descriptor)),
                 "Root recorded-read control ledger changed before open")
            import fcntl
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise
    except (ImportError, OSError) as error:
        raise EvidenceArchiveError(
            "Root recorded-read control ledger is already leased or unavailable",
        ) from error
    finally:
        os.close(parent_fd)


def _recorded_root_control_state(
    descriptor: int, context: dict[str, Any], basis: dict[str, Any],
    basis_pin: dict[str, Any], plan: dict[str, Any],
    plan_pin: dict[str, Any], plan_module: object, *,
    deadline_ns: int | None = None, cancel_event=None,
) -> tuple[int, dict[str, Any] | None, str]:
    info = os.fstat(descriptor)
    _require(info.st_size <= context["maximum_control_ledger_bytes"] and
             info.st_blocks * 512 <=
                context["maximum_control_ledger_allocated_bytes"] and
             stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
             stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
             "Root recorded-read current ledger exceeded its exact limit")
    os.lseek(descriptor, 0, os.SEEK_SET)
    raw = bytearray()
    while len(raw) < info.st_size:
        _require(deadline_ns is None or time.monotonic_ns() < deadline_ns,
                 "Root recorded-read ledger read exceeded its window")
        _require(cancel_event is None or not cancel_event.is_set(),
                 "Root recorded-read ledger read was cancelled")
        block = os.read(descriptor, min(COPY_BLOCK_BYTES,
                                        info.st_size - len(raw)))
        _require(bool(block),
                 "Root recorded-read ledger shortened during bounded replay")
        raw.extend(block)
        _require(len(raw) <= context["maximum_control_ledger_bytes"],
                 "Root recorded-read ledger exceeds its bounded session")
    _require(os.read(descriptor, 1) == b"" and
             _info_key(info) == _info_key(os.fstat(descriptor)),
             "Root recorded-read ledger changed during replay")
    previous = "0" * 64
    count = 0
    lines = bytes(raw).splitlines(keepends=True)
    _require(b"".join(lines) == bytes(raw) and
             all(line.endswith(b"\n") and
                 len(line) <= context["maximum_control_line_bytes"]
                 for line in lines),
             "Root recorded-read ledger has a partial or oversized line")
    pending_request = None
    cached_chunk_ordinal = None
    cached_window_chunk = None
    for index, line in enumerate(lines):
        _require(deadline_ns is None or time.monotonic_ns() < deadline_ns,
                 "Root recorded-read ledger replay exceeded its window")
        _require(cancel_event is None or not cancel_event.is_set(),
                 "Root recorded-read ledger replay was cancelled")
        try:
            envelope = json.loads(line.decode("ascii"))
        except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
            raise EvidenceArchiveError(
                "Root recorded-read ledger line is malformed",
            ) from error
        envelope = _exact(envelope, {
            "previous_sha256", "record", "record_sha256",
        }, f"Root recorded-read ledger line[{index}]")
        event = _exact(envelope["record"], {
            "schema", "sequence", "basis_pin", "read_plan_pin",
            "session_nonce", "consumer_host_id", "owner_host_id",
            "operation_kind", "read_ordinal", "job_index", "job_sha256",
            "action", "request_pin", "response_path", "bundle_path",
            "response_pin", "bundle_pin", "qualification_eligible",
            "event_sha256",
        }, f"Root recorded-read event[{index}]")
        ordinal = count // 2
        _require(ordinal < plan_module.READ_WINDOW_COUNT and
                 event["read_ordinal"] == ordinal,
                 "Root recorded-read ledger order differs from its exact schedule")
        current_chunk_ordinal = plan["window_index"][ordinal]["chunk_ordinal"]
        if current_chunk_ordinal != cached_chunk_ordinal:
            cached_window_chunk, _row = _recorded_read_window_chunk(
                plan, plan_pin, plan_module, ordinal,
                deadline_ns=deadline_ns, cancel_event=cancel_event,
            )
            cached_chunk_ordinal = current_chunk_ordinal
        window_chunk = cached_window_chunk
        row = plan_module.validate_recorded_preparation_read_window_v2(
            plan, plan_pin, window_chunk, ordinal,
        )
        request, request_raw, request_pin = \
            plan_module.build_recorded_preparation_read_request_v2(
                basis, basis_pin, plan, plan_pin, ordinal, window_chunk,
            )
        request_pin = {key: request_pin[key] for key in (
            "path", "raw_sha256", "semantic_sha256",
        )}
        if count % 2 == 0:
            expected = _recorded_root_control_event(
                basis, basis_pin, plan, plan_pin, row, count + 1,
                "request_accepted", request_pin, context["paths"],
            )
            pending_request = request_pin
        else:
            response_pin = event["response_pin"]
            bundle_pin = event["bundle_pin"]
            expected = _recorded_root_control_event(
                basis, basis_pin, plan, plan_pin, row, count + 1,
                "response_published", request_pin, context["paths"],
                response_pin, bundle_pin,
            )
            pending_request = None
        record_digest = _sha(_canonical({
            "previous_sha256": previous, "record": event,
        }))
        _require(line == _canonical(envelope) and
                 envelope["previous_sha256"] == previous and
                 envelope["record_sha256"] == record_digest and
                 event == expected and
                 event["event_sha256"] == _sha(_canonical({
                     key: value for key, value in event.items()
                     if key != "event_sha256"
                 })),
                 "Root recorded-read ledger chain/event differs from the current Source plan")
        previous = record_digest
        count += 1
    _require(count <= 2 * plan_module.READ_WINDOW_COUNT,
             "Root recorded-read ledger exceeds its exact 720-window schedule")
    return count // 2, pending_request, previous


def _append_recorded_root_control_event(
    descriptor: int, event: dict[str, Any], previous: str,
    context: dict[str, Any], *, deadline_ns: int | None = None,
    cancel_event=None,
) -> str:
    line = _canonical({
        "previous_sha256": previous, "record": event,
        "record_sha256": _sha(_canonical({
            "previous_sha256": previous, "record": event,
        })),
    })
    before = os.fstat(descriptor)
    _require(len(line) <= context["maximum_control_line_bytes"] and
             before.st_size + len(line) <=
                 context["maximum_control_ledger_bytes"],
             "Root recorded-read ledger append exceeds its exact reservation")
    os.lseek(descriptor, 0, os.SEEK_END)
    view = memoryview(line)
    while view:
        _require(deadline_ns is None or time.monotonic_ns() < deadline_ns,
                 "Root recorded-read ledger append exceeded its window")
        _require(cancel_event is None or not cancel_event.is_set(),
                 "Root recorded-read ledger append was cancelled")
        written = os.write(descriptor, view)
        _require(written > 0,
                 "Root recorded-read ledger writer made no progress")
        view = view[written:]
    os.fsync(descriptor)
    after = os.fstat(descriptor)
    _require(after.st_size == before.st_size + len(line) and
             after.st_blocks * 512 <=
                context["maximum_control_ledger_allocated_bytes"] and
             (before.st_dev, before.st_ino, stat.S_IFMT(before.st_mode),
              stat.S_IMODE(before.st_mode), before.st_nlink, before.st_uid,
              before.st_gid) ==
             (after.st_dev, after.st_ino, stat.S_IFMT(after.st_mode),
              stat.S_IMODE(after.st_mode), after.st_nlink, after.st_uid,
              after.st_gid),
             "Root recorded-read ledger event failed its stable append check")
    parent_fd = _open_dir_path(
        context["paths"]["session"],
        "Root recorded-read ledger session parent", private_final=True,
    )
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    return json.loads(line.decode("ascii"))["record_sha256"]


def _write_recorded_root_failure_receipt(
    context: dict[str, Any], basis: dict[str, Any], basis_pin: dict[str, Any],
    plan: dict[str, Any], plan_pin: dict[str, Any], read_ordinal: int,
    row: dict[str, Any], *, retained_window: bool,
    deadline_ns: int, cancel_event=None,
) -> None:
    body = {
        "schema": RECORDED_READ_ROOT_FAILURE_SCHEMA_V1,
        "basis_pin": basis_pin, "read_plan_pin": plan_pin,
        "session_nonce": plan["session_nonce"],
        "consumer_host_id": plan["consumer_host_id"],
        "owner_host_id": row["owner_host_id"],
        "operation_kind": plan["operation_kind"],
        "read_ordinal": read_ordinal,
        "job_index": row["job_index"],
        "failure_kind": "root_io_failed",
        "retained_window_bytes": (
            row["resource_bounds"]["outer_response_bytes"] +
            row["resource_bounds"]["tar_bytes"] if retained_window else 0
        ),
        "retained_window_inodes": 2 if retained_window else 0,
        "failure_sha256": "",
    }
    receipt = {**body, "failure_sha256": _sha(_canonical(body))}
    raw = _canonical(receipt)
    _require(len(raw) <= context["failure_receipt_bytes"],
             "Root recorded-read failure receipt exceeds its reserved slot")
    path = Path(context["paths"]["failure_receipt"])
    parent_fd = _open_dir_path(path.parent,
                               "Root recorded-read failure parent",
                               private_final=True)
    try:
        _write_recorded_read_output_bytes(
            parent_fd, path.name, raw, context["failure_receipt_bytes"],
            "Root recorded-read current failure receipt",
            allocation_block_bytes=context["allocation_block_bytes"],
            deadline_ns=deadline_ns, cancel_event=cancel_event,
        )
        info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        _require(stat.S_ISREG(info.st_mode) and
                 info.st_uid == os.getuid() and info.st_nlink == 1 and
                 stat.S_IMODE(info.st_mode) == 0o600 and
                 info.st_size == len(raw) and
                 info.st_blocks * 512 <=
                     context["failure_receipt_allocated_bytes"],
                 "Root recorded-read failure receipt exceeded its physical reservation")
        _verify_recorded_read_root_output_directory_growth(context)
    finally:
        os.close(parent_fd)


def _write_recorded_read_output_bytes(
    parent_fd: int, name: str, raw: bytes, maximum_bytes: int,
    label: str, *, allocation_block_bytes: int,
    deadline_ns: int, cancel_event=None,
) -> dict[str, Any]:
    _require(type(raw) is bytes and 0 < len(raw) <= maximum_bytes,
             f"{label} exceeds its exact bounded output slot")
    _require(name not in ("", ".", "..") and "/" not in name and "\x00" not in name,
             f"{label} has an unsafe output leaf")
    descriptor = -1
    identity = None
    try:
        descriptor = os.open(
            name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
            _O_CLOEXEC | _O_NOFOLLOW, 0o600, dir_fd=parent_fd,
        )
        os.fchmod(descriptor, 0o600)
        before = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino, before.st_mode, before.st_uid)
        view = memoryview(raw)
        while view:
            _require(time.monotonic_ns() < deadline_ns and
                     (cancel_event is None or not cancel_event.is_set()),
                     f"{label} write exceeded or cancelled its bounded window")
            written = os.write(descriptor, view)
            _require(written > 0, f"{label} writer made no progress")
            view = view[written:]
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _require(identity == (after.st_dev, after.st_ino, after.st_mode,
                              after.st_uid) and
                 _info_key(after) == _info_key(current) and
                 stat.S_ISREG(after.st_mode) and after.st_uid == os.getuid() and
                 stat.S_IMODE(after.st_mode) == 0o600 and
                 after.st_nlink == 1 and after.st_size == len(raw) and
                 after.st_blocks * 512 <=
                    ((maximum_bytes + allocation_block_bytes - 1) //
                     allocation_block_bytes) * allocation_block_bytes,
                 f"{label} writer did not create one exact private output")
        os.fsync(parent_fd)
        return {"raw_sha256": _sha(raw), "byte_count": len(raw)}
    except BaseException:
        try:
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if (identity is not None and current is not None and
                (current.st_dev, current.st_ino, current.st_mode,
                 current.st_uid) == identity and
                stat.S_ISREG(current.st_mode) and current.st_nlink == 1):
            os.unlink(name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


_RECORDED_READ_MANIFEST_SUMMARY_FIELDS_V1 = {
    "schema", "campaign_id", "host_id", "phase", "job_index",
    "job_ordinal", "job_sha256", "run_id", "job_record_raw_sha256",
    "predecessor_ack_pin", "object_count", "payload_bytes",
    "manifest_sha256",
}
_RECORDED_READ_MANIFEST_FIELDS_V1 = (
    _RECORDED_READ_MANIFEST_SUMMARY_FIELDS_V1 | {"objects"}
)
_RECORDED_READ_MANIFEST_OBJECT_FIELDS_V1 = {
    "origin_path", "role", "object_id", "byte_count", "raw_sha256",
    "semantic_sha256", "object_pin",
}
_RECORDED_READ_SOURCE_CAP_FIELDS_V1 = {
    "request_bytes", "response_bytes", "bundle_bytes", "stage_bytes",
    "stage_inodes", "object_count", "maximum_object_bytes",
    "live_window_bytes", "live_window_inodes", "maximum_request_bytes",
    "maximum_response_bytes", "maximum_bundle_bytes",
    "maximum_stage_bytes", "maximum_stage_inodes",
    "maximum_object_count", "maximum_live_window_bytes",
    "maximum_live_window_inodes",
}


def _recorded_read_source_cap_projection(value: object) -> dict[str, int]:
    """Project only the nine names used by the v2 plan from typed Source caps."""
    caps = _exact(value, _RECORDED_READ_SOURCE_CAP_FIELDS_V1,
                  "recorded-read typed Source readback caps")
    for name, cap in caps.items():
        _uint(cap, f"recorded-read typed Source cap {name}")
    return {
        "maximum_request_bytes": caps["request_bytes"],
        "maximum_response_bytes": caps["response_bytes"],
        "bundle_bytes": caps["bundle_bytes"],
        "stage_bytes": caps["stage_bytes"],
        "stage_inodes": caps["stage_inodes"],
        "object_count": caps["object_count"],
        "maximum_object_bytes": caps["maximum_object_bytes"],
        "live_window_bytes": caps["live_window_bytes"],
        "live_window_inodes": caps["live_window_inodes"],
    }


def _recorded_read_manifest_projection(plan_row: object) -> dict[str, Any]:
    """Rebuild the exact full Archive manifest from a typed plan row."""
    row = _exact(plan_row, {
        "read_ordinal", "consumer_host_id", "owner_host_id", "operation_kind",
        "job_index", "job", "job_sha256", "original_pins",
        "indexed_reservation_bindings", "archive_source5_root",
        "manifest_summary", "objects", "source_budget_schedule_caps",
        "recomputed_source_caps", "legacy_request_sha256", "resource_bounds",
        "session_stage_root", "session_paths",
    }, "recorded-read manifest source row")
    summary = _exact(
        row["manifest_summary"], _RECORDED_READ_MANIFEST_SUMMARY_FIELDS_V1,
        "recorded-read projected manifest summary",
    )
    original_pins = _exact(row["original_pins"], {
        "job_record", "request", "checkpoint", "object_manifest", "ack",
        "signature", "host_receipt",
    }, "recorded-read projected original pins")
    manifest_pin = _pin(original_pins["object_manifest"],
                         "recorded-read projected object-manifest pin")
    objects = row["objects"]
    _require(type(objects) is list,
             "recorded-read projected manifest objects are not a list")
    projected_objects = []
    seen_origins = set()
    payload_bytes = 0
    for index, value in enumerate(objects):
        obj = _exact(value, _RECORDED_READ_MANIFEST_OBJECT_FIELDS_V1,
                     f"recorded-read projected manifest object[{index}]")
        origin = _absolute_path(
            obj["origin_path"],
            f"recorded-read projected manifest object[{index}] origin",
        )
        role = _token(
            obj["role"],
            f"recorded-read projected manifest object[{index}] role",
        )
        raw_sha = _digest(
            obj["raw_sha256"],
            f"recorded-read projected manifest object[{index}] raw digest",
        )
        semantic_sha = obj["semantic_sha256"]
        if semantic_sha is not None:
            _digest(semantic_sha,
                    f"recorded-read projected manifest object[{index}] semantic digest")
        byte_count = _uint(
            obj["byte_count"],
            f"recorded-read projected manifest object[{index}] byte count",
        )
        object_id = _object_identity(origin, raw_sha)
        object_pin = _exact(obj["object_pin"], {
            "path", "raw_sha256", "semantic_sha256", "byte_count",
        }, f"recorded-read projected manifest object[{index}] pin")
        checked_pin = {
            "path": _absolute_path(
                object_pin["path"],
                f"recorded-read projected manifest object[{index}] pin path",
            ),
            "raw_sha256": _digest(
                object_pin["raw_sha256"],
                f"recorded-read projected manifest object[{index}] pin raw digest",
            ),
            "semantic_sha256": _digest(
                object_pin["semantic_sha256"],
                f"recorded-read projected manifest object[{index}] pin semantic digest",
            ),
            "byte_count": _uint(
                object_pin["byte_count"],
                f"recorded-read projected manifest object[{index}] pin byte count",
            ),
        }
        _require(obj["object_id"] == object_id and
                 checked_pin["raw_sha256"] == raw_sha and
                 checked_pin["semantic_sha256"] == raw_sha and
                 checked_pin["byte_count"] == byte_count and
                 origin not in seen_origins,
                 f"recorded-read projected manifest object[{index}] identity differs")
        seen_origins.add(origin)
        projected_objects.append({
            "origin_path": origin, "role": role, "object_id": object_id,
            "byte_count": byte_count, "raw_sha256": raw_sha,
            "semantic_sha256": semantic_sha, "object_pin": checked_pin,
        })
        payload_bytes += byte_count
    manifest = {**summary, "objects": projected_objects}
    _exact(manifest, _RECORDED_READ_MANIFEST_FIELDS_V1,
           "recorded-read reconstructed Archive manifest")
    body = {key: value for key, value in manifest.items()
            if key != "manifest_sha256"}
    _require(manifest["schema"] == OBJECT_MANIFEST_SCHEMA_V1 and
             manifest["host_id"] == row["owner_host_id"] and
             manifest["job_index"] == row["job_index"] and
             manifest["job_sha256"] == row["job_sha256"] and
             manifest["predecessor_ack_pin"] is None and
             manifest["object_count"] == len(projected_objects) and
             manifest["payload_bytes"] == payload_bytes and
             manifest["manifest_sha256"] == _sha(_canonical(body)) ==
                 manifest_pin["semantic_sha256"],
             "recorded-read reconstructed manifest differs from its Source pin summary")
    return manifest


def _recorded_read_archive_manifest(
    manifest_raw: bytes, manifest_pin: dict[str, Any],
    plan_row: dict[str, Any], source5_root: Path,
) -> dict[str, Any]:
    expected_manifest = _recorded_read_manifest_projection(plan_row)
    expected_manifest_pin = _pin(
        plan_row["original_pins"]["object_manifest"],
        "recorded-read plan original object-manifest pin",
    )
    _require(manifest_pin == expected_manifest_pin,
             "recorded-read captured manifest full pin differs from its Source row")
    _require(type(manifest_raw) is bytes and
             _sha(manifest_raw) == manifest_pin["raw_sha256"],
             "recorded-read captured signed manifest differs from its exact raw pin")
    manifest = _parse_canonical(
        manifest_raw, "recorded-read captured signed object manifest",
    )
    _require(manifest == expected_manifest and
             manifest_raw == _canonical(expected_manifest) and
             manifest.get("manifest_sha256") ==
                 manifest_pin["semantic_sha256"] ==
                 _sha(_canonical({key: value for key, value in
                                  manifest.items()
                                  if key != "manifest_sha256"})) and
             manifest.get("host_id") == plan_row["owner_host_id"] and
             manifest.get("job_sha256") == plan_row["job_sha256"] and
             manifest.get("job_index") == plan_row["job_index"] and
             manifest.get("phase") == "exploration" and
             manifest.get("predecessor_ack_pin") is None and
             type(manifest.get("objects")) is list and
             len(manifest["objects"]) == manifest.get("object_count") and
             0 < len(manifest["objects"]) <= MAX_ARCHIVE_READ_OBJECTS,
             "recorded-read plan manifest is not the exact captured signed document")
    _require(source5_root.name == "source5" and
             source5_root == Path(plan_row["archive_source5_root"]) and
             source5_root.resolve(strict=True) == source5_root,
             "recorded-read archive root differs from its exact planned Source5 root")
    _validate_archive_path_bindings(
        str(source5_root), plan_row["original_pins"]["checkpoint"],
        manifest_pin, plan_row["original_pins"]["ack"],
        plan_row["original_pins"]["signature"], manifest,
        {
            "campaign_id": manifest["campaign_id"],
            "host_id": manifest["host_id"], "phase": "exploration",
        },
        {"job_ordinal": manifest["job_ordinal"],
         "job_sha256": manifest["job_sha256"],
         "run_id": manifest["run_id"]},
    )
    for position, obj_value in enumerate(manifest["objects"]):
        obj = _exact(obj_value, {
            "origin_path", "role", "object_id", "byte_count", "raw_sha256",
            "semantic_sha256", "object_pin",
        }, f"recorded-read signed manifest object[{position}]")
        object_pin = _exact(obj["object_pin"], {
            "path", "raw_sha256", "semantic_sha256", "byte_count",
        }, f"recorded-read signed object pin[{position}]")
        object_id = _object_identity(obj["origin_path"], obj["raw_sha256"])
        _require(obj["object_id"] == object_id and
                 object_pin == {
                     "path": str(source5_root / "objects" / object_id),
                     "raw_sha256": obj["raw_sha256"],
                     "semantic_sha256": obj["raw_sha256"],
                     "byte_count": obj["byte_count"],
                 },
                 f"recorded-read signed object[{position}] is outside its Root object-store identity")
    return manifest


def _serve_recorded_preparation_read_window_core_v1(
    request_raw: bytes, *, basis_raw: bytes, read_plan_raw: bytes,
    session_descriptor_raw: bytes, source_root: str,
    selected_source_manifest_raw: bytes,
    lineage_capture_manifest_raw: bytes,
    lineage_capture_stage_root: str, archive_source5_root: str,
    response_output_path: str, bundle_output_path: str,
    root_resource_declaration: object,
    root_output_context: dict[str, Any],
    window_deadline_ns: int, cancel_event=None,
) -> dict[str, Any]:
    """Materialize one actual Source-verified recorded window into its exact slots.

    This seam rederives the actual SourceV2/Bridge graph and selected old H6
    row, performs the pinned Source ACK verifier, streams the signed manifest
    objects from the Root object store, and writes the two transport envelopes.
    It is deliberately a one-window Root I/O operation; the SourceA-owned
    720-row plan/cap reconstruction and admission session remain separate.
    """
    _require(type(request_raw) is bytes and
             type(basis_raw) is bytes and type(read_plan_raw) is bytes and
             type(session_descriptor_raw) is bytes and
             (cancel_event is None or
              callable(getattr(cancel_event, "is_set", None))),
             "recorded-read Root operation inputs or cancellation token are malformed")
    try:
        basis = _parse_canonical(basis_raw,
                                 "recorded-read replay basis",
                                 maximum_bytes=MAX_ARCHIVE_READ_METADATA_BYTES)
        plan = _parse_canonical(read_plan_raw,
                                "recorded-read source plan",
                                maximum_bytes=MAX_ARCHIVE_READ_METADATA_BYTES)
        session = _parse_canonical(
            session_descriptor_raw, "recorded-read session descriptor",
            maximum_bytes=MAX_ARCHIVE_READ_METADATA_BYTES,
        )
    except EvidenceArchiveError:
        raise
    except Exception as error:
        raise EvidenceArchiveError(
            f"recorded-read Root session documents are malformed: {error}",
        ) from error
    source_pin_value = basis.get("source_manifest_pins", {}).get(
        basis.get("consumer_host_id"),
    )
    _require(type(source_pin_value) is dict and
             type(selected_source_manifest_raw) is bytes and
             _sha(selected_source_manifest_raw) ==
                 source_pin_value.get("raw_sha256"),
             "recorded-read selected current Source bytes differ from the basis")
    namespaces = _recorded_pre_manifest_typed_module(
        selected_source_manifest_raw, source_pin_value,
        basis["source_module_pins"][basis["consumer_host_id"]],
        SOURCE5_RECORDED_READ_PLAN_PATH, source_root, source_root,
        namespace_name="_allocatbelt_recorded_read_plan_api",
    )
    plan_module = sys.modules[namespaces["__name__"]]
    basis_pin = _exact(session, {
        "schema", "basis_pin", "read_plan_pin", "session_nonce",
        "consumer_host_id", "operation_kind", "current_journal_frontier",
        "session_sha256",
    }, "recorded-read session descriptor")
    session_body = {key: value for key, value in session.items()
                    if key != "session_sha256"}
    _require(session["schema"] == plan_module.SESSION_DESCRIPTOR_SCHEMA_V2 and
             session["session_sha256"] == _sha(_canonical(session_body)),
             "recorded-read session descriptor self digest differs")
    basis_pin_value = _pin(session["basis_pin"],
                           "recorded-read session basis pin")
    checked_plan_pin = plan_module.recorded_preparation_read_plan_pin_v2(plan)
    plan_pin = _pin(session["read_plan_pin"],
                     "recorded-read session plan pin")
    _require(plan_pin == checked_plan_pin and
             plan["basis_pin"] == basis_pin_value and
             session["session_nonce"] == plan["session_nonce"] and
             session["consumer_host_id"] == basis["consumer_host_id"] and
             session["operation_kind"] == basis["operation_kind"] and
             session["current_journal_frontier"] ==
                 basis["current_journal_frontier"],
             "recorded-read session descriptor differs from its exact basis/plan")
    checked_basis, checked_basis_pin, _hosts = plan_module._validate_basis(
        basis, basis_pin_value,
    )
    _require(checked_basis == basis and checked_basis_pin == basis_pin_value,
             "recorded-read basis raw/semantic pin differs")
    source_module_pin = basis["source_module_pins"][basis["consumer_host_id"]][
        SOURCE5_RECORDED_READ_PLAN_PATH
    ]
    _require(getattr(plan_module, "__source5_typed_pin__", None) ==
             source_module_pin,
             "recorded-read plan APIs are not the selected typed Source bytes")
    request_header = _parse_canonical(
        request_raw, "recorded-read outer request header",
        maximum_bytes=MAX_ARCHIVE_READ_METADATA_BYTES,
    )
    ordinal = plan_module._uint(
        request_header.get("read_ordinal"),
        "recorded-read request ordinal",
        maximum=plan_module.READ_WINDOW_COUNT - 1,
    )
    window_chunk, row = _recorded_read_window_chunk(
        plan, plan_pin, plan_module, ordinal,
        deadline_ns=window_deadline_ns, cancel_event=cancel_event,
    )
    outer_request = plan_module.validate_recorded_preparation_read_request_v2(
        request_raw, basis, basis_pin_value, plan, plan_pin, window_chunk,
    )
    _require(_absolute_path(archive_source5_root,
                            "recorded-read Source5 archive root") ==
             row["archive_source5_root"] and
             _absolute_path(lineage_capture_stage_root,
                            "recorded-read metadata capture root") ==
                 basis["current_roots"]["metadata_capture_root"] and
             _absolute_path(source_root,
                            "recorded-read selected Source root") ==
                 basis["current_roots"]["source_root"],
             "recorded-read caller roots differ from its selected basis/plan")
    root_resource = _exact(
        root_resource_declaration, RECORDED_READ_GPG_RESOURCE_FIELDS_V2,
        "Root recorded-read GPG auxiliary reservation",
    )
    resource_body = {key: value for key, value in root_resource.items()
                     if key != "resource_sha256"}
    _require(root_resource["maximum_window_seconds"] ==
             plan["timeout_declaration"]["maximum_io_window_seconds"] and
             root_resource["schema"] == RECORDED_READ_GPG_RESOURCE_SCHEMA_V2 and
             root_resource["resource_sha256"] ==
                 _sha(_canonical(resource_body)),
             "recorded-read Root GPG window differs from its finite Source plan")
    source_scratch = plan["scratch_declaration"]["root"]
    protected_roots = list(basis["current_roots"].values()) + [
        source_scratch, row["archive_source5_root"],
    ]
    root_aux_path = _absolute_path(
        root_resource["scratch_root"], "Root recorded-read auxiliary scratch root",
    )
    protected_roots.append(str(root_output_context["root"]))
    for protected in protected_roots:
        _require(not plan_module._paths_overlap(root_aux_path, protected),
                 "Root recorded-read GPG scratch overlaps a Source/current/archive root")
    _require(type(window_deadline_ns) is int and
             time.monotonic_ns() < window_deadline_ns and
             window_deadline_ns < (1 << 63),
             "recorded-read Root window deadline is absent or expired")

    def check_window(label: str) -> None:
        _require(time.monotonic_ns() < window_deadline_ns and
                 (cancel_event is None or not cancel_event.is_set()),
                 f"recorded-read Root operation exceeded or cancelled {label}")

    auxiliary_root_fd = _open_dir_path(
        root_aux_path, "Root recorded-read auxiliary scratch root",
        private_final=True,
    )
    try:
        auxiliary_info = os.fstat(auxiliary_root_fd)
        auxiliary_space = os.fstatvfs(auxiliary_root_fd)
        _require(auxiliary_info.st_dev == root_resource["device"] and
                 auxiliary_space.f_bavail * auxiliary_space.f_frsize >=
                     root_resource["reserved_bytes"] and
                 auxiliary_space.f_favail >= root_resource["reserved_inodes"],
                 "Root recorded-read GPG auxiliary root lacks its exact declared resources")
    finally:
        os.close(auxiliary_root_fd)

    _require(row["owner_host_id"] == row["job"]["host_id"] and
             row["job"] == {
                 key: value for key, value in row["job"].items()
             } and row["job"]["phase"] == "exploration" and
             row["job_index"] == ordinal % plan_module.READ_JOB_COUNT_PER_HOST and
             row["owner_host_id"] == plan["cohort_hosts"][
                 ordinal // plan_module.READ_JOB_COUNT_PER_HOST
             ],
             "recorded-read requested window is outside its ordered Source cohort row")
    _require(request_raw == _canonical(outer_request) and
             request_raw == _read_absolute_private_file(
                 Path(row["session_paths"]["request"]),
                 row["resource_bounds"]["outer_request_bytes"],
                 "recorded-read current persisted request",
                 deadline_ns=window_deadline_ns,
                 cancel_event=cancel_event,
             )[0],
             "recorded-read request bytes differ from the exact persisted current slot")
    source_graph = _recorded_pre_manifest_source_closure(
        basis, basis_pin_value, selected_source_manifest_raw,
        lineage_capture_manifest_raw, lineage_capture_stage_root,
        source_root, plan_module, deadline_ns=window_deadline_ns,
        cancel_event=cancel_event,
    )
    reader = source_graph["reader"]
    try:
        check_window("Source metadata closure")
        source_graph["source_modules"]["source5_campaign"]._source5_recorded_read_session_documents(
            basis, basis_pin_value, plan, plan_pin, plan_module,
            create_missing=False, cancel_event=cancel_event,
            deadline_ns=window_deadline_ns,
        )
        owner = row["owner_host_id"]
        job_index = row["job_index"]
        proof = source_graph["proofs"][owner]
        _require(type(proof["index_rows"]) is list and
                 len(proof["index_rows"]) == plan_module.READ_JOB_COUNT_PER_HOST,
                 "recorded-read Source rich proof lost its exact owner schedule")
        index_row = proof["index_rows"][job_index]
        _require(index_row["row_index"] == job_index and
                 index_row["job"] == row["job"] and
                 index_row["job_sha256"] == row["job_sha256"],
                 "recorded-read plan row differs from its exact Source lineage index")
        durable_pins = row["original_pins"]
        raw_pin_names = {
            "job_record": index_row["job_record_pin"],
            "request": index_row["archive_pins"]["request_pin"],
            "checkpoint": index_row["archive_pins"]["checkpoint_pin"],
            "object_manifest": index_row["archive_pins"]["object_manifest_pin"],
            "ack": index_row["archive_pins"]["ack_pin"],
            "signature": index_row["archive_pins"]["signature_pin"],
        }
        for name, indexed_pin in raw_pin_names.items():
            indexed_raw = _pin_raw(indexed_pin,
                                   f"recorded-read Source index {name} pin")
            planned_pin = durable_pins[name]
            _require(planned_pin["path"] == indexed_raw["path"] and
                     planned_pin["raw_sha256"] == indexed_raw["raw_sha256"],
                     f"recorded-read plan {name} origin differs from its Source index")
            if name in {"request", "checkpoint", "object_manifest", "ack"}:
                _require(planned_pin["semantic_sha256"] ==
                         indexed_pin["semantic_sha256"],
                         f"recorded-read plan {name} semantic pin differs from its Source index")
        header_raw = reader.read(
            basis["ancestor_pins"][owner]["bridge_header"], 256 * 1024,
        )
        header = _parse_canonical(header_raw,
                                  "recorded-read owner bridge header",
                                  maximum_bytes=256 * 1024)
        initial = header["initial"]
        old_source_pin = source_graph["source_pins"][owner]
        old_source_raw = reader.read({
            "path": old_source_pin["path"],
            "raw_sha256": old_source_pin["raw_sha256"],
        }, MAX_SOURCE_MANIFEST_BYTES)
        old_execution_pin = _pin(
            initial["execution_manifest_pin"],
            "recorded-read original preparatory execution pin",
        )
        old_plan_pin = _pin(initial["plan_pin"],
                            "recorded-read original preparatory Plan pin")
        old_spec_pin = _pin(initial["spec_pin"],
                            "recorded-read original preparatory Spec pin")
        old_width_pin = _pin(initial["journal_width_pin"],
                             "recorded-read original preparatory width pin")
        old_budget_pin = _pin(initial["host_budget_pin"],
                              "recorded-read original H6 budget pin")
        old_execution_raw = reader.read({
            "path": old_execution_pin["path"],
            "raw_sha256": old_execution_pin["raw_sha256"],
        }, MAX_PLAN_BYTES)
        old_plan_raw = reader.read({
            "path": old_plan_pin["path"],
            "raw_sha256": old_plan_pin["raw_sha256"],
        }, MAX_PLAN_BYTES)
        old_spec_raw = reader.read({
            "path": old_spec_pin["path"],
            "raw_sha256": old_spec_pin["raw_sha256"],
        }, PREPARATORY_MAX_SPEC_BYTES)
        old_width_raw = reader.read({
            "path": old_width_pin["path"],
            "raw_sha256": old_width_pin["raw_sha256"],
        }, PREPARATORY_MAX_WIDTH_BYTES)
        old_budget_raw = reader.read({
            "path": old_budget_pin["path"],
            "raw_sha256": old_budget_pin["raw_sha256"],
        }, PREPARATORY_MAX_BUDGET_BYTES)
        original_context = _validate_context({
            "schema": CONTEXT_SCHEMA_V1,
            "campaign_id": basis["campaign_id"], "host_id": owner,
            "phase": "exploration", "job_index": job_index,
            "source_manifest_pin": source_graph["source_pins"][owner],
            "execution_manifest_pin": old_execution_pin,
            "plan_pin": old_plan_pin,
            "resource_budget_pin": old_budget_pin,
            "predecessor_ack_pin": None,
            "authorized_signer_fingerprint": initial["signer_fingerprint"],
        })
        # This validates all 360 old H6 rows, the typed catalogue and the
        # Source-derived per-job transport envelope for the selected row.
        prepared_profile = validate_preparatory_budget_profile_v1(
            old_budget_raw, original_context,
            source_manifest_raw=old_source_raw,
            execution_manifest_raw=old_execution_raw,
            plan_raw=old_plan_raw,
            journal_width_contract_raw=old_width_raw,
            spec_raw=old_spec_raw,
            captured_preparatory_artifact_reader=reader.read,
        )
        old_budget = prepared_profile["budget"]
        catalogue_module = prepared_profile["catalogue_module"]
        iterator_name = prepared_profile["catalogue_iterator_name"]
        old_rows = list(catalogue_module[iterator_name](
            old_budget["path_catalogue"], prepared_profile["catalogue_reader"],
        ))
        old_rows_by_path = {item["path"]: item for item in old_rows}
        _require(len(old_rows_by_path) == len(old_rows),
                 "recorded-read validated H6 catalogue repeats an exact row path")
        read_schedule = old_budget["read_schedule"]
        _require(len(read_schedule) == plan_module.READ_JOB_COUNT_PER_HOST and
                 read_schedule[job_index]["job"] == row["job"] and
                 read_schedule[job_index]["job_index"] == job_index,
                 "recorded-read plan row differs from the actual validated H6 budget schedule")
        projected_caps = catalogue_module[
            "project_fixed_pair_archive_readback_caps"
        ](catalogue_module[iterator_name](
            old_budget["path_catalogue"], prepared_profile["catalogue_reader"],
        ))
        cap_key = ("exploration", row["job"]["run_id"])
        _require(cap_key in projected_caps and
                 row["recomputed_source_caps"] ==
                     _recorded_read_source_cap_projection(
                         projected_caps[cap_key],
                     ) and
                 row["source_budget_schedule_caps"] ==
                     read_schedule[job_index]["caps"],
                 "recorded-read planned old cap differs from the typed Source H6 projections")
        initial_output_root = _absolute_path(
            header["initial_output_root"],
            "recorded-read owner initial H6 output root",
        )
        role_pin_names = {
            "source5_job_record": index_row["job_record_pin"],
            "source5_checkpoint_request": index_row["archive_pins"]["request_pin"],
            "source5_checkpoint": index_row["archive_pins"]["checkpoint_pin"],
            "source5_object_manifest": index_row["archive_pins"]["object_manifest_pin"],
            "source5_archive_ack": index_row["archive_pins"]["ack_pin"],
            "source5_archive_signature": index_row["archive_pins"]["signature_pin"],
        }
        for role, indexed_pin in role_pin_names.items():
            actual_pin, reservation_row = catalogue_module[
                "source5_indexed_reservation_binding_v1"
            ](
                index_row, indexed_pin, role, row["job"],
                initial_output_root=initial_output_root,
                campaign_id=basis["campaign_id"], selected_host=owner,
                old_rows=old_rows_by_path,
            )
            plan_binding = row["indexed_reservation_bindings"][role]
            _require(reservation_row == plan_binding and
                     actual_pin["path"] == indexed_pin["path"] and
                     actual_pin["raw_sha256"] == indexed_pin["raw_sha256"],
                     f"recorded-read {role} binding differs from the actual typed Source helper")
        manifest_pin = durable_pins["object_manifest"]
        manifest_raw = reader.read({
            "path": manifest_pin["path"],
            "raw_sha256": manifest_pin["raw_sha256"],
        }, MAX_JSON_BYTES)
        manifest = _recorded_read_archive_manifest(
            manifest_raw, manifest_pin, row,
            Path(row["archive_source5_root"]),
        )
        host_receipts = [obj for obj in manifest["objects"]
                         if obj["role"] == "fixed_pair_host_receipt"]
        _require(len(host_receipts) == 1 and
                 row["host_receipt_pin"] == {
                     "path": host_receipts[0]["origin_path"],
                     "raw_sha256": host_receipts[0]["raw_sha256"],
                     "host_verification_sha256":
                         host_receipts[0]["semantic_sha256"],
                 }, "recorded-read fixed host-receipt pin differs from its signed manifest")
        owner_source = source_graph["source_docs"][owner]
        selected_source = source_graph["source_docs"][basis["consumer_host_id"]]
        selected_files = {
            item["path"]: item for item in selected_source["source"]["files"]
            if type(item) is dict and type(item.get("path")) is str
        }
        owner_files = {
            item["path"]: item for item in owner_source["source"]["files"]
            if type(item) is dict and type(item.get("path")) is str
        }
        for path in (
            SOURCE5_BUDGET_VALIDATOR_PATH,
            PREPARATORY_OWNER_CATALOGUE_PATH,
            PREPARATORY_BUDGET_VALIDATOR_PATH,
            PREPARATORY_CAMPAIGN_SOURCE_PATH,
            PREPARATORY_INPUT_PREPARATION_SOURCE_PATH,
        ):
            _require(path in selected_files and path in owner_files and
                     selected_files[path].get("sha256") ==
                         owner_files[path].get("sha256"),
                     "recorded-read owner Source has a different validator ELF; peer binary loading is refused")
        def read_capture(pin_value: object, maximum_bytes: int) -> bytes:
            pin = _pin_raw(pin_value, "recorded-read exact capture request")
            return reader.read(pin, maximum_bytes)

        raw_artifacts = {
            name: reader.read({
                              "path": durable_pins[name]["path"],
                              "raw_sha256": durable_pins[name]["raw_sha256"],
                          },
                              (MAX_PLAN_BYTES if name in {"job_record", "checkpoint"}
                               else MAX_JSON_BYTES))
            for name in ("job_record", "request", "checkpoint", "object_manifest",
                         "ack", "signature")
        }
        def parse_captured(name: str) -> dict[str, Any]:
            raw = raw_artifacts[name]
            value = _parse_canonical(raw, f"recorded-read captured {name}")
            return value
        checkpoint = parse_captured("checkpoint")
        job_record = parse_captured("job_record")
        object_manifest = parse_captured("object_manifest")
        ack = parse_captured("ack")
        signer_context_pin = _pin(
            initial["signer_context_pin"],
            "recorded-read original signer-context pin",
        )
        signer_context_raw = reader.read({
            "path": signer_context_pin["path"],
            "raw_sha256": signer_context_pin["raw_sha256"],
        }, MAX_ARCHIVE_SIGNER_CONTEXT_BYTES)
        signature_pin = durable_pins["signature"]
        signature_raw = raw_artifacts["signature"]
        keyring_reader = lambda pin, maximum: read_capture(pin, maximum)
        gpgv_reader = lambda pin, maximum: read_capture(pin, maximum)
        remaining_window_seconds = (
            window_deadline_ns - time.monotonic_ns()
        ) // 1_000_000_000
        _require(remaining_window_seconds > 0,
                 "recorded-read Root source verification has no window time remaining")
        _check_recorded_read_root_resource_pair(
            root_output_context, root_resource,
            deadline_ns=window_deadline_ns, cancel_event=cancel_event,
        )
        check_window("before captured GPG verification")
        try:
            verify_signed_ack_for_recorded_read_v1(
                durable_pins["checkpoint"], checkpoint,
                raw_artifacts["checkpoint"], raw_artifacts["request"],
                old_budget_raw, durable_pins["job_record"],
                raw_artifacts["job_record"], old_plan_raw,
                durable_pins["object_manifest"], object_manifest,
                raw_artifacts["object_manifest"],
                durable_pins["ack"], ack, raw_artifacts["ack"],
                signature_pin, signature_raw,
                signer_context_pin, signer_context_raw,
                old_execution_pin, old_execution_raw,
                expected_ack_pin=durable_pins["ack"],
                expected_run_id=row["job"]["run_id"],
                journal_width_contract_raw=old_width_raw,
                source_manifest_raw=old_source_raw,
                captured_keyring_reader=keyring_reader,
                captured_gpgv_reader=gpgv_reader,
                captured_preparatory_artifact_reader=read_capture,
                root_auxiliary_resource_declaration=root_resource,
                maximum_io_window_seconds=min(
                    remaining_window_seconds,
                    root_resource["maximum_window_seconds"],
                ),
                recorded_deadline_ns=window_deadline_ns,
                cancel_event=cancel_event,
            )
        except Exception as error:
            raise EvidenceArchiveError(
                f"actual Source signed ACK verifier rejected recorded-read row {ordinal}: {error}",
            ) from error
        legacy_request = outer_request["legacy_request"]
        legacy_request_raw = _canonical(
            legacy_request,
            maximum_bytes=MAX_ARCHIVE_READ_METADATA_BYTES,
        )
        tar_path = Path(_absolute_path(
            bundle_output_path, "recorded-read Root bundle output slot",
        ))
        response_path = Path(_absolute_path(
            response_output_path, "recorded-read Root response output slot",
        ))
        _require(tar_path == Path(root_output_context["paths"]["bundle"]) and
                 response_path == Path(root_output_context["paths"]["response"]) and
                 tar_path.name == "response.tar.incoming" and
                 response_path.name == "response.json.incoming" and
                 not response_path.exists() and not response_path.is_symlink(),
                 "recorded-read Root output path differs from its exact incoming slots")
        check_window("before signed object materialization")
        tar_pin = _write_recorded_preparation_read_tar_v1(
            legacy_request, manifest, source_graph["source_modules"][
                "source5_campaign"], row["archive_source5_root"], tar_path,
            row["resource_bounds"]["tar_bytes"],
            allocation_block_bytes=root_output_context[
                "allocation_block_bytes"],
            deadline_ns=window_deadline_ns,
            cancel_event=cancel_event,
        )
        legacy_response, legacy_response_raw, _legacy_response_pin = \
            source_graph["source_modules"]["source5_campaign"].build_source5_archive_read_response(
                legacy_request_raw, tar_pin["raw_sha256"],
                tar_pin["byte_count"],
            )
        _outer, response_raw, _outer_pin = \
            plan_module.build_recorded_preparation_read_response_v2(
                request_raw, legacy_response, legacy_response_raw,
                basis, basis_pin_value, plan, plan_pin, window_chunk,
            )
        check_window("before outer response write")
        response_parent_fd = _open_dir_path(
            response_path.parent,
            "recorded-read Root response incoming parent",
            private_final=True,
        )
        try:
            output_pin = _write_recorded_read_output_bytes(
                response_parent_fd, response_path.name, response_raw,
                row["resource_bounds"]["outer_response_bytes"],
                "recorded-read Root outer response",
                allocation_block_bytes=root_output_context[
                    "allocation_block_bytes"],
                deadline_ns=window_deadline_ns,
                cancel_event=cancel_event,
            )
            reopened, reopened_sha, _ = _read_at(
                response_parent_fd, response_path.name,
                row["resource_bounds"]["outer_response_bytes"],
                "recorded-read Root outer response", expected_bytes=len(response_raw),
            )
            _require(reopened == response_raw and
                     reopened_sha == output_pin["raw_sha256"],
                     "recorded-read Root response failed independent reopen")
        finally:
            os.close(response_parent_fd)
        _verify_recorded_read_root_output_directory_growth(root_output_context)
        return {
            "schema": "allocatbelt.application-source5-recorded-preparation-read-window-output.v1",
            "response_pin": {
                "path": str(response_path),
                "raw_sha256": output_pin["raw_sha256"],
                "semantic_sha256": _outer["response_sha256"],
            },
            "bundle_pin": {
                "path": str(tar_path), "raw_sha256": tar_pin["raw_sha256"],
                "byte_count": tar_pin["byte_count"],
            },
        }
    finally:
        reader.close()


def serve_recorded_preparation_read_window_v1(
    request_raw: bytes, *, basis_raw: bytes, read_plan_raw: bytes,
    session_descriptor_raw: bytes, source_root: str,
    selected_source_manifest_raw: bytes,
    lineage_capture_manifest_raw: bytes,
    lineage_capture_stage_root: str, archive_source5_root: str,
    response_output_path: str, bundle_output_path: str,
    root_resource_declaration: object,
    root_output_resource_declaration: object,
    cancel_event=None,
) -> dict[str, Any]:
    """Serve one real Source-verified read into bounded current Root slots.

    This is the one-window Root materializer. It rebuilds the SourceV2 and
    Bridge closure, validates the selected actual old H6 row/cap, and freshly
    verifies its captured GPG signature. The SourceA 720-window plan rebuild
    and any admission authority remain separate.
    """
    _require(type(request_raw) is bytes and type(basis_raw) is bytes and
             type(read_plan_raw) is bytes and
             type(session_descriptor_raw) is bytes and
             (cancel_event is None or
              callable(getattr(cancel_event, "is_set", None))),
             "recorded-read Root inputs or cancellation token are malformed")
    basis = _parse_canonical(basis_raw, "recorded-read basis",
                             maximum_bytes=MAX_ARCHIVE_READ_METADATA_BYTES)
    plan = _parse_canonical(read_plan_raw, "recorded-read plan",
                            maximum_bytes=MAX_ARCHIVE_READ_METADATA_BYTES)
    session = _parse_canonical(session_descriptor_raw,
                               "recorded-read session descriptor",
                               maximum_bytes=MAX_ARCHIVE_READ_METADATA_BYTES)
    consumer = basis.get("consumer_host_id")
    source_pin = basis.get("source_manifest_pins", {}).get(consumer)
    _require(type(source_pin) is dict and
             type(selected_source_manifest_raw) is bytes and
             _sha(selected_source_manifest_raw) == source_pin.get("raw_sha256"),
             "recorded-read selected Source bytes differ from the basis")
    namespace = _recorded_pre_manifest_typed_module(
        selected_source_manifest_raw, source_pin,
        basis["source_module_pins"][consumer],
        SOURCE5_RECORDED_READ_PLAN_PATH, source_root, source_root,
        namespace_name="_allocatbelt_recorded_read_plan_api",
    )
    plan_module = sys.modules[namespace["__name__"]]
    session = _exact(session, {
        "schema", "basis_pin", "read_plan_pin", "session_nonce",
        "consumer_host_id", "operation_kind", "current_journal_frontier",
        "session_sha256",
    }, "recorded-read session descriptor")
    session_body = {key: value for key, value in session.items()
                    if key != "session_sha256"}
    _require(session["schema"] == plan_module.SESSION_DESCRIPTOR_SCHEMA_V2 and
             session["session_sha256"] == _sha(_canonical(session_body)),
             "recorded-read session descriptor digest differs")
    basis_pin = _pin(session["basis_pin"], "recorded-read basis pin")
    plan_pin = _pin(session["read_plan_pin"], "recorded-read plan pin")
    checked_basis, checked_basis_pin, _hosts = plan_module._validate_basis(
        basis, basis_pin,
    )
    _require(checked_basis == basis and checked_basis_pin == basis_pin and
             plan_module.recorded_preparation_read_plan_pin_v2(plan) == plan_pin and
             plan["basis_pin"] == basis_pin and
             session["session_nonce"] == plan["session_nonce"] and
             session["consumer_host_id"] == consumer and
             session["operation_kind"] == basis["operation_kind"] and
             session["current_journal_frontier"] ==
                 basis["current_journal_frontier"],
             "recorded-read session, basis and plan do not close")
    descriptor, descriptor_raw, descriptor_pin = \
        plan_module.build_recorded_preparation_read_session_descriptor_v2(
            plan, plan_pin,
        )
    _require(descriptor_raw == session_descriptor_raw,
             "recorded-read session descriptor differs from its plan")
    for pin, raw, label in (
        (basis_pin, basis_raw, "basis"), (plan_pin, read_plan_raw, "plan"),
        (descriptor_pin, session_descriptor_raw, "session descriptor"),
    ):
        persisted, digest, _info = _read_absolute_private_file(
            Path(pin["path"]), MAX_ARCHIVE_READ_METADATA_BYTES,
            f"recorded-read persisted {label}",
        )
        _require(persisted == raw and digest == pin["raw_sha256"],
                 f"recorded-read persisted {label} raw pin differs")
    request_header = _parse_canonical(
        request_raw, "recorded-read outer request header",
        maximum_bytes=MAX_ARCHIVE_READ_METADATA_BYTES,
    )
    ordinal = plan_module._uint(
        request_header.get("read_ordinal"),
        "recorded-read request ordinal",
        maximum=plan_module.READ_WINDOW_COUNT - 1,
    )
    start_ns = time.monotonic_ns()
    deadline_ns = start_ns + plan["timeout_declaration"][
        "maximum_io_window_seconds"] * 1_000_000_000
    _require(deadline_ns < (1 << 63),
             "Root recorded-read deadline exceeds monotonic arithmetic")
    window_chunk, row = _recorded_read_window_chunk(
        plan, plan_pin, plan_module, ordinal,
        deadline_ns=deadline_ns, cancel_event=cancel_event,
    )
    outer_request = plan_module.validate_recorded_preparation_read_request_v2(
        request_raw, basis, basis_pin, plan, plan_pin, window_chunk,
    )
    _request, expected_request_raw, expected_request_pin = \
        plan_module.build_recorded_preparation_read_request_v2(
            basis, basis_pin, plan, plan_pin, ordinal, window_chunk,
        )
    _require(expected_request_raw == request_raw,
             "recorded-read request is not the deterministic Source request")
    persisted_request, request_sha, _info = _read_absolute_private_file(
        Path(row["session_paths"]["request"]),
        row["resource_bounds"]["outer_request_bytes"],
        "recorded-read current request",
        deadline_ns=deadline_ns, cancel_event=cancel_event,
    )
    _require(persisted_request == request_raw and
             request_sha == expected_request_pin["raw_sha256"],
             "recorded-read current request slot differs")
    root_output = _recorded_read_root_output_context(
        root_output_resource_declaration, basis, basis_pin, plan, plan_pin,
        ordinal, window_chunk, plan_module,
    )
    _require(_absolute_path(response_output_path,
                            "Root response output path") ==
                 root_output["paths"]["response"] and
             _absolute_path(bundle_output_path,
                            "Root bundle output path") ==
                 root_output["paths"]["bundle"],
             "Root output arguments differ from their separately reserved Root slots")
    _prepare_recorded_read_root_output_dirs(root_output)
    failure_path = Path(root_output["paths"]["failure_receipt"])
    _require(not failure_path.exists() and not failure_path.is_symlink(),
             "Root recorded-read nonce has a retained failure receipt")
    root_ledger_fd = _open_recorded_read_root_ledger(root_output)
    request_pin = {key: expected_request_pin[key] for key in (
        "path", "raw_sha256", "semantic_sha256",
    )}
    reader = None
    try:
        cursor, pending, previous = _recorded_root_control_state(
            root_ledger_fd, root_output, basis, basis_pin, plan, plan_pin,
            plan_module, deadline_ns=deadline_ns,
            cancel_event=cancel_event,
        )
        _require(ordinal == cursor and
                 (pending is None or pending == request_pin),
                 "Root recorded-read request is not the next current event")
        if pending is None:
            accepted = _recorded_root_control_event(
                basis, basis_pin, plan, plan_pin, row, 2 * ordinal + 1,
                "request_accepted", request_pin, root_output["paths"],
            )
            previous = _append_recorded_root_control_event(
                root_ledger_fd, accepted, previous, root_output,
                deadline_ns=deadline_ns, cancel_event=cancel_event,
            )
        result = _serve_recorded_preparation_read_window_core_v1(
            request_raw, basis_raw=basis_raw,
            read_plan_raw=read_plan_raw,
            session_descriptor_raw=session_descriptor_raw,
            source_root=source_root,
            selected_source_manifest_raw=selected_source_manifest_raw,
            lineage_capture_manifest_raw=lineage_capture_manifest_raw,
            lineage_capture_stage_root=lineage_capture_stage_root,
            archive_source5_root=archive_source5_root,
            response_output_path=root_output["paths"]["response"],
            bundle_output_path=root_output["paths"]["bundle"],
            root_resource_declaration=root_resource_declaration,
            root_output_context=root_output,
            window_deadline_ns=deadline_ns,
            cancel_event=cancel_event,
        )
        completed = _recorded_root_control_event(
            basis, basis_pin, plan, plan_pin, row, 2 * ordinal + 2,
            "response_published", request_pin, root_output["paths"],
            result["response_pin"], result["bundle_pin"],
        )
        _append_recorded_root_control_event(
            root_ledger_fd, completed, previous, root_output,
            deadline_ns=deadline_ns, cancel_event=cancel_event,
        )
        return result
    except BaseException as error:
        retained = any(
            Path(path).exists() or Path(path).is_symlink()
            for path in (root_output["paths"]["response"],
                         root_output["paths"]["bundle"])
        )
        try:
            _write_recorded_root_failure_receipt(
                root_output, basis, basis_pin, plan, plan_pin, ordinal, row,
                retained_window=retained, deadline_ns=deadline_ns,
                cancel_event=cancel_event,
            )
        except BaseException as receipt_error:
            raise EvidenceArchiveError(
                f"Root recorded-read failure receipt could not be stored: {receipt_error}",
            ) from error
        raise
    finally:
        if reader is not None:
            reader.close()
        os.close(root_ledger_fd)


def release_recorded_preparation_read_root_output_v1(
    basis_raw: bytes, read_plan_raw: bytes, session_descriptor_raw: bytes,
    source_root: str, selected_source_manifest_raw: bytes,
    root_output_resource_declaration: object, read_ordinal: object,
    response_pin_value: object, bundle_pin_value: object,
) -> dict[str, Any]:
    """Free one exact Root spool only after the caller transferred its pins."""
    basis = _parse_canonical(basis_raw, "recorded-read release basis",
                             maximum_bytes=MAX_ARCHIVE_READ_METADATA_BYTES)
    plan = _parse_canonical(read_plan_raw, "recorded-read release plan",
                            maximum_bytes=MAX_ARCHIVE_READ_METADATA_BYTES)
    session = _parse_canonical(session_descriptor_raw,
                               "recorded-read release session",
                               maximum_bytes=MAX_ARCHIVE_READ_METADATA_BYTES)
    consumer = basis.get("consumer_host_id")
    source_pin = basis.get("source_manifest_pins", {}).get(consumer)
    _require(type(source_pin) is dict and
             _sha(selected_source_manifest_raw) == source_pin.get("raw_sha256"),
             "recorded-read Root release selected Source pin differs")
    namespace = _recorded_pre_manifest_typed_module(
        selected_source_manifest_raw, source_pin,
        basis["source_module_pins"][consumer],
        SOURCE5_RECORDED_READ_PLAN_PATH, source_root, source_root,
        namespace_name="_allocatbelt_recorded_read_root_release_plan",
    )
    module = sys.modules[namespace["__name__"]]
    basis_pin = _pin(session["basis_pin"], "Root release basis pin")
    plan_pin = _pin(session["read_plan_pin"], "Root release plan pin")
    _require(module._validate_basis(basis, basis_pin)[0] == basis and
             module.recorded_preparation_read_plan_pin_v2(plan) == plan_pin and
             plan["basis_pin"] == basis_pin,
             "recorded-read Root release basis/plan pins differ")
    _require(session_descriptor_raw ==
             module.build_recorded_preparation_read_session_descriptor_v2(
                 plan, plan_pin,
             )[1],
             "recorded-read Root release session descriptor differs")
    ordinal = module._uint(read_ordinal, "Root output release ordinal",
                           maximum=module.READ_WINDOW_COUNT - 1)
    deadline_ns = time.monotonic_ns() + plan["timeout_declaration"][
        "maximum_io_window_seconds"] * 1_000_000_000
    _require(deadline_ns < (1 << 63),
             "Root output release deadline exceeds monotonic arithmetic")
    window_chunk, row = _recorded_read_window_chunk(
        plan, plan_pin, module, ordinal, deadline_ns=deadline_ns,
    )
    context = _recorded_read_root_output_context(
        root_output_resource_declaration, basis, basis_pin, plan, plan_pin,
        ordinal, window_chunk, module,
    )
    response_pin = _pin(response_pin_value,
                        "Root output release response pin")
    bundle_pin = _exact(bundle_pin_value, {
        "path", "raw_sha256", "byte_count",
    }, "Root output release bundle pin")
    _require(response_pin["path"] == context["paths"]["response"] and
             bundle_pin["path"] == context["paths"]["bundle"],
             "Root output release paths differ from its nonce-bound slots")
    request, request_raw, request_pin = \
        module.build_recorded_preparation_read_request_v2(
            basis, basis_pin, plan, plan_pin, ordinal, window_chunk,
        )
    request_pin3 = {key: request_pin[key] for key in (
        "path", "raw_sha256", "semantic_sha256",
    )}
    request_saved, request_sha, _info = _read_absolute_private_file(
        Path(request_pin["path"]), row["resource_bounds"]["outer_request_bytes"],
        "Root output release current Source request",
        deadline_ns=deadline_ns,
    )
    _require(request_saved == request_raw and request_sha == request_pin["raw_sha256"],
             "Root output release Source request differs from its exact plan")
    ledger_fd = _open_recorded_read_root_ledger(context)
    try:
        cursor, pending, _previous = _recorded_root_control_state(
            ledger_fd, context, basis, basis_pin, plan, plan_pin, module,
            deadline_ns=deadline_ns,
        )
        _require(cursor > ordinal and pending is None,
                 "Root output release row is not a completed Root control pair")
        os.lseek(ledger_fd, 0, os.SEEK_SET)
        ledger_info = os.fstat(ledger_fd)
        ledger_raw = bytearray()
        while len(ledger_raw) < ledger_info.st_size:
            _require(time.monotonic_ns() < deadline_ns,
                     "Root output release ledger read exceeded its window")
            block = os.read(ledger_fd, min(
                COPY_BLOCK_BYTES, ledger_info.st_size - len(ledger_raw),
            ))
            _require(bool(block), "Root output release ledger shortened")
            ledger_raw.extend(block)
        lines = bytes(ledger_raw).splitlines()
        _require(len(lines) >= 2 * ordinal + 2,
                 "Root output release ledger omits its completed response")
        response_event = json.loads(lines[2 * ordinal + 1].decode("ascii"))["record"]
        event_response_pin = response_event["response_pin"]
        event_bundle_pin = response_event["bundle_pin"]
        _require(event_response_pin == response_pin and
                 event_bundle_pin == bundle_pin and
                 response_event["request_pin"] == request_pin3,
                 "Root output release pins differ from its append-only current ledger")
    finally:
        os.close(ledger_fd)
    response_raw, response_sha, _response_info = _read_absolute_private_file(
        Path(response_pin["path"]), row["resource_bounds"]["outer_response_bytes"],
        "Root output release response",
        deadline_ns=deadline_ns,
    )
    response = module.validate_recorded_preparation_read_response_v2(
        response_raw, request_raw, basis, basis_pin, plan, plan_pin,
        window_chunk,
    )
    _require(response_sha == response_pin["raw_sha256"] and
             response["response_sha256"] == response_pin["semantic_sha256"],
             "Root output release response raw/semantic pins differ")
    bundle_parent = _open_dir_path(
        Path(bundle_pin["path"]).parent,
        "Root output release bundle parent", private_final=True,
    )
    cleanup_started = False
    try:
        bundle_name = Path(bundle_pin["path"]).name
        _raw, bundle_sha, bundle_info = _read_at(
            bundle_parent, bundle_name,
            row["resource_bounds"]["tar_bytes"],
            "Root output release bundle", expected_bytes=bundle_pin["byte_count"],
            collect=False, deadline_ns=deadline_ns,
        )
        _require(bundle_sha == bundle_pin["raw_sha256"] and
                 bundle_info.st_uid == os.getuid() and
                 stat.S_IMODE(bundle_info.st_mode) == 0o600 and
                 bundle_info.st_nlink == 1 and
                 bundle_info.st_size == row["resource_bounds"]["tar_bytes"],
                 "Root output release bundle differs from its exact Root pin")
        cleanup_started = True
        current_bundle = os.stat(bundle_name, dir_fd=bundle_parent,
                                 follow_symlinks=False)
        _require(_info_key(current_bundle) == _info_key(bundle_info),
                 "Root output release bundle changed before exact unlink")
        os.unlink(bundle_name, dir_fd=bundle_parent)
        response_parent = _open_dir_path(
            Path(response_pin["path"]).parent,
            "Root output release response parent", private_final=True,
        )
        try:
            response_name = Path(response_pin["path"]).name
            _raw, response_raw_sha, response_info = _read_at(
                response_parent, response_name,
                row["resource_bounds"]["outer_response_bytes"],
                "Root output release response unlink check",
                expected_bytes=len(response_raw), collect=False,
                deadline_ns=deadline_ns,
            )
            current_response = os.stat(response_name, dir_fd=response_parent,
                                       follow_symlinks=False)
            _require(response_raw_sha == response_pin["raw_sha256"] and
                     _info_key(current_response) == _info_key(response_info),
                     "Root output release response changed before exact unlink")
            os.unlink(response_name, dir_fd=response_parent)
            os.fsync(response_parent)
        finally:
            os.close(response_parent)
        os.fsync(bundle_parent)
    except BaseException:
        if cleanup_started:
            retained = any(
                Path(value).exists() or Path(value).is_symlink()
                for value in (context["paths"]["response"],
                              context["paths"]["bundle"])
            )
            context["directory_allocation_baseline"] = \
                _recorded_read_root_output_directory_baseline(context)
            _write_recorded_root_failure_receipt(
                context, basis, basis_pin, plan, plan_pin, ordinal, row,
                retained_window=retained, deadline_ns=deadline_ns,
            )
        raise
    finally:
        os.close(bundle_parent)
    return {
        "schema": "allocatbelt.application-source5-recorded-preparation-root-output-release.v1",
        "read_ordinal": ordinal,
        "response_pin": response_pin,
        "bundle_pin": bundle_pin,
    }


def _require_prepared_catalogue_storage_parity(
    budget_module: object, budget: dict[str, Any], reader,
    storage_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    expected = {row["path"]: row for row in storage_rows}
    _require(len(expected) == len(storage_rows),
             "Source-derived captured storage rows repeat a current path")
    observed: dict[str, dict[str, Any]] = {}
    try:
        for row in budget_module.iter_path_catalogue_rows_with_reader(
                budget["path_catalogue"], reader):
            expected_row = expected.get(row["path"])
            if expected_row is not None:
                _require(row["path"] not in observed and row == expected_row,
                         f"current catalogue differs from Source capture storage at {row['path']}")
                observed[row["path"]] = row
    except Exception as error:
        raise EvidenceArchiveError(
            f"current Source catalogue failed complete captured-storage parity: {error}",
        ) from error
    _require(set(observed) == set(expected),
             "current Source catalogue omits a Source-derived captured storage row")
    return budget["path_catalogue"]


def validate_prepared_exploration_budget_profile_v1(
    budget_raw: bytes, context: dict[str, Any], *,
    source_manifest_raw: bytes, execution_manifest_raw: bytes,
    plan_raw: bytes, journal_width_contract_raw: bytes, spec_raw: bytes,
    lineage_capture_manifest_raw: bytes, lineage_capture_stage_root: str,
    catalogue_chunk_paths: dict[str, str] | None = None,
    catalogue_cache_root: str | None = None, root_local: bool = False,
) -> dict[str, Any]:
    """Validate the read-only V4/V5 budget profile and closed old ancestry."""
    checked_context = _validate_context(context)
    _require(type(root_local) is bool,
             "prepared profile Root/local access mode is malformed")
    budget_pin = _pin(checked_context["resource_budget_pin"],
                      "prepared V4 budget context pin")
    _require(type(budget_raw) is bytes and
             len(budget_raw) <= PREPARATORY_MAX_BUDGET_BYTES and
             _sha(budget_raw) == budget_pin["raw_sha256"],
             "prepared V4 budget bytes differ from their exact raw pin")
    budget = _exact(_parse_canonical(
        budget_raw, "prepared V4 host evidence budget",
        maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES,
    ), HOST_BUDGET_FIELDS_V3, "prepared V4 host evidence budget")
    _require(budget.get("schema") == HOST_BUDGET_SCHEMA_V4 and
             budget.get("admission_profile") == PREPARED_EXPLORATION_ADMISSION_PROFILE and
             budget.get("execution_manifest_schema") ==
                 PREPARED_EXPLORATION_EXECUTION_SCHEMA and
             budget.get("campaign_id") == checked_context["campaign_id"] and
             budget.get("host_id") == checked_context["host_id"] and
             budget.get("budget_sha256") == budget_pin["semantic_sha256"] ==
                 _sha(_canonical({key: value for key, value in budget.items()
                                  if key != "budget_sha256"},
                                 maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES)),
             "prepared budget V4 schema/profile or semantic context pin differs")
    _prepared_exploration_primary_context(budget, budget_pin)
    original = budget["original_pins"]
    source_pins = {host: _pin(value, f"prepared {host} Source pin")
                   for host, value in original["source_manifests"].items()}
    _require(checked_context["source_manifest_pin"] ==
                 source_pins[checked_context["host_id"]] and
             checked_context["plan_pin"] == _pin(original["plan"],
                                                   "prepared budget Plan pin") and
             checked_context["execution_manifest_pin"] == _pin(
                 original["execution_manifest"],
                 "prepared budget execution pin"),
             "prepared request context does not match the budget's exact selected pins")
    _require(type(source_manifest_raw) is bytes and
             type(execution_manifest_raw) is bytes and
             type(plan_raw) is bytes and
             type(journal_width_contract_raw) is bytes and
             type(spec_raw) is bytes,
             "prepared V4 requires all six exact primary document bytes")
    source_doc = _prepared_source_document(
        source_manifest_raw, source_pins[checked_context["host_id"]],
        "selected current",
    )
    _require(source_doc["source"]["source_tree_sha256"] ==
             original["source_tree_sha256"],
             "prepared budget Source-tree pin differs from the selected current Source")
    try:
        reader, declaration, storage_rows, execution, width, budget_module = \
            _prepared_lineage_closure(
                budget, checked_context, source_manifest_raw,
                execution_manifest_raw, plan_raw, spec_raw,
                journal_width_contract_raw, lineage_capture_manifest_raw,
                lineage_capture_stage_root,
            )
    except EvidenceArchiveError:
        raise
    except Exception as error:
        raise EvidenceArchiveError(
            f"prepared V4 Source closure failed: {error}",
        ) from error
    try:
        catalogue_reader = _source_budget_catalogue_reader(
            budget, catalogue_chunk_paths, catalogue_cache_root,
            root_local=root_local,
        )
        _require(callable(getattr(budget_module,
                                  "validate_host_evidence_budget_v4", None)) and
                 callable(getattr(budget_module,
                                 "required_archive_request_schema_v1", None)),
                 "selected Source budget module lacks its exact V4 profile APIs")
        try:
            validated = budget_module.validate_host_evidence_budget_v4(
                budget, journal_width_contract_raw=journal_width_contract_raw,
                final_spec_raw=spec_raw, lineage_artifact_reader=reader,
                catalogue_row_reader=catalogue_reader,
            )
        except Exception as error:
            raise EvidenceArchiveError(
                f"selected Source V4 budget validator rejected its metadata: {error}",
            ) from error
        _require(validated == budget,
                 "selected Source V4 validator returned a changed budget projection")
        catalogue = _require_prepared_catalogue_storage_parity(
            budget_module, validated, catalogue_reader, storage_rows,
        )
        try:
            required_schema = budget_module.required_archive_request_schema_v1(
                validated, execution, checked_context,
            )
        except Exception as error:
            raise EvidenceArchiveError(
                f"selected Source request-schema hook rejected the V4 profile: {error}",
            ) from error
        _require(required_schema is None or
                 required_schema == REQUEST_SCHEMA_V3,
                 "selected Source request-schema hook returned an unknown request profile")
        return {
            "budget": validated, "catalogue": catalogue,
            "execution_manifest": execution,
            "required_request_schema": required_schema,
        }
    finally:
        reader.close()


def _preparatory_original_pins(
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Reconstruct the non-cyclic prep input pins from the exact manifest."""
    hosts = manifest.get("hosts")
    _require(type(hosts) is list and len(hosts) in (2, 3) and
             all(type(item) is str and item for item in hosts) and
             len(set(hosts)) == len(hosts),
             "preparatory manifest does not preserve a complete supported host order")
    original = _exact(manifest.get("original_inputs"), {
        "spec", "plan", "source_manifests", "campaign_artifacts_root",
    }, "preparatory original input map")
    spec_wrapper = _exact(original["spec"], {"artifact", "semantic_sha256"},
                          "preparatory initial SpecV3 wrapper")
    spec_pin = _pin({**_pin_raw(spec_wrapper["artifact"],
                               "preparatory initial SpecV3 artifact"),
                     "semantic_sha256": spec_wrapper["semantic_sha256"]},
                    "preparatory initial SpecV3 pin")
    plan_wrapper = _exact(original["plan"], {"artifact", "semantic_sha256"},
                          "preparatory initial PlanV3 wrapper")
    plan_pin = _pin({**_pin_raw(plan_wrapper["artifact"],
                               "preparatory initial PlanV3 artifact"),
                     "semantic_sha256": plan_wrapper["semantic_sha256"]},
                    "preparatory initial PlanV3 pin")
    source_wrappers = _exact(original["source_manifests"], set(hosts),
                             "preparatory original Source manifest map")
    execution_sources = _exact(manifest.get("execution_sources"), set(hosts),
                               "preparatory original Source execution map")
    source_pins: dict[str, Any] = {}
    for host in hosts:
        wrapper = _exact(source_wrappers[host], {"artifact", "semantic_sha256"},
                         f"preparatory {host} Source manifest wrapper")
        artifact = _pin_raw(wrapper["artifact"],
                            f"preparatory {host} Source manifest artifact")
        snapshot = _exact(execution_sources[host], {
            "source_root", "git_commit", "source_tree_sha256", "build_sha256",
        }, f"preparatory {host} Source execution snapshot")
        source_pins[host] = {
            **artifact,
            "semantic_sha256": _digest(
                wrapper["semantic_sha256"],
                f"preparatory {host} Source semantic digest",
            ),
            "source_tree_sha256": _digest(
                snapshot["source_tree_sha256"],
                f"preparatory {host} Source tree digest",
            ),
        }
    observed = _exact(manifest.get("observed_hosts"), set(hosts),
                      "preparatory observed-host map")
    observed_pins = {
        host: _pin_raw(_exact(observed[host], {"artifact"},
                              f"preparatory {host} observed-host wrapper")["artifact"],
                       f"preparatory {host} observed-host pin")
        for host in hosts
    }
    modules_by_host = _exact(manifest.get("modules"), set(hosts),
                             "preparatory original host module map")
    _require(type(modules_by_host[manifest["host_id"]]) is dict,
             "preparatory selected-host typed module map is malformed")
    typed_modules = {}
    for path, pin_value in sorted(modules_by_host[manifest["host_id"]].items()):
        pin = _exact(pin_value, {"path", "sha256"},
                     f"preparatory typed module {path}")
        _require(pin["path"] == path,
                 f"preparatory typed module key/path differs for {path}")
        typed_modules[path] = {
            "path": path,
            "sha256": _digest(pin["sha256"],
                              f"preparatory typed module digest {path}"),
        }
    generation = _exact(manifest.get("preparatory_capacity_generation"), {
        "completion", "provenance",
    }, "preparatory capacity generation")
    provenance = _exact(generation["provenance"], {
        "schema", "preparation_pin", "initial_spec_pin", "initial_plan_pin",
    }, "preparatory capacity provenance")
    _require(provenance["schema"] ==
             "allocatbelt.application-source5-preparatory-capacity-provenance.v1",
             "preparatory capacity provenance schema differs")
    registration = _exact(manifest.get("preparatory_capacity_registration"), {
        "completion", "host_completion", "host_verification", "ledger",
        "capacity_schedule_sha256", "registration_head",
    }, "selected preparatory capacity registration")
    ledger = _exact(registration["ledger"], {
        "path", "raw_sha256", "terminal_head",
    }, "preparatory capacity registration ledger")
    signer = _exact(manifest.get("archive_signer_contexts"),
                    {manifest["host_id"]},
                    "preparatory archive signer map")[manifest["host_id"]]
    signer_wrapper = _exact(signer, {"artifact", "semantic_sha256"},
                            "preparatory archive signer wrapper")
    _pin({**_pin_raw(signer_wrapper["artifact"],
                     "preparatory archive signer artifact"),
          "semantic_sha256": signer_wrapper["semantic_sha256"]},
         "preparatory archive signer context pin")
    completion = _pin(generation["completion"],
                      "preparatory capacity generation completion")
    return {
        "preparation": _pin_raw(provenance["preparation_pin"],
                                 "preparatory intent pin"),
        "capacity_generation": {
            **completion,
            "provenance": provenance,
        },
        "initial_spec": spec_pin,
        "initial_plan": plan_pin,
        "source_manifests": source_pins,
        "observed_hosts": observed_pins,
        "typed_modules": typed_modules,
        "archive_signer_context": signer,
        "capacity_registration": {
            "registration_head": _digest(
                registration["registration_head"],
                "preparatory registration head",
            ),
            "capacity_schedule_sha256": _digest(
                registration["capacity_schedule_sha256"],
                "preparatory capacity schedule digest",
            ),
            "ledger": ledger,
        },
        "execution_basis_sha256": _digest(
            manifest["preparatory_execution_basis_sha256"],
            "preparatory execution basis digest",
        ),
    }


def _load_preparatory_catalogue_modules(
    source_manifest_raw: bytes, execution_manifest_raw: bytes,
    context: dict[str, Any], original_pins: dict[str, Any],
) -> tuple[dict[str, Any], Any, Any]:
    """Load both catalogue algorithms from this host's exact typed Source."""
    selected: dict[str, dict[str, Any]] = {}
    for module_path, namespace_name in (
        (SOURCE5_BUDGET_VALIDATOR_PATH,
         "_allocatbelt_source5_path_catalogue_validator"),
        (PREPARATORY_OWNER_CATALOGUE_PATH,
         "_allocatbelt_source5_owner_catalogue_validator"),
    ):
        namespace, _source, selected_execution = _read_source_typed_module(
            source_manifest_raw, execution_manifest_raw, context, module_path,
            PREPARATORY_EXECUTION_SCHEMA_V1,
            namespace_name=namespace_name,
        )
        pin = _exact(
            original_pins.get("typed_modules", {}).get(module_path),
            {"path", "sha256"},
            f"selected Source catalogue module pin {module_path}",
        )
        execution_pin = _exact(
            selected_execution["modules"][context["host_id"]].get(module_path),
            {"path", "sha256"},
            f"selected execution catalogue module pin {module_path}",
        )
        _require(pin == execution_pin and pin["path"] == module_path,
                 f"selected Source catalogue module path/digest differs for {module_path}")
        namespace["__source5_typed_pin__"] = pin
        selected[module_path] = namespace
    return (
        selected[SOURCE5_BUDGET_VALIDATOR_PATH],
        types.SimpleNamespace(**selected[SOURCE5_BUDGET_VALIDATOR_PATH]),
        types.SimpleNamespace(**selected[PREPARATORY_OWNER_CATALOGUE_PATH]),
    )


def _load_preparatory_capacity_modules(
    source_manifest_raw: bytes, execution_manifest_raw: bytes,
    context: dict[str, Any], original_pins: dict[str, Any],
) -> tuple[Any, Any]:
    """Load the two capacity-pilot algorithms from this host's typed Source."""
    loaded = []
    execution: dict[str, Any] | None = None
    for module_path, namespace_name in (
        (PREPARATORY_CAMPAIGN_SOURCE_PATH,
         "_allocatbelt_preparatory_campaign_capacity_projection"),
        (PREPARATORY_INPUT_PREPARATION_SOURCE_PATH,
         "_allocatbelt_preparatory_input_capacity_projection"),
    ):
        namespace, _source, selected_execution = _read_source_typed_module(
            source_manifest_raw, execution_manifest_raw, context, module_path,
            PREPARATORY_EXECUTION_SCHEMA_V1,
            namespace_name=namespace_name,
        )
        if execution is None:
            execution = selected_execution
        selected_pin = _exact(
            original_pins.get("typed_modules", {}).get(module_path),
            {"path", "sha256"},
            f"preparatory capacity-pilot typed module pin {module_path}",
        )
        execution_pin = _exact(
            selected_execution["modules"][context["host_id"]].get(module_path),
            {"path", "sha256"},
            f"preparatory capacity-pilot execution module pin {module_path}",
        )
        _require(selected_pin == execution_pin and
                 selected_pin["path"] == module_path,
                 f"preparatory capacity-pilot module {module_path} differs from its exact execution pin")
        namespace["__source5_typed_pin__"] = selected_pin
        loaded.append(types.SimpleNamespace(**namespace))
    _require(execution is not None,
             "preparatory capacity-pilot Source modules lack an execution manifest")
    _require(getattr(loaded[0], "MAX_SOURCE_MANIFEST_BYTES", None) ==
                 PREPARATORY_MAX_SPEC_BYTES and
             getattr(loaded[1], "MAX_MANIFEST_BYTES", None) ==
                 PREPARATORY_MAX_SPEC_BYTES,
             "selected campaign/input-preparation Spec read ceilings differ from the six-map bound")
    return loaded[0], loaded[1]


def _validate_preparatory_profile_v1(
    budget_raw: bytes, context: dict[str, Any], *,
    source_manifest_raw: bytes | None,
    execution_manifest_raw: bytes | None,
    plan_raw: bytes | None,
    journal_width_contract_raw: bytes | None,
    spec_raw: bytes | None,
    catalogue_chunk_paths: dict[str, str] | None,
    catalogue_cache_root: str | None,
    root_local: bool,
    captured_preparatory_artifact_reader=None,
) -> dict[str, Any]:
    """Validate only the selected Source's separate 360-job prep profile."""
    if captured_preparatory_artifact_reader is not None:
        _require(callable(captured_preparatory_artifact_reader) and root_local and
                 catalogue_chunk_paths is None and catalogue_cache_root is None and
                 all(type(raw) is bytes for raw in (
                     source_manifest_raw, execution_manifest_raw, plan_raw,
                     journal_width_contract_raw,
                 )),
                 "captured preparatory byte validation requires exact dependency bytes and no path map")
    _require(context.get("phase") == "exploration" and
             _uint(context.get("job_index"),
                   "preparatory original exploration index") < 360,
             "preparatory archive context is outside its original 360 exploration jobs")
    budget_pin = _pin(context["resource_budget_pin"],
                      "preparatory host budget context pin")
    _require(type(budget_raw) is bytes and len(budget_raw) <=
             PREPARATORY_MAX_BUDGET_BYTES and
             _sha(budget_raw) == budget_pin["raw_sha256"],
             "preparatory budget bytes differ from their exact raw pin")
    source_pin = _pin(context["source_manifest_pin"],
                      "preparatory selected Source manifest pin")
    execution_pin = _pin(context["execution_manifest_pin"],
                         "preparatory execution-manifest pin")
    width_raw_pin = None
    try:
        budget = _parse_canonical(
            budget_raw, "preparatory host evidence budget",
            maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES,
        )
        _exact(budget, PREPARATORY_BUDGET_FIELDS_V1,
               "preparatory host evidence budget")
        _require(budget.get("schema") == PREPARATORY_BUDGET_SCHEMA_V1 and
                 budget.get("profile") == PREPARATORY_PROFILE_V1 and
                 budget.get("campaign_id") == context["campaign_id"] and
                 budget.get("host_id") == context["host_id"] and
                 budget.get("budget_sha256") ==
                     _budget_body_semantic_sha256(budget) ==
                     budget_pin["semantic_sha256"],
                 "preparatory budget schema/profile or semantic pin differs")
        if source_manifest_raw is None:
            _require(not root_local,
                     "Root preparatory validation cannot reopen its Source origin")
            source_manifest_raw, source_sha, _source_info = \
                _read_absolute_private_file(
                    Path(source_pin["path"]), MAX_SOURCE_MANIFEST_BYTES,
                    "host-pinned preparatory SourceV5 manifest",
                )
            _require(source_sha == source_pin["raw_sha256"],
                     "host preparatory Source bytes differ from their exact pin")
        if plan_raw is None:
            _require(not root_local,
                     "Root preparatory validation cannot reopen its Plan origin")
            plan_raw, plan_sha, _plan_info = _read_absolute_private_file(
                Path(context["plan_pin"]["path"]), MAX_PLAN_BYTES,
                "host-pinned preparatory PlanV3",
            )
            _require(plan_sha == context["plan_pin"]["raw_sha256"],
                     "host preparatory Plan bytes differ from their exact pin")
        _require(execution_manifest_raw is not None and
                 journal_width_contract_raw is not None,
                 "preparatory budget requires its captured execution and width dependencies")
        prep_namespace, source, manifest = _read_source_typed_module(
            source_manifest_raw, execution_manifest_raw, context,
            PREPARATORY_BUDGET_VALIDATOR_PATH,
            PREPARATORY_EXECUTION_SCHEMA_V1,
            namespace_name="_allocatbelt_source5_preparatory_budget_validator",
        )
        required_prep_api = (
            "build_execution_basis", "validate_execution_manifest",
            "validate_journal_width_contract",
            "validate_host_evidence_budget_v1",
        )
        _require(all(callable(prep_namespace.get(name))
                     for name in required_prep_api) and
                 prep_namespace.get("EXECUTION_FIELDS") ==
                     PREPARATORY_EXECUTION_FIELDS_V1 and
                 prep_namespace.get("BUDGET_FIELDS") ==
                     PREPARATORY_BUDGET_FIELDS_V1 and
                 prep_namespace.get("WIDTH_FIELDS") ==
                     PREPARATORY_WIDTH_FIELDS_V1 and
                 prep_namespace.get("PREPARATORY_EXECUTION_SCHEMA") ==
                     PREPARATORY_EXECUTION_SCHEMA_V1 and
                 prep_namespace.get("PREPARATORY_BUDGET_SCHEMA") ==
                     PREPARATORY_BUDGET_SCHEMA_V1 and
                 prep_namespace.get("PREPARATORY_WIDTH_SCHEMA") ==
                     PREPARATORY_WIDTH_SCHEMA_V1 and
                 prep_namespace.get("PREPARATORY_PROFILE") ==
                     PREPARATORY_PROFILE_V1 and
                 prep_namespace.get("CAMPAIGN_SOURCE_PATH") ==
                     PREPARATORY_CAMPAIGN_SOURCE_PATH and
                 prep_namespace.get("INPUT_PREPARATION_SOURCE_PATH") ==
                     PREPARATORY_INPUT_PREPARATION_SOURCE_PATH,
                 "selected Source prep module does not expose the exact frozen profile API")
        checked_manifest = prep_namespace["validate_execution_manifest"](manifest)
        _require(checked_manifest == manifest and
                 prep_namespace["build_execution_basis"](manifest) ==
                     manifest["preparatory_execution_basis_sha256"],
                 "selected Source prep module rejected execution manifest/basis")
        _require(manifest["campaign_id"] == context["campaign_id"] and
                 manifest["host_id"] == context["host_id"] and
                 manifest["scope"] == "preparatory_exploration" and
                 manifest["phase_order"] == ["exploration"] and
                 manifest["qualification_eligible"] is False,
                 "preparatory execution manifest is outside its explicit scope")
        original = _exact(manifest["original_inputs"], {
            "spec", "plan", "source_manifests", "campaign_artifacts_root",
        }, "preparatory manifest original inputs")
        plan_wrapper = _exact(original["plan"], {"artifact", "semantic_sha256"},
                              "preparatory original Plan wrapper")
        manifest_plan_pin = _pin({
            **_pin_raw(plan_wrapper["artifact"],
                       "preparatory original Plan artifact"),
            "semantic_sha256": plan_wrapper["semantic_sha256"],
        }, "preparatory original Plan pin")
        _require(manifest_plan_pin == _pin(context["plan_pin"],
                                           "preparatory context Plan pin"),
                 "preparatory execution manifest differs from the original Plan pin")
        source_wrappers = original["source_manifests"]
        source_wrapper = _exact(source_wrappers[context["host_id"]],
                                {"artifact", "semantic_sha256"},
                                "preparatory selected Source wrapper")
        manifest_source_pin = _pin({
            **_pin_raw(source_wrapper["artifact"],
                       "preparatory selected Source artifact"),
            "semantic_sha256": source_wrapper["semantic_sha256"],
        }, "preparatory selected Source pin")
        _require(manifest_source_pin == source_pin,
                 "preparatory execution manifest differs from selected Source pin")
        prep_original_pins = _preparatory_original_pins(manifest)
        _require(budget["original_pins"] == prep_original_pins and
                 budget["original_pins"].get("execution_basis_sha256") ==
                     manifest["preparatory_execution_basis_sha256"] and
                 "execution_manifest" not in budget["original_pins"] and
                 "journal_width_contract" not in budget["original_pins"] and
                 "host_budget" not in budget["original_pins"],
                 "preparatory budget original pins differ from its sealed execution basis")
        initial_spec_pin = _pin(
            prep_original_pins["initial_spec"],
            "preparatory initial SpecV3 pin",
        )
        if spec_raw is None and captured_preparatory_artifact_reader is not None:
            spec_origin = {key: initial_spec_pin[key] for key in ("path", "raw_sha256")}
            try:
                spec_raw = captured_preparatory_artifact_reader(
                    spec_origin, PREPARATORY_MAX_SPEC_BYTES,
                )
            except Exception as error:
                raise EvidenceArchiveError(
                    "captured preparatory initial Spec is unavailable",
                ) from error
        if spec_raw is None:
            _require(not root_local,
                     "Root preparatory validation requires the sixth captured Spec dependency")
            spec_raw, spec_sha, _spec_info = _read_absolute_private_file(
                Path(initial_spec_pin["path"]), PREPARATORY_MAX_SPEC_BYTES,
                "host-pinned preparatory initial SpecV3",
            )
            _require(spec_sha == initial_spec_pin["raw_sha256"],
                     "host preparatory SpecV3 differs from its exact raw pin")
        _require(type(spec_raw) is bytes and
                 len(spec_raw) <= PREPARATORY_MAX_SPEC_BYTES and
                 _sha(spec_raw) == initial_spec_pin["raw_sha256"],
                 "preparatory SpecV3 bytes differ from the original raw pin")
        width_wrapper = _exact(
            _exact(manifest["preparatory_journal_width_contracts"],
                   {context["host_id"]},
                   "preparatory width-contract host map")[context["host_id"]],
            {"artifact", "semantic_sha256"},
            "preparatory selected width wrapper",
        )
        width_raw_pin = _pin({
            **_pin_raw(width_wrapper["artifact"],
                       "preparatory width-contract artifact"),
            "semantic_sha256": width_wrapper["semantic_sha256"],
        }, "preparatory width-contract pin")
        budget_wrapper = _exact(
            _exact(manifest["preparatory_host_budgets"],
                   {context["host_id"]},
                   "preparatory budget host map")[context["host_id"]],
            {"artifact", "semantic_sha256"},
            "preparatory selected budget wrapper",
        )
        manifest_budget_pin = _pin({
            **_pin_raw(budget_wrapper["artifact"],
                       "preparatory budget artifact"),
            "semantic_sha256": budget_wrapper["semantic_sha256"],
        }, "preparatory manifest budget pin")
        _require(manifest_budget_pin == budget_pin,
                 "preparatory budget differs from its exact manifest entry")
        artifact_root = _absolute_path(manifest["artifact_root"],
                                       "preparatory artifact root")
        expected_budget_path = _absolute_path(str(
            Path(artifact_root) / context["campaign_id"] / "source5" /
            context["host_id"] / "evidence-budget" /
            "host-evidence-budget-preparatory-v1.json",
        ), "preparatory deterministic budget path")
        expected_width_path = _absolute_path(str(
            Path(artifact_root) / context["campaign_id"] / "source5" /
            context["host_id"] / "evidence-budget" /
            "preparatory-journal-width-v1.json",
        ), "preparatory deterministic width path")
        _require(budget_pin["path"] == expected_budget_path and
                 width_raw_pin["path"] == expected_width_path,
                 "preparatory budget/width paths differ from their reserved locations")
        _require(type(journal_width_contract_raw) is bytes and
                 len(journal_width_contract_raw) <= PREPARATORY_MAX_WIDTH_BYTES and
                 _sha(journal_width_contract_raw) == width_raw_pin["raw_sha256"],
                 "preparatory width bytes differ from their exact raw pin")
        width = _parse_canonical(
            journal_width_contract_raw, "preparatory journal-width contract",
            maximum_bytes=PREPARATORY_MAX_WIDTH_BYTES,
        )
        _exact(width, PREPARATORY_WIDTH_FIELDS_V1,
               "preparatory journal-width contract")
        _require(width.get("contract_sha256") ==
                 width_raw_pin["semantic_sha256"] == _sha(_canonical({
                     key: item for key, item in width.items()
                     if key != "contract_sha256"
                 })), "preparatory width raw/semantic pin differs")
        checked_width = prep_namespace["validate_journal_width_contract"](
            width, expected_campaign_id=context["campaign_id"],
            expected_host_id=context["host_id"],
            expected_execution_basis_sha256=
                manifest["preparatory_execution_basis_sha256"],
            expected_original_pins=prep_original_pins,
        )
        _require(checked_width == width and
                 width["initial_plan_pin"] == manifest_plan_pin and
                 width["source_manifest_pin"] == source_pin and
                 width["capacity_generation_pin"] ==
                     manifest["preparatory_capacity_generation"]["completion"],
                 "selected Source prep module rejected width-to-basis linkage")
        _require(budget["journal_width_contract_pin"] == width_raw_pin,
                 "preparatory budget does not bind its manifest width pin")
        catalogue_reader = _source_budget_catalogue_reader(
            budget, catalogue_chunk_paths, catalogue_cache_root,
            root_local=root_local,
            captured_artifact_reader=captured_preparatory_artifact_reader,
        )
        budget_namespace, catalogue_module, owner_catalogue_module = \
            _load_preparatory_catalogue_modules(
                source_manifest_raw, execution_manifest_raw, context,
                prep_original_pins,
            )
        campaign_module, input_preparation_module = \
            _load_preparatory_capacity_modules(
                source_manifest_raw, execution_manifest_raw, context,
                prep_original_pins,
            )
        spec_document = _parse_canonical(
            spec_raw, "preparatory original SpecV3 dependency",
            maximum_bytes=PREPARATORY_MAX_SPEC_BYTES,
        )
        plan_document = _parse_canonical(
            plan_raw, "preparatory original PlanV3 dependency",
            maximum_bytes=MAX_PLAN_BYTES,
        )
        digest_object = getattr(campaign_module, "digest_object", None)
        _require(callable(digest_object) and
                 plan_document.get("spec_sha256") ==
                     digest_object(spec_document) ==
                     initial_spec_pin["semantic_sha256"],
                 "preparatory original Spec semantic pin differs from PlanV3")
        catalogue_api = (
            "validate_path_catalogue_manifest",
            "verify_path_catalogue_chunks_with_reader",
            "iter_path_catalogue_rows_with_reader",
        )
        fixed_catalogue_api = (
            "validate_fixed_pair_v3_path_catalogue_manifest",
            "verify_fixed_pair_v3_path_catalogue_chunks_with_reader",
            "iter_fixed_pair_v3_path_catalogue_rows_with_reader",
        )
        fixed_profile = any(name in budget_namespace
                            for name in fixed_catalogue_api)
        if fixed_profile:
            catalogue_api = fixed_catalogue_api
        _require(all(callable(budget_namespace.get(name))
                     for name in catalogue_api),
                 "selected Source path-catalogue module lacks its captured row APIs")
        catalogue = budget_namespace[catalogue_api[0]](
            budget["path_catalogue"],
        )
        checked_catalogue = budget_namespace[catalogue_api[1]](
                catalogue, catalogue_reader,
            )
        _require(checked_catalogue == catalogue,
                 "selected Source path-catalogue validator changed the manifest")
        width_rows = []
        spec_path_rows = []
        spec_role_rows = []
        for row in budget_namespace[catalogue_api[2]](
                catalogue, catalogue_reader):
            if row["path"] == width_raw_pin["path"]:
                width_rows.append(row)
            if row["path"] == initial_spec_pin["path"]:
                spec_path_rows.append(row)
            if row["role"] == "spec_v3" and row["host_id"] == context["host_id"]:
                spec_role_rows.append(row)
        _require(len(width_rows) == 1 and
                 width_rows[0]["kind"] == "file" and
                 width_rows[0]["role"] ==
                    "preparatory_journal_width_contract" and
                 width_rows[0]["origin_pin"] == {
                     "raw_sha256": width_raw_pin["raw_sha256"],
                     "semantic_sha256": width_raw_pin["semantic_sha256"],
                 } and width_rows[0]["max_file_bytes"] ==
                     len(journal_width_contract_raw),
                 "preparatory catalogue omits its exact width contract row")
        expected_spec_row = {
            "path": initial_spec_pin["path"], "kind": "file",
            "role": "spec_v3", "host_id": context["host_id"],
            "max_bytes": len(spec_raw), "max_file_bytes": len(spec_raw),
            "max_inodes": 1, "storage_root": None, "owner": "inputs",
            "phase": None, "run_id": None, "member_index": None,
            "aggregate_id": None, "aggregate_max_bytes": None,
            "origin_pin": {
                "raw_sha256": initial_spec_pin["raw_sha256"],
                "semantic_sha256": initial_spec_pin["semantic_sha256"],
            },
        }
        _require(spec_path_rows == [expected_spec_row] and
                 spec_role_rows == [expected_spec_row],
                 "preparatory catalogue SpecV3 row differs from its exact original bytes/pin")
        checked_budget = prep_namespace[
            "validate_host_evidence_budget_v1"](
                budget, expected_campaign_id=context["campaign_id"],
                expected_host_id=context["host_id"],
                expected_execution_basis_sha256=
                    manifest["preparatory_execution_basis_sha256"],
                expected_width_pin=width_raw_pin,
                expected_width=width,
                execution_manifest_raw=execution_manifest_raw,
                source_manifest_raw=source_manifest_raw,
                plan_raw=plan_raw,
                width_contract_raw=journal_width_contract_raw,
                owner_catalogue_module=owner_catalogue_module,
                catalogue_module=catalogue_module,
                catalogue_row_reader=catalogue_reader,
                campaign_module=campaign_module,
                input_preparation_module=input_preparation_module,
                spec_raw=spec_raw,
            )
        _require(checked_budget == budget,
                 "selected Source prep budget validator changed its projection")
        required_request_schema = None
        selector_name = "required_archive_request_schema_v1"
        if fixed_profile or selector_name in budget_namespace:
            selector = budget_namespace.get(selector_name)
            _require(callable(selector),
                     "selected Source Fixed profile lacks its schema selector")
            required_request_schema = selector(budget, manifest, context)
            _require(required_request_schema in {None, REQUEST_SCHEMA_V3} and
                     (not fixed_profile or
                      required_request_schema == REQUEST_SCHEMA_V3),
                     "selected Source Fixed profile returned an invalid schema requirement")
        archive_transport = budget["archive_transport"]
        _require(type(archive_transport) is dict and
                 archive_transport.get("schema") ==
                    "allocatbelt.application-source5-preparatory-archive-transport.v1" and
                 archive_transport.get("maximum_signature_bytes") == 4096 and
                 type(archive_transport.get("per_job")) is list and
                 len(archive_transport["per_job"]) == 360,
                 "preparatory archive transport does not close over 360 jobs and its signer quota")
        row = archive_transport["per_job"][context["job_index"]]
        _require(type(row) is dict and row.get("phase") == "exploration" and
                 row.get("job_index") == context["job_index"] and
                 row.get("ordinal") == width["job_rows"][context["job_index"]]["ordinal"] and
                 row.get("run_id") == width["job_rows"][context["job_index"]]["run_id"] and
                 row.get("job_sha256") ==
                     width["job_rows"][context["job_index"]]["job_sha256"],
                 "preparatory archive transport row differs from the exact original width row")
        return {
            "budget": budget, "execution_manifest": manifest,
            "width": width, "width_pin": width_raw_pin,
            "catalogue": catalogue, "catalogue_reader": catalogue_reader,
            "catalogue_module": budget_namespace,
            "catalogue_iterator_name": catalogue_api[2],
            "required_request_schema": required_request_schema,
            "preparatory_module": prep_namespace,
            "spec_raw": spec_raw,
            "transport_row": row,
        }
    except EvidenceArchiveError:
        raise
    except Exception as error:
        raise EvidenceArchiveError(
            f"selected Source preparatory budget validator rejected its profile: {error}",
        ) from error


def validate_preparatory_budget_profile_v1(
    budget_raw: bytes, context: dict[str, Any], *,
    source_manifest_raw: bytes, execution_manifest_raw: bytes,
    plan_raw: bytes | None = None,
    journal_width_contract_raw: bytes,
    spec_raw: bytes | None = None,
    catalogue_chunk_paths: dict[str, str] | None = None,
    catalogue_cache_root: str | None = None,
    root_local: bool = False,
    captured_preparatory_artifact_reader=None,
) -> dict[str, Any]:
    """Public captured-dependency boundary for the separate prep budget."""
    checked_context = _validate_context(context)
    return _validate_preparatory_profile_v1(
        budget_raw, checked_context,
        source_manifest_raw=source_manifest_raw,
        execution_manifest_raw=execution_manifest_raw,
        plan_raw=plan_raw,
        journal_width_contract_raw=journal_width_contract_raw,
        spec_raw=spec_raw,
        catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
        root_local=root_local,
        captured_preparatory_artifact_reader=captured_preparatory_artifact_reader,
    )


def _validate_ready_host_budget_v3(
    budget_raw: bytes, budget: dict[str, Any], context: dict[str, Any], *,
    source_manifest_raw: bytes | None,
    execution_manifest_raw: bytes | None,
    journal_width_contract_raw: bytes | None,
    catalogue_chunk_paths: dict[str, str] | None,
    catalogue_cache_root: str | None,
    root_local: bool,
) -> None:
    """Run the exact selected Source module's ready-v3 math and row closure."""
    pin = _pin(context["resource_budget_pin"],
               "v3 source-validator host budget pin")
    _require(_sha(budget_raw) == pin["raw_sha256"] and
             _sha(_canonical({key: item for key, item in budget.items()
                              if key != "budget_sha256"})) ==
                 pin["semantic_sha256"] and
             source_manifest_raw is not None and
             execution_manifest_raw is not None and
             journal_width_contract_raw is not None,
             "ready v3 validation lacks its exact five-map source/exec/width bytes")
    namespace = _read_source_budget_module(
        source_manifest_raw, context, execution_manifest_raw,
    )
    reader = _source_budget_catalogue_reader(
        budget, catalogue_chunk_paths, catalogue_cache_root,
        root_local=root_local,
    )
    try:
        validated = namespace["validate_host_evidence_budget_v3"](
            budget, journal_width_contract_raw=journal_width_contract_raw,
            catalogue_row_reader=reader,
        )
    except Exception as error:
        raise EvidenceArchiveError(
            f"selected Source5 host-budget v3 validator rejected its budget: {error}",
        ) from error
    _require(validated == budget,
             "selected Source5 v3 validator returned a different budget projection")


def _validate_host_budget_revision(
    budget: dict[str, Any], context: dict[str, Any], *,
    budget_raw: bytes | None = None,
    source_manifest_raw: bytes | None = None,
    execution_manifest_raw: bytes | None = None,
    journal_width_contract_raw: bytes | None = None,
    catalogue_chunk_paths: dict[str, str] | None = None,
    catalogue_cache_root: str | None = None,
    root_local: bool = False,
    validate_source_module: bool = True,
    require_v4_manifest: bool = False,
) -> bool:
    """Validate exact budget revisions without promoting the historic v2 body."""
    legacy = set(budget) == HOST_BUDGET_FIELDS_LEGACY
    r6 = set(budget) == HOST_BUDGET_FIELDS_R6
    ready_v3 = set(budget) == HOST_BUDGET_FIELDS_V3
    _require(legacy or r6 or ready_v3,
             "host evidence budget has an unsupported exact field set")
    schema_matches_fields = (
        ((legacy or r6) and budget.get("schema") == HOST_BUDGET_SCHEMA_V2) or
        (ready_v3 and budget.get("schema") == HOST_BUDGET_SCHEMA_V3 and
         budget.get("admission_profile") == HOST_BUDGET_V3_ADMISSION_PROFILE)
    )
    _require(schema_matches_fields,
             "host evidence budget schema/profile does not match its exact field set")
    if legacy:
        # A historic 13-field budget remains on its original readiness path,
        # including signer-only v4 fixture contexts. It carries no width claim.
        _require(journal_width_contract_raw is None,
                 "legacy host budget cannot carry v4 width-contract bytes")
        _require(not _has_h15_archive_readback_roles(
                    budget.get("path_catalogue")),
                 "H15 archive-read retention requires the width-bound v4 budget variant")
        return False
    schema = budget["execution_manifest_schema"]
    _require(schema == EXECUTION_SCHEMA_V4,
             "width-bound host-budget fields are reserved for execution manifest v4")
    readiness = _exact(budget["readiness"], {
        "budget_complete", "execution_ready", "component_gate_ready",
        "qualification_eligible",
    }, "width-bound host evidence budget readiness")
    if ready_v3:
        _require(validate_source_module,
                 "host budget v3 requires its selected Source validator")
        expected_readiness = {
            "budget_complete": True, "execution_ready": True,
            "component_gate_ready": False, "qualification_eligible": False,
        }
        expected_blockers: list[str] = []
    else:
        _require(budget.get("schema") == HOST_BUDGET_SCHEMA_V2,
                 "R6 width extension must retain its v2 schema")
        expected_readiness = {
            "budget_complete": False, "execution_ready": False,
            "component_gate_ready": False, "qualification_eligible": False,
        }
        expected_blockers = [
            "verified_between_pair_archive_ack_reclaim_not_integrated",
        ]
    _require(readiness == expected_readiness and
             budget["execution_blockers"] == expected_blockers,
             "width-bound host budget blockers/readiness differ from its exact schema")
    _pin(budget["journal_width_contract_pin"],
         "v4 host-budget journal-width pin")
    catalogue = budget.get("path_catalogue")
    retention = catalogue.get("retention_policy") if type(catalogue) is dict else None
    has_archive_readback = _has_h15_archive_readback_roles(catalogue)
    expected_local_roles = (
        ALWAYS_LOCAL_EVIDENCE_ROLES_LEGACY | {"journal_width_contract"} |
        ({SOURCE5_ARCHIVE_READ_CONTROL_ROLE} if has_archive_readback else set())
    )
    _require(type(retention) is dict and
             retention.get("always_local_roles") == sorted(expected_local_roles),
             "v4 retention always-local roles omit or broaden the exact width-contract role")
    if execution_manifest_raw is not None:
        _require(journal_width_contract_raw is not None,
                 "v4 host budget requires raw width-contract bytes")
        _validate_execution_manifest_budget_binding(
            execution_manifest_raw, context, budget,
            journal_width_contract_raw,
        )
    elif require_v4_manifest or ready_v3:
        raise EvidenceArchiveError(
            "width-bound host budget requires its raw-pinned execution manifest for width-pin verification",
        )
    _require(journal_width_contract_raw is None or
             execution_manifest_raw is not None,
             "width-contract bytes require their exact execution-manifest context")
    if ready_v3:
        _require(budget_raw is not None,
                 "ready v3 host budget requires its raw-pinned source document")
        _validate_ready_host_budget_v3(
            budget_raw, budget, context,
            source_manifest_raw=source_manifest_raw,
            execution_manifest_raw=execution_manifest_raw,
            journal_width_contract_raw=journal_width_contract_raw,
            catalogue_chunk_paths=catalogue_chunk_paths,
            catalogue_cache_root=catalogue_cache_root,
            root_local=root_local,
        )
    return True


def _validate_h15_archive_readback_profile(
    budget: dict[str, Any], host_id: str,
    readback_rows: list[dict[str, Any]], role_byte_sums: dict[str, int],
    analyzer_rows: list[dict[str, Any]] | None = None,
) -> bool:
    """Check H15's exact reusable read slots against its retained root bounds."""
    catalogue = budget.get("path_catalogue")
    has_readback = _has_h15_archive_readback_roles(catalogue)
    analyzer_rows = [] if analyzer_rows is None else analyzer_rows
    if not has_readback:
        _require(not readback_rows and not analyzer_rows,
                 "catalogue rows contain H15 readback roles absent from its manifest")
        return False
    _require((set(budget) == HOST_BUDGET_FIELDS_R6 or
              set(budget) == HOST_BUDGET_FIELDS_V3) and
             budget.get("execution_manifest_schema") == EXECUTION_SCHEMA_V4,
             "H15 archive-read catalogue is not bound to the exact width-v4 budget")
    catalogue = _exact(catalogue, SOURCE5_PATH_CATALOGUE_FIELDS,
                       "H15 Source5 path catalogue manifest")
    body = {key: value for key, value in catalogue.items()
            if key != "semantic_sha256"}
    _require(catalogue["schema"] ==
             "allocatbelt.application-source5-host-path-catalogue.v2" and
             catalogue["semantic_sha256"] == _sha(_canonical(body)) and
             type(catalogue["role_byte_bounds"]) is dict and
             role_byte_sums == catalogue["role_byte_bounds"],
             "H15 path catalogue role/root source projection differs")
    retention = catalogue["retention_policy"]
    retention_fields = set(retention) if type(retention) is dict else set()
    if retention_fields != (
            SOURCE5_RETENTION_POLICY_FIELDS |
            SOURCE5_CLEANUP_RETENTION_FIELDS):
        raise EvidenceArchiveError(
            "H15 width-bound readback requires the exact cleanup retention fields",
        )
    retention = _exact(
        retention, retention_fields,
        "H15 path catalogue retention policy",
    )
    analyzer_required = (
        budget.get("execution_manifest_schema") == EXECUTION_SCHEMA_V4 and
        budget.get("journal_width_contract_pin") is not None
    )
    _require(len(analyzer_rows) == int(analyzer_required),
             "v4 width-bound readback requires exactly one analyzer scratch tree")
    local_roles = sorted(
        ALWAYS_LOCAL_EVIDENCE_ROLES_LEGACY |
        {"journal_width_contract", SOURCE5_ARCHIVE_READ_CONTROL_ROLE},
    )
    _require(retention["always_local_roles"] == local_roles and
             retention["schema"] ==
                 "allocatbelt.application-source5-between-pair-retention.v2" and
             retention["mode"] == "verified_between_pair_offload_v1" and
             retention["max_live_job_windows"] == 1 and
             retention["max_retained_failure_windows"] == 1,
             "H15 readback retention role/mode/window contract differs")
    profile: dict[str, dict[str, Any]] = {}
    for index, row_value in enumerate(readback_rows):
        row = _exact(row_value, {
            "path", "kind", "role", "host_id", "max_bytes",
            "max_file_bytes", "max_inodes", "storage_root", "owner",
            "phase", "run_id", "member_index", "aggregate_id",
            "aggregate_max_bytes", "origin_pin",
        }, f"H15 archive-read catalogue row[{index}]")
        role = row["role"]
        _require(role in SOURCE5_ARCHIVE_READ_ROLES and role not in profile,
                 "H15 archive-read catalogue repeats or broadens its exact role set")
        _require(row["host_id"] == host_id and
                 row["owner"] == "source5_controller" and
                 row["phase"] is None and row["run_id"] is None and
                 row["member_index"] is None and
                 row["aggregate_id"] is None and
                 row["aggregate_max_bytes"] is None and
                 row["origin_pin"] is None and
                 type(row["storage_root"]) is str,
                 f"H15 archive-read slot {role} has job identity or owner drift")
        _absolute_path(row["path"], f"H15 archive-read slot {role} path")
        _absolute_path(row["storage_root"],
                       f"H15 archive-read slot {role} storage root")
        for field in ("max_bytes", "max_file_bytes", "max_inodes"):
            _uint(row[field], f"H15 archive-read {role} {field}")
        _require(row["max_bytes"] > 0 and
                 row["max_file_bytes"] <= row["max_bytes"],
                 f"H15 archive-read slot {role} has an empty or inverted cap")
        expected_kind = "tree" if role == "source5_archive_read_stage" else "file"
        _require(row["kind"] == expected_kind and
                 (expected_kind == "tree" or
                  (row["max_inodes"] == 1 and
                   row["max_file_bytes"] == row["max_bytes"])) and
                 (role != "source5_archive_read_stage" or
                  (row["max_inodes"] > 1 and
                   row["max_file_bytes"] > 0)),
                 f"H15 archive-read slot {role} type/byte/inode bounds differ")
        if role in {"source5_archive_read_request_slot",
                    "source5_archive_read_response_slot",
                    "source5_archive_read_response_incoming"}:
            _require(row["max_bytes"] <= MAX_ARCHIVE_READ_METADATA_BYTES and
                     row["max_file_bytes"] == row["max_bytes"],
                     f"H15 archive-read metadata slot {role} exceeds its parser ceiling")
        elif role in SOURCE5_ARCHIVE_READ_BUNDLE_ALTERNATIVES:
            _require(MIN_ARCHIVE_READ_BUNDLE_BYTES <= row["max_bytes"] <=
                     MAX_TOTAL_BYTES and
                     row["max_file_bytes"] == row["max_bytes"],
                     f"H15 archive-read bundle slot {role} exceeds its transport ceiling")
        elif role == "source5_archive_read_stage":
            _require(row["max_bytes"] <= MAX_TOTAL_BYTES and
                     row["max_file_bytes"] <= MAX_OBJECT_BYTES and
                     row["max_inodes"] <= MAX_ARCHIVE_READ_OBJECTS + 1,
                     "H15 archive-read stage exceeds its exact payload/object/inode limits")
        elif role == SOURCE5_ARCHIVE_READ_CONTROL_ROLE:
            _require(row["max_bytes"] <= MAX_TOTAL_BYTES and
                     row["max_file_bytes"] == row["max_bytes"],
                     "H15 read-control ledger exceeds its bounded regular-file limit")
        profile[role] = row
    _require(set(profile) == SOURCE5_ARCHIVE_READ_ROLES,
             "H15 archive-read catalogue omits one exact reusable slot")
    for role in SOURCE5_ARCHIVE_READ_ROLES:
        _require(role_byte_sums.get(role) == profile[role]["max_bytes"],
                 f"H15 archive-read role {role} byte sum differs from its row")
    response_rows = [profile[role] for role in
                     SOURCE5_ARCHIVE_READ_RESPONSE_ALTERNATIVES]
    bundle_rows = [profile[role] for role in
                   SOURCE5_ARCHIVE_READ_BUNDLE_ALTERNATIVES]
    for label, alternatives in (("response", response_rows),
                                ("bundle", bundle_rows)):
        _require(len(alternatives) == 2 and
                 len({(row["max_bytes"], row["max_file_bytes"],
                       row["max_inodes"], row["storage_root"],
                       row["owner"]) for row in alternatives}) == 1,
                 f"H15 readback {label} alternatives do not share exact caps/root")
    transient = [profile[role] for role in SOURCE5_ARCHIVE_READ_TRANSIENT_ROLES]
    read_roots = {row["storage_root"] for row in transient}
    _require(len(read_roots) == 1,
             "H15 readback slots do not share one reserved scratch root")
    read_root = next(iter(read_roots))
    analyzer_row = None
    if analyzer_required:
        analyzer_row = _exact(analyzer_rows[0], {
            "path", "kind", "role", "host_id", "max_bytes",
            "max_file_bytes", "max_inodes", "storage_root", "owner",
            "phase", "run_id", "member_index", "aggregate_id",
            "aggregate_max_bytes", "origin_pin",
        }, "v4 analyzer scratch catalogue row")
        _require(analyzer_row["role"] == SOURCE5_ANALYZER_SPOOL_ROLE and
                 analyzer_row["kind"] == "tree" and
                 analyzer_row["host_id"] == host_id and
                 analyzer_row["owner"] == "source5_controller" and
                 analyzer_row["phase"] is None and
                 analyzer_row["run_id"] is None and
                 analyzer_row["member_index"] is None and
                 analyzer_row["aggregate_id"] is None and
                 analyzer_row["aggregate_max_bytes"] is None and
                 analyzer_row["origin_pin"] is None and
                 analyzer_row["storage_root"] == read_root and
                 analyzer_row["max_bytes"] > 0 and
                 analyzer_row["max_bytes"] <= MAX_TOTAL_BYTES and
                 analyzer_row["max_file_bytes"] > 0 and
                 analyzer_row["max_file_bytes"] <= analyzer_row["max_bytes"] and
                 1 < analyzer_row["max_inodes"] <= MAX_ARCHIVE_READ_OBJECTS + 1,
                 "v4 analyzer scratch tree has an invalid exact root or finite cap")
        expected_analyzer_root = (
            Path(read_root) / budget["campaign_id"] / host_id / "analyzer-spool"
        )
        _require(Path(analyzer_row["path"]) == expected_analyzer_root and
                 role_byte_sums.get(SOURCE5_ANALYZER_SPOOL_ROLE) ==
                     analyzer_row["max_bytes"],
                 "v4 analyzer scratch path or role-byte projection differs")
    control = profile[SOURCE5_ARCHIVE_READ_CONTROL_ROLE]
    control_root = control["storage_root"]
    _require(read_root != control_root,
             "H15 readback scratch and persistent output roots are aliased")
    request = profile["source5_archive_read_request_slot"]
    stage = profile["source5_archive_read_stage"]
    expected_readback_root = (
        Path(read_root) / budget["campaign_id"] / host_id / "archive-readback"
    )
    expected_read_paths = {
        "source5_archive_read_request_slot": expected_readback_root / "request.json",
        "source5_archive_read_response_slot": expected_readback_root / "response.json",
        "source5_archive_read_response_incoming":
            expected_readback_root / "response.json.incoming",
        "source5_archive_read_bundle": expected_readback_root / "response.tar",
        "source5_archive_read_bundle_incoming":
            expected_readback_root / "response.tar.incoming",
        "source5_archive_read_stage": expected_readback_root / "stage",
    }
    _require(all(Path(profile[role]["path"]) == expected
                 for role, expected in expected_read_paths.items()) and
             Path(control["path"]) ==
                 Path(control_root) / budget["campaign_id"] / "source5" /
                 host_id / "archive-read-control.jsonl",
             "H15 reusable readback paths differ from their exact campaign layout")
    window_bytes = (
        request["max_bytes"] + response_rows[0]["max_bytes"] +
        bundle_rows[0]["max_bytes"] + stage["max_bytes"]
    )
    window_inodes = (
        request["max_inodes"] + response_rows[0]["max_inodes"] +
        bundle_rows[0]["max_inodes"] + stage["max_inodes"]
    )
    if analyzer_row is not None:
        window_bytes += analyzer_row["max_bytes"]
        window_inodes += analyzer_row["max_inodes"]
    _uint(window_bytes, "H15 archive-read active-window bytes")
    _uint(window_inodes, "H15 archive-read active-window inodes")
    catalogue_roots = set(catalogue["root_byte_bounds"])
    for field in ("persistent_root_byte_bounds",
                  "persistent_root_inode_bounds",
                  "maximum_window_root_byte_bounds",
                  "maximum_window_root_inode_bounds",
                  "maximum_live_root_byte_bounds",
                  "maximum_live_root_inode_bounds"):
        _require(type(retention[field]) is dict and
                 set(retention[field]) == catalogue_roots,
                 f"H15 archive-read retention {field} does not close over catalogue roots")
    persistent_bytes = retention["persistent_root_byte_bounds"]
    persistent_inodes = retention["persistent_root_inode_bounds"]
    window_byte_bounds = retention["maximum_window_root_byte_bounds"]
    window_inode_bounds = retention["maximum_window_root_inode_bounds"]
    live_bytes = retention["maximum_live_root_byte_bounds"]
    live_inodes = retention["maximum_live_root_inode_bounds"]
    for root in catalogue_roots:
        persistent_byte_count = _uint(
            persistent_bytes[root], f"H15 persistent bytes for {root}",
        )
        persistent_inode_count = _uint(
            persistent_inodes[root], f"H15 persistent inodes for {root}",
        )
        window_byte_count = _uint(
            window_byte_bounds[root], f"H15 window bytes for {root}",
        )
        window_inode_count = _uint(
            window_inode_bounds[root], f"H15 window inodes for {root}",
        )
        _require(_uint(live_bytes[root], f"H15 live bytes for {root}") ==
                    persistent_byte_count + window_byte_count and
                 _uint(live_inodes[root], f"H15 live inodes for {root}") ==
                    persistent_inode_count + window_inode_count,
                 f"H15 live root bounds for {root} do not equal persistent plus one window")
    _require(read_root in persistent_bytes and read_root in persistent_inodes and
             read_root in window_byte_bounds and read_root in window_inode_bounds and
             read_root in live_bytes and read_root in live_inodes and
             control_root in persistent_bytes and control_root in persistent_inodes and
             control_root in live_bytes and control_root in live_inodes and
             window_byte_bounds[read_root] >= window_bytes and
             window_inode_bounds[read_root] >= window_inodes and
             persistent_bytes[control_root] >= control["max_bytes"] and
             persistent_inodes[control_root] >= control["max_inodes"] and
             live_bytes[read_root] >=
                 persistent_bytes[read_root] + window_byte_bounds[read_root] and
             live_inodes[read_root] >=
                 persistent_inodes[read_root] + window_inode_bounds[read_root] and
             live_bytes[control_root] >= persistent_bytes[control_root] and
             live_inodes[control_root] >= persistent_inodes[control_root],
             "H15 readback slot byte/inode ceilings escape their retained root bounds")
    _require(_uint(retention["maximum_window_total_bytes"],
                   "H15 total live-window bytes") >= window_bytes and
             _uint(retention["maximum_window_total_inodes"],
                   "H15 total live-window inodes") >= window_inodes,
             "H15 total live-window ceilings are below the readback slot window")
    reservation = _exact(budget.get("storage_reservation"), {
        "pin", "roots", "required_bytes_by_root", "required_inodes_by_root",
    }, "H15 host storage reservation")
    _require(type(reservation["roots"]) is dict and
             type(reservation["required_bytes_by_root"]) is dict and
             type(reservation["required_inodes_by_root"]) is dict and
             set(reservation["required_bytes_by_root"]) == set(reservation["roots"]) and
             set(reservation["required_inodes_by_root"]) == set(reservation["roots"]),
             "H15 storage reservation root maps are malformed")
    roots = {}
    for root_path, root_value in reservation["roots"].items():
        root = _exact(root_value, {
            "path", "role", "reserved_bytes", "reserved_inodes",
            "filesystem_id",
        }, f"H15 storage reservation root[{root_path}]")
        _absolute_path(root_path, "H15 storage reservation root path")
        _require(root["path"] == root_path and
                 root["role"] in {"artifact", "output", "scratch",
                                   "evidence_store"} and
                 type(root["filesystem_id"]) is str and
                 re.fullmatch(r"[0-9]+", root["filesystem_id"]) is not None,
                 f"H15 storage reservation root {root_path} has an invalid identity")
        _uint(root["reserved_bytes"],
              f"H15 reserved bytes for {root_path}")
        _uint(root["reserved_inodes"],
              f"H15 reserved inodes for {root_path}")
        _uint(reservation["required_bytes_by_root"][root_path],
              f"H15 required bytes for {root_path}")
        _uint(reservation["required_inodes_by_root"][root_path],
              f"H15 required inodes for {root_path}")
        _require(root["reserved_bytes"] >=
                    reservation["required_bytes_by_root"][root_path] and
                 root["reserved_inodes"] >=
                    reservation["required_inodes_by_root"][root_path],
                 f"H15 reserved root {root_path} is below its required bounds")
        _require(root_path in catalogue_roots or
                 root["role"] == "evidence_store",
                 f"H15 storage reservation root {root_path} is not catalogue-bound")
        roots[root_path] = root
    _require(set(roots) >= catalogue_roots and
             set(root["role"] for root in roots.values()) ==
                 {"artifact", "output", "scratch", "evidence_store"} and
             roots[read_root]["role"] == "scratch" and
             roots[control_root]["role"] == "output",
             "H15 readback roots do not resolve to their exact reserved domains")
    for root_path in catalogue_roots:
        _require(reservation["required_bytes_by_root"][root_path] >=
                    live_bytes[root_path] and
                 reservation["required_inodes_by_root"][root_path] >=
                    live_inodes[root_path],
                 f"H15 storage reservation omits the live bound for {root_path}")
    for root_path, minimum_bytes, minimum_inodes in (
        (read_root, persistent_bytes[read_root] + window_bytes,
         persistent_inodes[read_root] + window_inodes),
        (control_root, persistent_bytes[control_root],
         persistent_inodes[control_root]),
    ):
        reserved = roots.get(root_path)
        _require(reserved is not None and
                 reservation["required_bytes_by_root"].get(root_path, 0) >=
                    minimum_bytes and
                 reservation["required_inodes_by_root"].get(root_path, 0) >=
                    minimum_inodes and
                 reserved["reserved_bytes"] >=
                    reservation["required_bytes_by_root"][root_path] and
                 reserved["reserved_inodes"] >=
                    reservation["required_inodes_by_root"][root_path],
                 "H15 readback/root reservation is below its exact byte/inode window")
    return True


def _validate_captured_h15_archive_readback_profile(
    budget_raw: bytes, budget: dict[str, Any], context: dict[str, Any],
    catalogue_chunk_paths: dict[str, str], catalogue_cache_root: str,
) -> bool:
    """Authenticate H15's global reusable slots from Root-local chunk copies."""
    catalogue = budget.get("path_catalogue")
    if not _has_h15_archive_readback_roles(catalogue):
        return False
    pin = _pin(context["resource_budget_pin"],
               "H15 readback catalogue budget pin")
    _require(_sha(budget_raw) == pin["raw_sha256"],
             "H15 readback catalogue budget raw pin differs")
    descriptors = catalogue["chunks"]
    expected_origins = {
        _absolute_path(row["path"], "H15 readback catalogue chunk origin")
        for row in descriptors
    }
    _require(type(catalogue_chunk_paths) is dict and
             set(catalogue_chunk_paths) == expected_origins,
             "H15 Root-local catalogue map is not the exact full chunk closure")
    cache_root = Path(_absolute_path(
        catalogue_cache_root, "H15 Root-local catalogue cache root",
    ))
    map_body = {origin: _absolute_path(catalogue_chunk_paths[origin],
                                       "H15 Root-local catalogue chunk")
                for origin in sorted(catalogue_chunk_paths)}
    cache_key = (pin["raw_sha256"], _sha(_canonical(map_body)))
    if SOURCE5_ARCHIVE_READ_CONTROL_CACHE.get(cache_key):
        return True
    role_sums: dict[str, int] = {}
    readback_rows: list[dict[str, Any]] = []
    analyzer_rows: list[dict[str, Any]] = []
    previous_path = ""
    observed_rows = 0
    chunk_limit = _uint(catalogue.get("chunk_bytes"),
                        "H15 catalogue chunk byte ceiling", positive=True)
    entry_limit = _uint(catalogue.get("entry_count"),
                        "H15 catalogue row ceiling", positive=True)
    for index, descriptor_value in enumerate(descriptors):
        descriptor = _exact(descriptor_value, {
            "path", "raw_sha256", "semantic_sha256", "byte_count",
            "row_count", "first_path", "last_path",
        }, f"H15 readback catalogue descriptor[{index}]")
        origin = _absolute_path(descriptor["path"],
                                "H15 catalogue chunk origin")
        raw_sha = _digest(descriptor["raw_sha256"],
                          "H15 catalogue chunk raw SHA-256")
        byte_count = _uint(descriptor["byte_count"],
                           "H15 catalogue chunk byte count", positive=True)
        row_count = _uint(descriptor["row_count"],
                          "H15 catalogue chunk row count", positive=True)
        _require(descriptor["semantic_sha256"] == raw_sha and
                 byte_count <= chunk_limit and row_count <= entry_limit and
                 observed_rows + row_count <= entry_limit,
                 "H15 readback catalogue chunk pins exceed exact limits")
        local_path = Path(map_body[origin])
        _require(local_path != Path(origin) and
                 local_path != cache_root and cache_root in local_path.parents and
                 local_path.resolve(strict=True) == local_path,
                 "H15 readback chunk is not a distinct Root-local cache file")
        raw, digest, _info = _read_absolute_private_file(
            local_path, byte_count, "H15 captured path catalogue chunk",
        )
        _require(len(raw) == byte_count and digest == raw_sha,
                 "H15 captured path catalogue chunk differs from its raw pin")
        lines = raw.splitlines(keepends=True)
        _require(len(lines) == row_count and bool(lines),
                 "H15 readback catalogue chunk row count differs")
        first_path = ""
        last_path = ""
        for line_index, line in enumerate(lines):
            _require(line.endswith(b"\n") and b"\r" not in line and
                     len(line) <= 64 * 1024,
                     "H15 readback catalogue row framing differs")
            row = _exact(_parse_canonical(
                line, f"H15 readback catalogue row[{index}:{line_index}]",
            ), {
                "path", "kind", "role", "host_id", "max_bytes",
                "max_file_bytes", "max_inodes", "storage_root", "owner",
                "phase", "run_id", "member_index", "aggregate_id",
                "aggregate_max_bytes", "origin_pin",
            }, "H15 path catalogue row")
            path = _absolute_path(row["path"], "H15 path catalogue row path")
            _require(_canonical(row) == line and path > previous_path,
                     "H15 path catalogue row bytes/order differ")
            previous_path = path
            first_path = path if not first_path else first_path
            last_path = path
            role = _token(row["role"], "H15 path catalogue role")
            for field in ("max_bytes", "max_file_bytes", "max_inodes"):
                _uint(row[field], f"H15 path catalogue {field}")
            _require(row["max_file_bytes"] <= row["max_bytes"] and
                     ((row["kind"] == "file" and row["max_inodes"] == 1) or
                      (row["kind"] == "tree" and row["max_inodes"] > 0)),
                     "H15 path catalogue row byte/inode bound is malformed")
            amount = _uint(row["max_bytes"],
                           "H15 path catalogue role bytes")
            role_sums[role] = role_sums.get(role, 0) + amount
            if role in SOURCE5_ARCHIVE_READ_ROLES:
                readback_rows.append(row)
            if role == SOURCE5_ANALYZER_SPOOL_ROLE:
                analyzer_rows.append(row)
        _require(first_path == descriptor["first_path"] and
                 last_path == descriptor["last_path"],
                 "H15 readback catalogue descriptor range differs from raw chunk")
        observed_rows += row_count
    _require(observed_rows == entry_limit,
             "H15 readback catalogue rows do not close over the entry count")
    _validate_h15_archive_readback_profile(
        budget, context["host_id"], readback_rows, role_sums,
        analyzer_rows,
    )
    if len(SOURCE5_ARCHIVE_READ_CONTROL_CACHE) >= 4:
        SOURCE5_ARCHIVE_READ_CONTROL_CACHE.pop(
            next(iter(SOURCE5_ARCHIVE_READ_CONTROL_CACHE)),
        )
    SOURCE5_ARCHIVE_READ_CONTROL_CACHE[cache_key] = True
    return True


def _campaign_signature_limit(
    raw: bytes, budget_pin: object, context: dict[str, Any], *,
    source_manifest_raw: bytes | None = None,
    execution_manifest_raw: bytes | None = None,
    plan_raw: bytes | None = None,
    journal_width_contract_raw: bytes | None = None,
    spec_raw: bytes | None = None,
    catalogue_chunk_paths: dict[str, str] | None = None,
    catalogue_cache_root: str | None = None,
    root_local: bool = False,
    require_v4_manifest: bool = False,
    captured_preparatory_artifact_reader=None,
    request_schema: str | None = None,
) -> int:
    pin = _pin(budget_pin, "campaign host evidence budget pin")
    _require(_sha(raw) == pin["raw_sha256"],
             "campaign host budget bytes differ from their raw pin")
    preparatory_probe = _parse_canonical(
        raw, "campaign host evidence budget",
        maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES,
    )
    if preparatory_probe.get("schema") == PREPARATORY_BUDGET_SCHEMA_V1:
        profile = _validate_preparatory_profile_v1(
            raw, context,
            source_manifest_raw=source_manifest_raw,
            execution_manifest_raw=execution_manifest_raw,
            plan_raw=plan_raw,
            journal_width_contract_raw=journal_width_contract_raw,
            spec_raw=spec_raw,
            catalogue_chunk_paths=catalogue_chunk_paths,
            catalogue_cache_root=catalogue_cache_root,
            root_local=root_local,
            captured_preparatory_artifact_reader=captured_preparatory_artifact_reader,
        )
        required_schema = profile.get("required_request_schema")
        _require(request_schema is None or required_schema is None or
                 request_schema == required_schema,
                 "checkpoint request schema differs from its selected Source profile")
        retention = profile["catalogue"].get("retention_policy")
        _require(type(retention) is dict,
                 "preparatory path catalogue lacks its signer quota")
        limit = _uint(profile["budget"]["archive_transport"].get(
            "maximum_signature_bytes"),
            "preparatory maximum signature bytes", positive=True)
        _require(limit == 4096 and
                 retention.get("maximum_signature_bytes") == limit and
                 limit <= MAX_GPG_OUTPUT_BYTES,
                 "preparatory signature quota differs from its fixed pinned allowance")
        return limit
    _require(captured_preparatory_artifact_reader is None,
             "captured preparatory byte reads cannot select a different budget profile")
    budget, _is_r6 = _parse_host_budget_value(
        raw, "campaign host evidence budget v2",
    )
    body = {key: item for key, item in budget.items()
            if key != "budget_sha256"}
    _require(budget.get("schema") in {
                 HOST_BUDGET_SCHEMA_V2, HOST_BUDGET_SCHEMA_V3,
             } and
             budget.get("campaign_id") == context["campaign_id"] and
             budget.get("host_id") == context["host_id"] and
             budget.get("budget_sha256") == _sha(_canonical(body)) ==
                 pin["semantic_sha256"],
             "campaign host budget schema/identity/semantic pin differs")
    _validate_host_budget_revision(
        budget, context, budget_raw=raw,
        source_manifest_raw=source_manifest_raw,
        execution_manifest_raw=execution_manifest_raw,
        journal_width_contract_raw=journal_width_contract_raw,
        catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
        root_local=root_local,
        require_v4_manifest=require_v4_manifest,
    )
    original_pins = _exact(budget.get("original_pins"), {
        "spec", "plan", "execution_manifest", "source_manifests",
        "source_tree_sha256",
    }, "host budget original input pins")
    _digest(original_pins["source_tree_sha256"], "budget source tree SHA-256")
    source_pins = original_pins["source_manifests"]
    _require(type(source_pins) is dict and context["host_id"] in source_pins and
             _pin(original_pins["plan"], "budget PlanV3 pin") ==
                 context["plan_pin"] and
             _pin(original_pins["execution_manifest"],
                  "budget execution-manifest pin") ==
                 context["execution_manifest_pin"] and
             _pin(source_pins[context["host_id"]],
                  "budget SourceV5 pin") == context["source_manifest_pin"],
             "archive context Source/Plan/execution pins differ from host budget")
    blockers = budget["execution_blockers"]
    readiness = _exact(budget["readiness"], {
        "budget_complete", "execution_ready", "component_gate_ready",
        "qualification_eligible",
    }, "campaign host budget readiness")
    _require(type(blockers) is list and
             all(type(item) is str and bool(item) for item in blockers) and
             len(blockers) == len(set(blockers)) and
             all(type(readiness[field]) is bool for field in readiness) and
             readiness["qualification_eligible"] is False and
             (not readiness["execution_ready"] or
              (readiness["budget_complete"] and not blockers)),
             "campaign budget blockers/readiness are inconsistent")
    catalogue = budget.get("path_catalogue")
    _require(type(catalogue) is dict and
             catalogue.get("schema") ==
                 "allocatbelt.application-source5-host-path-catalogue.v2" and
             catalogue.get("semantic_sha256") == _sha(_canonical({
                 key: item for key, item in catalogue.items()
                 if key != "semantic_sha256"
             })),
             "campaign host path catalogue semantic digest differs")
    retention = catalogue.get("retention_policy")
    _require(type(retention) is dict,
             "campaign path catalogue lacks signature quota")
    limit = _uint(retention.get("maximum_signature_bytes"),
                  "campaign maximum signature bytes", positive=True)
    _require(limit <= MAX_GPG_OUTPUT_BYTES,
             "campaign signature quota exceeds the generic parser ceiling")
    return limit


def _validate_execution_manifest_signer_context(
    raw: bytes, execution_manifest_pin: object,
    signer_context_pin: dict[str, str], context: dict[str, Any],
    *, require_width_contract: bool = False,
) -> dict[str, Any]:
    """Tie the host verifier context to the prepared execution-manifest pin."""
    pin = _pin(execution_manifest_pin, "execution-manifest pin")
    _require(pin == context["execution_manifest_pin"] and
             type(raw) is bytes and _sha(raw) == pin["raw_sha256"],
             "execution-manifest bytes differ from the checkpoint pin")
    parsed_probe = _parse_canonical(
        raw, "Source5 execution manifest", maximum_bytes=MAX_PLAN_BYTES,
    )
    if parsed_probe.get("schema") == PREPARATORY_EXECUTION_SCHEMA_V1:
        manifest = _exact(parsed_probe, PREPARATORY_EXECUTION_FIELDS_V1,
                          "preparatory Source5 execution manifest")
        body = {key: item for key, item in manifest.items()
                if key != "manifest_sha256"}
        hosts = manifest["hosts"]
        _require(manifest["campaign_id"] == context["campaign_id"] and
                 manifest["host_id"] == context["host_id"] and
                 type(hosts) is list and len(hosts) in (2, 3) and
                 all(type(host) is str and host for host in hosts) and
                 len(set(hosts)) == len(hosts) and context["host_id"] in hosts and
                 manifest["scope"] == "preparatory_exploration" and
                 manifest["phase_order"] == ["exploration"] and
                 manifest["qualification_eligible"] is False and
                 manifest["manifest_sha256"] == _sha(_canonical(
                     body, maximum_bytes=MAX_PLAN_BYTES,
                 )) == pin["semantic_sha256"],
                 "preparatory execution-manifest identity/scope/self digest differs")
        host_contexts = _exact(manifest["archive_signer_contexts"],
                               {context["host_id"]},
                               "preparatory archive signer map")
        wrapper = _exact(host_contexts[context["host_id"]], {
            "artifact", "semantic_sha256",
        }, "preparatory signer-context wrapper")
        artifact = _exact(wrapper["artifact"], {"path", "raw_sha256"},
                           "preparatory signer-context artifact")
        expected = {
            "path": signer_context_pin["path"],
            "raw_sha256": signer_context_pin["raw_sha256"],
            "semantic_sha256": signer_context_pin["semantic_sha256"],
        }
        _require(artifact == {"path": expected["path"],
                              "raw_sha256": expected["raw_sha256"]} and
                 wrapper["semantic_sha256"] == expected["semantic_sha256"],
                 "preparatory signer-context pin differs from its manifest entry")
        return pin
    fields = {
        "schema", "campaign_id", "hosts", "original_inputs",
        "execution_sources", "modules", "observed_hosts", "artifact_root",
        "output_root", "phase_order", "protocol_sha256",
        "qualification_eligible", "scope", "prepared_input_generation",
        "prepared_capacity_registration", "archive_signer_contexts",
        "manifest_sha256",
    }
    if require_width_contract:
        fields.add("journal_width_contracts")
    manifest = _exact(_parse_canonical(
        raw, "Source5 execution manifest", maximum_bytes=MAX_PLAN_BYTES,
    ),
                      fields, "bounded Source5 execution manifest v4")
    body = {key: item for key, item in manifest.items()
            if key != "manifest_sha256"}
    hosts = manifest["hosts"]
    _require(manifest["schema"] ==
             "allocatbelt.application-source5-campaign-execution.v4" and
             manifest["campaign_id"] == context["campaign_id"] and
             type(hosts) is list and len(hosts) in (2, 3) and
             all(type(host) is str and host for host in hosts) and
             len(hosts) == len(set(hosts)) and context["host_id"] in hosts and
             manifest["scope"] == "final_prepared_bounded" and
             manifest["qualification_eligible"] is False and
             manifest["manifest_sha256"] == _sha(_canonical(
                 body, maximum_bytes=MAX_PLAN_BYTES,
             )) ==
                 pin["semantic_sha256"],
             "execution-manifest schema, identity, scope or self digest differs")
    host_contexts = _exact(
        manifest["archive_signer_contexts"], set(hosts),
        "execution-manifest archive signer-context map",
    )
    wrapper = _exact(host_contexts[context["host_id"]], {
        "artifact", "semantic_sha256",
    }, "execution-manifest host signer-context wrapper")
    artifact = _exact(wrapper["artifact"], {"path", "raw_sha256"},
                       "execution-manifest signer-context artifact")
    expected = {
        "path": signer_context_pin["path"],
        "raw_sha256": signer_context_pin["raw_sha256"],
        "semantic_sha256": signer_context_pin["semantic_sha256"],
    }
    _require(artifact == {"path": expected["path"],
                          "raw_sha256": expected["raw_sha256"]} and
             wrapper["semantic_sha256"] == expected["semantic_sha256"],
             "signer-context pin is not the exact execution-manifest host entry")
    return pin


def _validate_archive_signer_context(
    raw: bytes, signer_context_pin: object, context: dict[str, Any],
    host_budget_raw: bytes, execution_manifest_pin: object,
    execution_manifest_raw: bytes,
    journal_width_contract_raw: bytes | None = None,
    *, source_manifest_raw: bytes | None = None,
    plan_raw: bytes | None = None,
    spec_raw: bytes | None = None,
    catalogue_chunk_paths: dict[str, str] | None = None,
    catalogue_cache_root: str | None = None,
    root_local: bool = False,
    captured_preparatory_artifact_reader=None,
    request_schema: str | None = None,
) -> dict[str, Any]:
    context_pin = _pin(signer_context_pin, "archive signer-context pin")
    _require(type(raw) is bytes and _sha(raw) == context_pin["raw_sha256"],
             "archive signer-context bytes differ from their origin raw pin")
    value = _exact(_parse_canonical(raw, "archive signer context"), {
        "schema", "campaign_id", "host_id", "authorized_primary_fingerprint",
        "maximum_signature_bytes", "keyring_pin", "gpgv_pin",
        "signature_format", "signer_context_sha256",
    }, "archive signer context")
    body = {key: item for key, item in value.items()
            if key != "signer_context_sha256"}
    self_sha = _digest(value["signer_context_sha256"],
                       "archive signer-context semantic digest")
    budget_probe = _parse_canonical(
        host_budget_raw, "campaign host evidence budget",
        maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES,
    )
    if budget_probe.get("schema") == PREPARATORY_BUDGET_SCHEMA_V1:
        budget_value = _exact(budget_probe, PREPARATORY_BUDGET_FIELDS_V1,
                              "campaign preparatory host budget")
        width_bound = True
    else:
        budget_value, is_r6 = _parse_host_budget_value(
            host_budget_raw, "campaign host evidence budget v2",
        )
        width_bound = (is_r6 and
                       budget_value.get("execution_manifest_schema") ==
                           EXECUTION_SCHEMA_V4)
    maximum_signature_bytes = _campaign_signature_limit(
        host_budget_raw, context["resource_budget_pin"], context,
        source_manifest_raw=source_manifest_raw,
        execution_manifest_raw=execution_manifest_raw,
        plan_raw=plan_raw,
        spec_raw=spec_raw,
        journal_width_contract_raw=journal_width_contract_raw,
        catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
        root_local=root_local,
        require_v4_manifest=width_bound,
        captured_preparatory_artifact_reader=captured_preparatory_artifact_reader,
        request_schema=request_schema,
    )
    fingerprint = _fingerprint(
        value["authorized_primary_fingerprint"],
        "archive signer-context primary fingerprint",
    )
    keyring_pin = _pin_raw(value["keyring_pin"],
                           "archive signer-context keyring pin")
    gpgv_pin = _pin_raw(value["gpgv_pin"],
                        "archive signer-context GPGV pin")
    _require(value["schema"] == SIGNER_CONTEXT_SCHEMA_V1 and
             value["campaign_id"] == context["campaign_id"] and
             value["host_id"] == context["host_id"] and
             fingerprint == context["authorized_signer_fingerprint"] and
             self_sha == _sha(_canonical(body)) ==
                 context_pin["semantic_sha256"] and
             value["maximum_signature_bytes"] == maximum_signature_bytes and
             value["signature_format"] ==
                 "binary_detached_primary_sha256_v1",
             "archive signer context differs from its host, budget or format pin")
    execution_pin = _validate_execution_manifest_signer_context(
        execution_manifest_raw, execution_manifest_pin,
        context_pin, context,
        require_width_contract=width_bound,
    )
    return {
        "signer_context_pin": context_pin,
        "execution_manifest_pin": execution_pin,
        "fingerprint": fingerprint,
        "maximum_signature_bytes": maximum_signature_bytes,
        "keyring_pin": keyring_pin, "gpgv_pin": gpgv_pin,
    }


def _parse_catalogue_local_map(
    raw: bytes, context: dict[str, Any],
) -> dict[str, str]:
    value = _exact(_parse_canonical(raw, "private catalogue local-path map"), {
        "schema", "campaign_id", "host_id", "resource_budget_pin",
        "chunks", "map_sha256",
    }, "private catalogue local-path map")
    body = {key: item for key, item in value.items() if key != "map_sha256"}
    _require(value["schema"] == CATALOGUE_LOCAL_MAP_SCHEMA_V1 and
             value["campaign_id"] == context["campaign_id"] and
             value["host_id"] == context["host_id"] and
             _pin(value["resource_budget_pin"], "catalogue-map budget pin") ==
                 context["resource_budget_pin"] and
             value["map_sha256"] == _sha(_canonical(body)) and
             type(value["chunks"]) is list,
             "private catalogue local map identity or digest differs")
    paths: dict[str, str] = {}
    previous = ""
    local_paths = set()
    for index, chunk_value in enumerate(value["chunks"]):
        row = _exact(chunk_value, {"origin_path", "local_path"},
                     f"catalogue local map row[{index}]")
        origin = _absolute_path(row["origin_path"],
                                "catalogue chunk origin path")
        local = _absolute_path(row["local_path"],
                               "Root-local catalogue chunk path")
        _require(origin > previous and local != origin and local not in local_paths,
                 "catalogue local map is unsorted, aliased, or uses an origin path")
        previous = origin
        local_paths.add(local)
        paths[origin] = local
    return paths


def _parse_dependency_local_map(
    raw: bytes, context: dict[str, Any],
) -> dict[str, str]:
    return _parse_dependency_local_map_details(raw, context)[0]


def _parse_dependency_local_map_details(
    raw: bytes, context: dict[str, Any],
) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    value = _exact(_parse_canonical(raw, "private dependency local-path map"), {
        "schema", "campaign_id", "host_id", "entries", "map_sha256",
    }, "private dependency local-path map")
    body = {key: item for key, item in value.items() if key != "map_sha256"}
    _require(value["schema"] == DEPENDENCY_LOCAL_MAP_SCHEMA_V1 and
             value["campaign_id"] == context["campaign_id"] and
             value["host_id"] == context["host_id"] and
             value["map_sha256"] == _sha(_canonical(body)) and
             type(value["entries"]) is list,
             "private dependency local map identity or digest differs")
    entries = value["entries"]
    _require(len(entries) in {3, 5, 6},
             "dependency map must use exactly a legacy three-row, final five-row, or preparatory six-row closure")
    paths: dict[str, str] = {}
    pins: dict[str, dict[str, str]] = {}
    local_paths = set()
    previous = ""
    for index, entry_value in enumerate(entries):
        entry = _exact(entry_value, {
            "origin_pin", "local_path",
        }, f"dependency local map entry[{index}]")
        pin = _pin(entry["origin_pin"], "mapped dependency origin pin")
        local = _absolute_path(entry["local_path"],
                               "Root-local dependency path")
        _require((len(entries) in {5, 6} or pin["path"] > previous) and
                 local != pin["path"] and
                 local not in local_paths,
                 "dependency map is unsorted, aliased, or uses a host origin path")
        previous = pin["path"]
        local_paths.add(local)
        paths[pin["path"]] = local
        pins[pin["path"]] = pin
    expected_pins = {
        context["source_manifest_pin"]["path"]:
            context["source_manifest_pin"],
        context["plan_pin"]["path"]: context["plan_pin"],
        context["resource_budget_pin"]["path"]:
            context["resource_budget_pin"],
    }
    execution_pin = _pin(
        context["execution_manifest_pin"],
        "dependency-map execution-manifest context pin",
    )
    _require(len(expected_pins) == 3,
             "dependency map base pin set is malformed")
    if len(entries) == 3:
        _require(set(paths) == set(expected_pins),
                 "legacy dependency map does not close over exact Source/Plan/budget pins")
        for origin_path, pin in expected_pins.items():
            _require(pins[origin_path] == pin,
                     "legacy dependency map origin pin differs from context")
    else:
        expected_prefix = [
            context["source_manifest_pin"], context["plan_pin"],
            context["resource_budget_pin"], execution_pin,
        ]
        _require([pins[_pin(item["origin_pin"],
                            f"v4 dependency map row[{index}] origin pin")["path"]]
                  for index, item in enumerate(entries[:4])] == expected_prefix and
                 len(paths) == len(entries) and
                 len(set(paths) - set(expected_pins) - {execution_pin["path"]}) ==
                     len(entries) - 4,
                 "v4/preparatory dependency map does not preserve its exact Source/Plan/budget/execution prefix")
        width_pin = pins[_pin(entries[4]["origin_pin"],
                              "dependency-map width pin")["path"]]
        _pin(width_pin, "dependency-map width pin")
        if len(entries) == 5:
            _require(len(paths) == 5 and
                     set(paths) == set(expected_pins) | {execution_pin["path"],
                                                         width_pin["path"]},
                     "final v4 dependency map is not the exact five-pin closure")
        else:
            spec_pin = pins[_pin(entries[5]["origin_pin"],
                                 "preparatory dependency-map Spec pin")["path"]]
            _pin(spec_pin, "preparatory dependency-map Spec pin")
            _require(len(paths) == 6 and
                     spec_pin["path"] not in {width_pin["path"],
                                               execution_pin["path"]} and
                     set(paths) == set(expected_pins) | {execution_pin["path"],
                                                         width_pin["path"],
                                                         spec_pin["path"]},
                     "preparatory dependency map is not the exact six-pin closure")
    return paths, pins


def _validate_preparatory_host_budget_object_rows(
    budget_raw: bytes, context: dict[str, Any], job_identity: dict[str, Any],
    entries: list[dict[str, Any]], job_record_pin: dict[str, str],
    job_record_bytes: int, job_record_semantic_sha256: str,
    catalogue_chunk_paths: dict[str, str], catalogue_cache_root: str,
    source_manifest_raw: bytes | None,
    execution_manifest_raw: bytes | None,
    plan_raw: bytes | None,
    journal_width_contract_raw: bytes | None,
    spec_raw: bytes | None,
    tree_inventories_value: object | None,
    owner_receipt_pins_value: object | None,
) -> None:
    profile = _validate_preparatory_profile_v1(
        budget_raw, context,
        source_manifest_raw=source_manifest_raw,
        execution_manifest_raw=execution_manifest_raw,
        plan_raw=plan_raw,
        journal_width_contract_raw=journal_width_contract_raw,
        spec_raw=spec_raw,
        catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
        root_local=True,
    )
    budget = profile["budget"]
    index = context["job_index"]
    width_row = profile["width"]["job_rows"][index]
    _require(context["phase"] == "exploration" and
             job_identity["job_index"] == index and
             job_identity["job_ordinal"] == width_row["ordinal"] and
             job_identity["run_id"] == width_row["run_id"] and
             job_identity["job_sha256"] == width_row["job_sha256"],
             "preparatory job record differs from its exact original width-contract row")
    record_bound = budget["schedule"]["maximum_job_record_bytes_by_ordinal"][index]
    _require(record_bound["ordinal"] == job_identity["job_ordinal"] and
             record_bound["run_id"] == job_identity["run_id"] and
             record_bound["job_sha256"] == job_identity["job_sha256"] and
             job_record_bytes <= record_bound["maximum_record_bytes"],
             "preparatory job record exceeds its original-ordinal source-derived cap")
    _require(all(row["origin_path"] != job_record_pin["path"] for row in entries) and
             all(row["role"] not in NON_EXPORTABLE_JOB_ROLES for row in entries),
             "preparatory request exports an always-local or non-exportable role")
    checked_trees = None
    if tree_inventories_value is not None:
        _require(type(owner_receipt_pins_value) is dict,
                 "preparatory ProbeV2 tree closure lacks owner receipt pins")
        checked_trees = _validate_tree_inventories(
            tree_inventories_value, entries, owner_receipt_pins_value,
            expected_job_sha256=job_identity["job_sha256"],
        )
    catalogue = profile["catalogue"]
    retention = budget["retention_policy"].get("source_policy")
    _require(type(retention) is dict,
             "preparatory budget lacks its exact one-window source retention policy")
    window_bytes = _uint(retention.get("maximum_window_total_bytes"),
                         "preparatory maximum live-window bytes")
    window_inodes = _uint(retention.get("maximum_window_total_inodes"),
                          "preparatory maximum live-window inodes")
    tree_file_paths = {
        entry["path"] for tree in (checked_trees or [])
        for entry in tree["entries"] if entry["kind"] == "file"
    }
    tree_inode_count = len(entries) - len(tree_file_paths) + sum(
        1 + tree["entry_count"] for tree in (checked_trees or [])
    )
    _require(sum(row["byte_count"] for row in entries) <= window_bytes and
             tree_inode_count <= window_inodes,
             "preparatory job object closure exceeds its pinned one-window byte/inode bounds")
    job_targets = {
        row["origin_path"]: (row["role"], row["byte_count"],
                             row["raw_sha256"], row["semantic_sha256"])
        for row in entries
    }
    _require(len(job_targets) == len(entries),
             "preparatory job object rows repeat an original path")
    protected_targets = {
        job_record_pin["path"]: (
            "source5_job_record", job_record_bytes,
            job_record_pin["raw_sha256"], job_record_semantic_sha256,
        ),
        profile["width_pin"]["path"]: (
            "preparatory_journal_width_contract",
            len(journal_width_contract_raw),
            profile["width_pin"]["raw_sha256"],
            profile["width_pin"]["semantic_sha256"],
        ),
    }
    _require(not (set(job_targets) & set(protected_targets)),
             "preparatory reclaimable entries alias local job/width records")
    targets = {**job_targets, **protected_targets}
    found: dict[str, dict[str, Any]] = {}
    tree_roots: set[str] = set()
    catalogue_module = profile["catalogue_module"]
    rows = catalogue_module[profile.get(
        "catalogue_iterator_name", "iter_path_catalogue_rows_with_reader",
    )](
        catalogue, profile["catalogue_reader"],
    )
    for row in rows:
        path = row["path"]
        if (row["kind"] == "tree" and row["role"] == "opaque_trace" and
                row["host_id"] == context["host_id"] and
                row["phase"] == context["phase"] and
                row["run_id"] == job_identity["run_id"]):
            tree_roots.add(path)
        if path not in targets:
            continue
        _require(path not in found,
                 "preparatory target has duplicate path-catalogue rows")
        role, byte_count, raw_sha, semantic_sha = targets[path]
        if path in job_targets:
            expected_host = context["host_id"]
            expected_phase = context["phase"]
            expected_run = job_identity["run_id"]
        elif path == job_record_pin["path"]:
            expected_host, expected_phase, expected_run = (
                context["host_id"], context["phase"], job_identity["run_id"],
            )
        elif path == profile["width_pin"]["path"]:
            expected_host, expected_phase, expected_run = (
                context["host_id"], None, None,
            )
        else:
            expected_host = expected_phase = expected_run = None
        _require(row["kind"] == "file" and row["role"] == role and
                 row["host_id"] == expected_host and
                 row["phase"] == expected_phase and
                 row["run_id"] == expected_run and
                 row["max_inodes"] == 1 and
                 row["max_file_bytes"] == row["max_bytes"] and
                 byte_count <= row["max_file_bytes"],
                 "preparatory job row differs from its exact typed catalogue entry/cap")
        if row["origin_pin"] is not None:
            origin_pin = _exact(row["origin_pin"],
                                {"raw_sha256", "semantic_sha256"},
                                "preparatory catalogued object pin")
            _require(origin_pin["raw_sha256"] == raw_sha and
                     origin_pin["semantic_sha256"] == semantic_sha,
                     "preparatory object differs from its catalogued raw/semantic pin")
        found[path] = row
    _require(set(found) == set(targets),
             "preparatory job/record/width objects are not closed by exact catalogue rows")
    expected_tree_roots = set() if checked_trees is None else {
        row["root_path"] for row in checked_trees
    }
    _require(tree_roots == expected_tree_roots,
             "preparatory request omits or adds an opaque-trace tree declaration")


def _validate_host_budget_object_rows(
    budget_raw: bytes, context: dict[str, Any], job_identity: dict[str, Any],
    entries: list[dict[str, Any]], job_record_pin: dict[str, str],
    job_record_bytes: int, job_record_semantic_sha256: str,
    catalogue_chunk_paths: dict[str, str], catalogue_cache_root: str,
    source_manifest_raw: bytes | None = None,
    execution_manifest_raw: bytes | None = None,
    journal_width_contract_raw: bytes | None = None,
    tree_inventories_value: object | None = None,
    owner_receipt_pins_value: object | None = None,
    plan_raw: bytes | None = None,
    spec_raw: bytes | None = None,
) -> None:
    """Bind every reclaimable row and the local job record to exact budget rows."""
    preparatory_probe = _parse_canonical(
        budget_raw, "host evidence budget object-row input",
        maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES,
    )
    if preparatory_probe.get("schema") == PREPARATORY_BUDGET_SCHEMA_V1:
        _validate_preparatory_host_budget_object_rows(
            budget_raw, context, job_identity, entries, job_record_pin,
            job_record_bytes, job_record_semantic_sha256,
            catalogue_chunk_paths, catalogue_cache_root,
            source_manifest_raw, execution_manifest_raw,
            plan_raw, journal_width_contract_raw, spec_raw,
            tree_inventories_value,
            owner_receipt_pins_value,
        )
        return
    budget_pin = _pin(context["resource_budget_pin"],
                      "host budget object-row pin")
    _require(_sha(budget_raw) == budget_pin["raw_sha256"],
             "host budget raw bytes differ before object-row validation")
    budget, _is_r6 = _parse_host_budget_value(
        budget_raw, "host evidence budget v2",
    )
    budget_body = {key: item for key, item in budget.items()
                   if key != "budget_sha256"}
    _require(budget.get("schema") in {
                 HOST_BUDGET_SCHEMA_V2, HOST_BUDGET_SCHEMA_V3,
             } and
             budget.get("campaign_id") == context["campaign_id"] and
             budget.get("host_id") == context["host_id"] and
             budget.get("budget_sha256") == _sha(_canonical(budget_body)) ==
                 budget_pin["semantic_sha256"],
             "host budget identity/semantic pin differs for object rows")
    _validate_host_budget_revision(
        budget, context, budget_raw=budget_raw,
        source_manifest_raw=source_manifest_raw,
        execution_manifest_raw=execution_manifest_raw,
        journal_width_contract_raw=journal_width_contract_raw,
        catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
        root_local=True,
        require_v4_manifest=execution_manifest_raw is not None,
    )
    original_pins = _exact(budget.get("original_pins"), {
        "spec", "plan", "execution_manifest", "source_manifests",
        "source_tree_sha256",
    }, "host budget original input pins")
    _digest(original_pins["source_tree_sha256"], "budget source tree SHA-256")
    source_pins = original_pins["source_manifests"]
    _require(type(source_pins) is dict and context["host_id"] in source_pins and
             _pin(original_pins["plan"], "budget PlanV3 pin") ==
                 context["plan_pin"] and
             _pin(original_pins["execution_manifest"],
                  "budget execution-manifest pin") ==
                 context["execution_manifest_pin"] and
             _pin(source_pins[context["host_id"]],
                  "budget SourceV5 pin") == context["source_manifest_pin"],
             "archive context Source/Plan/execution pins differ from host budget")
    catalogue = budget.get("path_catalogue")
    _require(type(catalogue) is dict and
             catalogue.get("schema") ==
                 "allocatbelt.application-source5-host-path-catalogue.v2" and
             type(catalogue.get("chunks")) is list and
             bool(catalogue["chunks"]),
             "host budget lacks its exact path catalogue chunks")
    catalogue_body = {key: item for key, item in catalogue.items()
                      if key != "semantic_sha256"}
    _require(catalogue.get("semantic_sha256") ==
             _sha(_canonical(catalogue_body)),
             "host path catalogue semantic digest differs")
    retention = catalogue.get("retention_policy")
    _require(type(retention) is dict,
             "host path catalogue lacks the prospective live-window ceiling")
    window_bytes = _uint(retention.get("maximum_window_total_bytes"),
                         "host maximum live-window bytes")
    window_inodes = _uint(retention.get("maximum_window_total_inodes"),
                          "host maximum live-window inodes")
    tree_inventories = None
    tree_file_paths: set[str] = set()
    trees_by_root: dict[str, dict[str, Any]] = {}
    if tree_inventories_value is not None:
        _require(type(owner_receipt_pins_value) is dict,
                 "v2 tree closure lacks its exact owner receipt pin map")
        tree_inventories = _validate_tree_inventories(
            tree_inventories_value, entries, owner_receipt_pins_value,
            expected_job_sha256=job_identity["job_sha256"],
        )
        trees_by_root = {row["root_path"]: row for row in tree_inventories}
        tree_file_paths = {
            entry["path"] for tree in tree_inventories
            for entry in tree["entries"] if entry["kind"] == "file"
        }
    tree_inode_count = (
        len(entries) - len(tree_file_paths) + sum(
            1 + tree["entry_count"] for tree in (tree_inventories or [])
        )
    )
    _require(sum(row["byte_count"] for row in entries) <= window_bytes and
             tree_inode_count <= window_inodes,
             "job object closure exceeds its pinned live-window bytes/inodes")
    chunk_bytes = _uint(catalogue.get("chunk_bytes"),
                        "host path catalogue chunk byte cap", positive=True)
    entry_count = _uint(catalogue.get("entry_count"),
                        "host path catalogue entry count", positive=True)
    _require(chunk_bytes <= MAX_JSON_BYTES and entry_count <= MAX_ROWS,
             "host path catalogue exceeds its finite metadata row/byte bound")
    all_targets = {
        row["origin_path"]: (row["role"], row["byte_count"],
                             row["raw_sha256"], row["semantic_sha256"])
        for row in entries
    }
    _require(job_record_pin["path"] not in all_targets,
             "always-local job record appeared in reclaimable budget targets")
    targets = {
        path: value for path, value in all_targets.items()
        if path not in tree_file_paths
    }
    targets[job_record_pin["path"]] = (
        "source5_job_record", job_record_bytes,
        job_record_pin["raw_sha256"], job_record_semantic_sha256,
    )
    width_contract_pin = None
    if _is_r6:
        width_contract_pin = _pin(
            budget["journal_width_contract_pin"],
            "R6 v4 width-contract catalogue pin",
        )
        _require(journal_width_contract_raw is not None and
                 width_contract_pin["path"] not in targets and
                 _validate_v4_width_contract_bytes(
                     journal_width_contract_raw, width_contract_pin, context,
                 )["contract_sha256"] == width_contract_pin["semantic_sha256"],
                 "R6 v4 width contract is missing or aliases a reclaimable/local record")
    else:
        _require(journal_width_contract_raw is None,
                 "legacy host budget cannot carry a v4 width-contract artifact")
    descriptors = []
    previous_descriptor_path = ""
    previous_last_path = ""
    described_rows = 0
    for index, descriptor_value in enumerate(catalogue["chunks"]):
        descriptor = _exact(descriptor_value, {
            "path", "raw_sha256", "semantic_sha256", "byte_count",
            "row_count", "first_path", "last_path",
        }, f"host path catalogue chunk[{index}]")
        chunk_path = _absolute_path(descriptor["path"],
                                    "host path catalogue chunk path")
        raw_sha = _digest(descriptor["raw_sha256"],
                          "host path catalogue chunk raw digest")
        semantic_sha = _digest(descriptor["semantic_sha256"],
                               "host path catalogue chunk semantic digest")
        byte_count = _uint(descriptor["byte_count"],
                           "host path catalogue chunk byte count", positive=True)
        row_count = _uint(descriptor["row_count"],
                          "host path catalogue chunk row count", positive=True)
        first_path = _absolute_path(descriptor["first_path"],
                                    "host catalogue first path")
        last_path = _absolute_path(descriptor["last_path"],
                                   "host catalogue last path")
        _require(chunk_path > previous_descriptor_path and
                 first_path <= last_path and first_path > previous_last_path and
                 semantic_sha == raw_sha and byte_count <= chunk_bytes and
                 row_count <= MAX_ROWS,
                 "host path catalogue chunk pins or order differ")
        previous_descriptor_path = chunk_path
        previous_last_path = last_path
        described_rows += row_count
        descriptors.append((first_path, last_path, chunk_path, raw_sha,
                            byte_count, row_count))
    _require(described_rows == entry_count,
             "host path catalogue chunk row counts do not close")
    cache_root = Path(_absolute_path(catalogue_cache_root,
                                     "private catalogue cache root"))
    cache_fd = _open_dir_path(str(cache_root), "private catalogue cache root",
                              private_final=True)
    os.close(cache_fd)
    _require(type(catalogue_chunk_paths) is dict and
             set(catalogue_chunk_paths) ==
                 {item[2] for item in descriptors},
             "Root-local catalogue chunk map does not close over its pinned budget")
    checked_local_paths = {}
    local_names = set()
    for descriptor in descriptors:
        origin = descriptor[2]
        local = Path(_absolute_path(catalogue_chunk_paths[origin],
                                    "Root-local catalogue chunk"))
        _require(local != cache_root and cache_root in local.parents and
                 str(local) != origin and str(local) not in local_names and
                 local.resolve(strict=True) == local,
                 "catalogue chunk is not a distinct file under the private cache root")
        local_names.add(str(local))
        checked_local_paths[origin] = str(local)
    _validate_captured_h15_archive_readback_profile(
        budget_raw, budget, context, checked_local_paths,
        str(cache_root),
    )
    if tree_inventories is not None:
        expected_tree_paths = _opaque_tree_catalogue_paths_for_job(
            budget_pin["raw_sha256"], descriptors, checked_local_paths,
            context["host_id"], context["phase"], job_identity["run_id"],
        )
        _require(expected_tree_paths == set(trees_by_root),
                 "v2 tree inventories omit or add an opaque-trace catalogue declaration")
    selected = {}
    catalogue_targets = set(targets) | set(trees_by_root)
    if width_contract_pin is not None:
        catalogue_targets.add(width_contract_pin["path"])
    for target in catalogue_targets:
        matches = [item for item in descriptors
                   if item[0] <= target <= item[1]]
        _require(len(matches) == 1,
                 "budgeted origin path is absent from one exact catalogue chunk")
        selected[matches[0][2]] = matches[0]
    found: dict[str, dict[str, Any]] = {}
    found_width_contract = width_contract_pin is None
    previous_path = ""
    for first_path, last_path, chunk_path, raw_sha, byte_count, row_count in sorted(
        selected.values(), key=lambda item: item[2],
    ):
        local_path = checked_local_paths[chunk_path]
        raw, actual_sha, _info = _read_absolute_private_file(
            Path(local_path), byte_count, "Root-local pinned host catalogue chunk",
        )
        _require(len(raw) == byte_count and actual_sha == raw_sha,
                 "host path catalogue chunk differs from its raw pin")
        lines = raw.splitlines(keepends=True)
        _require(len(lines) == row_count and bool(lines),
                 "host path catalogue chunk line count differs")
        chunk_first = ""
        chunk_last = ""
        for line_index, line in enumerate(lines):
            _require(line.endswith(b"\n") and b"\r" not in line and
                     len(line) <= 64 * 1024,
                     "host path catalogue row framing/size differs")
            row = _parse_canonical(
                line, f"host path catalogue row {chunk_path}:{line_index}",
            )
            row = _exact(row, {
                "path", "kind", "role", "host_id", "max_bytes",
                "max_file_bytes", "max_inodes", "storage_root", "owner",
                "phase", "run_id", "member_index", "aggregate_id",
                "aggregate_max_bytes", "origin_pin",
            }, "host path catalogue row")
            _require(_canonical(row) == line,
                     "host path catalogue row is not canonical")
            path = _absolute_path(row["path"], "host path catalogue origin")
            _require(path > previous_path and
                     row["kind"] in {"file", "tree"} and
                     row["role"] == _token(row["role"],
                                           "host catalogue role"),
                     "host path catalogue row order or kind differs")
            previous_path = path
            chunk_first = path if not chunk_first else chunk_first
            chunk_last = path
            for field in ("max_bytes", "max_file_bytes", "max_inodes"):
                _uint(row[field], f"host path catalogue {field}")
            if row["storage_root"] is not None:
                _absolute_path(row["storage_root"],
                               "host path catalogue storage root")
            _token(row["owner"], "host path catalogue owner")
            if row["host_id"] is not None:
                _token(row["host_id"], "host path catalogue host ID")
            if row["phase"] is not None:
                _token(row["phase"], "host path catalogue phase")
            if row["run_id"] is not None:
                _run_id(row["run_id"], "host path catalogue run ID")
            _require(
                     row["max_file_bytes"] <= row["max_bytes"] and
                     ((row["kind"] == "file" and row["max_inodes"] == 1) or
                      (row["kind"] == "tree" and row["max_inodes"] > 0)),
                     "host path catalogue row bounds/owner/group are malformed")
            if path in targets:
                _require(path not in found and row["kind"] == "file" and
                         row["host_id"] == context["host_id"] and
                         row["phase"] == context["phase"] and
                         row["run_id"] == job_identity["run_id"] and
                         row["role"] == targets[path][0] and
                         row["max_inodes"] == 1 and
                         row["max_file_bytes"] == row["max_bytes"] and
                         targets[path][1] <= row["max_file_bytes"],
                         "budgeted job object differs from its exact catalogue row/cap")
                if row["origin_pin"] is not None:
                    origin_pin = _exact(row["origin_pin"], {
                        "raw_sha256", "semantic_sha256",
                    }, "catalogued original object pin")
                    origin_raw = _digest(
                        origin_pin["raw_sha256"], "catalogued origin raw digest",
                    )
                    origin_semantic = origin_pin["semantic_sha256"]
                    if origin_semantic is not None:
                        origin_semantic = _digest(
                            origin_semantic,
                            "catalogued origin semantic digest",
                        )
                    _require(origin_raw == targets[path][2] and
                             origin_semantic == targets[path][3],
                             "request object differs from its catalogued origin pin")
                found[path] = row
            elif path in trees_by_root:
                tree = trees_by_root[path]
                max_tree_file = max(
                    (entry["size"] for entry in tree["entries"]
                     if entry["kind"] == "file"),
                    default=0,
                )
                _require(path not in found and row["kind"] == "tree" and
                         row["host_id"] == context["host_id"] and
                         row["phase"] == context["phase"] and
                         row["run_id"] == job_identity["run_id"] and
                         row["role"] == tree["role"] == "opaque_trace" and
                         row["max_inodes"] >= tree["entry_count"] + 1 and
                         tree["byte_count"] <= row["max_bytes"] and
                         max_tree_file <= row["max_file_bytes"],
                         "tree inventory exceeds its exact typed catalogue root cap")
                found[path] = row
            elif width_contract_pin is not None and path == width_contract_pin["path"]:
                origin_pin = row["origin_pin"]
                _require(path not in found and row["kind"] == "file" and
                         row["role"] == "journal_width_contract" and
                         row["owner"] == "source5_controller" and
                         row["host_id"] == context["host_id"] and
                         row["phase"] is None and row["run_id"] is None and
                         row["max_inodes"] == 1 and
                         row["max_file_bytes"] >=
                             len(journal_width_contract_raw) and
                         row["max_bytes"] >= len(journal_width_contract_raw) and
                         type(origin_pin) is dict and
                         _exact(origin_pin, {"raw_sha256", "semantic_sha256"},
                                "catalogued journal-width origin pin") == {
                                    "raw_sha256": width_contract_pin["raw_sha256"],
                                    "semantic_sha256": width_contract_pin["semantic_sha256"],
                                },
                         "v4 width contract differs from its exact always-local catalogue row")
                found_width_contract = True
        _require(chunk_first == first_path and chunk_last == last_path,
                 "host path catalogue chunk range differs from its raw rows")
    _require(set(found) == set(targets) | set(trees_by_root) and found_width_contract,
             "host path catalogue does not close over the exact job object set")


def _opaque_tree_catalogue_paths_for_job(
    budget_raw_sha256: str,
    descriptors: list[tuple[str, str, str, str, int, int]],
    local_paths: dict[str, str], host_id: str, phase: str, run_id: str,
) -> set[str]:
    """Return every exact opaque-trace tree declaration for one original job.

    Catalogue chunks are scanned once per immutable budget pin and only the
    small set of typed tree declarations is retained. This closes against an
    omitted root without treating a path prefix as authority or rescanning the
    complete multi-host catalogue for every job.
    """
    key = _digest(budget_raw_sha256, "tree catalogue budget raw digest")
    cache = _OPAQUE_TREE_CATALOGUE_CACHE.get(key)
    if cache is None:
        groups: dict[tuple[str, str, str], set[str]] = {}
        previous_path = ""
        rows_seen = 0
        for first_path, last_path, chunk_path, raw_sha, byte_count, row_count in descriptors:
            local_path = local_paths.get(chunk_path)
            _require(local_path is not None,
                     "tree declaration scan lacks one captured catalogue chunk")
            raw, actual_sha, _info = _read_absolute_private_file(
                Path(local_path), byte_count,
                "captured catalogue chunk for typed tree closure",
            )
            _require(len(raw) == byte_count and actual_sha == raw_sha,
                     "captured catalogue chunk changed during typed tree closure")
            lines = raw.splitlines(keepends=True)
            _require(len(lines) == row_count and bool(lines),
                     "typed tree catalogue chunk row count differs from its pin")
            chunk_first = ""
            chunk_last = ""
            for line_index, line in enumerate(lines):
                _require(line.endswith(b"\n") and b"\r" not in line and
                         len(line) <= 64 * 1024,
                         "typed tree catalogue line framing/size differs")
                row = _exact(_parse_canonical(
                    line, f"typed tree catalogue row {chunk_path}:{line_index}",
                ), {
                    "path", "kind", "role", "host_id", "max_bytes",
                    "max_file_bytes", "max_inodes", "storage_root", "owner",
                    "phase", "run_id", "member_index", "aggregate_id",
                    "aggregate_max_bytes", "origin_pin",
                }, "typed tree catalogue row")
                _require(_canonical(row) == line,
                         "typed tree catalogue row is not canonical")
                path = _absolute_path(row["path"],
                                      "typed tree catalogue path")
                _require(path > previous_path and
                         row["kind"] in {"file", "tree"},
                         "typed tree catalogue path order or kind differs")
                previous_path = path
                chunk_first = path if not chunk_first else chunk_first
                chunk_last = path
                role = _token(row["role"], "typed tree catalogue role")
                if row["kind"] == "tree" and role == "opaque_trace":
                    _require(type(row["host_id"]) is str and
                             type(row["phase"]) is str and
                             type(row["run_id"]) is str,
                             "opaque-trace tree declaration lacks its exact job identity")
                    group = (
                        _token(row["host_id"], "opaque-trace catalogue host ID"),
                        _token(row["phase"], "opaque-trace catalogue phase"),
                        _run_id(row["run_id"], "opaque-trace catalogue run ID"),
                    )
                    groups.setdefault(group, set()).add(path)
                rows_seen += 1
                _require(rows_seen <= MAX_ROWS,
                         "typed tree catalogue exceeds its finite global row count")
            _require(chunk_first == first_path and chunk_last == last_path,
                     "typed tree catalogue chunk path range differs from its pin")
        cache = {group: frozenset(paths) for group, paths in groups.items()}
        if len(_OPAQUE_TREE_CATALOGUE_CACHE) >= 4:
            _OPAQUE_TREE_CATALOGUE_CACHE.pop(
                next(iter(_OPAQUE_TREE_CATALOGUE_CACHE)),
            )
        _OPAQUE_TREE_CATALOGUE_CACHE[key] = cache
    return set(cache.get((host_id, phase, run_id), frozenset()))


def _validate_job_record(
    context: dict[str, Any], job_record_pin: object, job_record_bytes: bytes,
    plan_bytes: bytes, *, successor_run_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    pin = _pin_raw(job_record_pin, "Source5 job record pin")
    _require(_sha(job_record_bytes) == pin["raw_sha256"],
             "Source5 job record bytes differ from their raw pin")
    record = _parse_canonical(job_record_bytes, "Source5 job record")
    _exact(record, {
        "schema", "state", "job", "pair_directory", "process_metrics",
        "evidence", "chronology", "qualification_eligible", "record_sha256",
    }, "Source5 job record")
    body = {key: item for key, item in record.items() if key != "record_sha256"}
    _require(record["schema"] == "allocatbelt.application-source5-job-record.v1" and
             record["record_sha256"] == _sha(_canonical(body)) and
             record["qualification_eligible"] is False,
             "Source5 job record schema, self digest, or eligibility differs")
    plan_pin = context["plan_pin"]
    _require(type(plan_bytes) is bytes and _sha(plan_bytes) ==
             plan_pin["raw_sha256"],
             "raw PlanV3 bytes differ from their archive context pin")
    plan = _parse_canonical(
        plan_bytes, "original PlanV3", maximum_bytes=MAX_PLAN_BYTES,
    )
    _require(plan.get("schema") == "allocatbelt.application-campaign-plan.v3" and
             plan.get("campaign_id") == context["campaign_id"] and
             plan.get("plan_sha256") == plan_pin["semantic_sha256"] and
             plan.get("plan_sha256") == _sha(_canonical({
                 key: item for key, item in plan.items()
                 if key != "plan_sha256"
             }, maximum_bytes=MAX_PLAN_BYTES)),
             "PlanV3 identity or semantic digest differs from the archive context")
    job = record["job"]
    _require(type(job) is dict and job.get("host_id") == context["host_id"] and
             job.get("phase") == context["phase"] and
             type(job.get("ordinal")) is int and job["ordinal"] > 0 and
             type(job.get("run_id")) is str and
             type(record["process_metrics"]) is list,
             "Source5 job record identity is malformed")
    phase_jobs = plan.get("jobs", {}).get(context["phase"])
    _require(type(phase_jobs) is list and
             all(type(item) is dict for item in phase_jobs),
             "PlanV3 lacks the exact original phase job list")
    host_jobs = [item for item in phase_jobs
                 if item.get("host_id") == context["host_id"]]
    _require(context["job_index"] < len(host_jobs) and
             host_jobs[context["job_index"]] == job,
             "Source5 job record differs from its original filtered PlanV3 ordinal")
    job_sha = _sha(_canonical(job))
    job_identity = {
        "job": job, "job_index": context["job_index"],
        "job_ordinal": job["ordinal"], "job_sha256": job_sha,
        "run_id": _run_id(job["run_id"], "Source5 run ID"),
    }
    if successor_run_id is not None:
        target_run_id = _run_id(successor_run_id,
                                "expected PlanV3 successor run ID")
        jobs = plan.get("jobs")
        _require(type(jobs) is dict and bool(jobs),
                 "PlanV3 lacks its original phase job map")
        matches = []
        for target_phase, target_jobs in jobs.items():
            _token(target_phase, "PlanV3 successor phase")
            _require(type(target_jobs) is list and
                     all(type(item) is dict for item in target_jobs),
                     "PlanV3 successor phase list is malformed")
            filtered_index = 0
            for target_job in target_jobs:
                if target_job.get("host_id") != context["host_id"]:
                    continue
                if target_job.get("run_id") == target_run_id:
                    matches.append((target_phase, filtered_index, target_job))
                filtered_index += 1
        _require(len(matches) == 1,
                 "expected successor run ID is not unique in the original host PlanV3")
        target_phase, target_index, target_job = matches[0]
        target_predecessors = target_job.get("predecessor_run_ids")
        _require(target_run_id != job["run_id"] and
                 target_job.get("phase") == target_phase and
                 type(target_job.get("ordinal")) is int and
                 target_job["ordinal"] > 0 and
                 type(target_predecessors) is list and
                 target_predecessors == [job["run_id"]],
                 "expected run ID is not the exact PlanV3 predecessor of its successor")
        job_identity["plan_successor"] = {
            "phase": target_phase, "job_index": target_index,
            "ordinal": target_job["ordinal"], "run_id": target_run_id,
        }
    predecessors = job.get("predecessor_run_ids", [])
    _require(type(predecessors) is list and
             all(type(item) is str and item for item in predecessors),
             "PlanV3 predecessor run list is malformed")
    _require((context["predecessor_ack_pin"] is None) == (not predecessors) and
             len(predecessors) <= 1,
             "predecessor ACK presence differs from the original PlanV3 job")
    chronology = _exact(record["chronology"], {
        "authorization_id", "authorization_head", "app_started_heads",
        "app_terminal_heads", "job_terminal_head", "component_sha256",
        "process_metrics_sha256", "app_start_events", "app_terminal_events",
        "member_processes",
    }, "Source5 job record chronology")
    authorization = {
        "authorization_id": _token(chronology["authorization_id"],
                                   "Source5 authorization ID"),
        "authorization_head": _digest(chronology["authorization_head"],
                                      "Source5 authorization head"),
        "terminal_head": _digest(chronology["job_terminal_head"],
                                 "Source5 terminal head"),
        "component_sha256": _digest(chronology["component_sha256"],
                                    "Source5 component digest"),
        "process_metrics_sha256": _digest(
            chronology["process_metrics_sha256"],
            "Source5 process metrics digest",
        ),
    }
    _require(authorization["process_metrics_sha256"] ==
             _sha(_canonical(record["process_metrics"])),
             "Source5 job record metrics differ from the terminal chain")
    _require(pin["path"].endswith("/" + job["run_id"] + ".json"),
             "Source5 job record path does not name its exact run ID")
    return record, authorization, job_identity


def _validate_rows(value: object) -> list[dict[str, Any]]:
    _require(type(value) in (list, tuple) and 0 < len(value) <= MAX_ROWS,
             "archive object rows are outside their finite count bound")
    rows: list[dict[str, Any]] = []
    prior = ""
    total = 0
    for index, row_value in enumerate(value):
        row = _exact(row_value, {
            "origin_path", "role", "byte_count", "raw_sha256", "semantic_sha256",
        }, f"archive row[{index}]")
        origin = _absolute_path(row["origin_path"], f"archive row[{index}] origin")
        role = _token(row["role"], f"archive row[{index}] role")
        _require(role not in NON_EXPORTABLE_JOB_ROLES,
                 "non-exportable Source5 controller/job role is not reclaimable")
        count = _uint(row["byte_count"], f"archive row[{index}] byte count")
        _require(count <= MAX_OBJECT_BYTES and origin > prior,
                 "archive rows are unsorted, duplicated, or exceed the per-object ceiling")
        prior = origin
        total += count
        _require(total <= MAX_TOTAL_BYTES,
                 "archive rows exceed the fixed total-payload ceiling")
        semantic = row["semantic_sha256"]
        _require(semantic is None or
                 (type(semantic) is str and
                  re.fullmatch(r"[0-9a-f]{64}", semantic) is not None),
                 f"archive row[{index}] semantic SHA-256 is malformed")
        rows.append({
            "origin_path": origin, "role": role, "byte_count": count,
            "raw_sha256": _digest(row["raw_sha256"],
                                  f"archive row[{index}] raw SHA-256"),
            "semantic_sha256": semantic,
        })
    return rows


def _tree_contains(root_path: str, child_path: str) -> bool:
    prefix = "/" if root_path == "/" else root_path + "/"
    return child_path.startswith(prefix) and child_path != root_path


def _validate_tree_inventories(
    value: object, entries_value: object,
    owner_receipt_pins_value: object, *, expected_job_sha256: str | None = None,
) -> list[dict[str, Any]]:
    """Close v2 opaque-trace inventory rows over exact payload and receipt pins."""
    _require(type(value) is list and len(value) <= MAX_ROWS,
             "tree inventory rows exceed their finite count bound")
    entries = _validate_rows(entries_value)
    by_origin = {row["origin_path"]: row for row in entries}
    owner_receipts = owner_receipt_pins_value
    _require(type(owner_receipts) is dict and
             list(owner_receipts) == sorted(owner_receipts),
             "tree inventory owner-receipt map is malformed")
    owner_by_pin = {}
    for role, pin_value in owner_receipts.items():
        _token(role, "tree inventory owner-receipt role")
        pin = _pin(pin_value, f"tree inventory owner receipt {role}")
        owner_by_pin[(pin["path"], pin["raw_sha256"],
                      pin["semantic_sha256"])] = role

    checked: list[dict[str, Any]] = []
    prior_root = ""
    payload_paths: set[str] = set()
    receipt_paths: set[str] = set()
    total_inventory_entries = 0
    for index, value_row in enumerate(value):
        row = _exact(value_row, {
            "owner_job_sha256", "root_path", "role", "owner_receipt_pin",
            "inventory_pin", "inventory_sha256", "entry_count", "byte_count",
            "entries",
        }, f"tree inventory[{index}]")
        job_sha = _digest(row["owner_job_sha256"],
                          f"tree inventory[{index}] owner job digest")
        _require(expected_job_sha256 is None or job_sha == expected_job_sha256,
                 "tree inventory belongs to another original PlanV3 job")
        root = _absolute_path(row["root_path"],
                              f"tree inventory[{index}] root path")
        role = _token(row["role"], f"tree inventory[{index}] role")
        _require(role == "opaque_trace" and root > prior_root and
                 not any(_tree_contains(previous["root_path"], root) or
                         _tree_contains(root, previous["root_path"])
                         for previous in checked),
                 "tree inventory roots are not sorted, unique, disjoint opaque-trace declarations")
        prior_root = root
        owner_pin = _pin(row["owner_receipt_pin"],
                         f"tree inventory[{index}] owner receipt")
        owner_key = (owner_pin["path"], owner_pin["raw_sha256"],
                     owner_pin["semantic_sha256"])
        owner_role = owner_by_pin.get(owner_key)
        _require(owner_role is not None and
                 re.fullmatch(r"probe_capture_receipt(?:_member[0-9]+)?",
                              owner_role) is not None and
                 not _tree_contains(root, owner_pin["path"]) and
                 owner_pin["path"] not in receipt_paths,
                 "tree inventory is not bound to one unique ProbeV2 capture receipt")
        receipt_paths.add(owner_pin["path"])

        inventory_pin = _pin(row["inventory_pin"],
                             f"tree inventory[{index}] inventory object")
        inventory_sha = _digest(
            row["inventory_sha256"],
            f"tree inventory[{index}] semantic digest",
        )
        _require(inventory_pin["semantic_sha256"] == inventory_sha,
                 "tree inventory semantic pin differs from its inventory digest")
        inventory_row = by_origin.get(inventory_pin["path"])
        _require(inventory_row is not None and
                 re.fullmatch(r"probe_capture_inventory(?:_member[0-9]+)?",
                              inventory_row["role"]) is not None and
                 inventory_row["role"] not in NON_EXPORTABLE_JOB_ROLES and
                 inventory_row["raw_sha256"] == inventory_pin["raw_sha256"] and
                 inventory_row["semantic_sha256"] == inventory_sha and
                 inventory_pin["path"] != root and
                 not _tree_contains(root, inventory_pin["path"]),
                 "tree inventory document is not one exact non-reclaimable receipt-role object")
        _require(all(inventory_pin["path"] != previous["inventory_pin"]["path"]
                     for previous in checked),
                 "one ProbeV2 inventory object cannot describe multiple TMP roots")

        inventory_entries_value = row["entries"]
        _require(type(inventory_entries_value) is list and
                 len(inventory_entries_value) <= MAX_ROWS,
                 "tree inventory entries exceed their finite count bound")
        total_inventory_entries += len(inventory_entries_value)
        _require(total_inventory_entries <= MAX_ROWS,
                 "job tree inventories exceed the shared bounded row count")
        inventory_entries = []
        prior_path = ""
        total_tree_bytes = 0
        files: set[str] = set()
        for entry_index, entry_value in enumerate(inventory_entries_value):
            entry = _exact(entry_value, {
                "path", "kind", "uid", "mode", "size", "raw_sha256",
            }, f"tree inventory[{index}] entry[{entry_index}]")
            path = _absolute_path(
                entry["path"],
                f"tree inventory[{index}] entry[{entry_index}] path",
            )
            uid = _uint(entry["uid"],
                        f"tree inventory[{index}] entry[{entry_index}] uid")
            mode = _uint(entry["mode"],
                         f"tree inventory[{index}] entry[{entry_index}] mode")
            _require(path > prior_path and _tree_contains(root, path) and
                     mode <= 0o7777 and path not in payload_paths and
                     path not in {tree["root_path"] for tree in checked},
                     "tree inventory paths are unordered, duplicated, or outside their exact root")
            prior_path = path
            if entry["kind"] == "directory":
                _require(entry["size"] is None and
                         entry["raw_sha256"] is None,
                         "tree directory inventory row carries payload facts")
            elif entry["kind"] == "file":
                size = _uint(entry["size"],
                             f"tree inventory[{index}] file size")
                raw_sha = _digest(entry["raw_sha256"],
                                  f"tree inventory[{index}] file raw digest")
                request_row = by_origin.get(path)
                _require(request_row is not None and
                         request_row["role"] == role and
                         request_row["byte_count"] == size and
                         request_row["raw_sha256"] == raw_sha and
                         request_row["semantic_sha256"] is None,
                         "tree file does not match one exact reclaimable request object")
                files.add(path)
                payload_paths.add(path)
                total_tree_bytes += size
            else:
                raise EvidenceArchiveError(
                    "ProbeV2 tree inventory admits only regular files and directories",
                )
            inventory_entries.append({
                "path": path, "kind": entry["kind"], "uid": uid,
                "mode": mode, "size": entry["size"],
                "raw_sha256": entry["raw_sha256"],
            })
        declared_count = _uint(row["entry_count"],
                               f"tree inventory[{index}] entry count")
        declared_bytes = _uint(row["byte_count"],
                               f"tree inventory[{index}] byte count")
        _require(declared_count == len(inventory_entries) and
                 declared_bytes == total_tree_bytes and
                 total_tree_bytes <= MAX_U64,
                 "tree inventory declared count/bytes differ from its typed entries")
        inventory_paths = {entry["path"]: entry for entry in inventory_entries}
        for entry in inventory_entries:
            parent_path = PurePosixPath(entry["path"]).parent.as_posix()
            _require(parent_path == root or
                     (parent_path in inventory_paths and
                      inventory_paths[parent_path]["kind"] == "directory"),
                     "tree inventory omits a parent directory or places a child under a file")
        inventory_body = {
            "schema": PROBE_TMPDIR_INVENTORY_SCHEMA_V1,
            "entries": inventory_entries,
        }
        expected_inventory_sha = _sha(_canonical(inventory_body))
        inventory_document = {
            **inventory_body,
            "inventory_sha256": expected_inventory_sha,
        }
        inventory_raw = _canonical(inventory_document)
        _require(len(inventory_raw) <= MAX_PROBE_TMPDIR_INVENTORY_BYTES and
                 expected_inventory_sha == inventory_sha and
                 _sha(inventory_raw) == inventory_pin["raw_sha256"] and
                 inventory_row["byte_count"] == len(inventory_raw),
                 "tree inventory object bytes are not reconstructed by its exact typed rows")
        checked.append({
            "owner_job_sha256": job_sha, "root_path": root, "role": role,
            "owner_receipt_pin": owner_pin, "inventory_pin": inventory_pin,
            "inventory_sha256": inventory_sha,
            "entry_count": declared_count, "byte_count": declared_bytes,
            "entries": inventory_entries,
        })

    for row in entries:
        _require(all(row["origin_path"] != tree["root_path"]
                     for tree in checked),
                 "opaque-trace root cannot also be an object row")
        if any(_tree_contains(tree["root_path"], row["origin_path"])
               for tree in checked):
            _require(row["origin_path"] in payload_paths,
                     "request contains an undeclared or directory-only tree descendant")
    capture_receipt_paths = {
        pin["path"] for role, pin in owner_receipts.items()
        if role.startswith("probe_capture_receipt")
    }
    _require(receipt_paths == capture_receipt_paths,
             "tree inventories do not close over every pinned ProbeV2 capture receipt")
    return checked


def _tmp_final_proof(
    final_value: object, receipt_pin: dict[str, str], role: str,
    ordinal: int, label: str,
) -> dict[str, Any]:
    final = _exact(final_value, {
        "path", "device", "inode", "mode", "mount", "bytes_used",
        "file_count", "directory_count", "bytes_limit", "inode_limit",
        "available_bytes", "available_inodes",
    }, f"{label} final TMPDIR facts")
    path = _absolute_path(final["path"], f"{label} TMPDIR path")
    for field in ("device", "inode", "mode", "bytes_used", "file_count",
                  "directory_count", "bytes_limit", "inode_limit",
                  "available_bytes", "available_inodes"):
        _uint(final[field], f"{label} TMPDIR {field}")
    mount = _exact(final["mount"], {
        "mount_id", "major_minor", "mount_root", "mount_point",
        "filesystem_type", "mount_source", "device",
    }, f"{label} TMPDIR mount identity")
    _require(type(mount["mount_id"]) is int and mount["mount_id"] > 0 and
             type(mount["major_minor"]) is str and
             re.fullmatch(r"[0-9]+:[0-9]+", mount["major_minor"]) is not None and
             type(mount["mount_root"]) is str and mount["mount_root"].startswith("/") and
             type(mount["mount_point"]) is str and mount["mount_point"].startswith("/") and
             type(mount["filesystem_type"]) is str and
             mount["filesystem_type"] not in {"tmpfs", "ramfs", "devtmpfs"} and
             type(mount["mount_source"]) is str and
             type(mount["device"]) is int and mount["device"] >= 0 and
             mount["device"] == final["device"] and
             final["inode"] > 0 and final["mode"] == 0o700 and
             final["bytes_used"] == 0 and final["file_count"] == 0 and
             final["directory_count"] == 0 and final["bytes_limit"] > 0 and
             final["inode_limit"] > 0,
             f"{label} TMPDIR is not an exact empty private directory")
    return {
        "role": role, "path": path, "owner_receipt_pin": dict(receipt_pin),
        "member_ordinal": ordinal, "device": final["device"],
        "inode": final["inode"], "mode": final["mode"],
        "mount": mount, "bytes_used": 0, "file_count": 0,
        "directory_count": 0, "bytes_limit": final["bytes_limit"],
        "inode_limit": final["inode_limit"],
    }


def _zero_fixed_tmp_proofs(
    receipt: dict[str, Any], receipt_pin: dict[str, str], role: str, *,
    include_probe_tmp_proofs: bool = False,
) -> list[dict[str, Any]]:
    if receipt.get("schema") != "allocatbelt.application-fixed-pair-execution-receipt.v1":
        return []
    if receipt.get("status") != "valid_pair":
        return []
    attempts = receipt.get("member_attempts")
    _require(type(attempts) is list and len(attempts) == 2,
             "successful fixed receipt lacks its two original member TMPDIR facts")
    proofs = []
    for ordinal, attempt in enumerate(attempts):
        _require(type(attempt) is dict and attempt.get("ordinal") == ordinal,
                 "fixed receipt TMPDIR members are not in original order")
        proofs.append(_tmp_final_proof(
            attempt.get("tmpdir_final"), receipt_pin, role, ordinal,
            f"fixed member {ordinal}",
        ))
    if include_probe_tmp_proofs:
        probes = receipt.get("construction_probes")
        _require(type(probes) is list and len(probes) == 2,
                 "v2 successful fixed receipt lacks its two construction-probe TMPDIR facts")
        for ordinal, probe in enumerate(probes):
            _require(type(probe) is dict and
                     probe.get("member_ordinal") == ordinal,
                     "fixed construction-probe TMPDIR ordinals differ")
            proof = _tmp_final_proof(
                probe.get("tmpdir_final"), receipt_pin, role, ordinal,
                f"fixed construction probe {ordinal}",
            )
            proof["domain"] = "probe_tmpdir"
            proofs.append(proof)
    return proofs


def _zero_pressure_tmp_proofs(
    receipt: dict[str, Any], receipt_pin: dict[str, str], role: str,
) -> list[dict[str, Any]]:
    if receipt.get("schema") != "allocatbelt.application-pressure-pair-host-verification.v2":
        return []
    members = receipt.get("member_facts")
    _require(type(members) is list and len(members) == 2,
             "successful pressure receipt lacks two original member facts")
    proofs = []
    for ordinal, member in enumerate(members):
        _require(type(member) is dict and member.get("ordinal") == ordinal,
                 "pressure receipt member order differs from the original pair")
        storage = member.get("storage_proof")
        _require(type(storage) is dict and
                 "application_tmpdir_final" in storage,
                 "pressure owner receipt lacks its immediate final TMPDIR fact")
        proofs.append(_tmp_final_proof(
            storage["application_tmpdir_final"], receipt_pin, role,
            ordinal, f"pressure member {ordinal}",
        ))
    return proofs

def _zero_soak_tmp_proofs(
    receipt: dict[str, Any], receipt_pin: dict[str, str], role: str,
) -> list[dict[str, Any]]:
    if receipt.get("schema") != "allocatbelt.application-source5-soak-host-verification.v3":
        return []
    final = receipt.get("final_usage")
    domains = final.get("domains") if type(final) is dict else None
    domain = domains.get("application_tmpdir") if type(domains) is dict else None
    _require(type(domain) is dict and set(domain) == {"bytes_used", "inode_count"} and
             domain["bytes_used"] == 0 and domain["inode_count"] == 0,
             "successful Soak receipt does not prove zero application TMPDIR usage")
    origin = receipt.get("pressure_origin")
    _require(type(origin) is dict and
             type(origin.get("application_tmpdir_path")) is str,
             "Soak receipt lacks the original application TMPDIR path")
    inventory = receipt.get("evidence_inventory")
    _require(type(inventory) is list,
             "Soak receipt lacks its complete evidence inventory")
    return [{
        "role": role,
        "path": _absolute_path(origin["application_tmpdir_path"],
                                "Soak application TMPDIR path"),
        "owner_receipt_pin": dict(receipt_pin),
        "member_ordinal": 0, "domain": "application_tmpdir",
        "bytes_used": 0, "inode_count": 0,
        "inventory_sha256": _sha(_canonical(inventory)),
    }]


def _zero_usage_proofs(
    receipt: dict[str, Any], receipt_pin: dict[str, str], role: str, *,
    include_probe_tmp_proofs: bool = False,
) -> list[dict[str, Any]]:
    proofs = _zero_fixed_tmp_proofs(
        receipt, receipt_pin, role,
        include_probe_tmp_proofs=include_probe_tmp_proofs,
    )
    if proofs:
        return proofs
    proofs = _zero_pressure_tmp_proofs(receipt, receipt_pin, role)
    if proofs:
        return proofs
    return _zero_soak_tmp_proofs(receipt, receipt_pin, role)


def _bind_owner_receipt_identity(
    receipt: dict[str, Any], context: dict[str, Any], job: dict[str, Any],
    label: str,
) -> None:
    for field, expected in (
        ("campaign_id", context["campaign_id"]),
        ("host_id", context["host_id"]),
        ("run_id", job["run_id"]),
    ):
        if field in receipt:
            _require(receipt[field] == expected,
                     f"{label} {field} differs from its original job")
    nested_job = receipt.get("job")
    if type(nested_job) is dict and "run_id" in nested_job:
        _require(nested_job["run_id"] == job["run_id"] and
                 nested_job.get("ordinal") == job["ordinal"],
                 f"{label} nested job differs from its original ordinal")
        if "job_index" in nested_job:
            _require(nested_job["job_index"] == context["job_index"],
                     f"{label} nested job index differs from raw PlanV3")


def _fixed_pair_output_mount_static(value: object) -> dict[str, Any]:
    mount = _exact(value, {
        "mount_id", "major_minor", "mount_root", "mount_point",
        "filesystem_type", "mount_source", "device", "available_bytes",
        "available_inodes",
    }, "strict fixed-pair output mount")
    _uint(mount["mount_id"], "fixed-pair output mount ID", positive=True)
    _uint(mount["device"], "fixed-pair output mount device")
    _uint(mount["available_bytes"], "fixed-pair output mount available bytes")
    _uint(mount["available_inodes"], "fixed-pair output mount available inodes")
    _require(type(mount["major_minor"]) is str and
             re.fullmatch(r"[0-9]+:[0-9]+", mount["major_minor"]) is not None and
             type(mount["filesystem_type"]) is str and
             mount["filesystem_type"] not in {"tmpfs", "ramfs", "devtmpfs"} and
             type(mount["mount_source"]) is str,
             "strict fixed-pair output mount identity is malformed or memory-backed")
    _absolute_path(mount["mount_root"], "fixed-pair output mount root")
    _absolute_path(mount["mount_point"], "fixed-pair output mount point")
    return {key: mount[key] for key in (
        "mount_id", "major_minor", "mount_root", "mount_point",
        "filesystem_type", "mount_source", "device",
    )}


def _validate_fixed_pair_host_receipt_bindings(
    context: dict[str, Any], record: dict[str, Any],
    entries: list[dict[str, Any]], owner_receipt_pins: dict[str, Any], *,
    owner_receipt_bytes: dict[str, bytes] | None = None,
    overlay_raw: bytes | None = None,
    manifest_objects: list[dict[str, Any]] | None = None,
) -> None:
    """Close H14 fixed host-receipt pins over their original job and objects."""
    evidence = record.get("evidence")
    _require(type(evidence) is dict,
             "fixed-pair job evidence is not an object")
    host_pin_value = evidence.get("host_receipt")
    host_rows = [row for row in entries
                 if row["role"] == "fixed_pair_host_receipt"]
    pinned_host = owner_receipt_pins.get("fixed_pair_host_receipt")
    if host_pin_value is None:
        _require(not host_rows and pinned_host is None,
                 "fixed host receipt row has no original job-record pin")
        return

    _require(record["job"].get("phase") in {
                 "exploration", "aa", "confirmation",
             }, "strict fixed-pair host receipt is attached to a non-fixed phase")
    host_pin = _exact(host_pin_value, {
        "path", "raw_sha256", "host_verification_sha256",
    }, "original strict fixed-pair host receipt pin")
    host_path = _absolute_path(host_pin["path"],
                               "original strict fixed-pair host receipt path")
    host_raw_sha = _digest(host_pin["raw_sha256"],
                           "original strict fixed-pair host receipt raw digest")
    host_semantic = _digest(host_pin["host_verification_sha256"],
                            "original strict fixed-pair host receipt semantic digest")
    _require(len(host_rows) == 1 and
             host_rows[0]["origin_path"] == host_path and
             host_rows[0]["raw_sha256"] == host_raw_sha and
             host_rows[0]["semantic_sha256"] == host_semantic and
             pinned_host == {
                 "path": host_path, "raw_sha256": host_raw_sha,
                 "semantic_sha256": host_semantic,
             }, "strict fixed host receipt pin differs from its unique owner row")

    overlay_pin = _pin_raw(evidence.get("overlay"),
                           "original fixed-pair overlay pin")
    execution_pin = _pin_raw(evidence.get("receipt"),
                             "original fixed-pair execution receipt pin")
    by_origin = {row["origin_path"]: row for row in entries}
    overlay_row = by_origin.get(overlay_pin["path"])
    execution_row = by_origin.get(execution_pin["path"])
    _require(overlay_row is not None and
             overlay_row["role"] == "fixed_pair_artifact" and
             overlay_row["raw_sha256"] == overlay_pin["raw_sha256"] and
             execution_row is not None and
             execution_row["role"] == "component_receipt" and
             execution_row["raw_sha256"] == execution_pin["raw_sha256"],
             "strict fixed host receipt lacks its exact overlay/execution receipt rows")
    if manifest_objects is not None:
        object_by_origin = {row["origin_path"]: row
                            for row in manifest_objects}
        for origin, role, raw_sha, semantic_sha in (
            (host_path, "fixed_pair_host_receipt", host_raw_sha,
             host_semantic),
            (overlay_pin["path"], "fixed_pair_artifact",
             overlay_pin["raw_sha256"], overlay_row["semantic_sha256"]),
            (execution_pin["path"], "component_receipt",
             execution_pin["raw_sha256"], execution_row["semantic_sha256"]),
        ):
            obj = object_by_origin.get(origin)
            _require(obj is not None and obj["role"] == role and
                     obj["raw_sha256"] == raw_sha and
                     obj["semantic_sha256"] == semantic_sha,
                     "signed fixed host receipt manifest closure differs from its job pin")

    if owner_receipt_bytes is None:
        _require(overlay_raw is None,
                 "fixed host receipt overlay bytes require the owner receipt map")
        return
    host_raw = owner_receipt_bytes.get(host_path)
    execution_raw = owner_receipt_bytes.get(execution_pin["path"])
    _require(type(host_raw) is bytes and _sha(host_raw) == host_raw_sha and
             type(execution_raw) is bytes and
             _sha(execution_raw) == execution_pin["raw_sha256"],
             "fixed host receipt/execution receipt bytes are absent from their pinned rows")
    host_receipt, host_semantic_actual = _read_self_digest(
        host_raw, "strict fixed-pair host receipt", ("receipt_sha256",),
    )
    execution_receipt, execution_semantic = _read_self_digest(
        execution_raw, "fixed-pair execution receipt", ("receipt_sha256",),
    )
    _require(host_semantic_actual == host_semantic and
             execution_row["semantic_sha256"] == execution_semantic and
             execution_receipt.get("schema") ==
                 FIXED_PAIR_EXECUTION_RECEIPT_SCHEMA_V1 and
             execution_receipt.get("campaign_id") == context["campaign_id"] and
             execution_receipt.get("host_id") == context["host_id"] and
             execution_receipt.get("run_id") == record["job"]["run_id"],
             "fixed-pair execution receipt schema/identity/self pin differs")
    state = record.get("state")
    _require(type(state) is str,
             "fixed-pair host receipt job state is malformed")
    expected_status = {
        "valid_pair": "valid_pair",
        "invalid_pair": "failed_or_invalid",
    }.get(state)
    _require(expected_status is not None and
             execution_receipt.get("status") == expected_status,
             "fixed-pair execution receipt status differs from the sealed job state")
    _exact(host_receipt, {
        "schema", "strict_verified", "qualification_eligible",
        "execution_ready", "campaign_chronology_complete",
        "overlay_raw_sha256", "execution_receipt_raw_sha256",
        "execution_receipt_sha256", "status", "run_id",
        "host_verification", "receipt_sha256",
    }, "strict fixed-pair host receipt")
    _require(host_receipt["schema"] == FIXED_PAIR_HOST_RECEIPT_SCHEMA_V1 and
             host_receipt["strict_verified"] is True and
             host_receipt["qualification_eligible"] is False and
             host_receipt["execution_ready"] is False and
             host_receipt["campaign_chronology_complete"] is False and
             host_receipt["overlay_raw_sha256"] == overlay_pin["raw_sha256"] and
             host_receipt["execution_receipt_raw_sha256"] ==
                 execution_pin["raw_sha256"] and
             host_receipt["execution_receipt_sha256"] == execution_semantic and
             host_receipt["status"] == expected_status and
             host_receipt["run_id"] == record["job"]["run_id"],
             "strict fixed-pair host receipt differs from its original job/raw evidence")
    host_identity = _exact(host_receipt["host_verification"], {
        "schema", "host_id", "observed_host_raw_sha256", "process_affinity",
        "network_namespace_inode", "output_mount", "host_verification_sha256",
    }, "strict fixed-pair host identity")
    identity_body = {key: value for key, value in host_identity.items()
                     if key != "host_verification_sha256"}
    observed_sha = _digest(host_identity["observed_host_raw_sha256"],
                           "fixed-pair observed-host raw digest")
    _require(host_identity["schema"] == FIXED_PAIR_HOST_IDENTITY_SCHEMA_V1 and
             host_identity["host_id"] == context["host_id"] and
             host_identity["host_verification_sha256"] ==
                 _sha(_canonical(identity_body)),
             "strict fixed-pair nested host identity schema/digest differs")
    affinity = host_identity["process_affinity"]
    _require(type(affinity) is list and bool(affinity) and
             affinity == sorted(set(
                 cpu for cpu in affinity
                 if type(cpu) is int and 0 <= cpu <= 65535
             )), "strict fixed-pair nested CPU affinity is malformed")
    _uint(host_identity["network_namespace_inode"],
          "fixed-pair network namespace inode", positive=True)
    mount_static = _fixed_pair_output_mount_static(
        host_identity["output_mount"],
    )
    host_body = {key: value for key, value in host_receipt.items()
                 if key != "receipt_sha256"}
    _require(host_receipt["receipt_sha256"] == host_semantic_actual ==
             _sha(_canonical(host_body)),
             "strict fixed-pair host receipt self digest differs")
    if overlay_raw is None:
        return
    overlay = _parse_canonical(
        overlay_raw, "captured fixed-pair execution overlay",
        maximum_bytes=MAX_PLAN_BYTES,
    )
    _require(_sha(overlay_raw) == overlay_pin["raw_sha256"],
             "captured fixed-pair overlay differs from its original raw pin")
    _exact(overlay, {
        "schema", "campaign_id", "host_id", "spec", "plan", "sources",
        "execution_source", "modules", "job", "runtime_bindings", "members",
        "deadlines", "artifact_budgets", "output_root", "overlay_sha256",
    }, "captured fixed-pair execution overlay")
    overlay_body = {key: value for key, value in overlay.items()
                    if key != "overlay_sha256"}
    _require(overlay["schema"] == FIXED_PAIR_OVERLAY_SCHEMA_V1 and
             overlay["campaign_id"] == context["campaign_id"] and
             overlay["host_id"] == context["host_id"] and
             overlay["overlay_sha256"] == _sha(_canonical(overlay_body)),
             "captured fixed-pair overlay schema/identity/self digest differs")
    output_root = _absolute_path(overlay["output_root"],
                                 "captured fixed-pair output root")
    _require(overlay_pin["path"] == str(
                 Path(output_root) / "fixed-pair-execution-overlay.json"),
             "captured fixed-pair overlay is outside its exact original output path")
    overlay_job = _exact(overlay["job"], {"value", "sha256"},
                         "captured fixed-pair original job")
    _require(overlay_job["value"] == record["job"] and
             overlay_job["sha256"] == _sha(_canonical(record["job"])),
             "captured fixed-pair overlay names a different original Plan job")
    plan_binding = _exact(overlay["plan"], {"pin", "semantic_sha256"},
                          "captured fixed-pair original PlanV3 binding")
    plan_raw_pin = _exact(plan_binding["pin"], {"path", "sha256"},
                          "captured fixed-pair PlanV3 raw pin")
    _require(plan_raw_pin["path"] == context["plan_pin"]["path"] and
             plan_raw_pin["sha256"] == context["plan_pin"]["raw_sha256"] and
             plan_binding["semantic_sha256"] ==
                 context["plan_pin"]["semantic_sha256"] and
             execution_receipt.get("overlay_sha256") ==
                 overlay["overlay_sha256"],
             "fixed-pair overlay/execution receipt differs from its original Plan/job pins")
    sources = _exact(overlay["sources"], {
        "manifests", "selected", "campaign_artifacts_root", "observed_host",
        "historical_runner_sha256", "output_mount",
    }, "captured fixed-pair source bindings")
    selected = _exact(sources["selected"], {
        "host_id", "root", "git_commit", "source_tree_sha256",
        "build_sha256",
    }, "captured fixed-pair selected SourceV5 identity")
    _require(selected["host_id"] == context["host_id"],
             "captured fixed-pair selected SourceV5 host differs")
    observed = _exact(sources["observed_host"], {
        "pin", "host_fingerprint_sha256", "controls_sha256",
        "process_affinity", "network_namespace_inode",
    }, "captured fixed-pair observed-host binding")
    observed_pin = _exact(observed["pin"], {"path", "sha256"},
                          "captured fixed-pair observed-host pin")
    _absolute_path(observed_pin["path"],
                   "captured fixed-pair observed-host path")
    _require(host_identity["observed_host_raw_sha256"] ==
                 _digest(observed_pin["sha256"],
                         "captured fixed-pair observed-host digest") and
             host_identity["process_affinity"] == observed["process_affinity"] and
             host_identity["network_namespace_inode"] ==
                 observed["network_namespace_inode"] and
             host_identity["host_id"] == context["host_id"] and
             mount_static == sources["output_mount"],
             "strict fixed-pair host identity facts differ from its captured overlay")


def _validate_probe_capture_tree_receipt(
    tree: dict[str, Any], receipt: dict[str, Any],
    receipt_pin: dict[str, str],
) -> None:
    """Tie one opaque-trace inventory to the strict ProbeV2 owner-return facts."""
    _require(receipt.get("schema") ==
             "allocatbelt.application-feedback-probe-capture.v2" and
             receipt.get("output_matches_probe") is True and
             receipt.get("stderr_empty") is True and
             receipt.get("exit_status") == 0 and
             receipt.get("qualification_eligible") is False and
             receipt.get("execution_ready") is False and
             receipt.get("controller_chronology_proven") is False,
             "tree inventory owner receipt is not a successful nonready ProbeV2 capture")
    receipt_inventory = _exact(
        receipt.get("tmpdir_inventory_pin"),
        {"path", "raw_sha256", "inventory_sha256"},
        "ProbeV2 owner receipt TMPDIR inventory pin",
    )
    inventory_pin = tree["inventory_pin"]
    _require(receipt_inventory == {
                "path": inventory_pin["path"],
                "raw_sha256": inventory_pin["raw_sha256"],
                "inventory_sha256": tree["inventory_sha256"],
            }, "ProbeV2 owner receipt does not bind this exact tree inventory")
    root = tree["root_path"]
    initial = _exact(receipt.get("tmpdir_initial"), {
        "path", "device", "inode", "mode", "mount", "available_bytes",
        "available_inodes", "bytes_limit", "inode_limit",
    }, "ProbeV2 initial TMPDIR identity")
    final = _exact(receipt.get("tmpdir_final"), {
        "path", "device", "inode", "mode", "mount", "bytes_used",
        "file_count", "directory_count", "bytes_limit", "inode_limit",
        "available_bytes", "available_inodes",
    }, "ProbeV2 final TMPDIR usage")
    for label, facts in (("initial", initial), ("final", final)):
        _absolute_path(facts["path"], f"ProbeV2 {label} TMPDIR path")
        for field in ("device", "inode", "mode", "available_bytes",
                      "available_inodes", "bytes_limit", "inode_limit"):
            _uint(facts[field], f"ProbeV2 {label} TMPDIR {field}")
        mount = _exact(facts["mount"], {
            "mount_id", "major_minor", "mount_root", "mount_point",
            "filesystem_type", "mount_source", "device",
        }, f"ProbeV2 {label} TMPDIR mount")
        _uint(mount["mount_id"], f"ProbeV2 {label} mount ID", positive=True)
        _uint(mount["device"], f"ProbeV2 {label} mount device")
        _require(type(mount["major_minor"]) is str and
                 re.fullmatch(r"[0-9]+:[0-9]+", mount["major_minor"]) is not None and
                 type(mount["mount_root"]) is str and
                 mount["mount_root"].startswith("/") and
                 type(mount["mount_point"]) is str and
                 mount["mount_point"].startswith("/") and
                 type(mount["filesystem_type"]) is str and
                 mount["filesystem_type"] not in {"tmpfs", "ramfs", "devtmpfs"} and
                 type(mount["mount_source"]) is str and
                 mount["device"] == facts["device"],
                 f"ProbeV2 {label} TMPDIR mount identity is malformed")
    for field in ("bytes_used", "file_count", "directory_count"):
        _uint(final[field], f"ProbeV2 final TMPDIR {field}")
    budget = _exact(receipt.get("storage_budget"), {
        "tmpdir_bytes", "tmpdir_inodes", "stdout_bytes", "stderr_bytes",
        "owner_result_bytes", "inventory_bytes", "failure_bytes",
        "receipt_bytes", "output_inodes",
    }, "ProbeV2 receipt storage budget")
    tmpdir_bytes = _uint(budget["tmpdir_bytes"],
                         "ProbeV2 TMPDIR byte budget", positive=True)
    tmpdir_inodes = _uint(budget["tmpdir_inodes"],
                          "ProbeV2 TMPDIR inode budget", positive=True)
    file_count = sum(entry["kind"] == "file" for entry in tree["entries"])
    directory_count = sum(
        entry["kind"] == "directory" for entry in tree["entries"]
    )
    _require(initial["path"] == final["path"] == root and
             initial["device"] == final["device"] and
             initial["inode"] == final["inode"] > 0 and
             initial["mode"] == final["mode"] == 0o700 and
             initial["mount"] == final["mount"] and
             initial["bytes_limit"] == final["bytes_limit"] == tmpdir_bytes and
             initial["inode_limit"] == final["inode_limit"] == tmpdir_inodes and
             final["bytes_used"] == tree["byte_count"] and
             final["file_count"] == file_count and
             final["directory_count"] == directory_count and
             tree["entry_count"] == file_count + directory_count and
             tree["byte_count"] <= tmpdir_bytes and
             tree["entry_count"] <= tmpdir_inodes,
             "ProbeV2 owner receipt counters differ from its exact typed tree inventory")


def _validate_tree_inventory_payloads(
    tree_inventories: list[dict[str, Any]],
    entries: list[dict[str, Any]],
    owner_receipt_bytes: dict[str, bytes],
    load_object,
) -> None:
    """Reopen each pinned inventory and capture receipt from transferred objects."""
    by_origin = {row["origin_path"]: row for row in entries}
    for index, tree in enumerate(tree_inventories):
        inventory_pin = tree["inventory_pin"]
        inventory_row = by_origin.get(inventory_pin["path"])
        _require(inventory_row is not None,
                 "tree inventory sidecar is absent from the exact request rows")
        raw = load_object(inventory_row)
        _require(type(raw) is bytes and
                 len(raw) == inventory_row["byte_count"] and
                 _sha(raw) == inventory_row["raw_sha256"] ==
                     inventory_pin["raw_sha256"],
                 f"tree inventory[{index}] sidecar bytes differ from their raw pin")
        inventory = _exact(
            _parse_canonical(raw, f"ProbeV2 tree inventory[{index}]",
                             maximum_bytes=MAX_PROBE_TMPDIR_INVENTORY_BYTES),
            {"schema", "entries", "inventory_sha256"},
            f"ProbeV2 tree inventory[{index}] document",
        )
        body = {key: item for key, item in inventory.items()
                if key != "inventory_sha256"}
        _require(inventory["schema"] == PROBE_TMPDIR_INVENTORY_SCHEMA_V1 and
                 inventory["entries"] == tree["entries"] and
                 inventory["inventory_sha256"] == tree["inventory_sha256"] ==
                     _sha(_canonical(body)) ==
                     inventory_pin["semantic_sha256"],
                 f"ProbeV2 tree inventory[{index}] differs from its exact request projection")
        receipt_pin = tree["owner_receipt_pin"]
        receipt_raw = owner_receipt_bytes.get(receipt_pin["path"])
        _require(type(receipt_raw) is bytes and
                 _sha(receipt_raw) == receipt_pin["raw_sha256"],
                 f"ProbeV2 tree capture receipt[{index}] is absent or changed")
        receipt, semantic = _read_self_digest(
            receipt_raw, f"ProbeV2 tree capture receipt[{index}]",
            ("receipt_sha256",),
        )
        _require(semantic == receipt_pin["semantic_sha256"],
                 f"ProbeV2 tree capture receipt[{index}] semantic digest differs")
        _validate_probe_capture_tree_receipt(tree, receipt, receipt_pin)


def _fixed_pair_tmp_proof_shape(empty_tmp_proofs: object) -> bool:
    if type(empty_tmp_proofs) is not list or len(empty_tmp_proofs) != 4 or \
            any(type(item) is not dict for item in empty_tmp_proofs):
        return False
    member = [item for item in empty_tmp_proofs if "domain" not in item]
    probes = [item for item in empty_tmp_proofs
              if item.get("domain") == "probe_tmpdir"]
    return (
        len(member) == len(probes) == 2 and
        all(item.get("role") == "component_receipt"
            for item in empty_tmp_proofs) and
        all(type(item.get("member_ordinal")) is int and
            item["member_ordinal"] in (0, 1)
            for item in empty_tmp_proofs) and
        sorted(item.get("member_ordinal") for item in member) == [0, 1] and
        sorted(item.get("member_ordinal") for item in probes) == [0, 1] and
        all(item.get("domain") in (None, "probe_tmpdir")
            for item in empty_tmp_proofs)
    )


def _require_success_tmp_proofs(
    record: dict[str, Any], empty_tmp_proofs: list[dict[str, Any]],
    *, require_probe_tmp_proofs: bool = False,
    require_fixed_pair_tmp_proofs: bool = False,
) -> None:
    phase = record["job"]["phase"]
    state = record["state"]
    if state == "valid_pair":
        members = sorted(
            item["member_ordinal"] for item in empty_tmp_proofs
            if "domain" not in item
        )
        _require(members == [0, 1],
                 f"successful {phase} job lacks both owner-return zero TMPDIR facts")
        if require_fixed_pair_tmp_proofs:
            _require(phase in {"exploration", "aa", "confirmation"} and
                     _fixed_pair_tmp_proof_shape(empty_tmp_proofs),
                     "fixed-pair v3 checkpoint requires exactly four receipt-derived TMP proofs")
        if (require_probe_tmp_proofs and
                phase in {"exploration", "aa", "confirmation"}):
            probe_members = sorted(
                item["member_ordinal"] for item in empty_tmp_proofs
                if item.get("domain") == "probe_tmpdir"
            )
            _require(probe_members == [0, 1],
                     "v2 successful fixed job lacks its two construction-probe empty TMPDIR facts")
    elif state == "valid_soak":
        domains = [item for item in empty_tmp_proofs
                   if item.get("domain") == "application_tmpdir"]
        _require(len(domains) == 1 and domains[0]["member_ordinal"] == 0 and
                 domains[0]["bytes_used"] == 0 and
                 domains[0]["inode_count"] == 0,
                 "successful Soak job lacks its exact zero-usage TMPDIR receipt")


def _checkpoint_request_projection(
    context: object, job_record_pin: object, job_record_bytes: bytes,
    plan_bytes: bytes, rows: Iterable[object],
    owner_receipt_bytes: dict[str, bytes],
    tree_inventories_value: object | None = None,
    *, fixed_pair_request_v3: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if tree_inventories_value is not None:
        tree_inventories_value = list(tree_inventories_value)
        if not tree_inventories_value:
            tree_inventories_value = None
    checked_context = _validate_context(context)
    if fixed_pair_request_v3:
        _require(tree_inventories_value is None and
                 checked_context["phase"] in {
                     "exploration", "aa", "confirmation",
                 }, "fixed-pair v3 checkpoint requests require a fixed phase and no tree inventories")
    record, authorization, identity = _validate_job_record(
        checked_context, job_record_pin, job_record_bytes, plan_bytes,
    )
    checked_rows = _validate_rows(list(rows))
    job_pin = _pin_raw(job_record_pin, "Source5 job record pin")
    _require(all(row["origin_path"] != job_pin["path"]
                 for row in checked_rows),
             "always-local job record must not enter reclaimable object rows")
    _require(type(owner_receipt_bytes) is dict,
             "owner receipt bytes must be keyed by exact origin path")
    receipt_origins = {
        row["origin_path"] for row in checked_rows
        if _is_owner_receipt_role(row["role"])
    }
    receipt_roles = {
        row["role"] for row in checked_rows
        if _is_owner_receipt_role(row["role"])
    }
    _require(set(owner_receipt_bytes) == receipt_origins,
             "owner receipt byte set differs from the exact receipt-role closure")
    if fixed_pair_request_v3:
        _require(record["state"] == "valid_pair" and
                 receipt_roles == {
                     "component_receipt", "fixed_pair_host_receipt",
                 } and
                 record["evidence"].get("host_receipt") is not None,
                 "fixed-pair v3 checkpoint requires the successful exact component and strict host receipts")
    by_origin = {row["origin_path"]: row for row in checked_rows}
    owner_pins: dict[str, dict[str, str]] = {}
    empty_proofs: list[dict[str, Any]] = []
    for origin, raw in owner_receipt_bytes.items():
        _absolute_path(origin, "owner receipt origin path")
        row = by_origin.get(origin)
        _require(row is not None and type(raw) is bytes and
                 len(raw) == row["byte_count"] and _sha(raw) == row["raw_sha256"],
                 "owner receipt bytes differ from their exact object row")
        receipt, semantic = _read_self_digest(
            raw, f"owner receipt {origin}",
            ("receipt_sha256", "record_sha256"),
        )
        _bind_owner_receipt_identity(
            receipt, checked_context, record["job"], f"owner receipt {row['role']}",
        )
        _require(row["semantic_sha256"] == semantic,
                 "owner receipt semantic digest differs from its pinned row")
        role = row["role"]
        _require(role not in owner_pins,
                 "owner receipt roles must be unique within one job")
        receipt_pin = {
            "path": origin, "raw_sha256": row["raw_sha256"],
            "semantic_sha256": semantic,
        }
        owner_pins[role] = receipt_pin
        empty_proofs.extend(_zero_usage_proofs(
            receipt, receipt_pin, role,
            include_probe_tmp_proofs=(
                fixed_pair_request_v3 or tree_inventories_value is not None
            ),
        ))
    owner_pins = {role: owner_pins[role] for role in sorted(owner_pins)}
    _validate_fixed_pair_host_receipt_bindings(
        checked_context, record, checked_rows, owner_pins,
        owner_receipt_bytes=owner_receipt_bytes,
    )
    tree_inventories = None
    if tree_inventories_value is not None:
        _require(record["state"] in {"valid_pair", "valid_soak"},
                 "v2 tree checkpoint requests require a successful original job")
        tree_inventories = _validate_tree_inventories(
            tree_inventories_value, checked_rows, owner_pins,
            expected_job_sha256=identity["job_sha256"],
        )
        for tree in tree_inventories:
            owner_raw = owner_receipt_bytes[tree["owner_receipt_pin"]["path"]]
            receipt, semantic = _read_self_digest(
                owner_raw, "ProbeV2 tree capture receipt", ("receipt_sha256",),
            )
            _require(semantic == tree["owner_receipt_pin"]["semantic_sha256"],
                     "ProbeV2 tree capture receipt semantic pin differs")
            _validate_probe_capture_tree_receipt(
                tree, receipt, tree["owner_receipt_pin"],
            )
        capture_receipt_paths = {
            pin["path"] for role, pin in owner_pins.items()
            if role.startswith("probe_capture_receipt")
        }
        _require(capture_receipt_paths == {
                    tree["owner_receipt_pin"]["path"]
                    for tree in tree_inventories
                }, "v2 tree rows do not cover every exact ProbeV2 capture receipt")
    _require_success_tmp_proofs(
        record, empty_proofs,
        require_probe_tmp_proofs=tree_inventories_value is not None,
        require_fixed_pair_tmp_proofs=fixed_pair_request_v3,
    )
    request_body = {
        "schema": (REQUEST_SCHEMA_V3 if fixed_pair_request_v3 else
                   REQUEST_SCHEMA_V1 if tree_inventories_value is None
                   else REQUEST_SCHEMA_V2),
        "context": checked_context,
        "job_record_pin": job_pin,
        "authorization": authorization,
        "predecessor_ack_pin": checked_context["predecessor_ack_pin"],
        "owner_receipt_pins": owner_pins,
        "empty_tmp_proofs": sorted(
            empty_proofs,
            key=lambda item: (item["role"], item["member_ordinal"],
                              item.get("domain", "")),
        ),
        "entries": checked_rows,
        "request_sha256": "",
    }
    if tree_inventories is not None:
        request_body["tree_inventories"] = tree_inventories
    request_sha = _sha(_canonical({
        key: item for key, item in request_body.items()
        if key != "request_sha256"
    }, maximum_bytes=_checkpoint_metadata_limit(request_body)))
    return ({**request_body, "request_sha256": request_sha},
            record, identity)


def _validate_checkpoint_request(value: object) -> dict[str, Any]:
    base_fields = {
        "schema", "context", "job_record_pin", "authorization",
        "predecessor_ack_pin", "owner_receipt_pins", "empty_tmp_proofs",
        "entries", "request_sha256",
    }
    _require(type(value) is dict, "Source5 job checkpoint request is not an object")
    if value.get("schema") == REQUEST_SCHEMA_V1:
        request = _exact(value, base_fields, "Source5 job checkpoint request v1")
        tree_inventories = None
        fixed_pair_request_v3 = False
    elif value.get("schema") == REQUEST_SCHEMA_V2:
        request = _exact(value, base_fields | {"tree_inventories"},
                          "Source5 job checkpoint request v2")
        tree_inventories = request["tree_inventories"]
        _require(type(tree_inventories) is list and bool(tree_inventories),
                 "v2 checkpoint request requires at least one exact tree declaration")
        fixed_pair_request_v3 = False
    elif value.get("schema") == REQUEST_SCHEMA_V3:
        request = _exact(value, base_fields,
                         "fixed-pair Source5 checkpoint request v3")
        tree_inventories = None
        fixed_pair_request_v3 = True
    else:
        raise EvidenceArchiveError("Source5 job checkpoint request schema differs")
    context = _validate_context(request["context"])
    _pin_raw(request["job_record_pin"], "checkpoint-request job record pin")
    _require(request["predecessor_ack_pin"] == context["predecessor_ack_pin"] and
             type(request["owner_receipt_pins"]) is dict and
             list(request["owner_receipt_pins"]) ==
                 sorted(request["owner_receipt_pins"]) and
             type(request["empty_tmp_proofs"]) is list,
             "checkpoint-request receipt/predecessor facts are malformed")
    if fixed_pair_request_v3:
        _require(context["phase"] in {"exploration", "aa", "confirmation"} and
                 set(request["owner_receipt_pins"]) == {
                     "component_receipt", "fixed_pair_host_receipt",
                 } and
                 _fixed_pair_tmp_proof_shape(request["empty_tmp_proofs"]),
                 "fixed-pair v3 request lacks its exact four-proof fixed closure")
    entries = _validate_rows(request["entries"])
    job_pin = _pin_raw(request["job_record_pin"],
                       "checkpoint-request job record pin")
    _require(all(row["origin_path"] != job_pin["path"] for row in entries),
             "always-local job record must not enter reclaimable request entries")
    if tree_inventories is not None:
        _validate_tree_inventories(
            tree_inventories, entries, request["owner_receipt_pins"],
        )
    body = {key: item for key, item in request.items()
            if key != "request_sha256"}
    _require(request["request_sha256"] == _sha(_canonical(
                 body, maximum_bytes=_checkpoint_metadata_limit(request),
             )),
             "Source5 checkpoint-request self digest differs")
    # Validate proof/pin structure through the exact final-checkpoint validator
    # without inventing a manifest pin or publishing a final checkpoint.
    provisional = {
        "schema": _checkpoint_schema_for_request_schema(request["schema"]),
        "request_pin": {
            "path": "/request.json", "raw_sha256": "0" * 64,
            "semantic_sha256": "0" * 64,
        },
        "context": context,
        "job_record_pin": request["job_record_pin"],
        "authorization": request["authorization"],
        "predecessor_ack_pin": request["predecessor_ack_pin"],
        "owner_receipt_pins": request["owner_receipt_pins"],
        "empty_tmp_proofs": request["empty_tmp_proofs"],
        "object_manifest_pin": {
            "path": "/manifest.json", "raw_sha256": "0" * 64,
            "semantic_sha256": "0" * 64,
        },
        "entries": entries, "checkpoint_sha256": "0" * 64,
    }
    if tree_inventories is not None:
        provisional["tree_inventories"] = tree_inventories
    _validate_checkpoint(provisional, validate_digest=False)
    return request


def build_checkpoint_request(
    context: object, job_record_pin: object, job_record_bytes: bytes,
    plan_bytes: bytes, rows: Iterable[object],
    owner_receipt_bytes: dict[str, bytes],
    output_path: str | os.PathLike[str],
    *, tree_inventories: Iterable[object] | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Write the immutable host intent sent with its one bounded transfer packet."""
    request, _record, _identity = _checkpoint_request_projection(
        context, job_record_pin, job_record_bytes, plan_bytes, rows,
        owner_receipt_bytes,
        None if tree_inventories is None else list(tree_inventories),
    )
    output = Path(_absolute_path(os.fspath(output_path),
                                 "checkpoint-request output path"))
    _require(output.parent.is_dir() and
             output.parent.resolve(strict=True) == output.parent,
             "checkpoint-request output parent is absent or aliased")
    parent_fd = _open_dir_path(str(output.parent),
                               "checkpoint-request output parent",
                               private_final=True)
    try:
        raw = _canonical_checkpoint_metadata(request)
        raw_sha, size = _write_at(
            parent_fd, output.name, raw, "Source5 checkpoint request",
        )
        reopened, reopened_sha, _ = _read_at(
            parent_fd, output.name, _checkpoint_metadata_limit(request),
            "Source5 checkpoint request", expected_bytes=size,
        )
        _require(reopened == raw and reopened_sha == raw_sha,
                 "checkpoint request failed independent reopen verification")
        return request, {
            "path": str(output), "raw_sha256": raw_sha,
            "semantic_sha256": request["request_sha256"],
        }
    finally:
        os.close(parent_fd)


def build_fixed_checkpoint_request_v3(
    context: object, job_record_pin: object, job_record_bytes: bytes,
    plan_bytes: bytes, rows: Iterable[object],
    owner_receipt_bytes: dict[str, bytes],
    output_path: str | os.PathLike[str],
) -> tuple[dict[str, Any], dict[str, str]]:
    """Write a fixed-only request with four receipt-derived TMP proofs."""
    request, _record, _identity = _checkpoint_request_projection(
        context, job_record_pin, job_record_bytes, plan_bytes, rows,
        owner_receipt_bytes, fixed_pair_request_v3=True,
    )
    output = Path(_absolute_path(os.fspath(output_path),
                                 "fixed-pair checkpoint-request output path"))
    _require(output.parent.is_dir() and
             output.parent.resolve(strict=True) == output.parent,
             "fixed-pair checkpoint-request output parent is absent or aliased")
    parent_fd = _open_dir_path(str(output.parent),
                               "fixed-pair checkpoint-request output parent",
                               private_final=True)
    try:
        raw = _canonical_checkpoint_metadata(request)
        raw_sha, size = _write_at(
            parent_fd, output.name, raw,
            "fixed-pair v3 checkpoint request",
        )
        reopened, reopened_sha, _ = _read_at(
            parent_fd, output.name, _checkpoint_metadata_limit(request),
            "fixed-pair v3 checkpoint request", expected_bytes=size,
        )
        _require(reopened == raw and reopened_sha == raw_sha,
                 "fixed-pair v3 checkpoint request failed independent reopen verification")
        return request, {
            "path": str(output), "raw_sha256": raw_sha,
            "semantic_sha256": request["request_sha256"],
        }
    finally:
        os.close(parent_fd)


def build_job_checkpoint(
    request_pin: object, request_bytes: bytes,
    context: object, job_record_pin: object, job_record_bytes: bytes,
    plan_bytes: bytes, rows: Iterable[object],
    owner_receipt_bytes: dict[str, bytes],
    object_manifest_pin: object,
    output_path: str | os.PathLike[str],
) -> tuple[dict[str, Any], dict[str, str]]:
    """Write the final checkpoint after its durable object manifest exists."""
    parsed_request = _validate_checkpoint_request(_parse_checkpoint_metadata(
        request_bytes, "checkpoint request",
    ))
    tree_inventories = parsed_request.get("tree_inventories")
    fixed_pair_request_v3 = parsed_request["schema"] == REQUEST_SCHEMA_V3
    request, _record, _identity = _checkpoint_request_projection(
        context, job_record_pin, job_record_bytes, plan_bytes, rows,
        owner_receipt_bytes, tree_inventories,
        fixed_pair_request_v3=fixed_pair_request_v3,
    )
    checked_request_pin = _pin(request_pin, "checkpoint request pin")
    _require(type(request_bytes) is bytes and
             _sha(request_bytes) == checked_request_pin["raw_sha256"] and
             _parse_checkpoint_metadata(request_bytes, "checkpoint request") == request and
             checked_request_pin["semantic_sha256"] == request["request_sha256"],
             "checkpoint request differs from its exact raw/semantic pin")
    manifest_pin = _pin(object_manifest_pin, "Source5 object manifest pin")
    checked_context = _validate_context(context)
    job_pin = _pin_raw(job_record_pin, "Source5 job record pin")
    checkpoint_body = {
        "schema": _checkpoint_schema_for_request_schema(request["schema"]),
        "request_pin": checked_request_pin,
        "context": checked_context,
        "job_record_pin": job_pin,
        "authorization": request["authorization"],
        "predecessor_ack_pin": request["predecessor_ack_pin"],
        "owner_receipt_pins": request["owner_receipt_pins"],
        "empty_tmp_proofs": request["empty_tmp_proofs"],
        "object_manifest_pin": manifest_pin,
        "entries": request["entries"],
        "checkpoint_sha256": "",
    }
    if tree_inventories is not None:
        checkpoint_body["tree_inventories"] = tree_inventories
    checkpoint_digest = _sha(_canonical({
        key: item for key, item in checkpoint_body.items()
        if key != "checkpoint_sha256"
    }, maximum_bytes=_checkpoint_metadata_limit(checkpoint_body)))
    checkpoint = {**checkpoint_body, "checkpoint_sha256": checkpoint_digest}
    output = Path(_absolute_path(os.fspath(output_path),
                                 "checkpoint output path"))
    _require(output.parent.is_dir() and
             output.parent.resolve(strict=True) == output.parent,
             "checkpoint output parent is absent or aliased")
    parent_fd = _open_dir_path(str(output.parent), "checkpoint output parent",
                               private_final=True)
    try:
        raw = _canonical_checkpoint_metadata(checkpoint)
        raw_sha, size = _write_at(
            parent_fd, output.name, raw, "final Source5 job checkpoint",
        )
        reopened, reopened_sha, _ = _read_at(
            parent_fd, output.name, _checkpoint_metadata_limit(checkpoint),
            "final Source5 job checkpoint", expected_bytes=size,
        )
        _require(reopened == raw and reopened_sha == raw_sha,
                 "final checkpoint failed independent reopen verification")
        return checkpoint, {
            "path": str(output), "raw_sha256": raw_sha,
            "semantic_sha256": checkpoint_digest,
        }
    finally:
        os.close(parent_fd)

def _validate_checkpoint(
    value: object, *, validate_digest: bool = True,
) -> dict[str, Any]:
    base_fields = {
        "schema", "request_pin", "context", "job_record_pin", "authorization",
        "predecessor_ack_pin", "owner_receipt_pins", "empty_tmp_proofs",
        "object_manifest_pin", "entries", "checkpoint_sha256",
    }
    _require(type(value) is dict, "Source5 job checkpoint is not an object")
    if value.get("schema") == CHECKPOINT_SCHEMA_V1:
        checkpoint = _exact(value, base_fields, "Source5 job checkpoint v1")
        tree_inventories = None
        fixed_pair_checkpoint_v3 = False
    elif value.get("schema") == CHECKPOINT_SCHEMA_V2:
        checkpoint = _exact(value, base_fields | {"tree_inventories"},
                             "Source5 job checkpoint v2")
        tree_inventories = checkpoint["tree_inventories"]
        _require(type(tree_inventories) is list and bool(tree_inventories),
                 "v2 checkpoint requires at least one exact tree declaration")
        fixed_pair_checkpoint_v3 = False
    elif value.get("schema") == CHECKPOINT_SCHEMA_V3:
        checkpoint = _exact(value, base_fields,
                             "fixed-pair Source5 job checkpoint v3")
        tree_inventories = None
        fixed_pair_checkpoint_v3 = True
    else:
        raise EvidenceArchiveError("Source5 job checkpoint schema differs")
    _pin(checkpoint["request_pin"], "checkpoint request pin")
    context = _validate_context(checkpoint["context"])
    _pin_raw(checkpoint["job_record_pin"], "checkpoint job record pin")
    _require(checkpoint["predecessor_ack_pin"] == context["predecessor_ack_pin"],
             "checkpoint predecessor differs from its context")
    _require(type(checkpoint["owner_receipt_pins"]) is dict and
             list(checkpoint["owner_receipt_pins"]) ==
                 sorted(checkpoint["owner_receipt_pins"]) and
             type(checkpoint["empty_tmp_proofs"]) is list,
             "checkpoint receipt or TMP proof maps are malformed")
    if fixed_pair_checkpoint_v3:
        _require(context["phase"] in {"exploration", "aa", "confirmation"} and
                 set(checkpoint["owner_receipt_pins"]) == {
                     "component_receipt", "fixed_pair_host_receipt",
                 } and
                 _fixed_pair_tmp_proof_shape(checkpoint["empty_tmp_proofs"]),
                 "fixed-pair v3 checkpoint lacks its exact four-proof fixed closure")
    entries = _validate_rows(checkpoint["entries"])
    if tree_inventories is not None:
        _validate_tree_inventories(
            tree_inventories, entries, checkpoint["owner_receipt_pins"],
        )
    job_origin = checkpoint["job_record_pin"]["path"]
    _require(all(row["origin_path"] != job_origin for row in entries),
             "always-local job record must not enter reclaimable checkpoint entries")
    by_origin = {row["origin_path"]: row for row in entries}
    for role, value_pin in checkpoint["owner_receipt_pins"].items():
        _token(role, "checkpoint owner receipt role")
        owner_pin = _pin(value_pin, f"checkpoint owner receipt {role}")
        row = by_origin.get(owner_pin["path"])
        _require(row is not None and row["role"] == role and
                 row["raw_sha256"] == owner_pin["raw_sha256"] and
                 row["semantic_sha256"] == owner_pin["semantic_sha256"],
                 "checkpoint owner receipt pin has no exact closure row")
    proof_order = []
    for index, proof_value in enumerate(checkpoint["empty_tmp_proofs"]):
        _require(type(proof_value) is dict,
                 f"checkpoint empty TMP proof[{index}] is malformed")
        proof = proof_value
        role = _token(proof.get("role"), "empty TMP proof role")
        owner_pin = _pin(proof.get("owner_receipt_pin"),
                         "empty TMP proof owner receipt")
        _require(checkpoint["owner_receipt_pins"].get(role) == owner_pin and
                 proof.get("bytes_used") == 0,
                 "empty TMP proof is not tied to its exact zero-usage owner receipt")
        if fixed_pair_checkpoint_v3:
            _uint(proof.get("bytes_used"),
                  "fixed-pair v3 TMP proof byte count")
        if proof.get("domain") == "application_tmpdir":
            _exact(proof, {
                "role", "path", "owner_receipt_pin", "member_ordinal",
                "domain", "bytes_used", "inode_count", "inventory_sha256",
            }, f"Soak empty TMP proof[{index}]")
            _absolute_path(proof["path"], "Soak empty TMP path")
            _uint(proof["member_ordinal"], "Soak TMP member ordinal")
            _require(proof["inode_count"] == 0,
                     "Soak application TMPDIR inode count is not zero")
            _digest(proof["inventory_sha256"], "Soak TMP inventory digest")
        elif checkpoint["schema"] in {
                CHECKPOINT_SCHEMA_V2, CHECKPOINT_SCHEMA_V3,
        } and \
                proof.get("domain") == "probe_tmpdir":
            _exact(proof, {
                "role", "path", "owner_receipt_pin", "member_ordinal",
                "domain", "device", "inode", "mode", "mount",
                "bytes_used", "file_count", "directory_count", "bytes_limit",
                "inode_limit",
            }, f"ProbeV2 empty TMP proof[{index}]")
            _absolute_path(proof["path"], "ProbeV2 empty TMP path")
            for field in ("member_ordinal", "device", "inode", "mode",
                          "file_count", "directory_count", "bytes_limit",
                          "inode_limit"):
                _uint(proof[field], f"ProbeV2 empty TMP proof {field}")
            _require(proof["inode"] > 0 and proof["mode"] == 0o700 and
                     proof["file_count"] == 0 and
                     proof["directory_count"] == 0 and
                     proof["bytes_limit"] > 0 and proof["inode_limit"] > 0,
                     "ProbeV2 empty TMP proof counters or identity differ")
            mount = _exact(proof["mount"], {
                "mount_id", "major_minor", "mount_root", "mount_point",
                "filesystem_type", "mount_source", "device",
            }, "ProbeV2 empty TMP mount")
            if fixed_pair_checkpoint_v3:
                _uint(mount["device"],
                      "fixed-pair v3 probe TMP mount device")
            _require(mount["device"] == proof["device"],
                     "ProbeV2 empty TMP mount device differs")
        else:
            _exact(proof, {
                "role", "path", "owner_receipt_pin", "member_ordinal",
                "device", "inode", "mode", "mount", "bytes_used",
                "file_count", "directory_count", "bytes_limit", "inode_limit",
            }, f"empty TMP proof[{index}]")
            _absolute_path(proof["path"], "empty TMP path")
            for field in ("member_ordinal", "device", "inode", "mode",
                          "file_count", "directory_count", "bytes_limit",
                          "inode_limit"):
                _uint(proof[field], f"empty TMP proof {field}")
            _require(proof["inode"] > 0 and proof["mode"] == 0o700 and
                     proof["file_count"] == 0 and
                     proof["directory_count"] == 0 and
                     proof["bytes_limit"] > 0 and proof["inode_limit"] > 0,
                     "empty TMP proof counters or private identity differ")
            mount = _exact(proof["mount"], {
                "mount_id", "major_minor", "mount_root", "mount_point",
                "filesystem_type", "mount_source", "device",
            }, "empty TMP proof mount")
            if fixed_pair_checkpoint_v3:
                _uint(mount["device"],
                      "fixed-pair v3 member TMP mount device")
            _require(mount["device"] == proof["device"],
                     "empty TMP mount device differs from the owner proof")
        proof_order.append((role, proof["member_ordinal"],
                            proof.get("domain", "")))
    _require(proof_order == sorted(proof_order) and
             len(proof_order) == len(set(proof_order)),
             "checkpoint empty TMP proofs are not sorted unique")
    manifest_pin = checkpoint["object_manifest_pin"]
    _pin(manifest_pin, "checkpoint object-manifest pin")
    body = {key: item for key, item in checkpoint.items()
            if key != "checkpoint_sha256"}
    if validate_digest:
        _require(checkpoint["checkpoint_sha256"] == _sha(_canonical(
                     body, maximum_bytes=_checkpoint_metadata_limit(checkpoint),
                 )),
                 "Source5 checkpoint self digest differs")
    return checkpoint


def _object_identity(origin_path: str, raw_sha256: str) -> str:
    origin_name = _sha(origin_path.encode("utf-8"))
    return f"{origin_name[:2]}/{origin_name}-{raw_sha256}.bin"


def _staged_descriptor(
    path_value: object, staging_root: str, expected: dict[str, Any], *,
    expected_regular_mode: int | None = None,
) -> tuple[dict[str, Any], bytes | None]:
    path_text = _absolute_path(path_value, "local staged file path")
    root = Path(_absolute_path(staging_root, "private staging root"))
    path = Path(path_text)
    _require(path != root and root in path.parents,
             "staged file escapes its caller-reserved private staging root")
    rel = path.relative_to(root).as_posix()
    root_fd = _open_dir_path(str(root), "private staging root", private_final=True)
    parent_fd, name = _open_parent(root_fd, rel, create=False,
                                   label="staged file")
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISREG(before.st_mode):
            expected_mode = (0o600 if expected_regular_mode is None
                             else _uint(expected_regular_mode,
                                       "typed tree file mode"))
            _require(before.st_uid == os.getuid() and
                     stat.S_IMODE(before.st_mode) == expected_mode and
                     before.st_nlink == 1 and before.st_size <= MAX_OBJECT_BYTES,
                     "staged regular file differs from its exact owner/mode/link/size bounds")
            descriptor = os.open(name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW |
                                 _O_NONBLOCK, dir_fd=parent_fd)
            try:
                opened = os.fstat(descriptor)
                _require(_info_key(opened) == _info_key(before),
                         "staged file changed identity before open")
                hasher = hashlib.sha256()
                total = 0
                while total < opened.st_size:
                    block = os.read(descriptor, min(COPY_BLOCK_BYTES,
                                                    opened.st_size - total))
                    _require(bool(block), "staged file ended before its pinned size")
                    total += len(block)
                    _require(total <= expected["byte_count"] and
                             total <= MAX_OBJECT_BYTES,
                             "staged file grew beyond the exact object size")
                    hasher.update(block)
                _require(os.read(descriptor, 1) == b"" and
                         total == opened.st_size == expected["byte_count"],
                         "staged file size differs from its checkpoint row")
                after = os.fstat(descriptor)
                after_path = os.stat(name, dir_fd=parent_fd,
                                     follow_symlinks=False)
                _require(_info_key(opened) == _info_key(after) ==
                         _info_key(after_path),
                         "staged file changed while being hashed")
                digest = hasher.hexdigest()
                _require(digest == expected["raw_sha256"],
                         "staged file bytes differ from the checkpoint raw pin")
                return ({
                    "path": path_text, "kind": "regular",
                    "device": after.st_dev, "inode": after.st_ino,
                    "mode": stat.S_IMODE(after.st_mode),
                    "byte_count": total, "raw_sha256": digest,
                }, None)
            finally:
                os.close(descriptor)
        _require(expected_regular_mode is None and
                 stat.S_ISLNK(before.st_mode) and before.st_uid == os.getuid() and
                 before.st_nlink == 1,
                 "staged object is neither an owned regular file nor a literal symlink")
        target_before = os.readlink(name, dir_fd=parent_fd)
        raw_target = os.fsencode(target_before)
        after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        target_after = os.readlink(name, dir_fd=parent_fd)
        _require(_info_key(before) == _info_key(after) and
                 target_before == target_after and
                 len(raw_target) == expected["byte_count"] and
                 _sha(raw_target) == expected["raw_sha256"],
                 "staged literal symlink bytes differ from the checkpoint raw pin")
        return ({
            "path": path_text, "kind": "symlink",
            "device": after.st_dev, "inode": after.st_ino,
            "mode": stat.S_IMODE(after.st_mode),
            "byte_count": len(raw_target), "raw_sha256": _sha(raw_target),
        }, raw_target)
    finally:
        os.close(parent_fd)
        os.close(root_fd)


def _copy_object(
    archive_root_fd: int, object_id: str, staged_path: str,
    staging_root: str, expected: dict[str, Any],
) -> tuple[dict[str, str], dict[str, Any]]:
    source_descriptor, literal = _staged_descriptor(staged_path, staging_root, expected)
    parent_fd, name = _open_parent(
        archive_root_fd, f"objects/{object_id}", create=True,
        label="archive object",
    )
    try:
        try:
            existing_info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing_info = None
        if existing_info is not None:
            _require(stat.S_ISREG(existing_info.st_mode) and
                     existing_info.st_uid == os.getuid() and
                     stat.S_IMODE(existing_info.st_mode) == 0o600 and
                     existing_info.st_nlink == 1,
                     "existing content-addressed object is not private and single-link")
            raw, digest, info = _read_at(
                parent_fd, name, expected["byte_count"], "existing archive object",
                expected_bytes=expected["byte_count"], collect=False,
            )
            _require(raw is None and digest == expected["raw_sha256"],
                     "existing content-addressed object has different bytes")
            os.fsync(parent_fd)
        else:
            output_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                _O_CLOEXEC | _O_NOFOLLOW, 0o600,
                                dir_fd=parent_fd)
            try:
                os.fchmod(output_fd, 0o600)
                if literal is not None:
                    view = memoryview(literal)
                    while view:
                        count = os.write(output_fd, view)
                        _require(count > 0, "literal-link object writer made no progress")
                        view = view[count:]
                else:
                    staging_root_path = Path(staging_root)
                    source = Path(staged_path)
                    source_rel = source.relative_to(staging_root_path).as_posix()
                    stage_root_fd = _open_dir_path(
                        staging_root, "private staging root", private_final=True,
                    )
                    stage_parent_fd, stage_name = _open_parent(
                        stage_root_fd, source_rel, create=False,
                        label="staged source",
                    )
                    source_fd = os.open(
                        stage_name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW |
                        _O_NONBLOCK, dir_fd=stage_parent_fd,
                    )
                    try:
                        source_before = os.fstat(source_fd)
                        _require(stat.S_ISREG(source_before.st_mode) and
                                 source_before.st_uid == os.getuid() and
                                 stat.S_IMODE(source_before.st_mode) == 0o600 and
                                 source_before.st_nlink == 1 and
                                 source_before.st_size == expected["byte_count"] and
                                 source_before.st_dev == source_descriptor["device"] and
                                 source_before.st_ino == source_descriptor["inode"] and
                                 stat.S_IMODE(source_before.st_mode) ==
                                     source_descriptor["mode"],
                                 "staged regular file changed before object copy")
                        hasher = hashlib.sha256()
                        total = 0
                        while total < source_before.st_size:
                            block = os.read(source_fd, min(COPY_BLOCK_BYTES,
                                                           source_before.st_size - total))
                            _require(bool(block), "staged regular file ended during copy")
                            total += len(block)
                            _require(total <= expected["byte_count"],
                                     "staged regular file exceeded its exact copy bound")
                            hasher.update(block)
                            view = memoryview(block)
                            while view:
                                count = os.write(output_fd, view)
                                _require(count > 0,
                                         "archive object writer made no progress")
                                view = view[count:]
                        _require(os.read(source_fd, 1) == b"" and
                                 total == expected["byte_count"] and
                                 hasher.hexdigest() == expected["raw_sha256"] and
                                 _info_key(source_before) ==
                                 _info_key(os.fstat(source_fd)),
                                 "staged source changed or failed its exact copy hash")
                    finally:
                        os.close(source_fd)
                        os.close(stage_parent_fd)
                        os.close(stage_root_fd)
                os.fsync(output_fd)
            finally:
                os.close(output_fd)
            os.fsync(parent_fd)
            raw, digest, info = _read_at(
                parent_fd, name, expected["byte_count"], "new archive object",
                expected_bytes=expected["byte_count"], collect=False,
            )
            _require(raw is None and digest == expected["raw_sha256"],
                     "archive object failed independent reopen hashing")
        staged_after, _literal_after = _staged_descriptor(
            staged_path, staging_root, expected,
        )
        _require(staged_after == source_descriptor,
                 "staged local identity changed during archive object copy")
        pin = {
            "path": object_id, "raw_sha256": digest,
            "semantic_sha256": digest, "byte_count": info.st_size,
        }
        return pin, source_descriptor
    finally:
        os.close(parent_fd)


def _gpg_sign(raw: bytes, signer: object) -> bytes:
    config = _exact(signer, {
        "gpg_executable", "gpg_homedir", "primary_fingerprint",
        "maximum_signature_bytes",
    }, "archive signer configuration")
    executable = _absolute_path(config["gpg_executable"], "GPG executable")
    homedir = _absolute_path(config["gpg_homedir"], "private signing home")
    fingerprint = _fingerprint(config["primary_fingerprint"],
                               "archive signer fingerprint")
    signature_limit = _uint(config["maximum_signature_bytes"],
                            "campaign signature byte ceiling", positive=True)
    _require(signature_limit <= MAX_GPG_OUTPUT_BYTES,
             "campaign signature byte ceiling exceeds its generic parser limit")
    homedir_fd = _open_dir_path(homedir, "private signing home",
                                private_final=True)
    os.close(homedir_fd)
    _gpg_raw_before, gpg_sha_before, _gpg_info = _read_absolute_executable(
        Path(executable), MAX_OBJECT_BYTES, "GPG signing executable",
    )
    command = [
        executable, "--no-options", "--batch", "--no-tty", "--no-armor",
        "--digest-algo", "SHA256", "--homedir", homedir,
        "--local-user", fingerprint + "!", "--detach-sign", "--output", "-",
    ]
    try:
        result = subprocess.run(
            command, input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=60, check=False, close_fds=True,
            env={"LC_ALL": "C", "LANG": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise EvidenceArchiveError(f"GPG detached signing failed: {error}") from error
    _require(result.returncode == 0 and
             0 < len(result.stdout) <= signature_limit,
             "GPG detached signature exceeds its pinned campaign quota")
    _gpg_raw_after, gpg_sha_after, _gpg_info_after = _read_absolute_executable(
        Path(executable), MAX_OBJECT_BYTES, "GPG signing executable after sign",
    )
    _require(gpg_sha_after == gpg_sha_before,
             "GPG signing executable changed during detached signing")
    return result.stdout


def _verify_detached_signature(
    ack_raw: bytes, signature_raw: bytes, signer_pin: object,
    *, captured_keyring_reader=None,
) -> str:
    signer = _exact(signer_pin, {
        "fingerprint", "keyring_pin", "gpgv_pin",
    }, "archive verification signer pin")
    fingerprint = _fingerprint(signer["fingerprint"],
                               "archive verification fingerprint")
    keyring_pin = _pin_raw(signer["keyring_pin"], "archive public keyring pin")
    gpgv_pin = _pin_raw(signer["gpgv_pin"], "pinned gpgv executable")
    keyring_maximum = MAX_GPG_OUTPUT_BYTES * 16
    if captured_keyring_reader is None:
        keyring_raw, keyring_sha, _ = _read_absolute_external_file(
            Path(keyring_pin["path"]), keyring_maximum, "archive public keyring",
        )
    else:
        _require(callable(captured_keyring_reader),
                 "captured public keyring reader is not callable")
        try:
            keyring_raw = captured_keyring_reader(dict(keyring_pin), keyring_maximum)
        except Exception as error:
            raise EvidenceArchiveError("captured public keyring could not be read") from error
        _require(type(keyring_raw) is bytes and 0 < len(keyring_raw) <= keyring_maximum,
                 "captured public keyring violates its Source byte bound")
        keyring_sha = _sha(keyring_raw)
    _require(keyring_sha == keyring_pin["raw_sha256"],
             "archive public keyring changed from its raw pin")
    gpgv_path = Path(gpgv_pin["path"])
    _gpgv_raw, gpgv_sha, _ = _read_absolute_executable(
        gpgv_path, MAX_OBJECT_BYTES, "pinned gpgv executable",
    )
    _require(gpgv_sha == gpgv_pin["raw_sha256"],
             "gpgv executable changed from its raw pin")
    with _private_temp_pair(ack_raw, signature_raw, keyring_raw) as (
        ack_path, sig_path, keyring_path,
    ):
        try:
            result = subprocess.run(
                [str(gpgv_path), "--status-fd", "1", "--keyring",
                 str(keyring_path), str(sig_path), str(ack_path)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=30, check=False,
                close_fds=True, env={"LC_ALL": "C", "LANG": "C"},
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise EvidenceArchiveError(f"gpgv ACK verification failed: {error}") from error
    _require(result.returncode == 0,
             "gpgv rejected the durable ACK detached signature")
    try:
        lines = result.stdout.decode("ascii", "strict").splitlines()
    except UnicodeError as error:
        raise EvidenceArchiveError("gpgv status output is not ASCII") from error
    valid = [line.split() for line in lines if line.startswith("[GNUPG:] VALIDSIG ")]
    rejected = [line for line in lines if line.startswith((
        "[GNUPG:] BADSIG ", "[GNUPG:] ERRSIG ", "[GNUPG:] NO_PUBKEY ",
        "[GNUPG:] REVKEYSIG ", "[GNUPG:] EXPKEYSIG ", "[GNUPG:] EXPSIG ",
    ))]
    _require(len(valid) == 1 and not rejected and len(valid[0]) >= 4,
             "gpgv status lacks one unambiguous valid signature")
    status = valid[0]
    signing_fingerprint = _fingerprint(status[2].upper(),
                                        "gpgv signing fingerprint")
    primary_raw = status[-1] if len(status) >= 12 else status[2]
    primary_fingerprint = _fingerprint(primary_raw.upper(),
                                       "gpgv primary fingerprint")
    _require(primary_fingerprint == fingerprint and
             signing_fingerprint == fingerprint,
             "detached ACK signer or primary fingerprint differs from its pin")
    return primary_fingerprint


def _verify_detached_signature_recorded(
    ack_raw: bytes, signature_raw: bytes, signer_pin: object, *,
    captured_keyring_reader, captured_gpgv_reader,
    root_auxiliary_resource_declaration: object,
    operation_started_ns: int, window_deadline_ns: int,
    cancel_event=None,
) -> str:
    """Freshly run the exact captured GPGV pin in one charged Root window."""
    signer = _exact(signer_pin, {
        "fingerprint", "keyring_pin", "gpgv_pin",
    }, "recorded-read archive verification signer pin")
    fingerprint = _fingerprint(signer["fingerprint"],
                               "recorded-read authorized fingerprint")
    keyring_pin = _pin_raw(signer["keyring_pin"],
                           "recorded-read public keyring pin")
    gpgv_pin = _pin_raw(signer["gpgv_pin"],
                        "recorded-read captured GPGV pin")
    resource = _exact(root_auxiliary_resource_declaration,
                      RECORDED_READ_GPG_RESOURCE_FIELDS_V2,
                      "Root recorded-read GPG auxiliary reservation")
    resource_body = {key: value for key, value in resource.items()
                     if key != "resource_sha256"}
    _require(resource["schema"] == RECORDED_READ_GPG_RESOURCE_SCHEMA_V2 and
             resource["resource_sha256"] == _sha(_canonical(resource_body)),
             "Root recorded-read GPG resource self digest differs")
    scratch_root = Path(_absolute_path(
        resource["scratch_root"], "Root recorded-read GPG scratch root",
    ))
    device = _uint(resource["device"], "Root GPG scratch device")
    reserved_bytes = _uint(resource["reserved_bytes"],
                           "Root GPG auxiliary reserved bytes", positive=True)
    allocation_block = _uint(
        resource["allocation_block_bytes"],
        "Root GPG scratch allocation block", positive=True, maximum=1 << 20,
    )
    directory_allocated = _uint(
        resource["window_directory_allocated_bytes"],
        "Root GPG private-window directory allocation", positive=True,
    )
    projected_allocated = _uint(
        resource["required_allocated_bytes"],
        "Root GPG block-rounded resource projection", positive=True,
    )
    projected_file_bytes = _uint(
        resource["required_file_bytes"],
        "Root GPG raw file-cap projection", positive=True,
    )
    reserved_inodes = _uint(resource["reserved_inodes"],
                            "Root GPG auxiliary reserved inodes", positive=True)
    gpgv_maximum = _uint(
        resource["maximum_gpgv_bytes"], "Root GPGV executable cap",
        positive=True, maximum=MAX_ARCHIVE_GPGV_BYTES,
    )
    keyring_maximum = _uint(
        resource["maximum_keyring_bytes"], "Root GPG keyring cap",
        positive=True, maximum=MAX_GPG_OUTPUT_BYTES * 16,
    )
    ack_maximum = _uint(
        resource["maximum_ack_bytes"], "Root GPG ACK input cap",
        positive=True, maximum=MAX_JSON_BYTES,
    )
    signature_maximum = _uint(
        resource["maximum_signature_bytes"], "Root GPG signature cap",
        positive=True, maximum=MAX_GPG_OUTPUT_BYTES,
    )
    stdout_maximum = _uint(
        resource["maximum_stdout_bytes"], "Root GPG status cap",
        positive=True, maximum=MAX_GPG_OUTPUT_BYTES,
    )
    stderr_maximum = _uint(
        resource["maximum_stderr_bytes"], "Root GPG diagnostic cap",
        positive=True, maximum=MAX_GPG_OUTPUT_BYTES,
    )
    maximum_window_seconds = _uint(
        resource["maximum_window_seconds"], "Root GPG window timeout",
        positive=True, maximum=300,
    )
    _require(stdout_maximum == stderr_maximum,
             "Root GPG stdout/stderr caps must share one enforced file-size limit")
    _require(type(ack_raw) is bytes and 0 < len(ack_raw) <= ack_maximum and
             type(signature_raw) is bytes and
             0 < len(signature_raw) <= signature_maximum and
             callable(captured_keyring_reader) and
             callable(captured_gpgv_reader) and
             type(operation_started_ns) is int and operation_started_ns >= 0 and
             type(window_deadline_ns) is int and
             operation_started_ns < window_deadline_ns <=
                 operation_started_ns + maximum_window_seconds * 1_000_000_000 and
             (cancel_event is None or
              callable(getattr(cancel_event, "is_set", None))),
             "Root recorded-read GPG inputs, clock window or cancellation token differ")

    def require_window_open(label: str) -> None:
        _require(time.monotonic_ns() < window_deadline_ns and
                 (cancel_event is None or not cancel_event.is_set()),
                 f"Root recorded-read GPG window expired or cancelled {label}")

    file_maxima = (gpgv_maximum, keyring_maximum, ack_maximum,
                   signature_maximum, stdout_maximum, stderr_maximum)
    required_bytes = directory_allocated + sum(
        ((maximum + allocation_block - 1) // allocation_block) *
        allocation_block for maximum in file_maxima
    )
    required_file_bytes = sum(file_maxima)
    required_inodes = 7  # One private window directory and its six exact files.
    _require(directory_allocated == allocation_block and
             projected_file_bytes == required_file_bytes and
             projected_allocated == required_bytes and
             reserved_bytes >= required_bytes and
             reserved_inodes >= required_inodes,
             "Root recorded-read GPG auxiliary reservation is below its exact physical projection")
    root_fd = _open_dir_path(scratch_root, "Root recorded-read GPG scratch root",
                             private_final=True)
    try:
        import fcntl
        fcntl.flock(root_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (ImportError, OSError) as error:
        os.close(root_fd)
        raise EvidenceArchiveError(
            "Root recorded-read GPG scratch window is already leased",
        ) from error
    root_identity = None
    window_name = None
    window_fd = -1
    created_window = False
    window_identity: tuple[int, int, int, int] | None = None
    file_fds: dict[str, int] = {}
    process = None
    try:
        root_info = os.fstat(root_fd)
        root_identity = (root_info.st_dev, root_info.st_ino,
                         root_info.st_mode, root_info.st_uid)
        _require(not os.listdir(root_fd),
                 "Root GPG auxiliary scratch retains a prior failed window")
        window_name = os.urandom(16).hex()
        require_window_open("before scratch allocation")
        root_info = os.fstat(root_fd)
        _require(root_info.st_dev == device,
                 "Root GPG scratch device differs from its declared identity")
        available = os.fstatvfs(root_fd)
        available_block = available.f_frsize or available.f_bsize
        _require(available_block == allocation_block and
                 available.f_bavail * available_block >= reserved_bytes and
                 available.f_favail >= reserved_inodes,
                 "Root GPG scratch root lacks its reserved current byte/inode window")
        _require(cancel_event is None or not cancel_event.is_set(),
                 "Root recorded-read GPG window was cancelled before allocation")
        try:
            os.mkdir(window_name, 0o700, dir_fd=root_fd)
        except FileExistsError as error:
            raise EvidenceArchiveError(
                "Root recorded-read GPG window name unexpectedly exists",
            ) from error
        created_window = True
        created_info = os.stat(window_name, dir_fd=root_fd,
                               follow_symlinks=False)
        window_identity = (created_info.st_dev, created_info.st_ino,
                           created_info.st_mode, created_info.st_uid)
        os.fsync(root_fd)
        window_fd = os.open(
            window_name, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW,
            dir_fd=root_fd,
        )
        window_info = os.fstat(window_fd)
        _require(stat.S_ISDIR(window_info.st_mode) and
                 window_info.st_uid == os.getuid() and
                 stat.S_IMODE(window_info.st_mode) == 0o700 and
                 window_info.st_dev == device and
                 _info_key(window_info) == _info_key(created_info) and
                 (window_info.st_dev, window_info.st_ino,
                  window_info.st_mode, window_info.st_uid) == window_identity,
                 "Root recorded-read GPG window is not an owned same-device 0700 directory")

        def write_file(name: str, raw: bytes, maximum: int,
                       mode: int) -> int:
            _require(type(raw) is bytes and 0 <= len(raw) <= maximum,
                     f"Root GPG auxiliary {name} exceeds its declared file cap")
            fd = os.open(
                name, os.O_RDWR | os.O_CREAT | os.O_EXCL | _O_CLOEXEC |
                _O_NOFOLLOW, mode, dir_fd=window_fd,
            )
            try:
                os.fchmod(fd, mode)
                view = memoryview(raw)
                while view:
                    require_window_open(f"while writing {name}")
                    written = os.write(fd, view)
                    _require(written > 0,
                             f"Root GPG auxiliary {name} writer made no progress")
                    view = view[written:]
                os.fsync(fd)
                info = os.fstat(fd)
                _require(stat.S_ISREG(info.st_mode) and
                         info.st_uid == os.getuid() and
                         stat.S_IMODE(info.st_mode) == mode and
                         info.st_nlink == 1 and info.st_size == len(raw) and
                         info.st_blocks * 512 <=
                            ((maximum + allocation_block - 1) //
                             allocation_block) * allocation_block,
                         f"Root GPG auxiliary {name} changed during creation")
                file_fds[name] = fd
                return fd
            except BaseException:
                os.close(fd)
                raise

        try:
            keyring_raw = captured_keyring_reader(
                dict(keyring_pin), keyring_maximum,
            )
            gpgv_raw = captured_gpgv_reader(dict(gpgv_pin), gpgv_maximum)
        except Exception as error:
            raise EvidenceArchiveError(
                "closed capture lacks the exact recorded-read signer tool bytes",
            ) from error
        _require(type(keyring_raw) is bytes and
                 0 < len(keyring_raw) <= keyring_maximum and
                 _sha(keyring_raw) == keyring_pin["raw_sha256"] and
                 type(gpgv_raw) is bytes and 0 < len(gpgv_raw) <= gpgv_maximum and
                 _sha(gpgv_raw) == gpgv_pin["raw_sha256"],
                 "captured GPG signer tools differ from their exact old raw pins")
        require_window_open("after reading captured signer tools")
        write_file("gpgv", gpgv_raw, gpgv_maximum, 0o700)
        write_file("trusted-keyring.gpg", keyring_raw, keyring_maximum, 0o600)
        write_file("ack.json", ack_raw, ack_maximum, 0o600)
        write_file("ack.sig", signature_raw, signature_maximum, 0o600)
        stdout_fd = write_file("status.stdout", b"", stdout_maximum, 0o600)
        stderr_fd = write_file("status.stderr", b"", stderr_maximum, 0o600)
        os.fsync(window_fd)
        window_info = os.fstat(window_fd)
        _require(window_info.st_blocks * 512 <= directory_allocated,
                 "Root GPG private-window directory exceeded its metadata reserve")

        # Linux refuses execve of a file while any process holds it writable.
        gpgv_write_fd = file_fds.pop("gpgv")
        gpgv_written_info = os.fstat(gpgv_write_fd)
        os.close(gpgv_write_fd)
        gpgv_read_fd = os.open(
            "gpgv", os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW | _O_NONBLOCK,
            dir_fd=window_fd,
        )
        try:
            gpgv_read_info = os.fstat(gpgv_read_fd)
            gpgv_path_info = os.stat("gpgv", dir_fd=window_fd,
                                     follow_symlinks=False)
            _require(_info_key(gpgv_written_info) ==
                        _info_key(gpgv_read_info) == _info_key(gpgv_path_info) and
                     stat.S_ISREG(gpgv_read_info.st_mode) and
                     gpgv_read_info.st_uid == os.getuid() and
                     stat.S_IMODE(gpgv_read_info.st_mode) == 0o700 and
                     gpgv_read_info.st_nlink == 1 and
                     _hash_fd_exact(gpgv_read_fd, len(gpgv_raw),
                                    gpgv_maximum,
                                    "Root captured GPGV read-only reopen",
                                    deadline_ns=window_deadline_ns,
                                    cancel_event=cancel_event) ==
                        gpgv_pin["raw_sha256"],
                     "Root captured GPGV changed or lost read-only custody")
        except BaseException:
            os.close(gpgv_read_fd)
            raise
        file_fds["gpgv"] = gpgv_read_fd

        def cap_child_file_size() -> None:
            import resource
            maximum_file_size = stdout_maximum
            resource.setrlimit(
                resource.RLIMIT_FSIZE,
                (maximum_file_size, maximum_file_size),
            )

        gpgv_path = scratch_root / window_name / "gpgv"
        command = [
            str(gpgv_path), "--status-fd", "1", "--keyring",
            str(scratch_root / window_name / "trusted-keyring.gpg"),
            str(scratch_root / window_name / "ack.sig"),
            str(scratch_root / window_name / "ack.json"),
        ]
        require_window_open("before execution")
        try:
            process = subprocess.Popen(
                command, stdin=subprocess.DEVNULL,
                stdout=stdout_fd, stderr=stderr_fd,
                close_fds=True,
                cwd=str(scratch_root / window_name),
                env={"LC_ALL": "C", "LANG": "C",
                     "HOME": str(scratch_root / window_name),
                     "GNUPGHOME": str(scratch_root / window_name),
                     "TMPDIR": str(scratch_root / window_name)},
                preexec_fn=cap_child_file_size,
            )
        except (OSError, ValueError) as error:
            raise EvidenceArchiveError(
                f"captured recorded-read GPGV could not start: {error}",
            ) from error
        while process.poll() is None:
            if cancel_event is not None and cancel_event.is_set():
                process.kill()
                process.wait()
                raise EvidenceArchiveError(
                    "Root recorded-read GPG verification was cancelled",
                )
            if time.monotonic_ns() >= window_deadline_ns:
                process.kill()
                process.wait()
                raise EvidenceArchiveError(
                    "Root recorded-read GPG verification exceeded its bounded window",
                )
            time.sleep(0.01)
        return_code = process.returncode
        require_window_open("after execution")

        def read_log(name: str, fd: int, maximum: int) -> bytes:
            before = os.fstat(fd)
            current = os.stat(name, dir_fd=window_fd, follow_symlinks=False)
            _require(stat.S_ISREG(before.st_mode) and
                     before.st_uid == os.getuid() and
                     stat.S_IMODE(before.st_mode) == 0o600 and
                     before.st_nlink == 1 and before.st_size <= maximum and
                     before.st_blocks * 512 <=
                         ((maximum + allocation_block - 1) //
                          allocation_block) * allocation_block and
                     _info_key(before) == _info_key(current),
                     f"Root GPG receipt {name} exceeds its exact bounded file")
            os.lseek(fd, 0, os.SEEK_SET)
            chunks = []
            total = 0
            while total < before.st_size:
                block = os.read(fd, min(COPY_BLOCK_BYTES,
                                        before.st_size - total))
                _require(bool(block),
                         f"Root GPG receipt {name} shortened before readback")
                total += len(block)
                _require(total <= maximum,
                         f"Root GPG receipt {name} exceeded its cap")
                chunks.append(block)
            after = os.fstat(fd)
            path_after = os.stat(name, dir_fd=window_fd,
                                 follow_symlinks=False)
            _require(os.read(fd, 1) == b"" and
                     _info_key(before) == _info_key(after) ==
                         _info_key(path_after),
                     f"Root GPG receipt {name} changed during bounded readback")
            return b"".join(chunks)

        stdout_raw = read_log("status.stdout", stdout_fd, stdout_maximum)
        stderr_raw = read_log("status.stderr", stderr_fd, stderr_maximum)
        _require(os.fstat(window_fd).st_blocks * 512 <= directory_allocated,
                 "Root GPG window directory exceeded its metadata reserve after execution")
        _require(return_code == 0,
                 "captured Source GPGV rejected the durable ACK")
        try:
            lines = stdout_raw.decode("ascii", "strict").splitlines()
        except UnicodeError as error:
            raise EvidenceArchiveError(
                "captured Source GPGV status output is not ASCII",
            ) from error
        valid = [line.split() for line in lines
                 if line.startswith("[GNUPG:] VALIDSIG ")]
        rejected = [line for line in lines if line.startswith((
            "[GNUPG:] BADSIG ", "[GNUPG:] ERRSIG ",
            "[GNUPG:] NO_PUBKEY ", "[GNUPG:] REVKEYSIG ",
            "[GNUPG:] EXPKEYSIG ", "[GNUPG:] EXPSIG ",
        ))]
        _require(len(valid) == 1 and not rejected and len(valid[0]) >= 4,
                 "captured Source GPGV status lacks one unambiguous valid signature")
        status = valid[0]
        signing_fingerprint = _fingerprint(
            status[2].upper(), "captured GPGV signing fingerprint",
        )
        primary_raw = status[-1] if len(status) >= 12 else status[2]
        primary_fingerprint = _fingerprint(
            primary_raw.upper(), "captured GPGV primary fingerprint",
        )
        _require(primary_fingerprint == fingerprint and
                 signing_fingerprint == fingerprint and
                 type(stderr_raw) is bytes,
                 "captured GPGV signer or primary fingerprint differs from its pin")
        for name, raw, maximum in (
            ("gpgv", gpgv_raw, gpgv_maximum),
            ("trusted-keyring.gpg", keyring_raw, keyring_maximum),
            ("ack.json", ack_raw, ack_maximum),
            ("ack.sig", signature_raw, signature_maximum),
        ):
            fd = file_fds[name]
            before = os.fstat(fd)
            _require(stat.S_ISREG(before.st_mode) and
                     before.st_uid == os.getuid() and before.st_nlink == 1 and
                     before.st_size == len(raw) <= maximum and
                     _hash_fd_exact(fd, before.st_size, maximum, name) ==
                         _sha(raw) and
                     _info_key(before) == _info_key(os.stat(
                         name, dir_fd=window_fd, follow_symlinks=False,
                     )),
                     f"Root GPG input {name} changed during verification")
        return primary_fingerprint
    except subprocess.TimeoutExpired as error:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        raise EvidenceArchiveError(
            "Root recorded-read GPG verification exceeded its bounded window",
        ) from error
    finally:
        try:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
            for descriptor in file_fds.values():
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if created_window and window_fd < 0:
                try:
                    window_fd = os.open(
                        window_name, os.O_RDONLY | _O_DIRECTORY |
                        _O_CLOEXEC | _O_NOFOLLOW, dir_fd=root_fd,
                    )
                except FileNotFoundError:
                    window_fd = -1
            if created_window and window_fd >= 0:
                cleanup_info = os.fstat(window_fd)
                _require(stat.S_ISDIR(cleanup_info.st_mode) and
                         cleanup_info.st_uid == os.getuid() and
                         stat.S_IMODE(cleanup_info.st_mode) == 0o700 and
                         cleanup_info.st_dev == device and
                         window_identity == (
                             cleanup_info.st_dev, cleanup_info.st_ino,
                             cleanup_info.st_mode, cleanup_info.st_uid,
                         ),
                         "Root recorded-read GPG partial window changed before cleanup")
                expected_names = {
                    "gpgv", "trusted-keyring.gpg", "ack.json", "ack.sig",
                    "status.stdout", "status.stderr",
                }
                present = set(os.listdir(window_fd))
                _require(present <= expected_names,
                         "Root recorded-read GPG window contains an undeclared file")
                for name in sorted(present):
                    info = os.stat(name, dir_fd=window_fd,
                                   follow_symlinks=False)
                    _require(stat.S_ISREG(info.st_mode) and
                             info.st_uid == os.getuid() and
                             info.st_nlink == 1 and
                             stat.S_IMODE(info.st_mode) in {0o600, 0o700},
                             "Root recorded-read GPG cleanup found a foreign file")
                    os.unlink(name, dir_fd=window_fd)
                os.fsync(window_fd)
                _require(not os.listdir(window_fd),
                         "Root recorded-read GPG window did not clean its exact files")
                os.close(window_fd)
                window_fd = -1
                current = os.stat(window_name, dir_fd=root_fd,
                                  follow_symlinks=False)
                _require((current.st_dev, current.st_ino,
                          current.st_mode, current.st_uid) == window_identity,
                         "Root recorded-read GPG temp directory changed before removal")
                os.rmdir(window_name, dir_fd=root_fd)
                os.fsync(root_fd)
            if root_identity is not None:
                reopened_root_fd = _open_dir_path(
                    scratch_root, "Root recorded-read GPG scratch root after window",
                    private_final=True,
                )
                try:
                    reopened_root = os.fstat(reopened_root_fd)
                    _require((reopened_root.st_dev, reopened_root.st_ino,
                              reopened_root.st_mode, reopened_root.st_uid) ==
                             root_identity,
                             "Root GPG scratch root changed during recorded verification")
                finally:
                    os.close(reopened_root_fd)
        finally:
            if window_fd >= 0:
                try:
                    os.close(window_fd)
                except OSError:
                    pass
            os.close(root_fd)


def _hash_fd_exact(fd: int, expected_bytes: int, maximum: int,
                   label: str, *, deadline_ns: int | None = None,
                   cancel_event=None) -> str:
    before = os.fstat(fd)
    _require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and
             before.st_nlink == 1 and before.st_size == expected_bytes <= maximum,
             f"{label} is not one exact bounded recorded-read GPG file")
    os.lseek(fd, 0, os.SEEK_SET)
    hasher = hashlib.sha256()
    total = 0
    while total < expected_bytes:
        _require(deadline_ns is None or time.monotonic_ns() < deadline_ns,
                 f"{label} exceeded its finite recorded-read window")
        _require(cancel_event is None or not cancel_event.is_set(),
                 f"{label} was cancelled")
        block = os.read(fd, min(COPY_BLOCK_BYTES, expected_bytes - total))
        _require(bool(block), f"{label} shortened during its bounded hash")
        total += len(block)
        _require(total <= maximum,
                 f"{label} exceeded its recorded-read GPG byte bound")
        hasher.update(block)
    after = os.fstat(fd)
    _require(os.read(fd, 1) == b"" and total == expected_bytes and
             _info_key(before) == _info_key(after),
             f"{label} changed while hashing its recorded-read GPG bytes")
    return hasher.hexdigest()


def _read_absolute_private_file(
    path: Path, maximum: int, label: str, *, deadline_ns: int | None = None,
    cancel_event=None,
) -> tuple[bytes, str, os.stat_result]:
    path_text = _absolute_path(str(path), f"{label} path")
    require_path = Path(path_text)
    _require(require_path.resolve(strict=True) == require_path,
             f"{label} path traverses a symlink or alias")
    parent_fd = _open_dir_path(str(require_path.parent), f"{label} parent",
                               private_final=False)
    try:
        raw, digest, info = _read_at(
            parent_fd, require_path.name, maximum, label,
            deadline_ns=deadline_ns, cancel_event=cancel_event,
        )
        return raw, digest, info
    finally:
        os.close(parent_fd)


def _recorded_read_window_chunk(
    plan: dict[str, Any], plan_pin: dict[str, Any], plan_module: object,
    read_ordinal: int, *, deadline_ns: int | None = None,
    cancel_event=None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    ordinal = plan_module._uint(
        read_ordinal, "Root recorded-read chunk ordinal",
        maximum=plan_module.READ_WINDOW_COUNT - 1,
    )
    index = plan["window_index"][ordinal]
    ref = plan["window_chunks"][index["chunk_ordinal"]]
    path = Path(ref["pin"]["path"])
    expected = (Path(plan["session_paths"]["window_metadata_root"]) /
                f"chunk-{ref['chunk_ordinal']:06d}.json")
    _require(path == expected and path.is_absolute(),
             "Root recorded-read chunk path differs from its nonce-bound plan")
    raw, digest, info = _read_absolute_private_file(
        path, MAX_ARCHIVE_READ_METADATA_BYTES,
        "Root recorded-read current window metadata chunk",
        deadline_ns=deadline_ns, cancel_event=cancel_event,
    )
    _require(digest == ref["pin"]["raw_sha256"] and
             len(raw) == ref["byte_count"] and
             info.st_dev == plan["scratch_declaration"]["device_id"],
             "Root recorded-read chunk raw pin or byte count differs")
    chunk_space = os.statvfs(path.parent)
    chunk_block = chunk_space.f_frsize or chunk_space.f_bsize
    _require(chunk_block ==
             plan["scratch_declaration"]["allocation_block_bytes"],
             "Root recorded-read chunk filesystem block differs from the plan")
    chunk = _parse_canonical(
        raw, "Root recorded-read current window metadata chunk",
        maximum_bytes=MAX_ARCHIVE_READ_METADATA_BYTES,
    )
    row = plan_module.validate_recorded_preparation_read_window_v2(
        plan, plan_pin, chunk, ordinal,
    )
    return chunk, row


def _hash_absolute_private_file(
    path: Path, maximum: int, label: str,
) -> tuple[str, os.stat_result]:
    path_text = _absolute_path(str(path), f"{label} path")
    checked = Path(path_text)
    _require(checked.resolve(strict=True) == checked,
             f"{label} path traverses a symlink or alias")
    parent_fd = _open_dir_path(str(checked.parent), f"{label} parent",
                               private_final=False)
    try:
        raw, digest, info = _read_at(
            parent_fd, checked.name, maximum, label, collect=False,
        )
        _require(raw is None, f"{label} unexpectedly allocated its full contents")
        return digest, info
    finally:
        os.close(parent_fd)


def _validate_local_dependencies(
    dependency_paths: dict[str, str], dependency_cache_root: str,
    context: dict[str, Any], plan_bytes: bytes, host_budget_raw: bytes,
    dependency_pins: dict[str, dict[str, str]] | None = None,
) -> tuple[bytes, bytes | None, bytes | None]:
    root = Path(_absolute_path(dependency_cache_root,
                               "private dependency cache root"))
    root_fd = _open_dir_path(str(root), "private dependency cache root",
                             private_final=True)
    os.close(root_fd)
    preparatory_budget = _parse_canonical(
        host_budget_raw, "Root-local host evidence budget",
        maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES,
    )
    if preparatory_budget.get("schema") == PREPARATORY_BUDGET_SCHEMA_V1:
        budget = _exact(preparatory_budget, PREPARATORY_BUDGET_FIELDS_V1,
                        "Root-local preparatory host budget")
        _require(budget.get("campaign_id") == context["campaign_id"] and
                 budget.get("host_id") == context["host_id"] and
                 budget.get("profile") == PREPARATORY_PROFILE_V1 and
                 _sha(host_budget_raw) ==
                    context["resource_budget_pin"]["raw_sha256"],
                 "Root-local preparatory budget identity/raw pin differs")
        pins = {
            "source": context["source_manifest_pin"],
            "plan": context["plan_pin"],
            "budget": context["resource_budget_pin"],
            "execution": context["execution_manifest_pin"],
            "width": _pin(budget["journal_width_contract_pin"],
                           "Root-local preparatory width pin"),
        }
        initial_spec_pin = _pin(
            budget["original_pins"]["initial_spec"],
            "Root-local preparatory initial Spec pin",
        )
        pins["spec"] = initial_spec_pin
        _require(type(dependency_paths) is dict and
                 list(dependency_paths) ==
                     [pin["path"] for pin in pins.values()] and
                 set(dependency_paths) == {pin["path"] for pin in pins.values()} and
                 type(dependency_pins) is dict and
                 dependency_pins == {pin["path"]: pin for pin in pins.values()},
                 "preparatory Root dependency map is not the exact six-pin Source/Plan/budget/execution/width/Spec closure")
        checked = {}
        local_paths = set()
        for kind, pin in pins.items():
            local = Path(_absolute_path(
                dependency_paths[pin["path"]],
                f"Root-local preparatory {kind} path",
            ))
            _require(local != root and root in local.parents and
                     str(local) != pin["path"] and str(local) not in local_paths and
                     local.resolve(strict=True) == local,
                     f"Root-local preparatory {kind} copy is aliased or outside its private cache")
            local_paths.add(str(local))
            checked[kind] = (local, pin)
        plan_local, plan_pin = checked["plan"]
        local_plan, plan_sha, _plan_info = _read_absolute_private_file(
            plan_local, MAX_PLAN_BYTES, "Root-local preparatory original PlanV3",
        )
        _require(plan_sha == plan_pin["raw_sha256"] and local_plan == plan_bytes,
                 "preparatory PlanV3 bytes differ from their Root-local raw pin")
        budget_local, budget_raw_pin = checked["budget"]
        local_budget, budget_sha, _budget_info = _read_absolute_private_file(
            budget_local, PREPARATORY_MAX_BUDGET_BYTES,
            "Root-local preparatory host budget",
        )
        _require(budget_sha == budget_raw_pin["raw_sha256"] and
                 local_budget == host_budget_raw,
                 "preparatory host budget differs from its Root-local captured pin")
        source_local, source_pin = checked["source"]
        source_manifest_raw, source_sha, _source_info = _read_absolute_private_file(
            source_local, MAX_SOURCE_MANIFEST_BYTES,
            "Root-local preparatory Source manifest",
        )
        _require(source_sha == source_pin["raw_sha256"],
                 "preparatory Source manifest differs from its Root-local raw pin")
        execution_local, execution_pin = checked["execution"]
        execution_manifest_raw, execution_sha, _execution_info = \
            _read_absolute_private_file(
                execution_local, MAX_PLAN_BYTES,
                "Root-local preparatory execution manifest",
            )
        _require(execution_sha == execution_pin["raw_sha256"],
                 "preparatory execution manifest differs from its Root-local raw pin")
        width_local, width_pin = checked["width"]
        journal_width_contract_raw, width_sha, _width_info = \
            _read_absolute_private_file(
                width_local, PREPARATORY_MAX_WIDTH_BYTES,
                "Root-local preparatory journal-width contract",
            )
        _require(width_sha == width_pin["raw_sha256"],
                 "preparatory width contract differs from its Root-local raw pin")
        return source_manifest_raw, execution_manifest_raw, journal_width_contract_raw
    budget, _is_r6 = _parse_host_budget_value(
        host_budget_raw, "Root-local host evidence budget",
    )
    v4_width_bound = (
        _is_r6 and
        budget.get("execution_manifest_schema") == EXECUTION_SCHEMA_V4
    )
    pins = {
        "source": context["source_manifest_pin"],
        "plan": context["plan_pin"],
        "budget": context["resource_budget_pin"],
    }
    if v4_width_bound:
        pins["execution"] = context["execution_manifest_pin"]
        pins["width"] = _pin(
            budget["journal_width_contract_pin"],
            "Root-local width-contract budget pin",
        )
    _require(type(dependency_paths) is dict and
             set(dependency_paths) == {pin["path"] for pin in pins.values()},
             "Root-local dependency map does not close over Source/Plan/budget pins")
    if v4_width_bound:
        _require(type(dependency_pins) is dict and
                 dependency_pins == {
                     pin["path"]: pin for pin in pins.values()
                 },
                 "v4 dependency map raw/semantic pins differ from the exact Source/Plan/budget/manifest/width pins")
    elif dependency_pins is not None:
        _require(dependency_pins == {
                    pin["path"]: pin for pin in pins.values()
                }, "legacy dependency-map pins differ from its exact three-row closure")
    local_paths = set()
    checked = {}
    for kind, pin in pins.items():
        local = Path(_absolute_path(dependency_paths[pin["path"]],
                                    f"Root-local {kind} path"))
        _require(local != root and root in local.parents and
                 str(local) != pin["path"] and str(local) not in local_paths and
                 local.resolve(strict=True) == local,
                 f"Root-local {kind} copy is aliased or outside its private cache")
        local_paths.add(str(local))
        checked[kind] = (local, pin)
    plan_local, plan_pin = checked["plan"]
    local_plan, plan_sha, _plan_info = _read_absolute_private_file(
        plan_local, MAX_PLAN_BYTES, "Root-local original PlanV3",
    )
    _require(plan_sha == plan_pin["raw_sha256"] and local_plan == plan_bytes,
             "PlanV3 bytes used by the coordinator differ from their Root-local captured pin")
    budget_local, budget_pin = checked["budget"]
    local_budget, budget_sha, _budget_info = _read_absolute_private_file(
        budget_local, MAX_JSON_BYTES, "Root-local host evidence budget",
    )
    _require(budget_sha == budget_pin["raw_sha256"] and
             local_budget == host_budget_raw,
             "host budget bytes used by the coordinator differ from their Root-local captured pin")
    source_local, source_pin = checked["source"]
    source_manifest_raw, source_sha, _source_info = _read_absolute_private_file(
        source_local, MAX_SOURCE_MANIFEST_BYTES,
        "Root-local Source manifest",
    )
    _require(source_sha == source_pin["raw_sha256"],
             "Root-local Source manifest differs from its origin raw pin")
    execution_manifest_raw = None
    journal_width_contract_raw = None
    if v4_width_bound:
        execution_local, execution_pin = checked["execution"]
        execution_manifest_raw, execution_sha, _execution_info = \
            _read_absolute_private_file(
                execution_local, MAX_PLAN_BYTES,
                "Root-local captured v4 execution manifest",
            )
        _require(execution_sha == execution_pin["raw_sha256"],
                 "Root-local execution manifest differs from its origin raw pin")
        width_local, width_pin = checked["width"]
        journal_width_contract_raw, width_sha, _width_info = \
            _read_absolute_private_file(
                width_local, MAX_JSON_BYTES,
                "Root-local captured v4 journal-width contract",
            )
        _require(width_sha == width_pin["raw_sha256"],
                 "Root-local width contract differs from its origin raw pin")
    return source_manifest_raw, execution_manifest_raw, journal_width_contract_raw


def _read_root_preparatory_spec(
    dependency_paths: dict[str, str], dependency_cache_root: str,
    budget_raw: bytes,
) -> bytes:
    """Read the sixth cached prep dependency named by both sealed pin sets."""
    budget = _exact(_parse_canonical(
        budget_raw, "Root-local preparatory budget for Spec dependency",
        maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES,
    ), PREPARATORY_BUDGET_FIELDS_V1,
                    "Root-local preparatory budget for Spec dependency")
    original = budget.get("original_pins")
    _require(type(original) is dict,
             "Root preparatory budget lacks its original pins")
    spec_pin = _pin(original.get("initial_spec"),
                    "Root preparatory initial Spec pin")
    root = Path(_absolute_path(dependency_cache_root,
                               "Root preparatory dependency cache root"))
    local_text = dependency_paths.get(spec_pin["path"])
    _require(type(local_text) is str,
             "Root preparatory dependency map omits its initial Spec copy")
    local = Path(_absolute_path(local_text,
                                "Root-local captured initial SpecV3"))
    _require(local != root and root in local.parents and local != Path(spec_pin["path"]) and
             local.resolve(strict=True) == local,
             "Root-local initial Spec copy aliases an origin or escapes its private cache")
    raw, actual, info = _read_absolute_private_file(
        local, PREPARATORY_MAX_SPEC_BYTES,
        "Root-local captured initial SpecV3",
    )
    _require(actual == spec_pin["raw_sha256"] and
             info.st_size == len(raw) <= PREPARATORY_MAX_SPEC_BYTES,
             "Root-local initial SpecV3 differs from its exact raw pin")
    return raw


def _read_root_prepared_exploration_dependencies(
    budget: dict[str, Any], budget_raw: bytes, budget_pin: object,
    context: dict[str, Any], dependency_map_raw: bytes,
    dependency_cache_root: str | os.PathLike[str],
) -> tuple[dict[str, Any], bytes, bytes, bytes, bytes, bytes]:
    """Reopen the exact six FINAL V5 dependencies without opening old origins."""
    derived_context, expected = _prepared_exploration_primary_context(budget, budget_pin)
    _require(context == derived_context,
             "Root V5 request context differs from its exact final budget pins")
    checked_budget_pin = expected[2]
    _require(type(budget_raw) is bytes and _sha(budget_raw) == checked_budget_pin["raw_sha256"] and
             budget_raw == _canonical(budget, maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES) and
             budget["budget_sha256"] == checked_budget_pin["semantic_sha256"] ==
                 _sha(_canonical({key: value for key, value in budget.items()
                                  if key != "budget_sha256"},
                                 maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES)),
             "Root V5 budget differs from its exact raw/semantic pin")
    spec_pin = expected[5]
    local_map = _exact(_parse_canonical(
        dependency_map_raw, "Root-local prepared-exploration dependency map",
    ), {"schema", "campaign_id", "host_id", "entries", "map_sha256"},
                       "Root-local prepared-exploration dependency map")
    map_body = {key: item for key, item in local_map.items()
                if key != "map_sha256"}
    _require(local_map["schema"] == DEPENDENCY_LOCAL_MAP_SCHEMA_V1 and
             local_map["campaign_id"] == context["campaign_id"] and
             local_map["host_id"] == context["host_id"] and
             local_map["map_sha256"] == _sha(_canonical(map_body)) and
             type(local_map["entries"]) is list and
             len(local_map["entries"]) == 6,
             "Root V5 dependency map identity/size/self digest differs")
    dependency_paths: dict[str, str] = {}
    local_paths = set()
    for index, (entry_value, expected_pin) in enumerate(zip(
            local_map["entries"], expected, strict=True)):
        entry = _exact(entry_value, {"origin_pin", "local_path"},
                       f"Root V5 dependency map row[{index}]")
        origin_pin = _pin(entry["origin_pin"],
                          f"Root V5 dependency origin pin[{index}]")
        local_path = _absolute_path(entry["local_path"],
                           f"Root V5 dependency local path[{index}]")
        _require(origin_pin == expected_pin and
                 origin_pin["path"] not in dependency_paths and
                 local_path != origin_pin["path"] and
                 local_path not in local_paths,
                 "Root V5 dependency map is not the exact ordered six-pin closure")
        dependency_paths[origin_pin["path"]] = local_path
        local_paths.add(local_path)
    cache_root = Path(_absolute_path(os.fspath(dependency_cache_root),
                            "Root V5 dependency cache root"))
    root_fd = _open_dir_path(str(cache_root),
                            "Root V5 dependency cache root",
                            private_final=True)
    root_identity = os.fstat(root_fd)
    try:
        limits = [
            MAX_SOURCE_MANIFEST_BYTES, MAX_PLAN_BYTES,
            PREPARATORY_MAX_BUDGET_BYTES, MAX_PLAN_BYTES,
            PREPARATORY_MAX_WIDTH_BYTES, PREPARATORY_MAX_SPEC_BYTES,
        ]
        captured = []
        for pin, maximum in zip(expected, limits, strict=True):
            origin = pin["path"]
            local_text = dependency_paths[origin]
            local = Path(_absolute_path(local_text, "Root V5 mapped dependency"))
            _require(origin == pin["path"] and local != cache_root and
                     cache_root in local.parents and local != Path(origin) and
                     local.resolve(strict=True) == local,
                     "Root V5 dependency path aliases or escapes its exact private cache")
            raw, actual, _info = _read_absolute_private_file(
                local, maximum, "Root-local captured prepared-exploration dependency",
            )
            _require(actual == pin["raw_sha256"],
                     "Root V5 dependency bytes differ from their original raw pin")
            captured.append(raw)
        _require(captured[2] == budget_raw,
                 "Root-local prepared-exploration budget copy differs from supplied bytes")
        execution = _parse_canonical(
            captured[3], "Root-local prepared-exploration execution manifest",
            maximum_bytes=MAX_PLAN_BYTES,
        )
        _exact(execution, {
            "schema", "campaign_id", "hosts", "original_inputs", "execution_sources",
            "modules", "observed_hosts", "artifact_root", "output_root", "phase_order",
            "protocol_sha256", "qualification_eligible", "manifest_sha256", "scope",
            "prepared_input_generation", "prepared_capacity_registration",
            "archive_signer_contexts", "journal_width_contracts",
        }, "Root V5 execution manifest")
        _require(execution["schema"] == PREPARED_EXPLORATION_EXECUTION_SCHEMA and
                 execution["scope"] == PREPARED_EXPLORATION_SCOPE and
                 execution["campaign_id"] == context["campaign_id"] and
                 execution["qualification_eligible"] is False and
                 execution["manifest_sha256"] == expected[3]["semantic_sha256"] ==
                     _sha(_canonical({key: value for key, value in execution.items()
                                      if key != "manifest_sha256"}, maximum_bytes=MAX_PLAN_BYTES)),
                 "Root V5 execution identity, scope or semantic pin differs")
        spec_wrapper = _exact(
            _exact(execution.get("original_inputs"), {
                "spec", "plan", "source_manifests", "campaign_artifacts_root",
            }, "Root V5 execution original inputs")["spec"],
            {"artifact", "semantic_sha256"},
            "Root V5 execution final Spec wrapper",
        )
        execution_spec_pin = _pin({
            **_pin_raw(spec_wrapper["artifact"],
                       "Root V5 execution final Spec artifact"),
            "semantic_sha256": spec_wrapper["semantic_sha256"],
        }, "Root V5 execution final Spec pin")
        _require(execution_spec_pin == spec_pin,
                 "sixth Root V5 dependency does not match both original Spec pin sets")
        final_root = os.stat(cache_root, follow_symlinks=False)
        held_root = os.fstat(root_fd)
        _require((final_root.st_dev, final_root.st_ino) ==
                     (held_root.st_dev, held_root.st_ino) ==
                     (root_identity.st_dev, root_identity.st_ino) and
                 stat.S_ISDIR(final_root.st_mode) and
                 final_root.st_uid == held_root.st_uid == os.getuid() and
                 stat.S_IMODE(final_root.st_mode) == stat.S_IMODE(held_root.st_mode) == 0o700 and
                 cache_root.resolve(strict=True) == cache_root,
                 "Root V5 dependency cache custody changed during the six-copy read")
        return (context, captured[0], captured[1], captured[3], captured[4],
                captured[5])
    finally:
        os.close(root_fd)


def _validate_v3_captured_budget_dependencies(
    dependency_map_raw: bytes, dependency_cache_root: str,
    catalogue_map_raw: bytes, catalogue_cache_root: str,
    context: dict[str, Any], plan_bytes: bytes, host_budget_raw: bytes,
    execution_manifest_raw: bytes | None,
    journal_width_contract_raw: bytes | None,
) -> tuple[bytes, bytes, bytes, dict[str, str], str]:
    """Reopen the exact five local dependencies and full catalogue map for v3."""
    budget, _ = _parse_host_budget_value(
        host_budget_raw, "captured ready host budget v3",
    )
    _require(budget.get("schema") == HOST_BUDGET_SCHEMA_V3,
             "captured dependency closure is reserved for ready budget v3")
    dependency_paths, dependency_pins = _parse_dependency_local_map_details(
        dependency_map_raw, context,
    )
    checked_catalogue_paths = _parse_catalogue_local_map(
        catalogue_map_raw, context,
    )
    catalogue_root = _absolute_path(catalogue_cache_root,
                                    "Root-local catalogue cache root")
    source_raw, captured_execution_raw, captured_width_raw = \
        _validate_local_dependencies(
            dependency_paths,
            _absolute_path(dependency_cache_root,
                           "Root-local dependency cache root"),
            context, plan_bytes, host_budget_raw, dependency_pins,
        )
    _require(execution_manifest_raw == captured_execution_raw and
             journal_width_contract_raw == captured_width_raw,
             "caller execution/width bytes differ from the exact Root-local five-map copies")
    return (source_raw, captured_execution_raw, captured_width_raw,
            checked_catalogue_paths, catalogue_root)


def _validate_preparatory_captured_budget_dependencies(
    dependency_map_raw: bytes, dependency_cache_root: str,
    catalogue_map_raw: bytes, catalogue_cache_root: str,
    context: dict[str, Any], plan_bytes: bytes, host_budget_raw: bytes,
    execution_manifest_raw: bytes | None,
    journal_width_contract_raw: bytes | None,
) -> tuple[bytes, bytes, bytes, bytes, dict[str, str], str]:
    """Reopen the exact six captured prep dependencies and catalogue."""
    budget = _exact(_parse_canonical(
        host_budget_raw, "captured preparatory host budget",
        maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES,
    ), PREPARATORY_BUDGET_FIELDS_V1,
                    "captured preparatory host budget")
    _require(budget.get("schema") == PREPARATORY_BUDGET_SCHEMA_V1 and
             budget.get("campaign_id") == context["campaign_id"] and
             budget.get("host_id") == context["host_id"],
             "captured preparatory budget identity differs")
    dependency_paths, dependency_pins = _parse_dependency_local_map_details(
        dependency_map_raw, context,
    )
    _require(len(dependency_paths) == 6,
             "preparatory Root map must contain exactly six dependency copies")
    checked_catalogue_paths = _parse_catalogue_local_map(
        catalogue_map_raw, context,
    )
    catalogue_root = _absolute_path(catalogue_cache_root,
                                    "Root-local preparatory catalogue cache")
    source_raw, captured_execution_raw, captured_width_raw = \
        _validate_local_dependencies(
            dependency_paths,
            _absolute_path(dependency_cache_root,
                           "Root-local preparatory dependency cache"),
            context, plan_bytes, host_budget_raw, dependency_pins,
        )
    spec_raw = _read_root_preparatory_spec(
        dependency_paths,
        _absolute_path(dependency_cache_root,
                       "Root-local preparatory dependency cache"),
        host_budget_raw,
    )
    _require(execution_manifest_raw == captured_execution_raw and
             journal_width_contract_raw == captured_width_raw,
             "caller prep execution/width bytes differ from their Root-local mapped copies")
    return (source_raw, captured_execution_raw, captured_width_raw, spec_raw,
            checked_catalogue_paths, catalogue_root)


def _read_absolute_external_file(
    path: Path, maximum: int, label: str,
) -> tuple[bytes, str, os.stat_result]:
    """Read a pinned public key/tool without trusting its path ancestors."""
    path_text = _absolute_path(str(path), f"{label} path")
    checked = Path(path_text)
    _require(checked.resolve(strict=True) == checked,
             f"{label} path traverses a symlink or alias")
    parent_fd = _open_dir_path(str(checked.parent), f"{label} parent",
                               private_final=False)
    try:
        try:
            before_path = os.stat(checked.name, dir_fd=parent_fd,
                                  follow_symlinks=False)
            _require(stat.S_ISREG(before_path.st_mode) and
                     before_path.st_uid in {0, os.getuid()} and
                     before_path.st_nlink == 1 and
                     before_path.st_size <= maximum,
                     f"{label} is not a bounded root/user-owned regular file")
            descriptor = os.open(checked.name, os.O_RDONLY | _O_CLOEXEC |
                                 _O_NOFOLLOW | _O_NONBLOCK, dir_fd=parent_fd)
        except OSError as error:
            raise EvidenceArchiveError(f"cannot open {label}: {error}") from error
        try:
            before = os.fstat(descriptor)
            _require(_info_key(before) == _info_key(before_path),
                     f"{label} changed identity before read")
            hasher = hashlib.sha256()
            chunks = []
            total = 0
            while total < before.st_size:
                block = os.read(descriptor, min(COPY_BLOCK_BYTES,
                                                before.st_size - total))
                _require(bool(block), f"{label} ended before its pinned size")
                total += len(block)
                _require(total <= maximum and total <= before.st_size,
                         f"{label} exceeded its bounded read")
                hasher.update(block)
                chunks.append(block)
            _require(os.read(descriptor, 1) == b"" and total == before.st_size,
                     f"{label} has trailing bytes or changed size")
            after = os.fstat(descriptor)
            after_path = os.stat(checked.name, dir_fd=parent_fd,
                                 follow_symlinks=False)
            _require(_info_key(before) == _info_key(after) ==
                     _info_key(after_path), f"{label} changed during stable read")
            return b"".join(chunks), hasher.hexdigest(), after
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_fd)


def _read_absolute_executable(
    path: Path, maximum: int, label: str,
) -> tuple[bytes, str, os.stat_result]:
    raw, digest, info = _read_absolute_external_file(path, maximum, label)
    _require(stat.S_IMODE(info.st_mode) & 0o111,
             f"{label} is not executable")
    return raw, digest, info


class _private_temp_pair:
    """Create bounded private GPG inputs and remove only these exact temp names."""

    def __init__(self, ack_raw: bytes, signature_raw: bytes,
                 keyring_raw: bytes) -> None:
        self.ack_raw = ack_raw
        self.signature_raw = signature_raw
        self.keyring_raw = keyring_raw
        self.directory = None
        self.paths: tuple[Path, Path] | None = None

    def __enter__(self) -> tuple[Path, Path, Path]:
        import tempfile
        directory = tempfile.mkdtemp(prefix="source5-ack-verify-", dir="/tmp")
        os.chmod(directory, 0o700)
        self.directory = Path(directory)
        _require(self.directory.parent == Path("/tmp") and
                 self.directory.lstat().st_uid == os.getuid() and
                 stat.S_IMODE(self.directory.lstat().st_mode) == 0o700,
                 "GPG verification inputs are outside an owned private temp directory")
        ack_path = self.directory / "ack.json"
        signature_path = self.directory / "ack.sig"
        keyring_path = self.directory / "trusted-keyring.gpg"
        for path, raw in ((ack_path, self.ack_raw),
                          (signature_path, self.signature_raw),
                          (keyring_path, self.keyring_raw)):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         _O_CLOEXEC | _O_NOFOLLOW, 0o600)
            try:
                view = memoryview(raw)
                while view:
                    count = os.write(fd, view)
                    _require(count > 0, "GPG verification input writer made no progress")
                    view = view[count:]
                os.fsync(fd)
            finally:
                os.close(fd)
        self.paths = (ack_path, signature_path, keyring_path)
        return self.paths

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self.paths is not None:
            for path in self.paths:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            try:
                self.directory.rmdir()
            except FileNotFoundError:
                pass


class _private_temp_executable:
    """Execute exact captured tool bytes without reopening their old path."""

    def __init__(self, raw: bytes, expected_sha256: str):
        _require(type(raw) is bytes and 0 < len(raw) <= MAX_ARCHIVE_GPGV_BYTES and
                 _sha(raw) == _digest(expected_sha256,
                                      "captured GPGV executable digest"),
                 "captured GPGV bytes differ from their exact bounded pin")
        self.raw = raw
        self.digest = expected_sha256
        self.directory: Path | None = None
        self.path: Path | None = None
        self.directory_identity: tuple[int, int] | None = None
        self.file_identity: tuple[int, ...] | None = None

    def __enter__(self) -> Path:
        import tempfile
        directory = Path(tempfile.mkdtemp(
            prefix="source5-recorded-gpgv-", dir="/tmp",
        ))
        self.directory = directory
        path = directory / "gpgv"
        self.path = path
        try:
            directory_info = directory.lstat()
            _require(directory.parent == Path("/tmp") and
                     stat.S_ISDIR(directory_info.st_mode) and
                     directory_info.st_uid == os.getuid() and
                     stat.S_IMODE(directory_info.st_mode) == 0o700,
                     "captured GPGV temp root is not one owned private directory")
            self.directory_identity = (directory_info.st_dev, directory_info.st_ino)
            fd = os.open(
                path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                _O_CLOEXEC | _O_NOFOLLOW, 0o700,
            )
            try:
                os.fchmod(fd, 0o700)
                view = memoryview(self.raw)
                while view:
                    count = os.write(fd, view)
                    _require(count > 0,
                             "captured GPGV temp writer made no progress")
                    view = view[count:]
                os.fsync(fd)
                info = os.fstat(fd)
                _require(stat.S_ISREG(info.st_mode) and
                         info.st_uid == os.getuid() and
                         stat.S_IMODE(info.st_mode) == 0o700 and
                         info.st_nlink == 1 and info.st_size == len(self.raw),
                         "captured GPGV temp executable has wrong identity or mode")
                self.file_identity = _info_key(info)
            finally:
                os.close(fd)
            directory_fd = os.open(
                directory, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW,
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            _raw, digest, _info = _read_absolute_executable(
                path, MAX_ARCHIVE_GPGV_BYTES,
                "captured GPGV temp executable before verification",
            )
            _require(digest == self.digest,
                     "captured GPGV temp executable changed before verification")
            return path
        except BaseException:
            self._cleanup_partial()
            raise

    def _cleanup_partial(self) -> None:
        if self.directory is None:
            return
        try:
            if self.path is not None:
                try:
                    info = self.path.lstat()
                except FileNotFoundError:
                    info = None
                if info is not None:
                    _require(stat.S_ISREG(info.st_mode) and
                             info.st_uid == os.getuid() and
                             stat.S_IMODE(info.st_mode) == 0o700 and
                             info.st_nlink == 1,
                             "captured GPGV temp path changed during failed setup")
                    self.path.unlink()
            try:
                self.directory.rmdir()
            except FileNotFoundError:
                pass
            parent_fd = os.open(
                "/tmp", os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW,
            )
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        finally:
            self.path = None
            self.directory = None

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self.path is None or self.directory is None:
            return
        try:
            before_path = self.path.lstat()
            _require(self.file_identity == _info_key(before_path) and
                     stat.S_ISREG(before_path.st_mode) and
                     before_path.st_uid == os.getuid() and
                     stat.S_IMODE(before_path.st_mode) == 0o700 and
                     before_path.st_nlink == 1 and
                     before_path.st_size == len(self.raw),
                     "captured GPGV temp executable changed before cleanup")
            _raw, digest, after = _read_absolute_executable(
                self.path, MAX_ARCHIVE_GPGV_BYTES,
                "captured GPGV temp executable after verification",
            )
            _require(digest == self.digest and
                     self.file_identity == _info_key(after),
                     "captured GPGV temp executable bytes changed during verification")
            parent_fd = os.open(
                self.directory, os.O_RDONLY | _O_DIRECTORY |
                _O_CLOEXEC | _O_NOFOLLOW,
            )
            try:
                current = os.stat("gpgv", dir_fd=parent_fd,
                                  follow_symlinks=False)
                _require(self.file_identity == _info_key(current),
                         "captured GPGV temp path changed before cleanup")
                os.unlink("gpgv", dir_fd=parent_fd)
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
            directory_info = self.directory.lstat()
            _require(self.directory_identity ==
                     (directory_info.st_dev, directory_info.st_ino) and
                     stat.S_ISDIR(directory_info.st_mode) and
                     stat.S_IMODE(directory_info.st_mode) == 0o700 and
                     directory_info.st_uid == os.getuid() and
                     not any(self.directory.iterdir()),
                     "captured GPGV temp directory changed before cleanup")
            self.directory.rmdir()
            tmp_fd = os.open(
                "/tmp", os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC | _O_NOFOLLOW,
            )
            try:
                os.fsync(tmp_fd)
            finally:
                os.close(tmp_fd)
        finally:
            self.path = None
            self.directory = None


def archive_job_checkpoint(
    request_pin: object, request_bytes: bytes,
    context: object, job_record_pin: object, job_record_bytes: bytes,
    plan_bytes: bytes, host_budget_raw: bytes,
    dependency_paths: dict[str, str],
    dependency_cache_root: str | os.PathLike[str],
    catalogue_chunk_paths: dict[str, str],
    catalogue_cache_root: str | os.PathLike[str], rows: Iterable[object],
    owner_receipt_bytes: dict[str, bytes], staged_files: dict[str, str],
    staging_root: str | os.PathLike[str], archive_root: str | os.PathLike[str],
    stage_map_path: str | os.PathLike[str], signer: object, *,
    dependency_pins: dict[str, dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Copy, seal, and sign one completed job outside every timed lane."""
    rows = list(rows)
    request_value = _validate_checkpoint_request(_parse_checkpoint_metadata(
        request_bytes, "transferred checkpoint request",
    ))
    checked_context = _validate_context(context)
    source_manifest_raw, execution_manifest_raw, journal_width_contract_raw = \
        _validate_local_dependencies(
        dependency_paths,
        _absolute_path(os.fspath(dependency_cache_root),
                       "private dependency cache root"),
        checked_context, plan_bytes, host_budget_raw, dependency_pins,
    )
    budget_probe = _parse_canonical(
        host_budget_raw, "archive host evidence budget",
        maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES,
    )
    spec_raw = None
    if budget_probe.get("schema") == PREPARATORY_BUDGET_SCHEMA_V1:
        spec_raw = _read_root_preparatory_spec(
            dependency_paths,
            _absolute_path(os.fspath(dependency_cache_root),
                           "private dependency cache root"),
            host_budget_raw,
        )
    signature_limit = _campaign_signature_limit(
        host_budget_raw, checked_context["resource_budget_pin"],
        checked_context, source_manifest_raw=source_manifest_raw,
        execution_manifest_raw=execution_manifest_raw,
        plan_raw=plan_bytes,
        journal_width_contract_raw=journal_width_contract_raw,
        spec_raw=spec_raw,
        catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=_absolute_path(
            os.fspath(catalogue_cache_root), "private catalogue cache root",
        ),
        root_local=True,
        require_v4_manifest=execution_manifest_raw is not None,
        request_schema=request_value["schema"],
    )
    signer_value = _exact(signer, {
        "gpg_executable", "gpg_homedir", "primary_fingerprint",
        "maximum_signature_bytes",
    }, "private archive signing configuration")
    _require(_fingerprint(signer_value["primary_fingerprint"],
                          "private archive signer fingerprint") ==
             checked_context["authorized_signer_fingerprint"] and
             _uint(signer_value["maximum_signature_bytes"],
                   "private signer signature quota", positive=True) ==
                 signature_limit,
             "private signer fingerprint/quota differs from the pinned campaign budget")
    checked_request_pin = _pin(request_pin, "host checkpoint request pin")
    _require(type(request_bytes) is bytes and
             _sha(request_bytes) == checked_request_pin["raw_sha256"],
             "transferred checkpoint request differs from its raw/semantic pin")
    request_value = _validate_checkpoint_request(_parse_checkpoint_metadata(
        request_bytes, "transferred checkpoint request",
    ))
    tree_inventories = request_value.get("tree_inventories")
    request, _request_record, job_identity = _checkpoint_request_projection(
        checked_context, job_record_pin, job_record_bytes, plan_bytes, rows,
        owner_receipt_bytes, tree_inventories,
        fixed_pair_request_v3=request_value["schema"] == REQUEST_SCHEMA_V3,
    )
    _require(request_value == request and
             checked_request_pin["semantic_sha256"] == request["request_sha256"],
             "transferred checkpoint request differs from its raw/semantic pin")
    record, _authorization, job_identity = _validate_job_record(
        checked_context, job_record_pin, job_record_bytes, plan_bytes,
    )
    checked_rows = _validate_rows(list(rows))
    job_pin = _pin_raw(job_record_pin, "Source5 job record pin")
    _require(all(row["origin_path"] != job_pin["path"]
                 for row in checked_rows),
             "always-local job record must not enter the reclaimable object closure")
    _validate_host_budget_object_rows(
        host_budget_raw, checked_context, job_identity, checked_rows,
        job_pin, len(job_record_bytes), record["record_sha256"],
        catalogue_chunk_paths,
        _absolute_path(os.fspath(catalogue_cache_root),
                       "private catalogue cache root"),
        source_manifest_raw=source_manifest_raw,
        execution_manifest_raw=execution_manifest_raw,
        journal_width_contract_raw=journal_width_contract_raw,
        tree_inventories_value=tree_inventories,
        owner_receipt_pins_value=request["owner_receipt_pins"],
        plan_raw=plan_bytes,
        spec_raw=spec_raw,
    )
    _require(type(staged_files) is dict and
             set(staged_files) == {row["origin_path"] for row in checked_rows},
             "staged-file map is not a complete exact-origin mapping")
    stage_root = _absolute_path(os.fspath(staging_root), "private staging root")
    if tree_inventories is not None:
        staged_rows = {row["origin_path"]: row for row in checked_rows}
        tree_file_paths = {
            item["path"] for tree in tree_inventories
            for item in tree["entries"] if item["kind"] == "file"
        }
        typed_metadata_paths = {
            tree["inventory_pin"]["path"] for tree in tree_inventories
        } | {
            tree["owner_receipt_pin"]["path"] for tree in tree_inventories
        }
        for origin in sorted(tree_file_paths):
            _require(origin in staged_files and origin in staged_rows,
                     "v2 tree file lacks its exact staged catalogue row")
            staged_tree_file, literal = _staged_descriptor(
                staged_files[origin], stage_root, staged_rows[origin],
            )
            _require(staged_tree_file["kind"] == "regular" and literal is None,
                     "ProbeV2 inventory file was staged as a symlink or non-regular object")
        for origin in sorted(typed_metadata_paths):
            _require(origin in staged_files and origin in staged_rows,
                     "v2 tree receipt/inventory lacks its exact staged row")
            staged_metadata, literal = _staged_descriptor(
                staged_files[origin], stage_root, staged_rows[origin],
            )
            _require(staged_metadata["kind"] == "regular" and literal is None,
                     "ProbeV2 receipt/inventory origin is not a no-follow regular file")
        checked_tree_receipts = {}
        for tree in tree_inventories:
            pin = tree["owner_receipt_pin"]
            receipt_row = staged_rows[pin["path"]]
            staged_receipt = _read_staged_raw(
                staged_files[pin["path"]], stage_root, receipt_row,
            )
            _require(staged_receipt == owner_receipt_bytes[pin["path"]],
                     "staged ProbeV2 capture receipt differs from its raw request bytes")
            checked_tree_receipts[pin["path"]] = staged_receipt

        def load_staged_tree_object(row: dict[str, Any]) -> bytes:
            _require(row["origin_path"] in staged_files,
                     "v2 tree closure omits an exact staged inventory object")
            return _read_staged_raw(
                staged_files[row["origin_path"]], stage_root, row,
            )

        _validate_tree_inventory_payloads(
            tree_inventories, checked_rows, checked_tree_receipts,
            load_staged_tree_object,
        )
    archive = _absolute_path(os.fspath(archive_root), "private archive root")
    context_value = checked_context
    phase = _token(context_value["phase"], "original phase")
    leaf = (f"{job_identity['job_ordinal']:06d}-"
            f"{job_identity['job_sha256']}.json")
    checkpoint_relative = f"checkpoints/{phase}/{leaf}"
    manifest_relative = f"objects/manifests/{phase}/{leaf}"
    ack_relative = f"acks/{phase}/{leaf}"
    signature_relative = f"acks/signatures/{phase}/{leaf[:-5]}.sig"

    archive_root_fd = _open_dir_path(archive, "private archive root",
                                     private_final=True)
    try:
        campaign_fd = _ensure_private_child(
            archive_root_fd, context_value["campaign_id"],
            "archive campaign directory",
        )
        try:
            host_fd = _ensure_private_child(
                campaign_fd, context_value["host_id"], "archive host directory",
            )
            try:
                source5_fd = _ensure_private_child(
                    host_fd, "source5", "archive Source5 directory",
                )
                try:
                    validation_relative = (
                        f"validation/job-records/{phase}/{leaf}"
                    )
                    validation_parent, validation_name = _open_parent(
                        source5_fd, validation_relative, create=True,
                        label="always-local Source5 job-record validation",
                    )
                    try:
                        try:
                            validation_raw_sha, validation_size = _write_at(
                                validation_parent, validation_name,
                                job_record_bytes,
                                "always-local Source5 job record",
                            )
                        except FileExistsError:
                            validation_raw_sha = _sha(job_record_bytes)
                            validation_size = len(job_record_bytes)
                        validation_reopened, validation_reopened_sha, _ = _read_at(
                            validation_parent, validation_name, MAX_JSON_BYTES,
                            "always-local Source5 job record",
                            expected_bytes=validation_size,
                        )
                        _require(validation_reopened == job_record_bytes and
                                 validation_reopened_sha == validation_raw_sha ==
                                     job_pin["raw_sha256"],
                                 "always-local job record failed independent reopen")
                    finally:
                        os.close(validation_parent)
                    job_record_validation = {
                        "path": str(
                            Path(archive) / context_value["campaign_id"] /
                            context_value["host_id"] / "source5" /
                            validation_relative
                        ),
                        "origin_path": job_pin["path"],
                        "raw_sha256": validation_raw_sha,
                        "semantic_sha256": record["record_sha256"],
                        "byte_count": validation_size,
                    }
                    object_rows = []
                    stage_rows = []
                    payload_bytes = 0
                    for row in checked_rows:
                        origin = row["origin_path"]
                        object_id = _object_identity(origin, row["raw_sha256"])
                        object_pin, staged_descriptor = _copy_object(
                            source5_fd, object_id, staged_files[origin],
                            stage_root, row,
                        )
                        relative_object = f"objects/{object_id}"
                        object_pin = {
                            "path": str(Path(archive) /
                                        context_value["campaign_id"] /
                                        context_value["host_id"] / "source5" /
                                        relative_object),
                            "raw_sha256": object_pin["raw_sha256"],
                            "semantic_sha256": object_pin["semantic_sha256"],
                            "byte_count": object_pin["byte_count"],
                        }
                        object_rows.append({
                            "origin_path": origin, "role": row["role"],
                            "object_id": object_id,
                            "byte_count": row["byte_count"],
                            "raw_sha256": row["raw_sha256"],
                            "semantic_sha256": row["semantic_sha256"],
                            "object_pin": object_pin,
                        })
                        stage_rows.append({
                            "origin_path": origin, "object_id": object_id,
                            "remote_object_pin": dict(object_pin),
                            "local_staged_file": staged_descriptor,
                        })
                        payload_bytes += row["byte_count"]
                        _require(payload_bytes <= MAX_TOTAL_BYTES,
                                 "job archive exceeds the fixed total payload ceiling")

                    if record["evidence"].get("host_receipt") is not None:
                        overlay_pin = _pin_raw(
                            record["evidence"].get("overlay"),
                            "original fixed-pair overlay pin",
                        )
                        overlay_row = next(
                            row for row in checked_rows
                            if row["origin_path"] == overlay_pin["path"]
                        )
                        staged_overlay_raw = _read_staged_raw(
                            staged_files[overlay_pin["path"]], stage_root,
                            overlay_row,
                        )
                        _validate_fixed_pair_host_receipt_bindings(
                            checked_context, record, checked_rows,
                            request["owner_receipt_pins"],
                            owner_receipt_bytes=owner_receipt_bytes,
                            overlay_raw=staged_overlay_raw,
                        )

                    manifest_body = {
                        "schema": OBJECT_MANIFEST_SCHEMA_V1,
                        "campaign_id": context_value["campaign_id"],
                        "host_id": context_value["host_id"],
                        "phase": phase,
                        "job_index": context_value["job_index"],
                        "job_ordinal": job_identity["job_ordinal"],
                        "job_sha256": job_identity["job_sha256"],
                        "run_id": job_identity["run_id"],
                        "job_record_raw_sha256": job_pin["raw_sha256"],
                        "predecessor_ack_pin":
                            context_value["predecessor_ack_pin"],
                        "objects": object_rows,
                        "object_count": len(object_rows),
                        "payload_bytes": payload_bytes,
                        "manifest_sha256": "",
                    }
                    manifest_sha = _sha(_canonical({
                        key: item for key, item in manifest_body.items()
                        if key != "manifest_sha256"
                    }))
                    manifest = {**manifest_body, "manifest_sha256": manifest_sha}
                    manifest_raw = _canonical(manifest)
                    manifest_parent, manifest_name = _open_parent(
                        source5_fd, manifest_relative, create=True,
                        label="Source5 object manifest",
                    )
                    try:
                        manifest_raw_sha, manifest_size = _write_at(
                            manifest_parent, manifest_name, manifest_raw,
                            "Source5 object manifest",
                        )
                        reopened, reopened_sha, _ = _read_at(
                            manifest_parent, manifest_name, MAX_JSON_BYTES,
                            "Source5 object manifest",
                            expected_bytes=manifest_size,
                        )
                        _require(reopened == manifest_raw and
                                 reopened_sha == manifest_raw_sha,
                                 "object manifest failed independent reopen")
                    finally:
                        os.close(manifest_parent)
                    manifest_pin = {
                        "path": str(Path(archive) /
                                    context_value["campaign_id"] /
                                    context_value["host_id"] / "source5" /
                                    manifest_relative),
                        "raw_sha256": manifest_raw_sha,
                        "semantic_sha256": manifest_sha,
                    }

                    checkpoint_path = str(
                        Path(archive) / context_value["campaign_id"] /
                        context_value["host_id"] / "source5" /
                        checkpoint_relative
                    )
                    checkpoint_parent, _checkpoint_name = _open_parent(
                        source5_fd, checkpoint_relative, create=True,
                        label="final Source5 checkpoint",
                    )
                    os.close(checkpoint_parent)
                    checkpoint, checkpoint_pin = build_job_checkpoint(
                        checked_request_pin, request_bytes, checked_context,
                        job_pin, job_record_bytes, plan_bytes, checked_rows,
                        owner_receipt_bytes, manifest_pin, checkpoint_path,
                    )
                    checked_manifest = _validate_manifest(
                        manifest, checkpoint, job_identity,
                    )
                    object_reopen_sha = _verify_archive_objects(
                        checked_manifest,
                    )

                    root_info = os.fstat(source5_fd)
                    archive_directory = {
                        "path": str(Path(archive) /
                                    context_value["campaign_id"] /
                                    context_value["host_id"] / "source5"),
                        "device": root_info.st_dev, "inode": root_info.st_ino,
                        "mode": stat.S_IMODE(root_info.st_mode),
                    }
                    durable_commit = {
                        "commit_id": _sha(_canonical({
                            "checkpoint_pin": checkpoint_pin,
                            "object_manifest_pin": manifest_pin,
                            "object_reopen_sha256": object_reopen_sha,
                            "job_record_validation": job_record_validation,
                        })),
                        "archive_source5_directory": archive_directory,
                        "job_record_validation": job_record_validation,
                        "checkpoint_pin": checkpoint_pin,
                        "object_manifest_pin": manifest_pin,
                        "object_reopen_sha256": object_reopen_sha,
                        "object_count": len(object_rows),
                        "payload_bytes": payload_bytes,
                    }
                    fingerprint = _fingerprint(
                        context_value["authorized_signer_fingerprint"],
                        "authorized signer fingerprint",
                    )
                    ack_body = {
                        "schema": ACK_SCHEMA_V1,
                        "checkpoint_pin": checkpoint_pin,
                        "object_manifest_pin": manifest_pin,
                        "predecessor_ack_pin":
                            context_value["predecessor_ack_pin"],
                        "signer_fingerprint": fingerprint,
                        "durable_commit": durable_commit,
                        "ack_sha256": "",
                    }
                    ack_sha = _sha(_canonical({
                        key: item for key, item in ack_body.items()
                        if key != "ack_sha256"
                    }))
                    ack = {**ack_body, "ack_sha256": ack_sha}
                    ack_raw = _canonical(ack)
                    signature_raw = _gpg_sign(ack_raw, signer_value)
                    ack_parent, ack_name = _open_parent(
                        source5_fd, ack_relative, create=True,
                        label="Source5 durable ACK",
                    )
                    try:
                        ack_raw_sha, ack_size = _write_at(
                            ack_parent, ack_name, ack_raw,
                            "Source5 durable ACK",
                        )
                        reopened, reopened_sha, _ = _read_at(
                            ack_parent, ack_name, MAX_JSON_BYTES,
                            "Source5 durable ACK", expected_bytes=ack_size,
                        )
                        _require(reopened == ack_raw and
                                 reopened_sha == ack_raw_sha,
                                 "durable ACK failed independent reopen")
                    finally:
                        os.close(ack_parent)
                    signature_parent, signature_name = _open_parent(
                        source5_fd, signature_relative, create=True,
                        label="Source5 ACK signature",
                    )
                    try:
                        signature_sha, signature_size = _write_at(
                            signature_parent, signature_name, signature_raw,
                            "Source5 detached signature",
                        )
                        signature_read, signature_read_sha, _ = _read_at(
                            signature_parent, signature_name,
                            signature_limit, "Source5 detached signature",
                            expected_bytes=signature_size,
                        )
                        _require(signature_read == signature_raw and
                                 signature_read_sha == signature_sha,
                                 "detached signature failed independent reopen")
                    finally:
                        os.close(signature_parent)

                    stage_map_body = {
                        "schema": STAGE_MAP_SCHEMA_V1,
                        "checkpoint_pin": checkpoint_pin,
                        "object_manifest_pin": manifest_pin,
                        "rows": stage_rows,
                        "stage_map_sha256": "",
                    }
                    stage_map_sha = _sha(_canonical({
                        key: item for key, item in stage_map_body.items()
                        if key != "stage_map_sha256"
                    }))
                    stage_map = {
                        **stage_map_body, "stage_map_sha256": stage_map_sha,
                    }
                    stage_raw = _canonical(stage_map)
                    stage_path = Path(_absolute_path(
                        os.fspath(stage_map_path), "stage-map output path",
                    ))
                    stage_parent_fd = _open_dir_path(
                        str(stage_path.parent), "stage-map output parent",
                        private_final=True,
                    )
                    try:
                        stage_raw_sha, stage_size = _write_at(
                            stage_parent_fd, stage_path.name, stage_raw,
                            "Source5 stage map",
                        )
                        stage_reopened, stage_reopened_sha, _ = _read_at(
                            stage_parent_fd, stage_path.name, MAX_JSON_BYTES,
                            "Source5 stage map", expected_bytes=stage_size,
                        )
                        _require(stage_reopened == stage_raw and
                                 stage_reopened_sha == stage_raw_sha,
                                 "stage map failed independent reopen")
                    finally:
                        os.close(stage_parent_fd)
                    stage_map_pin = {
                        "path": str(stage_path), "raw_sha256": stage_raw_sha,
                        "semantic_sha256": stage_map_sha,
                    }
                    checked_stage_map = _validate_stage_map(
                        stage_map, checkpoint, checked_manifest,
                    )
                    _require(checked_stage_map == stage_map,
                             "stage map changed during archive sealing")
                    return {
                        "request": request,
                        "request_pin": checked_request_pin,
                        "checkpoint": checkpoint,
                        "checkpoint_pin": checkpoint_pin,
                        "object_manifest": manifest,
                        "object_manifest_pin": manifest_pin,
                        "ack": ack,
                        "ack_pin": {
                            "path": str(Path(archive) /
                                        context_value["campaign_id"] /
                                        context_value["host_id"] / "source5" /
                                        ack_relative),
                            "raw_sha256": ack_raw_sha,
                            "semantic_sha256": ack_sha,
                        },
                        "signature_pin": {
                            "path": str(Path(archive) /
                                        context_value["campaign_id"] /
                                        context_value["host_id"] / "source5" /
                                        signature_relative),
                            "raw_sha256": signature_sha,
                            "signer_fingerprint": fingerprint,
                        },
                        "job_record_validation": job_record_validation,
                        "coordinator_stage_map": stage_map,
                        "coordinator_stage_map_pin": stage_map_pin,
                        "object_pin_map": {
                            row["origin_path"]: row["object_pin"]
                            for row in object_rows
                        },
                    }
                finally:
                    os.close(source5_fd)
            finally:
                os.close(host_fd)
        finally:
            os.close(campaign_fd)
    finally:
        os.close(archive_root_fd)

def _read_object_pin(pin: object, byte_count: int) -> tuple[None, dict[str, Any]]:
    object_pin = _exact(pin, {
        "path", "raw_sha256", "semantic_sha256", "byte_count",
    }, "captured object pin")
    path = Path(_absolute_path(object_pin["path"], "captured object path"))
    parent_fd = _open_dir_path(str(path.parent), "captured object parent",
                               private_final=True)
    try:
        raw, digest, info = _read_at(
            parent_fd, path.name, byte_count, "captured object",
            expected_bytes=byte_count, collect=False,
        )
    finally:
        os.close(parent_fd)
    _require(raw is None and byte_count == object_pin["byte_count"] and
             digest == object_pin["raw_sha256"] ==
                 object_pin["semantic_sha256"],
             "captured object differs from its exact raw/semantic pin")
    return None, object_pin


class _RecordedReadTarOutput:
    def __init__(self, fd: int, maximum: int, deadline_ns: int,
                 cancel_event: Any):
        self.fd = fd
        self.maximum = maximum
        self.deadline_ns = deadline_ns
        self.cancel_event = cancel_event
        self.total = 0
        self.digest = hashlib.sha256()

    def _check(self) -> None:
        _require(time.monotonic_ns() < self.deadline_ns and
                 (self.cancel_event is None or
                  not self.cancel_event.is_set()),
                 "Root recorded-read tar write exceeded or cancelled its bounded window")

    def write(self, value: bytes) -> int:
        _require(type(value) is bytes,
                 "Root recorded-read tar writer received a non-byte block")
        self._check()
        _require(self.total + len(value) <= self.maximum,
                 "Root recorded-read tar exceeds its exact Source bundle ceiling")
        view = memoryview(value)
        while view:
            self._check()
            written = os.write(self.fd, view)
            _require(written > 0,
                     "Root recorded-read tar writer made no progress")
            piece = view[:written]
            self.digest.update(piece)
            self.total += written
            view = view[written:]
        return len(value)

    def tell(self) -> int:
        return self.total

    def flush(self) -> None:
        self._check()


class _RecordedReadTarObject:
    def __init__(self, fd: int, expected_bytes: int, maximum: int,
                 expected_sha256: str, deadline_ns: int,
                 cancel_event: Any, label: str):
        self.fd = fd
        self.expected_bytes = expected_bytes
        self.maximum = maximum
        self.expected_sha256 = expected_sha256
        self.deadline_ns = deadline_ns
        self.cancel_event = cancel_event
        self.label = label
        self.total = 0
        self.digest = hashlib.sha256()

    def _check(self) -> None:
        _require(time.monotonic_ns() < self.deadline_ns and
                 (self.cancel_event is None or
                  not self.cancel_event.is_set()),
                 f"{self.label} Root tar copy exceeded or cancelled its window")

    def read(self, size: int = -1) -> bytes:
        self._check()
        remaining = self.expected_bytes - self.total
        if size < 0 or size > COPY_BLOCK_BYTES:
            size = min(COPY_BLOCK_BYTES, remaining)
        else:
            size = min(size, remaining)
        if size == 0:
            return b""
        output = bytearray()
        while len(output) < size:
            self._check()
            block = os.read(self.fd, size - len(output))
            _require(bool(block), f"{self.label} shortened during Root tar copy")
            output.extend(block)
        raw = bytes(output)
        self.total += len(raw)
        _require(self.total <= self.expected_bytes <= self.maximum,
                 f"{self.label} exceeded its exact Source object bound")
        self.digest.update(raw)
        return raw

    def verify_complete(self, before: os.stat_result,
                        parent_fd: int, name: str) -> None:
        _require(self.total == self.expected_bytes and
                 self.digest.hexdigest() == self.expected_sha256 and
                 os.read(self.fd, 1) == b"" and
                 _info_key(before) == _info_key(os.fstat(self.fd)) ==
                     _info_key(os.stat(name, dir_fd=parent_fd,
                                       follow_symlinks=False)),
                 f"{self.label} raw bytes or identity changed during Root tar copy")


def _write_recorded_preparation_read_tar_v1(
    legacy_request: object, signed_manifest: object,
    source5_campaign_module: object, archive_source5_root: object,
    output_path: object, maximum_response_bytes: int, *,
    allocation_block_bytes: int,
    deadline_ns: int, cancel_event=None,
) -> dict[str, Any]:
    """Stream only the exact signed objects into the unchanged H USTAR format."""
    request = _exact(legacy_request, {
        "schema", "campaign_id", "host_id", "analysis_phase",
        "request_ordinal", "objects", "maximum_response_bytes",
        "request_sha256",
    }, "recorded-read legacy SourceH request")
    manifest = _exact(signed_manifest, {
        "schema", "campaign_id", "host_id", "phase", "job_index",
        "job_ordinal", "job_sha256", "run_id", "job_record_raw_sha256",
        "predecessor_ack_pin", "objects", "object_count", "payload_bytes",
        "manifest_sha256",
    }, "recorded-read freshly verified object manifest")
    archive_root = Path(_absolute_path(
        archive_source5_root, "recorded-read signed Source5 root",
    ))
    target = Path(_absolute_path(output_path,
                                 "Root recorded-read bundle output path"))
    member_name = getattr(source5_campaign_module,
                          "_source5_archive_read_tar_member_name", None)
    _require(callable(member_name) and
             type(maximum_response_bytes) is int and
             0 < maximum_response_bytes <= request["maximum_response_bytes"] and
             request["schema"] == REQUEST_SCHEMA_V1 and
             request["analysis_phase"] == "exploration" and
             request["campaign_id"] == manifest["campaign_id"] and
             request["host_id"] == manifest["host_id"] ==
                 manifest["host_id"] and
             type(request["request_ordinal"]) is int and
             0 <= request["request_ordinal"] < (1 << 64) and
             type(request["objects"]) is list and
             request["objects"] == sorted(
                 request["objects"], key=lambda row: row["origin_path"],
             ) and
             archive_root.name == "source5" and
             target.parent.resolve(strict=True) == target.parent and
             target.resolve(strict=False) == target and
             target.name == "response.tar.incoming",
             "Root recorded-read request, Source root, cap or output slot differs")
    body = {key: value for key, value in manifest.items()
            if key != "manifest_sha256"}
    _require(manifest["schema"] == OBJECT_MANIFEST_SCHEMA_V1 and
             type(manifest["objects"]) is list and
             type(manifest["object_count"]) is int and
             manifest["object_count"] == len(manifest["objects"]) and
             manifest["manifest_sha256"] == _sha(_canonical(body)) and
             request["request_sha256"] == _sha(_canonical({
                 key: value for key, value in request.items()
                 if key != "request_sha256"
             })) and
             request["objects"] == [{
                 "owner_job_sha256": manifest["job_sha256"],
                 "origin_path": row["origin_path"],
                 "raw_sha256": row["raw_sha256"],
                 "byte_count": row["byte_count"],
             } for row in manifest["objects"]],
             "Root read request is not the exact ordered signed-manifest object set")
    expected_tar_bytes = ((sum(
        512 + ((row["byte_count"] + 511) // 512) * 512
        for row in request["objects"]
    ) + 1024 + MIN_ARCHIVE_READ_BUNDLE_BYTES - 1) //
        MIN_ARCHIVE_READ_BUNDLE_BYTES) * MIN_ARCHIVE_READ_BUNDLE_BYTES
    _require(0 < expected_tar_bytes <= maximum_response_bytes,
             "Root deterministic USTAR exceeds its exact per-window cap")
    parent_fd = _open_dir_path(target.parent,
                               "Root recorded-read incoming parent",
                               private_final=True)
    output_fd = -1
    created_identity = None
    input_fds: list[tuple[int, int, str, str, _RecordedReadTarObject]] = []
    try:
        try:
            output_fd = os.open(
                target.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                _O_CLOEXEC | _O_NOFOLLOW, 0o600, dir_fd=parent_fd,
            )
        except FileExistsError as error:
            raise EvidenceArchiveError(
                "Root recorded-read incoming bundle slot already exists",
            ) from error
        os.fchmod(output_fd, 0o600)
        output_before = os.fstat(output_fd)
        created_identity = (output_before.st_dev, output_before.st_ino,
                            output_before.st_mode, output_before.st_uid)
        writer = _RecordedReadTarOutput(
            output_fd, maximum_response_bytes, deadline_ns, cancel_event,
        )
        manifest_rows = manifest["objects"]
        _require(type(manifest_rows) is list and
                 len(manifest_rows) == manifest["object_count"] and
                 type(request["objects"]) is list and
                 0 < len(manifest_rows) <= MAX_ARCHIVE_READ_OBJECTS,
                 "Root signed manifest object count differs from the request")
        with tarfile.open(fileobj=writer, mode="w|",
                          format=tarfile.USTAR_FORMAT) as archive:
            for position, (request_row, manifest_row) in enumerate(zip(
                    request["objects"], manifest_rows, strict=True)):
                _require(cancel_event is None or not cancel_event.is_set(),
                         "Root recorded-read tar materialization was cancelled")
                obj = _exact(manifest_row, {
                    "origin_path", "role", "object_id", "byte_count",
                    "raw_sha256", "semantic_sha256", "object_pin",
                }, f"Root signed manifest object[{position}]")
                origin = _absolute_path(obj["origin_path"],
                                        f"Root signed origin[{position}]")
                raw_sha = _digest(obj["raw_sha256"],
                                  f"Root signed raw digest[{position}]")
                object_count = _uint(obj["byte_count"],
                                     f"Root signed byte count[{position}]")
                object_id = _object_identity(origin, raw_sha)
                object_pin = _exact(obj["object_pin"], {
                    "path", "raw_sha256", "semantic_sha256", "byte_count",
                }, f"Root signed store pin[{position}]")
                expected_path = archive_root / "objects" / object_id
                _require(obj["object_id"] == object_id and
                         object_pin == {
                             "path": str(expected_path),
                             "raw_sha256": raw_sha,
                             "semantic_sha256": raw_sha,
                             "byte_count": object_count,
                         } and request_row == {
                             "owner_job_sha256": manifest["job_sha256"],
                             "origin_path": origin, "raw_sha256": raw_sha,
                             "byte_count": object_count,
                         },
                         f"Root object[{position}] escaped its signed path/hash/count")
                _read_object_pin(object_pin, object_count)
                object_path = Path(object_pin["path"])
                object_parent_fd = _open_dir_path(
                    object_path.parent,
                    f"Root object store parent[{position}]",
                    private_final=True,
                )
                object_fd = -1
                try:
                    before_path = os.stat(object_path.name,
                                          dir_fd=object_parent_fd,
                                          follow_symlinks=False)
                    _require(stat.S_ISREG(before_path.st_mode) and
                             before_path.st_uid == os.getuid() and
                             stat.S_IMODE(before_path.st_mode) == 0o600 and
                             before_path.st_nlink == 1 and
                             before_path.st_size == object_count <= MAX_OBJECT_BYTES,
                             f"Root object[{position}] is not its exact private object file")
                    object_fd = os.open(
                        object_path.name, os.O_RDONLY | _O_CLOEXEC |
                        _O_NOFOLLOW | _O_NONBLOCK, dir_fd=object_parent_fd,
                    )
                    before = os.fstat(object_fd)
                    _require(_info_key(before) == _info_key(before_path),
                             f"Root object[{position}] changed identity before tar copy")
                    stream = _RecordedReadTarObject(
                        object_fd, object_count, MAX_OBJECT_BYTES, raw_sha,
                        deadline_ns, cancel_event,
                        f"Root signed object[{position}]",
                    )
                    name = member_name(request_row)
                    _require(type(name) is str and name.startswith("objects/") and
                             len(name.encode("ascii", "strict")) <= 255 and
                             ".." not in PurePosixPath(name).parts and
                             "\\" not in name,
                             f"Root tar object[{position}] name exceeds exact USTAR path")
                    info = tarfile.TarInfo(name)
                    info.size = object_count
                    info.mode = 0o600
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    info.mtime = 0
                    info.type = tarfile.REGTYPE
                    info.linkname = ""
                    info.pax_headers = {}
                    archive.addfile(info, stream)
                    stream.verify_complete(before, object_parent_fd,
                                           object_path.name)
                    input_fds.append((object_fd, object_parent_fd,
                                      object_path.name, raw_sha, stream))
                    object_fd = -1
                    object_parent_fd = -1
                finally:
                    if object_fd >= 0:
                        os.close(object_fd)
                    if object_parent_fd >= 0:
                        os.close(object_parent_fd)
        writer.flush()
        os.fsync(output_fd)
        output_after = os.fstat(output_fd)
        output_path_info = os.stat(target.name, dir_fd=parent_fd,
                                   follow_symlinks=False)
        _require(created_identity == (output_after.st_dev, output_after.st_ino,
                                      output_after.st_mode, output_after.st_uid) and
                 _info_key(output_after) == _info_key(output_path_info) and
                 stat.S_ISREG(output_after.st_mode) and
                 output_after.st_uid == os.getuid() and
                 stat.S_IMODE(output_after.st_mode) == 0o600 and
                 output_after.st_nlink == 1 and
                 output_after.st_size == writer.total == expected_tar_bytes and
                 writer.total <= maximum_response_bytes and
                 output_after.st_blocks * 512 <=
                    ((maximum_response_bytes + allocation_block_bytes - 1) //
                     allocation_block_bytes) * allocation_block_bytes,
                 "Root recorded-read USTAR output changed or exceeds its exact bound")
        os.fsync(parent_fd)
        return {"path": str(target), "raw_sha256": writer.digest.hexdigest(),
                "byte_count": writer.total}
    except BaseException:
        if output_fd >= 0:
            try:
                current = os.stat(target.name, dir_fd=parent_fd,
                                  follow_symlinks=False)
                if (created_identity is not None and
                        (current.st_dev, current.st_ino, current.st_mode,
                         current.st_uid) == created_identity and
                        stat.S_ISREG(current.st_mode) and current.st_nlink == 1):
                    os.unlink(target.name, dir_fd=parent_fd)
                    os.fsync(parent_fd)
            except FileNotFoundError:
                pass
        raise
    finally:
        if output_fd >= 0:
            os.close(output_fd)
        try:
            for object_fd, object_parent_fd, object_name, expected_sha, stream in input_fds:
                try:
                    current = os.stat(object_name, dir_fd=object_parent_fd,
                                      follow_symlinks=False)
                    _require(stat.S_ISREG(current.st_mode) and
                             current.st_nlink == 1 and
                             _hash_fd_exact(
                                 object_fd, stream.expected_bytes,
                                 stream.maximum,
                                 "Root tar source object after copy",
                                 deadline_ns=deadline_ns,
                                 cancel_event=cancel_event,
                             ) == expected_sha and
                             _info_key(current) == _info_key(os.stat(
                                 object_name, dir_fd=object_parent_fd,
                                 follow_symlinks=False,
                             )),
                             "Root source object changed after tar materialization")
                finally:
                    os.close(object_fd)
                    os.close(object_parent_fd)
        finally:
            os.close(parent_fd)


def _validate_stage_map(value: object, checkpoint: dict[str, Any],
                        manifest: dict[str, Any]) -> dict[str, Any]:
    stage_map = _exact(value, {
        "schema", "checkpoint_pin", "object_manifest_pin", "rows",
        "stage_map_sha256",
    }, "Source5 local stage map")
    _require(stage_map["schema"] == STAGE_MAP_SCHEMA_V1 and
             type(stage_map["rows"]) is list,
             "Source5 local stage map schema/rows differ")
    body = {key: item for key, item in stage_map.items()
            if key != "stage_map_sha256"}
    _require(stage_map["stage_map_sha256"] == _sha(_canonical(body)),
             "Source5 local stage map self digest differs")
    manifest_rows = manifest["objects"]
    rows = stage_map["rows"]
    _require(len(rows) == len(checkpoint["entries"]) == len(manifest_rows),
             "stage map is not one-to-one with checkpoint and object manifest")
    expected_by_origin = {row["origin_path"]: row for row in manifest_rows}
    prior = ""
    for index, value_row in enumerate(rows):
        row = _exact(value_row, {
            "origin_path", "object_id", "remote_object_pin",
            "local_staged_file",
        }, f"stage map row[{index}]")
        origin = _absolute_path(row["origin_path"],
                                f"stage map row[{index}] origin")
        _require(origin > prior and origin in expected_by_origin,
                 "stage map origins are unsorted or unexpected")
        prior = origin
        expected = expected_by_origin[origin]
        _require(row["object_id"] == expected["object_id"] and
                 row["remote_object_pin"] == expected["object_pin"],
                 "stage map object identity differs from the exact manifest row")
        local = _exact(row["local_staged_file"], {
            "path", "kind", "device", "inode", "mode", "byte_count",
            "raw_sha256",
        }, f"stage map row[{index}] local staged file")
        _absolute_path(local["path"], "stage map local staged file path")
        _require(local["kind"] in {"regular", "symlink"} and
                 type(local["device"]) is int and local["device"] >= 0 and
                 type(local["inode"]) is int and local["inode"] > 0 and
                 type(local["mode"]) is int and local["mode"] >= 0,
                 "stage map local file identity is malformed")
        _uint(local["byte_count"], "stage map local byte count")
        _digest(local["raw_sha256"], "stage map local raw digest")
    return stage_map


def _validate_manifest(
    value: object, checkpoint: dict[str, Any], job_identity: dict[str, Any],
) -> dict[str, Any]:
    manifest = _exact(value, {
        "schema", "campaign_id", "host_id", "phase", "job_index",
        "job_ordinal", "job_sha256", "run_id", "job_record_raw_sha256",
        "predecessor_ack_pin",
        "objects", "object_count", "payload_bytes", "manifest_sha256",
    }, "Source5 object manifest")
    context = checkpoint["context"]
    _require(manifest["schema"] == OBJECT_MANIFEST_SCHEMA_V1 and
             manifest["campaign_id"] == context["campaign_id"] and
             manifest["host_id"] == context["host_id"] and
             manifest["phase"] == context["phase"] and
             manifest["job_index"] == context["job_index"] and
             manifest["job_ordinal"] == job_identity["job_ordinal"] and
             manifest["job_sha256"] == job_identity["job_sha256"] and
             manifest["run_id"] == job_identity["run_id"] and
             manifest["job_record_raw_sha256"] ==
                 checkpoint["job_record_pin"]["raw_sha256"] and
             manifest["predecessor_ack_pin"] ==
                 checkpoint["predecessor_ack_pin"] and
             type(manifest["objects"]) is list,
             "object manifest identity differs from its checkpoint")
    if checkpoint["schema"] == CHECKPOINT_SCHEMA_V2:
        _require(all(tree["owner_job_sha256"] == job_identity["job_sha256"]
                     for tree in checkpoint["tree_inventories"]),
                 "checkpoint tree inventory owner job differs from its raw PlanV3 job")
    entries = checkpoint["entries"]
    _require(len(manifest["objects"]) == len(entries) ==
             manifest["object_count"] and len(entries) <= MAX_ROWS,
             "object manifest row count differs from checkpoint")
    total = 0
    for row, obj in zip(entries, manifest["objects"], strict=True):
        exact_obj = _exact(obj, {
            "origin_path", "role", "object_id", "byte_count", "raw_sha256",
            "semantic_sha256", "object_pin",
        }, "object manifest entry")
        expected_object_id = _object_identity(row["origin_path"],
                                              row["raw_sha256"])
        _require(exact_obj["origin_path"] == row["origin_path"] and
                 exact_obj["role"] == row["role"] and
                 exact_obj["object_id"] == expected_object_id and
                 exact_obj["byte_count"] == row["byte_count"] and
                 exact_obj["raw_sha256"] == row["raw_sha256"] and
                 exact_obj["semantic_sha256"] == row["semantic_sha256"],
                 "object manifest entry differs from its exact checkpoint row")
        object_pin = _exact(exact_obj["object_pin"], {
            "path", "raw_sha256", "semantic_sha256", "byte_count",
        }, "object pin")
        _absolute_path(object_pin["path"], "object pin path")
        _require(object_pin["path"].endswith("/objects/" + expected_object_id) and
                 object_pin["raw_sha256"] == row["raw_sha256"] and
                 object_pin["semantic_sha256"] == row["raw_sha256"] and
                 object_pin["byte_count"] == row["byte_count"],
                 "object pin does not use accepted Source5 v3 content-address naming")
        total += row["byte_count"]
        _require(total <= MAX_TOTAL_BYTES,
                 "manifest payload exceeds the fixed aggregate ceiling")
    _require(manifest["payload_bytes"] == total,
             "object manifest payload byte total differs")
    body = {key: item for key, item in manifest.items()
            if key != "manifest_sha256"}
    _require(manifest["manifest_sha256"] == _sha(_canonical(body)),
             "object manifest self digest differs")
    return manifest


def _validate_archive_path_bindings(
    source5_path: str, checkpoint_pin: dict[str, str],
    manifest_pin: dict[str, str], ack_pin: dict[str, str],
    signature_pin: dict[str, Any], manifest: dict[str, Any],
    context: dict[str, Any], identity: dict[str, Any],
) -> None:
    root = Path(_absolute_path(source5_path, "signed archive Source5 root"))
    _require(root.name == "source5" and root.parent.name == context["host_id"] and
             root.parent.parent.name == context["campaign_id"],
             "signed archive root is outside the exact campaign/host layout")
    phase = context["phase"]
    leaf = f"{identity['job_ordinal']:06d}-{identity['job_sha256']}.json"
    expected = {
        "checkpoint": root / "checkpoints" / phase / leaf,
        "manifest": root / "objects" / "manifests" / phase / leaf,
        "ack": root / "acks" / phase / leaf,
        "signature": root / "acks" / "signatures" / phase /
                    f"{leaf[:-5]}.sig",
    }
    for label, actual in (
        ("checkpoint", checkpoint_pin["path"]),
        ("manifest", manifest_pin["path"]),
        ("ack", ack_pin["path"]),
        ("signature", signature_pin["path"]),
    ):
        _require(Path(_absolute_path(actual, f"signed {label} path")) ==
                 expected[label],
                 f"signed {label} path differs from deterministic Source5 layout")
    for item in manifest["objects"]:
        _require(Path(item["object_pin"]["path"]) ==
                 root / "objects" / item["object_id"],
                 "signed object path differs from the accepted v3 object root")


def _verify_archive_objects(manifest: dict[str, Any]) -> str:
    projection = []
    for item in manifest["objects"]:
        pin = item["object_pin"]
        _read_object_pin(pin, item["byte_count"])
        checked_pin = pin
        projection.append({
            "object_id": item["object_id"], "path": checked_pin["path"],
            "raw_sha256": checked_pin["raw_sha256"],
            "byte_count": item["byte_count"],
        })
    return _sha(_canonical(projection))


def _read_staged_raw(
    path_text: str, staging_root: str, expected: dict[str, Any],
) -> bytes:
    descriptor, literal = _staged_descriptor(path_text, staging_root, expected)
    if literal is not None:
        return literal
    path = Path(path_text)
    root = Path(staging_root)
    root_fd = _open_dir_path(str(root), "private staging root",
                             private_final=True)
    parent_fd, name = _open_parent(
        root_fd, path.relative_to(root).as_posix(), create=False,
        label="staged evidence object",
    )
    try:
        fd = os.open(name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW |
                     _O_NONBLOCK, dir_fd=parent_fd)
        try:
            before = os.fstat(fd)
            _require(stat.S_ISREG(before.st_mode) and
                     before.st_size == expected["byte_count"] and
                     before.st_size <= MAX_OBJECT_BYTES,
                     "staged evidence object changed type or size")
            pieces = []
            total = 0
            while total < before.st_size:
                block = os.read(fd, min(COPY_BLOCK_BYTES,
                                        before.st_size - total))
                _require(bool(block), "staged evidence object shortened while reading")
                total += len(block)
                pieces.append(block)
            _require(os.read(fd, 1) == b"" and
                     _info_key(before) == _info_key(os.fstat(fd)),
                     "staged evidence object changed during bounded read")
            raw = b"".join(pieces)
            _require(_sha(raw) == expected["raw_sha256"],
                     "staged evidence object changed after its exact path check")
            return raw
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
        os.close(root_fd)


def _validate_host_stage_closure(
    checkpoint: dict[str, Any], manifest: dict[str, Any],
    stage_map: dict[str, Any], staging_root: str,
) -> str:
    rows_by_origin = {row["origin_path"]: row for row in stage_map["rows"]}
    tree_file_modes = {
        item["path"]: item["mode"]
        for tree in checkpoint.get("tree_inventories", [])
        for item in tree["entries"] if item["kind"] == "file"
    }
    _require(set(rows_by_origin) == {
        row["origin_path"] for row in checkpoint["entries"]
    }, "host stage map is not the exact per-job origin closure")
    projection = []
    for entry, obj in zip(checkpoint["entries"], manifest["objects"], strict=True):
        staged = rows_by_origin[entry["origin_path"]]
        local = staged["local_staged_file"]
        measured, _literal = _staged_descriptor(
            local["path"], staging_root, entry,
            expected_regular_mode=tree_file_modes.get(entry["origin_path"]),
        )
        _require(measured == local,
                 "local staged object identity changed from the pinned stage map")
        _require(entry["origin_path"] not in tree_file_modes or
                 measured["kind"] == "regular",
                 "ProbeV2 inventory file is no longer a no-follow regular file")
        _require(staged["object_id"] == obj["object_id"] and
                 staged["remote_object_pin"] == obj["object_pin"],
                 "host stage map differs from the signed object manifest")
        projection.append({
            "object_id": obj["object_id"],
            "path": obj["object_pin"]["path"],
            "raw_sha256": obj["object_pin"]["raw_sha256"],
            "byte_count": obj["byte_count"],
        })
    return _sha(_canonical(projection))


def _verify_owner_receipt_bytes(
    checkpoint: dict[str, Any], stage_map: dict[str, Any],
    staging_root: str, record: dict[str, Any],
) -> dict[str, bytes]:
    job = record["job"]
    entries = {row["origin_path"]: row for row in checkpoint["entries"]}
    staged = {row["origin_path"]: row for row in stage_map["rows"]}
    owner_bytes: dict[str, bytes] = {}
    _require(type(checkpoint["owner_receipt_pins"]) is dict,
             "checkpoint owner receipt pin map is malformed")
    for role, raw_pin in checkpoint["owner_receipt_pins"].items():
        pin = _pin(raw_pin, f"owner receipt pin {role}")
        row = entries.get(pin["path"])
        map_row = staged.get(pin["path"])
        _require(row is not None and map_row is not None and
                 row["role"] == role and row["raw_sha256"] == pin["raw_sha256"] and
                 row["semantic_sha256"] == pin["semantic_sha256"],
                 f"owner receipt {role} is not bound to one exact closure row")
        raw = _read_staged_raw(map_row["local_staged_file"]["path"],
                               staging_root, row)
        owner_bytes[pin["path"]] = raw
        receipt, semantic = _read_self_digest(
            raw, f"owner receipt {role}",
            ("receipt_sha256", "record_sha256"),
        )
        _bind_owner_receipt_identity(
            receipt, checkpoint["context"], job, f"owner receipt {role}",
        )
        _require(semantic == pin["semantic_sha256"],
                 f"owner receipt {role} semantic digest differs")
        expected_proofs = _zero_usage_proofs(
            receipt, pin, role,
            include_probe_tmp_proofs=(
                checkpoint["schema"] in {
                    CHECKPOINT_SCHEMA_V2, CHECKPOINT_SCHEMA_V3,
                }
            ),
        )
        expected_proofs.sort(
            key=lambda item: (item["role"], item["member_ordinal"],
                              item.get("domain", "")),
        )
        if expected_proofs:
            matching = [item for item in checkpoint["empty_tmp_proofs"]
                        if item.get("role") == role]
            _require(matching == expected_proofs,
                     f"owner {role} TMPDIR proof differs from its raw receipt")
    if record["evidence"].get("host_receipt") is not None:
        host_pin = _pin_raw(record["evidence"].get("overlay"),
                            "original fixed-pair overlay pin")
        overlay_row = entries.get(host_pin["path"])
        _require(overlay_row is not None and
                 overlay_row["role"] == "fixed_pair_artifact" and
                 overlay_row["raw_sha256"] == host_pin["raw_sha256"],
                 "strict fixed host receipt overlay is not in its exact checkpoint")
        overlay_map = staged.get(host_pin["path"])
        _require(overlay_map is not None,
                 "strict fixed host receipt overlay is absent from the stage map")
        overlay_raw = _read_staged_raw(
            overlay_map["local_staged_file"]["path"], staging_root,
            overlay_row,
        )
        _validate_fixed_pair_host_receipt_bindings(
            checkpoint["context"], record, list(entries.values()),
            checkpoint["owner_receipt_pins"],
            owner_receipt_bytes=owner_bytes, overlay_raw=overlay_raw,
        )
    if checkpoint["schema"] == CHECKPOINT_SCHEMA_V2:
        def load_inventory(row: dict[str, Any]) -> bytes:
            map_row = staged.get(row["origin_path"])
            _require(map_row is not None,
                     "stage map omits a pinned ProbeV2 inventory object")
            return _read_staged_raw(
                map_row["local_staged_file"]["path"], staging_root, row,
            )

        _validate_tree_inventory_payloads(
            checkpoint["tree_inventories"], list(entries.values()),
            owner_bytes, load_inventory,
        )
    return owner_bytes


def _verify_signed_ack_metadata(
    checkpoint_pin: object, checkpoint: object, checkpoint_raw: bytes,
    request_raw: bytes, host_budget_raw: bytes,
    job_record_pin: object, job_record_bytes: bytes, plan_bytes: bytes,
    object_manifest_pin: object, object_manifest: object, manifest_raw: bytes,
    ack_pin: object, ack: object, ack_raw: bytes,
    signature_pin: object, signature_raw: bytes,
    signer_context_pin: object, signer_context_raw: bytes,
    execution_manifest_pin: object, execution_manifest_raw: bytes,
    *, expected_ack_pin: object, expected_run_id: str,
    successor_run_id: str | None, purpose: str,
    journal_width_contract_raw: bytes | None = None,
    source_manifest_raw: bytes | None = None,
    budget_dependency_map_raw: bytes | None = None,
    budget_dependency_cache_root: str | None = None,
    budget_catalogue_map_raw: bytes | None = None,
    budget_catalogue_cache_root: str | None = None,
    captured_keyring_reader=None,
    captured_preparatory_artifact_reader=None,
    captured_gpgv_reader=None,
    root_auxiliary_resource_declaration: object | None = None,
    maximum_io_window_seconds: int | None = None,
    recorded_deadline_ns: int | None = None,
    cancel_event=None,
) -> dict[str, Any]:
    """Verify one persisted signed ACK and its complete metadata signature closure.

    This read-only verifier authenticates metadata and the detached signature.
    It deliberately does not inspect object payload paths or return the
    reclaim-capable ``VERIFIED_ACK_SCHEMA_V1`` result.  Payload closure must
    have been checked by the ordinary verifier before reclaim.
    """
    _require(purpose in {"predecessor", "read"} and
             ((purpose == "predecessor") == (successor_run_id is not None)),
             "metadata ACK verifier purpose/successor binding differs")
    _require(captured_keyring_reader is None or
             (purpose == "read" and callable(captured_keyring_reader)),
             "captured keyring bytes are reserved for read-only ACK verification")
    _require(captured_preparatory_artifact_reader is None or
             (purpose == "read" and callable(captured_preparatory_artifact_reader) and
              callable(captured_keyring_reader) and
              all(value is None for value in (
                  budget_dependency_map_raw, budget_dependency_cache_root,
                  budget_catalogue_map_raw, budget_catalogue_cache_root,
              ))),
             "captured preparatory bytes require a read-only closed keyring and no physical map")
    _require(captured_gpgv_reader is None or
             (purpose == "read" and callable(captured_gpgv_reader) and
              callable(captured_keyring_reader) and
              callable(captured_preparatory_artifact_reader) and
              type(root_auxiliary_resource_declaration) is dict and
              type(maximum_io_window_seconds) is int and
              maximum_io_window_seconds > 0),
             "captured GPGV bytes require the named bounded recorded-read route")
    _require((root_auxiliary_resource_declaration is None) ==
             (captured_gpgv_reader is None) and
             (maximum_io_window_seconds is None) ==
             (captured_gpgv_reader is None) and
             (recorded_deadline_ns is None or
              captured_gpgv_reader is not None and
              type(recorded_deadline_ns) is int and
              recorded_deadline_ns > 0) and
             (cancel_event is None or callable(getattr(cancel_event, "is_set", None))),
             "recorded-read GPG resource arguments are incomplete or malformed")
    recorded_operation_started_ns = (
        time.monotonic_ns() if captured_gpgv_reader is not None else None
    )
    checked_checkpoint = _validate_checkpoint(checkpoint)
    context = checked_checkpoint["context"]
    check_pin = _pin(
        checkpoint_pin,
        "predecessor checkpoint pin" if purpose == "predecessor" else
        "persisted job-read checkpoint pin",
    )
    _require(type(checkpoint_raw) is bytes and
             _sha(checkpoint_raw) == check_pin["raw_sha256"] and
             _parse_checkpoint_metadata(checkpoint_raw, "persisted predecessor checkpoint") ==
                 checked_checkpoint and
             check_pin["semantic_sha256"] ==
                 checked_checkpoint["checkpoint_sha256"],
             "persisted predecessor checkpoint differs from its exact pin")

    checked_job_pin = _pin_raw(
        job_record_pin,
        "predecessor Source5 job-record pin" if purpose == "predecessor" else
        "persisted job-read Source5 job-record pin",
    )
    _require(checked_job_pin == checked_checkpoint["job_record_pin"],
             "predecessor job-record pin differs from its checkpoint")
    if successor_run_id is None:
        record, authorization, identity = _validate_job_record(
            context, checked_job_pin, job_record_bytes, plan_bytes,
        )
    else:
        record, authorization, identity = _validate_job_record(
            context, checked_job_pin, job_record_bytes, plan_bytes,
            successor_run_id=successor_run_id,
        )
    expected_run = _run_id(
        expected_run_id,
        "expected original PlanV3 predecessor run ID"
        if purpose == "predecessor" else
        "expected original PlanV3 read run ID",
    )
    _require(identity["run_id"] == expected_run,
             "ACK job identity differs from the exact original PlanV3 predecessor"
             if purpose == "predecessor" else
             "ACK job identity differs from the exact original PlanV3 read job")
    if purpose == "predecessor":
        _require(identity["plan_successor"]["run_id"] ==
                 _run_id(successor_run_id,
                         "expected original PlanV3 successor run ID"),
                 "ACK job identity differs from the exact original PlanV3 predecessor")
    else:
        _require("plan_successor" not in identity,
                 "arbitrary read verification unexpectedly derived a successor edge")
    expected_state = "valid_soak" if context["phase"] == "soak" else "valid_pair"
    _require(record["state"] == expected_state,
             "only an owner-verified successful original job may precede authorization"
             if purpose == "predecessor" else
             "only an owner-verified successful original job has a durable read ACK")
    _require(authorization == checked_checkpoint["authorization"] and
             checked_checkpoint["predecessor_ack_pin"] ==
                 context["predecessor_ack_pin"],
             "predecessor checkpoint authorization differs from its raw PlanV3 job record")
    _require_success_tmp_proofs(
        record, checked_checkpoint["empty_tmp_proofs"],
        require_probe_tmp_proofs=(
            checked_checkpoint["schema"] == CHECKPOINT_SCHEMA_V2
        ),
        require_fixed_pair_tmp_proofs=(
            checked_checkpoint["schema"] == CHECKPOINT_SCHEMA_V3
        ),
    )

    request_pin = _pin(checked_checkpoint["request_pin"],
                       "persisted predecessor request pin")
    request = _validate_checkpoint_request(
        _parse_checkpoint_metadata(request_raw, "persisted predecessor request"),
    )
    _require(_sha(request_raw) == request_pin["raw_sha256"] and
             request["request_sha256"] == request_pin["semantic_sha256"] and
             checked_checkpoint["schema"] ==
                 _checkpoint_schema_for_request_schema(request["schema"]) and
             request["context"] == context and
             request["job_record_pin"] == checked_job_pin and
             request["authorization"] == authorization and
             request["predecessor_ack_pin"] ==
                 checked_checkpoint["predecessor_ack_pin"] and
             request["owner_receipt_pins"] ==
                 checked_checkpoint["owner_receipt_pins"] and
             request["empty_tmp_proofs"] ==
                 checked_checkpoint["empty_tmp_proofs"] and
             request["entries"] == checked_checkpoint["entries"] and
             request.get("tree_inventories") ==
                 checked_checkpoint.get("tree_inventories"),
             "persisted checkpoint does not close over its exact original request")

    checked_manifest_pin = _pin(
        object_manifest_pin, "persisted predecessor object-manifest pin",
    )
    _require(checked_checkpoint["object_manifest_pin"] == checked_manifest_pin and
             type(manifest_raw) is bytes and
             _sha(manifest_raw) == checked_manifest_pin["raw_sha256"] and
             _parse_canonical(manifest_raw, "persisted predecessor object manifest") ==
                 object_manifest,
             "persisted object manifest differs from its checkpoint pin")
    manifest = _validate_manifest(object_manifest, checked_checkpoint, identity)
    _require(_semantic_for_document(manifest) ==
             checked_manifest_pin["semantic_sha256"],
             "persisted object-manifest semantic digest differs")
    _validate_fixed_pair_host_receipt_bindings(
        context, record, checked_checkpoint["entries"],
        checked_checkpoint["owner_receipt_pins"],
        manifest_objects=manifest["objects"],
    )

    checked_ack_pin = _pin(ack_pin, "persisted predecessor ACK pin")
    _require(_pin(expected_ack_pin, "expected original predecessor ACK pin") ==
             checked_ack_pin and type(ack_raw) is bytes and
             _sha(ack_raw) == checked_ack_pin["raw_sha256"] and
             _parse_canonical(ack_raw, "persisted predecessor ACK") == ack,
             "persisted ACK differs from the exact expected predecessor ACK pin")
    checked_ack = _exact(ack, {
        "schema", "checkpoint_pin", "object_manifest_pin",
        "predecessor_ack_pin", "signer_fingerprint", "durable_commit",
        "ack_sha256",
    }, "persisted Source5 durable ACK")
    ack_body = {key: item for key, item in checked_ack.items()
                if key != "ack_sha256"}
    _require(checked_ack["schema"] == ACK_SCHEMA_V1 and
             checked_ack["ack_sha256"] == _sha(_canonical(ack_body)) and
             checked_ack_pin["semantic_sha256"] == checked_ack["ack_sha256"] and
             checked_ack["checkpoint_pin"] == check_pin and
             checked_ack["object_manifest_pin"] == checked_manifest_pin and
             checked_ack["predecessor_ack_pin"] ==
                 checked_checkpoint["predecessor_ack_pin"],
             "persisted ACK does not bind its exact checkpoint/manifest/predecessor")

    budget_probe = _parse_canonical(
        host_budget_raw, "persisted ACK host evidence budget",
        maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES,
    )
    if budget_probe.get("schema") == PREPARATORY_BUDGET_SCHEMA_V1:
        budget_value = _exact(budget_probe, PREPARATORY_BUDGET_FIELDS_V1,
                              "persisted preparatory ACK host budget")
    else:
        budget_value, _ = _parse_host_budget_value(
            host_budget_raw, "persisted ACK host evidence budget",
        )
    catalogue_chunk_paths = None
    catalogue_cache_root = None
    root_local_budget = False
    spec_raw = None
    _require(captured_preparatory_artifact_reader is None or
             budget_value.get("schema") == PREPARATORY_BUDGET_SCHEMA_V1,
             "captured preparatory bytes are not a legacy or final budget route")
    if budget_value.get("schema") == PREPARATORY_BUDGET_SCHEMA_V1:
        if captured_preparatory_artifact_reader is not None:
            _require(type(source_manifest_raw) is bytes and
                     type(execution_manifest_raw) is bytes and
                     type(journal_width_contract_raw) is bytes,
                     "captured preparatory ACK lacks its exact Source/execution/width bytes")
            root_local_budget = True
        elif budget_dependency_map_raw is not None:
            _require(budget_dependency_cache_root is not None and
                     budget_catalogue_map_raw is not None and
                     budget_catalogue_cache_root is not None,
                     "Root preparatory ACK replay requires captured dependency/catalogue maps")
            source_manifest_raw, captured_execution_raw, captured_width_raw, \
                spec_raw, catalogue_chunk_paths, catalogue_cache_root = \
                _validate_preparatory_captured_budget_dependencies(
                    budget_dependency_map_raw, budget_dependency_cache_root,
                    budget_catalogue_map_raw, budget_catalogue_cache_root,
                    context, plan_bytes, host_budget_raw,
                    execution_manifest_raw, journal_width_contract_raw,
                )
            _require(captured_execution_raw == execution_manifest_raw and
                     captured_width_raw == journal_width_contract_raw,
                     "persisted preparatory ACK exec/width bytes differ from captured map")
            root_local_budget = True
        else:
            _require(budget_dependency_cache_root is None and
                     budget_catalogue_map_raw is None and
                     budget_catalogue_cache_root is None,
                     "host preparatory ACK replay cannot use a partial Root dependency map")
    elif budget_value.get("schema") == HOST_BUDGET_SCHEMA_V3:
        if budget_dependency_map_raw is not None:
            _require(budget_dependency_cache_root is not None and
                     budget_catalogue_map_raw is not None and
                     budget_catalogue_cache_root is not None,
                     "Root v3 ACK replay requires both captured dependency/catalogue maps")
            source_manifest_raw, captured_execution_raw, captured_width_raw, \
                catalogue_chunk_paths, catalogue_cache_root = \
                _validate_v3_captured_budget_dependencies(
                budget_dependency_map_raw, budget_dependency_cache_root,
                budget_catalogue_map_raw, budget_catalogue_cache_root,
                context, plan_bytes, host_budget_raw,
                execution_manifest_raw, journal_width_contract_raw,
            )
            _require(captured_execution_raw == execution_manifest_raw and
                     captured_width_raw == journal_width_contract_raw,
                     "persisted ACK execution/width bytes differ from captured map")
            root_local_budget = True
        else:
            _require(source_manifest_raw is not None and
                     budget_dependency_cache_root is None and
                     budget_catalogue_map_raw is None and
                     budget_catalogue_cache_root is None,
                     "host v3 ACK replay requires exact pinned Source bytes and no partial Root map")
    signer = _validate_archive_signer_context(
        signer_context_raw, signer_context_pin, context, host_budget_raw,
        execution_manifest_pin, execution_manifest_raw,
        journal_width_contract_raw,
        source_manifest_raw=source_manifest_raw,
        plan_raw=plan_bytes,
        spec_raw=spec_raw,
        catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
        root_local=root_local_budget,
        captured_preparatory_artifact_reader=captured_preparatory_artifact_reader,
        request_schema=request["schema"],
    )
    fingerprint = signer["fingerprint"]
    signature_limit = signer["maximum_signature_bytes"]
    _require(checked_ack["signer_fingerprint"] == fingerprint and
             fingerprint == context["authorized_signer_fingerprint"] and
             signature_limit > 0,
             "persisted ACK signer differs from its exact host authority")

    durable = _exact(checked_ack["durable_commit"], {
        "commit_id", "archive_source5_directory", "checkpoint_pin",
        "object_manifest_pin", "object_reopen_sha256", "object_count",
        "payload_bytes", "job_record_validation",
    }, "persisted durable commit facts")
    archive_dir = _exact(durable["archive_source5_directory"], {
        "path", "device", "inode", "mode",
    }, "persisted archive directory identity")
    archive_dir_path = _absolute_path(
        archive_dir["path"], "persisted archive directory path",
    )
    _uint(archive_dir["device"], "persisted archive directory device")
    _uint(archive_dir["inode"], "persisted archive directory inode", positive=True)
    _require(archive_dir["mode"] == 0o700 and
             durable["checkpoint_pin"] == check_pin and
             durable["object_manifest_pin"] == checked_manifest_pin and
             durable["object_count"] == manifest["object_count"] and
             durable["payload_bytes"] == manifest["payload_bytes"],
             "persisted durable facts differ from the signed manifest closure")
    validation_pin = _exact(durable["job_record_validation"], {
        "path", "origin_path", "raw_sha256", "semantic_sha256", "byte_count",
    }, "persisted always-local job-record validation")
    expected_validation_path = (
        Path(archive_dir_path) / "validation" / "job-records" /
        context["phase"] /
        f"{identity['job_ordinal']:06d}-{identity['job_sha256']}.json"
    )
    _require(Path(_absolute_path(validation_pin["path"],
                                 "persisted validation record path")) ==
                 expected_validation_path and
             validation_pin["origin_path"] == checked_job_pin["path"] and
             _digest(validation_pin["raw_sha256"],
                     "persisted validation record raw digest") ==
                 checked_job_pin["raw_sha256"] == _sha(job_record_bytes) and
             _digest(validation_pin["semantic_sha256"],
                     "persisted validation record semantic digest") ==
                 record["record_sha256"] and
             _uint(validation_pin["byte_count"],
                   "persisted validation record byte count", positive=True) ==
                 len(job_record_bytes),
             "persisted job-record validation facts differ from the pinned original record")
    object_reopen_sha = _digest(
        durable["object_reopen_sha256"],
        "signed coordinator object-reopen digest",
    )
    expected_commit_id = _sha(_canonical({
        "checkpoint_pin": check_pin,
        "object_manifest_pin": checked_manifest_pin,
        "object_reopen_sha256": object_reopen_sha,
        "job_record_validation": validation_pin,
    }))
    _require(_digest(durable["commit_id"], "signed durable commit ID") ==
             expected_commit_id,
             "signed durable commit ID differs from its canonical facts")

    checked_signature = _exact(signature_pin, {
        "path", "raw_sha256", "signer_fingerprint",
    }, "persisted detached signature pin")
    _validate_archive_path_bindings(
        archive_dir_path, check_pin, checked_manifest_pin, checked_ack_pin,
        checked_signature, manifest, context, identity,
    )
    signature_sha = _digest(checked_signature["raw_sha256"],
                            "persisted detached signature raw digest")
    _require(type(signature_raw) is bytes and
             _sha(signature_raw) == signature_sha and
             len(signature_raw) <= signature_limit and
             checked_signature["signer_fingerprint"] == fingerprint,
             "persisted detached signature differs from its exact pin or quota")
    verification_signer = {
        "fingerprint": fingerprint,
        "keyring_pin": signer["keyring_pin"],
        "gpgv_pin": signer["gpgv_pin"],
    }
    if captured_gpgv_reader is not None:
        _require(type(recorded_operation_started_ns) is int,
                 "recorded-read GPG monotonic start is absent")
        primary = _verify_detached_signature_recorded(
            ack_raw, signature_raw, verification_signer,
            captured_keyring_reader=captured_keyring_reader,
            captured_gpgv_reader=captured_gpgv_reader,
            root_auxiliary_resource_declaration=
                root_auxiliary_resource_declaration,
            operation_started_ns=recorded_operation_started_ns,
            window_deadline_ns=(recorded_deadline_ns
                                if recorded_deadline_ns is not None else
                                recorded_operation_started_ns +
                                maximum_io_window_seconds * 1_000_000_000),
            cancel_event=cancel_event,
        )
    elif captured_keyring_reader is None:
        primary = _verify_detached_signature(ack_raw, signature_raw, verification_signer)
    else:
        primary = _verify_detached_signature(
            ack_raw, signature_raw, verification_signer,
            captured_keyring_reader=captured_keyring_reader,
        )
    _require(primary == fingerprint,
             "detached signature verifier returned a different primary fingerprint")
    result = {
        "schema": (VERIFIED_PREDECESSOR_ACK_SCHEMA_V1
                   if purpose == "predecessor" else
                   VERIFIED_READ_ACK_SCHEMA_V1),
        "may_reclaim": False,
        "purpose": ("original_plan_predecessor_only"
                    if purpose == "predecessor" else
                    "original_plan_job_readback_only"),
        "checkpoint_pin": check_pin,
        "object_manifest_pin": checked_manifest_pin,
        "ack_pin": checked_ack_pin,
        "signature_pin": {
            "path": checked_signature["path"],
            "raw_sha256": signature_sha,
            "signer_fingerprint": primary,
        },
        "signer_context_pin": signer["signer_context_pin"],
        "signer_pin": {
            "fingerprint": fingerprint,
            "keyring_pin": signer["keyring_pin"],
            "gpgv_pin": signer["gpgv_pin"],
            "maximum_signature_bytes": signature_limit,
        },
        "authorization": authorization,
        "job_identity": {
            "phase": context["phase"],
            "job_index": identity["job_index"],
            "ordinal": identity["job_ordinal"],
            "run_id": identity["run_id"],
            "job_sha256": identity["job_sha256"],
        },
        "predecessor_ack_pin": checked_checkpoint["predecessor_ack_pin"],
        "durable_commit_id": expected_commit_id,
        "object_reopen_sha256": object_reopen_sha,
        "object_count": manifest["object_count"],
        "payload_bytes": manifest["payload_bytes"],
    }
    if purpose == "predecessor":
        result.pop("job_identity")
        result["plan_predecessor"] = {
            "phase": context["phase"],
            "job_index": identity["job_index"],
            "ordinal": identity["job_ordinal"],
            "run_id": identity["run_id"],
            "successor": identity["plan_successor"],
        }
    else:
        result["may_read"] = True
        result["job_identity"] = {
            "phase": context["phase"],
            "job_index": identity["job_index"],
            "ordinal": identity["job_ordinal"],
            "run_id": identity["run_id"],
            "job_sha256": identity["job_sha256"],
        }
    return result


def verify_signed_ack_for_predecessor(
    checkpoint_pin: object, checkpoint: object, checkpoint_raw: bytes,
    request_raw: bytes, host_budget_raw: bytes,
    job_record_pin: object, job_record_bytes: bytes, plan_bytes: bytes,
    object_manifest_pin: object, object_manifest: object, manifest_raw: bytes,
    ack_pin: object, ack: object, ack_raw: bytes,
    signature_pin: object, signature_raw: bytes,
    signer_context_pin: object, signer_context_raw: bytes,
    execution_manifest_pin: object, execution_manifest_raw: bytes,
    *, expected_ack_pin: object, expected_run_id: str,
    successor_run_id: str,
    journal_width_contract_raw: bytes | None = None,
    source_manifest_raw: bytes | None = None,
    budget_dependency_map_raw: bytes | None = None,
    budget_dependency_cache_root: str | None = None,
    budget_catalogue_map_raw: bytes | None = None,
    budget_catalogue_cache_root: str | None = None,
) -> dict[str, Any]:
    """Verify a persisted ACK as the exact PlanV3 predecessor of a successor."""
    return _verify_signed_ack_metadata(
        checkpoint_pin, checkpoint, checkpoint_raw, request_raw,
        host_budget_raw, job_record_pin, job_record_bytes, plan_bytes,
        object_manifest_pin, object_manifest, manifest_raw,
        ack_pin, ack, ack_raw, signature_pin, signature_raw,
        signer_context_pin, signer_context_raw,
        execution_manifest_pin, execution_manifest_raw,
        expected_ack_pin=expected_ack_pin, expected_run_id=expected_run_id,
        successor_run_id=successor_run_id, purpose="predecessor",
        journal_width_contract_raw=journal_width_contract_raw,
        source_manifest_raw=source_manifest_raw,
        budget_dependency_map_raw=budget_dependency_map_raw,
        budget_dependency_cache_root=budget_dependency_cache_root,
        budget_catalogue_map_raw=budget_catalogue_map_raw,
        budget_catalogue_cache_root=budget_catalogue_cache_root,
    )


def verify_signed_ack_for_read(
    checkpoint_pin: object, checkpoint: object, checkpoint_raw: bytes,
    request_raw: bytes, host_budget_raw: bytes,
    job_record_pin: object, job_record_bytes: bytes, plan_bytes: bytes,
    object_manifest_pin: object, object_manifest: object, manifest_raw: bytes,
    ack_pin: object, ack: object, ack_raw: bytes,
    signature_pin: object, signature_raw: bytes,
    signer_context_pin: object, signer_context_raw: bytes,
    execution_manifest_pin: object, execution_manifest_raw: bytes,
    *, expected_ack_pin: object, expected_run_id: str,
    journal_width_contract_raw: bytes | None = None,
    source_manifest_raw: bytes | None = None,
    budget_dependency_map_raw: bytes | None = None,
    budget_dependency_cache_root: str | None = None,
    budget_catalogue_map_raw: bytes | None = None,
    budget_catalogue_cache_root: str | None = None,
    captured_keyring_reader=None,
    captured_preparatory_artifact_reader=None,
) -> dict[str, Any]:
    """Verify one arbitrary successful PlanV3 job for readback, never reclaim.

    This restart-safe metadata verifier closes the exact request, job record,
    Plan, manifest, ACK, signature, signer context, execution manifest and
    optional v4 width contract. It never opens remote archive/object paths or
    local payload paths and returns a distinct non-reclaim capability.
    An explicit captured keyring reader supplies only pinned public bytes;
    the current pinned gpgv executable is still opened and executed normally.
    Preparatory metadata may use a closed byte reader instead of creating
    dependency/catalogue cache copies; all Source-owned validators still run.
    """
    return _verify_signed_ack_metadata(
        checkpoint_pin, checkpoint, checkpoint_raw, request_raw,
        host_budget_raw, job_record_pin, job_record_bytes, plan_bytes,
        object_manifest_pin, object_manifest, manifest_raw,
        ack_pin, ack, ack_raw, signature_pin, signature_raw,
        signer_context_pin, signer_context_raw,
        execution_manifest_pin, execution_manifest_raw,
        expected_ack_pin=expected_ack_pin, expected_run_id=expected_run_id,
        successor_run_id=None, purpose="read",
        journal_width_contract_raw=journal_width_contract_raw,
        source_manifest_raw=source_manifest_raw,
        budget_dependency_map_raw=budget_dependency_map_raw,
        budget_dependency_cache_root=budget_dependency_cache_root,
        budget_catalogue_map_raw=budget_catalogue_map_raw,
        budget_catalogue_cache_root=budget_catalogue_cache_root,
        captured_keyring_reader=captured_keyring_reader,
        captured_preparatory_artifact_reader=captured_preparatory_artifact_reader,
    )


def verify_signed_ack_for_recorded_read_v1(
    checkpoint_pin: object, checkpoint: object, checkpoint_raw: bytes,
    request_raw: bytes, host_budget_raw: bytes,
    job_record_pin: object, job_record_bytes: bytes, plan_bytes: bytes,
    object_manifest_pin: object, object_manifest: object, manifest_raw: bytes,
    ack_pin: object, ack: object, ack_raw: bytes,
    signature_pin: object, signature_raw: bytes,
    signer_context_pin: object, signer_context_raw: bytes,
    execution_manifest_pin: object, execution_manifest_raw: bytes,
    *, expected_ack_pin: object, expected_run_id: str,
    journal_width_contract_raw: bytes,
    source_manifest_raw: bytes,
    captured_keyring_reader,
    captured_gpgv_reader,
    captured_preparatory_artifact_reader,
    root_auxiliary_resource_declaration: object,
    maximum_io_window_seconds: int,
    recorded_deadline_ns: int | None = None,
    cancel_event=None,
) -> dict[str, Any]:
    """Freshly verify one recorded-window ACK with exact captured Source tools.

    This named read-only sibling leaves the legacy v1 disk verifier unchanged.
    Its closed readers are byte sources created inside the Root service from
    the exact metadata-capture declaration. The captured GPGV bytes are copied
    into a private, explicitly reserved per-window tool directory and executed
    there; no historical executable path fallback is permitted.
    """
    _require(type(journal_width_contract_raw) is bytes and
             type(source_manifest_raw) is bytes and
             callable(captured_keyring_reader) and
             callable(captured_gpgv_reader) and
             callable(captured_preparatory_artifact_reader) and
             type(maximum_io_window_seconds) is int and
             0 < maximum_io_window_seconds <= 300 and
             (recorded_deadline_ns is None or
              type(recorded_deadline_ns) is int and
              time.monotonic_ns() < recorded_deadline_ns) and
             type(root_auxiliary_resource_declaration) is dict,
             "recorded-read signed ACK verification lacks exact closed inputs or finite Root GPG resources")
    return _verify_signed_ack_metadata(
        checkpoint_pin, checkpoint, checkpoint_raw, request_raw,
        host_budget_raw, job_record_pin, job_record_bytes, plan_bytes,
        object_manifest_pin, object_manifest, manifest_raw,
        ack_pin, ack, ack_raw, signature_pin, signature_raw,
        signer_context_pin, signer_context_raw,
        execution_manifest_pin, execution_manifest_raw,
        expected_ack_pin=expected_ack_pin, expected_run_id=expected_run_id,
        successor_run_id=None, purpose="read",
        journal_width_contract_raw=journal_width_contract_raw,
        source_manifest_raw=source_manifest_raw,
        captured_keyring_reader=captured_keyring_reader,
        captured_preparatory_artifact_reader=
            captured_preparatory_artifact_reader,
        captured_gpgv_reader=captured_gpgv_reader,
        root_auxiliary_resource_declaration=
            root_auxiliary_resource_declaration,
        maximum_io_window_seconds=maximum_io_window_seconds,
        recorded_deadline_ns=recorded_deadline_ns,
        cancel_event=cancel_event,
    )


def verify_durable_ack(
    checkpoint_pin: object, checkpoint: object, checkpoint_raw: bytes,
    request_raw: bytes, host_budget_raw: bytes,
    job_record_pin: object, job_record_bytes: bytes, plan_bytes: bytes,
    object_manifest_pin: object, object_manifest: object, manifest_raw: bytes,
    ack_pin: object, ack: object, ack_raw: bytes,
    signature_pin: object, signature_raw: bytes,
    signer_context_pin: object, signer_context_raw: bytes,
    execution_manifest_pin: object, execution_manifest_raw: bytes,
    stage_map_pin: object, stage_map: object, staging_root: str | os.PathLike[str],
    expected_predecessor: object,
    journal_width_contract_raw: bytes | None = None,
    source_manifest_raw: bytes | None = None,
    budget_dependency_map_raw: bytes | None = None,
    budget_dependency_cache_root: str | None = None,
    budget_catalogue_map_raw: bytes | None = None,
    budget_catalogue_cache_root: str | None = None,
) -> dict[str, Any]:
    """Verify transferred bytes and signature without opening private-store paths.

    Absolute object paths in the manifest are authenticated origin identities.
    On the host this verifier rehashes the already-owned originals in the local
    stage map and never claims to reopen a Root-private archive path.
    """
    checked_checkpoint = _validate_checkpoint(checkpoint)
    checked_context = checked_checkpoint["context"]
    check_pin = _pin(checkpoint_pin, "checkpoint pin")
    _require(type(checkpoint_raw) is bytes and
             _sha(checkpoint_raw) == check_pin["raw_sha256"] and
             _parse_checkpoint_metadata(checkpoint_raw, "transferred checkpoint") ==
                 checked_checkpoint and
             check_pin["semantic_sha256"] ==
                 checked_checkpoint["checkpoint_sha256"],
             "transferred checkpoint bytes differ from their exact pin")
    _require(_pin_raw(job_record_pin, "Source5 job record pin") ==
             checked_checkpoint["job_record_pin"],
             "job record pin differs from its checkpoint")
    record, authorization, identity = _validate_job_record(
        checked_context, job_record_pin, job_record_bytes, plan_bytes,
    )
    _require(authorization == checked_checkpoint["authorization"] and
             checked_checkpoint["predecessor_ack_pin"] ==
                 checked_context["predecessor_ack_pin"],
             "checkpoint authorization or predecessor differs from raw Plan/record")
    _require_success_tmp_proofs(
        record, checked_checkpoint["empty_tmp_proofs"],
        require_probe_tmp_proofs=(
            checked_checkpoint["schema"] == CHECKPOINT_SCHEMA_V2
        ),
        require_fixed_pair_tmp_proofs=(
            checked_checkpoint["schema"] == CHECKPOINT_SCHEMA_V3
        ),
    )
    if expected_predecessor is None:
        _require(checked_checkpoint["predecessor_ack_pin"] is None,
                 "first original job has a predecessor ACK")
    else:
        _require(_pin(expected_predecessor, "expected predecessor ACK") ==
                 checked_checkpoint["predecessor_ack_pin"],
                 "checkpoint is not bound to the exact expected predecessor ACK")
    checked_manifest_pin = _pin(
        object_manifest_pin, "transferred object manifest pin",
    )
    _require(checked_checkpoint["object_manifest_pin"] == checked_manifest_pin and
             type(manifest_raw) is bytes and
             _sha(manifest_raw) == checked_manifest_pin["raw_sha256"] and
             _parse_canonical(manifest_raw, "transferred object manifest") ==
                 object_manifest,
             "transferred object manifest bytes differ from checkpoint pin")
    manifest = _validate_manifest(object_manifest, checked_checkpoint, identity)
    _require(_semantic_for_document(manifest) ==
             checked_manifest_pin["semantic_sha256"],
             "transferred object manifest semantic digest differs")
    checked_ack_pin = _pin(ack_pin, "transferred durable ACK pin")
    _require(type(ack_raw) is bytes and
             _sha(ack_raw) == checked_ack_pin["raw_sha256"] and
             _parse_canonical(ack_raw, "transferred durable ACK") == ack,
             "transferred ACK bytes differ from their raw pin")
    checked_ack = _exact(ack, {
        "schema", "checkpoint_pin", "object_manifest_pin",
        "predecessor_ack_pin", "signer_fingerprint", "durable_commit",
        "ack_sha256",
    }, "Source5 durable ACK")
    ack_body = {key: item for key, item in checked_ack.items()
                if key != "ack_sha256"}
    _require(checked_ack["schema"] == ACK_SCHEMA_V1 and
             checked_ack["ack_sha256"] == _sha(_canonical(ack_body)) and
             checked_ack_pin["semantic_sha256"] == checked_ack["ack_sha256"] and
             checked_ack["checkpoint_pin"] == check_pin and
             checked_ack["object_manifest_pin"] == checked_manifest_pin and
             checked_ack["predecessor_ack_pin"] ==
                 checked_checkpoint["predecessor_ack_pin"],
             "durable ACK does not bind the exact checkpoint/manifest/predecessor")
    budget_probe = _parse_canonical(
        host_budget_raw, "durable ACK host evidence budget",
        maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES,
    )
    if budget_probe.get("schema") == PREPARATORY_BUDGET_SCHEMA_V1:
        budget_value = _exact(budget_probe, PREPARATORY_BUDGET_FIELDS_V1,
                              "durable ACK preparatory host budget")
    else:
        budget_value, _ = _parse_host_budget_value(
            host_budget_raw, "durable ACK host evidence budget",
        )
    catalogue_chunk_paths = None
    catalogue_cache_root = None
    root_local_budget = False
    spec_raw = None
    if budget_value.get("schema") == PREPARATORY_BUDGET_SCHEMA_V1:
        if budget_dependency_map_raw is not None:
            _require(budget_dependency_cache_root is not None and
                     budget_catalogue_map_raw is not None and
                     budget_catalogue_cache_root is not None,
                     "Root preparatory ACK verification requires both captured dependency/catalogue maps")
            source_manifest_raw, captured_execution_raw, captured_width_raw, \
                spec_raw, catalogue_chunk_paths, catalogue_cache_root = \
                _validate_preparatory_captured_budget_dependencies(
                    budget_dependency_map_raw, budget_dependency_cache_root,
                    budget_catalogue_map_raw, budget_catalogue_cache_root,
                    checked_context, plan_bytes, host_budget_raw,
                    execution_manifest_raw, journal_width_contract_raw,
                )
            _require(captured_execution_raw == execution_manifest_raw and
                     captured_width_raw == journal_width_contract_raw,
                     "preparatory ACK execution/width bytes differ from captured map")
            root_local_budget = True
        else:
            _require(budget_dependency_cache_root is None and
                     budget_catalogue_map_raw is None and
                     budget_catalogue_cache_root is None,
                     "host preparatory ACK verification cannot use a partial Root map")
    elif budget_value.get("schema") == HOST_BUDGET_SCHEMA_V3:
        if budget_dependency_map_raw is not None:
            _require(budget_dependency_cache_root is not None and
                     budget_catalogue_map_raw is not None and
                     budget_catalogue_cache_root is not None,
                     "Root v3 ACK verification requires both captured dependency/catalogue maps")
            source_manifest_raw, captured_execution_raw, captured_width_raw, \
                catalogue_chunk_paths, catalogue_cache_root = \
                _validate_v3_captured_budget_dependencies(
                budget_dependency_map_raw, budget_dependency_cache_root,
                budget_catalogue_map_raw, budget_catalogue_cache_root,
                checked_context, plan_bytes, host_budget_raw,
                execution_manifest_raw, journal_width_contract_raw,
            )
            _require(captured_execution_raw == execution_manifest_raw and
                     captured_width_raw == journal_width_contract_raw,
                     "durable ACK execution/width bytes differ from captured map")
            root_local_budget = True
        else:
            _require(source_manifest_raw is not None and
                     budget_dependency_cache_root is None and
                     budget_catalogue_map_raw is None and
                     budget_catalogue_cache_root is None,
                     "host v3 ACK verification requires exact pinned Source bytes and no partial Root map")
    signer = _validate_archive_signer_context(
        signer_context_raw, signer_context_pin, checked_context,
        host_budget_raw, execution_manifest_pin, execution_manifest_raw,
        journal_width_contract_raw,
        source_manifest_raw=source_manifest_raw,
        plan_raw=plan_bytes,
        spec_raw=spec_raw,
        catalogue_chunk_paths=catalogue_chunk_paths,
        catalogue_cache_root=catalogue_cache_root,
        root_local=root_local_budget,
        request_schema=_validate_checkpoint_request(_parse_checkpoint_metadata(
            request_raw, "transferred checkpoint request profile",
        ))["schema"],
    )
    fingerprint = signer["fingerprint"]
    signature_limit = signer["maximum_signature_bytes"]
    _require(fingerprint == checked_context["authorized_signer_fingerprint"] and
             checked_ack["signer_fingerprint"] == fingerprint and
             signature_limit > 0,
             "durable ACK signer differs from externally pinned authority")
    durable = _exact(checked_ack["durable_commit"], {
        "commit_id", "archive_source5_directory", "checkpoint_pin",
        "object_manifest_pin", "object_reopen_sha256", "object_count",
        "payload_bytes", "job_record_validation",
    }, "durable commit facts")
    archive_dir = _exact(durable["archive_source5_directory"], {
        "path", "device", "inode", "mode",
    }, "durable archive directory identity")
    archive_dir_path = _absolute_path(
        archive_dir["path"], "durable archive directory path",
    )
    _uint(archive_dir["device"], "durable archive directory device")
    _uint(archive_dir["inode"], "durable archive directory inode", positive=True)
    _require(archive_dir["mode"] == 0o700 and
             durable["checkpoint_pin"] == check_pin and
             durable["object_manifest_pin"] == checked_manifest_pin and
             durable["object_count"] == manifest["object_count"] and
             durable["payload_bytes"] == manifest["payload_bytes"],
             "signed durable commit facts differ from the exact transferred manifest")
    validation_pin = _exact(durable["job_record_validation"], {
        "path", "origin_path", "raw_sha256", "semantic_sha256", "byte_count",
    }, "durable always-local job-record validation")
    expected_validation_path = (
        Path(archive_dir_path) / "validation" / "job-records" /
        checked_context["phase"] /
        f"{identity['job_ordinal']:06d}-{identity['job_sha256']}.json"
    )
    _require(Path(_absolute_path(validation_pin["path"],
                                 "durable job-record validation path")) ==
                 expected_validation_path and
             validation_pin["origin_path"] ==
                 checked_checkpoint["job_record_pin"]["path"] and
             _digest(validation_pin["raw_sha256"],
                     "durable job-record raw digest") ==
                 checked_checkpoint["job_record_pin"]["raw_sha256"] ==
                 _sha(job_record_bytes) and
             _digest(validation_pin["semantic_sha256"],
                     "durable job-record semantic digest") ==
                 record["record_sha256"] and
             _uint(validation_pin["byte_count"],
                   "durable job-record byte count", positive=True) ==
                 len(job_record_bytes),
             "signed durable job-record validation facts differ from the original local pin")
    checked_signature = _exact(signature_pin, {
        "path", "raw_sha256", "signer_fingerprint",
    }, "detached signature pin")
    _validate_archive_path_bindings(
        archive_dir_path, check_pin, checked_manifest_pin, checked_ack_pin,
        checked_signature, manifest, checked_context, identity,
    )
    stage = _validate_stage_map(stage_map, checked_checkpoint, manifest)
    stage_pin = _pin(stage_map_pin, "transferred local stage-map pin")
    _require(type(stage_pin["path"]) is str and
             _absolute_path(stage_pin["path"], "stage-map path") and
             stage_pin["semantic_sha256"] == stage["stage_map_sha256"],
             "stage-map pin differs from its semantic body")
    stage_raw_file, stage_raw_sha, _ = _read_absolute_private_file(
        Path(stage_pin["path"]), MAX_JSON_BYTES, "local stage map",
    )
    _require(stage_raw_sha == stage_pin["raw_sha256"] and
             stage_raw_file == _canonical(stage),
             "local stage map file differs from its exact pin")
    staging = _absolute_path(os.fspath(staging_root), "private staging root")
    object_projection_sha = _validate_host_stage_closure(
        checked_checkpoint, manifest, stage, staging,
    )
    owner_receipt_bytes = _verify_owner_receipt_bytes(
        checked_checkpoint, stage, staging, record,
    )
    request_pin = _pin(checked_checkpoint["request_pin"],
                       "checkpoint request pin")
    request = _validate_checkpoint_request(
        _parse_checkpoint_metadata(request_raw, "transferred checkpoint request"),
    )
    expected_request, _request_record, _request_identity = \
        _checkpoint_request_projection(
            checked_context, job_record_pin, job_record_bytes, plan_bytes,
            checked_checkpoint["entries"], owner_receipt_bytes,
            checked_checkpoint.get("tree_inventories"),
            fixed_pair_request_v3=(request["schema"] == REQUEST_SCHEMA_V3),
        )
    _require(_sha(request_raw) == request_pin["raw_sha256"] and
             request_pin["semantic_sha256"] == request["request_sha256"] and
             checked_checkpoint["schema"] ==
                 _checkpoint_schema_for_request_schema(request["schema"]) and
             request == expected_request and
             request["context"] == checked_context and
             request["job_record_pin"] == checked_checkpoint["job_record_pin"] and
             request["authorization"] == checked_checkpoint["authorization"] and
             request["predecessor_ack_pin"] ==
                 checked_checkpoint["predecessor_ack_pin"] and
             request["owner_receipt_pins"] ==
                 checked_checkpoint["owner_receipt_pins"] and
             request["empty_tmp_proofs"] ==
                 checked_checkpoint["empty_tmp_proofs"] and
             request["entries"] == checked_checkpoint["entries"] and
             request.get("tree_inventories") ==
                 checked_checkpoint.get("tree_inventories"),
             "final checkpoint does not bind its exact host checkpoint request")
    _require(durable["object_reopen_sha256"] == object_projection_sha and
             durable["commit_id"] == _sha(_canonical({
                 "checkpoint_pin": check_pin,
                 "object_manifest_pin": checked_manifest_pin,
                 "object_reopen_sha256": object_projection_sha,
                 "job_record_validation": validation_pin,
             })),
             "signed coordinator reopen projection differs from transferred bytes")
    signature = checked_signature
    _absolute_path(signature["path"], "detached signature origin path")
    signature_sha = _digest(signature["raw_sha256"],
                             "detached signature raw SHA-256")
    _require(type(signature_raw) is bytes and _sha(signature_raw) == signature_sha and
             len(signature_raw) <= signature_limit and
             signature["signer_fingerprint"] == fingerprint,
             "detached signature transfer differs from its exact pin")
    primary = _verify_detached_signature(ack_raw, signature_raw, {
        "fingerprint": fingerprint, "keyring_pin": signer["keyring_pin"],
        "gpgv_pin": signer["gpgv_pin"],
    })
    return {
        "schema": VERIFIED_ACK_SCHEMA_V1,
        "checkpoint_pin": check_pin,
        "object_manifest_pin": checked_manifest_pin,
        "ack_pin": checked_ack_pin,
        "signature_pin": {
            "path": signature["path"], "raw_sha256": signature_sha,
            "signer_fingerprint": primary,
        },
        "stage_map_pin": stage_pin,
        "signer_pin": {
            "fingerprint": fingerprint,
            "keyring_pin": signer["keyring_pin"],
            "gpgv_pin": signer["gpgv_pin"],
            "maximum_signature_bytes": signature_limit,
        },
        "signer_context_pin": signer["signer_context_pin"],
        "object_reopen_sha256": object_projection_sha,
        "stage_map_sha256": stage["stage_map_sha256"],
        "archive_source5_directory": archive_dir_path,
    }


def _unlink_stage_file(path_text: str, staging_root: str,
                       expected: dict[str, Any]) -> None:
    path = Path(_absolute_path(path_text, "stage file to reclaim"))
    root = Path(_absolute_path(staging_root, "private staging root"))
    _require(path != root and root in path.parents,
             "stage file to reclaim escaped the caller-reserved root")
    root_fd = _open_dir_path(str(root), "private staging root",
                             private_final=True)
    parent_fd, name = _open_parent(
        root_fd, path.relative_to(root).as_posix(), create=False,
        label="stage file to reclaim",
    )
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _require((info.st_dev, info.st_ino, info.st_uid,
                  stat.S_IMODE(info.st_mode)) ==
                 (expected["device"], expected["inode"], os.getuid(),
                  expected["mode"]),
                 "staged file identity changed before reclamation")
        if expected["kind"] == "regular":
            _require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                     info.st_size == expected["byte_count"],
                     "staged regular file changed type, link count, or size")
            descriptor = os.open(name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW |
                                 _O_NONBLOCK, dir_fd=parent_fd)
            try:
                before = os.fstat(descriptor)
                hasher = hashlib.sha256()
                total = 0
                while total < before.st_size:
                    block = os.read(descriptor, min(COPY_BLOCK_BYTES,
                                                    before.st_size - total))
                    _require(bool(block), "staged regular file shortened before reclaim")
                    hasher.update(block)
                    total += len(block)
                _require(os.read(descriptor, 1) == b"" and
                         total == expected["byte_count"] and
                         hasher.hexdigest() == expected["raw_sha256"] and
                         _info_key(before) == _info_key(os.fstat(descriptor)),
                         "staged regular file bytes changed before reclaim")
            finally:
                os.close(descriptor)
        else:
            _require(stat.S_ISLNK(info.st_mode) and info.st_nlink == 1,
                     "staged literal symlink changed before reclaim")
            target = os.fsencode(os.readlink(name, dir_fd=parent_fd))
            _require(len(target) == expected["byte_count"] and
                     _sha(target) == expected["raw_sha256"],
                     "staged literal symlink bytes changed before reclaim")
        os.unlink(name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
        os.close(root_fd)


def _verify_typed_tree_on_disk(
    tree: dict[str, Any], receipt: dict[str, Any], staging_root: str,
) -> list[dict[str, Any]]:
    """Re-enumerate one signed ProbeV2 tree without following links.

    The returned directory identities are local, short-lived cleanup facts;
    they are never promoted to original owner evidence or added to the signed
    checkpoint. Exact membership comes from the receipt-pinned inventory.
    """
    root_text = _absolute_path(tree["root_path"], "reclaimed ProbeV2 tree root")
    root = Path(root_text)
    staging = Path(_absolute_path(staging_root, "private staging root"))
    _require(root != staging and staging in root.parents and
             root.resolve(strict=True) == root,
             "ProbeV2 tree root escaped its exact private staging tree")
    final = _exact(receipt.get("tmpdir_final"), {
        "path", "device", "inode", "mode", "mount", "bytes_used",
        "file_count", "directory_count", "bytes_limit", "inode_limit",
        "available_bytes", "available_inodes",
    }, "ProbeV2 owner-return final tree identity")
    _require(final["path"] == root_text,
             "ProbeV2 owner-return tree root differs from its inventory root")
    before_root = root.lstat()
    _require(stat.S_ISDIR(before_root.st_mode) and
             not stat.S_ISLNK(before_root.st_mode) and
             before_root.st_uid == os.getuid() and
             before_root.st_dev == final["device"] and
             before_root.st_ino == final["inode"] and
             stat.S_IMODE(before_root.st_mode) == final["mode"] == 0o700,
             "ProbeV2 root device/inode/mode changed after its owner receipt")
    inventory = {entry["path"]: entry for entry in tree["entries"]}
    seen: set[str] = set()
    directory_identities: dict[str, dict[str, Any]] = {
        root_text: {
            "path": root_text, "device": before_root.st_dev,
            "inode": before_root.st_ino, "uid": before_root.st_uid,
            "mode": stat.S_IMODE(before_root.st_mode),
        },
    }
    try:
        for current, directories, files, directory_fd in os.fwalk(
                root_text, topdown=True, follow_symlinks=False):
            current_text = _absolute_path(current,
                                         "enumerated ProbeV2 tree directory")
            if current_text == root_text:
                expected_directory = directory_identities[root_text]
            else:
                current_entry = inventory.get(current_text)
                _require(current_entry is not None and
                         current_entry["kind"] == "directory",
                         "filesystem traversal reached an undeclared tree directory")
                expected_directory = directory_identities.get(current_text)
                _require(expected_directory is not None,
                         "filesystem traversal reached an uncaptured tree directory identity")
            opened_directory = os.fstat(directory_fd)
            _require((opened_directory.st_dev, opened_directory.st_ino,
                      opened_directory.st_uid,
                      stat.S_IMODE(opened_directory.st_mode)) ==
                     (expected_directory["device"], expected_directory["inode"],
                      expected_directory["uid"], expected_directory["mode"]),
                     "ProbeV2 directory changed identity before no-follow enumeration")
            for name in directories + files:
                child_path = _absolute_path(
                    str(Path(current_text) / name),
                    "enumerated ProbeV2 tree entry",
                )
                expected = inventory.get(child_path)
                _require(expected is not None and child_path not in seen,
                         "ProbeV2 tree has an unexpected or duplicate descendant")
                seen.add(child_path)
                before = os.stat(name, dir_fd=directory_fd,
                                 follow_symlinks=False)
                expected_mode = _uint(expected["mode"],
                                      "ProbeV2 inventory entry mode")
                expected_uid = _uint(expected["uid"],
                                     "ProbeV2 inventory entry UID")
                if name in directories:
                    _require(expected["kind"] == "directory" and
                             stat.S_ISDIR(before.st_mode) and
                             not stat.S_ISLNK(before.st_mode) and
                             before.st_uid == expected_uid == os.getuid() and
                             before.st_dev == before_root.st_dev and
                             stat.S_IMODE(before.st_mode) == expected_mode,
                             "ProbeV2 directory differs from its exact owner inventory")
                    child_fd = os.open(
                        name, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC |
                        _O_NOFOLLOW, dir_fd=directory_fd,
                    )
                    try:
                        opened = os.fstat(child_fd)
                        _require((opened.st_dev, opened.st_ino,
                                  opened.st_uid, stat.S_IMODE(opened.st_mode)) ==
                                 (before.st_dev, before.st_ino,
                                  expected_uid, expected_mode),
                                 "ProbeV2 directory changed identity before no-follow open")
                        directory_identities[child_path] = {
                            "path": child_path, "device": opened.st_dev,
                            "inode": opened.st_ino, "uid": opened.st_uid,
                            "mode": stat.S_IMODE(opened.st_mode),
                        }
                    finally:
                        os.close(child_fd)
                else:
                    size = _uint(expected["size"],
                                 "ProbeV2 inventory file size")
                    expected_sha = _digest(expected["raw_sha256"],
                                           "ProbeV2 inventory file digest")
                    _require(expected["kind"] == "file" and
                             stat.S_ISREG(before.st_mode) and
                             before.st_uid == expected_uid == os.getuid() and
                             before.st_dev == before_root.st_dev and
                             stat.S_IMODE(before.st_mode) == expected_mode and
                             before.st_nlink == 1 and before.st_size == size,
                             "ProbeV2 regular file differs from its exact owner inventory")
                    descriptor = os.open(
                        name, os.O_RDONLY | _O_CLOEXEC | _O_NOFOLLOW |
                        _O_NONBLOCK, dir_fd=directory_fd,
                    )
                    try:
                        opened = os.fstat(descriptor)
                        _require(_info_key(opened) == _info_key(before),
                                 "ProbeV2 file changed identity before no-follow open")
                        hasher = hashlib.sha256()
                        total = 0
                        while total < size:
                            block = os.read(descriptor, min(COPY_BLOCK_BYTES,
                                                            size - total))
                            _require(bool(block),
                                     "ProbeV2 file shortened during inventory replay")
                            total += len(block)
                            hasher.update(block)
                        after_fd = os.fstat(descriptor)
                        after_path = os.stat(name, dir_fd=directory_fd,
                                             follow_symlinks=False)
                        _require(total == size and hasher.hexdigest() == expected_sha and
                                 _info_key(opened) == _info_key(after_fd) ==
                                     _info_key(after_path),
                                 "ProbeV2 file bytes or identity changed after ACK")
                    finally:
                        os.close(descriptor)
        _require(seen == set(inventory),
                 "ProbeV2 filesystem membership differs from its exact inventory")
    except OSError as error:
        raise EvidenceArchiveError(
            f"cannot re-enumerate signed ProbeV2 TMP tree: {error}",
        ) from error
    after_root = root.lstat()
    _require(_info_key(before_root) == _info_key(after_root),
             "ProbeV2 root identity changed during exact inventory replay")
    return list(directory_identities.values())


def _rmdir_typed_tree_directory(
    path_text: str, staging_root: str, expected: dict[str, Any],
) -> None:
    """Remove one exact, empty inventory directory through no-follow dirfds."""
    path = Path(_absolute_path(path_text, "ProbeV2 directory to reclaim"))
    root = Path(_absolute_path(staging_root, "private staging root"))
    _require(path != root and root in path.parents and
             expected.get("path") == str(path),
             "ProbeV2 directory cleanup escaped its exact inventory root")
    root_fd = _open_dir_path(str(root), "private staging root",
                             private_final=True)
    try:
        parent_fd, name = _open_parent(
            root_fd, path.relative_to(root).as_posix(), create=False,
            label="ProbeV2 directory to reclaim",
        )
        try:
            before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            expected_identity = (
                _uint(expected.get("device"), "ProbeV2 directory device"),
                _uint(expected.get("inode"), "ProbeV2 directory inode", positive=True),
                _uint(expected.get("uid"), "ProbeV2 directory UID"),
                _uint(expected.get("mode"), "ProbeV2 directory mode"),
            )
            _require(stat.S_ISDIR(before.st_mode) and
                     not stat.S_ISLNK(before.st_mode) and
                     (before.st_dev, before.st_ino, before.st_uid,
                      stat.S_IMODE(before.st_mode)) == expected_identity and
                     before.st_uid == os.getuid(),
                     "ProbeV2 directory was replaced or changed before cleanup")
            descriptor = os.open(name, os.O_RDONLY | _O_DIRECTORY | _O_CLOEXEC |
                                 _O_NOFOLLOW, dir_fd=parent_fd)
            try:
                opened = os.fstat(descriptor)
                _require((opened.st_dev, opened.st_ino, opened.st_uid,
                          stat.S_IMODE(opened.st_mode)) == expected_identity,
                         "ProbeV2 directory changed identity before no-follow cleanup")
            finally:
                os.close(descriptor)
            os.rmdir(name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        os.close(root_fd)


def reclaim_acknowledged_local_paths(
    checkpoint: object, verified_ack: object, stage_map: object,
    staging_root: str | os.PathLike[str], *,
    checkpoint_raw: bytes, request_raw: bytes, host_budget_raw: bytes,
    job_record_bytes: bytes, plan_bytes: bytes,
    object_manifest: object, manifest_raw: bytes,
    ack: object, ack_raw: bytes, signature_raw: bytes,
    signer_context_pin: object, signer_context_raw: bytes,
    execution_manifest_pin: object, execution_manifest_raw: bytes,
    journal_width_contract_raw: bytes | None = None,
    source_manifest_raw: bytes | None = None,
    budget_dependency_map_raw: bytes | None = None,
    budget_dependency_cache_root: str | None = None,
    budget_catalogue_map_raw: bytes | None = None,
    budget_catalogue_cache_root: str | None = None,
) -> list[str]:
    """Reverify the signed transferred closure, then unlink only its exact files."""
    checked = _validate_checkpoint(checkpoint)
    capability = _exact(verified_ack, {
        "schema", "checkpoint_pin", "object_manifest_pin", "ack_pin",
        "signature_pin", "stage_map_pin", "signer_pin",
        "signer_context_pin", "object_reopen_sha256", "stage_map_sha256",
        "archive_source5_directory",
    }, "verified durable ACK capability")
    _require(capability["schema"] == VERIFIED_ACK_SCHEMA_V1,
             "reclamation lacks a coordinator-verified ACK result")
    checked_capability = verify_durable_ack(
        capability["checkpoint_pin"], checked, checkpoint_raw,
        request_raw, host_budget_raw,
        checked["job_record_pin"], job_record_bytes, plan_bytes,
        capability["object_manifest_pin"], object_manifest, manifest_raw,
        capability["ack_pin"], ack, ack_raw,
        capability["signature_pin"], signature_raw,
        signer_context_pin, signer_context_raw,
        execution_manifest_pin, execution_manifest_raw,
        capability["stage_map_pin"], stage_map, staging_root,
        checked["predecessor_ack_pin"],
        journal_width_contract_raw=journal_width_contract_raw,
        source_manifest_raw=source_manifest_raw,
        budget_dependency_map_raw=budget_dependency_map_raw,
        budget_dependency_cache_root=budget_dependency_cache_root,
        budget_catalogue_map_raw=budget_catalogue_map_raw,
        budget_catalogue_cache_root=budget_catalogue_cache_root,
    )
    _require(checked_capability == capability and
             capability["stage_map_sha256"] ==
                 _validate_stage_map(
                     stage_map, checked, object_manifest,
                 )["stage_map_sha256"],
             "durable ACK capability changed before local cleanup")
    checked_stage_map = _validate_stage_map(stage_map, checked, object_manifest)
    rows = checked_stage_map["rows"]
    tree_directory_identities: list[dict[str, Any]] = []
    tree_file_modes = {
        entry["path"]: entry["mode"]
        for tree in checked.get("tree_inventories", [])
        for entry in tree["entries"] if entry["kind"] == "file"
    }
    if checked["schema"] in {
            CHECKPOINT_SCHEMA_V2, CHECKPOINT_SCHEMA_V3,
    }:
        record, _authorization, _identity = _validate_job_record(
            checked["context"], checked["job_record_pin"],
            job_record_bytes, plan_bytes,
        )
        owner_receipts = _verify_owner_receipt_bytes(
            checked, checked_stage_map, os.fspath(staging_root),
            record,
        )
    if checked["schema"] == CHECKPOINT_SCHEMA_V2:
        for tree in checked["tree_inventories"]:
            receipt_pin = tree["owner_receipt_pin"]
            receipt_raw = owner_receipts[receipt_pin["path"]]
            receipt, semantic = _read_self_digest(
                receipt_raw, "ProbeV2 owner receipt before tree cleanup",
                ("receipt_sha256",),
            )
            _require(semantic == receipt_pin["semantic_sha256"],
                     "ProbeV2 owner receipt changed before tree cleanup")
            _validate_probe_capture_tree_receipt(tree, receipt, receipt_pin)
            tree_directory_identities.extend(
                _verify_typed_tree_on_disk(
                    tree, receipt, os.fspath(staging_root),
                )
            )
    # Verify every mapped byte before beginning exact-name unlink operations.
    for row in rows:
        local = row["local_staged_file"]
        checked_descriptor, _literal = _staged_descriptor(
            local["path"], os.fspath(staging_root), {
                "byte_count": local["byte_count"],
                "raw_sha256": local["raw_sha256"],
            }, expected_regular_mode=tree_file_modes.get(row["origin_path"]),
        )
        _require(checked_descriptor == local,
                 "local stage file identity changed before cleanup")
    removed = []
    for row in rows:
        local = row["local_staged_file"]
        _unlink_stage_file(local["path"], os.fspath(staging_root), local)
        removed.append(local["path"])
    for directory in sorted(
            tree_directory_identities,
            key=lambda item: (len(PurePosixPath(item["path"]).parts),
                              item["path"]),
            reverse=True):
        _rmdir_typed_tree_directory(
            directory["path"], os.fspath(staging_root), directory,
        )
    return removed

def _read_staged_path(
    path_text: str, staging_root: str, maximum: int, label: str,
) -> bytes:
    path = Path(_absolute_path(path_text, f"{label} path"))
    root = Path(_absolute_path(staging_root, "private staging root"))
    _require(path != root and root in path.parents,
             f"{label} escapes the caller-reserved staging root")
    root_fd = _open_dir_path(str(root), "private staging root",
                             private_final=True)
    parent_fd, name = _open_parent(
        root_fd, path.relative_to(root).as_posix(), create=False, label=label,
    )
    try:
        raw, _digest_value, _info = _read_at(
            parent_fd, name, maximum, label,
        )
        _require(raw is not None, f"{label} was not collected within its byte ceiling")
        return raw
    finally:
        os.close(parent_fd)
        os.close(root_fd)


def _cli_request(path: str) -> tuple[dict[str, Any], bytes]:
    raw, digest, _ = _read_absolute_private_file(
        Path(path), MAX_ARCHIVE_REQUEST_CHECKPOINT_BYTES,
        "private checkpoint request",
    )
    request = _validate_checkpoint_request(
        _parse_checkpoint_metadata(raw, "private checkpoint request"),
    )
    _require(digest == _sha(raw),
             "private checkpoint request raw digest changed")
    return request, raw


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Archive one completed Source5 job outside its timed lane.",
    )
    parser.add_argument("--request", required=True,
                        help="mode-0600 canonical host checkpoint request")
    parser.add_argument("--request-pin", required=True,
                        help="mode-0600 pin file for the host request bytes")
    parser.add_argument("--job-record", required=True,
                        help="separate packet-staged validation/job-record.json member")
    parser.add_argument("--catalogue-chunk-map", required=True,
                        help="canonical origin-to-local map for captured path-catalogue chunks")
    parser.add_argument("--catalogue-cache-root", required=True,
                        help="owned mode-0700 Root-local catalogue chunk cache")
    parser.add_argument("--dependency-local-map", required=True,
                        help="canonical Root-local Source/Plan/budget path map")
    parser.add_argument("--dependency-cache-root", required=True,
                        help="owned mode-0700 Root-local dependency cache")
    parser.add_argument("--staging-root", required=True,
                        help="existing owned mode-0700 staging root")
    parser.add_argument("--archive-root", required=True,
                        help="existing owned mode-0700 private archive root")
    parser.add_argument("--stage-map-path", required=True,
                        help="new mode-0600 local stage-map output path")
    parser.add_argument("--gpg-executable", required=True,
                        help="absolute GPG executable path on this private coordinator")
    parser.add_argument("--gpg-homedir", required=True,
                        help="owned mode-0700 private signing key home on this coordinator")
    parser.add_argument("--signer-fingerprint", required=True,
                        help="externally pinned signer primary fingerprint")
    arguments = parser.parse_args(argv)
    try:
        request_path = _absolute_path(arguments.request, "request path")
        staging_root = _absolute_path(arguments.staging_root, "staging root")
        request, request_raw = _cli_request(request_path)
        request_pin_raw, _request_pin_raw_sha, _ = _read_absolute_private_file(
            Path(_absolute_path(arguments.request_pin, "request pin path")),
            MAX_JSON_BYTES, "host checkpoint request pin file",
        )
        request_pin = _pin(
            _parse_canonical(request_pin_raw, "host request pin file"),
            "host checkpoint request pin",
        )
        _require(request_pin["raw_sha256"] == _sha(request_raw) and
                 request_pin["semantic_sha256"] == request["request_sha256"],
                 "host checkpoint request differs from its external pin file")
        rows = _validate_rows(request["entries"])
        staged_files = {
            row["origin_path"]: str(
                Path(staging_root) / "objects" /
                _object_identity(row["origin_path"], row["raw_sha256"])
            ) for row in rows
        }
        job_pin = _pin_raw(request["job_record_pin"], "request job record pin")
        job_record_bytes = _read_staged_path(
            _absolute_path(arguments.job_record, "staged validation job-record path"),
            staging_root, MAX_JSON_BYTES, "staged always-local job record",
        )
        _require(_sha(job_record_bytes) == job_pin["raw_sha256"],
                 "separate packet validation record differs from its request raw pin")
        dependency_map_raw, _dependency_map_sha, _dependency_map_info = \
            _read_absolute_private_file(
                Path(_absolute_path(arguments.dependency_local_map,
                                    "dependency local map path")),
                MAX_JSON_BYTES, "Root-local dependency map",
            )
        dependency_paths, dependency_pins = _parse_dependency_local_map_details(
            dependency_map_raw, request["context"],
        )
        plan_bytes, _plan_sha, _plan_info = _read_absolute_private_file(
            Path(dependency_paths[
                request["context"]["plan_pin"]["path"]
            ]), MAX_PLAN_BYTES, "Root-local captured PlanV3",
        )
        host_budget_raw, _budget_sha, _budget_info = _read_absolute_private_file(
            Path(dependency_paths[
                request["context"]["resource_budget_pin"]["path"]
            ]), PREPARATORY_MAX_BUDGET_BYTES,
            "Root-local captured host evidence budget",
        )
        catalogue_map_raw, _catalogue_map_sha, _catalogue_map_info = \
            _read_absolute_private_file(
                Path(_absolute_path(arguments.catalogue_chunk_map,
                                    "catalogue chunk map path")),
                MAX_JSON_BYTES, "Root-local catalogue chunk map",
            )
        catalogue_chunk_paths = _parse_catalogue_local_map(
            catalogue_map_raw, request["context"],
        )
        source_manifest_raw, execution_manifest_raw, journal_width_contract_raw = \
            _validate_local_dependencies(
            dependency_paths,
            _absolute_path(arguments.dependency_cache_root,
                           "dependency cache root"),
            request["context"], plan_bytes, host_budget_raw,
            dependency_pins,
        )
        budget_probe = _parse_canonical(
            host_budget_raw, "Root-local host evidence budget",
            maximum_bytes=PREPARATORY_MAX_BUDGET_BYTES,
        )
        if budget_probe.get("schema") == PREPARATORY_BUDGET_SCHEMA_V1:
            budget_value = _exact(
                budget_probe, PREPARATORY_BUDGET_FIELDS_V1,
                "Root-local preparatory host evidence budget",
            )
        else:
            budget_value, _ = _parse_host_budget_value(
                host_budget_raw, "Root-local host evidence budget",
            )
        cli_catalogue = budget_value.get("path_catalogue")
        _require(type(cli_catalogue) is dict and
                 type(cli_catalogue.get("retention_policy")) is dict,
                 "Root-local budget lacks its prospective signature quota")
        if budget_value.get("schema") == PREPARATORY_BUDGET_SCHEMA_V1:
            signature_limit = _uint(
                budget_value["archive_transport"].get(
                    "maximum_signature_bytes",
                ), "preparatory signature quota", positive=True,
            )
            _require(signature_limit ==
                     cli_catalogue["retention_policy"].get(
                         "maximum_signature_bytes",
                     ), "preparatory signature limits differ across budget sections")
        else:
            signature_limit = _uint(
                cli_catalogue["retention_policy"].get(
                    "maximum_signature_bytes",
                ), "prospective signature quota", positive=True,
            )
        owner_receipt_bytes = {
            row["origin_path"]: _read_staged_raw(
                staged_files[row["origin_path"]], staging_root, row,
            )
            for row in rows if _is_owner_receipt_role(row["role"])
        }
        result = archive_job_checkpoint(
            request_pin, request_raw, request["context"], job_pin,
            job_record_bytes, plan_bytes, host_budget_raw,
            dependency_paths,
            _absolute_path(arguments.dependency_cache_root,
                           "dependency cache root"),
            catalogue_chunk_paths,
            _absolute_path(arguments.catalogue_cache_root,
                           "catalogue cache root"),
            rows,
            owner_receipt_bytes,
            staged_files, staging_root,
            _absolute_path(arguments.archive_root, "archive root"),
            _absolute_path(arguments.stage_map_path, "stage-map output path"),
            {
                "gpg_executable": _absolute_path(
                    arguments.gpg_executable, "GPG executable",
                ),
                "gpg_homedir": _absolute_path(
                    arguments.gpg_homedir, "private GPG home",
                ),
                "primary_fingerprint": _fingerprint(
                    arguments.signer_fingerprint,
                    "external signer fingerprint",
                ),
                "maximum_signature_bytes": signature_limit,
            },
            dependency_pins=dependency_pins,
        )
        summary = {
            "schema": "allocatbelt.application-source5-evidence-archive-result.v1",
            "request_pin": result["request_pin"],
            "checkpoint_pin": result["checkpoint_pin"],
            "object_manifest_pin": result["object_manifest_pin"],
            "ack_pin": result["ack_pin"],
            "signature_pin": result["signature_pin"],
            "coordinator_stage_map_pin":
                result["coordinator_stage_map_pin"],
            "object_count": result["object_manifest"]["object_count"],
            "payload_bytes": result["object_manifest"]["payload_bytes"],
        }
        sys.stdout.buffer.write(_canonical(summary))
        return 0
    except (EvidenceArchiveError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"Source5 evidence archive failed: {type(error).__name__}: {error}",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
